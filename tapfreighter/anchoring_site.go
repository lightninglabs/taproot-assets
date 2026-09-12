package tapfreighter

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapreorg"
)

const (
	// PorterSiteID identifies the chain porter as a re-org watcher
	// site.
	PorterSiteID tapreorg.SiteID = "tapfreighter.porter"

	// BurnSupplyEventsEffectKind is the outbox effect kind under
	// which the porter's burn supply-commit events are dispatched.
	// They are act-gated: burns reach the supply-commit state
	// machine only once the transfer is buried, never on a
	// potency-tier confirmation.
	BurnSupplyEventsEffectKind tapreorg.EffectKind = "tapfreighter." +
		"burn-supply-events"

	// porterBlobVersion versions the porter's anchoring blobs.
	porterBlobVersion = 1
)

// AnchoringLog is the transaction-scoped persistence surface the
// porter site drives from its handlers. It is implemented by the
// asset store; every method runs on the caller's query handle, inside
// the re-org watcher's delivery (or registration) transaction.
type AnchoringLog interface {
	// ApplyPendingParcel is the phase-1 speculative write.
	ApplyPendingParcel(ctx context.Context, q *sqlc.Queries,
		spend *OutboundParcel, finalLeaseOwner [32]byte,
		finalLeaseExpiry time.Time) error

	// ApplyAnchorTxConfirm applies a (re)confirmation, convergently.
	ApplyAnchorTxConfirm(ctx context.Context, q *sqlc.Queries,
		conf *AssetConfirmEvent,
		burns []*AssetBurn) ([]OutputIdentifier, error)

	// ApplyAnchorTxUnconfirm withdraws the recorded confirmation:
	// the potency-tier soft downgrade.
	ApplyAnchorTxUnconfirm(ctx context.Context, q *sqlc.Queries,
		anchorTxid chainhash.Hash) error

	// ApplyTransferAbandonment compensates an act-level loss,
	// returning the locators of the proofs it deleted. foreclosure,
	// when non-nil, is the transaction the chain decided for; inputs
	// it consumed are not restored.
	ApplyTransferAbandonment(ctx context.Context, q *sqlc.Queries,
		anchorTxid chainhash.Hash,
		foreclosure *wire.MsgTx) ([]proof.Locator, error)

	// RebuildAnchorConfirm reconstructs the confirmation event from
	// stored state plus the witness's block context, without
	// mutating anything.
	RebuildAnchorConfirm(ctx context.Context, q *sqlc.Queries,
		anchorTx *wire.MsgTx, blockHash chainhash.Hash,
		blockHeight, txIndex uint32, header wire.BlockHeader,
		merkle proof.TxMerkleProof,
		burnNote string) (*AssetConfirmEvent, []*AssetBurn, error)

	// RebuildConfirmEvent is RebuildAnchorConfirm in a read
	// transaction of its own, for use outside the watcher's
	// delivery path (the porter's proof-file import).
	RebuildConfirmEvent(ctx context.Context, anchorTx *wire.MsgTx,
		blockHash chainhash.Hash, blockHeight, txIndex uint32,
		header wire.BlockHeader, merkle proof.TxMerkleProof,
		burnNote string) (*AssetConfirmEvent, []*AssetBurn, error)

	// NotifyProofs delivers final proof files to the local proof
	// subscribers, the custodian among them. The watcher's
	// confirmation delivery runs inside its transaction, so the
	// porter calls this once the outcome is in hand and the proofs
	// are committed.
	NotifyProofs(blobs ...proof.Blob)
}

// enqueueMirrorSync enqueues the proof-file mirror's catch-up for the
// database proofs a handler rewrote or deleted, in the handler's own
// transaction. Nothing is enqueued for an empty set.
func enqueueMirrorSync(ctx context.Context, tx tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring, op proof.MirrorSyncOp,
	locators []proof.Locator) error {

	if len(locators) == 0 {
		return nil
	}

	version, data, err := proof.MirrorSyncPayload{
		Op:       op,
		Locators: locators,
	}.Encode()
	if err != nil {
		return fmt.Errorf("unable to encode mirror sync: %w", err)
	}

	return tx.EnqueueEffect(ctx, tapreorg.OutboxEffect{
		Kind:      proof.MirrorSyncEffectKind,
		Anchoring: fn.Some(anchoring.ID),
		Payload: tapreorg.VersionedBlob{
			Version: version,
			Data:    data,
		},
	})
}

// porterBlob is the porter's anchoring payload (and, without the
// note, its match data): the anchor transaction the parcel
// broadcast, plus the user's burn note. Everything else the handlers
// need lives in the transfer tables, keyed by the anchor txid.
type porterBlob struct {
	// AnchorTxid identifies the transfer.
	AnchorTxid chainhash.Hash

	// Note is the user-provided description carried into burn
	// records; it exists only in porter memory at registration
	// time, so it travels in the payload.
	Note string
}

// encodePorterBlob encodes a porter blob.
func encodePorterBlob(blob porterBlob) tapreorg.VersionedBlob {
	data := make([]byte, 0, 32+len(blob.Note))
	data = append(data, blob.AnchorTxid[:]...)
	data = append(data, []byte(blob.Note)...)

	return tapreorg.VersionedBlob{
		Version: porterBlobVersion,
		Data:    data,
	}
}

// decodePorterBlob decodes a porter blob, of any version the porter
// has ever written.
func decodePorterBlob(blob tapreorg.VersionedBlob) (porterBlob, error) {
	if blob.Version != porterBlobVersion {
		return porterBlob{}, fmt.Errorf("unknown porter blob "+
			"version %d", blob.Version)
	}
	if len(blob.Data) < 32 {
		return porterBlob{}, fmt.Errorf("porter blob too short: "+
			"%d bytes", len(blob.Data))
	}

	var out porterBlob
	copy(out.AnchorTxid[:], blob.Data[:32])
	out.Note = string(blob.Data[32:])

	return out, nil
}

// porterSite is the chain porter's re-org watcher site: the porter
// stakes a transfer's local state on its anchor transaction
// confirming, and these handlers converge that state to whatever the
// chain answers.
type porterSite struct {
	porter *ChainPorter
}

// ID returns the site's stable identifier.
func (s *porterSite) ID() tapreorg.SiteID {
	return PorterSiteID
}

// EvaluateCandidate judges a spend of the transfer's inputs: the
// porter owns broadcast and does not fee-bump, so exactly the
// broadcast transaction satisfies the anchoring; any other spender
// (a replacement published elsewhere, a conflicting sweep) is
// foreign.
func (s *porterSite) EvaluateCandidate(match tapreorg.VersionedBlob,
	spendingTx *wire.MsgTx) (tapreorg.Verdict, error) {

	blob, err := decodePorterBlob(match)
	if err != nil {
		return 0, err
	}

	if spendingTx.TxHash() == blob.AnchorTxid {
		return tapreorg.VerdictSatisfies, nil
	}

	return tapreorg.VerdictForeign, nil
}

// applyConfirm rebuilds the confirmation event from stored state plus
// the witness's block context and applies it, all on the handler's
// transaction. The database proofs the confirmation wrote — the
// transfer's local outputs and the passive assets it re-anchored —
// are mirrored to the file tree through the outbox.
func (s *porterSite) applyConfirm(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	blob, err := decodePorterBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	witness, err := tapreorg.WitnessContext(anchoring, anchoring.Phase)
	if err != nil {
		return err
	}

	q := tx.Queries()
	conf, burns, err := s.porter.cfg.AnchoringLog.RebuildAnchorConfirm(
		ctx, q, witness.W.Tx(), witness.W.BlockHash(),
		witness.W.Height(), witness.W.TxIndex(),
		*witness.BlockHeader, *witness.MerkleProof, blob.Note,
	)
	if err != nil {
		return fmt.Errorf("unable to rebuild confirmation: %w", err)
	}

	localKeys, err := s.porter.cfg.AnchoringLog.ApplyAnchorTxConfirm(
		ctx, q, conf, burns,
	)
	if err != nil {
		return fmt.Errorf("unable to apply confirmation: %w", err)
	}

	var rewritten []proof.Locator
	for _, key := range localKeys {
		if p, ok := conf.FinalProofs[key]; ok {
			rewritten = append(rewritten, p.Locator)
		}
	}
	for assetID := range conf.PassiveAssetProofFiles {
		for _, p := range conf.PassiveAssetProofFiles[assetID] {
			rewritten = append(rewritten, p.Locator)
		}
	}

	return enqueueMirrorSync(
		ctx, tx, anchoring, proof.MirrorSyncRewrite, rewritten,
	)
}

// OnWitnessed converges the transfer to a confirmed anchor: the full
// confirmation application, rebuilt against the current witness (the
// same transaction in a new block after a re-org included).
func (s *porterSite) OnWitnessed(ctx context.Context, tx tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	return s.applyConfirm(ctx, tx, anchoring)
}

// OnUnwitnessed converges the transfer to an unconfirmed anchor after
// its witness was lost with no successor: the recorded confirmation
// is withdrawn, nothing else is reversed.
func (s *porterSite) OnUnwitnessed(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	blob, err := decodePorterBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	return s.porter.cfg.AnchoringLog.ApplyAnchorTxUnconfirm(
		ctx, tx.Queries(), blob.AnchorTxid,
	)
}

// OnConflicted takes the same soft action as OnUnwitnessed: a foreign
// spend of the transfer's inputs sits on the chain, so the anchor
// certainly is not confirmed — but the foreign spend can itself
// re-org out, so nothing is compensated yet.
func (s *porterSite) OnConflicted(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	blob, err := decodePorterBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	return s.porter.cfg.AnchoringLog.ApplyAnchorTxUnconfirm(
		ctx, tx.Queries(), blob.AnchorTxid,
	)
}

// OnBuried converges the transfer to act-level confirmation. The
// confirmation application re-runs convergently (covering the case
// where delivery coalesced straight from an earlier phase), and the
// burn supply-commit events — irrevocable assertions to a receiver
// that re-checks nothing — are enqueued for dispatch here, and only
// here.
func (s *porterSite) OnBuried(ctx context.Context, tx tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	if err := s.applyConfirm(ctx, tx, anchoring); err != nil {
		return err
	}

	return tx.EnqueueEffect(ctx, tapreorg.OutboxEffect{
		Kind:      BurnSupplyEventsEffectKind,
		Anchoring: fn.Some(anchoring.ID),
		Payload:   anchoring.Payload,
	})
}

// foreclosingTx extracts the transaction the chain decided for from
// an abandoned anchoring's phase evidence: the buried foreign spend,
// or the witness whose burial foreclosed a depended-upon parent. Its
// input set is what compensation needs — an outpoint that transaction
// consumed is gone from the node's control, not restorable. Nil when
// the phase carries no such transaction.
func foreclosingTx(anchoring *tapreorg.Anchoring) *wire.MsgTx {
	abandoned, ok := anchoring.Phase.(tapreorg.Abandoned)
	if !ok {
		return nil
	}

	switch cause := abandoned.Cause.(type) {
	case tapreorg.ForeignBurial:
		return cause.Spend.W.Tx()

	case tapreorg.Foreclosed:
		return cause.W.Tx()
	}

	return nil
}

// OnAbandoned compensates: the chain decided against the transfer's
// anchor with act-level finality. The deleted database proofs are
// shed from the file mirror through the outbox.
func (s *porterSite) OnAbandoned(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	blob, err := decodePorterBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	deleted, err := s.porter.cfg.AnchoringLog.ApplyTransferAbandonment(
		ctx, tx.Queries(), blob.AnchorTxid, foreclosingTx(anchoring),
	)
	if err != nil {
		return err
	}

	return enqueueMirrorSync(
		ctx, tx, anchoring, proof.MirrorSyncDelete, deleted,
	)
}

// A compile-time assertion that the porter site satisfies the site
// contract.
var _ tapreorg.Site = (*porterSite)(nil)

// OnAnchoringDelivered is the porter's delivery listener: it nudges
// whatever parcel waits on the anchoring. Latency path only.
func (p *ChainPorter) OnAnchoringDelivered(id tapreorg.AnchoringID,
	site tapreorg.SiteID, phase tapreorg.Phase) {

	if site != PorterSiteID {
		return
	}

	p.waiters.Nudge(id)
}

// AnchoringSite returns the porter's site implementation, for
// registration with the re-org watcher.
func (p *ChainPorter) AnchoringSite() tapreorg.Site {
	return &porterSite{porter: p}
}

// DispatchBurnSupplyEvents is the outbox dispatch handler for the
// porter's act-gated burn events: it rebuilds the burn records from
// the (by now buried) transfer and hands them to the supply-commit
// event system. Idempotent — the supply-commit side dedupes events by
// content hash.
func (p *ChainPorter) DispatchBurnSupplyEvents(ctx context.Context,
	anchoringID fn.Option[tapreorg.AnchoringID],
	payload tapreorg.VersionedBlob) error {

	blob, err := decodePorterBlob(payload)
	if err != nil {
		return err
	}

	id, err := anchoringID.UnwrapOrErr(fmt.Errorf("burn effect "+
		"lacks an anchoring: %v", blob.AnchorTxid))
	if err != nil {
		return err
	}

	anchoring, err := p.cfg.AnchoringWatcher.Anchoring(ctx, id)
	if err != nil {
		return err
	}

	witness, err := tapreorg.WitnessContext(anchoring, anchoring.Phase)
	if err != nil {
		return err
	}

	_, burns, err := p.cfg.AnchoringLog.RebuildConfirmEvent(
		ctx, witness.W.Tx(), witness.W.BlockHash(),
		witness.W.Height(), witness.W.TxIndex(),
		*witness.BlockHeader, *witness.MerkleProof, blob.Note,
	)
	if err != nil {
		return fmt.Errorf("unable to rebuild burns: %w", err)
	}
	if len(burns) == 0 {
		return nil
	}

	return p.sendBurnSupplyCommitEvents(ctx, burns)
}

// ErrNoParcelAnchoring is returned when the site's per-txid identity
// index has no anchoring for a transfer's anchor transaction.
var ErrNoParcelAnchoring = errors.New("no anchoring for anchor tx")

// findAnchoring resolves the porter anchoring for the given anchor
// transaction via the site's per-txid identity index.
func (p *ChainPorter) findAnchoring(ctx context.Context,
	anchorTxid chainhash.Hash) (*tapreorg.Anchoring, error) {

	anchoring, err := p.cfg.AnchoringWatcher.LookupByMatchKey(
		ctx, PorterSiteID, anchorTxid.CloneBytes(),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to look up anchoring: %w", err)
	}
	if anchoring == nil {
		return nil, fmt.Errorf("%w: %v", ErrNoParcelAnchoring,
			anchorTxid)
	}

	return anchoring, nil
}

// registerParcelAnchoring stakes the parcel on its anchor transaction
// confirming: the anchoring registration and the pending-parcel write
// commit in one transaction.
func (p *ChainPorter) registerParcelAnchoring(ctx context.Context,
	pkg *sendPackage) (tapreorg.AnchoringID, error) {

	parcel := pkg.OutboundPkg

	// The trigger set is the transfer's asset-bearing input anchor
	// outpoints: any admissible form of this transfer must spend
	// all of them (the whole-set rule), and any other spender
	// forecloses it.
	triggerScripts := make(map[wire.OutPoint][]byte)
	for _, vPkt := range pkg.VirtualPackets {
		for _, vIn := range vPkt.Inputs {
			triggerScripts[vIn.PrevID.OutPoint] = vIn.Anchor.
				PkScript
		}
	}

	points := make([]tapreorg.TriggerOutPoint, 0, len(parcel.Inputs))
	seen := make(map[wire.OutPoint]struct{}, len(parcel.Inputs))
	for idx := range parcel.Inputs {
		op := parcel.Inputs[idx].OutPoint
		if _, ok := seen[op]; ok {
			continue
		}
		seen[op] = struct{}{}

		points = append(points, tapreorg.TriggerOutPoint{
			OutPoint:   op,
			PkScript:   triggerScripts[op],
			HeightHint: parcel.AnchorTxHeightHint,
		})
	}
	triggers, err := tapreorg.NewTriggerSet(points)
	if err != nil {
		return 0, fmt.Errorf("unable to build trigger set: %w", err)
	}

	anchorTxid := parcel.AnchorTx.TxHash()
	blob := encodePorterBlob(porterBlob{
		AnchorTxid: anchorTxid,
		Note:       pkg.Note,
	})

	spec := tapreorg.RegistrationSpec{
		Site:      PorterSiteID,
		Triggers:  triggers,
		MatchData: blob,
		Payload:   blob,
		MatchKey:  anchorTxid.CloneBytes(),
		Threshold: p.cfg.AnchoringThreshold,
	}

	leaseExpiry := time.Now().Add(defaultBroadcastCoinLeaseDuration)

	return p.cfg.AnchoringWatcher.Register(
		ctx, spec, func(ctx context.Context, tx tapreorg.RegistryTx,
			id tapreorg.AnchoringID) error {

			return p.cfg.AnchoringLog.ApplyPendingParcel(
				ctx, tx.Queries(), parcel,
				defaultWalletLeaseIdentifier, leaseExpiry,
			)
		},
	)
}

// registerResumedParcelAnchoring adopts a resumed parcel that has no
// anchoring: one written before the anchoring watcher existed and
// carried across the upgrade. The pending transfer state is already
// durable, so the registration stakes nothing (a nil phase-1 body);
// the trigger scripts, which the original registration read from the
// in-memory virtual packets, are recovered from the inputs' proof
// files instead.
//
// The registration blob carries an empty burn note: the note is not
// recoverable from durable transfer state, so burn supply events
// rebuilt for an adopted parcel lose the user's description.
func (p *ChainPorter) registerResumedParcelAnchoring(ctx context.Context,
	pkg *sendPackage) (tapreorg.AnchoringID, error) {

	parcel := pkg.OutboundPkg

	points := make([]tapreorg.TriggerOutPoint, 0, len(parcel.Inputs))
	seen := make(map[wire.OutPoint]struct{}, len(parcel.Inputs))
	for idx := range parcel.Inputs {
		op := parcel.Inputs[idx].OutPoint
		if _, ok := seen[op]; ok {
			continue
		}
		seen[op] = struct{}{}

		file, err := p.fetchInputProof(ctx, parcel.Inputs[idx].PrevID)
		if err != nil {
			return 0, fmt.Errorf("unable to fetch input proof "+
				"for %v: %w", op, err)
		}
		last, err := file.LastProof()
		if err != nil {
			return 0, fmt.Errorf("unable to read input proof "+
				"for %v: %w", op, err)
		}
		if last.OutPoint() != op {
			return 0, fmt.Errorf("input proof for %v anchors at "+
				"%v", op, last.OutPoint())
		}
		if op.Index >= uint32(len(last.AnchorTx.TxOut)) {
			return 0, fmt.Errorf("input outpoint %v exceeds "+
				"anchor outputs", op)
		}

		points = append(points, tapreorg.TriggerOutPoint{
			OutPoint:   op,
			PkScript:   last.AnchorTx.TxOut[op.Index].PkScript,
			HeightHint: parcel.AnchorTxHeightHint,
		})
	}
	triggers, err := tapreorg.NewTriggerSet(points)
	if err != nil {
		return 0, fmt.Errorf("unable to build trigger set: %w", err)
	}

	anchorTxid := parcel.AnchorTx.TxHash()
	blob := encodePorterBlob(porterBlob{
		AnchorTxid: anchorTxid,
	})

	return p.cfg.AnchoringWatcher.Register(ctx, tapreorg.RegistrationSpec{
		Site:      PorterSiteID,
		Triggers:  triggers,
		MatchData: blob,
		Payload:   blob,
		MatchKey:  anchorTxid.CloneBytes(),
		Threshold: p.cfg.AnchoringThreshold,
	}, nil)
}

// anchoringOutcome is what waiting on an anchoring resolves to.
type anchoringOutcome struct {
	// witness is set for a positive outcome (witnessed or buried,
	// with the site's confirmation state already applied and
	// delivered).
	witness *tapreorg.CandidateSpend

	// abandoned is set when the chain decided against the transfer
	// with act-level finality.
	abandoned bool
}

// waitForAnchoringOutcome blocks until the parcel's anchoring reaches
// a delivered positive phase (witnessed or buried) or a terminal
// negative one. The registry is the durable source; the delivery
// listener provides latency.
func (p *ChainPorter) waitForAnchoringOutcome(ctx context.Context,
	pkg *sendPackage) (*anchoringOutcome, error) {

	anchorTxid := pkg.OutboundPkg.AnchorTx.TxHash()

	// Resolve the anchoring ID (cheap after the first pass).
	if pkg.AnchoringID == 0 {
		anchoring, err := p.findAnchoring(ctx, anchorTxid)
		switch {
		// A parcel written before the anchoring watcher existed
		// resumes at broadcast without an anchoring. Adopt it
		// now, so the transfer confirms through the watcher like
		// any other instead of failing terminally on every
		// restart with its inputs leased.
		case errors.Is(err, ErrNoParcelAnchoring):
			id, err := p.registerResumedParcelAnchoring(ctx, pkg)
			if err != nil {
				return nil, fmt.Errorf("unable to adopt "+
					"resumed parcel: %w", err)
			}

			log.Infof("Adopted resumed parcel without an "+
				"anchoring (anchor_txid=%v, anchoring_id=%d)",
				anchorTxid, id)
			pkg.AnchoringID = id

		case err != nil:
			return nil, err

		default:
			pkg.AnchoringID = anchoring.ID
		}
	}

	nudge := p.waiters.Channel(pkg.AnchoringID)
	defer p.waiters.Forget(pkg.AnchoringID)

	ticker := time.NewTicker(anchoringPollInterval)
	defer ticker.Stop()

	for {
		anchoring, err := p.cfg.AnchoringWatcher.Anchoring(
			ctx, pkg.AnchoringID,
		)
		if err != nil {
			return nil, err
		}

		// Only *delivered* phases matter here: delivery is what
		// carries the site's own state application.
		switch anchoring.DeliveredPhase.(type) {
		case tapreorg.Witnessed, tapreorg.Buried:
			// The witness comes from the *delivered* phase:
			// sensing may already have moved past it, but the
			// delivered phase is what the site's state was
			// converged to.
			witness, err := tapreorg.WitnessContext(
				anchoring, anchoring.DeliveredPhase,
			)
			if err != nil {
				return nil, err
			}

			return &anchoringOutcome{witness: witness}, nil

		case tapreorg.Abandoned:
			return &anchoringOutcome{abandoned: true}, nil

		case tapreorg.Withdrawn:
			return nil, fmt.Errorf("anchoring %d withdrawn",
				pkg.AnchoringID)
		}

		select {
		case <-nudge:
		case <-ticker.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.Quit:
			return nil, errShutdown
		}
	}
}

// importConfirmedProofFiles rebuilds the transfer's final proof files
// from the (already applied) database state and imports them into the
// file archive, so couriers and archive readers see exactly what the
// database holds, then notifies the local proof subscribers of them.
// The rebuild is deterministic, so re-imports after a restart are
// idempotent.
func (p *ChainPorter) importConfirmedProofFiles(ctx context.Context,
	pkg *sendPackage, witness *tapreorg.CandidateSpend) error {

	conf, _, err := p.cfg.AnchoringLog.RebuildConfirmEvent(
		ctx, witness.W.Tx(), witness.W.BlockHash(),
		witness.W.Height(), witness.W.TxIndex(),
		*witness.BlockHeader, *witness.MerkleProof, pkg.Note,
	)
	if err != nil {
		return fmt.Errorf("unable to rebuild proofs: %w", err)
	}

	proofs := make(
		[]*proof.AnnotatedProof, 0,
		len(conf.FinalProofs)+len(conf.PassiveAssetProofFiles),
	)
	for key := range conf.FinalProofs {
		proofs = append(proofs, conf.FinalProofs[key])
	}
	for assetID := range conf.PassiveAssetProofFiles {
		proofs = append(
			proofs, conf.PassiveAssetProofFiles[assetID]...,
		)
	}

	if len(proofs) == 0 {
		return nil
	}

	// Verification here is belt-and-braces (the proofs were rebuilt
	// from state this daemon itself verified and stored), and
	// enriches the proofs with the locator metadata the archive
	// import requires.
	headerVerifier := tapnode.GenHeaderVerifier(ctx, p.cfg.ChainBridge)
	vCtx := proof.VerifierCtx{
		HeaderVerifier: headerVerifier,
		MerkleVerifier: proof.DefaultMerkleVerifier,
		GroupVerifier:  p.cfg.GroupVerifier,
		ChainLookupGen: p.cfg.ChainBridge,
		IgnoreChecker:  p.cfg.IgnoreChecker,
	}
	verified, err := proof.VerifyAnnotatedProofs(ctx, vCtx, proofs...)
	if err != nil {
		return fmt.Errorf("unable to verify rebuilt proofs: %w", err)
	}

	// A re-import after a restart (or a re-organized confirmation)
	// replaces; setting replace on a first import is accepted by the
	// file archive, so the flag keys off whether this parcel already
	// went through this state once.
	err = p.cfg.ProofWriter.ImportVerifiedProofs(
		ctx, false, verified...,
	)
	if err != nil {
		return fmt.Errorf("unable to import proofs: %w", err)
	}

	// Stash the rebuilt event for the states that follow (manifest
	// construction and proof transfer read from the archive, but
	// event subscribers expect the final proofs).
	pkg.FinalProofs = conf.FinalProofs

	// Notify the local proof subscribers, as the legacy confirmation
	// path did from inside its store: the final proofs of the
	// outputs the confirmation materialized locally, and every
	// passive re-anchor. A self-send to a non-mailbox address is
	// completed by the custodian on this notification alone. Remote
	// outputs are the receiver's to learn of through proof delivery.
	p.cfg.AnchoringLog.NotifyProofs(
		localProofBlobs(pkg.OutboundPkg, conf)...,
	)

	return nil
}

// localProofBlobs selects, from a rebuilt confirmation, the proof
// files the local subscribers expect: the final proofs of the outputs
// the confirmation materializes as local assets, plus every passive
// re-anchor.
func localProofBlobs(parcel *OutboundParcel,
	conf *AssetConfirmEvent) []proof.Blob {

	var blobs []proof.Blob
	for _, annotated := range conf.FinalProofs {
		locator := annotated.Locator
		if locator.OutPoint == nil {
			continue
		}

		for idx := range parcel.Outputs {
			out := &parcel.Outputs[idx]
			scriptKey := out.ScriptKey.PubKey
			if out.Anchor.OutPoint != *locator.OutPoint ||
				scriptKey == nil ||
				!scriptKey.IsEqual(&locator.ScriptKey) {

				continue
			}

			if isLocalOutput(out) {
				blobs = append(blobs, annotated.Blob)
			}

			break
		}
	}

	for _, passive := range conf.PassiveAssetProofFiles {
		for _, annotated := range passive {
			blobs = append(blobs, annotated.Blob)
		}
	}

	return blobs
}

// isLocalOutput reports whether the confirmation materializes a
// transfer output as a local asset, mirroring the asset store's
// asset-creation rule: tombstones and burns (kept so their anchors
// can be garbage collected), outputs to a local script key, and
// outputs to a known script key that does not belong to a remote
// node.
func isLocalOutput(out *TransferOutput) bool {
	scriptKeyType := asset.ScriptKeyUnknown
	if out.ScriptKey.TweakedScriptKey != nil {
		scriptKeyType = out.ScriptKey.TweakedScriptKey.Type
	}

	isTombstone := out.IsTombstone() && out.Type == tappsbt.TypeSplitRoot
	isBurn := len(out.WitnessData) > 0 && asset.IsBurnKey(
		out.ScriptKey.PubKey, out.WitnessData[0],
	)
	isKnown := scriptKeyType != asset.ScriptKeyUnknown
	isRemotePedersen := scriptKeyType == asset.ScriptKeyUniquePedersen &&
		!out.ScriptKeyLocal

	return isTombstone || isBurn || out.ScriptKeyLocal ||
		(isKnown && !isRemotePedersen)
}

// anchoringPollInterval is the fallback cadence for reading the
// anchoring registry while waiting on an outcome; delivery listener
// nudges make the usual path much faster.
const anchoringPollInterval = 30 * time.Second

// errShutdown is returned when a wait is interrupted by shutdown.
var errShutdown = fmt.Errorf("chain porter shutting down")

// enrichSendManifests fills each address-v2 send fragment manifest
// with the transfer's confirmed anchor context, taken from the
// anchoring's enriched witness. The auth mailbox courier cannot
// deliver a fragment without a transaction proof for its claimed
// outpoint, so on the anchoring path this replaces the enrichment the
// legacy confirmation path performs from its re-stamped proof
// suffixes.
func enrichSendManifests(pkg *sendPackage,
	witness *tapreorg.CandidateSpend) error {

	if len(pkg.SendManifests) == 0 {
		return nil
	}
	if witness == nil || witness.BlockHeader == nil ||
		witness.MerkleProof == nil {

		return fmt.Errorf("send manifests require an enriched " +
			"confirmation witness")
	}

	for i := range pkg.OutboundPkg.Outputs {
		out := pkg.OutboundPkg.Outputs[i]
		manifest, ok := pkg.SendManifests[out.Anchor.OutPoint.Index]
		if !ok {
			continue
		}

		if out.Anchor.InternalKey.PubKey == nil {
			return fmt.Errorf("anchor internal key not set for "+
				"output %d", out.Anchor.OutPoint.Index)
		}

		copy(
			manifest.Fragment.TaprootAssetRoot[:],
			out.Anchor.TaprootAssetRoot,
		)
		manifest.Fragment.OutPoint = out.Anchor.OutPoint
		manifest.Fragment.BlockHeader = *witness.BlockHeader
		manifest.Fragment.BlockHeight = witness.W.Height()
		manifest.TxProof = proof.TxProof{
			MsgTx:           *witness.W.Tx(),
			BlockHeader:     *witness.BlockHeader,
			BlockHeight:     witness.W.Height(),
			MerkleProof:     *witness.MerkleProof,
			ClaimedOutPoint: out.Anchor.OutPoint,
			InternalKey:     *out.Anchor.InternalKey.PubKey,
			MerkleRoot:      out.Anchor.MerkleRoot,
		}
	}

	return nil
}
