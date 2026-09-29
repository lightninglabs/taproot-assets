package tapcustody

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
)

const (
	// ReceiveSiteID identifies the receive side (custodian and RPC
	// proof import) as a re-org watcher site.
	ReceiveSiteID tapreorg.SiteID = "tapcustody.receiver"

	// receiveBlobVersion versions the receive side's anchoring
	// blobs.
	receiveBlobVersion = 1
)

// ReceiveAnchoringLog is the receive site's persistence surface, implemented
// by the asset store. Speculative bodies run on watcher transactions; safe
// imports open their own. Proof changes enqueue the file mirror's catch-up in
// the same database transaction.
type ReceiveAnchoringLog interface {
	// ApplyReceiveReconfirm converges received state to a
	// (re)confirmed anchor, returning the locators of the proofs it
	// re-stamped.
	ApplyReceiveReconfirm(
		ctx context.Context, q *sqlc.Queries,
		blockContext proof.VerifiedBlockContext,
	) ([]proof.Locator, error)

	// ApplyReceiveUnconfirm withdraws the recorded confirmation.
	ApplyReceiveUnconfirm(ctx context.Context, q *sqlc.Queries,
		anchorTxid chainhash.Hash) error

	// ApplyReceiveAbandonment compensates an abandoned receive,
	// returning the locators of the proofs it deleted.
	ApplyReceiveAbandonment(ctx context.Context, q *sqlc.Queries,
		anchorTxid chainhash.Hash,
		resetStatus int16) ([]proof.Locator, error)

	// StakeReceivedProofs imports verified received proofs on the
	// registration transaction, skipping any already held, and
	// returns the blobs it imported.
	StakeReceivedProofs(ctx context.Context, tx tapreorg.RegistryTx,
		proofs ...proof.VerifiedAnnotatedProof) ([]proof.Blob, error)

	// StoreReceivedProofs imports already-safe received proofs in its own
	// transaction, skipping any already held. No watcher stake is needed
	// once every anchor in the proof DAG has crossed the safety depth.
	StoreReceivedProofs(ctx context.Context,
		proofs ...proof.VerifiedAnnotatedProof) ([]proof.Blob, error)

	// HasReceivedProof reports whether the database holds a proof
	// for exactly the asset the locator names: asset ID, script key
	// and outpoint together.
	HasReceivedProof(ctx context.Context,
		locator proof.Locator) (bool, error)

	// NotifyProofs delivers imported proofs to the proof event
	// subscribers, outside the transaction that stored them.
	NotifyProofs(blobs ...proof.Blob)
}

// ProofAnchorOwnership records which local subsystems have durable state
// staked on a proof transition. Mint and porter ownership require their own
// compensation. Receive ownership is independent: a self-send, for example,
// belongs to both the porter and an address event.
type ProofAnchorOwnership struct {
	Mint    bool
	Porter  bool
	Receive bool
}

// NeedsReceiveAdoption reports whether the transition belongs at the receive
// site. A transition with no recognizable owner is treated as restored wallet
// custody; recognized mint and porter state stays with its native site.
func (o ProofAnchorOwnership) NeedsReceiveAdoption() bool {
	return o.Receive || (!o.Mint && !o.Porter)
}

// ProofAdoptionLog is the read surface used by the one-shot upgrade adopter.
// It is separate from ReceiveAnchoringLog so ordinary site tests and alternate
// persistence implementations need not pretend to support database rollout.
type ProofAdoptionLog interface {
	// ProofsForAdoption returns the stored proof files whose tip may
	// still need protection: those anchored at or above the given
	// block height, and those whose anchor height is unknown.
	ProofsForAdoption(ctx context.Context,
		minBlockHeight uint32) ([]proof.Blob, error)

	ProofAnchorOwnership(ctx context.Context,
		anchorTxid chainhash.Hash) (ProofAnchorOwnership, error)
}

// VerifiedProofWriter is the proof-file mirror: it stores verified
// proofs without re-validating them.
type VerifiedProofWriter interface {
	// ImportVerifiedProofs stores verified proofs; with replace set
	// the proof is expected to exist already.
	ImportVerifiedProofs(ctx context.Context, replace bool,
		proofs ...proof.VerifiedAnnotatedProof) error
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

// encodeReceiveBlob encodes the receive site's anchoring blob: the
// anchor transaction the received proofs are keyed to.
func encodeReceiveBlob(anchorTxid chainhash.Hash) tapreorg.VersionedBlob {
	return tapreorg.VersionedBlob{
		Version: receiveBlobVersion,
		Data:    anchorTxid[:],
	}
}

// decodeReceiveBlob decodes a receive blob of any version the site
// has ever written.
func decodeReceiveBlob(
	blob tapreorg.VersionedBlob) (chainhash.Hash, error) {

	var txid chainhash.Hash
	if blob.Version != receiveBlobVersion {
		return txid, fmt.Errorf("unknown receive blob version %d",
			blob.Version)
	}
	if len(blob.Data) != 32 {
		return txid, fmt.Errorf("receive blob has %d bytes",
			len(blob.Data))
	}
	copy(txid[:], blob.Data)

	return txid, nil
}

// receiveSite is the receive side's re-org watcher site: the
// custodian stakes imported proofs, materialized assets and completed
// address events on the sender's anchor transaction, and these
// handlers converge that state to whatever the chain answers.
type receiveSite struct {
	custodian *Custodian
}

// ID returns the site's stable identifier.
func (s *receiveSite) ID() tapreorg.SiteID {
	return ReceiveSiteID
}

// EvaluateCandidate judges a spend of the received transfer's inputs:
// only the exact anchor transaction the proofs attest satisfies the
// anchoring. A replacement published by the sender is foreign here —
// the receiver cannot validate it without a new proof, which arrives
// as a fresh receive with its own anchoring while this one abandons.
func (s *receiveSite) EvaluateCandidate(match tapreorg.VersionedBlob,
	spendingTx *wire.MsgTx) (tapreorg.Verdict, error) {

	anchorTxid, err := decodeReceiveBlob(match)
	if err != nil {
		return 0, err
	}

	if spendingTx.TxHash() == anchorTxid {
		return tapreorg.VerdictSatisfies, nil
	}

	return tapreorg.VerdictForeign, nil
}

// reconfirm converges received state to the current witness. The
// re-stamped database proofs are mirrored to the file tree through
// the outbox.
func (s *receiveSite) reconfirm(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	anchorTxid, err := decodeReceiveBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	blockContext, err := tapreorg.VerifiedProofContext(
		anchoring, anchoring.Phase,
	)
	if err != nil {
		return err
	}
	if blockContext.AnchorTxID() != anchorTxid {
		return fmt.Errorf(
			"witness transaction %v does not match "+
				"receive anchor %v",
			blockContext.AnchorTxID(), anchorTxid,
		)
	}

	restamped, err := s.custodian.cfg.AnchoringLog.ApplyReceiveReconfirm(
		ctx, tx.Queries(), blockContext,
	)
	if err != nil {
		return err
	}

	return enqueueMirrorSync(
		ctx, tx, anchoring, proof.MirrorSyncRewrite, restamped,
	)
}

// OnWitnessed converges the receive to a confirmed anchor, refreshed
// block context included.
func (s *receiveSite) OnWitnessed(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	return s.reconfirm(ctx, tx, anchoring)
}

// OnUnwitnessed withdraws the recorded confirmation: soft downgrade
// only.
func (s *receiveSite) OnUnwitnessed(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	anchorTxid, err := decodeReceiveBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	return s.custodian.cfg.AnchoringLog.ApplyReceiveUnconfirm(
		ctx, tx.Queries(), anchorTxid,
	)
}

// OnConflicted takes the same soft action as OnUnwitnessed: the
// foreign spend can itself re-org out.
func (s *receiveSite) OnConflicted(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	anchorTxid, err := decodeReceiveBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	return s.custodian.cfg.AnchoringLog.ApplyReceiveUnconfirm(
		ctx, tx.Queries(), anchorTxid,
	)
}

// OnBuried converges to act-level confirmation. The receive side
// emits nothing across trust boundaries, so burial is simply the
// final convergent confirmation.
func (s *receiveSite) OnBuried(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	return s.reconfirm(ctx, tx, anchoring)
}

// OnAbandoned compensates: the sender's anchor transaction was
// decided against with act-level finality, so the received assets
// never materialized on the surviving chain. The deleted database
// proofs are shed from the file mirror through the outbox.
func (s *receiveSite) OnAbandoned(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	anchorTxid, err := decodeReceiveBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	deleted, err := s.custodian.cfg.AnchoringLog.ApplyReceiveAbandonment(
		ctx, tx.Queries(), anchorTxid,
		int16(address.StatusTransactionDetected),
	)
	if err != nil {
		return err
	}

	return enqueueMirrorSync(
		ctx, tx, anchoring, proof.MirrorSyncDelete, deleted,
	)
}

// A compile-time assertion that the receive site satisfies the site
// contract.
var _ tapreorg.Site = (*receiveSite)(nil)

// ErrAnchoringAbandoned marks a proof file refused for import because
// the receive site's anchoring for its tip anchor transaction has been
// abandoned: the chain decided against that transaction with act-level
// finality and the site's compensation withdrew whatever the file had
// materialized, so importing it again would resurrect state the chain
// discarded.
var ErrAnchoringAbandoned = errors.New("receive anchoring abandoned")

// RefuseAbandonedReceive returns ErrAnchoringAbandoned when the receive
// site holds an abandoned anchoring for the file's tip anchor
// transaction. It guards the import paths that could re-materialize
// compensated state: the custodian's archive assertion, fed by a local
// universe that keeps the proof past the abandonment, and the
// RegisterTransfer RPC. A nil watcher checks nothing.
//
// The check is an early refusal, not the authoritative one: it runs
// outside the stake's transaction, so an abandonment that lands after
// it is caught by the registry, which refuses an own-stake attach onto
// an abandoned anchoring inside the registration transaction.
func RefuseAbandonedReceive(ctx context.Context,
	watcher tapreorg.Registrar, file *proof.File) error {

	if watcher == nil || file.IsEmpty() {
		return nil
	}

	tip, err := file.LastProof()
	if err != nil {
		return fmt.Errorf("unable to read tip proof: %w", err)
	}
	anchorTxid := tip.AnchorTx.TxHash()

	anchoring, err := watcher.LookupByMatchKey(
		ctx, ReceiveSiteID, anchorTxid.CloneBytes(),
	)
	if err != nil {
		return fmt.Errorf("unable to look up receive anchoring: %w",
			err)
	}
	if anchoring == nil {
		return nil
	}

	if _, abandoned := anchoring.Phase.(tapreorg.Abandoned); abandoned {
		return fmt.Errorf("%w: anchor tx %v", ErrAnchoringAbandoned,
			anchorTxid)
	}

	return nil
}

// AnchoringSite returns the custodian's site implementation, for
// registration with the re-org watcher.
func (c *Custodian) AnchoringSite() tapreorg.Site {
	return &receiveSite{custodian: c}
}

// RegisterReceiveAnchoring stakes a received proof file on every anchor
// transaction in its proof DAG that has not crossed the safety depth. The
// registrations and the caller's shared phase-1 write form one transaction.
// Registration is idempotent per anchor transaction, including when the same
// transaction occurs at several proof positions.
//
// The phase-1 write is the received stake itself (StakeReceive passes the
// proof import), and it runs once whether the registrations are new or attach
// to existing anchor transactions. A nil phase-1 registers custody alone.
//
// Each transition's own confirmation seeds its anchoring: the verified file
// attests the anchor tx at a block, so the registration carries that as the
// candidate spend and is born delivered Witnessed on it, inside the
// registration transaction. The state the stake materialized then
// starts on the phase it already reflects — which is what makes a
// second registration for the same anchor tx (another output of the
// same send, a retried RegisterTransfer) harmless: the attach
// re-delivers Witnessed rather than the registry's default
// Unwitnessed, which would withdraw the stake's confirmation until
// the sensor's first pass. The watcher's conf subscription on the
// seed certifies act crossing and detects re-org-out, and its
// adoption-time verification downgrades a seed whose block has gone
// stale in the meantime.
//
// A transition whose trigger set cannot be derived because it is a genesis
// registers on the seed alone: there is no prior outpoint for a foreign
// spender to foreclose against. It therefore needs block context; without it
// there is nothing to stake on and ErrUnwatchable is returned.
func (c *Custodian) RegisterReceiveAnchoring(ctx context.Context,
	file *proof.File, phase1 tapreorg.BatchPhase1Func) error {

	return c.registerReceiveAnchoring(ctx, file, nil, phase1)
}

// registerReceiveAnchoring is RegisterReceiveAnchoring with an optional set
// of transaction identities owned by another local site. Exclusions are used
// only by upgrade adoption; a new receive stakes its whole DAG normally.
func (c *Custodian) registerReceiveAnchoring(ctx context.Context,
	file *proof.File, excluded map[chainhash.Hash]struct{},
	phase1 tapreorg.BatchPhase1Func) error {

	specs, err := receiveRegistrationSpecsExcept(
		file, c.cfg.AnchoringThreshold,
		c.cfg.AnchoringWatcher.BestHeight(), excluded,
	)
	if err != nil {
		return err
	}
	if len(specs) == 0 {
		return ErrNoYoungAnchors
	}

	_, err = c.cfg.AnchoringWatcher.RegisterBatch(ctx, specs, phase1)
	if err != nil {
		return fmt.Errorf("unable to register receive anchorings: "+
			"%w", err)
	}

	return nil
}

// AdoptProofs restores watcher coverage for proof files that predate atomic
// staking. Native mint and porter anchors are excluded so their own startup
// adoption retains the compensation semantics of the state they created.
// Unknown anchors are ordinary proof custody and belong to the receive site.
//
// A file whose tip has crossed the safety depth holds nothing young: a
// spender confirms no earlier than its inputs. Such files are neither
// fetched, since the database is asked only for tips still within the
// depth or of unknown height, nor read past their tip when the decoded
// file says the same. Anchors the receive site already stakes are
// skipped too, so a repeated pass registers nothing and re-delivers
// nothing. A file whose contents cannot be adopted — undecodable, or a
// young transition with nothing to stake on — is logged and left rather
// than allowed to keep the daemon from starting; failures of the database
// or the registry are returned, as is a context that ends mid-pass.
func (c *Custodian) AdoptProofs(ctx context.Context) error {
	if c.cfg.ProofAdoptionLog == nil {
		return errors.New("proof adoption log is not configured")
	}

	// Only files whose tip is still young can hold anything to adopt,
	// so the database is asked for those alone.
	bestHeight := c.cfg.AnchoringWatcher.BestHeight()
	blobs, err := c.cfg.ProofAdoptionLog.ProofsForAdoption(
		ctx, tapreorg.ProtectionFloor(
			bestHeight, c.cfg.AnchoringThreshold,
		),
	)
	if err != nil {
		return fmt.Errorf("unable to list proofs for adoption: %w", err)
	}

	var adopted, skipped int
	for proofIdx, blob := range blobs {
		// Decoding a file consults nothing that carries the context,
		// so a shutdown is honoured between files.
		if err := ctx.Err(); err != nil {
			return err
		}

		specs, err := c.adoptionSpecs(ctx, blob, bestHeight)
		switch {
		case errors.Is(err, errAdoptionData):
			log.Warnf("Proof %d not adopted: %v", proofIdx, err)
			skipped++
			continue

		case err != nil:
			return fmt.Errorf("unable to adopt proof %d: %w",
				proofIdx, err)

		case len(specs) == 0:
			continue
		}

		_, err = c.cfg.AnchoringWatcher.RegisterBatch(ctx, specs, nil)
		if err != nil {
			return fmt.Errorf("unable to adopt proof %d: %w",
				proofIdx, err)
		}
		adopted++
	}

	if adopted > 0 || skipped > 0 {
		log.Infof("Adopted %d proof file(s) into receive custody, "+
			"skipped %d", adopted, skipped)
	}

	return nil
}

// errAdoptionData marks a proof file adoption cannot act on because of what
// it contains, as opposed to a failure of the database or the registry.
var errAdoptionData = errors.New("proof file cannot be adopted")

// errAdoptionStore marks a failure of the persistence adoption consults
// while classifying a file.
var errAdoptionStore = errors.New("adoption persistence")

// adoptionSpecs derives the registrations a stored file still needs: its
// young anchors that no native site claims and that the receive site does
// not already stake. Problems with the file itself are reported as
// errAdoptionData.
func (c *Custodian) adoptionSpecs(ctx context.Context, blob proof.Blob,
	bestHeight uint32) ([]tapreorg.RegistrationSpec, error) {

	file, err := blob.AsFile()
	if err != nil {
		return nil, fmt.Errorf("%w: decoding: %w", errAdoptionData, err)
	}

	// The tip is the file's youngest transition.
	tip, err := file.LastProof()
	if err != nil {
		return nil, fmt.Errorf("%w: reading tip: %w", errAdoptionData,
			err)
	}
	if !tapreorg.AnchorNeedsProtection(
		bestHeight, tip.BlockHeight, c.cfg.AnchoringThreshold,
	) {

		return nil, nil
	}

	excluded := make(map[chainhash.Hash]struct{})
	classified := make(map[chainhash.Hash]struct{})
	err = walkReceiveProofDAG(file, func(current, _ *proof.Proof) error {
		if !tapreorg.AnchorNeedsProtection(
			bestHeight, current.BlockHeight,
			c.cfg.AnchoringThreshold,
		) {

			return nil
		}

		txID := current.AnchorTx.TxHash()
		if _, ok := classified[txID]; ok {
			return nil
		}
		classified[txID] = struct{}{}

		existing, err := c.cfg.AnchoringWatcher.LookupByMatchKey(
			ctx, ReceiveSiteID, txID.CloneBytes(),
		)
		if err != nil {
			return fmt.Errorf("%w: looking up anchor %v: %w",
				errAdoptionStore, txID, err)
		}
		if existing != nil {
			excluded[txID] = struct{}{}
			return nil
		}

		ownership, err := c.cfg.ProofAdoptionLog.ProofAnchorOwnership(
			ctx, txID,
		)
		if err != nil {
			return fmt.Errorf("%w: classifying anchor %v: %w",
				errAdoptionStore, txID, err)
		}
		if !ownership.NeedsReceiveAdoption() {
			excluded[txID] = struct{}{}
		}

		return nil
	})
	switch {
	case errors.Is(err, errAdoptionStore):
		return nil, err

	case err != nil:
		return nil, fmt.Errorf("%w: classifying: %w", errAdoptionData,
			err)
	}

	specs, err := receiveRegistrationSpecsExcept(
		file, c.cfg.AnchoringThreshold, bestHeight, excluded,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errAdoptionData, err)
	}

	return specs, nil
}

// receiveRegistrationSpecs derives one transaction-level registration for
// each young anchor in a proof DAG, in dependency-first order. Repeated proof
// positions for one anchor transaction are folded into one registration whose
// trigger set is the union of the evidence those positions carry.
func receiveRegistrationSpecs(file *proof.File, threshold,
	bestHeight uint32) ([]tapreorg.RegistrationSpec, error) {

	return receiveRegistrationSpecsExcept(
		file, threshold, bestHeight, nil,
	)
}

// receiveRegistrationSpecsExcept is receiveRegistrationSpecs with an
// ownership exclusion set used by the legacy adopter.
func receiveRegistrationSpecsExcept(file *proof.File, threshold,
	bestHeight uint32, excluded map[chainhash.Hash]struct{}) (
	[]tapreorg.RegistrationSpec, error) {

	if file.NumProofs() == 0 {
		return nil, errors.New("empty proof file")
	}

	positions := make(map[chainhash.Hash]int)
	var specs []tapreorg.RegistrationSpec
	err := walkReceiveProofDAG(file, func(current,
		previous *proof.Proof) error {

		if !tapreorg.AnchorNeedsProtection(
			bestHeight, current.BlockHeight, threshold,
		) {

			return nil
		}

		txID := current.AnchorTx.TxHash()
		if _, skip := excluded[txID]; skip {
			return nil
		}

		spec, err := receiveRegistrationSpecForProof(
			current, previous, threshold,
		)
		if err != nil {
			return err
		}

		position, ok := positions[txID]
		if !ok {
			positions[txID] = len(specs)
			specs = append(specs, spec)

			return nil
		}

		return mergeReceiveRegistration(&specs[position], spec)
	})
	if err != nil {
		return nil, fmt.Errorf("deriving proof DAG registrations: "+
			"%w", err)
	}

	return specs, nil
}

// walkReceiveProofDAG visits every proof occurrence dependency-first, carrying
// the preceding proof from the same file when one exists.
func walkReceiveProofDAG(file *proof.File,
	visit func(current, previous *proof.Proof) error) error {

	var previous *proof.Proof
	for proofIdx := 0; proofIdx < file.NumProofs(); proofIdx++ {
		current, err := file.ProofAt(uint32(proofIdx))
		if err != nil {
			return fmt.Errorf(
				"decoding proof %d: %w", proofIdx, err,
			)
		}

		for inputIdx := range current.AdditionalInputs {
			err := walkReceiveProofDAG(
				&current.AdditionalInputs[inputIdx], visit,
			)
			if err != nil {
				return fmt.Errorf(
					"walking input %d of proof %d: %w",
					inputIdx, proofIdx, err,
				)
			}
		}

		if err := visit(current, previous); err != nil {
			return fmt.Errorf(
				"visiting proof %d: %w", proofIdx, err,
			)
		}
		previous = current
	}

	return nil
}

// mergeReceiveRegistration combines proof occurrences of one anchor
// transaction. Conflicting chain locations or trigger descriptions are
// rejected instead of letting traversal order choose the watch.
func mergeReceiveRegistration(existing *tapreorg.RegistrationSpec,
	next tapreorg.RegistrationSpec) error {

	if existing.SeedCandidate == nil || next.SeedCandidate == nil {
		if existing.SeedCandidate != next.SeedCandidate {
			return errors.New(
				"anchor transaction has conflicting " +
					"confirmation contexts",
			)
		}
	} else {
		a := existing.SeedCandidate.W
		b := next.SeedCandidate.W
		sameLocation := a.TxHash() == b.TxHash() &&
			a.BlockHash() == b.BlockHash() &&
			a.Height() == b.Height() && a.TxIndex() == b.TxIndex()
		if !sameLocation {
			return errors.New(
				"anchor transaction has conflicting " +
					"confirmation contexts",
			)
		}
	}

	points := existing.Triggers.OutPoints()
	positions := make(map[wire.OutPoint]int, len(points))
	for idx := range points {
		positions[points[idx].OutPoint] = idx
	}
	for _, point := range next.Triggers.OutPoints() {
		idx, ok := positions[point.OutPoint]
		if !ok {
			positions[point.OutPoint] = len(points)
			points = append(points, point)
			continue
		}

		prior := points[idx]
		if prior.HeightHint != point.HeightHint ||
			!bytes.Equal(prior.PkScript, point.PkScript) {

			return fmt.Errorf("trigger %v has conflicting evidence",
				point.OutPoint)
		}
	}

	if len(points) == 0 {
		return nil
	}
	triggers, err := tapreorg.NewTriggerSet(points)
	if err != nil {
		return err
	}
	existing.Triggers = triggers

	return nil
}

// receiveRegistrationSpec derives a received file's registration: its
// identity, trigger set and seed.
func receiveRegistrationSpec(file *proof.File,
	threshold uint32) (tapreorg.RegistrationSpec, error) {

	var spec tapreorg.RegistrationSpec

	numProofs := file.NumProofs()
	if numProofs == 0 {
		return spec, fmt.Errorf("empty proof file")
	}

	tip, err := file.ProofAt(uint32(numProofs - 1))
	if err != nil {
		return spec, fmt.Errorf("unable to read tip proof: %w", err)
	}
	var previous *proof.Proof
	if numProofs >= 2 {
		previous, err = file.ProofAt(uint32(numProofs - 2))
		if err != nil {
			return spec, fmt.Errorf(
				"unable to read preceding proof: %w", err,
			)
		}
	}

	return receiveRegistrationSpecForProof(tip, previous, threshold)
}

// receiveRegistrationSpecForProof derives one proof transition's identity,
// trigger set and seed.
func receiveRegistrationSpecForProof(current, previous *proof.Proof,
	threshold uint32) (tapreorg.RegistrationSpec, error) {

	var spec tapreorg.RegistrationSpec
	anchorTxid := current.AnchorTx.TxHash()

	// One anchoring per anchor transaction: a previous receive (or
	// another output of the same send) may already have registered
	// it. The registry resolves that atomically — the duplicate
	// registration attaches to the existing anchoring, unioning any
	// trigger outpoints this file reveals that the first one did
	// not, running this file's own stake, and re-delivering the
	// anchoring's delivered phase so the state this receive just
	// materialized lands on what its siblings already reflect.
	blob := encodeReceiveBlob(anchorTxid)
	spec = tapreorg.RegistrationSpec{
		Site:           ReceiveSiteID,
		MatchData:      blob,
		Payload:        blob,
		MatchKey:       anchorTxid.CloneBytes(),
		Threshold:      threshold,
		Phase1OnAttach: true,
	}

	// A file with derivable asset-bearing triggers watches them:
	// spend subscriptions on the trigger set observe the anchor tx
	// confirming (as the witnessing spender) and any foreign
	// spender as a foreclosure. A file without them (a single-proof
	// genesis receive) has no prior outpoint to watch and stakes on
	// the seed alone.
	points, err := receiveTriggerPointsForProof(previous, current)
	switch {
	case errors.Is(err, ErrNoTriggers):
	case err != nil:
		return spec, err

	default:
		triggers, err := tapreorg.NewTriggerSet(points)
		if err != nil {
			return spec, fmt.Errorf("unable to build trigger "+
				"set: %w", err)
		}
		spec.Triggers = triggers
	}

	// The tip's block context is what the seed stakes on. A tip
	// without it (a stub, or a proof imported before confirmation)
	// cannot seed; with triggers the sensor discovers the
	// confirmation instead, and without them there is nothing to
	// stake on at all. ErrUnwatchable tells callers the latter
	// legibly rather than letting them mistake it for a successful
	// registration.
	switch {
	case current.BlockHeight != 0:
		seed, seedErr := tipSeedCandidate(current)
		if seedErr != nil {
			return spec, fmt.Errorf("unable to build tip seed: "+
				"%w", seedErr)
		}
		spec.SeedCandidate = &seed

	case spec.Triggers.Len() == 0:
		return spec, fmt.Errorf("%w: genesis-shape file with no "+
			"block context (anchor_txid=%v)",
			ErrUnwatchable, anchorTxid)
	}

	return spec, nil
}

// StakeReceive verifies a received proof file and commits its import with all
// young proof-DAG anchorings in one registration transaction. If every anchor
// is already safe, it imports without creating watcher state. A file the
// watcher has abandoned is refused before anything runs, and again by the
// registry inside the stake's transaction should the abandonment land in
// between; an unwatchable young transition is refused rather than held.
//
// The proof-file mirror is written for the proofs the stake imported
// once the transaction commits, and the proof event subscribers are
// told of them then, outside the transaction. A proof already held —
// a re-driven registration after a crash, a self-send the porter
// materialized — is staked without being imported or announced
// again.
func (c *Custodian) StakeReceive(ctx context.Context,
	annotated *proof.AnnotatedProof) error {

	return c.StakeReceiveWithGroupVerifier(ctx, annotated, nil)
}

// StakeReceiveWithGroupVerifier is StakeReceive with the caller's group
// verifier in place of the configured one. A restore into a wallet that has
// never seen an asset group can prove the group only from the genesis reveal
// in the proofs it restores; the caller narrows its verifier to keys derived
// from those reveals, which the same verification pass checks. Header,
// merkle and chain verification stay the custodian's. A nil verifier means
// the configured one.
func (c *Custodian) StakeReceiveWithGroupVerifier(ctx context.Context,
	annotated *proof.AnnotatedProof,
	groupVerifier proof.GroupVerifier) error {

	file, err := annotated.Blob.AsFile()
	if err != nil {
		return fmt.Errorf("unable to decode proof file: %w", err)
	}

	err = RefuseAbandonedReceive(ctx, c.cfg.AnchoringWatcher, file)
	if err != nil {
		return err
	}

	// The locator names the proof in the mirror and to subscribers;
	// a caller that only has the blob leaves it to the tip.
	tip, err := file.LastProof()
	if err != nil {
		return fmt.Errorf("unable to read tip proof: %w", err)
	}
	if annotated.AssetID == nil {
		annotated.AssetID = fn.Ptr(tip.Asset.ID())
		annotated.ScriptKey = *tip.Asset.ScriptKey.PubKey
		if tip.Asset.GroupKey != nil {
			annotated.GroupKey = &tip.Asset.GroupKey.GroupPubKey
		}
	}
	if annotated.Locator.OutPoint == nil {
		annotated.Locator.OutPoint = fn.Ptr(tip.OutPoint())
	}

	verifier := c.cfg.ProofVerifier
	if verifier == nil {
		verifier = &proof.BaseVerifier{}
	}
	verified, err := proof.VerifyAnnotatedProofsWithVerifier(
		ctx, verifier, c.verifierCtx(ctx, groupVerifier), annotated,
	)
	if err != nil {
		return fmt.Errorf("unable to verify received proof: %w", err)
	}

	var imported []proof.Blob
	var safeImport bool
	phase1 := func(ctx context.Context, tx tapreorg.RegistryTx,
		_ []tapreorg.AnchoringID) error {

		var err error
		imported, err = c.cfg.AnchoringLog.StakeReceivedProofs(
			ctx, tx, verified...,
		)

		return err
	}
	err = c.RegisterReceiveAnchoring(ctx, file, phase1)
	switch {
	case errors.Is(err, tapreorg.ErrAnchoringAbandoned):
		return fmt.Errorf("%w: anchor tx %v", ErrAnchoringAbandoned,
			tip.AnchorTx.TxHash())

	case errors.Is(err, ErrNoYoungAnchors):
		imported, err = c.cfg.AnchoringLog.StoreReceivedProofs(
			ctx, verified...,
		)
		if err != nil {
			return fmt.Errorf(
				"unable to store safe received proof: %w", err,
			)
		}
		safeImport = true

	case err != nil:
		return err
	}
	if safeImport {
		c.cfg.AnchoringWatcher.KickOutbox()
	}
	if len(imported) == 0 {
		return nil
	}

	// The mirror trails the database: a write lost here is repaired
	// by the mirror-sync effect the receive site enqueued with the
	// stake's delivery.
	if c.cfg.ProofFiles != nil {
		err := c.cfg.ProofFiles.ImportVerifiedProofs(
			ctx, false, verified...,
		)
		if err != nil {
			log.Warnf("Unable to mirror received proof file, "+
				"mirror sync will repair: %v", err)
		}
	}

	c.cfg.AnchoringLog.NotifyProofs(imported...)

	return nil
}

// tipSeedCandidate builds a fully-enriched candidate spend from a
// proof file's tip. All the required data lives in the proof: the
// anchor tx, its confirmation block header + height, and its merkle
// proof (which also encodes the tx's index within the block). The
// candidate is on-chain and not act-certified; certification and
// re-org sensing follow through the watcher's conf subscription on
// the anchor tx.
func tipSeedCandidate(tip *proof.Proof) (tapreorg.CandidateSpend, error) {
	blockHash := tip.BlockHeader.BlockHash()
	txIndex := tip.TxMerkleProof.TxIndex()

	witness, err := tapreorg.NewWitness(
		&tip.AnchorTx, blockHash, tip.BlockHeight, txIndex,
	)
	if err != nil {
		return tapreorg.CandidateSpend{}, fmt.Errorf("unable to "+
			"build witness: %w", err)
	}

	header := tip.BlockHeader
	merkle := tip.TxMerkleProof

	return tapreorg.CandidateSpend{
		W:            witness,
		Verdict:      tapreorg.VerdictSatisfies,
		OnChain:      true,
		BlockHeader:  &header,
		MerkleProof:  &merkle,
		ActCertified: false,
	}, nil
}

// ErrNoTriggers marks a proof file from which no asset-bearing
// trigger set can be derived (a single-proof genesis file has no
// asset-bearing inputs). It is an internal signal from
// receiveTriggerPoints to RegisterReceiveAnchoring, which then stakes
// on the tip's seed alone rather than watching for a witnessing
// spender.
var ErrNoTriggers = fmt.Errorf("no derivable trigger outpoints")

// ErrNoYoungAnchors reports that every anchor transaction in a received proof
// DAG has already crossed the configured safety depth. No watcher state is
// needed, so StakeReceive imports the verified proof directly.
var ErrNoYoungAnchors = fmt.Errorf("proof DAG has no young anchors")

// ErrUnwatchable is returned by RegisterReceiveAnchoring when a young proof
// transition carries no trigger or chain context to stake on. The canonical
// case is a genesis proof imported before its anchor transaction confirmed.
var ErrUnwatchable = fmt.Errorf("proof file is not watchable")

// receiveTriggerPoints derives the anchoring's trigger set from a
// proof file: the tip transition's previous asset outpoint (script
// recovered from the preceding proof) plus the tips of any
// additional-input files, each admitted only if the tip's anchor
// transaction actually spends it. The file's shape is the sender's
// to choose, and an additional-input file the anchor transaction
// never spends is an outpoint nothing about this receive turns on;
// admitting it would register a trigger the witnessing transaction
// does not cover, which the registry's whole-set rule then refuses.
// Drawing triggers from the anchor transaction's own inputs is what
// makes a verified file unrefusable.
//
// ErrNoTriggers is reserved for a genuine genesis: an asset with no
// asset-bearing previous outpoints at all, which therefore has nothing
// for a foreign spender to foreclose against and must be staked by
// seeding its anchor transaction instead.
//
// The distinction is deliberately drawn from the asset's witnesses
// rather than from the file's length. A file's first proof is exempt
// from the linkage check that binds each proof to its predecessor, so
// a single-proof file whose provenance lives entirely in
// AdditionalInputs verifies perfectly well — and the file's shape is
// the sender's to choose. Gating on the proof count alone therefore
// let a counterparty select the seed path for an ordinary transfer,
// and with it an anchoring that has no trigger set, opens no spend
// subscriptions, and so can never reach Abandoned: the receiver would
// keep materialized assets for a transaction the chain had discarded.
func receiveTriggerPoints(file *proof.File,
	tip *proof.Proof) ([]tapreorg.TriggerOutPoint, error) {

	var previous *proof.Proof
	if numProofs := file.NumProofs(); numProofs >= 2 {
		var err error
		previous, err = file.ProofAt(uint32(numProofs - 2))
		if err != nil {
			return nil, fmt.Errorf(
				"unable to read preceding proof: %w", err,
			)
		}
	}

	return receiveTriggerPointsForProof(previous, tip)
}

// receiveTriggerPointsForProof derives one transition's trigger set from its
// preceding proof and additional-input files.
func receiveTriggerPointsForProof(previous,
	tip *proof.Proof) ([]tapreorg.TriggerOutPoint, error) {

	var points []tapreorg.TriggerOutPoint

	// Triggers are chain-level outpoints, so inputs sharing one
	// outpoint (several asset leaves under a single UTXO, merged in
	// one transition) contribute a single point.
	seen := make(map[wire.OutPoint]struct{})

	// The anchor transaction's inputs bound the trigger set.
	spends := make(map[wire.OutPoint]struct{}, len(tip.AnchorTx.TxIn))
	for _, txIn := range tip.AnchorTx.TxIn {
		spends[txIn.PreviousOutPoint] = struct{}{}
	}

	// The tip's own previous outpoint, whose script has to be read
	// out of the proof that precedes it in the file. A single-proof
	// file has no predecessor and so contributes nothing here; its
	// inputs, if it has any, arrive below.
	if previous != nil {
		prevOut := tip.PrevOut
		if int(prevOut.Index) >= len(previous.AnchorTx.TxOut) {
			return nil, fmt.Errorf("previous outpoint index %d "+
				"out of range", prevOut.Index)
		}

		if _, spent := spends[prevOut]; spent {
			points = append(points, tapreorg.TriggerOutPoint{
				OutPoint: prevOut,
				PkScript: previous.AnchorTx.
					TxOut[prevOut.Index].PkScript,
				HeightHint: previous.BlockHeight,
			})
			seen[prevOut] = struct{}{}
		}
	}

	for idx := range tip.AdditionalInputs {
		inputFile := &tip.AdditionalInputs[idx]
		numInput := inputFile.NumProofs()
		if numInput == 0 {
			continue
		}
		inputTip, err := inputFile.ProofAt(uint32(numInput - 1))
		if err != nil {
			return nil, fmt.Errorf("unable to read additional "+
				"input tip: %w", err)
		}

		op := inputTip.OutPoint()
		if _, ok := seen[op]; ok {
			continue
		}
		if _, spent := spends[op]; !spent {
			continue
		}
		seen[op] = struct{}{}

		outputIndex := inputTip.InclusionProof.OutputIndex
		if int(outputIndex) >= len(inputTip.AnchorTx.TxOut) {
			return nil, fmt.Errorf("inclusion output index %d "+
				"out of range", outputIndex)
		}

		points = append(points, tapreorg.TriggerOutPoint{
			OutPoint: op,
			PkScript: inputTip.AnchorTx.
				TxOut[outputIndex].PkScript,
			HeightHint: inputTip.BlockHeight,
		})
	}

	if len(points) == 0 {
		// Only a genesis legitimately has nothing to watch. A
		// transition that spends asset inputs but yielded no
		// trigger outpoints is malformed, and staking it as a
		// seed would register an anchoring that can never be
		// abandoned, so it is refused rather than downgraded.
		if !tip.Asset.IsGenesisAsset() {
			return nil, fmt.Errorf("%w: non-genesis proof "+
				"yielded no trigger outpoints",
				ErrUnwatchable)
		}

		return nil, ErrNoTriggers
	}

	return points, nil
}
