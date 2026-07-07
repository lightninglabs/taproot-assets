package tapcustody

import (
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

// ReceiveAnchoringLog is the transaction-scoped persistence surface
// the receive site drives from its handlers, implemented by the asset
// store.
type ReceiveAnchoringLog interface {
	// ApplyReceiveReconfirm converges received state to a
	// (re)confirmed anchor.
	ApplyReceiveReconfirm(ctx context.Context, q *sqlc.Queries,
		anchorTxid chainhash.Hash, blockHash chainhash.Hash,
		blockHeight, txIndex uint32, header wire.BlockHeader,
		merkle proof.TxMerkleProof) error

	// ApplyReceiveUnconfirm withdraws the recorded confirmation.
	ApplyReceiveUnconfirm(ctx context.Context, q *sqlc.Queries,
		anchorTxid chainhash.Hash) error

	// ApplyReceiveAbandonment compensates an abandoned receive.
	ApplyReceiveAbandonment(ctx context.Context, q *sqlc.Queries,
		anchorTxid chainhash.Hash, resetStatus int16) error

	// StakeReceivedProofs imports verified received proofs on the
	// registration transaction, skipping any already held, and
	// returns the blobs it imported.
	StakeReceivedProofs(ctx context.Context, tx tapreorg.RegistryTx,
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

// VerifiedProofWriter is the proof-file mirror: it stores verified
// proofs without re-validating them.
type VerifiedProofWriter interface {
	// ImportVerifiedProofs stores verified proofs; with replace set
	// the proof is expected to exist already.
	ImportVerifiedProofs(ctx context.Context, replace bool,
		proofs ...proof.VerifiedAnnotatedProof) error
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

// reconfirm converges received state to the current witness.
func (s *receiveSite) reconfirm(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	anchorTxid, err := decodeReceiveBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	witness, err := tapreorg.WitnessContext(anchoring, anchoring.Phase)
	if err != nil {
		return err
	}

	return s.custodian.cfg.AnchoringLog.ApplyReceiveReconfirm(
		ctx, tx.Queries(), anchorTxid, witness.W.BlockHash(),
		witness.W.Height(), witness.W.TxIndex(),
		*witness.BlockHeader, *witness.MerkleProof,
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
// never materialized on the surviving chain.
func (s *receiveSite) OnAbandoned(ctx context.Context,
	tx tapreorg.RegistryTx, anchoring *tapreorg.Anchoring) error {

	anchorTxid, err := decodeReceiveBlob(anchoring.Payload)
	if err != nil {
		return err
	}

	return s.custodian.cfg.AnchoringLog.ApplyReceiveAbandonment(
		ctx, tx.Queries(), anchorTxid,
		int16(address.StatusTransactionDetected),
	)
}

// A compile-time assertion that the receive site satisfies the site
// contract.
var _ tapreorg.Site = (*receiveSite)(nil)

// AnchoringSite returns the custodian's site implementation, for
// registration with the re-org watcher.
func (c *Custodian) AnchoringSite() tapreorg.Site {
	return &receiveSite{custodian: c}
}

// RegisterReceiveAnchoring stakes a received proof file's state on
// its tip anchor transaction, running the caller's phase-1 write in
// the registration transaction. The trigger set is derived from the
// file itself: the anchor transaction's asset-bearing inputs, with
// their scripts recovered from the preceding proof in the file and
// from the tips of any additional-input files. Every trigger is an
// outpoint the tip transaction spends, so a verified file is never
// refused by the registry's whole-set rule. Registration is
// idempotent per anchor transaction — receives sharing the anchor
// share the anchoring.
//
// The phase-1 write is the received stake itself (StakeReceive passes
// the proof import), and it runs on an attach as well as on a fresh
// registration (Phase1OnAttach): each output of a send is its own
// file and its own stake, and the custody covering it commits in the
// same transaction either way. A nil phase-1 registers custody alone.
//
// The tip's own confirmation seeds the anchoring: the file attests
// the anchor tx at a block the import verified against the chain, so
// the registration carries that confirmation as the anchoring's
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
// A file whose trigger set cannot be derived (a single-proof genesis
// file has no asset-bearing inputs) registers on the seed alone —
// there is no prior outpoint for a foreign spender to foreclose
// against — and so needs the block context; without it there is
// nothing to stake on and ErrUnwatchable is returned.
func (c *Custodian) RegisterReceiveAnchoring(ctx context.Context,
	file *proof.File, phase1 func(context.Context, tapreorg.RegistryTx,
		tapreorg.AnchoringID) error) error {

	spec, err := receiveRegistrationSpec(file, c.cfg.AnchoringThreshold)
	if err != nil {
		return err
	}

	_, err = c.cfg.AnchoringWatcher.Register(ctx, spec, phase1)
	if err != nil {
		return fmt.Errorf("unable to register receive "+
			"anchoring: %w", err)
	}

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
	anchorTxid := tip.AnchorTx.TxHash()

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
	points, err := receiveTriggerPoints(file, tip)
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
	case tip.BlockHeight != 0:
		seed, seedErr := tipSeedCandidate(tip)
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

// StakeReceive verifies a received proof file and commits its import
// and its anchoring in one registration transaction, so the receiver
// never holds an asset the watcher does not hold custody of: a
// registration the registry refuses, or any other failure inside the
// transaction, rolls the import back with it. An unwatchable file is
// refused rather than held.
//
// The proof-file mirror is written for the proofs the stake imported
// once the transaction commits, and the proof event subscribers are
// told of them then, outside the transaction. A proof already held —
// a re-driven registration after a crash, a self-send the porter
// materialized — is staked without being imported or announced
// again.
func (c *Custodian) StakeReceive(ctx context.Context,
	annotated *proof.AnnotatedProof) error {

	file, err := annotated.Blob.AsFile()
	if err != nil {
		return fmt.Errorf("unable to decode proof file: %w", err)
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
		ctx, verifier, c.verifierCtx(ctx), annotated,
	)
	if err != nil {
		return fmt.Errorf("unable to verify received proof: %w", err)
	}

	var imported []proof.Blob
	phase1 := func(ctx context.Context, tx tapreorg.RegistryTx,
		_ tapreorg.AnchoringID) error {

		var err error
		imported, err = c.cfg.AnchoringLog.StakeReceivedProofs(
			ctx, tx, verified...,
		)

		return err
	}
	if err := c.RegisterReceiveAnchoring(ctx, file, phase1); err != nil {
		return err
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

// ErrUnwatchable is returned by RegisterReceiveAnchoring when the
// proof file's tip carries no chain context we can stake on — the
// canonical case is a single-proof genesis file imported before its
// anchor transaction confirmed. The registration is a non-event, not
// a failure: callers typically log and continue, but the typed
// signal lets them distinguish "watched" from "un-watched" outcomes
// without conflating both with a nil return.
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
	if numProofs := file.NumProofs(); numProofs >= 2 {
		prev, err := file.ProofAt(uint32(numProofs - 2))
		if err != nil {
			return nil, fmt.Errorf("unable to read preceding "+
				"proof: %w", err)
		}
		prevOut := tip.PrevOut
		if int(prevOut.Index) >= len(prev.AnchorTx.TxOut) {
			return nil, fmt.Errorf("previous outpoint index %d "+
				"out of range", prevOut.Index)
		}

		if _, spent := spends[prevOut]; spent {
			points = append(points, tapreorg.TriggerOutPoint{
				OutPoint: prevOut,
				PkScript: prev.AnchorTx.
					TxOut[prevOut.Index].PkScript,
				HeightHint: prev.BlockHeight,
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
