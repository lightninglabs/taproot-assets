package supplycommit

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
)

const (
	// SupplySiteID identifies the supply-commit state machine as a
	// re-org watcher site.
	SupplySiteID tapreorg.SiteID = "supplycommit.committer"

	// CommitPushEffectKind is the outbox effect kind under which a
	// finalized supply commitment is pushed to the remote universes.
	// The push is an irrevocable assertion to receivers that re-check
	// nothing, so it is act-gated: it is enqueued only by the burial
	// handler, after finalization has been committed locally in the
	// same delivery transaction.
	CommitPushEffectKind tapreorg.EffectKind = "supplycommit.push"

	// CommitNudgeEffectKind is the outbox effect kind under which a
	// resting state machine is ticked so it re-derives its position
	// from the durable record. The abandonment handler enqueues it
	// after returning a foreclosed commitment's updates to the
	// pipeline, so the next cycle starts unattended.
	CommitNudgeEffectKind tapreorg.EffectKind = "supplycommit.nudge"

	// supplyBlobVersion versions the supply site's anchoring blobs.
	supplyBlobVersion = 1

	// nudgeBlobVersion versions the nudge effect's payload.
	nudgeBlobVersion = 1
)

// supplyBlob is the supply site's anchoring blob: the commit
// transaction plus the asset group it commits for, so the finalize
// event can be routed to the right state machine.
type supplyBlob struct {
	// CommitTxid is the broadcast commitment transaction.
	CommitTxid chainhash.Hash

	// GroupKey is the asset group's serialized key.
	GroupKey [33]byte
}

// encodeSupplyBlob encodes a supply blob.
func encodeSupplyBlob(blob supplyBlob) tapreorg.VersionedBlob {
	data := make([]byte, 0, 32+33)
	data = append(data, blob.CommitTxid[:]...)
	data = append(data, blob.GroupKey[:]...)

	return tapreorg.VersionedBlob{
		Version: supplyBlobVersion,
		Data:    data,
	}
}

// decodeSupplyBlob decodes a supply blob of any version the site has
// ever written.
func decodeSupplyBlob(blob tapreorg.VersionedBlob) (supplyBlob, error) {
	var out supplyBlob
	if blob.Version != supplyBlobVersion {
		return out, fmt.Errorf("unknown supply blob version %d",
			blob.Version)
	}
	if len(blob.Data) != 32+33 {
		return out, fmt.Errorf("supply blob has %d bytes",
			len(blob.Data))
	}
	copy(out.CommitTxid[:], blob.Data[:32])
	copy(out.GroupKey[:], blob.Data[32:])

	return out, nil
}

// nudgeBlob is the nudge effect's payload: the asset group whose state
// machine should re-derive its position from the durable record.
type nudgeBlob struct {
	// GroupKey is the asset group's serialized key.
	GroupKey [33]byte
}

// encodeNudgeBlob encodes a nudge blob.
func encodeNudgeBlob(blob nudgeBlob) tapreorg.VersionedBlob {
	data := make([]byte, 0, 33)
	data = append(data, blob.GroupKey[:]...)

	return tapreorg.VersionedBlob{
		Version: nudgeBlobVersion,
		Data:    data,
	}
}

// decodeNudgeBlob decodes a nudge blob of any version the site has ever
// written.
func decodeNudgeBlob(blob tapreorg.VersionedBlob) (nudgeBlob, error) {
	var out nudgeBlob
	if blob.Version != nudgeBlobVersion {
		return out, fmt.Errorf("unknown nudge blob version %d",
			blob.Version)
	}
	if len(blob.Data) != 33 {
		return out, fmt.Errorf("nudge blob has %d bytes",
			len(blob.Data))
	}
	copy(out.GroupKey[:], blob.Data)

	return out, nil
}

// AnchoringRegistrar is the surface of the re-org watcher the supply
// machinery uses to stake a broadcast commitment as a speculative
// anchoring. Implemented by *tapreorg.Watcher.
type AnchoringRegistrar interface {
	// Register stakes a new anchoring.
	Register(ctx context.Context, spec tapreorg.RegistrationSpec,
		phase1 func(context.Context, tapreorg.RegistryTx,
			tapreorg.AnchoringID) error) (tapreorg.AnchoringID,
		error)

	// AllAnchorings lists the site's anchorings across every phase,
	// settled ones included.
	AllAnchorings(ctx context.Context,
		site tapreorg.SiteID) ([]*tapreorg.Anchoring, error)

	// LookupByMatchKey returns the site's existing anchoring for
	// this per-site identity key, or (nil, nil) if none.
	LookupByMatchKey(ctx context.Context, site tapreorg.SiteID,
		matchKey []byte) (*tapreorg.Anchoring, error)
}

// SupplyAnchoringLog is the supply site's persistence surface,
// implemented by the tapdb supply-commit store. The q-scoped methods
// run inside the re-org watcher's delivery transaction; the fetch
// runs in its own read transaction, from the push dispatcher.
type SupplyAnchoringLog interface {
	// ApplyCommitFinalize finalizes the pending transition whose
	// commitment transaction is commitTxid, reconstructing it from
	// durable state and the given chain proof. Convergent.
	ApplyCommitFinalize(ctx context.Context, q *sqlc.Queries,
		groupKey *btcec.PublicKey, commitTxid chainhash.Hash,
		chainProof ChainProof) error

	// ApplyCommitAbandonment compensates a commitment the chain
	// decided against: the pending transition is removed and its
	// updates re-enter the pipeline. Convergent.
	ApplyCommitAbandonment(ctx context.Context, q *sqlc.Queries,
		groupKey *btcec.PublicKey, commitTxid chainhash.Hash) error

	// FetchCommitmentPushData loads everything the push dispatcher
	// needs about a finalized commitment: the root commitment, the
	// update events it committed, and its chain proof.
	FetchCommitmentPushData(ctx context.Context,
		groupKey *btcec.PublicKey, commitTxid chainhash.Hash) (
		RootCommitment, []SupplyUpdateEvent, ChainProof, error)
}

// SupplySite is the supply-commit state machine's re-org watcher
// site. Nothing is persisted or emitted before burial, so the
// potency-tier handlers have nothing to converge. Burial performs
// finalization — the same act the legacy machine runs in its finalize
// state — inside the delivery transaction, from durable state alone,
// and act-gates the remote-universe push behind the transactional
// outbox. Abandonment compensates by returning the transition's
// updates to the pipeline, and is surfaced loudly for the operator,
// since it means the commitment's own inputs (prior commitment or
// pre-commitments, which only this daemon controls) were claimed by a
// buried conflicting transaction.
type SupplySite struct {
	// Log is the persistence surface for the site's handlers.
	Log SupplyAnchoringLog
}

// ID returns the site's stable identifier.
func (s *SupplySite) ID() tapreorg.SiteID {
	return SupplySiteID
}

// EvaluateCandidate judges a spend of the commitment's inputs:
// exactly the broadcast commit transaction satisfies.
func (s *SupplySite) EvaluateCandidate(match tapreorg.VersionedBlob,
	spendingTx *wire.MsgTx) (tapreorg.Verdict, error) {

	blob, err := decodeSupplyBlob(match)
	if err != nil {
		return 0, err
	}

	if spendingTx.TxHash() == blob.CommitTxid {
		return tapreorg.VerdictSatisfies, nil
	}

	return tapreorg.VerdictForeign, nil
}

// OnWitnessed is a no-op: nothing is persisted before burial.
func (s *SupplySite) OnWitnessed(_ context.Context, _ tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	log.Debugf("Supply commit anchoring %d witnessed", anchoring.ID)

	return nil
}

// OnUnwitnessed is a no-op: nothing to downgrade.
func (s *SupplySite) OnUnwitnessed(_ context.Context, _ tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	log.Debugf("Supply commit anchoring %d unwitnessed", anchoring.ID)

	return nil
}

// OnConflicted is a no-op at the potency tier.
func (s *SupplySite) OnConflicted(_ context.Context, _ tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	log.Warnf("Supply commit anchoring %d conflicted: a foreign "+
		"transaction spends its inputs", anchoring.ID)

	return nil
}

// OnBuried finalizes the commitment: the commit transaction is
// act-confirmed, so the pending transition is applied to the durable
// supply trees inside this delivery transaction, with the chain proof
// taken from the anchoring's enriched witness. The remote-universe
// push rides the transactional outbox behind the same commit.
func (s *SupplySite) OnBuried(ctx context.Context, tx tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	blob, err := decodeSupplyBlob(anchoring.Payload)
	if err != nil {
		return err
	}
	groupKey, err := btcec.ParsePubKey(blob.GroupKey[:])
	if err != nil {
		return fmt.Errorf("unable to parse group key: %w", err)
	}

	witness, err := supplyWitnessContext(anchoring)
	if err != nil {
		return err
	}
	chainProof := ChainProof{
		Header:      *witness.BlockHeader,
		BlockHeight: witness.W.Height(),
		MerkleProof: *witness.MerkleProof,
		TxIndex:     witness.W.TxIndex(),
	}

	err = s.Log.ApplyCommitFinalize(
		ctx, tx.Queries(), groupKey, blob.CommitTxid, chainProof,
	)
	if err != nil {
		return fmt.Errorf("unable to finalize commitment: %w", err)
	}

	return tx.EnqueueEffect(ctx, tapreorg.OutboxEffect{
		Kind:      CommitPushEffectKind,
		Anchoring: fn.Some(anchoring.ID),
		Payload:   anchoring.Payload,
	})
}

// supplyWitnessContext extracts the buried phase's witness candidate
// with its block enrichment.
func supplyWitnessContext(
	anchoring *tapreorg.Anchoring) (*tapreorg.CandidateSpend, error) {

	var witness tapreorg.Witness
	switch p := anchoring.Phase.(type) {
	case tapreorg.Witnessed:
		witness = p.W

	case tapreorg.Buried:
		witness = p.W

	default:
		return nil, fmt.Errorf("no witness in phase %v",
			anchoring.Phase)
	}

	for idx := range anchoring.Spends {
		candidate := &anchoring.Spends[idx]
		if candidate.W.TxHash() != witness.TxHash() {
			continue
		}
		if candidate.BlockHeader == nil ||
			candidate.MerkleProof == nil {

			return nil, fmt.Errorf("witness %v lacks block "+
				"enrichment", witness.TxHash())
		}

		enriched := *candidate
		enriched.W = witness

		return &enriched, nil
	}

	return nil, fmt.Errorf("witness %v not among candidates",
		witness.TxHash())
}

// OnAbandoned compensates the loss: the pending transition and its
// never-confirmed commitment are removed, and the transition's supply
// updates return to the pipeline to be recommitted by the next cycle,
// which a nudge through the transactional outbox starts unattended.
// The condition is still surfaced loudly — the commitment's own
// inputs (prior commitment or pre-commitments, which only this daemon
// controls) were claimed by a buried conflicting transaction, so the
// next cycle may fail at transaction creation, and the operator
// should know why.
func (s *SupplySite) OnAbandoned(ctx context.Context, tx tapreorg.RegistryTx,
	anchoring *tapreorg.Anchoring) error {

	blob, err := decodeSupplyBlob(anchoring.Payload)
	if err != nil {
		return err
	}
	groupKey, err := btcec.ParsePubKey(blob.GroupKey[:])
	if err != nil {
		return fmt.Errorf("unable to parse group key: %w", err)
	}

	err = s.Log.ApplyCommitAbandonment(
		ctx, tx.Queries(), groupKey, blob.CommitTxid,
	)
	if err != nil {
		return fmt.Errorf("unable to compensate abandoned "+
			"commitment: %w", err)
	}

	log.Errorf("Supply commit anchoring %d ABANDONED: commitment tx "+
		"%v was foreclosed by a buried conflicting transaction; its "+
		"supply updates have been returned to the pipeline, but the "+
		"group's commitment inputs may be gone — operator attention "+
		"required", anchoring.ID, blob.CommitTxid)

	return tx.EnqueueEffect(ctx, tapreorg.OutboxEffect{
		Kind:      CommitNudgeEffectKind,
		Anchoring: fn.Some(anchoring.ID),
		Payload: encodeNudgeBlob(nudgeBlob{
			GroupKey: blob.GroupKey,
		}),
	})
}

// A compile-time assertion that the supply site satisfies the site
// contract.
var _ tapreorg.Site = (*SupplySite)(nil)

// commitAnchoringSpec builds the registration that stakes the supply
// transition on its commit transaction. The trigger set is the
// transaction's commitment-bearing inputs — the prior commitment
// output and the spent pre-commitment outputs — an essential
// identity, since any future commitment must spend them. Their
// scripts and confirmation heights come from the durable record
// rather than from anything held only in memory, so the spec is the
// same whether built at signing or rebuilt after a restart: the prior
// commitment from the transition the state log restores, and the
// pre-commitments from the store, resolved by outpoint. Wallet fee
// inputs are not part of the commitment's identity and lack a known
// script, which the notifier's spend registration requires, so they
// are excluded. The heights serve as spend-subscription hints — the
// notifier requires a positive hint, and an output cannot be spent
// before it was created.
func commitAnchoringSpec(ctx context.Context, env *Environment,
	transition *SupplyStateTransition) (tapreorg.RegistrationSpec,
	error) {

	var spec tapreorg.RegistrationSpec

	commitTx := transition.NewCommitment.Txn
	if commitTx == nil {
		return spec, fmt.Errorf("commitment transaction is nil")
	}
	commitTxid := commitTx.TxHash()

	groupKey, err := env.AssetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return spec, fmt.Errorf("unable to unwrap group key: %w", err)
	}
	var rawGroupKey [33]byte
	copy(rawGroupKey[:], groupKey.SerializeCompressed())

	type triggerSource struct {
		pkScript   []byte
		heightHint uint32
	}
	sources := make(map[wire.OutPoint]triggerSource)
	transition.OldCommitment.WhenSome(func(old RootCommitment) {
		if old.Txn == nil ||
			int(old.TxOutIdx) >= len(old.Txn.TxOut) {

			return
		}
		op := wire.OutPoint{
			Hash:  old.Txn.TxHash(),
			Index: old.TxOutIdx,
		}
		var height uint32
		old.CommitmentBlock.WhenSome(func(b CommitmentBlock) {
			height = b.Height
		})
		sources[op] = triggerSource{
			pkScript:   old.Txn.TxOut[old.TxOutIdx].PkScript,
			heightHint: max(height, 1),
		}
	})

	preCommits, err := env.Commitments.UnspentPrecommits(
		ctx, env.AssetSpec, true,
	).Unpack()
	if err != nil {
		return spec, fmt.Errorf("unable to fetch unspent "+
			"pre-commitments: %w", err)
	}
	for idx := range preCommits {
		preCommit := preCommits[idx]
		if preCommit.MintingTxn == nil || int(preCommit.OutIdx) >=
			len(preCommit.MintingTxn.TxOut) {

			continue
		}
		sources[preCommit.OutPoint()] = triggerSource{
			pkScript: preCommit.MintingTxn.
				TxOut[preCommit.OutIdx].PkScript,
			heightHint: max(preCommit.BlockHeight, 1),
		}
	}

	points := make([]tapreorg.TriggerOutPoint, 0, len(commitTx.TxIn))
	for _, txIn := range commitTx.TxIn {
		source, ok := sources[txIn.PreviousOutPoint]
		if !ok {
			continue
		}

		points = append(points, tapreorg.TriggerOutPoint{
			OutPoint:   txIn.PreviousOutPoint,
			PkScript:   source.pkScript,
			HeightHint: source.heightHint,
		})
	}
	triggers, err := tapreorg.NewTriggerSet(points)
	if err != nil {
		return spec, fmt.Errorf("unable to build trigger set: %w", err)
	}

	blob := encodeSupplyBlob(supplyBlob{
		CommitTxid: commitTxid,
		GroupKey:   rawGroupKey,
	})

	return tapreorg.RegistrationSpec{
		Site:      SupplySiteID,
		Triggers:  triggers,
		MatchData: blob,
		Payload:   blob,
		MatchKey:  commitTxid.CloneBytes(),
		Threshold: env.AnchoringThreshold,
	}, nil
}

// registerCommitAnchoring stakes the transition on its commit
// transaction if no anchoring carries the transaction yet. The signing
// step registers atomically with the signed transaction, so this is
// the safety net behind it, and the adoption path for a broadcast
// state persisted without an anchoring — the state the anchoring
// watches over is already durable, so the registration stakes nothing
// of its own. Returns whether a registration was made.
func registerCommitAnchoring(ctx context.Context, env *Environment,
	transition *SupplyStateTransition) (bool, error) {

	commitTx := transition.NewCommitment.Txn
	if commitTx == nil {
		return false, fmt.Errorf("commitment transaction is nil")
	}
	commitTxid := commitTx.TxHash()

	existing, err := env.AnchoringWatcher.LookupByMatchKey(
		ctx, SupplySiteID, commitTxid.CloneBytes(),
	)
	if err != nil {
		return false, fmt.Errorf("unable to look up supply commit "+
			"anchoring: %w", err)
	}
	if existing != nil {
		return false, nil
	}

	spec, err := commitAnchoringSpec(ctx, env, transition)
	if err != nil {
		return false, err
	}
	_, err = env.AnchoringWatcher.Register(ctx, spec, nil)
	if err != nil {
		return false, fmt.Errorf("unable to register commit "+
			"anchoring: %w", err)
	}

	return true, nil
}

// DispatchCommitNudge is the outbox dispatch handler for a nudge: it
// ticks the group's state machine so a resting machine re-derives its
// position from the durable record. Reaching the machine is the whole
// effect, so a failure to do so is returned and the outbox retries.
func (m *Manager) DispatchCommitNudge(ctx context.Context,
	_ fn.Option[tapreorg.AnchoringID],
	payload tapreorg.VersionedBlob) error {

	blob, err := decodeNudgeBlob(payload)
	if err != nil {
		return err
	}
	groupKey, err := btcec.ParsePubKey(blob.GroupKey[:])
	if err != nil {
		return fmt.Errorf("unable to parse group key: %w", err)
	}
	assetSpec := asset.NewSpecifierFromGroupKey(*groupKey)

	return m.SendEvent(ctx, assetSpec, &CommitTickEvent{})
}

// CommitPushCfg carries the push dispatcher's dependencies.
type CommitPushCfg struct {
	// Log is the durable record the push is rebuilt from.
	Log SupplyAnchoringLog

	// Syncer pushes commitments to the remote universes.
	Syncer SupplySyncer

	// AssetLookup resolves the group's canonical universe list.
	AssetLookup AssetLookup

	// IgnoreCache, if set, is invalidated when the finalized
	// commitment included ignore updates.
	IgnoreCache IgnoreCheckerCache

	// Manager, if set, is nudged with a tick after finalization so a
	// resting state machine re-derives its position from the durable
	// record. The nudge is a pure hint: its loss is repaired by the
	// next event, so nudge errors are logged, not returned.
	Manager *Manager
}

// DispatchCommitPush is the outbox dispatch handler for a finalized
// commitment: it rebuilds the commitment, its supply leaves and its
// chain proof from the database — no in-memory state crosses the
// boundary — and pushes them to the group's canonical universes.
// Idempotent, so outbox redelivery is safe.
func DispatchCommitPush(ctx context.Context, cfg CommitPushCfg,
	_ fn.Option[tapreorg.AnchoringID],
	payload tapreorg.VersionedBlob) error {

	blob, err := decodeSupplyBlob(payload)
	if err != nil {
		return err
	}
	groupKey, err := btcec.ParsePubKey(blob.GroupKey[:])
	if err != nil {
		return fmt.Errorf("unable to parse group key: %w", err)
	}
	assetSpec := asset.NewSpecifierFromGroupKey(*groupKey)

	// Nudge the resting state machine first: finalization is already
	// durable, and the machine's next cycle does not depend on the
	// push below succeeding.
	if cfg.Manager != nil {
		err := cfg.Manager.SendEvent(ctx, assetSpec, &CommitTickEvent{})
		if err != nil {
			log.Warnf("Unable to nudge supply commit machine "+
				"for group %x: %v", blob.GroupKey, err)
		}
	}

	commitment, updates, chainProof, err := cfg.Log.FetchCommitmentPushData(
		ctx, groupKey, blob.CommitTxid,
	)
	if err != nil {
		return fmt.Errorf("unable to load push data: %w", err)
	}

	// The finalized commitment updated the durable trees, so the
	// ignore checker's negative cache must be flushed before remote
	// parties can observe the new state.
	hasIgnoreUpdates := fn.Any(
		updates, func(u SupplyUpdateEvent) bool {
			return u.SupplySubTreeType() == IgnoreTreeType
		},
	)
	if hasIgnoreUpdates && cfg.IgnoreCache != nil {
		cfg.IgnoreCache.InvalidateCache(*groupKey)
	}

	metadata, err := FetchLatestAssetMetadata(
		ctx, cfg.AssetLookup, assetSpec,
	)
	if err != nil {
		return fmt.Errorf("unable to fetch latest asset "+
			"metadata: %w", err)
	}
	canonicalUniverses := metadata.CanonicalUniverses.UnwrapOr(
		[]url.URL{},
	)

	supplyLeaves, err := NewSupplyLeavesFromEvents(updates)
	if err != nil {
		return fmt.Errorf("unable to create supply leaves: %w", err)
	}

	serverErrors, err := cfg.Syncer.PushSupplyCommitment(
		ctx, assetSpec, commitment, supplyLeaves, chainProof,
		canonicalUniverses,
	)
	if err != nil {
		return fmt.Errorf("unable to push supply commitment: %w", err)
	}

	// Per-server failures fail the dispatch. The outbox exists to
	// guarantee this act's delivery, so the effect simply retries
	// until every target server holds the commitment. A retry does
	// not disturb the servers that already accepted: the syncer
	// skips every server its push log records as delivered, and a
	// receiver absorbs a re-push of a commitment it already stores
	// rather than failing its outpoint uniqueness. Treating a
	// failed push as delivered would strand those servers on the
	// predecessor commitment forever, with the successor's own push
	// then rejected for its missing parent.
	if len(serverErrors) > 0 {
		pushErrs := make([]error, 0, len(serverErrors))
		for serverHost, serverErr := range serverErrors {
			pushErrs = append(pushErrs, fmt.Errorf("%s: %w",
				serverHost, serverErr))
		}

		return fmt.Errorf("unable to push supply commitment to %d "+
			"server(s): %w", len(pushErrs),
			errors.Join(pushErrs...))
	}

	return nil
}
