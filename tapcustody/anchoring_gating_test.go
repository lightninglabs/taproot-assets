package tapcustody

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/stretchr/testify/require"
)

// receiveCall records one persistence call made by a receive handler.
type receiveCall struct {
	kind        string
	txid        chainhash.Hash
	blockHash   chainhash.Hash
	blockHeight uint32
	txIndex     uint32
	header      wire.BlockHeader
	resetStatus int16
}

// recordingReceiveLog captures the full argument list of every call, so
// a test can assert not merely that a handler persisted something but
// that it persisted the right block.
type recordingReceiveLog struct {
	calls []receiveCall

	// locators is what the proof-touching bodies report as
	// rewritten or deleted, and so what the site must hand to the
	// mirror.
	locators []proof.Locator
}

func (l *recordingReceiveLog) StakeReceivedProofs(_ context.Context,
	_ tapreorg.RegistryTx,
	_ ...proof.VerifiedAnnotatedProof) ([]proof.Blob, error) {

	return nil, nil
}

func (l *recordingReceiveLog) NotifyProofs(_ ...proof.Blob) {}

func (l *recordingReceiveLog) HasReceivedProof(_ context.Context,
	_ proof.Locator) (bool, error) {

	return false, nil
}

func (l *recordingReceiveLog) ApplyReceiveReconfirm(_ context.Context,
	_ *sqlc.Queries, anchorTxid chainhash.Hash,
	blockHash chainhash.Hash, blockHeight, txIndex uint32,
	header wire.BlockHeader,
	_ proof.TxMerkleProof) ([]proof.Locator, error) {

	l.calls = append(l.calls, receiveCall{
		kind:        "reconfirm",
		txid:        anchorTxid,
		blockHash:   blockHash,
		blockHeight: blockHeight,
		txIndex:     txIndex,
		header:      header,
	})

	return l.locators, nil
}

func (l *recordingReceiveLog) ApplyReceiveUnconfirm(_ context.Context,
	_ *sqlc.Queries, anchorTxid chainhash.Hash) error {

	l.calls = append(l.calls, receiveCall{
		kind: "unconfirm",
		txid: anchorTxid,
	})

	return nil
}

func (l *recordingReceiveLog) ApplyReceiveAbandonment(_ context.Context,
	_ *sqlc.Queries, anchorTxid chainhash.Hash,
	resetStatus int16) ([]proof.Locator, error) {

	l.calls = append(l.calls, receiveCall{
		kind:        "abandon",
		txid:        anchorTxid,
		resetStatus: resetStatus,
	})

	return l.locators, nil
}

// kinds returns the recorded call kinds in order.
func (l *recordingReceiveLog) kinds() []string {
	out := make([]string, 0, len(l.calls))
	for _, c := range l.calls {
		out = append(out, c.kind)
	}

	return out
}

// recordingReceiveTx is a RegistryTx that records enqueued effects.
type recordingReceiveTx struct {
	effects []tapreorg.OutboxEffect
}

func (r *recordingReceiveTx) Queries() *sqlc.Queries {
	return nil
}

func (r *recordingReceiveTx) EnqueueEffect(_ context.Context,
	effect tapreorg.OutboxEffect) error {

	r.effects = append(r.effects, effect)

	return nil
}

// mirrorLocator builds a locator the recording logs report as rewritten
// or deleted, and so the locator the site must hand to the mirror.
func mirrorLocator(t *testing.T, anchorTxid chainhash.Hash) proof.Locator {
	t.Helper()

	var assetID asset.ID
	assetID[0] = 0xaa

	return proof.Locator{
		AssetID:   &assetID,
		ScriptKey: *test.RandPubKey(t),
		OutPoint:  &wire.OutPoint{Hash: anchorTxid, Index: 0},
	}
}

// actGated filters the mirror-sync housekeeping out of the recorded
// effects, leaving the act-gated emissions.
func actGated(effects []tapreorg.OutboxEffect) []tapreorg.OutboxEffect {
	var out []tapreorg.OutboxEffect
	for _, effect := range effects {
		if effect.Kind != proof.MirrorSyncEffectKind {
			out = append(out, effect)
		}
	}

	return out
}

// requireMirrorSyncs asserts the recorded mirror-sync effects, in
// order: each is tied to the anchoring, carries the given op, and
// names exactly the given locator.
func requireMirrorSyncs(t *testing.T, effects []tapreorg.OutboxEffect,
	id tapreorg.AnchoringID, loc proof.Locator,
	ops ...proof.MirrorSyncOp) {

	t.Helper()

	var syncs []proof.MirrorSyncPayload
	for _, effect := range effects {
		if effect.Kind != proof.MirrorSyncEffectKind {
			continue
		}
		require.Equal(t, id, effect.Anchoring.UnwrapOr(0))

		payload, err := proof.DecodeMirrorSyncPayload(
			effect.Payload.Version, effect.Payload.Data,
		)
		require.NoError(t, err)
		syncs = append(syncs, payload)
	}

	require.Len(t, syncs, len(ops))
	for i, op := range ops {
		require.Equal(t, op, syncs[i].Op, "sync %d", i)
		require.Len(t, syncs[i].Locators, 1, "sync %d", i)

		got := syncs[i].Locators[0]
		require.Equal(t, loc.AssetID, got.AssetID, "sync %d", i)
		require.Equal(
			t, loc.ScriptKey.SerializeCompressed(),
			got.ScriptKey.SerializeCompressed(), "sync %d", i,
		)
		require.Equal(t, loc.OutPoint, got.OutPoint, "sync %d", i)
	}
}

// witnessAt builds a witness for the transaction in the given block,
// together with the candidate enrichment the registry would have
// recorded alongside it. A re-organized re-confirmation refreshes both
// halves together, so the helper keeps them consistent by construction
// — the site is entitled to assume they agree.
func witnessAt(t *testing.T, tx *wire.MsgTx, nonce uint32,
	height, txIndex uint32) (tapreorg.Witness, tapreorg.CandidateSpend) {

	t.Helper()

	header := &wire.BlockHeader{Version: 2, Nonce: nonce}
	blockHash := header.BlockHash()

	w, err := tapreorg.NewWitness(tx, blockHash, height, txIndex)
	require.NoError(t, err)

	return w, tapreorg.CandidateSpend{
		Verdict:     tapreorg.VerdictSatisfies,
		W:           w,
		OnChain:     true,
		BlockHeader: header,
		MerkleProof: &proof.TxMerkleProof{},
	}
}

// TestReceiveSiteReorgLadder drives the receive site's handlers through
// a nontrivial re-organization at the handler layer, where the tapdb
// ladder cannot reach: what the site derives from the anchoring and
// hands down to persistence.
//
// The property that matters is freshness. Both OnWitnessed and
// OnBuried route through reconfirm, which reads the block context out
// of the anchoring's current phase rather than out of anything the
// caller passed. A re-organization replaces that phase, so the second
// confirmation must carry the second block — a site that cached the
// first, or that read the wrong end of the candidate list, would still
// look correct to a single-confirmation test.
//
// The receive site also emits nothing act-gated at any phase: it is
// the one migrated site with no external effect, so its burial handler
// is a plain convergent confirmation. What it does enqueue is
// housekeeping — the file mirror's catch-up for every proof a
// confirmation re-stamped or the abandonment deleted.
func TestReceiveSiteReorgLadder(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51}))
	anchorTxid := anchorTx.TxHash()

	payload := encodeReceiveBlob(anchorTxid)

	// Block A, then the re-organized block B at a different height
	// and a different position within its block.
	witnessA, candidateA := witnessAt(t, anchorTx, 10, 700, 1)
	witnessB, candidateB := witnessAt(t, anchorTx, 11, 705, 4)
	require.NotEqual(t, witnessA.BlockHash(), witnessB.BlockHash())

	loc := mirrorLocator(t, anchorTxid)
	log := &recordingReceiveLog{locators: []proof.Locator{loc}}
	site := &receiveSite{custodian: &Custodian{
		cfg: &Config{AnchoringLog: log},
	}}
	ctx := context.Background()
	tx := &recordingReceiveTx{}

	anchoring := &tapreorg.Anchoring{
		ID:      3,
		Site:    ReceiveSiteID,
		Payload: payload,
		Spends:  []tapreorg.CandidateSpend{candidateA},
		Phase:   tapreorg.Witnessed{W: witnessA},
	}

	// Rung 1: first confirmation, in block A.
	require.NoError(t, site.OnWitnessed(ctx, tx, anchoring))

	// Rung 2: the block is re-organized away. A soft downgrade
	// withdraws the confirmation and nothing else — in particular it
	// must not carry block context, since there is no block.
	anchoring.Phase = tapreorg.Unwitnessed{}
	require.NoError(t, site.OnUnwitnessed(ctx, tx, anchoring))

	// Rung 3: re-confirmation in block B. The registry refreshes the
	// candidate's enrichment in place, so the site must now derive
	// B's context, not A's.
	anchoring.Spends = []tapreorg.CandidateSpend{candidateB}
	anchoring.Phase = tapreorg.Witnessed{W: witnessB}
	require.NoError(t, site.OnWitnessed(ctx, tx, anchoring))

	// Rung 4: burial in the same block B, the coalesced-delivery
	// case — convergent, and still block B.
	anchoring.Phase = tapreorg.Buried{W: witnessB}
	require.NoError(t, site.OnBuried(ctx, tx, anchoring))

	require.Equal(
		t, []string{
			"reconfirm", "unconfirm", "reconfirm", "reconfirm",
		}, log.kinds(),
	)

	// Every call named the anchoring's transaction.
	for i, c := range log.calls {
		require.Equal(t, anchorTxid, c.txid, "call %d", i)
	}

	// Freshness: the first confirmation carried block A; both
	// confirmations after the re-organization carried block B, at
	// its height and its position.
	require.Equal(t, witnessA.BlockHash(), log.calls[0].blockHash)
	require.EqualValues(t, 700, log.calls[0].blockHeight)
	require.EqualValues(t, 1, log.calls[0].txIndex)

	for _, idx := range []int{2, 3} {
		require.Equal(
			t, witnessB.BlockHash(), log.calls[idx].blockHash,
			"call %d carries a stale block hash", idx,
		)
		require.EqualValues(
			t, 705, log.calls[idx].blockHeight,
			"call %d carries a stale height", idx,
		)
		require.EqualValues(
			t, 4, log.calls[idx].txIndex,
			"call %d carries a stale tx index", idx,
		)
		require.Equal(
			t, *candidateB.BlockHeader, log.calls[idx].header,
			"call %d carries a stale header", idx,
		)
	}

	// Rung 5: the conflict is buried. Compensation resets the
	// address events to transaction-detected, the status the
	// custodian's resume window can pick up again.
	anchoring.Phase = tapreorg.Abandoned{}
	require.NoError(t, site.OnAbandoned(ctx, tx, anchoring))

	last := log.calls[len(log.calls)-1]
	require.Equal(t, "abandon", last.kind)
	require.Equal(
		t, int16(address.StatusTransactionDetected), last.resetStatus,
	)

	// The receive site emits nothing act-gated, at any phase. The
	// mirror follows each confirmation's re-stamp and the
	// abandonment's deletion, naming the proof the log reported.
	require.Empty(t, actGated(tx.effects))
	requireMirrorSyncs(
		t, tx.effects, anchoring.ID, loc,
		proof.MirrorSyncRewrite, proof.MirrorSyncRewrite,
		proof.MirrorSyncRewrite, proof.MirrorSyncDelete,
	)
}

// TestReceiveSiteConflictIsSoft pins the potency-tier treatment of an
// on-chain conflict: a foreign spend can itself be re-organized out, so
// observing one withdraws the confirmation and nothing more. Deleting
// the received assets here — rather than at abandonment — would
// destroy state that a one-block re-organization can restore.
func TestReceiveSiteConflictIsSoft(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51}))

	log := &recordingReceiveLog{}
	site := &receiveSite{custodian: &Custodian{
		cfg: &Config{AnchoringLog: log},
	}}

	witness, candidate := witnessAt(t, anchorTx, 10, 700, 0)
	anchoring := &tapreorg.Anchoring{
		ID:      4,
		Site:    ReceiveSiteID,
		Payload: encodeReceiveBlob(anchorTx.TxHash()),
		Spends:  []tapreorg.CandidateSpend{candidate},
		Phase:   tapreorg.Conflicted{},
	}

	ctx := context.Background()
	tx := &recordingReceiveTx{}
	require.NoError(t, site.OnConflicted(ctx, tx, anchoring))

	require.Equal(t, []string{"unconfirm"}, log.kinds())
	require.Empty(t, tx.effects)

	// And it is recoverable: the conflict re-organizes out, the
	// original transaction re-confirms, and the site converges
	// forward again rather than having thrown the state away.
	anchoring.Phase = tapreorg.Witnessed{W: witness}
	require.NoError(t, site.OnWitnessed(ctx, tx, anchoring))

	require.Equal(t, []string{"unconfirm", "reconfirm"}, log.kinds())

	// A re-stamp that touched no stored proof leaves the mirror
	// nothing to catch up on.
	require.Empty(t, tx.effects)
}
