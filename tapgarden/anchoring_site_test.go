package tapgarden

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// genMintBlob draws an arbitrary mint blob.
func genMintBlob(t *rapid.T) mintBlob {
	var blob mintBlob
	copy(blob.RawBatchKey[:], rapid.SliceOfN(rapid.Byte(), 33, 33).Draw(
		t, "batchKey",
	))
	copy(blob.GenesisTxid[:], rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(
		t, "genesisTxid",
	))

	return blob
}

// TestMintBlobRoundTrip asserts that every mint blob survives the
// encode/decode round trip, and that the encoding is canonical: the
// decoded value re-encodes to identical bytes.
func TestMintBlobRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		blob := genMintBlob(rt)

		encoded := encodeMintBlob(blob)
		decoded, err := decodeMintBlob(encoded)
		require.NoError(rt, err)
		require.Equal(rt, blob, decoded)

		require.Equal(rt, encoded, encodeMintBlob(decoded))
	})
}

// TestMintBlobDecodeRejects asserts the decoder rejects unknown
// versions and payloads of the wrong length.
func TestMintBlobDecodeRejects(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		data := rapid.SliceOfN(rapid.Byte(), 0, 96).Draw(rt, "data")

		version := rapid.Uint16().Draw(rt, "version")
		_, err := decodeMintBlob(tapreorg.VersionedBlob{
			Version: version,
			Data:    data,
		})

		switch {
		case version != mintBlobVersion:
			require.ErrorContains(rt, err, "unknown mint blob "+
				"version")

		case len(data) != 33+32:
			require.ErrorContains(rt, err, "mint blob has")

		default:
			require.NoError(rt, err)

			// The accepted decoding must reproduce the input.
			decoded, _ := decodeMintBlob(tapreorg.VersionedBlob{
				Version: version,
				Data:    data,
			})
			require.Equal(
				rt, data, encodeMintBlob(decoded).Data,
			)
		}
	})
}

// recordingMintLog is a MintAnchoringLog that records which bodies
// the site handlers drove.
type recordingMintLog struct {
	reconfirms  int
	unconfirms  int
	abandonment int

	lastTxid chainhash.Hash

	// locators is what the proof-touching bodies report as
	// rewritten or deleted, and so what the site must hand to the
	// mirror.
	locators []proof.Locator
}

func (l *recordingMintLog) ApplyReceiveReconfirm(_ context.Context,
	_ *sqlc.Queries, anchorTxid chainhash.Hash, _ chainhash.Hash,
	_, _ uint32, _ wire.BlockHeader,
	_ proof.TxMerkleProof) ([]proof.Locator, error) {

	l.reconfirms++
	l.lastTxid = anchorTxid

	return l.locators, nil
}

func (l *recordingMintLog) ApplyReceiveUnconfirm(_ context.Context,
	_ *sqlc.Queries, anchorTxid chainhash.Hash) error {

	l.unconfirms++
	l.lastTxid = anchorTxid

	return nil
}

func (l *recordingMintLog) ApplyMintAbandonment(_ context.Context,
	_ *sqlc.Queries, genesisTxid chainhash.Hash,
	_ []byte) ([]proof.Locator, error) {

	l.abandonment++
	l.lastTxid = genesisTxid

	return l.locators, nil
}

// recordingRegistryTx is a RegistryTx that records enqueued effects.
type recordingRegistryTx struct {
	effects []tapreorg.OutboxEffect
}

func (r *recordingRegistryTx) Queries() *sqlc.Queries {
	return nil
}

func (r *recordingRegistryTx) EnqueueEffect(_ context.Context,
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

// TestMintSiteActGating pins the mint site's act-gating contract: the
// batch's external emissions (the universe/supply publish effect) are
// enqueued by the burial handler and only there. Every other handler
// converges local state without enqueueing anything act-gated; the
// confirmations and the abandonment enqueue only the file mirror's
// catch-up for the proofs they touched.
func TestMintSiteActGating(t *testing.T) {
	t.Parallel()

	genesisTx := wire.NewMsgTx(2)
	genesisTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	genesisTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51}))

	var blob mintBlob
	blob.RawBatchKey[0] = 0x02
	blob.GenesisTxid = genesisTx.TxHash()
	payload := encodeMintBlob(blob)

	witness, err := tapreorg.NewWitness(
		genesisTx, chainhash.Hash{0xbb}, 700, 1,
	)
	require.NoError(t, err)

	anchoring := &tapreorg.Anchoring{
		ID:      7,
		Site:    MintSiteID,
		Payload: payload,
		Spends: []tapreorg.CandidateSpend{{
			Verdict:     tapreorg.VerdictSatisfies,
			W:           witness,
			OnChain:     true,
			BlockHeader: &wire.BlockHeader{Nonce: 1},
			MerkleProof: &proof.TxMerkleProof{},
		}},
	}

	loc := mirrorLocator(t, blob.GenesisTxid)
	log := &recordingMintLog{locators: []proof.Locator{loc}}
	site := &mintSite{planter: NewChainPlanter(PlanterConfig{
		GardenKit: GardenKit{MintAnchoringLog: log},
	})}
	ctx := context.Background()

	// Witnessing converges the confirmation; nothing act-gated is
	// emitted, only the mirror's catch-up for the re-stamped proof.
	tx := &recordingRegistryTx{}
	anchoring.Phase = tapreorg.Witnessed{W: witness}
	require.NoError(t, site.OnWitnessed(ctx, tx, anchoring))
	require.Equal(t, 1, log.reconfirms)
	require.Equal(t, blob.GenesisTxid, log.lastTxid)
	require.Empty(t, actGated(tx.effects))
	requireMirrorSyncs(
		t, tx.effects, anchoring.ID, loc, proof.MirrorSyncRewrite,
	)

	// The soft downgrades emit nothing at all.
	anchoring.Phase = tapreorg.Unwitnessed{}
	require.NoError(t, site.OnUnwitnessed(ctx, tx, anchoring))
	require.Equal(t, 1, log.unconfirms)
	require.Len(t, tx.effects, 1)

	anchoring.Phase = tapreorg.Conflicted{}
	require.NoError(t, site.OnConflicted(ctx, tx, anchoring))
	require.Equal(t, 2, log.unconfirms)
	require.Len(t, tx.effects, 1)

	// Burial re-runs the convergent confirmation (covering
	// coalesced deliveries) and enqueues exactly the publish
	// effect, beside the re-stamp's mirror catch-up.
	anchoring.Phase = tapreorg.Buried{W: witness}
	require.NoError(t, site.OnBuried(ctx, tx, anchoring))
	require.Equal(t, 2, log.reconfirms)
	published := actGated(tx.effects)
	require.Len(t, published, 1)
	require.Equal(t, MintPublishEffectKind, published[0].Kind)
	require.Equal(t, anchoring.ID, published[0].Anchoring.UnwrapOr(0))
	require.Equal(t, payload, published[0].Payload)
	requireMirrorSyncs(
		t, tx.effects, anchoring.ID, loc,
		proof.MirrorSyncRewrite, proof.MirrorSyncRewrite,
	)

	// Abandonment compensates locally; nothing was published, so
	// nothing act-gated is emitted or retracted. The mirror sheds
	// the deleted proof.
	anchoring.Phase = tapreorg.Abandoned{}
	require.NoError(t, site.OnAbandoned(ctx, tx, anchoring))
	require.Equal(t, 1, log.abandonment)
	require.Len(t, actGated(tx.effects), 1)
	requireMirrorSyncs(
		t, tx.effects, anchoring.ID, loc,
		proof.MirrorSyncRewrite, proof.MirrorSyncRewrite,
		proof.MirrorSyncDelete,
	)
}

// TestMintSiteEvaluateCandidate pins the mint site's verdict: exactly
// the broadcast genesis transaction satisfies the anchoring, any other
// spender of its inputs is foreign, and a match blob the site cannot
// decode is an error rather than a verdict. A transaction spending
// only part of the trigger set never reaches the predicate — the
// watcher judges it foreign by the whole-set rule — so it is not a
// case here.
func TestMintSiteEvaluateCandidate(t *testing.T) {
	t.Parallel()

	fundingOp := test.RandOp(t)
	genesisTx := wire.NewMsgTx(2)
	genesisTx.AddTxIn(wire.NewTxIn(&fundingOp, nil, nil))
	genesisTx.AddTxOut(wire.NewTxOut(int64(GenesisAmtSats), []byte{0x51}))

	// A rival spends the same funding input to a different output.
	rivalTx := genesisTx.Copy()
	rivalTx.TxOut[0].Value++

	var batchKey [33]byte
	copy(batchKey[:], test.RandPubKey(t).SerializeCompressed())
	match := encodeMintBlob(mintBlob{
		RawBatchKey: batchKey,
		GenesisTxid: genesisTx.TxHash(),
	})

	tests := []struct {
		name    string
		match   tapreorg.VersionedBlob
		spender *wire.MsgTx
		want    tapreorg.Verdict
		wantErr bool
	}{{
		name:    "broadcast genesis transaction satisfies",
		match:   match,
		spender: genesisTx,
		want:    tapreorg.VerdictSatisfies,
	}, {
		name:    "other spender of the inputs is foreign",
		match:   match,
		spender: rivalTx,
		want:    tapreorg.VerdictForeign,
	}, {
		name: "undecodable match is an error",
		match: tapreorg.VersionedBlob{
			Version: mintBlobVersion,
			Data:    []byte{0x01},
		},
		spender: genesisTx,
		wantErr: true,
	}}

	site := &mintSite{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdict, err := site.EvaluateCandidate(
				tc.match, tc.spender,
			)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, verdict)
		})
	}
}
