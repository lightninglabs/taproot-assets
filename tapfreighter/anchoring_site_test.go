package tapfreighter

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
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

// genTxid draws an arbitrary 32-byte txid.
func genTxid(t *rapid.T, label string) chainhash.Hash {
	var h chainhash.Hash
	copy(h[:], rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, label))

	return h
}

// recordingPorterLog is an AnchoringLog that records which bodies the
// site handlers drove.
type recordingPorterLog struct {
	confirms    int
	unconfirms  int
	abandonment int

	lastTxid        chainhash.Hash
	lastNote        string
	lastForeclosure *wire.MsgTx

	notified []proof.Blob
}

func (l *recordingPorterLog) ApplyPendingParcel(_ context.Context,
	_ *sqlc.Queries, _ *OutboundParcel, _ [32]byte, _ time.Time) error {

	return nil
}

func (l *recordingPorterLog) ApplyAnchorTxConfirm(_ context.Context,
	_ *sqlc.Queries, _ *AssetConfirmEvent,
	_ []*AssetBurn) ([]OutputIdentifier, error) {

	l.confirms++

	return nil, nil
}

func (l *recordingPorterLog) ApplyAnchorTxUnconfirm(_ context.Context,
	_ *sqlc.Queries, anchorTxid chainhash.Hash) error {

	l.unconfirms++
	l.lastTxid = anchorTxid

	return nil
}

func (l *recordingPorterLog) ApplyTransferAbandonment(_ context.Context,
	_ *sqlc.Queries, anchorTxid chainhash.Hash,
	foreclosure *wire.MsgTx) error {

	l.abandonment++
	l.lastTxid = anchorTxid
	l.lastForeclosure = foreclosure

	return nil
}

func (l *recordingPorterLog) RebuildAnchorConfirm(_ context.Context,
	_ *sqlc.Queries, anchorTx *wire.MsgTx, _ chainhash.Hash, _, _ uint32,
	_ wire.BlockHeader, _ proof.TxMerkleProof,
	burnNote string) (*AssetConfirmEvent, []*AssetBurn, error) {

	l.lastTxid = anchorTx.TxHash()
	l.lastNote = burnNote

	return &AssetConfirmEvent{}, nil, nil
}

func (l *recordingPorterLog) RebuildConfirmEvent(_ context.Context,
	_ *wire.MsgTx, _ chainhash.Hash, _, _ uint32,
	_ wire.BlockHeader, _ proof.TxMerkleProof,
	_ string) (*AssetConfirmEvent, []*AssetBurn, error) {

	return &AssetConfirmEvent{}, nil, nil
}

func (l *recordingPorterLog) NotifyProofs(blobs ...proof.Blob) {
	l.notified = append(l.notified, blobs...)
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

// TestPorterSiteActGating pins the porter site's act-gating contract:
// the burn supply-commit events — irrevocable assertions to a receiver
// that re-checks nothing — are enqueued by the burial handler and only
// there. Every other handler converges local state without enqueueing
// anything.
func TestPorterSiteActGating(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51}))

	blob := porterBlob{
		AnchorTxid: anchorTx.TxHash(),
		Note:       "burn note",
	}
	payload := encodePorterBlob(blob)

	witness, err := tapreorg.NewWitness(
		anchorTx, chainhash.Hash{0xcc}, 700, 1,
	)
	require.NoError(t, err)

	anchoring := &tapreorg.Anchoring{
		ID:      9,
		Site:    PorterSiteID,
		Payload: payload,
		Spends: []tapreorg.CandidateSpend{{
			Verdict:     tapreorg.VerdictSatisfies,
			W:           witness,
			OnChain:     true,
			BlockHeader: &wire.BlockHeader{Nonce: 1},
			MerkleProof: &proof.TxMerkleProof{},
		}},
	}

	log := &recordingPorterLog{}
	site := &porterSite{porter: NewChainPorter(&ChainPorterConfig{
		AnchoringLog: log,
	})}
	ctx := context.Background()

	// Witnessing converges the confirmation; nothing is emitted.
	tx := &recordingRegistryTx{}
	anchoring.Phase = tapreorg.Witnessed{W: witness}
	require.NoError(t, site.OnWitnessed(ctx, tx, anchoring))
	require.Equal(t, 1, log.confirms)
	require.Equal(t, blob.AnchorTxid, log.lastTxid)
	require.Equal(t, blob.Note, log.lastNote)
	require.Empty(t, tx.effects)

	// The soft downgrades emit nothing either.
	anchoring.Phase = tapreorg.Unwitnessed{}
	require.NoError(t, site.OnUnwitnessed(ctx, tx, anchoring))
	require.Equal(t, 1, log.unconfirms)
	require.Empty(t, tx.effects)

	anchoring.Phase = tapreorg.Conflicted{}
	require.NoError(t, site.OnConflicted(ctx, tx, anchoring))
	require.Equal(t, 2, log.unconfirms)
	require.Empty(t, tx.effects)

	// Burial re-runs the convergent confirmation (covering
	// coalesced deliveries) and enqueues exactly the burn effect.
	anchoring.Phase = tapreorg.Buried{W: witness}
	require.NoError(t, site.OnBuried(ctx, tx, anchoring))
	require.Equal(t, 2, log.confirms)
	require.Len(t, tx.effects, 1)
	require.Equal(t, BurnSupplyEventsEffectKind, tx.effects[0].Kind)
	require.Equal(
		t, anchoring.ID, tx.effects[0].Anchoring.UnwrapOr(0),
	)
	require.Equal(t, payload, tx.effects[0].Payload)

	// Abandonment compensates locally; the burn events never went
	// out, so nothing further is emitted or retracted. Without a
	// cause there is no foreclosing transaction to hand down.
	anchoring.Phase = tapreorg.Abandoned{}
	require.NoError(t, site.OnAbandoned(ctx, tx, anchoring))
	require.Equal(t, 1, log.abandonment)
	require.Len(t, tx.effects, 1)
	require.Nil(t, log.lastForeclosure)

	// A foreign burial names the transaction the chain decided for;
	// the compensation receives it so it can leave that
	// transaction's inputs alone.
	foreignTx := wire.NewMsgTx(2)
	foreignTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 7}, nil, nil))
	foreignTx.AddTxOut(wire.NewTxOut(500, []byte{0x51, 0xff}))
	foreignWitness, err := tapreorg.NewWitness(
		foreignTx, chainhash.Hash{0xdd}, 701, 2,
	)
	require.NoError(t, err)

	anchoring.Phase = tapreorg.Abandoned{
		Cause: tapreorg.ForeignBurial{
			Spend: tapreorg.ForeignSpend{W: foreignWitness},
		},
	}
	require.NoError(t, site.OnAbandoned(ctx, tx, anchoring))
	require.Equal(t, 2, log.abandonment)
	require.NotNil(t, log.lastForeclosure)
	require.Equal(
		t, foreignTx.TxHash(), log.lastForeclosure.TxHash(),
	)
}

// TestPorterBlobRoundTrip asserts that every porter blob survives the
// encode/decode round trip, and that the encoding is canonical: the
// decoded value re-encodes to identical bytes.
func TestPorterBlobRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		blob := porterBlob{
			AnchorTxid: genTxid(rt, "txid"),
			Note: string(rapid.SliceOf(rapid.Byte()).Draw(
				rt, "note",
			)),
		}

		encoded := encodePorterBlob(blob)
		decoded, err := decodePorterBlob(encoded)
		require.NoError(rt, err)
		require.Equal(rt, blob, decoded)

		require.Equal(rt, encoded, encodePorterBlob(decoded))
	})
}

// TestPorterBlobDecodeRejects asserts the decoder rejects unknown
// versions and truncated payloads.
func TestPorterBlobDecodeRejects(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		data := rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(rt, "data")

		version := rapid.Uint16().Draw(rt, "version")
		_, err := decodePorterBlob(tapreorg.VersionedBlob{
			Version: version,
			Data:    data,
		})

		switch {
		case version != porterBlobVersion:
			require.ErrorContains(rt, err, "unknown porter "+
				"blob version")

		case len(data) < 32:
			require.ErrorContains(rt, err, "porter blob too "+
				"short")

		default:
			require.NoError(rt, err)
		}
	})
}

// TestLocalProofBlobs pins the subscriber notification set on the
// anchoring path to the legacy one: the final proofs of the outputs
// the confirmation materializes locally — a local script key, a burn
// — plus every passive re-anchor, and nothing for a remote output.
func TestLocalProofBlobs(t *testing.T) {
	t.Parallel()

	anchorTxid := chainhash.Hash{0xaa}
	assetID := asset.ID{0xbb}
	prevID := asset.PrevID{
		OutPoint: wire.OutPoint{Hash: chainhash.Hash{0x01}},
		ID:       assetID,
	}

	localKey := test.RandPubKey(t)
	remoteKey := test.RandPubKey(t)
	burnKey := asset.DeriveBurnKey(prevID)

	output := func(index uint32, key *btcec.PublicKey, local bool,
		witness []asset.Witness) TransferOutput {

		return TransferOutput{
			Anchor: Anchor{
				OutPoint: wire.OutPoint{
					Hash:  anchorTxid,
					Index: index,
				},
			},
			ScriptKey:      asset.NewScriptKey(key),
			ScriptKeyLocal: local,
			Amount:         1,
			WitnessData:    witness,
		}
	}
	parcel := &OutboundParcel{
		Outputs: []TransferOutput{
			output(0, localKey, true, nil),
			output(1, remoteKey, false, nil),
			output(2, burnKey, false, []asset.Witness{{
				PrevID: &prevID,
			}}),
		},
	}

	annotated := func(index uint32, key *btcec.PublicKey,
		blob byte) *proof.AnnotatedProof {

		return &proof.AnnotatedProof{
			Locator: proof.Locator{
				AssetID:   &assetID,
				ScriptKey: *key,
				OutPoint: &wire.OutPoint{
					Hash:  anchorTxid,
					Index: index,
				},
			},
			Blob: proof.Blob{blob},
		}
	}
	conf := &AssetConfirmEvent{
		FinalProofs: map[OutputIdentifier]*proof.AnnotatedProof{
			NewOutputIdentifier(assetID, 0, *localKey): annotated(
				0, localKey, 0x10,
			),
			NewOutputIdentifier(assetID, 1, *remoteKey): annotated(
				1, remoteKey, 0x20,
			),
			NewOutputIdentifier(assetID, 2, *burnKey): annotated(
				2, burnKey, 0x30,
			),
		},
		PassiveAssetProofFiles: map[asset.ID][]*proof.AnnotatedProof{
			{0xcc}: {annotated(3, test.RandPubKey(t), 0x40)},
		},
	}

	require.ElementsMatch(
		t, []proof.Blob{{0x10}, {0x30}, {0x40}},
		localProofBlobs(parcel, conf),
	)
}

// TestPorterSiteEvaluateCandidate pins the porter site's verdict:
// exactly the transaction the porter logged satisfies the anchoring,
// any other spender of its inputs — a replacement published elsewhere,
// a conflicting sweep — is foreign, and a match blob the site cannot
// decode is an error rather than a verdict. A transaction spending only
// part of the trigger set never reaches the predicate — the watcher
// judges it foreign by the whole-set rule — so it is not a case here.
func TestPorterSiteEvaluateCandidate(t *testing.T) {
	t.Parallel()

	inputOp := test.RandOp(t)
	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&inputOp, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51}))

	// A rival spends the same input to a different output.
	rivalTx := anchorTx.Copy()
	rivalTx.TxOut[0].Value++

	match := encodePorterBlob(porterBlob{
		AnchorTxid: anchorTx.TxHash(),
		Note:       "pinned",
	})

	tests := []struct {
		name    string
		match   tapreorg.VersionedBlob
		spender *wire.MsgTx
		want    tapreorg.Verdict
		wantErr bool
	}{{
		name:    "logged anchor transaction satisfies",
		match:   match,
		spender: anchorTx,
		want:    tapreorg.VerdictSatisfies,
	}, {
		name:    "other spender of the inputs is foreign",
		match:   match,
		spender: rivalTx,
		want:    tapreorg.VerdictForeign,
	}, {
		name: "undecodable match is an error",
		match: tapreorg.VersionedBlob{
			Version: porterBlobVersion,
			Data:    []byte{0x01},
		},
		spender: anchorTx,
		wantErr: true,
	}}

	site := &porterSite{}
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
