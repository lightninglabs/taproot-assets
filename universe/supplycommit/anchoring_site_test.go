package supplycommit

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// genSupplyBlob draws an arbitrary supply blob.
func genSupplyBlob(t *rapid.T) supplyBlob {
	var blob supplyBlob
	copy(blob.CommitTxid[:], rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(
		t, "commitTxid",
	))
	copy(blob.GroupKey[:], rapid.SliceOfN(rapid.Byte(), 33, 33).Draw(
		t, "groupKey",
	))

	return blob
}

// TestSupplyBlobRoundTrip asserts that every supply blob survives the
// encode/decode round trip, and that the encoding is canonical: the
// decoded value re-encodes to identical bytes.
func TestSupplyBlobRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		blob := genSupplyBlob(rt)

		encoded := encodeSupplyBlob(blob)
		decoded, err := decodeSupplyBlob(encoded)
		require.NoError(rt, err)
		require.Equal(rt, blob, decoded)

		require.Equal(rt, encoded, encodeSupplyBlob(decoded))
	})
}

// TestSupplyBlobDecodeRejects asserts the decoder rejects unknown
// versions and payloads of the wrong length.
func TestSupplyBlobDecodeRejects(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		data := rapid.SliceOfN(rapid.Byte(), 0, 96).Draw(rt, "data")

		version := rapid.Uint16().Draw(rt, "version")
		_, err := decodeSupplyBlob(tapreorg.VersionedBlob{
			Version: version,
			Data:    data,
		})

		switch {
		case version != supplyBlobVersion:
			require.ErrorContains(rt, err, "unknown supply "+
				"blob version")

		case len(data) != 32+33:
			require.ErrorContains(rt, err, "supply blob has")

		default:
			require.NoError(rt, err)
		}
	})
}

// stubPushLog serves fixed, empty push data for the dispatch tests.
type stubPushLog struct{}

func (s *stubPushLog) ApplyCommitFinalize(_ context.Context, _ *sqlc.Queries,
	_ *btcec.PublicKey, _ chainhash.Hash, _ ChainProof) error {

	return nil
}

func (s *stubPushLog) ApplyCommitAbandonment(_ context.Context,
	_ *sqlc.Queries, _ *btcec.PublicKey, _ chainhash.Hash) error {

	return nil
}

func (s *stubPushLog) FetchCommitmentPushData(_ context.Context,
	_ *btcec.PublicKey, _ chainhash.Hash) (RootCommitment,
	[]SupplyUpdateEvent, ChainProof, error) {

	return RootCommitment{}, nil, ChainProof{}, nil
}

// TestDispatchCommitPushFailureRetries pins the dispatcher's delivery
// contract: a per-server push failure fails the dispatch — the outbox
// exists to guarantee the act's delivery — and the redelivery succeeds
// once the servers do. The second attempt succeeding wholesale models
// the production syncer, which skips every server its push log records
// as delivered and so only re-targets the failed ones (receivers
// additionally absorb re-pushes of a commitment they already store). A
// swallowed failure would mark the effect delivered and strand the
// failed servers on the predecessor commitment forever.
func TestDispatchCommitPushFailureRetries(t *testing.T) {
	t.Parallel()

	groupKey := test.RandPubKey(t)
	var blob supplyBlob
	copy(blob.GroupKey[:], groupKey.SerializeCompressed())
	blob.CommitTxid = chainhash.Hash{0x01}
	payload := encodeSupplyBlob(blob)

	lookup := &MockAssetLookup{}
	lookup.On(
		"QueryAssetGroupByGroupKey", mock.Anything, mock.Anything,
	).Return(&asset.AssetGroup{Genesis: &asset.Genesis{}}, nil)
	lookup.On(
		"FetchAssetMetaForAsset", mock.Anything, mock.Anything,
	).Return(&proof.MetaReveal{}, nil)

	syncer := &mockSupplySyncer{}
	syncer.On(
		"PushSupplyCommitment", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(
		map[string]error{"uni.example:10029": errors.New("refused")},
		nil,
	).Once()
	syncer.On(
		"PushSupplyCommitment", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(nil, nil).Once()

	cfg := CommitPushCfg{
		Log:         &stubPushLog{},
		Syncer:      syncer,
		AssetLookup: lookup,
	}
	ctx := context.Background()

	err := DispatchCommitPush(
		ctx, cfg, fn.None[tapreorg.AnchoringID](), payload,
	)
	require.ErrorContains(t, err, "refused")

	require.NoError(t, DispatchCommitPush(
		ctx, cfg, fn.None[tapreorg.AnchoringID](), payload,
	))
	syncer.AssertExpectations(t)
}

// TestSupplySiteEvaluateCandidate pins the supply site's verdict:
// exactly the broadcast commitment transaction satisfies the anchoring,
// any other spender of its inputs is foreign, and a match blob the site
// cannot decode is an error rather than a verdict. A transaction
// spending only part of the trigger set never reaches the predicate —
// the watcher judges it foreign by the whole-set rule — so it is not a
// case here.
func TestSupplySiteEvaluateCandidate(t *testing.T) {
	t.Parallel()

	preCommitOp := test.RandOp(t)
	commitTx := wire.NewMsgTx(2)
	commitTx.AddTxIn(wire.NewTxIn(&preCommitOp, nil, nil))
	commitTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51}))

	// A rival spends the same input to a different output.
	rivalTx := commitTx.Copy()
	rivalTx.TxOut[0].Value++

	var groupKey [33]byte
	copy(groupKey[:], test.RandPubKey(t).SerializeCompressed())
	match := encodeSupplyBlob(supplyBlob{
		CommitTxid: commitTx.TxHash(),
		GroupKey:   groupKey,
	})

	tests := []struct {
		name    string
		match   tapreorg.VersionedBlob
		spender *wire.MsgTx
		want    tapreorg.Verdict
		wantErr bool
	}{{
		name:    "broadcast commitment transaction satisfies",
		match:   match,
		spender: commitTx,
		want:    tapreorg.VerdictSatisfies,
	}, {
		name:    "other spender of the inputs is foreign",
		match:   match,
		spender: rivalTx,
		want:    tapreorg.VerdictForeign,
	}, {
		name: "undecodable match is an error",
		match: tapreorg.VersionedBlob{
			Version: supplyBlobVersion,
			Data:    []byte{0x01},
		},
		spender: commitTx,
		wantErr: true,
	}}

	site := &SupplySite{}
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
