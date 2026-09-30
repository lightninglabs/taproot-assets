package universe

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

// TestBurnLeafNodeCanonical asserts that the universe leaf of a burn whose
// proof carries several STXO proofs is the same across encodings, including
// after the burn leaf is decoded and encoded again.
func TestBurnLeafNodeCanonical(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	anchorTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51}))
	block := wire.MsgBlock{
		Header:       wire.BlockHeader{Version: 1},
		Transactions: []*wire.MsgTx{anchorTx},
	}
	burnProof := proof.RandProof(
		t, asset.RandGenesis(t, asset.Normal), test.RandPubKey(t),
		block, 0, 0,
	)

	// Attach several STXO proofs to the inclusion proof and to an
	// exclusion proof, as for a burn that spends several inputs.
	commitmentProofs := []*proof.CommitmentProof{
		burnProof.InclusionProof.CommitmentProof,
		burnProof.ExclusionProofs[0].CommitmentProof,
	}
	for _, commitmentProof := range commitmentProofs {
		stxoProofs := make(map[asset.SerializedKey]commitment.Proof)
		for range 4 {
			key := asset.ToSerialized(test.RandPubKey(t))
			stxoProofs[key] = commitmentProof.Proof
		}
		commitmentProof.STXOProofs = stxoProofs
	}

	burnLeaf := &BurnLeaf{BurnProof: &burnProof}
	leafNode, err := burnLeaf.UniverseLeafNode()
	require.NoError(t, err)

	// A single encoding may match by chance, so we encode the burn leaf
	// several times.
	for range 10 {
		again, err := burnLeaf.UniverseLeafNode()
		require.NoError(t, err)
		require.Equal(t, leafNode.NodeHash(), again.NodeHash())

		var buf bytes.Buffer
		require.NoError(t, burnLeaf.Encode(&buf))

		var decoded BurnLeaf
		require.NoError(t, decoded.Decode(&buf))

		decodedNode, err := decoded.UniverseLeafNode()
		require.NoError(t, err)
		require.Equal(t, leafNode.NodeHash(), decodedNode.NodeHash())
	}
}
