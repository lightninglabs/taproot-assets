package rpcserver

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

// TestUnmarshalInputProofFiles checks that supplied input proof files are
// keyed by the input their last proof describes.
func TestUnmarshalInputProofFiles(t *testing.T) {
	t.Parallel()

	anchorTx := wire.NewMsgTx(2)
	anchorTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	anchorTx.AddTxOut(&wire.TxOut{Value: 1_000})
	last := proof.RandProof(
		t, asset.RandGenesis(t, asset.Normal), test.RandPubKey(t),
		wire.MsgBlock{Transactions: []*wire.MsgTx{anchorTx}}, 0, 0,
	)
	file, err := proof.NewFile(proof.V0, last)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, file.Encode(&buf))
	blob := buf.Bytes()

	inputProofs, err := unmarshalInputProofFiles(nil)
	require.NoError(t, err)
	require.Nil(t, inputProofs)

	inputProofs, err = unmarshalInputProofFiles([][]byte{blob})
	require.NoError(t, err)
	prevID := asset.PrevID{
		OutPoint:  last.OutPoint(),
		ID:        last.Asset.ID(),
		ScriptKey: asset.ToSerialized(last.Asset.ScriptKey.PubKey),
	}
	require.Equal(t, map[asset.PrevID]proof.Blob{prevID: blob}, inputProofs)

	_, err = unmarshalInputProofFiles([][]byte{blob, blob})
	require.ErrorContains(t, err, "duplicate input proof file")

	_, err = unmarshalInputProofFiles([][]byte{{0x01}})
	require.ErrorContains(t, err, "error decoding input proof file 0")
}
