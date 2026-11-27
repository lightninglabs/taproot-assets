package tapchannel

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestCreateCloseAllocMissingAssetKey asserts that shutdown records without
// an asset internal key are rejected instead of crashing the allocation.
func TestCreateCloseAllocMissingAssetKey(t *testing.T) {
	t.Parallel()

	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubKey := priv.PubKey()

	full := tapchannelmsg.NewAuxShutdownMsg(
		pubKey, pubKey, tapchannelmsg.ScriptKeyMap{}, nil,
	)

	// A complete set of records produces an allocation.
	alloc, err := createCloseAlloc(true, true, 1, *full)
	require.NoError(t, err)
	require.Equal(t, pubKey, alloc.InternalKey)

	// Encode only the BTC key and script key records. The asset key is
	// optional on the wire, so the message decodes with a nil key.
	stream, err := tlv.NewStream(
		full.BtcInternalKey.Record(), full.ScriptKeys.Record(),
	)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, stream.Encode(&buf))

	partial, err := tapchannelmsg.DecodeAuxShutdownMsg(buf.Bytes())
	require.NoError(t, err)
	require.Nil(t, partial.AssetInternalKey.Val)

	_, err = createCloseAlloc(true, true, 1, *partial)
	require.ErrorContains(t, err, "no asset internal key")
}
