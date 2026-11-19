package tapcustody

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/stretchr/testify/require"
)

// The v1 receive blob wire format. See the commentary on the mint
// blob's vector in tapgarden for why a round-trip test cannot pin a
// format and a literal can.
//
// The receive blob is a bare 32-byte txid with no framing at all, so
// it is simultaneously the least likely to be restructured and the
// least able to detect it if it were: every 32-byte string is a valid
// blob, and the decoder's length check cannot distinguish a txid from
// anything else of the same width. Only a literal pins it.

// receiveBlobV1Vector is the canonical encoding of the anchor txid
// built by receiveBlobV1Fixture.
const receiveBlobV1Vector = "808182838485868788898a8b8c8d8e8f909192939" +
	"495969798999a9b9c9d9e9f"

// receiveBlobV1Fixture builds the txid the vector encodes.
func receiveBlobV1Fixture() chainhash.Hash {
	var txid chainhash.Hash
	for i := range txid {
		txid[i] = byte(0x80 + i)
	}

	return txid
}

// TestReceiveBlobV1Format pins the v1 receive blob layout.
func TestReceiveBlobV1Format(t *testing.T) {
	t.Parallel()

	encoded := encodeReceiveBlob(receiveBlobV1Fixture())

	require.EqualValues(t, 1, encoded.Version)
	require.Equal(t, receiveBlobV1Vector, hex.EncodeToString(encoded.Data))

	decoded, err := decodeReceiveBlob(encoded)
	require.NoError(t, err)
	require.Equal(t, receiveBlobV1Fixture(), decoded)
}

// TestReceiveBlobV1Decodes asserts a stored v1 row still decodes.
func TestReceiveBlobV1Decodes(t *testing.T) {
	t.Parallel()

	data, err := hex.DecodeString(receiveBlobV1Vector)
	require.NoError(t, err)

	decoded, err := decodeReceiveBlob(tapreorg.VersionedBlob{
		Version: 1,
		Data:    data,
	})
	require.NoError(t, err)
	require.Equal(t, receiveBlobV1Fixture(), decoded)
}
