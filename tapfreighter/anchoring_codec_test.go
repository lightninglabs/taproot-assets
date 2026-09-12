package tapfreighter

import (
	"encoding/hex"
	"testing"

	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/stretchr/testify/require"
)

// The v1 porter blob wire format. See the commentary on the mint
// blob's vector in tapgarden for why a round-trip test cannot pin a
// format and a literal can.
//
// The porter blob is the one variable-length payload of the four: a
// fixed 32-byte txid followed by the user's burn note as raw bytes,
// with no length prefix. That makes the txid's position load-bearing
// in a way the decoder cannot check — any trailing bytes are accepted
// as a note — so the vector is the only thing standing between a
// layout edit and a silently mis-parsed note on every stored row.

// porterBlobV1Vector is the canonical encoding of the blob built by
// porterBlobV1Fixture: AnchorTxid (32 bytes) followed by the note's
// UTF-8 bytes, unterminated.
const porterBlobV1Vector = "808182838485868788898a8b8c8d8e8f9091929394" +
	"95969798999a9b9c9d9e9f6275726e"

// porterBlobV1Fixture builds the blob the vector encodes. "burn" is
// 6275726e.
func porterBlobV1Fixture() porterBlob {
	var blob porterBlob
	for i := range blob.AnchorTxid {
		blob.AnchorTxid[i] = byte(0x80 + i)
	}
	blob.Note = "burn"

	return blob
}

// TestPorterBlobV1Format pins the v1 porter blob layout.
func TestPorterBlobV1Format(t *testing.T) {
	t.Parallel()

	encoded := encodePorterBlob(porterBlobV1Fixture())

	require.EqualValues(t, 1, encoded.Version)
	require.Equal(t, porterBlobV1Vector, hex.EncodeToString(encoded.Data))

	decoded, err := decodePorterBlob(encoded)
	require.NoError(t, err)
	require.Equal(t, porterBlobV1Fixture(), decoded)
}

// TestPorterBlobV1Decodes asserts a stored v1 row still decodes, and
// that an empty note round-trips as the 32-byte minimum rather than
// being confused with a truncated blob.
func TestPorterBlobV1Decodes(t *testing.T) {
	t.Parallel()

	data, err := hex.DecodeString(porterBlobV1Vector)
	require.NoError(t, err)

	decoded, err := decodePorterBlob(tapreorg.VersionedBlob{
		Version: 1,
		Data:    data,
	})
	require.NoError(t, err)
	require.Equal(t, porterBlobV1Fixture(), decoded)

	// The note-free form: exactly 32 bytes, which is the match data
	// the porter registers with.
	noteless := porterBlobV1Fixture()
	noteless.Note = ""

	encoded := encodePorterBlob(noteless)
	require.Len(t, encoded.Data, 32)

	roundTripped, err := decodePorterBlob(encoded)
	require.NoError(t, err)
	require.Equal(t, noteless, roundTripped)
}
