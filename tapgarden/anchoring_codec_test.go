package tapgarden

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/stretchr/testify/require"
)

// The v1 mint blob wire format.
//
// Anchoring blobs are durable: they are written to
// reorg_anchorings.match_data and payload_data at registration and
// decoded on every restart, delivery and outbox dispatch thereafter.
// A layout change is therefore not a refactor — it mis-decodes every
// row already on disk.
//
// A round-trip test cannot see such a change, because it exercises the
// encoder and the decoder together: any edit applied to both leaves
// encode(decode(x)) == x intact. Swapping the two fields of mintBlob in
// both functions keeps every existing assertion green while silently
// re-defining the format. The mint and supply blobs make that concrete
// — both are a 33-byte key beside a 32-byte txid, in opposite orders —
// so the swap is a plausible edit, not a contrived one.
//
// The vector below pins the layout against a literal instead. It must
// only ever change alongside a version bump and a decoder that still
// reads version 1.

// mintBlobV1Vector is the canonical encoding of the blob built by
// mintBlobV1Fixture: RawBatchKey (33 bytes) followed by GenesisTxid
// (32 bytes).
const mintBlobV1Vector = "000102030405060708090a0b0c0d0e0f101112131415" +
	"161718191a1b1c1d1e1f20808182838485868788898a8b8c8d8e8f9091929394" +
	"95969798999a9b9c9d9e9f"

// mintBlobV1Fixture builds the blob the vector encodes. The two fields
// are drawn from disjoint byte ranges so that a transposition changes
// the encoding rather than merely re-labelling it.
func mintBlobV1Fixture() mintBlob {
	var blob mintBlob
	for i := range blob.RawBatchKey {
		blob.RawBatchKey[i] = byte(i)
	}
	for i := range blob.GenesisTxid {
		blob.GenesisTxid[i] = byte(0x80 + i)
	}

	return blob
}

// TestMintBlobV1Format pins the v1 mint blob layout.
func TestMintBlobV1Format(t *testing.T) {
	t.Parallel()

	encoded := encodeMintBlob(mintBlobV1Fixture())

	require.EqualValues(t, 1, encoded.Version)
	require.Equal(t, mintBlobV1Vector, hex.EncodeToString(encoded.Data))

	// The vector must also decode back to the fixture, so the format
	// is pinned in both directions rather than only on the way out.
	decoded, err := decodeMintBlob(encoded)
	require.NoError(t, err)
	require.Equal(t, mintBlobV1Fixture(), decoded)
}

// TestMintBlobV1Decodes asserts a stored v1 row still decodes, reading
// the vector as bytes on disk rather than as something this build
// produced.
func TestMintBlobV1Decodes(t *testing.T) {
	t.Parallel()

	data, err := hex.DecodeString(mintBlobV1Vector)
	require.NoError(t, err)

	decoded, err := decodeMintBlob(tapreorg.VersionedBlob{
		Version: 1,
		Data:    data,
	})
	require.NoError(t, err)

	var wantKey [33]byte
	for i := range wantKey {
		wantKey[i] = byte(i)
	}
	var wantTxid chainhash.Hash
	for i := range wantTxid {
		wantTxid[i] = byte(0x80 + i)
	}

	require.Equal(t, wantKey, decoded.RawBatchKey)
	require.Equal(t, wantTxid, decoded.GenesisTxid)
}
