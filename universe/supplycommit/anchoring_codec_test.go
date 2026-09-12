package supplycommit

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/stretchr/testify/require"
)

// The v1 supply blob wire format. See the commentary on the mint
// blob's vector in tapgarden for why a round-trip test cannot pin a
// format and a literal can.
//
// This blob is the sharper case of the two. The supply site's burial
// handler is the only one whose effect crosses a trust boundary — it
// pushes the finalized commitment to remote universes — and its blob
// holds a 32-byte txid beside a 33-byte key, the same pair the mint
// blob holds in the opposite order.

// supplyBlobV1Vector is the canonical encoding of the blob built by
// supplyBlobV1Fixture: CommitTxid (32 bytes) followed by GroupKey (33
// bytes).
const supplyBlobV1Vector = "808182838485868788898a8b8c8d8e8f9091929394" +
	"95969798999a9b9c9d9e9f000102030405060708090a0b0c0d0e0f1011121314" +
	"15161718191a1b1c1d1e1f20"

// supplyBlobV1Fixture builds the blob the vector encodes.
func supplyBlobV1Fixture() supplyBlob {
	var blob supplyBlob
	for i := range blob.CommitTxid {
		blob.CommitTxid[i] = byte(0x80 + i)
	}
	for i := range blob.GroupKey {
		blob.GroupKey[i] = byte(i)
	}

	return blob
}

// TestSupplyBlobV1Format pins the v1 supply blob layout.
func TestSupplyBlobV1Format(t *testing.T) {
	t.Parallel()

	encoded := encodeSupplyBlob(supplyBlobV1Fixture())

	require.EqualValues(t, 1, encoded.Version)
	require.Equal(t, supplyBlobV1Vector, hex.EncodeToString(encoded.Data))

	decoded, err := decodeSupplyBlob(encoded)
	require.NoError(t, err)
	require.Equal(t, supplyBlobV1Fixture(), decoded)
}

// TestSupplyBlobV1Decodes asserts a stored v1 row still decodes.
func TestSupplyBlobV1Decodes(t *testing.T) {
	t.Parallel()

	data, err := hex.DecodeString(supplyBlobV1Vector)
	require.NoError(t, err)

	decoded, err := decodeSupplyBlob(tapreorg.VersionedBlob{
		Version: 1,
		Data:    data,
	})
	require.NoError(t, err)

	var wantTxid chainhash.Hash
	for i := range wantTxid {
		wantTxid[i] = byte(0x80 + i)
	}
	var wantKey [33]byte
	for i := range wantKey {
		wantKey[i] = byte(i)
	}

	require.Equal(t, wantTxid, decoded.CommitTxid)
	require.Equal(t, wantKey, decoded.GroupKey)
}

// The v1 nudge blob wire format: the 33-byte group key alone. It is
// the payload of the abandonment handler's nudge effect, which only
// has to route a tick to the right state machine.

// nudgeBlobV1Vector is the canonical encoding of the blob built by
// nudgeBlobV1Fixture: GroupKey (33 bytes).
const nudgeBlobV1Vector = "000102030405060708090a0b0c0d0e0f1011121314" +
	"15161718191a1b1c1d1e1f20"

// nudgeBlobV1Fixture builds the blob the vector encodes.
func nudgeBlobV1Fixture() nudgeBlob {
	var blob nudgeBlob
	for i := range blob.GroupKey {
		blob.GroupKey[i] = byte(i)
	}

	return blob
}

// TestNudgeBlobV1Format pins the v1 nudge blob layout.
func TestNudgeBlobV1Format(t *testing.T) {
	t.Parallel()

	encoded := encodeNudgeBlob(nudgeBlobV1Fixture())

	require.EqualValues(t, 1, encoded.Version)
	require.Equal(t, nudgeBlobV1Vector, hex.EncodeToString(encoded.Data))

	decoded, err := decodeNudgeBlob(encoded)
	require.NoError(t, err)
	require.Equal(t, nudgeBlobV1Fixture(), decoded)
}

// TestNudgeBlobV1Decodes asserts a stored v1 row still decodes.
func TestNudgeBlobV1Decodes(t *testing.T) {
	t.Parallel()

	data, err := hex.DecodeString(nudgeBlobV1Vector)
	require.NoError(t, err)

	decoded, err := decodeNudgeBlob(tapreorg.VersionedBlob{
		Version: 1,
		Data:    data,
	})
	require.NoError(t, err)

	var wantKey [33]byte
	for i := range wantKey {
		wantKey[i] = byte(i)
	}

	require.Equal(t, wantKey, decoded.GroupKey)
}
