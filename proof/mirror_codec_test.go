package proof

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/stretchr/testify/require"
)

// The v1 mirror-sync payload wire format. See the commentary on the
// mint blob's vector in tapgarden for why a round-trip test cannot pin
// a format and a literal can: the payload is written to the outbox
// and decoded on dispatch, possibly by a later build, so its layout
// is durable state.

// mirrorSyncV1Vector is the canonical encoding of the payload built by
// mirrorSyncV1Fixture: the op byte, a big-endian uint32 locator count,
// then per locator the asset ID (32 bytes), the compressed script key
// (33 bytes), the outpoint hash (32 bytes) and the big-endian uint32
// outpoint index.
const mirrorSyncV1Vector = "01" + "00000001" +
	"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
	"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
	"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
	"00000007"

// mirrorSyncV1Fixture builds the payload the vector encodes: a delete
// of one locator whose fields are drawn from disjoint byte ranges (the
// script key is the curve's generator, whose encoding is fixed), so a
// transposition changes the encoding rather than re-labelling it.
func mirrorSyncV1Fixture() MirrorSyncPayload {
	var (
		assetID asset.ID
		op      wire.OutPoint
	)
	for i := range assetID {
		assetID[i] = byte(i)
	}
	for i := range op.Hash {
		op.Hash[i] = byte(0x80 + i)
	}
	op.Index = 7

	_, scriptKey := btcec.PrivKeyFromBytes([]byte{0x01})

	return MirrorSyncPayload{
		Op: MirrorSyncDelete,
		Locators: []Locator{{
			AssetID:   &assetID,
			ScriptKey: *scriptKey,
			OutPoint:  &op,
		}},
	}
}

// requireSameLocators asserts two locator lists name the same proofs.
func requireSameLocators(t *testing.T, want, got []Locator) {
	t.Helper()

	require.Len(t, got, len(want))
	for i := range want {
		require.Equal(t, want[i].AssetID, got[i].AssetID, "%d", i)
		require.Equal(
			t, want[i].ScriptKey.SerializeCompressed(),
			got[i].ScriptKey.SerializeCompressed(), "%d", i,
		)
		require.Equal(t, want[i].OutPoint, got[i].OutPoint, "%d", i)
	}
}

// TestMirrorSyncV1Format pins the v1 mirror-sync payload layout.
func TestMirrorSyncV1Format(t *testing.T) {
	t.Parallel()

	fixture := mirrorSyncV1Fixture()

	version, data, err := fixture.Encode()
	require.NoError(t, err)
	require.EqualValues(t, 1, version)
	require.Equal(t, mirrorSyncV1Vector, hex.EncodeToString(data))

	decoded, err := DecodeMirrorSyncPayload(version, data)
	require.NoError(t, err)
	require.Equal(t, MirrorSyncDelete, decoded.Op)
	requireSameLocators(t, fixture.Locators, decoded.Locators)

	// The rewrite op differs in the op byte alone.
	fixture.Op = MirrorSyncRewrite
	_, data, err = fixture.Encode()
	require.NoError(t, err)
	require.Equal(t, "02"+mirrorSyncV1Vector[2:], hex.EncodeToString(data))
}

// TestMirrorSyncV1Decodes asserts a stored v1 payload still decodes,
// reading the vector as bytes on disk rather than as something this
// build produced.
func TestMirrorSyncV1Decodes(t *testing.T) {
	t.Parallel()

	data, err := hex.DecodeString(mirrorSyncV1Vector)
	require.NoError(t, err)

	decoded, err := DecodeMirrorSyncPayload(1, data)
	require.NoError(t, err)
	require.Equal(t, MirrorSyncDelete, decoded.Op)
	requireSameLocators(t, mirrorSyncV1Fixture().Locators, decoded.Locators)
}

// TestMirrorSyncDecodeRejects asserts the decoder refuses what it
// cannot have written: an unknown version, an unknown op, and a body
// whose length disagrees with its locator count.
func TestMirrorSyncDecodeRejects(t *testing.T) {
	t.Parallel()

	data, err := hex.DecodeString(mirrorSyncV1Vector)
	require.NoError(t, err)

	_, err = DecodeMirrorSyncPayload(2, data)
	require.ErrorContains(t, err, "unknown mirror sync payload version")

	badOp := append([]byte{0x03}, data[1:]...)
	_, err = DecodeMirrorSyncPayload(1, badOp)
	require.ErrorContains(t, err, "unknown mirror sync op")

	_, err = DecodeMirrorSyncPayload(1, data[:len(data)-1])
	require.ErrorContains(t, err, "names 1 locators")

	// A locator without an outpoint cannot name a mirror file, so
	// it cannot be encoded either.
	fixture := mirrorSyncV1Fixture()
	fixture.Locators[0].OutPoint = nil
	_, _, err = fixture.Encode()
	require.ErrorIs(t, err, ErrOutPointMissing)
}
