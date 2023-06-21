package asset

import (
	"encoding/hex"
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

// RandGenesis creates a random genesis for testing.
func RandGenesis(t testing.TB, assetType Type) Genesis {
	t.Helper()

	var metaHash [32]byte
	test.RandRead(t, metaHash[:])

	return Genesis{
		FirstPrevOut: test.RandOp(t),
		Tag:          hex.EncodeToString(metaHash[:]),
		MetaHash:     metaHash,
		OutputIndex:  uint32(test.RandInt[int32]()),
		Type:         assetType,
	}
}

// RandGroupKey creates a random group key for testing.
func RandGroupKey(t testing.TB, genesis Genesis) *GroupKey {
	privateKey := test.RandPrivKey(t)

	genSigner := NewRawKeyGenesisSigner(privateKey)

	groupKey, err := DeriveGroupKey(
		genSigner, test.PubToKeyDesc(privateKey.PubKey()),
		genesis, nil,
	)
	require.NoError(t, err)
	return groupKey
}

// RandGroupKeyWithSigner creates a random group key for testing, and provides
// the signer for reissuing assets into the same group.
func RandGroupKeyWithSigner(t testing.TB, genesis Genesis) (*GroupKey, []byte) {
	privateKey := test.RandPrivKey(t)

	genSigner := NewRawKeyGenesisSigner(privateKey)
	groupKey, err := DeriveGroupKey(
		genSigner, test.PubToKeyDesc(privateKey.PubKey()),
		genesis, nil,
	)
	require.NoError(t, err)

	return groupKey, privateKey.Serialize()
}

// RandScriptKey creates a random script key for testing.
func RandScriptKey(t testing.TB) ScriptKey {
	return NewScriptKey(test.RandPrivKey(t).PubKey())
}

// RandSerializedKey creates a random serialized key for testing.
func RandSerializedKey(t testing.TB) SerializedKey {
	return ToSerialized(test.RandPrivKey(t).PubKey())
}

// RandID creates a random asset ID.
func RandID(t testing.TB) ID {
	var a ID
	test.RandRead(t, a[:])

	return a
}

// RandAsset creates a random asset of the given type for testing.
func RandAsset(t testing.TB, assetType Type) *Asset {
	t.Helper()

	genesis := RandGenesis(t, assetType)
	familyKey := RandGroupKey(t, genesis)
	scriptKey := RandScriptKey(t)

	return RandAssetWithValues(t, genesis, familyKey, scriptKey)
}

// RandAssetWithValues creates a random asset with the given genesis and keys
// for testing.
func RandAssetWithValues(t testing.TB, genesis Genesis, groupKey *GroupKey,
	scriptKey ScriptKey) *Asset {

	t.Helper()

	units := test.RandInt[uint64]() + 1

	switch genesis.Type {
	case Normal:

	case Collectible:
		units = 1

	default:
		t.Fatal("unhandled asset type", genesis.Type)
	}

	a, err := New(genesis, units, 0, 0, scriptKey, groupKey)
	require.NoError(t, err)

	return a
}
