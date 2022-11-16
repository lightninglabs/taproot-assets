package asset

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/stretchr/testify/require"
)

// RandGenesis creates a random genesis for testing.
func RandGenesis(t testing.TB, assetType Type) Genesis {
	t.Helper()

	metadata := make([]byte, test.RandInt[int]()%32+1)
	_, err := rand.Read(metadata)
	require.NoError(t, err)

	return Genesis{
		FirstPrevOut: test.RandOp(t),
		Tag:          hex.EncodeToString(metadata),
		Metadata:     metadata,
		OutputIndex:  uint32(test.RandInt[int32]()),
		Type:         assetType,
	}
}

// RandFamilyKey creates a random family key for testing.
func RandFamilyKey(t testing.TB, genesis *Genesis) *FamilyKey {
	privateKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	genSigner := NewRawKeyGenesisSigner(privateKey)

	familyKey, err := DeriveFamilyKey(
		genSigner, test.PubToKeyDesc(privateKey.PubKey()), *genesis,
	)
	require.NoError(t, err)
	return familyKey
}

// RandID creates a random asset ID.
func RandID(t testing.TB) ID {
	var a ID
	_, err := rand.Read(a[:])
	require.NoError(t, err)

	return a
}
