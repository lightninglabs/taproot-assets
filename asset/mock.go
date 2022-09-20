package asset

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/lightninglabs/taro/internal/test"
	"github.com/stretchr/testify/require"
)

// RandGenesis creates a random genesis for testing.
func RandGenesis(t *testing.T, assetType Type) Genesis {
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
