package tapscript

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewChannelFundingScriptTree tests the NewChannelFundingScriptTree
// function. We use this function to filter out assets used for custom channel
// funding from the balance queries. Therefor the script key cannot change since
// this would lead to inconsistencies in the balance queries.
func TestNewChannelFundingScriptTree(t *testing.T) {
	// This key, threaded through asset.NewScriptKey() would start with 02.
	// We don't do that here so we compare it to the expected compressed
	// form of the public key.
	expectedTaprootKeyHex := "0350aaeb166f4234650d84a2d8a130987aeaf695020" +
		"6e0905401ee74ff3f8d18e6"
	expectedTaprootKeyBytes, err := hex.DecodeString(expectedTaprootKeyHex)
	require.NoError(t, err)

	fundingScriptTree := NewChannelFundingScriptTree()
	taprootKey := fundingScriptTree.TaprootKey

	serializedTaprootKey := taprootKey.SerializeCompressed()
	require.Equal(t, expectedTaprootKeyBytes, serializedTaprootKey)
}
