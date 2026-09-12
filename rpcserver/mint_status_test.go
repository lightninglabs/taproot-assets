package rpcserver

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/stretchr/testify/require"
)

func TestMarshalCustomAnchorStatus(t *testing.T) {
	t.Parallel()

	batchKey, _ := test.RandKeyDesc(t)
	batch := &tapgarden.MintingBatch{
		BatchKey:                 batchKey,
		CustomAnchorLeaseError:   "lease renewal degraded",
		CustomAnchorPublishError: "wallet publication ambiguous",
		CustomAnchorKeyError:     "wallet locator required",
	}

	rpcBatch, err := marshalMintingBatch(batch, true)
	require.NoError(t, err)
	require.Equal(t, batch.CustomAnchorLeaseError,
		rpcBatch.CustomAnchorLeaseError)
	require.Equal(t, batch.CustomAnchorPublishError,
		rpcBatch.CustomAnchorPublishError)
	require.Equal(t, batch.CustomAnchorKeyError,
		rpcBatch.CustomAnchorKeyError)

	batch.CustomAnchorLeaseError = ""
	batch.CustomAnchorPublishError = ""
	batch.CustomAnchorKeyError = ""
	rpcBatch, err = marshalMintingBatch(batch, true)
	require.NoError(t, err)
	require.Empty(t, rpcBatch.CustomAnchorLeaseError)
	require.Empty(t, rpcBatch.CustomAnchorPublishError)
	require.Empty(t, rpcBatch.CustomAnchorKeyError)
}
