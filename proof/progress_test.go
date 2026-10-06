package proof

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/stretchr/testify/require"
)

// TestProofProgressCallback verifies that full-file verification reports each
// successfully verified proof step through the operation context.
func TestProofProgressCallback(t *testing.T) {
	t.Parallel()

	amt := uint64(100)
	genesisProof, _ := RandGenesisProofWithKey(
		t, asset.Normal, &amt, nil, true, nil, nil, nil, nil,
		asset.V0,
	)
	proofFile, err := NewFile(V0, genesisProof)
	require.NoError(t, err)

	var progressCount atomic.Uint32
	ctx := WithProgressCallback(context.Background(), func() {
		progressCount.Add(1)
	})

	_, err = proofFile.Verify(ctx, MockVerifierCtx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, progressCount.Load(), uint32(1))
}
