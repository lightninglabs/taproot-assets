package proof

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/stretchr/testify/require"
)

// TestEmptyAdditionalInput verifies that a nested empty proof file returns an
// error instead of a nil snapshot.
func TestEmptyAdditionalInput(t *testing.T) {
	t.Parallel()

	p, _ := RandGenesisProofWithKey(
		t, asset.Normal, fn.Ptr(uint64(1)), nil, true, nil, nil, nil,
		nil, asset.V0,
	)
	p.AdditionalInputs = []File{*NewEmptyFile(V0)}

	file, err := NewFile(V0, p)
	require.NoError(t, err)

	require.NotPanics(t, func() {
		_, err = file.Verify(context.Background(), MockVerifierCtx)
	})
	require.ErrorIs(t, err, ErrEmptyProofFile)
}
