package proof

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/stretchr/testify/require"
)

// TestGenesisProofMetaReveal verifies that a genesis proof validates the
// revealed metadata before accepting its committed hash, while tolerating
// malformed JSON documents.
func TestGenesisProofMetaReveal(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		metaReveal *MetaReveal
		expectErr  error
	}{
		{
			name: "malformed JSON tolerated",
			metaReveal: &MetaReveal{
				Type: MetaJson,
				Data: []byte("{"),
			},
		},
		{
			name: "decimal display too large",
			metaReveal: &MetaReveal{
				Type: MetaOpaque,
				Data: []byte("meta"),
				DecimalDisplay: fn.Some(
					MaxDecDisplay + 1,
				),
			},
			expectErr: ErrDecDisplayTooLarge,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			p, _ := RandGenesisProofWithKey(
				t, asset.Normal, fn.Ptr(uint64(1)), nil, false,
				testCase.metaReveal, nil, nil, nil, asset.V0,
			)

			_, err := p.Verify(
				context.Background(), nil, MockChainLookup,
				MockVerifierCtx,
			)
			if testCase.expectErr != nil {
				require.ErrorIs(t, err, testCase.expectErr)
				return
			}

			require.NoError(t, err)
		})
	}
}
