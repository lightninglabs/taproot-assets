package tapgarden

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNoOpAugmenterValidateSeedling exhaustively verifies that the fallback
// augmenter accepts ordinary seedlings and rejects supply-commit seedlings.
func TestNoOpAugmenterValidateSeedling(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		supplyCommitments bool
		wantErr           bool
	}{
		{
			name:              "ordinary seedling",
			supplyCommitments: false,
		},
		{
			name:              "supply-commit seedling",
			supplyCommitments: true,
			wantErr:           true,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			seedling := Seedling{
				SupplyCommitments: testCase.supplyCommitments,
			}
			err := (NoOpAugmenter{}).ValidateSeedling(
				nil, seedling,
			)
			if testCase.wantErr {
				require.ErrorContains(
					t, err,
					"no GenesisTxAugmenter is configured",
				)
				return
			}

			require.NoError(t, err)
		})
	}
}
