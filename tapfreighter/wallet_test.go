package tapfreighter

import (
	"context"
	"testing"

	"github.com/lightninglabs/taro/asset"
	"github.com/stretchr/testify/require"
)

// mockCoinLister is a mock implementation of the CoinLister interface.
type mockCoinLister struct {
	eligibleCommitments []*AnchoredCommitment
}

func (m *mockCoinLister) ListEligibleCoins(
	ctx context.Context, constraints CommitmentConstraints) (
	[]*AnchoredCommitment, error) {

	return m.eligibleCommitments, nil
}

// TestCoinSelection tests that the coin selection logic behaves as expected.
func TestCoinSelection(t *testing.T) {
	t.Parallel()

	type testCase struct {
		minTotalAmount      uint64
		eligibleCommitments []*AnchoredCommitment
		strategy            MultiCommitmentSelectStrategy

		// Result analysis parameters.
		//
		// Expected commitments.
		expectedCommitments      []*AnchoredCommitment
		checkSelectedCommitments bool

		// Expected error status.
		expectedSomeErr bool
	}

	testCases := []testCase{
		// Test that an unknown strategy returns an error.
		{
			minTotalAmount:      1000,
			eligibleCommitments: []*AnchoredCommitment{{}},
			strategy:            100, // Set to unknown strategy.
			expectedSomeErr:     true,
		},

		// Test that when the PreferMaxAmount strategy is employed
		// the selected commitment is the max amount commitment.
		{
			minTotalAmount: 1000,
			eligibleCommitments: []*AnchoredCommitment{
				{
					Asset: &asset.Asset{
						Amount: 510,
					},
				},
				{
					Asset: &asset.Asset{
						Amount: 2000,
					},
				},
				{
					Asset: &asset.Asset{
						Amount: 490,
					},
				},
			},
			strategy:                 PreferMaxAmount,
			checkSelectedCommitments: true,
			expectedCommitments: []*AnchoredCommitment{{
				Asset: &asset.Asset{
					Amount: 2000,
				},
			}},
		},

		// Test that when the PreferMaxAmount strategy is employed
		// the selected commitments include the max amount commitment.
		{
			minTotalAmount: 1000,
			eligibleCommitments: []*AnchoredCommitment{
				{
					Asset: &asset.Asset{
						Amount: 980,
					},
				},
				{
					Asset: &asset.Asset{
						Amount: 999,
					},
				},
				{
					Asset: &asset.Asset{
						Amount: 10,
					},
				},
			},
			strategy:                 PreferMaxAmount,
			checkSelectedCommitments: true,
			expectedCommitments: []*AnchoredCommitment{
				{
					Asset: &asset.Asset{
						Amount: 999,
					},
				},
				{
					Asset: &asset.Asset{
						Amount: 980,
					},
				},
			},
		},
	}

	// Execute test cases.
	for idx, testCase := range testCases {
		coinLister := &mockCoinLister{
			eligibleCommitments: testCase.eligibleCommitments,
		}
		coinSelect := NewCoinSelect(coinLister)

		resultCommitments, err := coinSelect.SelectForAmount(
			testCase.minTotalAmount, testCase.eligibleCommitments,
			testCase.strategy,
		)

		// Analyse results.
		if testCase.checkSelectedCommitments {
			require.EqualValues(
				t, testCase.expectedCommitments,
				resultCommitments,
			)
		}

		if testCase.expectedSomeErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}

		// Variable included for debugging (conditional breakpoints),
		// may otherwise be unused.
		_ = idx
	}
}
