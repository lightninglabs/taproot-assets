package tapfreighter

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/stretchr/testify/require"
)

// mockCoinLister is a mock implementation of the CoinLister interface.
type mockCoinLister struct {
	eligibleCommitments []*AnchoredCommitment

	listSignals    chan struct{}
	leaseSignals   chan struct{}
	releaseSignals chan struct{}
	deleteSignals  chan struct{}
}

func newMockCoinLister(c []*AnchoredCommitment) *mockCoinLister {
	return &mockCoinLister{
		eligibleCommitments: c,
		listSignals:         make(chan struct{}, 1),
		leaseSignals:        make(chan struct{}, 1),
		releaseSignals:      make(chan struct{}, 1),
		deleteSignals:       make(chan struct{}, 1),
	}
}

func (m *mockCoinLister) ListEligibleCoins(context.Context,
	CommitmentConstraints) ([]*AnchoredCommitment, error) {

	m.listSignals <- struct{}{}

	return m.eligibleCommitments, nil
}

func (m *mockCoinLister) LeaseCoins(context.Context, [32]byte, time.Time,
	...wire.OutPoint) error {

	m.leaseSignals <- struct{}{}

	return nil
}

func (m *mockCoinLister) ReleaseCoins(context.Context, ...wire.OutPoint) error {
	m.releaseSignals <- struct{}{}

	return nil
}

func (m *mockCoinLister) DeleteExpiredLeases(ctx context.Context) error {
	m.deleteSignals <- struct{}{}

	return nil
}

// TestCoinSelector tests that the coin selector behaves as expected.
func TestCoinSelector(t *testing.T) {
	var (
		ctxb       = context.Background()
		timeout    = 20 * time.Millisecond
		coinLister = newMockCoinLister(nil)
		coinSelect = NewCoinSelect(coinLister)
	)

	// Make sure the correct methods are called on the coin lister depending
	// on the input.
	_, err := coinSelect.SelectCoins(
		ctxb, CommitmentConstraints{MinAmt: 1}, PreferMaxAmount,
		commitment.TapCommitmentV1,
	)
	require.ErrorIs(t, err, ErrMatchingAssetsNotFound)

	// Both the list and delete signals should have been sent.
	_, err = fn.RecvOrTimeout(coinLister.deleteSignals, timeout)
	require.NoError(t, err)
	_, err = fn.RecvOrTimeout(coinLister.listSignals, timeout)
	require.NoError(t, err)

	// But because of the error we shouldn't have leased any coins.
	_, err = fn.RecvOrTimeout(coinLister.listSignals, timeout)
	require.Error(t, err)

	// Now let's add some UTXOs to the coin lister and actually select some.
	coinLister.eligibleCommitments = []*AnchoredCommitment{
		{
			Asset: &asset.Asset{
				Amount: 1000,
			},
			Commitment: &commitment.TapCommitment{
				Version: commitment.TapCommitmentV1,
			},
		},
	}

	// Coin selection should fail if there are no compatible commitments.
	_, err = coinSelect.SelectCoins(
		ctxb, CommitmentConstraints{MinAmt: 1}, PreferMaxAmount,
		commitment.TapCommitmentV0,
	)
	require.ErrorIs(t, err, ErrMatchingAssetsNotFound)
	_, err = fn.RecvOrTimeout(coinLister.deleteSignals, timeout)
	require.NoError(t, err)
	_, err = fn.RecvOrTimeout(coinLister.listSignals, timeout)
	require.NoError(t, err)

	selected, err := coinSelect.SelectCoins(
		ctxb, CommitmentConstraints{MinAmt: 1}, PreferMaxAmount,
		commitment.TapCommitmentV1,
	)
	require.NoError(t, err)
	require.Len(t, selected, 1)

	// In addition to old leases being deleted and coins listed, we now also
	// should have leased the selected coins.
	_, err = fn.RecvOrTimeout(coinLister.deleteSignals, timeout)
	require.NoError(t, err)
	_, err = fn.RecvOrTimeout(coinLister.listSignals, timeout)
	require.NoError(t, err)
	_, err = fn.RecvOrTimeout(coinLister.leaseSignals, timeout)
	require.NoError(t, err)
}

// TestCoinSelection tests that the coin selection logic behaves as expected.
func TestCoinSelection(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name                string
		minTotalAmount      uint64
		eligibleCommitments []*AnchoredCommitment
		strategy            MultiCommitmentSelectStrategy

		// Expected commitments (only set if no error is expected).
		expectedCommitments []*AnchoredCommitment

		// Expected error status.
		expectedErr string
	}

	testCases := []testCase{
		// Test that an unknown strategy returns an error.
		{
			name:                "unknown strategy",
			minTotalAmount:      1000,
			eligibleCommitments: []*AnchoredCommitment{{}},
			strategy:            100,
			expectedErr: "unknown multi coin selection " +
				"strategy",
		},

		// Test that when the PreferMaxAmount strategy is employed
		// the selected commitment is the max amount commitment.
		{
			name:           "prefer max amount",
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
			strategy: PreferMaxAmount,
			expectedCommitments: []*AnchoredCommitment{{
				Asset: &asset.Asset{
					Amount: 2000,
				},
			}},
		},

		// Test that when the PreferMaxAmount strategy is employed
		// the selected commitments include the max amount commitment.
		{
			name: "prefer max amount with multiple " +
				"commitments",
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
			strategy: PreferMaxAmount,
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
		{
			name:           "not enough assets",
			minTotalAmount: 1000,
			eligibleCommitments: []*AnchoredCommitment{
				{
					Asset: &asset.Asset{
						Amount: 980,
					},
				},
			},
			strategy:    PreferMaxAmount,
			expectedErr: ErrMatchingAssetsNotFound.Error(),
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			coinLister := newMockCoinLister(tc.eligibleCommitments)
			coinSelect := NewCoinSelect(coinLister)

			resultCommitments, err := coinSelect.selectForAmount(
				tc.minTotalAmount, tc.eligibleCommitments,
				tc.strategy,
			)

			if tc.expectedErr == "" {
				require.NoError(t, err)

				require.EqualValues(
					t, tc.expectedCommitments,
					resultCommitments,
				)

				return
			}

			require.ErrorContains(t, err, tc.expectedErr)
		})
	}
}
