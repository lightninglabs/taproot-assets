package tapfreighter

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
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

	// listCalls records the constraints of each ListEligibleCoins call.
	listCalls []CommitmentConstraints
}

func newMockCoinLister(c []*AnchoredCommitment) *mockCoinLister {
	return &mockCoinLister{
		eligibleCommitments: c,
		listSignals:         make(chan struct{}, 100),
		leaseSignals:        make(chan struct{}, 100),
		releaseSignals:      make(chan struct{}, 100),
		deleteSignals:       make(chan struct{}, 100),
	}
}

func (m *mockCoinLister) ListEligibleCoins(_ context.Context,
	constraints CommitmentConstraints) ([]*AnchoredCommitment, error) {

	m.listSignals <- struct{}{}
	m.listCalls = append(m.listCalls, constraints)

	coins := m.eligibleCommitments

	// Emulate the behavior of the database backed lister for bounded
	// listings: coins are returned in pages of CoinLimit coins, in
	// descending amount order, and a page past the end of the coin set
	// reports no matching assets.
	if constraints.CoinLimit > 0 {
		coins = append([]*AnchoredCommitment{}, coins...)
		sort.Slice(coins, func(i, j int) bool {
			return coins[i].Asset.Amount > coins[j].Asset.Amount
		})

		start := min(int(constraints.CoinOffset), len(coins))
		end := min(start+int(constraints.CoinLimit), len(coins))
		coins = coins[start:end]

		if len(coins) == 0 {
			return nil, ErrMatchingAssetsNotFound
		}
	}

	return coins, nil
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

func (m *mockCoinLister) FetchOrphanUTXOs(
	context.Context) ([]*ZeroValueInput, error) {

	return nil, nil
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
				Amount:    1000,
				ScriptKey: asset.RandScriptKey(t),
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

// newTestCommitment creates an anchored commitment with the given amount and
// commitment version. Each commitment gets a unique script key, so
// commitments can be told apart by their PrevID.
func newTestCommitment(t *testing.T, amt uint64,
	version commitment.TapCommitmentVersion) *AnchoredCommitment {

	return &AnchoredCommitment{
		Asset: &asset.Asset{
			Amount:    amt,
			ScriptKey: asset.RandScriptKey(t),
		},
		Commitment: &commitment.TapCommitment{
			Version: version,
		},
	}
}

// TestCoinSelectionPaging tests that eligible coins are listed in bounded
// pages and that listing stops as soon as the accumulated compatible amount
// covers the target.
func TestCoinSelectionPaging(t *testing.T) {
	t.Parallel()

	ctxb := context.Background()
	pageSize := int(eligibleCoinsPageSize)

	repeatCommitments := func(n int, amt uint64,
		version commitment.TapCommitmentVersion) []*AnchoredCommitment {

		commitments := make([]*AnchoredCommitment, n)
		for i := 0; i < n; i++ {
			commitments[i] = newTestCommitment(t, amt, version)
		}

		return commitments
	}

	testCases := []struct {
		name        string
		commitments []*AnchoredCommitment
		targetAmt   uint64
		maxVersion  commitment.TapCommitmentVersion
		prevIDs     []asset.PrevID

		expectedNumSelected int
		expectedListCalls   int
		expectedFallback    bool
		expectedErr         string
	}{{
		// The first page holds more than enough coins, so a single
		// bounded listing should be issued.
		name: "first page covers target",
		commitments: repeatCommitments(
			3*pageSize, 10, commitment.TapCommitmentV1,
		),
		targetAmt:           20,
		maxVersion:          commitment.TapCommitmentV1,
		expectedNumSelected: 2,
		expectedListCalls:   1,
	}, {
		// The target amount needs more coins than a single page
		// holds, so a second page should be fetched.
		name: "second page covers target",
		commitments: repeatCommitments(
			2*pageSize, 1, commitment.TapCommitmentV1,
		),
		targetAmt:           uint64(pageSize + 10),
		maxVersion:          commitment.TapCommitmentV1,
		expectedNumSelected: pageSize + 10,
		expectedListCalls:   2,
	}, {
		// The coins can't cover the target amount, so all pages
		// should be fetched, followed by an unbounded listing that
		// rules out coins a paged listing could have skipped, before
		// giving up.
		name: "insufficient total amount",
		commitments: repeatCommitments(
			2*pageSize+10, 1, commitment.TapCommitmentV1,
		),
		targetAmt:         3 * uint64(pageSize),
		maxVersion:        commitment.TapCommitmentV1,
		expectedListCalls: 4,
		expectedFallback:  true,
		expectedErr:       "insufficient amount available",
	}, {
		// The largest coins are all anchored in incompatible
		// commitments, so listing should continue past them until a
		// compatible coin covers the target.
		name: "incompatible coins on first page",
		commitments: append(
			repeatCommitments(
				pageSize, 100, commitment.TapCommitmentV2,
			),
			newTestCommitment(t, 5, commitment.TapCommitmentV1),
		),
		targetAmt:           5,
		maxVersion:          commitment.TapCommitmentV1,
		expectedNumSelected: 1,
		expectedListCalls:   2,
	}, {
		// When specific inputs are requested, the listing can't be
		// bounded, so a single unbounded listing should be issued.
		name: "prev IDs disable paging",
		commitments: repeatCommitments(
			2*pageSize, 10, commitment.TapCommitmentV1,
		),
		targetAmt:  10,
		maxVersion: commitment.TapCommitmentV1,
		prevIDs: []asset.PrevID{{
			OutPoint: wire.OutPoint{Index: 1},
		}},
		expectedNumSelected: 1,
		expectedListCalls:   1,
	}}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			coinLister := newMockCoinLister(tc.commitments)
			coinSelect := NewCoinSelect(coinLister)

			selected, err := coinSelect.SelectCoins(
				ctxb, CommitmentConstraints{
					MinAmt:  tc.targetAmt,
					PrevIDs: tc.prevIDs,
				}, PreferMaxAmount, tc.maxVersion,
			)

			require.Len(
				t, coinLister.listCalls, tc.expectedListCalls,
			)

			// A listing that couldn't cover the target amount must
			// be followed by an unbounded one.
			numBounded := len(coinLister.listCalls)
			if tc.expectedFallback {
				numBounded--

				last := coinLister.listCalls[numBounded]
				require.EqualValues(t, 0, last.CoinLimit)
			}

			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)

				return
			}

			require.NoError(t, err)
			require.Len(t, selected, tc.expectedNumSelected)

			// All selected coins must be compatible with the
			// maximum commitment version and be distinct coins.
			seen := fn.NewSet[asset.PrevID]()
			for _, c := range selected {
				require.LessOrEqual(
					t, c.Commitment.Version, tc.maxVersion,
				)
				require.False(t, seen.Contains(c.PrevID()))
				seen.Add(c.PrevID())
			}

			// The bounded list calls must all use the expected
			// page size, while requests for specific inputs must
			// be unbounded.
			bounded := coinLister.listCalls[:numBounded]
			for idx, call := range bounded {
				if len(tc.prevIDs) > 0 {
					require.EqualValues(
						t, 0, call.CoinLimit,
					)
					continue
				}

				require.EqualValues(
					t, pageSize, call.CoinLimit,
				)
				require.EqualValues(
					t, idx*pageSize, call.CoinOffset,
				)
			}
		})
	}
}

// scriptedCoinLister is a CoinLister that returns a fixed sequence of pages,
// regardless of the constraints passed to it. It is used to simulate a coin
// set that shifts between pages.
type scriptedCoinLister struct {
	pages     [][]*AnchoredCommitment
	listErr   error
	callCount int

	// unboundedCalls counts the calls that asked for an unbounded listing.
	unboundedCalls int
}

func (m *scriptedCoinLister) ListEligibleCoins(_ context.Context,
	constraints CommitmentConstraints) ([]*AnchoredCommitment, error) {

	if m.listErr != nil {
		return nil, m.listErr
	}

	// An unbounded listing sees every coin, as a real lister would, no
	// matter how the scripted pages are laid out.
	if constraints.CoinLimit == 0 {
		m.unboundedCalls++

		seen := fn.NewSet[asset.PrevID]()
		var all []*AnchoredCommitment
		for _, page := range m.pages {
			for _, c := range page {
				if seen.Contains(c.PrevID()) {
					continue
				}

				seen.Add(c.PrevID())
				all = append(all, c)
			}
		}

		return all, nil
	}

	if m.callCount >= len(m.pages) {
		return nil, ErrMatchingAssetsNotFound
	}

	page := m.pages[m.callCount]
	m.callCount++

	return page, nil
}

func (m *scriptedCoinLister) LeaseCoins(context.Context, [32]byte, time.Time,
	...wire.OutPoint) error {

	return nil
}

func (m *scriptedCoinLister) ReleaseCoins(context.Context,
	...wire.OutPoint) error {

	return nil
}

func (m *scriptedCoinLister) DeleteExpiredLeases(context.Context) error {
	return nil
}

func (m *scriptedCoinLister) FetchOrphanUTXOs(
	context.Context) ([]*ZeroValueInput, error) {

	return nil, nil
}

// TestCoinSelectionPagingDuplicates tests that a coin appearing on two pages,
// which can happen when the coin set shifts between the paged queries, is
// only counted and selected once.
func TestCoinSelectionPagingDuplicates(t *testing.T) {
	t.Parallel()

	ctxb := context.Background()
	pageSize := int(eligibleCoinsPageSize)

	firstPage := make([]*AnchoredCommitment, pageSize)
	for i := 0; i < pageSize; i++ {
		firstPage[i] = newTestCommitment(
			t, 1, commitment.TapCommitmentV1,
		)
	}

	// The second page repeats the last coin of the first page, followed
	// by a fresh coin.
	secondPage := []*AnchoredCommitment{
		firstPage[pageSize-1],
		newTestCommitment(t, 1, commitment.TapCommitmentV1),
	}

	coinLister := &scriptedCoinLister{
		pages: [][]*AnchoredCommitment{firstPage, secondPage},
	}
	coinSelect := NewCoinSelect(coinLister)

	// All distinct coins are needed to cover the target, so the
	// duplicate must not be double counted or double selected.
	targetAmt := uint64(pageSize + 1)
	selected, err := coinSelect.SelectCoins(
		ctxb, CommitmentConstraints{MinAmt: targetAmt},
		PreferMaxAmount, commitment.TapCommitmentV1,
	)
	require.NoError(t, err)
	require.Len(t, selected, pageSize+1)

	seen := fn.NewSet[asset.PrevID]()
	for _, c := range selected {
		require.False(t, seen.Contains(c.PrevID()))
		seen.Add(c.PrevID())
	}

	// Asking for more than the distinct coins can cover must fail, even
	// though the raw listing returned enough rows when counting the
	// duplicate twice.
	coinLister = &scriptedCoinLister{
		pages: [][]*AnchoredCommitment{firstPage, secondPage},
	}
	coinSelect = NewCoinSelect(coinLister)

	_, err = coinSelect.SelectCoins(
		ctxb, CommitmentConstraints{MinAmt: targetAmt + 1},
		PreferMaxAmount, commitment.TapCommitmentV1,
	)
	require.ErrorContains(t, err, "insufficient amount available")

	// The paged listing couldn't cover the target, so it must have been
	// repeated unbounded before giving up.
	require.Equal(t, 1, coinLister.unboundedCalls)
}

// TestCoinSelectionPagingSkip tests that a coin the paged listing skips, which
// can happen when the coin set shifts between the paged queries, is still
// found instead of being reported as insufficient funds.
func TestCoinSelectionPagingSkip(t *testing.T) {
	t.Parallel()

	pageSize := int(eligibleCoinsPageSize)

	// The first page is full, so listing continues. The coin that would
	// have been on the second page is missing from it, as if a larger coin
	// had confirmed in between and shifted it out of the paging window.
	firstPage := make([]*AnchoredCommitment, pageSize)
	for i := 0; i < pageSize; i++ {
		firstPage[i] = newTestCommitment(
			t, 1, commitment.TapCommitmentV1,
		)
	}
	skippedPage := []*AnchoredCommitment{
		newTestCommitment(t, 10, commitment.TapCommitmentV1),
	}

	coinLister := &scriptedCoinLister{
		pages: [][]*AnchoredCommitment{firstPage, {}, skippedPage},
	}
	coinSelect := NewCoinSelect(coinLister)

	// The target can only be covered with the skipped coin, which the
	// unbounded listing that follows the paged one must surface.
	selected, err := coinSelect.SelectCoins(
		context.Background(),
		CommitmentConstraints{MinAmt: uint64(pageSize + 5)},
		PreferMaxAmount, commitment.TapCommitmentV1,
	)
	require.NoError(t, err)
	require.Equal(t, 1, coinLister.unboundedCalls)

	var sum uint64
	for _, c := range selected {
		sum += c.Asset.Amount
	}
	require.GreaterOrEqual(t, sum, uint64(pageSize+5))
}

// TestCoinSelectionListError tests that an unexpected listing error aborts the
// selection instead of being treated as an exhausted coin set.
func TestCoinSelectionListError(t *testing.T) {
	t.Parallel()

	coinLister := &scriptedCoinLister{
		listErr: fmt.Errorf("database on fire"),
	}
	coinSelect := NewCoinSelect(coinLister)

	_, err := coinSelect.SelectCoins(
		context.Background(), CommitmentConstraints{MinAmt: 1},
		PreferMaxAmount, commitment.TapCommitmentV1,
	)
	require.ErrorContains(t, err, "unable to list eligible coins")
	require.ErrorContains(t, err, "database on fire")
}
