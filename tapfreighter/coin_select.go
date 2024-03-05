package tapfreighter

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
)

// NewCoinSelect creates a new CoinSelect.
func NewCoinSelect(coinLister CoinLister) *CoinSelect {
	return &CoinSelect{
		coinLister: coinLister,
	}
}

// CoinSelect selects asset coins to spend in order to fund a send
// transaction.
type CoinSelect struct {
	coinLister CoinLister

	// coinLock is a read/write mutex that is used to ensure that only one
	// goroutine is attempting to call any coin selection related methods at
	// any time. This is necessary as some of the calls to the store (e.g.
	// ListEligibleCoins -> LeaseCoin) are called after each other and
	// cannot be placed within the same database transaction. So calls to
	// those methods must hold this coin lock.
	coinLock sync.Mutex
}

// SelectCoins returns a set of not yet leased coins that satisfy the given
// constraints and strategy. The coins returned are leased for the default lease
// duration.
func (s *CoinSelect) SelectCoins(ctx context.Context,
	constraints CommitmentConstraints,
	strategy MultiCommitmentSelectStrategy) ([]*AnchoredCommitment, error) {

	s.coinLock.Lock()
	defer s.coinLock.Unlock()

	// Before we select any coins, let's do some cleanup of expired leases.
	if err := s.coinLister.DeleteExpiredLeases(ctx); err != nil {
		return nil, fmt.Errorf("unable to delete expired leases: %w",
			err)
	}

	listConstraints := CommitmentConstraints{
		GroupKey: constraints.GroupKey,
		AssetID:  constraints.AssetID,
		MinAmt:   1,
	}
	eligibleCommitments, err := s.coinLister.ListEligibleCoins(
		ctx, listConstraints,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to list eligible coins: %w", err)
	}

	log.Infof("Identified %v eligible asset inputs for send of %d to %v",
		len(eligibleCommitments), constraints)

	selectedCoins, err := s.selectForAmount(
		constraints.MinAmt, eligibleCommitments, strategy,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to select coins: %w", err)
	}

	// We now need to lock/lease/reserve those selected coins so
	// that they can't be used by other processes.
	expiry := time.Now().Add(defaultCoinLeaseDuration)
	coinOutPoints := fn.Map(
		selectedCoins, func(c *AnchoredCommitment) wire.OutPoint {
			return c.AnchorPoint
		},
	)
	err = s.coinLister.LeaseCoins(
		ctx, defaultWalletLeaseIdentifier, expiry, coinOutPoints...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to lease coin: %w", err)
	}

	return selectedCoins, nil
}

// LeaseCoins leases/locks/reserves coins for the given lease owner until the
// given expiry. This is used to prevent multiple concurrent coin selection
// attempts from selecting the same coin(s).
func (s *CoinSelect) LeaseCoins(ctx context.Context, leaseOwner [32]byte,
	expiry time.Time, utxoOutpoints ...wire.OutPoint) error {

	s.coinLock.Lock()
	defer s.coinLock.Unlock()

	return s.coinLister.LeaseCoins(
		ctx, leaseOwner, expiry, utxoOutpoints...,
	)
}

// ReleaseCoins releases/unlocks coins that were previously leased and makes
// them available for coin selection again.
func (s *CoinSelect) ReleaseCoins(ctx context.Context,
	utxoOutpoints ...wire.OutPoint) error {

	s.coinLock.Lock()
	defer s.coinLock.Unlock()

	return s.coinLister.ReleaseCoins(ctx, utxoOutpoints...)
}

// selectForAmount selects a subset of the given eligible commitments which
// cumulatively sum to at least the minimum required amount. The selection
// strategy determines how the commitments are selected.
func (s *CoinSelect) selectForAmount(minTotalAmount uint64,
	eligibleCommitments []*AnchoredCommitment,
	strategy MultiCommitmentSelectStrategy) ([]*AnchoredCommitment,
	error) {

	// Select the first subset of eligible commitments which cumulatively
	// sum to at least the minimum required amount.
	var selectedCommitments []*AnchoredCommitment
	amountSum := uint64(0)

	switch strategy {
	case PreferMaxAmount:
		// Sort eligible commitments from the largest amount to
		// smallest.
		sort.Slice(
			eligibleCommitments, func(i, j int) bool {
				isLess := eligibleCommitments[i].Asset.Amount <
					eligibleCommitments[j].Asset.Amount

				// Negate the result to sort in descending
				// order.
				return !isLess
			},
		)

		// Select the first subset of eligible commitments which
		// cumulatively sum to at least the minimum required amount.
		for _, anchoredCommitment := range eligibleCommitments {
			selectedCommitments = append(
				selectedCommitments, anchoredCommitment,
			)

			// Keep track of the total amount of assets we've seen
			// so far.
			amountSum += anchoredCommitment.Asset.Amount
			if amountSum >= minTotalAmount {
				// At this point a target min amount was
				// specified and has been reached.
				break
			}
		}

	default:
		return nil, fmt.Errorf("unknown multi coin selection "+
			"strategy: %v", strategy)
	}

	// Having examined all the eligible commitments, return an error if the
	// minimal funding amount was not reached.
	if amountSum < minTotalAmount {
		return nil, ErrMatchingAssetsNotFound
	}
	return selectedCommitments, nil
}

var _ CoinSelector = (*CoinSelect)(nil)
