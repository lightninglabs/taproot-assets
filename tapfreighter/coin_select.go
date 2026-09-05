package tapfreighter

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
)

const (
	// eligibleCoinsPageSize is the number of coins we fetch per query when
	// listing eligible coins for a send. Coins are listed in descending
	// amount order, so in most cases a single page is enough to cover the
	// target amount. Listing a coin is expensive, as the full commitment
	// of its anchor output is reconstructed, so we only fetch more pages
	// when the previous ones can't cover the target.
	eligibleCoinsPageSize = 32
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
	strategy MultiCommitmentSelectStrategy,
	maxVersion commitment.TapCommitmentVersion) ([]*AnchoredCommitment,
	error) {

	s.coinLock.Lock()
	defer s.coinLock.Unlock()

	// Before we select any coins, let's do some cleanup of expired leases.
	if err := s.coinLister.DeleteExpiredLeases(ctx); err != nil {
		return nil, fmt.Errorf("unable to delete expired leases: %w",
			err)
	}

	listConstraints := CommitmentConstraints{
		AssetSpecifier:    constraints.AssetSpecifier,
		MinAmt:            1,
		ScriptKeyType:     constraints.ScriptKeyType,
		PrevIDs:           constraints.PrevIDs,
		DistinctSpecifier: constraints.DistinctSpecifier,
	}

	// We list the eligible coins in pages of descending amounts, so we can
	// stop listing as soon as the accumulated amount covers the target,
	// instead of loading every coin the node holds. Specific inputs are
	// already bounded by their anchor points at the database layer, but the
	// full previous ID is filtered afterward, so that listing stays
	// unpaged.
	pageSize := int32(eligibleCoinsPageSize)
	if len(constraints.PrevIDs) > 0 {
		pageSize = 0
	}

	listing, err := s.listCoins(
		ctx, listConstraints, constraints.MinAmt, maxVersion, pageSize,
	)
	if err != nil {
		return nil, err
	}

	// Each page is listed by a separate query, so the coin set can shift
	// between two pages and move a coin out of a page we already read past.
	// That can only ever hide coins from us, never invent ones, but it
	// could make us report insufficient funds while the funds are actually
	// there. So if a listing that took more than one page couldn't cover
	// the target amount, we repeat it unbounded to be sure. A listing that
	// took a single page needs no such check, as no offset was applied to
	// it, so it saw the full coin set at that instant.
	if listing.numPages > 1 && listing.amountSum < constraints.MinAmt {
		listing, err = s.listCoins(
			ctx, listConstraints, constraints.MinAmt, maxVersion, 0,
		)
		if err != nil {
			return nil, err
		}
	}

	anchorInputs := fn.Map(
		listing.eligible, func(c *AnchoredCommitment) string {
			return c.AnchorPoint.String()
		},
	)
	log.Infof("Identified %v eligible asset inputs for send of %d to %v: "+
		"%v", len(anchorInputs), constraints.MinAmt,
		constraints.String(), anchorInputs)

	if len(listing.eligible) == 0 {
		return nil, ErrMatchingAssetsNotFound
	}

	if len(listing.compatible) == 0 {
		return nil, fmt.Errorf("%w: no compatible commitments for max "+
			"version %v", ErrMatchingAssetsNotFound, maxVersion)
	}

	selectedCoins, err := s.selectForAmount(
		constraints.MinAmt, listing.compatible, strategy,
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

// coinListing is the set of coins a listing produced.
type coinListing struct {
	// eligible are all the coins that satisfied the constraints.
	eligible []*AnchoredCommitment

	// compatible are the eligible coins that are anchored in a commitment
	// compatible with the requested maximum commitment version.
	compatible []*AnchoredCommitment

	// amountSum is the total amount of the compatible coins.
	amountSum uint64

	// numPages is the number of queries the listing took.
	numPages int
}

// listCoins lists the coins that satisfy the given constraints.
//
// A non-zero pageSize bounds each query to that many coins, which the store
// returns in descending amount order, and listing stops as soon as the
// compatible coins cover the target amount. A zero pageSize lists all coins
// that satisfy the constraints, in no particular order.
//
// A page holding fewer coins than the page size is what tells us that the
// eligible coins are exhausted, so the lister must only return a short page
// when it has nothing left to list.
func (s *CoinSelect) listCoins(ctx context.Context,
	constraints CommitmentConstraints, targetAmt uint64,
	maxVersion commitment.TapCommitmentVersion,
	pageSize int32) (*coinListing, error) {

	var (
		listing   = &coinListing{}
		seenCoins = fn.NewSet[asset.PrevID]()
	)
	for offset := int32(0); ; offset += pageSize {
		constraints.CoinLimit = pageSize
		constraints.CoinOffset = offset

		listing.numPages++

		page, err := s.coinLister.ListEligibleCoins(ctx, constraints)
		switch {
		// A page past the end of the eligible coin set comes back
		// empty, which the lister reports as no assets being found.
		case errors.Is(err, ErrMatchingAssetsNotFound):
			page = nil

		case err != nil:
			return nil, fmt.Errorf("unable to list eligible "+
				"coins: %w", err)
		}

		// We use the raw number of listed coins to detect whether we've
		// exhausted the eligible coins further below. It has to be the
		// raw count, taken before the filters below: a page made up
		// entirely of coins we've already seen, or of coins in
		// incompatible commitments, is still a full page, and stopping
		// on it would report insufficient funds while spendable coins
		// sit on a later page.
		numListed := len(page)

		// The coin set can shift between pages, as the queries run in
		// separate database transactions. We de-duplicate the coins
		// here, so a shift can never cause the same coin to be
		// selected twice.
		page = fn.Filter(page, func(c *AnchoredCommitment) bool {
			return !seenCoins.Contains(c.PrevID())
		})
		for _, c := range page {
			seenCoins.Add(c.PrevID())
		}

		listing.eligible = append(listing.eligible, page...)

		// Only coins anchored in a compatible commitment can be
		// selected, so only those count towards the target amount.
		compatible := fn.Filter(page, func(c *AnchoredCommitment) bool {
			return c.Commitment.Version <= maxVersion
		})
		listing.compatible = append(listing.compatible, compatible...)
		for _, c := range compatible {
			listing.amountSum += c.Asset.Amount
		}

		// We stop listing once the compatible coins cover the target
		// amount, once we've exhausted the eligible coins (which an
		// unbounded or partial page indicates), or once a page no
		// longer adds any coin we haven't already seen, which also
		// guarantees that this loop terminates.
		if listing.amountSum >= targetAmt || pageSize == 0 ||
			numListed < int(pageSize) || len(page) == 0 {

			return listing, nil
		}
	}
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
		return nil, fmt.Errorf("%w: insufficient amount available, "+
			"have %d, want %d", ErrMatchingAssetsNotFound,
			amountSum, minTotalAmount)
	}
	return selectedCommitments, nil
}

// SelectOrphanCoins fetches all managed UTXOs that contain only
// zero-value assets (tombstones and burns). The selected UTXOs are
// leased for the default lease duration.
func (s *CoinSelect) SelectOrphanCoins(ctx context.Context) (
	[]*ZeroValueInput, error) {

	s.coinLock.Lock()
	defer s.coinLock.Unlock()

	// Fetch all zero-value UTXOs that are eligible for sweeping.
	zeroValueInputs, err := s.coinLister.FetchOrphanUTXOs(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch zero-value UTXOs: %w",
			err)
	}

	// We now need to lock/lease/reserve those selected coins so
	// that they can't be used by other processes.
	if len(zeroValueInputs) > 0 {
		expiry := time.Now().UTC().Add(defaultCoinLeaseDuration)
		zeroValueOutpoints := fn.Map(
			zeroValueInputs,
			func(z *ZeroValueInput) wire.OutPoint {
				return z.OutPoint
			},
		)
		err = s.coinLister.LeaseCoins(
			ctx, defaultWalletLeaseIdentifier, expiry,
			zeroValueOutpoints...,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to lease zero-value "+
				"UTXOs: %w", err)
		}

		log.Debugf("Selected and leased %d zero-value UTXOs",
			len(zeroValueInputs))
	}

	return zeroValueInputs, nil
}

var _ CoinSelector = (*CoinSelect)(nil)
