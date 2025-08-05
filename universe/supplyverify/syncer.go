package supplyverify

import (
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
)

// SupplyLeafFetcher is an interface that can be used to fetch information from
// a Universe.
type SupplyLeafFetcher interface {
	// FetchSupplyLeaves fetches the supply leaves for a specific asset
	// group within a specified block height range.
	FetchSupplyLeaves(ctx context.Context,
		assetSpec asset.Specifier, startBlockHeight,
		endBlockHeight fn.Option[uint32]) (supplycommit.SupplyLeaves,
		error)

	// Close closes the fetcher and cleans up any resources.
	Close() error
}

// SupplyLeafFetcherFactory is a function type that creates SupplyLeafFetcher
// instances for a given universe server address.
type SupplyLeafFetcherFactory func(
	serverAddr universe.ServerAddr) (SupplyLeafFetcher, error)

// SupplyLeafStore is an interface for storing supply commitment leaves.
type SupplyLeafStore interface {
	// ApplySupplyUpdates stores a batch of supply update events to the
	// database without requiring a transition.
	ApplySupplyUpdates(ctx context.Context, spec asset.Specifier,
		updates []supplycommit.SupplyUpdateEvent) (mssmt.Node, error)
}

// SupplySyncer is a struct that is responsible for retrieving supply leaves
// from a universe.
type SupplySyncer struct {
	// fetcherFactory is a factory function that creates SupplyLeafFetcher
	// instances for specific universe server addresses.
	fetcherFactory SupplyLeafFetcherFactory

	// store is used to persist supply leaves to the local database.
	store SupplyLeafStore
}

// NewSupplySyncer creates a new SupplySyncer with a factory function for
// creating SupplyLeafFetcher instances and a store for persisting leaves.
func NewSupplySyncer(factory SupplyLeafFetcherFactory,
	store SupplyLeafStore) *SupplySyncer {

	return &SupplySyncer{
		fetcherFactory: factory,
		store:          store,
	}
}

// Sync retrieves all supply leaves from the specified universe server.
func (s *SupplySyncer) Sync(ctx context.Context, serverAddr universe.ServerAddr,
	assetSpec asset.Specifier, startBlockHeight uint32) (
	supplycommit.SupplyLeaves, error) {

	var zero supplycommit.SupplyLeaves

	// Create a fetcher for the specific universe server address
	fetcher, err := s.fetcherFactory(serverAddr)
	if err != nil {
		return zero, fmt.Errorf("unable to create supply leaf "+
			"fetcher: %w", err)
	}

	// Ensure the fetcher is properly closed when we're done
	defer func() {
		if closeErr := fetcher.Close(); closeErr != nil {
			// Log the error but don't override the main error
			// TODO(ffranr): Consider using a logger here
		}
	}()

	leaves, err := fetcher.FetchSupplyLeaves(
		ctx, assetSpec, fn.Some(startBlockHeight), fn.None[uint32](),
	)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch supply leaves: %w",
			err)
	}

	// Convert SupplyLeaves to SupplyUpdateEvents for storage.
	var updates []supplycommit.SupplyUpdateEvent

	for i := range leaves.IssuanceLeafEntries {
		updates = append(updates, &leaves.IssuanceLeafEntries[i])
	}

	for i := range leaves.BurnLeafEntries {
		updates = append(updates, &leaves.BurnLeafEntries[i])
	}

	for i := range leaves.IgnoreLeafEntries {
		updates = append(updates, &leaves.IgnoreLeafEntries[i])
	}

	// Store the updates to the local database (ignore the return value).
	_, err = s.store.ApplySupplyUpdates(ctx, assetSpec, updates)
	if err != nil {
		return zero, fmt.Errorf("unable to store supply leaves: %w",
			err)
	}

	return leaves, nil
}
