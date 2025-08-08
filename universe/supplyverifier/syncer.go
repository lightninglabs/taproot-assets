package supplyverifier

import (
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
)

// UniverseClient is an interface that represents a client connection to a
// remote universe server.
type UniverseClient interface {
	// FetchSupplyLeaves fetches the supply leaves for a specific asset
	// group within a specified block height range.
	FetchSupplyLeaves(ctx context.Context,
		assetSpec asset.Specifier, startBlockHeight,
		endBlockHeight fn.Option[uint32]) (supplycommit.SupplyLeaves,
		error)

	// InsertSupplyLeaves inserts supply leaves for a specific asset group
	// into the remote universe server.
	InsertSupplyLeaves(ctx context.Context, assetSpec asset.Specifier,
		leaves supplycommit.SupplyLeaves) error

	// Close closes the fetcher and cleans up any resources.
	Close() error
}

// UniverseClientFactory is a function type that creates UniverseClient
// instances for a given universe server address.
type UniverseClientFactory func(
	serverAddr universe.ServerAddr) (UniverseClient, error)

// SupplySyncerStore is an interface for storing synced leaves and state.
type SupplySyncerStore interface {
	// UpsertSupplyLeaves stores a batch of supply update events to the
	// database without requiring a supply commitment transition.
	UpsertSupplyLeaves(ctx context.Context, spec asset.Specifier,
		updates []supplycommit.SupplyUpdateEvent) error
}

// SupplySyncer is a struct that is responsible for retrieving supply leaves
// from a universe.
type SupplySyncer struct {
	// clientFactory is a factory function that creates UniverseClient
	// instances for specific universe server addresses.
	clientFactory UniverseClientFactory

	// store is used to persist supply leaves to the local database.
	store SupplySyncerStore
}

// NewSupplySyncer creates a new SupplySyncer with a factory function for
// creating UniverseClient instances and a store for persisting leaves.
func NewSupplySyncer(factory UniverseClientFactory,
	store SupplySyncerStore) SupplySyncer {

	return SupplySyncer{
		clientFactory: factory,
		store:         store,
	}
}

// FetchLeaves retrieves all supply leaves from the specified universe server.
//
// NOTE: This function is thread safe.
func (s *SupplySyncer) FetchLeaves(ctx context.Context,
	serverAddr universe.ServerAddr, assetSpec asset.Specifier,
	startBlockHeight uint32) (supplycommit.SupplyLeaves, error) {

	var zero supplycommit.SupplyLeaves

	// Create a client for the specific universe server address
	client, err := s.clientFactory(serverAddr)
	if err != nil {
		return zero, fmt.Errorf("unable to create universe client: %w",
			err)
	}

	// Ensure the client is properly closed when we're done
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			log.Errorf("unable to close universe client: %v",
				closeErr)
		}
	}()

	leaves, err := client.FetchSupplyLeaves(
		ctx, assetSpec, fn.Some(startBlockHeight), fn.None[uint32](),
	)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch supply leaves: %w",
			err)
	}

	// Convert SupplyLeaves to SupplyUpdateEvents for storage.
	totalLeaves := len(leaves.IssuanceLeafEntries) +
		len(leaves.BurnLeafEntries) +
		len(leaves.IgnoreLeafEntries)
	updates := make([]supplycommit.SupplyUpdateEvent, 0, totalLeaves)

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
	err = s.store.UpsertSupplyLeaves(ctx, assetSpec, updates)
	if err != nil {
		return zero, fmt.Errorf("unable to store supply leaves: %w",
			err)
	}

	return leaves, nil
}
