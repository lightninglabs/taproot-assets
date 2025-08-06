package supplyverifier

import (
	"context"
	"fmt"
	"net/url"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
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

	// InsertSupplyCommit inserts a supply commitment for a specific
	// asset group into the remote universe server.
	InsertSupplyCommit(ctx context.Context, assetSpec asset.Specifier,
		commitment supplycommit.RootCommitment,
		updateLeaves supplycommit.SupplyLeaves,
		chainProof supplycommit.ChainProof) error

	// Close closes the fetcher and cleans up any resources.
	Close() error
}

// UniverseClientFactory is a function type that creates UniverseClient
// instances for a given universe server address.
type UniverseClientFactory func(serverAddr url.URL) (UniverseClient, error)

// SupplySyncerStore is an interface for storing synced leaves and state.
type SupplySyncerStore interface {
	// LogRemoteFetch stores a batch of supply update events fetched from
	// a remote universe to the database without requiring a supply
	// commitment transition.
	LogRemoteFetch(ctx context.Context, spec asset.Specifier,
		updates []supplycommit.SupplyUpdateEvent) error

	// LogRemoteInsert logs that supply leaves have been successfully
	// inserted into a remote universe.
	LogRemoteInsert(ctx context.Context, spec asset.Specifier,
		leaves supplycommit.SupplyLeaves) error
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
	serverAddr url.URL, assetSpec asset.Specifier,
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
	err = s.store.LogRemoteFetch(ctx, assetSpec, updates)
	if err != nil {
		return zero, fmt.Errorf("unable to store supply leaves: %w",
			err)
	}

	return leaves, nil
}

// pushUniServer pushes the supply commitment to a specific universe server.
func (s *SupplySyncer) pushUniServer(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment,
	updateLeaves supplycommit.SupplyLeaves,
	chainProof supplycommit.ChainProof, serverAddr url.URL) error {

	// Create a client for the specific universe server address.
	client, err := s.clientFactory(serverAddr)
	if err != nil {
		return fmt.Errorf("unable to create universe client: %w", err)
	}

	// Ensure the client is properly closed when we're done.
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			log.Errorf("unable to close universe client: %v",
				closeErr)
		}
	}()

	err = client.InsertSupplyCommit(
		ctx, assetSpec, commitment, updateLeaves, chainProof,
	)
	if err != nil {
		return fmt.Errorf("unable to insert supply leaves: %w", err)
	}

	// Log the successful insertion to the remote universe.
	err = s.store.LogRemoteInsert(ctx, assetSpec, updateLeaves)
	if err != nil {
		return fmt.Errorf("unable to log remote insert: %w", err)
	}

	return nil
}

// PushSupplyCommitment pushes a supply commitment to the remote universe
// server. This function should block until the sync insertion is complete.
//
// NOTE: This function must be thread safe.
func (s *SupplySyncer) PushSupplyCommitment(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment,
	updateLeaves supplycommit.SupplyLeaves,
	chainProof supplycommit.ChainProof,
	canonicalUniverses []url.URL) error {

	// TODO(ffranr): Execute the push in parallel for each universe addr.
	//  Onc failed attempt should not cancel the others.
	for idx := range canonicalUniverses {
		serverAddr := canonicalUniverses[idx]

		// Push the supply commitment to the universe server.
		err := s.pushUniServer(
			ctx, assetSpec, commitment, updateLeaves, chainProof,
			serverAddr,
		)
		if err != nil {
			return fmt.Errorf("unable to push supply commitment "+
				"to %s: %w", serverAddr.String(), err)
		}
	}

	return nil
}
