package tapdb

import (
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
)

// SupplySyncerStore implements the persistent storage for supply syncing
// operations. It provides methods to store supply updates without requiring
// a supply commitment transition.
type SupplySyncerStore struct {
	db BatchedUniverseTree
}

// NewSupplySyncerStore creates a new supply syncer DB store handle.
func NewSupplySyncerStore(db BatchedUniverseTree) *SupplySyncerStore {
	return &SupplySyncerStore{
		db: db,
	}
}

// LogRemoteFetch stores a batch of supply update events fetched from a remote
// universe to the database and logs the max fetch block height in the same
// db transaction.
func (s *SupplySyncerStore) LogRemoteFetch(ctx context.Context,
	spec asset.Specifier,
	updates []supplycommit.SupplyUpdateEvent) error {

	// If no updates were provided, return early without error.
	if len(updates) == 0 {
		return nil
	}

	// Find the highest block height from all the supply update events.
	var maxBlockHeight uint32
	for _, update := range updates {
		if height := update.BlockHeight(); height > maxBlockHeight {
			maxBlockHeight = height
		}
	}

	// All updates must have a valid block height.
	if maxBlockHeight == 0 {
		return fmt.Errorf("all supply updates must have a valid " +
			"block height greater than 0")
	}

	// Extract the group key for logging.
	groupKey, err := spec.UnwrapGroupKeyOrErr()
	if err != nil {
		return fmt.Errorf("group key must be specified for supply "+
			"syncer: %w", err)
	}

	var writeTx BaseUniverseStoreOptions
	return s.db.ExecTx(ctx, &writeTx, func(dbTx BaseUniverseStore) error {
		// Reuse the internal supply update logic which handles all
		// the complex subtree and root tree updates within the
		// transaction.
		_, err := applySupplyUpdatesInternal(ctx, dbTx, spec, updates)
		if err != nil {
			return err
		}

		// Log the latest synced block height for this asset group.
		groupKeyBytes := groupKey.SerializeCompressed()
		err = dbTx.UpsertSupplySyncerLog(
			ctx, sqlc.UpsertSupplySyncerLogParams{
				GroupKey:              groupKeyBytes,
				MaxFetchedBlockHeight: sqlInt32(maxBlockHeight),
			},
		)
		if err != nil {
			return fmt.Errorf("failed to log synced block "+
				"height: %w", err)
		}

		return nil
	})
}

// LogRemoteInsert logs that supply leaves have been successfully inserted
// into a remote universe.
func (s *SupplySyncerStore) LogRemoteInsert(ctx context.Context,
	spec asset.Specifier, leaves supplycommit.SupplyLeaves) error {

	// Calculate the total number of leaves.
	totalLeaves := len(leaves.IssuanceLeafEntries) +
		len(leaves.BurnLeafEntries) +
		len(leaves.IgnoreLeafEntries)

	// If no leaves were provided, return early without error.
	if totalLeaves == 0 {
		return nil
	}

	// Find the highest block height from all the supply leaves.
	var maxBlockHeight uint32
	for _, leafEntry := range leaves.IssuanceLeafEntries {
		if height := leafEntry.BlockHeight(); height > maxBlockHeight {
			maxBlockHeight = height
		}
	}
	for _, leafEntry := range leaves.BurnLeafEntries {
		if height := leafEntry.BlockHeight(); height > maxBlockHeight {
			maxBlockHeight = height
		}
	}
	for _, leafEntry := range leaves.IgnoreLeafEntries {
		if height := leafEntry.BlockHeight(); height > maxBlockHeight {
			maxBlockHeight = height
		}
	}

	// All leaves must have a valid block height.
	if maxBlockHeight == 0 {
		return fmt.Errorf("all supply leaves must have a valid " +
			"block height greater than 0")
	}

	// Extract the group key for the log entry.
	groupKey, err := spec.UnwrapGroupKeyOrErr()
	if err != nil {
		return fmt.Errorf("group key must be specified for supply "+
			"syncer log: %w", err)
	}

	var writeTx BaseUniverseStoreOptions
	return s.db.ExecTx(ctx, &writeTx, func(dbTx BaseUniverseStore) error {
		groupKeyBytes := groupKey.SerializeCompressed()
		params := sqlc.UpsertSupplySyncerLogParams{
			GroupKey:               groupKeyBytes,
			MaxInsertedBlockHeight: sqlInt32(maxBlockHeight),
		}
		err := dbTx.UpsertSupplySyncerLog(ctx, params)
		if err != nil {
			return fmt.Errorf("failed to log remote insert: %w",
				err)
		}

		return nil
	})
}
