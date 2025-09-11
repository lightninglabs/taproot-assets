package tapdb

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
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

// LogSupplyCommitPush logs that a supply commitment and its leaves
// have been successfully pushed to a remote universe server.
func (s *SupplySyncerStore) LogSupplyCommitPush(ctx context.Context,
	serverAddr universe.ServerAddr, assetSpec asset.Specifier,
	commitment supplycommit.RootCommitment,
	leaves supplycommit.SupplyLeaves) error {

	// Calculate the total number of leaves in this push.
	numLeaves := int32(len(leaves.IssuanceLeafEntries) +
		len(leaves.BurnLeafEntries) +
		len(leaves.IgnoreLeafEntries))

	// If no leaves were provided, return early without error.
	if numLeaves == 0 {
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
	groupKey, err := assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return fmt.Errorf("group key must be specified for supply "+
			"syncer log: %w", err)
	}

	groupKeyBytes := schnorr.SerializePubKey(groupKey)

	// Extract the outpoint (transaction ID and output index) from the
	// commitment.
	commitTxid := commitment.Txn.TxHash()
	outputIndex := commitment.TxOutIdx

	var writeTx BaseUniverseStoreOptions
	return s.db.ExecTx(ctx, &writeTx, func(dbTx BaseUniverseStore) error {
		// Insert the push log entry. The SQL query will find the
		// chain_txn_id by looking up the supply commitment using the
		// commitment transaction hash and output index (outpoint).
		params := sqlc.InsertSupplySyncerPushLogParams{
			GroupKey:             groupKeyBytes,
			MaxPushedBlockHeight: int32(maxBlockHeight),
			ServerAddress:        serverAddr.HostStr(),
			CommitTxid:           commitTxid[:],
			OutputIndex:          int32(outputIndex),
			NumLeavesPushed:      numLeaves,
			CreatedAt:            time.Now().Unix(),
		}
		err := dbTx.InsertSupplySyncerPushLog(ctx, params)
		if err != nil {
			return fmt.Errorf("failed to log supply commit push: "+
				"%w", err)
		}

		return nil
	})
}
