package tapdb

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
)

// InsertSignedCommitTx persists a signed commitment transaction for the
// active supply commitment transition in a transaction of its own.
// Production persists it inside the anchoring watcher's registration
// transaction through the state log; tests use this to move a transition
// to CommitBroadcastState directly.
func (s *SupplyCommitMachine) InsertSignedCommitTx(ctx context.Context,
	assetSpec asset.Specifier,
	commitDetails supplycommit.SupplyCommitTxn) error {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return ErrMissingGroupKey
	}
	groupKeyBytes := schnorr.SerializePubKey(groupKey)

	writeTx := WriteTxOption()
	return s.db.ExecTx(ctx, writeTx, func(db SupplyCommitStore) error {
		return insertSignedCommitTxBody(
			ctx, db, groupKeyBytes, commitDetails,
		)
	})
}
