package tapdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/keychain"
)

// SupplyPreCommitStore is the tapdb-side gateway to the
// mint_supply_pre_commits table. It owns the supply-pre-commit
// reads that supplycommit's augmenter performs during seedling
// intake and the lookups that supplyverifier performs against
// the group-keyed delegation key. The write side is still
// performed by AssetMintingStore inside its binding transactions
// (so the row lands atomically with the batch's chain update);
// the augmenter constructs the payload and tapgarden plumbs it
// through.
type SupplyPreCommitStore struct {
	db BatchedPendingAssetStore
}

// NewSupplyPreCommitStore returns a new SupplyPreCommitStore
// backed by the same db handle as AssetMintingStore. Callers may
// instantiate multiple stores against the same handle without
// coordination; the underlying SQL queries are commutative on
// their own.
func NewSupplyPreCommitStore(
	db BatchedPendingAssetStore) *SupplyPreCommitStore {

	return &SupplyPreCommitStore{db: db}
}

// FetchDelegationKey fetches the delegation key (Taproot internal
// key of the pre-commitment output) for the given asset group
// public key. Returns None if no pre-commit row matches the
// group.
//
// NOTE: When multiple pre-commitment outputs share the same group
// key, the row with the lowest precommits.id is selected. The
// invariant that all outputs in a group share the same delegation
// key is enforced upstream during minting; the ordering guarantees
// a deterministic fallback if a legacy DB somehow violated it.
func (s *SupplyPreCommitStore) FetchDelegationKey(ctx context.Context,
	groupKey btcec.PublicKey) (fn.Option[keychain.KeyDescriptor], error) {

	var zero fn.Option[keychain.KeyDescriptor]
	groupKeyBytes := schnorr.SerializePubKey(&groupKey)

	var delegationKey fn.Option[keychain.KeyDescriptor]

	readOpts := NewAssetStoreReadTx()
	dbErr := s.db.ExecTx(ctx, &readOpts, func(q PendingAssetStore) error {
		fetchRow, err := q.FetchMintSupplyPreCommits(
			ctx, FetchMintPreCommitsParams{
				GroupKey: groupKeyBytes,
			},
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("unable to fetch mint anchor "+
				"uni commitment by group key: %w", err)
		}

		if len(fetchRow) == 0 {
			return nil
		}

		internalKey, err := parseInternalKey(fetchRow[0].InternalKey)
		if err != nil {
			return fmt.Errorf("error parsing pre-commitment "+
				"internal key: %w", err)
		}

		delegationKey = fn.Some(internalKey)
		return nil
	})
	if dbErr != nil {
		return zero, dbErr
	}

	return delegationKey, nil
}
