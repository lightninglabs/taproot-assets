package tarodb

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/tarodb/sqlc"
	"github.com/lightninglabs/taro/universe"
)

type (
	BaseUniverseRoot = sqlc.UniverseRootsRow
)

// BaseUniverseForestStore is used to interact with a set of base universe
// roots, also known as a universe forest.
type BaseUniverseForestStore interface {
	UniverseRoots(ctx context.Context) ([]BaseUniverseRoot, error)
}

// BaseUniverseForestOptions is the set of options for universe grove queries.
type BaseUniverseForestOptions struct {
	readOnly bool
}

// ReadOnly returns true if the transaction is read-only.
func (b *BaseUniverseForestOptions) ReadOnly() bool {
	return b.readOnly
}

// NewBaseUniverseForestReadTx creates a new read-only transaction for the base
// universe.
func NewBaseUniverseForestReadTx() BaseUniverseForestOptions {
	return BaseUniverseForestOptions{
		readOnly: true,
	}
}

// BasedUniverseForest is a wrapper around the base universe forest that allows
// us perform batch queries with all the relevant query interfaces.
type BatchedUniverseForest interface {
	BaseUniverseForestStore

	BatchedTx[BaseUniverseForestStore]
}

// BaseUniverseForest implements the persistent storage for the Base universe
// for a given asset. The minting outpoints stored of the asset are used to key
// into the universe tree.
//
// NOTE: This implements the universe.BaseForest interface.
type BaseUniverseForest struct {
	db BatchedUniverseForest

	// TODO(roasbeef): actually the start of multiverse?
	// * mapping: assetID -> baseUniverseRoot => outpoint || scriptKey => transfer
	// * drop base in front?
}

// NewBaseUniverseForest creates a new base universe forest.
func NewBaseUniverseForest(db BatchedUniverseForest) *BaseUniverseForest {
	return &BaseUniverseForest{
		db: db,
	}
}

// RootNodes returns the complete set of known root nodes for the set of assets
// tracked in the base Universe.
func (b *BaseUniverseForest) RootNodes(ctx context.Context) ([]universe.BaseRoot, error) {
	var uniRoots []universe.BaseRoot

	readTx := NewBaseUniverseForestReadTx()

	dbErr := b.db.ExecTx(ctx, &readTx, func(db BaseUniverseForestStore) error {
		dbRoots, err := db.UniverseRoots(ctx)
		if err != nil {
			return err
		}

		for _, dbRoot := range dbRoots {
			var (
				assetID  asset.ID
				groupKey *btcec.PublicKey
			)

			if dbRoot.AssetID != nil {
				copy(assetID[:], dbRoot.AssetID)
			}

			if dbRoot.GroupKey != nil {
				groupKey, err = schnorr.ParsePubKey(
					dbRoot.GroupKey,
				)
				if err != nil {
					return err
				}
			}

			var nodeHash mssmt.NodeHash
			copy(nodeHash[:], dbRoot.RootHash)
			uniRoot := universe.BaseRoot{
				ID: universe.Identifier{
					AssetID:  assetID,
					GroupKey: groupKey,
				},
				Node: mssmt.NewComputedBranch(
					nodeHash, uint64(dbRoot.RootSum),
				),
				AssetName: dbRoot.AssetName,
			}

			uniRoots = append(uniRoots, uniRoot)
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return uniRoots, nil
}
