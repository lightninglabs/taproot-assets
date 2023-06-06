package tapdb

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
)

const mssmtNamespace = "multiverse"

type (
	BaseUniverseRoot = sqlc.UniverseRootsRow
)

// BaseUniverseForestStore is used to interact with a set of base universe
// roots, also known as a universe forest.
type BaseUniverseForestStore interface {
	BaseUniverseStore

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

// NewBaseUniverseForestReadTx creates a new read-only transaction for the
// universe forest.
func NewBaseUniverseForestReadTx() BaseUniverseForestOptions {
	return BaseUniverseForestOptions{
		readOnly: true,
	}
}

// BatchedUniverseForest is a wrapper around the base universe forest that
// allows us to perform batch transactional database queries with all the
// relevant query interfaces.
type BatchedUniverseForest interface {
	BaseUniverseForestStore

	BatchedTx[BaseUniverseForestStore]
}

// BaseUniverseForest implements the persistent storage for a universe forest.
//
// NOTE: This implements the universe.Multiverse interface.
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

// RootNodes returns the complete set of known base universe root nodes for the
// set of base universes tracked in the universe forest.
func (b *BaseUniverseForest) RootNodes(
	ctx context.Context) ([]universe.BaseRoot, error) {

	var (
		uniRoots []universe.BaseRoot
		readTx   = NewBaseUniverseForestReadTx()
	)

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

// RegisterIssuance inserts a new minting leaf within the multiverse tree and
// the universe tree that corresponds to the given base key.
func (b *BaseUniverseForest) RegisterIssuance(ctx context.Context,
	id universe.Identifier, key universe.BaseKey,
	leaf *universe.MintingLeaf,
	metaReveal *proof.MetaReveal) (*universe.IssuanceProof, error) {

	var (
		writeTx       BaseUniverseForestOptions
		issuanceProof *universe.IssuanceProof
	)

	dbErr := b.db.ExecTx(
		ctx, &writeTx, func(dbTx BaseUniverseForestStore) error {
			// Register issuance in the asset (group) specific
			// universe tree.
			var (
				universeRoot mssmt.Node
				err          error
			)
			issuanceProof, universeRoot, err = universeRegisterIssuance(
				ctx, dbTx, id, key, leaf, metaReveal,
			)
			if err != nil {
				return err
			}

			// Retrieve a handle to the multiverse tree so that we
			// can update the tree by inserting a new issuance.
			multiverseTree := mssmt.NewCompactedTree(
				newTreeStoreWrapperTx(dbTx, mssmtNamespace),
			)

			// Construct a leaf node for insertion into the
			// multiverse tree. The leaf node includes a reference
			// to the lower tree via the lower tree root hash.
			universeRootHash := universeRoot.NodeHash()
			assetGroupSum := universeRoot.NodeSum()

			leafNode := mssmt.NewLeafNode(
				universeRootHash[:], assetGroupSum,
			)

			// Use asset ID (or asset group hash) as the upper tree
			// leaf node key. This is the same as the asset specific
			// universe ID.
			leafNodeKey := id.Bytes()

			_, err = multiverseTree.Insert(
				ctx, leafNodeKey, leafNode,
			)
			if err != nil {
				return err
			}

			// Retrieve the multiverse root and asset specific
			// inclusion proof for the leaf node.
			multiverseRoot, err := multiverseTree.Root(ctx)
			if err != nil {
				return err
			}

			multiverseInclusionProof, err := multiverseTree.MerkleProof(
				ctx, leafNodeKey,
			)
			if err != nil {
				return err
			}

			// Add multiverse specific fields to the issuance proof.
			issuanceProof.MultiverseRoot = multiverseRoot
			issuanceProof.MultiverseInclusionProof = multiverseInclusionProof

			return err
		},
	)

	if dbErr != nil {
		return nil, dbErr
	}

	return issuanceProof, nil
}
