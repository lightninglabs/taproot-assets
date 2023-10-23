package tapdb

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
)

const (
	// issuanceMultiverseNS is the namespace used for the multiverse
	// transfer proofs.
	issuanceMultiverseNS = "multiverse-issuance"

	// transferMultiverseNS is the namespace used for the multiverse
	// issuance proofs.
	transferMultiverseNS = "multiverse-transfer"
)

type (
	BaseUniverseRoot = sqlc.UniverseRootsRow
)

// BaseMultiverseStore is used to interact with a set of base universe
// roots, also known as a multiverse.
type BaseMultiverseStore interface {
	BaseUniverseStore

	UniverseRoots(ctx context.Context) ([]BaseUniverseRoot, error)
}

// BaseMultiverseOptions is the set of options for multiverse queries.
type BaseMultiverseOptions struct {
	readOnly bool
}

// ReadOnly returns true if the transaction is read-only.
func (b *BaseMultiverseOptions) ReadOnly() bool {
	return b.readOnly
}

// NewBaseMultiverseReadTx creates a new read-only transaction for the
// multiverse.
func NewBaseMultiverseReadTx() BaseMultiverseOptions {
	return BaseMultiverseOptions{
		readOnly: true,
	}
}

// BatchedMultiverse is a wrapper around the base multiverse that allows us to
// perform batch transactional database queries with all the relevant query
// interfaces.
type BatchedMultiverse interface {
	BaseMultiverseStore

	BatchedTx[BaseMultiverseStore]
}

// MultiverseStore implements the persistent storage for a multiverse.
//
// NOTE: This implements the universe.MultiverseArchive interface.
type MultiverseStore struct {
	db BatchedMultiverse

	// TODO(roasbeef): actually the start of multiverse?
	// * mapping: assetID -> baseUniverseRoot => outpoint || scriptKey => transfer
	// * drop base in front?
}

// NewMultiverseStore creates a new multiverse DB store handle.
func NewMultiverseStore(db BatchedMultiverse) *MultiverseStore {
	return &MultiverseStore{
		db: db,
	}
}

// namespaceForProof returns the multiverse namespace used for the given proof
// type.
func namespaceForProof(proofType universe.ProofType) (string, error) {
	switch proofType {
	case universe.ProofTypeIssuance:
		return issuanceMultiverseNS, nil

	case universe.ProofTypeTransfer:
		return transferMultiverseNS, nil

	default:
		return "", fmt.Errorf("unknown proof type: %v", int(proofType))
	}
}

// RootNode returns the root multiverse node for the given proof type.
func (b *MultiverseStore) RootNode(ctx context.Context,
	proofType universe.ProofType) (*universe.MultiverseRoot, error) {

	var rootNode *universe.MultiverseRoot

	multiverseNS, err := namespaceForProof(proofType)
	if err != nil {
		return nil, err
	}

	readTx := NewBaseUniverseReadTx()
	dbErr := b.db.ExecTx(ctx, &readTx, func(db BaseMultiverseStore) error {
		multiverseTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(db, multiverseNS),
		)

		multiverseRoot, err := multiverseTree.Root(ctx)
		if err != nil {
			return err
		}

		rootNode = &universe.MultiverseRoot{
			Node:      multiverseRoot,
			ProofType: proofType,
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return rootNode, nil
}

// RootNodes returns the complete set of known base universe root nodes for the
// set of base universes tracked in the multiverse.
func (b *MultiverseStore) RootNodes(ctx context.Context,
	withAmountsById bool) ([]universe.BaseRoot, error) {

	var (
		uniRoots []universe.BaseRoot
		readTx   = NewBaseMultiverseReadTx()
	)

	dbErr := b.db.ExecTx(ctx, &readTx, func(db BaseMultiverseStore) error {
		dbRoots, err := db.UniverseRoots(ctx)
		if err != nil {
			return err
		}

		for _, dbRoot := range dbRoots {
			var (
				id            universe.Identifier
				groupedAssets map[asset.ID]uint64
			)

			// Parse universe proof type and populate the universe
			// ID.
			id.ProofType, err = universe.ParseStrProofType(
				dbRoot.ProofType,
			)
			if err != nil {
				return err
			}

			if dbRoot.AssetID != nil {
				copy(id.AssetID[:], dbRoot.AssetID)
			}

			if dbRoot.GroupKey != nil {
				id.GroupKey, err = schnorr.ParsePubKey(
					dbRoot.GroupKey,
				)
				if err != nil {
					return err
				}
			}

			// We skip the grouped assets if that wasn't explicitly
			// requested by the user, saves us some calls for
			// grouped assets.
			if dbRoot.GroupKey != nil && withAmountsById {
				groupLeaves, err := db.QueryUniverseLeaves(
					ctx, UniverseLeafQuery{
						Namespace: id.String(),
					},
				)
				if err != nil {
					return err
				}

				groupedAssets = make(
					map[asset.ID]uint64, len(groupLeaves),
				)
				for _, leaf := range groupLeaves {
					var id asset.ID
					copy(id[:], leaf.AssetID)
					groupedAssets[id] = uint64(leaf.SumAmt)
				}
			} else if withAmountsById {
				// For non-grouped assets, there's exactly one
				// member, the asset itself.
				groupedAssets = map[asset.ID]uint64{
					id.AssetID: uint64(dbRoot.RootSum),
				}
			}

			var nodeHash mssmt.NodeHash
			copy(nodeHash[:], dbRoot.RootHash)
			uniRoot := universe.BaseRoot{
				ID: id,
				Node: mssmt.NewComputedBranch(
					nodeHash, uint64(dbRoot.RootSum),
				),
				AssetName:     dbRoot.AssetName,
				GroupedAssets: groupedAssets,
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

// FetchProofLeaf returns a proof leaf for the target key. If the key doesn't
// have a script key specified, then all the proof leafs for the minting
// outpoint will be returned. If neither are specified, then all inserted proof
// leafs will be returned.
func (b *MultiverseStore) FetchProofLeaf(ctx context.Context,
	id universe.Identifier,
	universeKey universe.LeafKey) ([]*universe.Proof, error) {

	var (
		readTx = NewBaseUniverseReadTx()
		proofs []*universe.Proof
	)

	multiverseNS, err := namespaceForProof(id.ProofType)
	if err != nil {
		return nil, err
	}

	dbErr := b.db.ExecTx(ctx, &readTx, func(dbTx BaseMultiverseStore) error {
		var err error
		proofs, err = universeFetchProofLeaf(
			ctx, id, universeKey, dbTx,
		)
		if err != nil {
			return err
		}

		// Populate multiverse specific fields of proofs.
		//
		// Retrieve a handle to the multiverse MS-SMT tree.
		multiverseTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(dbTx, multiverseNS),
		)

		multiverseRoot, err := multiverseTree.Root(ctx)
		if err != nil {
			return err
		}

		// Use asset ID (or asset group hash) as the upper tree leaf
		// node key. This is the same as the asset specific universe ID.
		leafNodeKey := id.Bytes()

		// Retrieve the multiverse inclusion proof for the asset
		// specific universe.
		multiverseInclusionProof, err := multiverseTree.MerkleProof(
			ctx, leafNodeKey,
		)
		if err != nil {
			return err
		}

		for i := range proofs {
			proofs[i].MultiverseRoot = multiverseRoot
			proofs[i].MultiverseInclusionProof = multiverseInclusionProof
		}

		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return proofs, nil
}

// UpsertProofLeaf upserts a proof leaf within the multiverse tree and the
// universe tree that corresponds to the given key.
func (b *MultiverseStore) UpsertProofLeaf(ctx context.Context,
	id universe.Identifier, key universe.LeafKey,
	leaf *universe.Leaf,
	metaReveal *proof.MetaReveal) (*universe.Proof, error) {

	var (
		writeTx       BaseMultiverseOptions
		issuanceProof *universe.Proof
	)

	multiverseNS, err := namespaceForProof(id.ProofType)
	if err != nil {
		return nil, err
	}

	execTxFunc := func(dbTx BaseMultiverseStore) error {
		// Register issuance in the asset (group) specific universe
		// tree.
		var (
			universeRoot mssmt.Node
			err          error
		)
		issuanceProof, universeRoot, err = universeUpsertProofLeaf(
			ctx, dbTx, id, key, leaf, metaReveal,
		)
		if err != nil {
			return err
		}

		// Retrieve a handle to the multiverse tree so that we can
		// update the tree by inserting a new issuance.
		multiverseTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(dbTx, multiverseNS),
		)

		// Construct a leaf node for insertion into the multiverse tree.
		// The leaf node includes a reference to the lower tree via the
		// lower tree root hash.
		universeRootHash := universeRoot.NodeHash()
		assetGroupSum := universeRoot.NodeSum()

		if id.ProofType == universe.ProofTypeIssuance {
			assetGroupSum = 1
		}

		leafNode := mssmt.NewLeafNode(
			universeRootHash[:], assetGroupSum,
		)

		// Use asset ID (or asset group hash) as the upper tree leaf
		// node key. This is the same as the asset specific universe ID.
		leafNodeKey := id.Bytes()

		_, err = multiverseTree.Insert(
			ctx, leafNodeKey, leafNode,
		)
		if err != nil {
			return err
		}

		// Retrieve the multiverse root and asset specific inclusion
		// proof for the leaf node.
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
	}
	dbErr := b.db.ExecTx(ctx, &writeTx, execTxFunc)

	if dbErr != nil {
		return nil, dbErr
	}

	return issuanceProof, nil
}

// UpsertProofLeafBatch upserts a proof leaf batch within the multiverse tree
// and the universe tree that corresponds to the given key(s).
func (b *MultiverseStore) UpsertProofLeafBatch(ctx context.Context,
	items []*universe.Item) error {

	insertProof := func(item *universe.Item,
		dbTx BaseMultiverseStore) error {

		// Upsert proof leaf into the asset (group) specific universe
		// tree.
		_, universeRoot, err := universeUpsertProofLeaf(
			ctx, dbTx, item.ID, item.Key, item.Leaf,
			item.MetaReveal,
		)
		if err != nil {
			return err
		}

		multiverseNS, err := namespaceForProof(item.ID.ProofType)
		if err != nil {
			return err
		}

		// Retrieve a handle to the multiverse tree so that we can
		// update the tree by inserting/updating a proof leaf.
		multiverseTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(dbTx, multiverseNS),
		)

		// Construct a leaf node for insertion into the multiverse tree.
		// The leaf node includes a reference to the lower tree via the
		// lower tree root hash.
		universeRootHash := universeRoot.NodeHash()
		assetGroupSum := universeRoot.NodeSum()

		if item.ID.ProofType == universe.ProofTypeIssuance {
			assetGroupSum = 1
		}

		leafNode := mssmt.NewLeafNode(
			universeRootHash[:], assetGroupSum,
		)

		// Use asset ID (or asset group hash) as the upper tree leaf
		// node key. This is the same as the asset specific universe ID.
		leafNodeKey := item.ID.Bytes()

		_, err = multiverseTree.Insert(ctx, leafNodeKey, leafNode)
		if err != nil {
			return err
		}

		return nil
	}

	var writeTx BaseMultiverseOptions
	dbErr := b.db.ExecTx(
		ctx, &writeTx, func(store BaseMultiverseStore) error {
			for idx := range items {
				item := items[idx]
				err := insertProof(item, store)
				if err != nil {
					return err
				}
			}

			return nil
		},
	)
	if dbErr != nil {
		return dbErr
	}

	return nil
}
