package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"

	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnutils"
)

const (
	// supplyRootNS is the prefix for the root supply tree namespace.
	supplyRootNS = "supply-root"

	// supplySubTreeNS is the prefix for supply sub-tree namespaces.
	supplySubTreeNS = "supply-sub"
)

// allSupplyTreeTypes contains all supply sub-tree types that are commonly
// iterated over.
var allSupplyTreeTypes = []supplycommit.SupplySubTree{
	supplycommit.MintTreeType,
	supplycommit.BurnTreeType,
	supplycommit.IgnoreTreeType,
}

// SupplyTreeStore implements the persistent storage for supply trees. It
// manages a root supply tree per asset group, where each leaf in the root tree
// corresponds to the root of a sub-tree (mint, burn, ignore).
type SupplyTreeStore struct {
	db BatchedUniverseTree
}

// NewSupplyTreeStore creates a new supply tree DB store handle.
func NewSupplyTreeStore(db BatchedUniverseTree) *SupplyTreeStore {
	return &SupplyTreeStore{
		db: db,
	}
}

// rootSupplyNamespace generates the SMT namespace for the root supply tree
// associated with a given group key.
func rootSupplyNamespace(groupKey *btcec.PublicKey) string {
	keyHex := hex.EncodeToString(groupKey.SerializeCompressed())
	return fmt.Sprintf("%s-%s", supplyRootNS, keyHex)
}

// subTreeNamespace generates the SMT namespace for a specific supply sub-tree
// (mint, burn, ignore) associated with a given group key.
func subTreeNamespace(groupKey *btcec.PublicKey,
	treeType supplycommit.SupplySubTree) string {

	keyHex := hex.EncodeToString(groupKey.SerializeCompressed())
	return fmt.Sprintf("%s-%s-%s", supplySubTreeNS,
		treeType.String(), keyHex)
}

// upsertSupplyTreeLeaf inserts or updates a leaf in the root supply tree.
// The leaf represents the root of a specific sub-tree (mint, burn, or ignore).
// It returns the new root of the main supply tree.
//
// NOTE: This function must be called within a database transaction.
func upsertSupplyTreeLeaf(ctx context.Context, dbTx BaseUniverseStore,
	groupKey *btcec.PublicKey, subTreeType supplycommit.SupplySubTree,
	subTreeRootNode mssmt.Node) (mssmt.Node, error) {

	rootNs := rootSupplyNamespace(groupKey)
	subNs := subTreeNamespace(groupKey, subTreeType)

	// Ensure the root supply tree entry exists in universe_supply_roots.
	rootID, err := dbTx.UpsertUniverseSupplyRoot(ctx,
		UpsertUniverseSupplyRoot{
			NamespaceRoot: rootNs,
			GroupKey:      groupKey.SerializeCompressed(),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("unable to upsert supply root: %w", err)
	}

	// Map the internal enum to the DB string representation for the proof
	// type.
	subTreeTypeStr := subTreeType.String()

	nodeSum := subTreeRootNode.NodeSum()

	// Create the SMT leaf node for the root supply tree. The value is the
	// hash of the sub-tree root, and the sum is the sum of the sub-tree.
	leafNode := mssmt.NewLeafNode(
		lnutils.ByteSlice(subTreeRootNode.NodeHash()), nodeSum,
	)

	// The key for this leaf in the root supply tree is derived from the
	// sub-tree type.
	leafKey := subTreeType.UniverseKey()

	// Instantiate the root supply SMT tree.
	rootTree := mssmt.NewCompactedTree(
		newTreeStoreWrapperTx(dbTx, rootNs),
	)

	// Insert the leaf node representing the sub-tree root.
	_, err = rootTree.Insert(ctx, leafKey, leafNode)
	if err != nil {
		return nil, fmt.Errorf("unable to insert leaf into root "+
			"supply tree: %w", err)
	}

	// Upsert the universe_supply_leaves entry to link the root tree,
	// sub-tree type, and the sub-tree's namespace.
	_, err = dbTx.UpsertUniverseSupplyLeaf(ctx, UpsertUniverseSupplyLeaf{
		SupplyRootID:      rootID,
		SubTreeType:       subTreeTypeStr,
		LeafNodeKey:       leafKey[:],
		LeafNodeNamespace: subNs,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to upsert supply leaf "+
			"entry: %w", err)
	}

	// Return the new root of the root supply tree.
	newRootSupplyRoot, err := rootTree.Root(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch new root supply "+
			"tree root: %w", err)
	}

	return newRootSupplyRoot, nil
}

// FetchSubTree returns a copy of the sub-tree for the given asset spec and
// sub-tree type.
func (s *SupplyTreeStore) FetchSubTree(ctx context.Context,
	spec asset.Specifier,
	treeType supplycommit.SupplySubTree) lfn.Result[mssmt.Tree] {

	groupKey, err := spec.UnwrapGroupKeyOrErr()
	if err != nil {
		return lfn.Errf[mssmt.Tree]("group key must be "+
			"specified for supply tree: %w", err)
	}

	var treeCopy mssmt.Tree
	readTx := NewBaseUniverseReadTx()
	dbErr := s.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		var internalErr error
		treeCopy, internalErr = fetchSubTreeInternal(
			ctx, db, groupKey, treeType,
		)
		if internalErr != nil {
			return internalErr
		}
		return nil
	})
	if dbErr != nil {
		return lfn.Err[mssmt.Tree](dbErr)
	}

	return lfn.Ok(treeCopy)
}

// fetchSubTreeInternal fetches and copies a specific sub-tree within an
// existing database transaction.
func fetchSubTreeInternal(ctx context.Context, db BaseUniverseStore,
	groupKey *btcec.PublicKey,
	treeType supplycommit.SupplySubTree) (mssmt.Tree, error) {

	subNs := subTreeNamespace(groupKey, treeType)

	// Create a wrapper for the persistent tree store using the provided tx.
	persistentStore := newTreeStoreWrapperTx(db, subNs)
	persistentTree := mssmt.NewCompactedTree(persistentStore)

	// Create a new in-memory tree to copy into.
	memTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())

	// Copy the persistent tree to the in-memory tree.
	err := persistentTree.Copy(ctx, memTree)
	if err != nil {
		return nil, fmt.Errorf("unable to copy sub-tree %s: %w",
			subNs, err)
	}

	return memTree, nil
}

// FetchSubTrees returns copies of all sub-trees (mint, burn, ignore) for the
// given asset spec.
func (s *SupplyTreeStore) FetchSubTrees(ctx context.Context,
	spec asset.Specifier) lfn.Result[supplycommit.SupplyTrees] {

	groupKey, err := spec.UnwrapGroupKeyOrErr()
	if err != nil {
		return lfn.Errf[supplycommit.SupplyTrees](
			"group key must be specified for supply tree: %w", err,
		)
	}

	trees := make(supplycommit.SupplyTrees)
	readTx := NewBaseUniverseReadTx()
	dbErr := s.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		// For each supply tree type, we'll fetch the corresponding
		// sub-tree within this single transaction.
		for _, treeType := range allSupplyTreeTypes {
			subTree, fetchErr := fetchSubTreeInternal(
				ctx, db, groupKey, treeType,
			)
			if fetchErr != nil {
				return fmt.Errorf("failed to fetch "+
					"sub-tree %v: %w", treeType, fetchErr)
			}

			trees[treeType] = subTree
		}
		return nil
	})
	if dbErr != nil {
		return lfn.Err[supplycommit.SupplyTrees](dbErr)
	}

	return lfn.Ok(trees)
}

// FetchRootSupplyTree returns a copy of the root supply tree for the given
// asset spec.
func (s *SupplyTreeStore) FetchRootSupplyTree(ctx context.Context,
	spec asset.Specifier) lfn.Result[mssmt.Tree] {

	groupKey, err := spec.UnwrapGroupKeyOrErr()
	if err != nil {
		return lfn.Errf[mssmt.Tree](
			"group key must be specified for supply tree: %w", err,
		)
	}

	rootNs := rootSupplyNamespace(groupKey)

	var treeCopy mssmt.Tree

	readTx := NewBaseUniverseReadTx()
	err = s.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		// Create a wrapper for the persistent tree store.
		persistentStore := newTreeStoreWrapperTx(db, rootNs)
		persistentTree := mssmt.NewCompactedTree(persistentStore)

		// Create a new in-memory tree to copy into.
		memTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())

		// Copy the persistent tree to the in-memory tree.
		err := persistentTree.Copy(ctx, memTree)
		if err != nil {
			return fmt.Errorf("unable to copy root supply "+
				"tree %s: %w", rootNs, err)
		}

		treeCopy = memTree
		return nil
	})
	if err != nil {
		return lfn.Err[mssmt.Tree](err)
	}

	return lfn.Ok(treeCopy)
}

// registerMintSupplyInternal inserts a new minting leaf into the mint supply
// sub-tree within an existing database transaction. It returns the universe
// proof containing the new sub-tree root.
//
// NOTE: This function must be called within a database transaction.
func registerMintSupplyInternal(ctx context.Context, dbTx BaseUniverseStore,
	assetSpec asset.Specifier, key universe.LeafKey,
	leaf *universe.AssetLeaf, metaReveal *proof.MetaReveal,
	blockHeight lfn.Option[uint32]) (*universe.Proof, error) {

	groupKey, err := assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return nil, fmt.Errorf("group key must be "+
			"specified for mint supply: %w", err)
	}
	subNs := subTreeNamespace(groupKey, supplycommit.MintTreeType)

	// Upsert the leaf into the mint supply sub-tree SMT and DB.
	mintSupplyProof, err := universeUpsertProofLeaf(
		ctx, dbTx, subNs, supplycommit.MintTreeType.String(), groupKey,
		key, leaf, metaReveal, blockHeight,
	)
	if err != nil {
		return nil, fmt.Errorf("failed mint supply universe "+
			"upsert: %w", err)
	}

	return mintSupplyProof, nil
}

// RegisterMintSupply inserts a new minting leaf into the mint supply sub-tree
// and updates the root supply tree.
//
// TODO(roasbeef): don't actually need? public version
func (s *SupplyTreeStore) RegisterMintSupply(ctx context.Context,
	spec asset.Specifier, key universe.LeafKey,
	leaf *universe.AssetLeaf) (*universe.Proof, mssmt.Node, error) {

	groupKey := leaf.GroupKey
	if groupKey == nil {
		return nil, nil, fmt.Errorf("group key must be specified " +
			"for mint supply")
	}

	var (
		writeTx           BaseUniverseStoreOptions
		mintSupplyProof   *universe.Proof
		newRootSupplyRoot mssmt.Node
	)
	dbErr := s.db.ExecTx(ctx, &writeTx, func(dbTx BaseUniverseStore) error {
		// We don't need to decode the whole proof, we just need the
		// block height.
		blockHeight, err := SparseDecodeBlockHeight(leaf.RawProof)
		if err != nil {
			return err
		}

		// Upsert the leaf into the mint supply sub-tree SMT and DB
		// first.
		mintSupplyProof, err = registerMintSupplyInternal(
			ctx, dbTx, spec, key, leaf, nil, blockHeight,
		)
		if err != nil {
			return fmt.Errorf("failed mint supply universe "+
				"upsert: %w", err)
		}

		// Now, upsert the root of the mint supply sub-tree into the
		// main root supply tree.
		//
		// TODO(roasbeef): or other method will always be used?
		newRootSupplyRoot, err = upsertSupplyTreeLeaf(
			ctx, dbTx, &groupKey.GroupPubKey,
			supplycommit.MintTreeType, mintSupplyProof.UniverseRoot,
		)
		if err != nil {
			return fmt.Errorf("failed to upsert mint supply leaf "+
				"into root supply tree: %w", err)
		}

		return nil
	})
	if dbErr != nil {
		return nil, nil, dbErr
	}

	// TODO(roasbeef): cache invalidation?

	return mintSupplyProof, newRootSupplyRoot, nil
}

// applySupplyUpdatesInternal applies a list of supply updates within an
// existing database transaction. It updates the relevant sub-trees and the main
// root supply tree. It returns the final root of the main supply tree.
//
// NOTE: This function must be called within a database transaction.
func applySupplyUpdatesInternal(ctx context.Context, dbTx BaseUniverseStore,
	spec asset.Specifier,
	updates []supplycommit.SupplyUpdateEvent) (mssmt.Node, error) {

	groupKey, err := spec.UnwrapGroupKeyOrErr()
	if err != nil {
		return nil, fmt.Errorf(
			"group key must be specified for supply "+
				"updates: %w", err,
		)
	}

	// Group updates by their sub-tree type, this'll simplify the logic
	// below, as we can update one sub-tree at a time.
	groupedUpdates := make(
		map[supplycommit.SupplySubTree][]supplycommit.SupplyUpdateEvent,
	)
	for _, update := range updates {
		treeType := update.SupplySubTreeType()
		groupedUpdates[treeType] = append(
			groupedUpdates[treeType], update,
		)
	}

	// We'll keep track of the final sub-tree roots after each insertion
	// phase. We'll use this to update the leaves of the root supply tree at
	// the end.
	finalSubTreeRoots := make(map[supplycommit.SupplySubTree]mssmt.Node)

	// Process Mint updates.
	if mintUpdates, ok := groupedUpdates[supplycommit.MintTreeType]; ok {
		var lastMintProof *universe.Proof
		for _, update := range mintUpdates {
			mintEvent, ok := update.(*supplycommit.NewMintEvent)
			if !ok {
				return nil, fmt.Errorf("invalid mint event "+
					"type: %T", update)
			}

			var blockHeight lfn.Option[uint32]
			height := mintEvent.BlockHeight()
			if height > 0 {
				blockHeight = lfn.Some(height)
			}

			mintProof, err := registerMintSupplyInternal(
				ctx, dbTx, spec, mintEvent.LeafKey,
				&mintEvent.IssuanceProof, nil, blockHeight,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to register "+
					"mint supply: %w", err)
			}

			lastMintProof = mintProof
		}
		if lastMintProof != nil {
			finalSubTreeRoots[supplycommit.MintTreeType] = lastMintProof.UniverseRoot //nolint:lll
		}
	}

	// Process Burn updates.
	if burnUpdates, ok := groupedUpdates[supplycommit.BurnTreeType]; ok {
		// First, we'll extract the inner type, shedding the outer
		// interface.
		burnLeaves := make([]*universe.BurnLeaf, 0, len(burnUpdates))
		for _, update := range burnUpdates {
			burnEvent, ok := update.(*supplycommit.NewBurnEvent)
			if !ok {
				return nil, fmt.Errorf("invalid burn event "+
					"type: %T", update)
			}

			burnLeaves = append(burnLeaves, &burnEvent.BurnLeaf)
		}

		authLeaves, err := insertBurnsInternal(
			ctx, dbTx, spec, burnLeaves...,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to insert burns: %w",
				err)
		}

		// All leaves in the batch will have the same final root. We'll
		// collect this as we'll want to update the sub-tree root below.
		if len(authLeaves) > 0 {
			finalSubTreeRoots[supplycommit.BurnTreeType] = authLeaves[0].BurnTreeRoot //nolint:lll
		}
	}

	// Finally, we'll process any ignore updates. These are a bit different
	// as a state transition proof isn't stored as the value.
	//
	//nolint:lll
	if ignoreUpdates, ok := groupedUpdates[supplycommit.IgnoreTreeType]; ok {
		ignoreTuples := make(
			[]*universe.SignedIgnoreTuple, 0, len(ignoreUpdates),
		)
		for _, update := range ignoreUpdates {
			ignoreEvent, ok := update.(*supplycommit.NewIgnoreEvent)
			if !ok {
				return nil, fmt.Errorf("invalid ignore event "+
					"type: %T", update)
			}
			ignoreTuples = append(
				ignoreTuples, &ignoreEvent.SignedIgnoreTuple,
			)
		}

		// addTuplesInternal already handles batching.
		authTuples, err := addTuplesInternal(
			ctx, dbTx, spec, ignoreTuples...,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to add ignore "+
				"tuples: %w", err)
		}

		// All tuples in the batch will have the same final root.
		if len(authTuples) > 0 {
			finalSubTreeRoots[supplycommit.IgnoreTreeType] = authTuples[0].IgnoreTreeRoot //nolint:lll
		}
	}

	// Update the main root supply tree with the final roots of modified
	// sub-trees.
	var finalRootSupplyRoot mssmt.Node
	for treeType, subTreeRoot := range finalSubTreeRoots {
		finalRootSupplyRoot, err = upsertSupplyTreeLeaf(
			ctx, dbTx, groupKey, treeType, subTreeRoot,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to update root supply "+
				"tree for %v: %w", treeType, err)
		}
	}

	// If no sub-trees were modified, fetch the current root supply root.
	if finalRootSupplyRoot == nil {
		rootNs := rootSupplyNamespace(groupKey)
		rootTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(dbTx, rootNs),
		)

		finalRootSupplyRoot, err = rootTree.Root(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch existing root "+
				"supply root: %w", err)
		}
	}

	return finalRootSupplyRoot, nil
}

// initEmptySupplyTrees creates the initial database entries for a new supply
// tree and its sub-trees, all initialized to the canonical empty SMT state. It
// inserts the necessary root and leaf entries into the universe_supply_* tables
// and ensures the corresponding empty SMT roots exist in mssmt_roots. It MUST
// be called within a database transaction.
//
//nolint:unused
func initEmptySupplyTrees(ctx context.Context, dbTx BaseUniverseStore,
	groupKey *btcec.PublicKey) (mssmt.Node, error) {

	// Initialize a map holding the empty root node for each sub-tree type.
	emptyRootNode := mssmt.NewComputedNode(mssmt.EmptyTreeRootHash, 0)
	emptySubTreeRoots := map[supplycommit.SupplySubTree]mssmt.Node{
		supplycommit.MintTreeType:   emptyRootNode,
		supplycommit.BurnTreeType:   emptyRootNode,
		supplycommit.IgnoreTreeType: emptyRootNode,
	}

	// Iterate through the empty roots and insert them as leaves into the
	// main root supply tree. The upsertSupplyTreeLeaf function handles
	// creating the necessary DB entries (universe_supply_roots,
	// universe_supply_leaves, and implicitly mssmt_roots via the store
	// wrapper).
	var (
		finalRootSupplyRoot mssmt.Node
		err                 error
	)
	for treeType, subTreeRoot := range emptySubTreeRoots {
		finalRootSupplyRoot, err = upsertSupplyTreeLeaf(
			ctx, dbTx, groupKey, treeType, subTreeRoot,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to upsert empty leaf "+
				"for %v: %w", treeType, err)
		}
	}

	// If the loop didn't run (which shouldn't happen), fetch the root.
	// Otherwise, the last call to upsertSupplyTreeLeaf returned the final
	// root.
	if finalRootSupplyRoot == nil {
		rootNs := rootSupplyNamespace(groupKey)
		rootTree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(dbTx, rootNs),
		)
		finalRootSupplyRoot, err = rootTree.Root(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch initial root "+
				"supply root: %w", err)
		}
	}

	return finalRootSupplyRoot, nil
}

// ApplySupplyUpdates atomically applies a list of supply updates. It updates
// the relevant sub-trees and the main root supply tree within a single database
// transaction. It returns the final root of the main supply tree.
func (s *SupplyTreeStore) ApplySupplyUpdates(ctx context.Context,
	spec asset.Specifier,
	updates []supplycommit.SupplyUpdateEvent) (mssmt.Node, error) {

	var (
		writeTx   BaseUniverseStoreOptions
		finalRoot mssmt.Node
		err       error
	)
	dbErr := s.db.ExecTx(ctx, &writeTx, func(dbTx BaseUniverseStore) error {
		finalRoot, err = applySupplyUpdatesInternal(
			ctx, dbTx, spec, updates,
		)
		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	// TODO(roasbeef): cache invalidation?

	return finalRoot, nil
}

// SupplyUpdate is a struct that holds a supply update event.
type SupplyUpdate struct {
	supplycommit.SupplyUpdateEvent
}

// FetchSupplyLeavesByHeight fetches all supply leaves for a given asset
// specifier within a given block height range.
func (s *SupplyTreeStore) FetchSupplyLeavesByHeight(ctx context.Context,
	spec asset.Specifier, startHeight,
	endHeight uint32) ([]SupplyUpdate, error) {

	groupKey, err := spec.UnwrapGroupKeyOrErr()
	if err != nil {
		return nil, fmt.Errorf("group key must be "+
			"specified for supply tree: %w", err)
	}

	var updates []SupplyUpdate

	readTx := NewBaseUniverseReadTx()
	dbErr := s.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		for _, treeType := range allSupplyTreeTypes {
			namespace := subTreeNamespace(groupKey, treeType)

			leaves, err := db.QuerySupplyLeavesByHeight(
				ctx, sqlc.QuerySupplyLeavesByHeightParams{
					Namespace:   namespace,
					StartHeight: sqlInt32(startHeight),
					EndHeight:   sqlInt32(endHeight),
				},
			)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					continue
				}

				return fmt.Errorf("failed to query "+
					"supply leaves: %w", err)
			}

			for _, leaf := range leaves {
				var event supplycommit.SupplyUpdateEvent
				switch treeType {
				case supplycommit.MintTreeType:
					var mintEvent supplycommit.NewMintEvent
					err = mintEvent.Decode(
						bytes.NewReader(
							leaf.SupplyLeafBytes,
						),
					)
					if err != nil {
						return fmt.Errorf("failed "+
							"to decode mint "+
							"event: %w", err)
					}

					event = &mintEvent

				case supplycommit.BurnTreeType:
					var burnEvent supplycommit.NewBurnEvent
					err = burnEvent.Decode(
						bytes.NewReader(
							leaf.SupplyLeafBytes,
						),
					)
					if err != nil {
						return fmt.Errorf("failed "+
							"to decode burn "+
							"event: %w", err)
					}

					event = &burnEvent

				case supplycommit.IgnoreTreeType:
					//nolint:lll
					var ignoreEvent supplycommit.NewIgnoreEvent
					err = ignoreEvent.Decode(
						bytes.NewReader(
							leaf.SupplyLeafBytes,
						),
					)
					if err != nil {
						return fmt.Errorf("failed "+
							"to decode ignore "+
							"event: %w", err)
					}
					event = &ignoreEvent
				}

				updates = append(updates, SupplyUpdate{
					SupplyUpdateEvent: event,
				})
			}
		}
		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return updates, nil
}
