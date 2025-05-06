package tapdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"

	lfn "github.com/lightningnetwork/lnd/fn/v2"
)

// IgnoreUniverseTree is a structure that holds the DB for ignore operations.
type IgnoreUniverseTree struct {
	db BatchedUniverseTree
}

// NewIgnoreUniverseTree returns a new IgnoreUniverseTree with the target DB.
func NewIgnoreUniverseTree(db BatchedUniverseTree) *IgnoreUniverseTree {
	return &IgnoreUniverseTree{db: db}
}

// addTuplesInternal performs the insertion of ignore tuples within a database
// transaction. It also updates the main supply tree with the new ignore
// sub-tree root.
//
// NOTE: This function must be called within a database transaction.
func addTuplesInternal(ctx context.Context, db BaseUniverseStore,
	spec asset.Specifier, tuples ...*universe.SignedIgnoreTuple,
) ([]universe.AuthenticatedIgnoreTuple, error) {

	if len(tuples) == 0 {
		return nil, fmt.Errorf("no tuples provided")
	}

	groupKey := spec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return nil, ErrMissingGroupKey
	}

	// Derive identifier (and thereby the namespace) from the
	// asset.Specifier.
	namespace := subTreeNamespace(groupKey, supplycommit.IgnoreTreeType)

	groupKeyBytes := schnorr.SerializePubKey(groupKey)

	var finalResults []universe.AuthenticatedIgnoreTuple

	tree := mssmt.NewCompactedTree(
		newTreeStoreWrapperTx(db, namespace),
	)

	// First, insert all tuples into the ignore sub-tree SMT.
	for _, tup := range tuples {
		smtKey := tup.IgnoreTuple.Val.Hash()
		ignoreTup := tup.IgnoreTuple.Val

		leafNode, err := tup.UniverseLeafNode()
		if err != nil {
			return nil, fmt.Errorf("failed to create leaf "+
				"node: %w", err)
		}
		_, err = tree.Insert(ctx, smtKey, leafNode)
		if err != nil {
			return nil, fmt.Errorf("failed to insert into "+
				"ignore tree: %w", err)
		}

		// To insert the universe leaf below, we'll need both the db the
		// outpoint to be ignored. primary key for the asset genesis,
		// and also the raw bytes of
		assetGenID, err := db.FetchGenesisIDByAssetID(
			ctx, ignoreTup.ID[:],
		)

		// If the genesis ID doesn't exist, we can't insert the leaf.
		// This might happen if the asset wasn't properly registered
		// first.
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("genesis ID not found for "+
				"asset %v", ignoreTup.ID)
		}
		if err != nil {
			return nil, fmt.Errorf("error looking up genesis "+
				"ID for asset %v: %w", ignoreTup.ID, err)
		}
		ignorePointBytes, err := encodeOutpoint(
			tup.IgnoreTuple.Val.OutPoint,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to encode "+
				"ignore point: %w", err)
		}

		// With the leaf inserted into the tree, we'll now
		// create the universe leaf that references the SMT
		// leaf.
		universeRootID, err := db.UpsertUniverseRoot(
			ctx, NewUniverseRoot{
				NamespaceRoot: namespace,
				GroupKey:      groupKeyBytes,
				ProofType: sqlStr(
					supplycommit.IgnoreTreeType.String(),
				),
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to upsert ignore "+
				"universe root: %w", err)
		}

		scriptKey := ignoreTup.ScriptKey
		err = db.UpsertUniverseLeaf(ctx, UpsertUniverseLeaf{
			AssetGenesisID:    assetGenID,
			ScriptKeyBytes:    scriptKey.SchnorrSerialized(), //nolint:lll
			UniverseRootID:    universeRootID,
			LeafNodeKey:       smtKey[:],
			LeafNodeNamespace: namespace,
			MintingPoint:      ignorePointBytes,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to upsert ignore "+
				"universe leaf: %w", err)
		}
	}

	// Fetch the final ignore sub-tree root after all insertions.
	finalIgnoreRoot, err := tree.Root(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get ignore tree "+
			"root: %w", err)
	}

	// Next, for each inserted tuple, generate its inclusion proof from the
	// final tree and build its AuthenticatedIgnoreTuple.
	for _, tup := range tuples {
		smtKey := tup.IgnoreTuple.Val.Hash()
		proof, err := tree.MerkleProof(ctx, smtKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get ignore "+
				"proof: %w", err)
		}

		authTup := universe.AuthenticatedIgnoreTuple{
			SignedIgnoreTuple: *tup,
			InclusionProof:    proof,
			IgnoreTreeRoot:    finalIgnoreRoot,
		}

		finalResults = append(finalResults, authTup)
	}

	return finalResults, nil
}

// AddTuples adds a new ignore tuples to the ignore tree.
func (it *IgnoreUniverseTree) AddTuples(ctx context.Context,
	spec asset.Specifier, tuples ...*universe.SignedIgnoreTuple,
) lfn.Result[[]universe.AuthenticatedIgnoreTuple] {

	var (
		writeTx      BaseUniverseStoreOptions
		finalResults []universe.AuthenticatedIgnoreTuple
		err          error
	)
	txErr := it.db.ExecTx(ctx, &writeTx, func(db BaseUniverseStore) error {
		finalResults, err = addTuplesInternal(ctx, db, spec, tuples...)
		return err
	})
	if txErr != nil {
		return lfn.Err[universe.AuthIgnoreTuples](txErr)
	}

	// TODO(roasbeef): cache invalidation?

	return lfn.Ok(finalResults)
}

// Sum returns the sum of the ignore tuples for the given asset.
func (it *IgnoreUniverseTree) Sum(ctx context.Context,
	spec asset.Specifier) universe.SumQueryResp {

	// Derive identifier from the asset.Specifier.
	groupKey := spec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return lfn.Err[lfn.Option[uint64]](ErrMissingGroupKey)
	}

	namespace := subTreeNamespace(groupKey, supplycommit.IgnoreTreeType)

	// Use the generic helper to get the sum of the universe tree.
	return getUniverseTreeSum(ctx, it.db, namespace)
}

// decodeIgnoreTuple decodes the raw bytes into an IgnoreTuple.
func decodeIgnoreTuple(dbLeaf UniverseLeaf) (*universe.IgnoreTuple, error) {
	signedTuple, err := universe.DecodeSignedIgnoreTuple(
		dbLeaf.GenesisProof,
	)
	if err != nil {
		return nil, fmt.Errorf("error decoding signed ignore "+
			"tuple: %w", err)
	}

	return &signedTuple.IgnoreTuple.Val, nil
}

// ListTuples returns the list of ignore tuples for the given asset.
func (it *IgnoreUniverseTree) ListTuples(ctx context.Context,
	spec asset.Specifier) universe.ListTuplesResp {

	groupKey := spec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return lfn.Err[lfn.Option[universe.IgnoreTuples]](
			ErrMissingGroupKey,
		)
	}
	namespace := subTreeNamespace(groupKey, supplycommit.IgnoreTreeType)

	// Use the generic list helper to list the leaves from the universe
	// Tree. We pass in our custom decode function to handle the logic
	// specific to IgnoreTuples.
	return listUniverseLeaves(ctx, it.db, namespace, decodeIgnoreTuple)
}

// queryIgnoreLeaves retrieves UniverseLeaf records based on IgnoreTuple
// criteria.
func queryIgnoreLeaves(ctx context.Context, dbtx BaseUniverseStore,
	spec asset.Specifier,
	tuples ...universe.IgnoreTuple) ([]UniverseLeaf, error) {

	groupKey := spec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return nil, ErrMissingGroupKey
	}
	namespace := subTreeNamespace(groupKey, supplycommit.IgnoreTreeType)

	var allLeaves []UniverseLeaf
	for _, queryTuple := range tuples {
		// Create a leaf query for this specific key.
		//
		// TODO(roasbeef): need a more specific key here?
		//   * also add outpoint?
		scriptKey := queryTuple.ScriptKey
		leafQuery := UniverseLeafQuery{
			ScriptKeyBytes: scriptKey.SchnorrSerialized(),
			Namespace:      namespace,
		}

		leaves, err := dbtx.QueryUniverseLeaves(ctx, leafQuery)

		// We'll continue on to the next query if no leaves are found
		// for this query.
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("error querying leaf for tuple "+
				"(script_key=%x): %w", leafQuery.ScriptKeyBytes,
				err)
		}

		// Since the query is specific, we expect at most one leaf.
		if len(leaves) > 0 {
			allLeaves = append(allLeaves, leaves[0])
		}
	}

	// Return sql.ErrNoRows if no leaves were found across all tuples.
	if len(allLeaves) == 0 {
		return nil, sql.ErrNoRows
	}

	return allLeaves, nil
}

// parseDbSignedIgnoreTuple decodes the raw leaf, reconstructs the key, and
// builds the AuthenticatedIgnoreTuple.
func parseDbSignedIgnoreTuple(dbLeaf UniverseLeaf,
) (universe.SignedIgnoreTuple, uniKey, error) {

	signedTuple, err := universe.DecodeSignedIgnoreTuple(
		dbLeaf.GenesisProof,
	)
	if err != nil {
		return universe.SignedIgnoreTuple{}, uniKey{},
			fmt.Errorf("error decoding tuple: %w", err)
	}

	return signedTuple, signedTuple.UniverseKey(), nil
}

// QueryTuples returns the ignore tuples for the given asset.
func (it *IgnoreUniverseTree) QueryTuples(ctx context.Context,
	spec asset.Specifier,
	queryTuples ...universe.IgnoreTuple) universe.TupleQueryResp {

	if len(queryTuples) == 0 {
		return lfn.Ok(lfn.None[[]universe.AuthenticatedIgnoreTuple]())
	}

	groupKey := spec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return lfn.Err[lfn.Option[[]universe.AuthenticatedIgnoreTuple]](
			ErrMissingGroupKey,
		)
	}
	namespace := subTreeNamespace(groupKey, supplycommit.IgnoreTreeType)

	// Use the generic query helper, which will handle: doing the initial
	// query, decoding the ignore tuples, and finally building the merkle
	// proof for the tuples.
	return queryUniverseLeavesAndProofs(
		ctx, it.db, spec, namespace, queryIgnoreLeaves,
		parseDbSignedIgnoreTuple, universe.NewAuthIgnoreTuple,
		queryTuples...,
	)
}
