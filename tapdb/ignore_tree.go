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

// AddTuple adds a new ignore tuples to the ignore tree.
func (it *IgnoreUniverseTree) AddTuples(ctx context.Context,
	spec asset.Specifier, tuples ...universe.SignedIgnoreTuple,
) lfn.Result[universe.AuthIgnoreTuples] {

	if len(tuples) == 0 {
		return lfn.Err[[]universe.AuthenticatedIgnoreTuple](
			fmt.Errorf("no tuples provided"),
		)
	}

	// Derive identifier (and thereby the namespace) from the
	// asset.Specifier.
	id, err := specifierToIdentifier(spec, universe.ProofTypeIgnore)
	if err != nil {
		return lfn.Err[universe.AuthIgnoreTuples](err)
	}

	namespace := id.String()

	groupKeyBytes := schnorr.SerializePubKey(id.GroupKey)

	var finalResults []universe.AuthenticatedIgnoreTuple

	var writeTx BaseUniverseStoreOptions
	txErr := it.db.ExecTx(ctx, &writeTx, func(db BaseUniverseStore) error {
		tree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(db, namespace),
		)

		// First, insert all tuples into the tree. This'll create a new
		// insert universe leaves to reference the SMT leafs. set of
		// normal SMT leafs. Once inserted, we'll then also obtain
		// inclusion proofs for each.
		for _, tup := range tuples {
			smtKey := tup.IgnoreTuple.Val.Hash()

			ignoreTup := tup.IgnoreTuple.Val

			leafNode, err := tup.UniverseLeafNode()
			if err != nil {
				return err
			}
			_, err = tree.Insert(ctx, smtKey, leafNode)
			if err != nil {
				return err
			}

			// To insert the universe leaf below, we'll need both
			// the db primary key for the asset genesis, and also
			// the raw bytes of the outpoint to be ignored.
			assetGenID, err := db.FetchGenesisIDByAssetID(
				ctx, ignoreTup.ID[:],
			)
			if err != nil {
				return fmt.Errorf("error looking up genesis "+
					"ID for asset %v: %w", ignoreTup.ID,
					err)
			}
			ignorePointBytes, err := encodeOutpoint(
				tup.IgnoreTuple.Val.OutPoint,
			)
			if err != nil {
				return err
			}

			// With the leaf inserted into the tree, we'll now
			// create the universe leaf that references the SMT
			// leaf.
			universeRootID, err := db.UpsertUniverseRoot(
				ctx, NewUniverseRoot{
					NamespaceRoot: namespace,
					GroupKey:      groupKeyBytes,
					ProofType: sqlStr(
						id.ProofType.String(),
					),
				},
			)
			if err != nil {
				return err
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
				return err
			}
		}

		// Fetch the final tree root after all insertions.
		finalRoot, err := tree.Root(ctx)
		if err != nil {
			return err
		}

		// Next, for each inserted tuple, generate its inclusion proof
		// from the final tree and build its AuthenticatedIgnoreTuple.
		for _, tup := range tuples {
			smtKey := tup.IgnoreTuple.Val.Hash()
			proof, err := tree.MerkleProof(ctx, smtKey)
			if err != nil {
				return err
			}

			authTup := universe.AuthenticatedIgnoreTuple{
				SignedIgnoreTuple: tup,
				InclusionProof:    proof,
				IgnoreTreeRoot:    finalRoot,
			}

			finalResults = append(finalResults, authTup)
		}

		return nil
	})
	if txErr != nil {
		return lfn.Err[universe.AuthIgnoreTuples](txErr)
	}

	return lfn.Ok(finalResults)
}

// Sum returns the sum of the ignore tuples for the given asset.
func (it *IgnoreUniverseTree) Sum(ctx context.Context,
	spec asset.Specifier) universe.SumQueryResp {

	// Derive identifier from the asset.Specifier.
	id, err := specifierToIdentifier(spec, universe.ProofTypeIgnore)
	if err != nil {
		return lfn.Err[lfn.Option[uint64]](err)
	}

	// Use the generic helper to get the sum of the universe tree.
	return getUniverseTreeSum(ctx, it.db, id)
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

	// Derive identifier from the asset.Specifier.
	id, err := specifierToIdentifier(spec, universe.ProofTypeIgnore)
	if err != nil {
		return lfn.Err[lfn.Option[universe.IgnoreTuples]](err)
	}

	// Use the generic list helper to list the leaves from the universe
	// Tree. We pass in our custom decode function to handle the logic
	// specific to IgnoreTuples.
	return listUniverseLeaves(ctx, it.db, id, decodeIgnoreTuple)
}

// queryIgnoreLeaves retrieves UniverseLeaf records based on IgnoreTuple
// criteria.
func queryIgnoreLeaves(ctx context.Context, dbtx BaseUniverseStore,
	spec asset.Specifier,
	tuples ...universe.IgnoreTuple) ([]UniverseLeaf, error) {

	uniNamespace, err := specifierToIdentifier(
		spec, universe.ProofTypeIgnore,
	)
	if err != nil {
		return nil, fmt.Errorf("error deriving identifier: %w", err)
	}

	var allLeaves []UniverseLeaf
	for _, queryTuple := range tuples {
		// Create a leaf query for this specific key.
		//
		// TODO(roasbeef): need a more specific key here?
		//   * also add outpoint?
		scriptKey := queryTuple.ScriptKey
		leafQuery := UniverseLeafQuery{
			ScriptKeyBytes: scriptKey.SchnorrSerialized(),
			Namespace:      uniNamespace.String(),
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

	// Derive identifier from the asset.Specifier.
	id, err := specifierToIdentifier(spec, universe.ProofTypeIgnore)
	if err != nil {
		return lfn.Err[lfn.Option[[]universe.AuthenticatedIgnoreTuple]](
			err,
		)
	}

	// Use the generic query helper, which will handle: doing the initial
	// query, decoding the ignore tuples, and finally building the merkle
	// proof for the tuples.
	return queryUniverseLeavesAndProofs(
		ctx, it.db, spec, id, queryIgnoreLeaves,
		parseDbSignedIgnoreTuple, universe.NewAuthIgnoreTuple,
		queryTuples...,
	)
}
