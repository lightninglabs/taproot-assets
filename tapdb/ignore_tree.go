package tapdb

import (
	"context"
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

// specifierToIdentifier converts an asset.Specifier into a universe.Identifier.
func specifierToIdentifier(spec asset.Specifier) (universe.Identifier, error) {
	var id universe.Identifier

	groupKey, err := spec.UnwrapGroupKeyOrErr()
	if err != nil {
		return id, fmt.Errorf("group key must be set: %w", err)
	}

	id.GroupKey = groupKey

	id.ProofType = universe.ProofTypeIgnore
	return id, nil
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
	id, err := specifierToIdentifier(spec)
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
	id, err := specifierToIdentifier(spec)
	if err != nil {
		return lfn.Err[lfn.Option[uint64]](err)
	}
	namespace := id.String()

	var sumValue uint64
	var foundSum bool

	readTx := NewBaseUniverseReadTx()
	txErr := it.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		tree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(db, namespace),
		)

		// Get the root of the tree to retrieve the sum.
		root, err := tree.Root(ctx)
		if err != nil {
			return err
		}

		// If root is empty, return empty sum.
		if root.NodeHash() == mssmt.EmptyTreeRootHash {
			return nil
		}

		// Return the sum from the root.
		sumValue = root.NodeSum()
		foundSum = true
		return nil
	})
	if txErr != nil {
		return lfn.Err[lfn.Option[uint64]](txErr)
	}

	if !foundSum {
		return lfn.Ok(lfn.None[uint64]())
	}

	return lfn.Ok(lfn.Some(sumValue))
}

// ListTuples returns the list of ignore tuples for the given asset.
func (it *IgnoreUniverseTree) ListTuples(ctx context.Context,
	spec asset.Specifier) lfn.Result[[]*universe.IgnoreTuple] {

	// Derive identifier from the asset.Specifier.
	id, err := specifierToIdentifier(spec)
	if err != nil {
		return lfn.Err[[]*universe.IgnoreTuple](err)
	}

	namespace := id.String()

	var tuples []*universe.IgnoreTuple

	readTx := NewBaseUniverseReadTx()
	txErr := it.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		// To list all the tuples, we'll just query for all the universe
		// leaves for this namespace. The namespace is derived from the
		// group key, and the proof type, which in this case is ignore.
		universeLeaves, err := db.QueryUniverseLeaves(
			ctx, UniverseLeafQuery{
				Namespace: namespace,
			},
		)
		if err != nil {
			return err
		}

		for _, leaf := range universeLeaves {
			leafBytes := leaf.GenesisProof

			tuple, err := universe.DecodeSignedIgnoreTuple(
				leafBytes,
			)
			if err != nil {
				return fmt.Errorf("error decoding tuple: "+
					"%w", err)
			}

			tuples = append(tuples, &tuple.IgnoreTuple.Val)
		}

		return nil
	})

	if txErr != nil {
		return lfn.Err[[]*universe.IgnoreTuple](txErr)
	}

	return lfn.Ok(tuples)
}

// QueryTuples returns the ignore tuples for the given asset.
func (it *IgnoreUniverseTree) QueryTuples(ctx context.Context,
	spec asset.Specifier,
	queryTuples ...universe.IgnoreTuple) universe.TupleQueryResp {

	if len(queryTuples) == 0 {
		return lfn.Ok(lfn.None[[]universe.AuthenticatedIgnoreTuple]())
	}

	// Derive identifier from the asset.Specifier.
	id, err := specifierToIdentifier(spec)
	if err != nil {
		return lfn.Err[lfn.Option[[]universe.AuthenticatedIgnoreTuple]](
			err,
		)
	}

	namespace := id.String()

	var (
		resultTuples []universe.AuthenticatedIgnoreTuple
		foundAny     bool
	)

	readTx := NewBaseUniverseReadTx()
	txErr := it.db.ExecTx(ctx, &readTx, func(db BaseUniverseStore) error {
		// Create the tree within the transaction for getting root and
		// proofs.
		tree := mssmt.NewCompactedTree(
			newTreeStoreWrapperTx(db, namespace),
		)

		// Get the tree root once for all queries
		root, err := tree.Root(ctx)
		if err != nil {
			return err
		}

		for _, queryTuple := range queryTuples {
			// Generate the SMT key for the query tuple.
			smtKey := queryTuple.Hash()

			// Create a leaf query for this specific key.
			scriptKey := queryTuple.ScriptKey
			leafQuery := UniverseLeafQuery{
				ScriptKeyBytes: scriptKey.SchnorrSerialized(),
				Namespace:      namespace,
			}

			leaves, err := db.QueryUniverseLeaves(
				ctx, leafQuery,
			)
			if err != nil {
				return fmt.Errorf("error querying leaf "+
					"for tuple: %w", err)
			}

			// Skip if no leaves found for this tuple.
			//
			// TODO(roasbeef): move to slice of results? then can
			// see if one failed or not for each
			if len(leaves) == 0 {
				continue
			}

			// Get the first leaf (there should only be one for this
			// specific key).
			rawLeaf := leaves[0].GenesisProof

			// With the key, we can generate the inclusion proof for
			// this tuple.
			proof, err := tree.MerkleProof(ctx, smtKey)
			if err != nil {
				return fmt.Errorf("error generating proof for "+
					"tuple: %w", err)
			}

			// With all the data gathered, we can now create the
			// signed tuple along side the universe root and its
			// inclusion proof.
			signedTuple, err := universe.DecodeSignedIgnoreTuple(
				rawLeaf,
			)
			if err != nil {
				return fmt.Errorf("error deserializing "+
					"tuple: %w", err)
			}
			tup := universe.AuthenticatedIgnoreTuple{
				SignedIgnoreTuple: signedTuple,
				InclusionProof:    proof,
				IgnoreTreeRoot:    root,
			}
			resultTuples = append(resultTuples, tup)

			foundAny = true
		}

		return nil
	})
	if txErr != nil {
		return lfn.Err[lfn.Option[[]universe.AuthenticatedIgnoreTuple]](
			txErr,
		)
	}

	if !foundAny {
		return lfn.Ok(lfn.None[[]universe.AuthenticatedIgnoreTuple]())
	}

	return lfn.Ok(lfn.Some(resultTuples))
}
