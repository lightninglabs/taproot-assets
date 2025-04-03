package tapdb

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
)

const numBurnLeaves = 10

// createBurnAsset creates a burn asset for testing purposes.
func createBurnAsset(t *testing.T) *asset.Asset {
	a := asset.RandAsset(t, asset.Normal)

	a.ScriptKey = asset.NewScriptKey(
		asset.DeriveBurnKey(*a.PrevWitnesses[0].PrevID),
	)

	return a
}

// createBurnProof creates a valid burn proof for testing.
func createBurnProof(t *testing.T) *proof.Proof {
	a := createBurnAsset(t)

	return randProof(t, a)
}

// createBurnLeaf creates a burn leaf from a burn proof.
func createBurnLeaf(t *testing.T) *universe.BurnLeaf {
	burnProof := createBurnProof(t)
	scriptKey := asset.RandScriptKey(t)

	return &universe.BurnLeaf{
		UniverseKey: universe.AssetLeafKey{
			BaseLeafKey: universe.BaseLeafKey{
				OutPoint:  burnProof.OutPoint(),
				ScriptKey: &scriptKey,
			},
			AssetID: burnProof.Asset.ID(),
		},
		BurnProof: burnProof,
	}
}

// setupBurnTreeTest sets up a test environment for BurnUniverseTree testing.
func setupBurnTreeTest(t *testing.T) (*BurnUniverseTree, asset.Specifier,
	[]*universe.BurnLeaf) {

	// Create the burn tree instance backed by the usual set of batched db
	// abstractions.
	sqlDB := NewTestDB(t)
	dbTxer := NewTransactionExecutor(
		sqlDB, func(tx *sql.Tx) BaseUniverseStore {
			return sqlDB.WithTx(tx)
		},
	)
	burnTree := NewBurnUniverseTree(dbTxer)

	// Create a context for the test.
	ctx := context.Background()

	// Generate a random group key for testing.
	groupPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	groupPub := groupPrivKey.PubKey()
	groupKey := asset.GroupKey{
		GroupPubKey: *groupPub,
	}

	genesis := asset.RandGenesis(t, asset.Normal)
	assetID := genesis.ID()

	// Create an asset specifier with the group key.
	spec, err := asset.NewSpecifier(
		&assetID, &groupKey.GroupPubKey, nil, true,
	)
	require.NoError(t, err)

	// Create burn leaves.
	burnLeaves := make([]*universe.BurnLeaf, numBurnLeaves)
	for i := 0; i < numBurnLeaves; i++ {
		burnLeaves[i] = createBurnLeaf(t)

		// Insert the asset genesis for each burn leaf into the DB.
		burnAsset := burnLeaves[i].BurnProof.Asset
		burnGenesis := burnAsset.Genesis
		burnGenesisOutpoint := burnGenesis.FirstPrevOut

		genesisPointID, err := upsertGenesisPoint(
			ctx, dbTxer, burnGenesisOutpoint,
		)
		require.NoError(t, err)
		_, err = upsertGenesis(ctx, dbTxer, genesisPointID, burnGenesis)
		require.NoError(t, err)
	}

	genesisOutpoint := genesis.FirstPrevOut

	// Insert the asset genesis, genesis point, and group key into the
	// database. We'll need this to be able to create universe leaves
	// properly.
	genesisPointID, err := upsertGenesisPoint(ctx, dbTxer, genesisOutpoint)
	require.NoError(t, err)
	genAssetID, err := upsertGenesis(ctx, dbTxer, genesisPointID, genesis)
	require.NoError(t, err)

	_, err = upsertGroupKey(
		ctx, &groupKey, dbTxer, genesisPointID, genAssetID,
	)
	require.NoError(t, err)

	return burnTree, spec, burnLeaves
}

// TestBurnUniverseTreeInsertBurns tests the InsertBurns method.
func TestBurnUniverseTreeInsertBurns(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	burnTree, spec, burnLeaves := setupBurnTreeTest(t)

	// Test case 1: Inserting valid burn leaves should succeed.
	t.Run("valid_insert", func(t *testing.T) {
		result := burnTree.InsertBurns(ctx, spec, burnLeaves...)

		authLeaves, err := result.Unpack()
		require.NoError(t, err)

		require.Len(t, authLeaves, numBurnLeaves)
		for i, authLeaf := range authLeaves {
			require.NotNil(t, authLeaf.BurnTreeRoot)
			require.NotNil(t, authLeaf.BurnProof)
			require.Equal(t, burnLeaves[i], authLeaf.BurnLeaf)

			// The returned inclusion proof should be valid.
			leafNode, err := authLeaf.BurnLeaf.UniverseLeafNode()
			require.NoError(t, err)
			key := authLeaf.BurnLeaf.UniverseKey.UniverseKey()

			valid := mssmt.VerifyMerkleProof(
				key, leafNode, authLeaf.BurnProof,
				authLeaf.BurnTreeRoot,
			)
			require.True(t, valid)
		}
	})

	// Test case 2: Inserting with no burn leaves should return an error.
	t.Run("no_leaves", func(t *testing.T) {
		result := burnTree.InsertBurns(ctx, spec)
		require.Error(t, result.Err())
		require.Contains(
			t, result.Err().Error(), "no burn leaves provided",
		)
	})

	// Test case 3: Inserting with a specifier without a group key should
	// fail.
	t.Run("no_group_key", func(t *testing.T) {
		invalidSpec := asset.Specifier{}
		result := burnTree.InsertBurns(
			ctx, invalidSpec, burnLeaves...,
		)
		require.Error(t, result.Err())
		require.Contains(
			t, result.Err().Error(), "group key must be set",
		)
	})

	// Test case 4: Inserting non-burn proof should fail.
	t.Run("non_burn_proof", func(t *testing.T) {
		// Create a non-burn leaf, the script key won't be an actual
		// burn.
		a := asset.RandAsset(t, asset.Normal)

		op := test.RandOp(t)

		nonBurnProof := &proof.Proof{
			Asset:   *a,
			PrevOut: op,
		}

		nonBurnLeaf := &universe.BurnLeaf{
			UniverseKey: universe.AssetLeafKey{
				BaseLeafKey: universe.BaseLeafKey{
					OutPoint:  op,
					ScriptKey: &a.ScriptKey,
				},
				AssetID: a.ID(),
			},
			BurnProof: nonBurnProof,
		}

		result := burnTree.InsertBurns(ctx, spec, nonBurnLeaf)
		require.Error(t, result.Err())
		require.True(t, errors.Is(result.Err(), ErrNotBurn))
	})

	// Test case 5: Test idempotency - inserting the same burn leaf multiple
	// times.
	t.Run("idempotency", func(t *testing.T) {
		// Create a new test environment to isolate the test.
		burnTree, spec, burnLeaves := setupBurnTreeTest(t)

		// Select a single burn leaf for the test.
		burnLeaf := burnLeaves[0]

		// Initial insertion.
		result1 := burnTree.InsertBurns(ctx, spec, burnLeaf)
		authLeaves1, err := result1.Unpack()
		require.NoError(t, err)
		require.Len(t, authLeaves1, 1)

		// Store the root and proof from the first insertion.
		originalRoot := authLeaves1[0].BurnTreeRoot

		// Check sum after first insertion.
		sumResult1 := burnTree.Sum(ctx, spec)
		sumOpt1, err := sumResult1.Unpack()
		require.NoError(t, err)

		originalSum := sumOpt1.UnwrapOrFail(t)
		require.Equal(t, burnLeaf.BurnProof.Asset.Amount, originalSum)

		// Insert the same burn leaf again.
		result2 := burnTree.InsertBurns(ctx, spec, burnLeaf)
		authLeaves2, err := result2.Unpack()
		require.NoError(t, err)
		require.Len(t, authLeaves2, 1)

		// The root should be the same as the original, indicating the
		// tree didn't change.
		require.Equal(
			t, originalRoot.NodeHash(),
			authLeaves2[0].BurnTreeRoot.NodeHash(),
		)
		require.Equal(
			t, originalRoot.NodeSum(),
			authLeaves2[0].BurnTreeRoot.NodeSum(),
		)

		// The sum should not change after inserting the same leaf
		// again.
		sumResult2 := burnTree.Sum(ctx, spec)
		sumOpt2, err := sumResult2.Unpack()
		require.NoError(t, err)

		newSum := sumOpt2.UnwrapOrFail(t)
		require.Equal(t, originalSum, newSum)

		// Insert the same burn leaf a third time.
		result3 := burnTree.InsertBurns(ctx, spec, burnLeaf)
		require.NoError(t, result3.Err())

		// Query for the burn leaf - should only find one instance.
		queryResult := burnTree.QueryBurns(
			ctx, spec, burnLeaf.BurnProof.OutPoint(),
		)
		queryOpt, err := queryResult.Unpack()
		require.NoError(t, err)
		queryLeaves := queryOpt.UnwrapOrFail(t)

		// There should be exactly one leaf for this outpoint+scriptkey
		// combination, not multiple.
		count := 0
		for _, leaf := range queryLeaves {
			//nolint:lll
			if leaf.BurnLeaf.UniverseKey.LeafOutPoint() ==
				burnLeaf.UniverseKey.LeafOutPoint() &&
				leaf.BurnLeaf.UniverseKey.LeafScriptKey().PubKey.IsEqual(
					burnLeaf.UniverseKey.LeafScriptKey().PubKey,
				) {

				count++
			}
		}
		require.Equal(
			t, 1, count,
			"expected only one leaf for the same UniverseKey",
		)
	})

	// Test case 6: Test idempotency with multiple leaves, including
	// duplicates.
	t.Run("idempotency_multiple_leaves", func(t *testing.T) {
		// Create a new test environment to isolate the test.
		burnTree, spec, burnLeaves := setupBurnTreeTest(t)

		// Initial insertion of all burn leaves.
		result1 := burnTree.InsertBurns(ctx, spec, burnLeaves...)
		require.NoError(t, result1.Err())

		// Get the sum after inserting all leaves.
		sumResult1 := burnTree.Sum(ctx, spec)
		require.NoError(t, sumResult1.Err())
		sumOpt1, err := sumResult1.Unpack()
		require.NoError(t, err)
		require.False(t, sumOpt1.IsNone())
		originalSum := sumOpt1.UnwrapOrFail(t)

		// Create a batch with some duplicates - first 3 leaves
		// repeated.
		duplicateBatch := append(
			[]*universe.BurnLeaf{
				burnLeaves[0],
				burnLeaves[1],
				burnLeaves[2],
			},
			burnLeaves...,
		)

		// Insert the batch with duplicates.
		result2 := burnTree.InsertBurns(ctx, spec, duplicateBatch...)
		require.NoError(t, result2.Err())

		// The sum should not change after inserting duplicates.
		sumResult2 := burnTree.Sum(ctx, spec)
		require.NoError(t, sumResult2.Err())
		sumOpt2, err := sumResult2.Unpack()
		require.NoError(t, err)
		require.False(t, sumOpt2.IsNone())
		newSum := sumOpt2.UnwrapOrFail(t)
		require.Equal(t, originalSum, newSum)

		// ListBurns should show the correct number of unique burns.
		listResult := burnTree.ListBurns(ctx, spec)
		burnsOpt, err := listResult.Unpack()
		require.NoError(t, err)

		burnDescs := burnsOpt.UnwrapOrFail(t)
		require.Len(
			t, burnDescs, numBurnLeaves,
			"expected burnDescs length to match original "+
				"number of leaves",
		)
	})
}

// TestBurnUniverseTreeSum tests the Sum method.
func TestBurnUniverseTreeSum(t *testing.T) {
	t.Parallel()

	burnTree, spec, burnLeaves := setupBurnTreeTest(t)

	ctx := context.Background()

	// Test case 1: Sum of an empty tree should return None.
	t.Run("empty_tree", func(t *testing.T) {
		result := burnTree.Sum(ctx, spec)
		require.NoError(t, result.Err())

		sumOption, err := result.Unpack()
		require.NoError(t, err)
		require.True(t, sumOption.IsNone())
	})

	// Test case 2: Sum after adding burn leaves should return their summed
	// amount.
	t.Run("with_burns", func(t *testing.T) {
		// Insert the burn leaves first.
		addResult := burnTree.InsertBurns(ctx, spec, burnLeaves...)
		require.NoError(t, addResult.Err())

		// Get the sum.
		result := burnTree.Sum(ctx, spec)
		require.NoError(t, result.Err())

		// We should have a non-empty result with the correct sum>
		sumOption, err := result.Unpack()
		require.NoError(t, err)
		require.False(t, sumOption.IsNone())

		// Calculate the expected sum.
		var expectedSum uint64
		for _, leaf := range burnLeaves {
			expectedSum += leaf.BurnProof.Asset.Amount
		}

		actualSum := sumOption.UnwrapOrFail(t)
		require.Equal(t, expectedSum, actualSum)

		// Add one more burn leaf and check sum is updated.
		extraLeaf := createBurnLeaf(t)
		extraAmount := extraLeaf.BurnProof.Asset.Amount

		addResult = burnTree.InsertBurns(ctx, spec, extraLeaf)
		require.NoError(t, addResult.Err())

		newSumRes := burnTree.Sum(ctx, spec)
		require.NoError(t, newSumRes.Err())

		newSumOption, err := newSumRes.Unpack()
		require.NoError(t, err)
		require.False(t, newSumOption.IsNone())

		newSum := newSumOption.UnwrapOrFail(t)
		expectedNewSum := expectedSum + extraAmount
		require.Equal(t, expectedNewSum, newSum)
	})

	// Test case 3: Failed sum from invalid specifier.
	t.Run("invalid_specifier", func(t *testing.T) {
		var invalidSpec asset.Specifier
		result := burnTree.Sum(ctx, invalidSpec)
		require.Error(t, result.Err())
		require.Contains(
			t, result.Err().Error(), "group key must be set",
		)
	})
}

// TestBurnUniverseTreeQueryBurns tests the QueryBurns method.
func TestBurnUniverseTreeQueryBurns(t *testing.T) {
	t.Parallel()

	burnTree, spec, burnLeaves := setupBurnTreeTest(t)

	ctx := context.Background()

	// Test case 1: Query on empty tree should return None.
	t.Run("empty_tree", func(t *testing.T) {
		result := burnTree.QueryBurns(ctx, spec)
		require.NoError(t, result.Err())

		burnOption, err := result.Unpack()
		require.NoError(t, err)
		require.True(t, burnOption.IsNone())
	})

	// Test case 2: Query after inserting burns should return correct
	// results.
	t.Run("query_all", func(t *testing.T) {
		// Insert the burn leaves first
		addResult := burnTree.InsertBurns(ctx, spec, burnLeaves...)
		require.NoError(t, addResult.Err())

		// Query all burns.
		result := burnTree.QueryBurns(ctx, spec)
		require.NoError(t, result.Err())

		burnOption, err := result.Unpack()
		require.NoError(t, err)
		require.False(t, burnOption.IsNone())

		authLeaves := burnOption.UnwrapOrFail(t)
		require.Len(t, authLeaves, numBurnLeaves)

		// Verify each burn leaf has correct data and proofs.
		for _, authLeaf := range authLeaves {
			require.NotNil(t, authLeaf.BurnTreeRoot)
			require.NotNil(t, authLeaf.BurnProof)
			require.NotNil(t, authLeaf.BurnLeaf)
			require.NotNil(t, authLeaf.BurnLeaf.BurnProof)

			// The proofs should be valid.
			leafNode, err := authLeaf.BurnLeaf.UniverseLeafNode()
			require.NoError(t, err)
			leafKey := authLeaf.BurnLeaf.UniverseKey
			key := leafKey.UniverseKey()

			valid := mssmt.VerifyMerkleProof(
				key, leafNode, authLeaf.BurnProof,
				authLeaf.BurnTreeRoot,
			)
			require.True(t, valid)
		}
	})

	// Test case 3: Query specific burn points.
	t.Run("query_specific_point", func(t *testing.T) {
		// Insert the burn leaves first if not already done.
		addResult := burnTree.InsertBurns(ctx, spec, burnLeaves...)
		require.NoError(t, addResult.Err())

		// Query for a specific burn point.
		targetPoint := burnLeaves[0].BurnProof.OutPoint()
		result := burnTree.QueryBurns(ctx, spec, targetPoint)
		require.NoError(t, result.Err())

		burnOption, err := result.Unpack()
		require.NoError(t, err)
		require.False(t, burnOption.IsNone())

		authLeaves := burnOption.UnwrapOrFail(t)
		require.NotEmpty(t, authLeaves)

		// All returned leaves should match the target outpoint.
		for _, authLeaf := range authLeaves {
			require.Equal(
				t, targetPoint,
				authLeaf.BurnLeaf.BurnProof.OutPoint(),
			)
		}

		// Query for a non-existent point.
		nonExistentPoint := wire.OutPoint{
			Index: 99999,
		}
		nonExistResult := burnTree.QueryBurns(
			ctx, spec, nonExistentPoint,
		)
		require.NoError(t, nonExistResult.Err())

		nonExistOption, err := nonExistResult.Unpack()
		require.NoError(t, err)
		require.True(t, nonExistOption.IsNone())
	})

	// Test case 4: Invalid specifier.
	t.Run("invalid_specifier", func(t *testing.T) {
		var invalidSpec asset.Specifier
		result := burnTree.QueryBurns(ctx, invalidSpec)
		require.Error(t, result.Err())
		require.Contains(
			t, result.Err().Error(), "group key must be set",
		)
	})
}

// TestBurnUniverseTreeListBurns tests the ListBurns method.
func TestBurnUniverseTreeListBurns(t *testing.T) {
	t.Parallel()

	burnTree, spec, burnLeaves := setupBurnTreeTest(t)

	ctx := context.Background()

	// Test case 1: List from an empty tree should return None.
	t.Run("empty_tree", func(t *testing.T) {
		result := burnTree.ListBurns(ctx, spec)
		require.NoError(t, result.Err())

		burnsOption, err := result.Unpack()
		require.NoError(t, err)
		require.True(t, burnsOption.IsNone())
	})

	// Test case 2: List after adding burn leaves should return all burns
	t.Run("with_burns", func(t *testing.T) {
		// Insert the burn leaves first.
		addResult := burnTree.InsertBurns(ctx, spec, burnLeaves...)
		require.NoError(t, addResult.Err())

		// List all burns.
		result := burnTree.ListBurns(ctx, spec)
		require.NoError(t, result.Err())

		burnsOption, err := result.Unpack()
		require.NoError(t, err)
		require.False(t, burnsOption.IsNone())

		burnDescs := burnsOption.UnwrapOrFail(t)
		require.Len(t, burnDescs, numBurnLeaves)

		// Verify the returned burn descriptions match our inserted
		// leaves Create a map to help with verification.
		burnMap := make(map[wire.OutPoint]*universe.BurnDesc)
		for _, desc := range burnDescs {
			burnMap[desc.BurnPoint] = desc
		}

		// Check each original leaf has a matching description.
		for _, leaf := range burnLeaves {
			burnPoint := leaf.BurnProof.OutPoint()
			desc, found := burnMap[burnPoint]
			require.True(t, found)

			// Verify the data matches.
			require.Equal(
				t, int64(leaf.BurnProof.Asset.Amount),
				int64(desc.Amt),
			)
			require.Equal(t, burnPoint, desc.BurnPoint)
			assetSpec := leaf.BurnProof.Asset.Specifier()
			require.Equal(t, assetSpec, desc.AssetSpec)
		}

		// Add another burn leaf and check it appears in the list.
		extraLeaf := createBurnLeaf(t)
		addResult = burnTree.InsertBurns(ctx, spec, extraLeaf)
		require.NoError(t, addResult.Err())

		newResult := burnTree.ListBurns(ctx, spec)
		require.NoError(t, newResult.Err())

		newBurnsOption, err := newResult.Unpack()
		require.NoError(t, err)
		require.False(t, newBurnsOption.IsNone())

		newBurnDescs := newBurnsOption.UnwrapOrFail(t)
		require.Len(t, newBurnDescs, numBurnLeaves+1)
	})

	// Test case 3: List with invalid specifier should fail.
	t.Run("invalid_specifier", func(t *testing.T) {
		invalidSpec := asset.Specifier{}
		result := burnTree.ListBurns(ctx, invalidSpec)
		require.Error(t, result.Err())
		require.Contains(
			t, result.Err().Error(), "group key must be set",
		)
	})
}

// A compile-time assertion to ensure BurnUniverseTree implements the
// universe.BurnTree interface.
var _ universe.BurnTree = (*BurnUniverseTree)(nil)
