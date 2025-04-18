package tapdb

import (
	"context"
	"database/sql"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

const numTuples = 10

func randIgnoreTuple(t *testing.T,
	db BatchedUniverseTree) universe.SignedIgnoreTuple {

	scriptKey := asset.RandScriptKey(t)

	ctx := context.Background()

	// Create an outpoint for the ignore tuple.
	op := test.RandOp(t)

	genesis := asset.RandGenesis(t, asset.Normal)

	assetID := genesis.ID()

	ignoreTuple := &universe.IgnoreTuple{
		PrevID: asset.PrevID{
			ID:        assetID,
			ScriptKey: asset.ToSerialized(scriptKey.PubKey),
			OutPoint:  op,
		},
		Amount: 100,
	}

	// Create a signature for the ignore tuple.
	testSchnorrSigStr, err := hex.DecodeString(
		"04e7f9037658a92afeb4f25bae5339e3ddca81a353493827d26f16d92308" +
			"e49e2a25e92208678a2df86970da91b03a8af8815a8a60498b35" +
			"8daf560b347aa557",
	)
	require.NoError(t, err)
	testSchnorrSig, _ := lnwire.NewSigFromSchnorrRawSignature(
		testSchnorrSigStr,
	)
	testSchnorrSig.ForceSchnorr()
	sig, err := testSchnorrSig.ToSignature()
	require.NoError(t, err)

	signature, ok := sig.(*schnorr.Signature)
	require.True(t, ok)

	genesisOutpoint := genesis.FirstPrevOut

	genesisPointID, err := upsertGenesisPoint(ctx, db, genesisOutpoint)
	require.NoError(t, err)
	_, err = upsertGenesis(ctx, db, genesisPointID, genesis)
	require.NoError(t, err)

	// Create a SignedIgnoreTuple.
	return universe.NewSignedIgnoreTuple(
		*ignoreTuple, universe.IgnoreSig{Signature: *signature},
	)
}

// setupIgnoreTreeTest sets up a test environment for IgnoreUniverseTree
// testing.
func setupIgnoreTreeTest(t *testing.T) (*IgnoreUniverseTree, asset.Specifier,
	[]universe.SignedIgnoreTuple) {

	// Create the ignore tree instance backed by the usual set of batched db
	// abstractions.
	sqlDB := NewTestDB(t)
	dbTxer := NewTransactionExecutor(
		sqlDB, func(tx *sql.Tx) BaseUniverseStore {
			return sqlDB.WithTx(tx)
		},
	)
	ignoreTree := NewIgnoreUniverseTree(dbTxer)

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

	tuples := make([]universe.SignedIgnoreTuple, numTuples)
	for i := 0; i < numTuples; i++ {
		signedTuple := randIgnoreTuple(t, dbTxer)

		tuples[i] = signedTuple
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

	return ignoreTree, spec, tuples
}

// TestIgnoreUniverseTreeAddTuples tests the AddTuples method.
func TestIgnoreUniverseTreeAddTuples(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ignoreTree, spec, signedTuples := setupIgnoreTreeTest(t)

	// Test case 1: Adding a valid tuple should succeed.
	t.Run("valid_add", func(t *testing.T) {
		result := ignoreTree.AddTuples(ctx, spec, signedTuples...)

		tuples, err := result.Unpack()
		require.NoError(t, err)

		require.Len(t, tuples, numTuples)
		for i, tuple := range tuples {
			require.NotNil(t, tuple.InclusionProof)
			require.NotNil(t, tuple.IgnoreTreeRoot)
			require.Equal(
				t, signedTuples[i], tuple.SignedIgnoreTuple,
			)

			// The returned inclusion proof should be valid.
			leafNode, err := tuple.UniverseLeafNode()
			require.NoError(t, err)
			valid := mssmt.VerifyMerkleProof(
				tuple.UniverseKey(), leafNode,
				tuple.InclusionProof,
				tuple.IgnoreTreeRoot,
			)
			require.True(t, valid)
		}
	})

	// Test case 2: Adding with no tuples should return an error.
	t.Run("no_tuples", func(t *testing.T) {
		result := ignoreTree.AddTuples(ctx, spec)
		require.Error(t, result.Err())
		require.Contains(t, result.Err().Error(), "no tuples provided")
	})

	// Test case 3: Adding with a specifier without a group key should fail.
	t.Run("no_group_key", func(t *testing.T) {
		invalidSpec := asset.Specifier{}
		result := ignoreTree.AddTuples(
			ctx, invalidSpec, signedTuples...,
		)
		require.Error(t, result.Err())
		require.Contains(
			t, result.Err().Error(), "group key must be set",
		)
	})
}

// TestIgnoreUniverseTreeSum tests the Sum method.
func TestIgnoreUniverseTreeSum(t *testing.T) {
	ignoreTree, spec, signedTuples := setupIgnoreTreeTest(t)

	ctx := context.Background()

	// Test case 1: Sum of an empty tree should return None.
	t.Run("empty_tree", func(t *testing.T) {
		result := ignoreTree.Sum(ctx, spec)
		require.NoError(t, result.Err())

		sumOption, err := result.Unpack()
		require.NoError(t, err)
		require.True(t, sumOption.IsNone())
	})

	// Test case 2: Sum after adding a tuple should return the tuple's
	// amount.
	t.Run("with_tuple", func(t *testing.T) {
		// First, we'll add the set of tuples to the tree.
		addResult := ignoreTree.AddTuples(
			ctx, spec, signedTuples...,
		)
		require.NoError(t, addResult.Err())

		// With the tuples inserted, we should be able to get the sum.
		result := ignoreTree.Sum(ctx, spec)
		require.NoError(t, result.Err())

		// We should have a non-empty result with the correct sum.
		sumOption, err := result.Unpack()
		require.NoError(t, err)
		require.False(t, sumOption.IsNone())

		expectedTupleSum := fn.Reduce(
			signedTuples,
			func(acc int, tuple universe.SignedIgnoreTuple) int {
				return acc + int(tuple.IgnoreTuple.Val.Amount)
			},
		)
		tupleSum := sumOption.UnwrapOrFail(t)
		require.Equal(t, expectedTupleSum, int(tupleSum))

		// If we add another set of tuples, then the sum should be
		// updated.
		extraTuple := randIgnoreTuple(t, ignoreTree.db)
		extraSum := extraTuple.IgnoreTuple.Val.Amount
		addResult = ignoreTree.AddTuples(ctx, spec, extraTuple)
		require.NoError(t, addResult.Err())

		newSumRes := ignoreTree.Sum(ctx, spec)
		require.NoError(t, newSumRes.Err())

		newSumOption, err := newSumRes.Unpack()
		require.NoError(t, err)
		require.False(t, newSumOption.IsNone())

		newSum := newSumOption.UnwrapOrFail(t)
		expectedNewSum := expectedTupleSum + int(extraSum)
		require.Equal(t, expectedNewSum, int(newSum))
	})

	// Test case 3: Failed sum from invalid specifier.
	t.Run("invalid_specifier", func(t *testing.T) {
		var invalidSpec asset.Specifier
		result := ignoreTree.Sum(ctx, invalidSpec)
		require.Error(t, result.Err())
		require.Contains(
			t, result.Err().Error(), "group key must be set",
		)
	})
}

// TestIgnoreUniverseTreeListTuples tests the ListTuples method.
func TestIgnoreUniverseTreeListTuples(t *testing.T) {
	ignoreTree, spec, signedTuples := setupIgnoreTreeTest(t)

	ctx := context.Background()

	// Test case 1: List from an empty tree should return an empty slice.
	t.Run("empty_tree", func(t *testing.T) {
		result := ignoreTree.ListTuples(ctx, spec)
		require.NoError(t, result.Err())

		tuples, err := result.Unpack()
		require.NoError(t, err)
		require.Empty(t, tuples)
	})

	// Test case 2: List after adding a tuple should return that tuple.
	t.Run("with_tuple", func(t *testing.T) {
		// First, add the set of tuples.
		addResult := ignoreTree.AddTuples(ctx, spec, signedTuples...)
		require.NoError(t, addResult.Err())

		// We should be able to retrieve the exact same set of tuples
		// that we added.
		resTuples, err := ignoreTree.ListTuples(ctx, spec).Unpack()
		require.NoError(t, err)

		dbTuples := resTuples.UnwrapOrFail(t)
		require.Len(t, dbTuples, 10)

		// To make our next assertion easier, we'll create a map of the
		// results keyed by their asset ID, then use that to assert that
		// all the tuples are found and identical.
		tupleMap := make(map[[32]byte]*universe.IgnoreTuple)
		for _, tuple := range dbTuples {
			tupleMap[tuple.ID] = tuple
		}

		for _, tuple := range signedTuples {
			// The tuple should be in the map.
			assetID := tuple.IgnoreTuple.Val.ID
			tup, ok := tupleMap[assetID]
			require.True(t, ok)

			require.Equal(t, *tup, tuple.IgnoreTuple.Val)
		}

		// If we add another new tuple, it should show up in the list.
		extraTuple := randIgnoreTuple(t, ignoreTree.db)
		addResult = ignoreTree.AddTuples(ctx, spec, extraTuple)
		require.NoError(t, addResult.Err())

		newTuples, err := ignoreTree.ListTuples(ctx, spec).Unpack()
		require.NoError(t, err)

		dbTuples = newTuples.UnwrapOrFail(t)
		require.Len(t, dbTuples, len(signedTuples)+1)
	})

	// Test case 3: List with invalid specifier should fail.
	t.Run("invalid_specifier", func(t *testing.T) {
		invalidSpec := asset.Specifier{}
		result := ignoreTree.ListTuples(ctx, invalidSpec)
		require.Error(t, result.Err())
		require.Contains(
			t, result.Err().Error(), "group key must be set",
		)
	})
}

// TestIgnoreUniverseTreeQueryTuples tests the QueryTuples method.
func TestIgnoreUniverseTreeQueryTuples(t *testing.T) {
	ignoreTree, spec, signedTuples := setupIgnoreTreeTest(t)

	ctx := context.Background()

	// Test case 1: Query with no tuples should return None.
	t.Run("no_tuples", func(t *testing.T) {
		result := ignoreTree.QueryTuples(ctx, spec)
		require.NoError(t, result.Err())

		tuplesOption, err := result.Unpack()
		require.NoError(t, err)
		require.True(t, tuplesOption.IsNone())
	})

	// Test case 2: Query with invalid specifier should fail.
	t.Run("invalid_specifier", func(t *testing.T) {
		invalidSpec := asset.Specifier{}
		result := ignoreTree.QueryTuples(
			ctx, invalidSpec, signedTuples[0].IgnoreTuple.Val,
		)
		require.Error(t, result.Err())
		require.Contains(
			t, result.Err().Error(), "group key must be set",
		)
	})

	// Test case 3: Query for a tuple that doesn't exist should return None.
	t.Run("non_existent_tuple", func(t *testing.T) {
		// Query for a tuple that hasn't been added.
		result := ignoreTree.QueryTuples(
			ctx, spec, signedTuples[0].IgnoreTuple.Val,
		)
		require.NoError(t, result.Err())

		tuplesOption, err := result.Unpack()
		require.NoError(t, err)
		require.True(t, tuplesOption.IsNone())
	})

	// Test case 4: Query for a tuple that exists should return that tuple.
	t.Run("existing_tuple", func(t *testing.T) {
		// Add all the tuples to the tree.
		addResult := ignoreTree.AddTuples(ctx, spec, signedTuples...)
		require.NoError(t, addResult.Err())

		// For each tuple we added, we should be able to query for it,
		// and verify that it has a valid inclusion proof.
		for _, tuple := range signedTuples {
			qResult := ignoreTree.QueryTuples(
				ctx, spec, tuple.IgnoreTuple.Val,
			)
			require.NoError(t, qResult.Err())

			optTuples, err := qResult.Unpack()
			require.NoError(t, err)
			require.False(
				t, optTuples.IsNone(), "expected non-empty "+
					"result for existing tuple",
			)

			queriedTuples := optTuples.UnwrapOrFail(t)
			require.Len(
				t, queriedTuples, 1, "should return exactly "+
					"one matching tuple",
			)

			queriedTuple := queriedTuples[0]
			require.Equal(t, tuple, queriedTuple.SignedIgnoreTuple)

			leafNode, err := queriedTuple.UniverseLeafNode()
			require.NoError(t, err)
			valid := mssmt.VerifyMerkleProof(
				queriedTuple.UniverseKey(),
				leafNode,
				queriedTuple.InclusionProof,
				queriedTuple.IgnoreTreeRoot,
			)
			require.True(t, valid, "inclusion proof is not valid")
		}
	})
}
