//go:build !race

package mssmt_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	_ "github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/stretchr/testify/require"
)

var (
	errorTestVectorName       = "mssmt_tree_error_cases.json"
	deletionTestVectorName    = "mssmt_tree_deletion.json"
	replacementTestVectorName = "mssmt_tree_replacement.json"

	allTestVectorFiles = []string{
		proofsTestVectorName,
		deletionTestVectorName,
		replacementTestVectorName,
		errorTestVectorName,
	}
)

type makeTestTreeStoreFunc = func() (mssmt.TreeStore, error)

func genTestStores(t *testing.T) map[string]makeTestTreeStoreFunc {
	constructors := make(map[string]makeTestTreeStoreFunc)

	for _, driver := range mssmt.RegisteredTreeStores() {
		var makeFunc makeTestTreeStoreFunc
		if driver.Name == "sqlite3" {
			makeFunc = func() (mssmt.TreeStore, error) {
				dbFileName := filepath.Join(
					t.TempDir(), "tmp.db",
				)

				treeStore, err := driver.New(dbFileName, "test")
				if err != nil {
					return nil, fmt.Errorf("unable to "+
						"create new sqlite tree "+
						"store: %w", err)
				}

				return treeStore, nil
			}
		}

		constructors[driver.Name] = makeFunc
	}

	constructors["default"] = func() (mssmt.TreeStore, error) {
		return mssmt.NewDefaultStore(), nil
	}

	return constructors
}

func printStoreStats(t *testing.T, store mssmt.TreeStore) {
	s, ok := store.(*mssmt.DefaultStore)
	if ok {
		t.Logf("%s: %s", t.Name(), s.Stats())
	}
}

func makeFullTree(store mssmt.TreeStore) mssmt.Tree {
	tree := mssmt.NewFullTree(store)
	return tree
}

func makeSmolTree(store mssmt.TreeStore) mssmt.Tree {
	tree := mssmt.NewCompactedTree(store)
	return tree
}

// testInsertion asserts that we can insert N leaves and retrieve them by their
// insertion key. Keys that do not exist within the tree should return an empty
// leaf.
func testInsertion(t *testing.T, leaves []treeLeaf, tree mssmt.Tree) {
	ctx := context.Background()
	for _, item := range leaves {
		_, err := tree.Insert(ctx, item.key, item.leaf)
		require.NoError(t, err)
	}

	for _, item := range leaves {
		// The leaf was already inserted into the tree above, so verify
		// that we're able to look it up again.
		leafCopy, err := tree.Get(ctx, item.key)
		require.NoError(t, err)
		require.Equal(t, item.leaf, leafCopy)
	}

	// Finally verify that we're able to loop up a random key (resulting
	// in the default empty leaf).
	emptyLeaf, err := tree.Get(ctx, test.RandHash())
	require.NoError(t, err)
	require.True(t, emptyLeaf.IsEmpty())
}

// testProofs asserts that we can generate merkle proofs for leaves in the tree.
func testProofs(t *testing.T, leaves []treeLeaf, tree mssmt.Tree) {
	ctx := context.Background()

	for _, item := range leaves {
		proof, err := tree.MerkleProof(ctx, item.key)
		require.NoError(t, err)

		// Verify that compressing and encoding then decoding and
		// decompressing leads to identical proofs.
		var buf bytes.Buffer
		err = proof.Compress().Encode(&buf)
		require.NoError(t, err)

		compressedProof := &mssmt.CompressedProof{}
		err = compressedProof.Decode(&buf)
		require.NoError(t, err)

		copiedProof, err := compressedProof.Decompress()
		require.NoError(t, err)

		assertEqualProof(t, proof, copiedProof)

		// Now make sure that copying a proof also results in an
		// identical copy.
		copiedProof = proof.Copy()
		assertEqualProof(t, proof, copiedProof)
	}
}

func TestInsertion(t *testing.T) {
	t.Parallel()

	leaves := randTree(100)

	runTest := func(t *testing.T, name string,
		makeTree func(mssmt.TreeStore) mssmt.Tree,
		makeStore makeTestTreeStoreFunc) {

		t.Run(name, func(t *testing.T) {
			store, err := makeStore()
			require.NoError(t, err)

			tree := makeTree(store)

			testInsertion(t, leaves, tree)
			testProofs(t, leaves, tree)
			printStoreStats(t, store)
		})
	}

	for storeName, makeStore := range genTestStores(t) {
		t.Run(storeName, func(t *testing.T) {
			runTest(t, "full SMT", makeFullTree, makeStore)
			runTest(t, "smol SMT", makeSmolTree, makeStore)
		})
	}
}

// TestInsertionOverflow tests to ensure that we catch overflows when inserting
// leaves into the tree.
func TestInsertionOverflow(t *testing.T) {
	t.Parallel()

	testCaseOk := &mssmt.ValidTestCase{
		Comment: "non overflowing leaf",
	}
	testCaseOverflow := &mssmt.ErrorTestCase{
		Comment: "overflowing leaf",
	}
	testVectors := &mssmt.TestVectors{
		ValidTestCases: []*mssmt.ValidTestCase{
			testCaseOk,
		},
		ErrorTestCases: []*mssmt.ErrorTestCase{
			testCaseOverflow,
		},
	}

	// Construct a minimal leaf which should not cause an overflow when
	// inserted.
	value := test.RandBytes(10)
	minLeaf := treeLeaf{
		key:  test.RandHash(),
		leaf: mssmt.NewLeafNode(value, 1),
	}

	// Construct a leaf which should cause an overflow when inserted.
	leafSum := uint64(math.MaxUint64)
	overflowLeaf := treeLeaf{
		key:  test.RandHash(),
		leaf: mssmt.NewLeafNode(value, leafSum),
	}

	// We'll generate two test vectors, one successful with just the minimal
	// leaf and one overflowing.
	testVectors.AllTreeLeaves = []*mssmt.TestLeaf{
		mssmt.NewTestFromLeaf(t, minLeaf.key, minLeaf.leaf),
		mssmt.NewTestFromLeaf(t, overflowLeaf.key, overflowLeaf.leaf),
	}
	testCaseOk.InsertedLeaves = []string{hex.EncodeToString(minLeaf.key[:])}
	testCaseOverflow.InsertedLeaves = []string{
		hex.EncodeToString(minLeaf.key[:]),
		hex.EncodeToString(overflowLeaf.key[:]),
	}

	runTest := func(t *testing.T, name string,
		makeTree func(mssmt.TreeStore) mssmt.Tree,
		makeStore makeTestTreeStoreFunc) {

		t.Run(name, func(t *testing.T) {
			store, err := makeStore()
			require.NoError(t, err)

			tree := makeTree(store)

			ctx := context.TODO()

			// Insert minimal sum leaf, which shouldn't cause an
			// overflow.
			_, err = tree.Insert(ctx, minLeaf.key, minLeaf.leaf)
			require.NoError(t, err)

			root, err := tree.Root(ctx)
			require.NoError(t, err)

			testCaseOk.RootHash = hex.EncodeToString(
				fn.ByteSlice(root.NodeHash()),
			)
			testCaseOk.RootSum = strconv.FormatUint(
				root.NodeSum(), 10,
			)

			// Insert overflow leaf, which should return an error.
			_, err = tree.Insert(
				ctx, overflowLeaf.key, overflowLeaf.leaf,
			)
			require.ErrorIs(t, err, mssmt.ErrIntegerOverflow)

			testCaseOverflow.Error = mssmt.ErrIntegerOverflow.Error()
		})
	}

	for storeName, makeStore := range genTestStores(t) {
		t.Run(storeName, func(t *testing.T) {
			runTest(
				t, "full tree minimal overflow", makeFullTree,
				makeStore,
			)
			runTest(
				t, "compact tree minimal overflow",
				makeSmolTree, makeStore,
			)
		})
	}

	// Write test vectors to file. This is a no-op if the "gen_test_vectors"
	// build tag is not set.
	test.WriteTestVectors(t, errorTestVectorName, testVectors)
}

// TestReplaceWithEmptyBranch tests that a compacted tree won't add default
// branches when whole subtrees are deleted.
func TestReplaceWithEmptyBranch(t *testing.T) {
	t.Parallel()

	testCase := &mssmt.ValidTestCase{
		Comment: "sub tree deletion",
	}
	testVectors := &mssmt.TestVectors{
		ValidTestCases: []*mssmt.ValidTestCase{
			testCase,
		},
	}

	store := mssmt.NewDefaultStore()
	tree := mssmt.NewCompactedTree(store)

	// Generate a tree of this shape:
	//           R
	//          / \
	//         1   B
	//            / \
	//           4   2
	keys := [][32]byte{
		{1}, {2}, {4},
	}

	ctx := context.TODO()
	for _, key := range keys {
		leaf := randLeaf()
		_, err := tree.Insert(ctx, key, leaf)
		require.NoError(t, err)

		testVectors.AllTreeLeaves = append(
			testVectors.AllTreeLeaves, mssmt.NewTestFromLeaf(
				t, key, leaf,
			),
		)
		testCase.InsertedLeaves = append(
			testCase.InsertedLeaves,
			hex.EncodeToString(key[:]),
		)
	}

	// Make sure the store has all our leaves and branches.
	require.Equal(t, 2, store.NumBranches())
	require.Equal(t, 0, store.NumLeaves())
	require.Equal(t, 3, store.NumCompactedLeaves())

	// Now delete compacted leafs 2 and 4 which would trigger inserting a
	// default branch in place of their parent B.
	_, err := tree.Delete(ctx, keys[1])
	require.NoError(t, err)
	_, err = tree.Delete(ctx, keys[2])
	require.NoError(t, err)

	testCase.DeletedLeaves = append(
		testCase.DeletedLeaves,
		hex.EncodeToString(keys[1][:]),
		hex.EncodeToString(keys[2][:]),
	)

	// We expect that the store only has one compacted leaf and one branch.
	require.Equal(t, 1, store.NumBranches())
	require.Equal(t, 0, store.NumLeaves())
	require.Equal(t, 1, store.NumCompactedLeaves())

	root, err := tree.Root(ctx)
	require.NoError(t, err)

	testCase.RootHash = hex.EncodeToString(fn.ByteSlice(root.NodeHash()))
	testCase.RootSum = strconv.FormatUint(root.NodeSum(), 10)

	// Write test vectors to file. This is a no-op if the "gen_test_vectors"
	// build tag is not set.
	test.WriteTestVectors(t, deletionTestVectorName, testVectors)
}

// TestReplace tests that replacing keys works as expected.
func TestReplace(t *testing.T) {
	t.Parallel()

	testCase := &mssmt.ValidTestCase{
		Comment: "leaf replacement",
	}
	testVectors := &mssmt.TestVectors{
		ValidTestCases: []*mssmt.ValidTestCase{
			testCase,
		},
	}

	const numLeaves = 100

	leaves1 := genTreeFromRange(numLeaves)
	leaves2 := genTreeFromRange(numLeaves)

	for idx := range leaves1 {
		item := leaves1[idx]
		testVectors.AllTreeLeaves = append(
			testVectors.AllTreeLeaves,
			mssmt.NewTestFromLeaf(t, item.key, item.leaf),
		)
		testCase.InsertedLeaves = append(
			testCase.InsertedLeaves,
			hex.EncodeToString(item.key[:]),
		)
	}
	for idx := range leaves2 {
		item := leaves2[idx]
		testCase.ReplacedLeaves = append(
			testCase.ReplacedLeaves,
			mssmt.NewTestFromLeaf(t, item.key, item.leaf),
		)
	}

	testUpdate := func(tree mssmt.Tree) {
		ctx := context.TODO()
		for _, item := range leaves1 {
			_, err := tree.Insert(ctx, item.key, item.leaf)
			require.NoError(t, err)
		}

		for _, item := range leaves1 {
			leafCopy, err := tree.Get(ctx, item.key)
			require.NoError(t, err)
			require.Equal(t, item.leaf, leafCopy)
		}

		for _, item := range leaves2 {
			_, err := tree.Insert(ctx, item.key, item.leaf)
			require.NoError(t, err)
		}

		for _, item := range leaves2 {
			leafCopy, err := tree.Get(ctx, item.key)
			require.NoError(t, err)
			require.Equal(t, item.leaf, leafCopy)
		}

		root, err := tree.Root(ctx)
		require.NoError(t, err)

		testCase.RootHash = hex.EncodeToString(
			fn.ByteSlice(root.NodeHash()),
		)
		testCase.RootSum = strconv.FormatUint(root.NodeSum(), 10)
	}

	runTest := func(t *testing.T, name string,
		makeTree func(mssmt.TreeStore) mssmt.Tree,
		makeStore makeTestTreeStoreFunc) {

		t.Run(name, func(t *testing.T) {
			store, err := makeStore()
			require.NoError(t, err)

			tree := makeTree(store)
			testUpdate(tree)
		})
	}

	for storeName, makeStore := range genTestStores(t) {
		makeStore := makeStore

		t.Run(storeName, func(t *testing.T) {
			runTest(t, "full SMT", makeFullTree, makeStore)
			runTest(t, "smol SMT", makeSmolTree, makeStore)
		})
	}

	// Write test vectors to file. This is a no-op if the "gen_test_vectors"
	// build tag is not set.
	test.WriteTestVectors(t, replacementTestVectorName, testVectors)
}

// TestHistoryIndependence tests that given the same set of keys, two trees
// that insert the keys in an arbitrary order get the same root hash in the
// end.
func TestHistoryIndependence(t *testing.T) {
	t.Parallel()

	for storeName, makeStore := range genTestStores(t) {
		makeStore := makeStore

		t.Run(storeName, func(t *testing.T) {
			t.Parallel()

			testHistoryIndependence(t, makeStore)
		})
	}
}

func testHistoryIndependence(t *testing.T, makeStore makeTestTreeStoreFunc) {
	// Create a tree and insert 100 random leaves in to the tree.
	leaves := randTree(100)

	// Create all empty trees.

	// First create the default SMT tree in the same order we created the
	// leaves.
	ctx := context.TODO()
	treeStore1, err := makeStore()
	require.NoError(t, err)
	tree1 := mssmt.NewFullTree(treeStore1)

	for _, item := range leaves {
		_, err := tree1.Insert(ctx, item.key, item.leaf)
		require.NoError(t, err)
	}

	// Next recreate the same tree but by changing the insertion order
	// to a random permutation of the original range.
	treeStore2, err := makeStore()
	require.NoError(t, err)
	tree2 := mssmt.NewFullTree(treeStore2)

	for i := range rand.Perm(len(leaves)) {
		_, err := tree2.Insert(ctx, leaves[i].key, leaves[i].leaf)
		require.NoError(t, err)
	}

	// Now create a compacted tree again with the original order.
	treeStore3, err := makeStore()
	require.NoError(t, err)
	smolTree1 := mssmt.NewCompactedTree(treeStore3)

	for i := range leaves {
		_, err := smolTree1.Insert(ctx, leaves[i].key, leaves[i].leaf)
		require.NoError(t, err)
	}

	// Finally create a compacted tree but by changing the insertion order
	// to a random permutation of the original range.
	treeStore4, err := makeStore()
	require.NoError(t, err)

	smolTree2 := mssmt.NewCompactedTree(treeStore4)
	for i := range rand.Perm(len(leaves)) {
		_, err := smolTree2.Insert(ctx, leaves[i].key, leaves[i].leaf)
		require.NoError(t, err)
	}

	// The root hash and sum of both full trees should be the same.
	tree1Root, err := tree1.Root(ctx)
	require.NoError(t, err)
	tree2Root, err := tree2.Root(ctx)
	require.NoError(t, err)

	require.Equal(t, tree1Root.NodeHash(), tree2Root.NodeHash())
	require.Equal(t, tree1Root.NodeSum(), tree2Root.NodeSum())

	// Similarly for the compacted trees.
	smol1Root, err := smolTree1.Root(ctx)
	require.NoError(t, err)
	smol2Root, err := smolTree2.Root(ctx)
	require.NoError(t, err)

	require.Equal(t, smol1Root.NodeHash(), smol2Root.NodeHash())
	require.Equal(t, smol1Root.NodeSum(), smol2Root.NodeSum())

	// Now check that the full tree has the same root as the compacted tree.
	// Due to transitivity this also means that all roots and sums are the
	// same.
	require.Equal(t, tree1Root.NodeHash(), smol1Root.NodeHash())
	require.Equal(t, tree1Root.NodeSum(), smol1Root.NodeSum())
}

// TestDeletion asserts that deleting all inserted leaves of a tree results in
// an empty tree.
func TestDeletion(t *testing.T) {
	t.Parallel()

	leaves := randTree(100)

	for storeName, makeStore := range genTestStores(t) {
		t.Run(storeName, func(t *testing.T) {
			t.Run("full SMT", func(t *testing.T) {
				t.Parallel()

				store, err := makeStore()
				require.NoError(t, err)

				testDeletion(t,
					leaves, mssmt.NewFullTree(store),
				)
				testBatchDeletion(t,
					leaves, mssmt.NewFullTree(store),
				)
			})

			t.Run("smol SMT", func(t *testing.T) {
				t.Parallel()

				store, err := makeStore()
				require.NoError(t, err)

				testDeletion(t,
					leaves, mssmt.NewCompactedTree(store),
				)
				testBatchDeletion(t,
					leaves, mssmt.NewCompactedTree(store),
				)
			})
		})
	}
}

func testDeletion(t *testing.T, leaves []treeLeaf, tree mssmt.Tree) {
	ctx := context.TODO()
	for _, item := range leaves {
		_, err := tree.Insert(ctx, item.key, item.leaf)
		require.NoError(t, err)
	}

	treeRoot, err := tree.Root(ctx)
	require.NoError(t, err)
	require.NotEqual(t, mssmt.EmptyTree[0], treeRoot)

	for _, item := range leaves {
		_, err := tree.Delete(ctx, item.key)
		require.NoError(t, err)

		emptyLeaf, err := tree.Get(ctx, item.key)
		require.NoError(t, err)

		require.True(t, emptyLeaf.IsEmpty())
	}

	treeRoot, err = tree.Root(ctx)
	require.NoError(t, err)

	require.True(t, mssmt.IsEqualNode(mssmt.EmptyTree[0], treeRoot))
}

func testBatchDeletion(t *testing.T, leaves []treeLeaf, tree mssmt.Tree) {
	ctx := context.TODO()
	for _, item := range leaves {
		_, err := tree.Insert(ctx, item.key, item.leaf)
		require.NoError(t, err)
	}

	treeRoot, err := tree.Root(ctx)
	require.NoError(t, err)
	require.NotEqual(t, mssmt.EmptyTree[0], treeRoot)

	err = tree.DeleteAllNodes(ctx)
	require.NoError(t, err)

	for _, item := range leaves {
		emptyLeaf, err := tree.Get(ctx, item.key)
		require.Nil(t, emptyLeaf)
		require.ErrorContains(t, err, "node not found")
	}

	err = tree.DeleteRoot(ctx)
	require.NoError(t, err)

	treeRoot, err = tree.Root(ctx)
	require.NoError(t, err)
	require.Equal(t, mssmt.EmptyTree[0], treeRoot)
}

func assertEqualProofAfterCompression(t *testing.T, proof *mssmt.Proof) {
	t.Helper()

	// Compressed proofs should never have empty nodes.
	compressedProof := proof.Compress()
	for _, node := range compressedProof.Nodes {
		for _, emptyNode := range mssmt.EmptyTree {
			require.False(t, mssmt.IsEqualNode(node, emptyNode))
		}
	}
	fullProof, err := compressedProof.Decompress()
	require.NoError(t, err)
	require.Equal(t, proof, fullProof)
}

func testMerkleProof(t *testing.T, tree mssmt.Tree, leaves []treeLeaf) {
	// Compute the proof for the first leaf and test some negative cases.
	ctx := context.TODO()
	for _, item := range leaves {
		proof, err := tree.MerkleProof(ctx, item.key)
		require.NoError(t, err)

		treeRoot, err := tree.Root(ctx)
		require.NoError(t, err)

		require.True(t,
			mssmt.VerifyMerkleProof(
				item.key, item.leaf, proof, treeRoot,
			),
		)

		// If we alter the proof's leaf sum, then the proof should no
		// longer be valid.
		alteredLeaf := mssmt.NewLeafNode(
			item.leaf.Value, item.leaf.NodeSum()+1,
		)
		treeRoot, err = tree.Root(ctx)
		require.NoError(t, err)
		require.False(t,
			mssmt.VerifyMerkleProof(
				item.key, alteredLeaf, proof, treeRoot,
			),
		)

		// If we delete the proof's leaf node from the tree, then it
		// should also no longer be valid.
		_, err = tree.Delete(ctx, item.key)
		require.NoError(t, err)

		treeRoot, err = tree.Root(ctx)
		require.NoError(t, err)

		require.False(t,
			mssmt.VerifyMerkleProof(
				item.key, item.leaf, proof, treeRoot,
			),
		)
	}

	// Create a new leaf that will not be inserted in the tree. Computing
	// its proof should result in a non-inclusion proof (an empty leaf
	// exists at said key).
	nonExistentKey := test.RandHash()
	nonExistentLeaf := randLeaf()

	proof, err := tree.MerkleProof(ctx, nonExistentKey)
	require.NoError(t, err)

	assertEqualProofAfterCompression(t, proof)

	treeRoot, err := tree.Root(ctx)
	require.NoError(t, err)

	require.False(t, mssmt.VerifyMerkleProof(
		nonExistentKey, nonExistentLeaf, proof, treeRoot,
	))

	require.True(t, mssmt.VerifyMerkleProof(
		nonExistentKey, mssmt.EmptyLeafNode, proof, treeRoot,
	))
}

func testProofEquality(t *testing.T, tree1, tree2 mssmt.Tree,
	leaves []treeLeaf) {

	assertEqualProof := func(proof1, proof2 *mssmt.Proof) {
		t.Helper()

		require.Equal(t, len(proof1.Nodes), len(proof2.Nodes))
		for i := range proof1.Nodes {
			require.Equal(t,
				proof1.Nodes[i].NodeHash(),
				proof2.Nodes[i].NodeHash(),
			)
			require.Equal(t,
				proof1.Nodes[i].NodeSum(),
				proof2.Nodes[i].NodeSum(),
			)
		}
	}

	ctx := context.TODO()
	for _, item := range leaves {
		proof1, err := tree1.MerkleProof(ctx, item.key)
		require.NoError(t, err)

		proof2, err := tree2.MerkleProof(ctx, item.key)
		require.NoError(t, err)

		treeRoot1, err := tree1.Root(ctx)
		require.NoError(t, err)

		treeRoot2, err := tree2.Root(ctx)
		require.NoError(t, err)

		require.True(t,
			mssmt.VerifyMerkleProof(
				item.key, item.leaf, proof1, treeRoot1,
			),
		)
		require.True(t,
			mssmt.VerifyMerkleProof(
				item.key, item.leaf, proof2, treeRoot2,
			),
		)

		assertEqualProof(proof1, proof2)

		assertEqualProofAfterCompression(t, proof1)
		assertEqualProofAfterCompression(t, proof2)
	}
}

// TestMerkleProof asserts that merkle proofs (inclusion and non-inclusion) for
// leaf nodes are constructed, compressed, decompressed, and verified properly.
func TestMerkleProof(t *testing.T) {
	t.Parallel()

	for storeName, makeStore := range genTestStores(t) {
		t.Run(storeName, func(t *testing.T) {
			store1, err := makeStore()
			require.NoError(t, err)
			tree := mssmt.NewFullTree(store1)

			store2, err := makeStore()
			require.NoError(t, err)
			smolTree := mssmt.NewCompactedTree(store2)

			leaves := randTree(100)
			ctx := context.TODO()
			for _, item := range leaves {
				_, err := tree.Insert(ctx, item.key, item.leaf)
				require.NoError(t, err)
				_, err = smolTree.Insert(
					ctx, item.key, item.leaf,
				)
				require.NoError(t, err)
			}

			t.Run("proof equality", func(t *testing.T) {
				testProofEquality(t, tree, smolTree, leaves)
			})

			t.Run("full SMT proof properties", func(t *testing.T) {
				testMerkleProof(t, tree, leaves)
			})

			t.Run("smol SMT proof properties", func(t *testing.T) {
				testMerkleProof(t, smolTree, leaves)
			})
		})
	}
}

// TestBIPTestVectors tests that the BIP test vectors are passing.
func TestBIPTestVectors(t *testing.T) {
	t.Parallel()

	for idx := range allTestVectorFiles {
		var (
			fileName    = allTestVectorFiles[idx]
			testVectors = &mssmt.TestVectors{}
		)
		test.ParseTestVectors(t, fileName, &testVectors)
		t.Run(fileName, func(tt *testing.T) {
			tt.Parallel()

			runBIPTestVector(tt, testVectors)
		})
	}
}

// TestTreeCopy tests the Copy method for both FullTree and CompactedTree,
// including copying between different tree types.
func TestTreeCopy(t *testing.T) {
	t.Parallel()

	leaves := randTree(50) // Use a smaller number for faster testing

	// Prepare source trees (Full and Compacted)
	ctx := context.Background()
	sourceFullStore := mssmt.NewDefaultStore()
	sourceFullTree := mssmt.NewFullTree(sourceFullStore)
	sourceCompactedStore := mssmt.NewDefaultStore()
	sourceCompactedTree := mssmt.NewCompactedTree(sourceCompactedStore)

	for _, item := range leaves {
		_, err := sourceFullTree.Insert(ctx, item.key, item.leaf)
		require.NoError(t, err)
		_, err = sourceCompactedTree.Insert(ctx, item.key, item.leaf)
		require.NoError(t, err)
	}

	sourceFullRoot, err := sourceFullTree.Root(ctx)
	require.NoError(t, err)
	sourceCompactedRoot, err := sourceCompactedTree.Root(ctx)
	require.NoError(t, err)
	require.True(t, mssmt.IsEqualNode(sourceFullRoot, sourceCompactedRoot))

	// Define some leaves to pre-populate the target tree.
	initialTargetLeaves := []treeLeaf{
		{key: test.RandHash(), leaf: randLeaf()},
		{key: test.RandHash(), leaf: randLeaf()},
	}
	initialTargetLeavesMap := make(map[[hashSize]byte]*mssmt.LeafNode)
	for _, item := range initialTargetLeaves {
		initialTargetLeavesMap[item.key] = item.leaf
	}

	// Define test cases
	testCases := []struct {
		name       string
		sourceTree mssmt.Tree
		makeTarget func() mssmt.Tree
	}{
		{
			name:       "Full -> Full",
			sourceTree: sourceFullTree,
			makeTarget: func() mssmt.Tree {
				return mssmt.NewFullTree(
					mssmt.NewDefaultStore(),
				)
			},
		},
		{
			name:       "Full -> Compacted",
			sourceTree: sourceFullTree,
			makeTarget: func() mssmt.Tree {
				return mssmt.NewCompactedTree(
					mssmt.NewDefaultStore(),
				)
			},
		},
		{
			name:       "Compacted -> Full",
			sourceTree: sourceCompactedTree,
			makeTarget: func() mssmt.Tree {
				return mssmt.NewFullTree(
					mssmt.NewDefaultStore(),
				)
			},
		},
		{
			name:       "Compacted -> Compacted",
			sourceTree: sourceCompactedTree,
			makeTarget: func() mssmt.Tree {
				return mssmt.NewCompactedTree(
					mssmt.NewDefaultStore(),
				)
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			targetTree := tc.makeTarget()

			// Pre-populate the target tree.
			_, err := targetTree.InsertMany(
				ctx, initialTargetLeavesMap,
			)
			require.NoError(t, err)

			// Calculate the expected root after combining initial
			// and source leaves.
			expectedStateStore := mssmt.NewDefaultStore()
			expectedStateTree := mssmt.NewFullTree(
				expectedStateStore,
			)
			_, err = expectedStateTree.InsertMany(
				ctx, initialTargetLeavesMap,
			)
			require.NoError(t, err)
			sourceLeavesMap := make(
				map[[hashSize]byte]*mssmt.LeafNode,
			)
			for _, item := range leaves {
				sourceLeavesMap[item.key] = item.leaf
			}
			_, err = expectedStateTree.InsertMany(
				ctx, sourceLeavesMap,
			)
			require.NoError(t, err)
			expectedRoot, err := expectedStateTree.Root(ctx)
			require.NoError(t, err)

			// Actually perform the copy.
			err = tc.sourceTree.Copy(ctx, targetTree)
			require.NoError(t, err)

			// Verify the target tree root matches the expected
			// combined root.
			targetRoot, err := targetTree.Root(ctx)
			require.NoError(t, err)
			require.True(t,
				mssmt.IsEqualNode(expectedRoot, targetRoot),
				"root mismatch after copy to non-empty target",
			)

			// Verify individual leaves (both initial and copied) in
			// the target tree
			allExpectedLeaves := append([]treeLeaf{}, leaves...)
			allExpectedLeaves = append(
				allExpectedLeaves, initialTargetLeaves...,
			)
			for _, item := range allExpectedLeaves {
				targetLeaf, err := targetTree.Get(ctx, item.key)
				require.NoError(t, err)
				require.Equal(t, item.leaf, targetLeaf,
					"leaf mismatch for key %x", item.key)
			}

			// Verify a non-existent key is still empty
			emptyLeaf, err := targetTree.Get(ctx, test.RandHash())
			require.NoError(t, err)
			require.True(
				t, emptyLeaf.IsEmpty(),
				"non-existent key found",
			)
		})
	}
}

// TestInsertMany tests inserting multiple leaves using the InsertMany method.
func TestInsertMany(t *testing.T) {
	t.Parallel()

	leavesToInsert := randTree(50)
	leavesMap := make(map[[hashSize]byte]*mssmt.LeafNode)
	for _, item := range leavesToInsert {
		leavesMap[item.key] = item.leaf
	}

	// Calculate expected root after individual insertions for comparison.
	tempStore := mssmt.NewDefaultStore()
	tempTree := mssmt.NewFullTree(tempStore)
	ctx := context.Background()
	for key, leaf := range leavesMap {
		_, err := tempTree.Insert(ctx, key, leaf)
		require.NoError(t, err)
	}
	expectedRoot, err := tempTree.Root(ctx)
	require.NoError(t, err)

	runTest := func(t *testing.T, name string,
		makeTree func(mssmt.TreeStore) mssmt.Tree,
		makeStore makeTestTreeStoreFunc) {

		t.Run(name, func(t *testing.T) {
			store, err := makeStore()
			require.NoError(t, err)
			tree := makeTree(store)

			// Test inserting an empty map (should be a no-op).
			_, err = tree.InsertMany(
				ctx, make(map[[hashSize]byte]*mssmt.LeafNode),
			)
			require.NoError(t, err)
			initialRoot, err := tree.Root(ctx)
			require.NoError(t, err)
			require.True(
				t,
				mssmt.IsEqualNode(
					mssmt.EmptyTree[0], initialRoot,
				),
			)

			// Insert the leaves using InsertMany.
			_, err = tree.InsertMany(ctx, leavesMap)
			require.NoError(t, err)

			// Verify the root.
			finalRoot, err := tree.Root(ctx)
			require.NoError(t, err)
			require.True(
				t, mssmt.IsEqualNode(expectedRoot, finalRoot),
			)

			// Verify each leaf can be retrieved.
			for key, expectedLeaf := range leavesMap {
				retrievedLeaf, err := tree.Get(ctx, key)
				require.NoError(t, err)
				require.Equal(t, expectedLeaf, retrievedLeaf)
			}
		})
	}

	for storeName, makeStore := range genTestStores(t) {
		t.Run(storeName, func(t *testing.T) {
			runTest(t, "full SMT", makeFullTree, makeStore)
			runTest(t, "smol SMT", makeSmolTree, makeStore)
		})
	}
}

// runBIPTestVector runs the tests in a single BIP test vector file.
func runBIPTestVector(t *testing.T, testVectors *mssmt.TestVectors) {
	for _, validCase := range testVectors.ValidTestCases {
		validCase := validCase

		t.Run(validCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			ctx := context.Background()
			fullTree := mssmt.NewFullTree(mssmt.NewDefaultStore())
			smolTree := mssmt.NewCompactedTree(
				mssmt.NewDefaultStore(),
			)

			// Insert all leaves declared in the test vector into
			// both sets of trees.
			for idx := range testVectors.AllTreeLeaves {
				leaf := testVectors.AllTreeLeaves[idx]
				leafKey := test.Parse32Byte(t, leaf.Key)
				leafNode := leaf.ToLeafNode(t)

				if !validCase.ShouldInsert(leaf.Key) {
					continue
				}

				_, err := fullTree.Insert(
					ctx, leafKey, leafNode,
				)
				require.NoError(tt, err)

				_, err = smolTree.Insert(ctx, leafKey, leafNode)
				require.NoError(tt, err)
			}

			// Now delete all leaves declared in the test vector.
			for idx := range validCase.DeletedLeaves {
				keyHex := validCase.DeletedLeaves[idx]
				key := test.Parse32Byte(t, keyHex)

				if !validCase.ShouldDelete(keyHex) {
					continue
				}

				_, err := fullTree.Delete(ctx, key)
				require.NoError(tt, err)

				_, err = smolTree.Delete(ctx, key)
				require.NoError(tt, err)
			}

			// And finally replace all leaves declared in the test
			// vector.
			for idx := range validCase.ReplacedLeaves {
				leaf := validCase.ReplacedLeaves[idx]
				leafKey := test.Parse32Byte(t, leaf.Key)
				leafNode := leaf.ToLeafNode(t)

				_, err := fullTree.Insert(
					ctx, leafKey, leafNode,
				)
				require.NoError(tt, err)

				_, err = smolTree.Insert(ctx, leafKey, leafNode)
				require.NoError(tt, err)
			}

			// Verify the expected root hash and sum.
			expectedHash := fn.ToArray[mssmt.NodeHash](
				test.ParseHex(t, validCase.RootHash),
			)
			expectedSum, err := strconv.ParseUint(
				validCase.RootSum, 10, 64,
			)
			require.NoError(tt, err)

			fullTreeRoot, err := fullTree.Root(ctx)
			require.NoError(tt, err)
			smolTreeRoot, err := smolTree.Root(ctx)
			require.NoError(tt, err)

			require.Equal(tt, expectedHash, fullTreeRoot.NodeHash())
			require.Equal(tt, expectedHash, smolTreeRoot.NodeHash())

			require.Equal(tt, expectedSum, fullTreeRoot.NodeSum())
			require.Equal(tt, expectedSum, smolTreeRoot.NodeSum())

			// Verify all inclusion proofs.
			for idx := range validCase.InclusionProofs {
				inclusion := validCase.InclusionProofs[idx]

				key := test.Parse32Byte(
					t, inclusion.ProofKey,
				)
				proof := inclusion.ToProof(t)
				leaf := testVectors.FindLeaf(inclusion.ProofKey)
				require.NotNil(tt, leaf)

				require.True(t, mssmt.VerifyMerkleProof(
					key, leaf.ToLeafNode(t), proof,
					fullTreeRoot,
				))
				require.True(t, mssmt.VerifyMerkleProof(
					key, leaf.ToLeafNode(t), proof,
					smolTreeRoot,
				))
			}

			// Verify all exclusion proofs.
			for idx := range validCase.ExclusionProofs {
				exclusion := validCase.ExclusionProofs[idx]

				key := test.Parse32Byte(
					t, exclusion.ProofKey,
				)
				proof := exclusion.ToProof(t)

				require.True(t, mssmt.VerifyMerkleProof(
					key, mssmt.EmptyLeafNode, proof,
					fullTreeRoot,
				))
				require.True(t, mssmt.VerifyMerkleProof(
					key, mssmt.EmptyLeafNode, proof,
					smolTreeRoot,
				))
			}
		})
	}

	for _, invalidCase := range testVectors.ErrorTestCases {
		invalidCase := invalidCase

		t.Run(invalidCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			ctx := context.Background()
			fullTree := mssmt.NewFullTree(mssmt.NewDefaultStore())
			smolTree := mssmt.NewCompactedTree(
				mssmt.NewDefaultStore(),
			)

			for idx := range testVectors.AllTreeLeaves {
				leaf := testVectors.AllTreeLeaves[idx]
				leafKey := test.Parse32Byte(t, leaf.Key)
				leafNode := leaf.ToLeafNode(t)

				if !invalidCase.ShouldInsert(leaf.Key) {
					continue
				}

				lastIdx := len(testVectors.AllTreeLeaves) - 1
				checkErr := func(err error) {
					if idx == lastIdx {
						require.ErrorContains(
							tt, err,
							invalidCase.Error,
						)
					} else {
						require.NoError(tt, err)
					}
				}

				_, err := fullTree.Insert(
					ctx, leafKey, leafNode,
				)
				checkErr(err)

				_, err = smolTree.Insert(
					ctx, leafKey, leafNode,
				)
				checkErr(err)
			}
		})
	}
}
