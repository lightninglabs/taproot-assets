//go:build !race
// +build !race

package mssmt_test

import (
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"

	"github.com/lightninglabs/taro/mssmt"
	_ "github.com/lightninglabs/taro/tarodb"
	"github.com/stretchr/testify/require"
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
						"store: %v", err)
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
	switch s := store.(type) {
	case *mssmt.DefaultStore:
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

// TestInsertion asserts that we can insert N leaves and retrieve them by their
// insertion key. Keys that do not exist within the tree should return an empty
// leaf.
func testInsertion(t *testing.T, leaves []treeLeaf, tree mssmt.Tree) {
	ctx := context.TODO()
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

	// Finally veryify that we're able to loop up a random key (resulting
	// in the default empty leaf).
	emptyLeaf, err := tree.Get(ctx, randKey())
	require.NoError(t, err)
	require.True(t, emptyLeaf.IsEmpty())
}

func TestInsertion(t *testing.T) {
	t.Parallel()

	leaves := randTree(100)

	runTest := func(t *testing.T, name string, makeTree func(mssmt.TreeStore) mssmt.Tree,
		makeStore makeTestTreeStoreFunc) {

		t.Run(name, func(t *testing.T) {
			store, err := makeStore()
			require.NoError(t, err)

			tree := makeTree(store)

			testInsertion(t, leaves, tree)
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

// TestReplaceWithEmptyBranch tests that a compacted tree won't add default
// branches when whole subtrees are deleted.
func TestReplaceWithEmptyBranch(t *testing.T) {
	t.Parallel()

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
		_, err := tree.Insert(ctx, key, randLeaf())
		require.NoError(t, err)
	}

	// Make sure the store has all our leaves and branches.
	require.Equal(t, 2, store.NumBranches())
	require.Equal(t, 0, store.NumLeaves())
	require.Equal(t, 3, store.NumCompactedLeaves())

	// Now delete compacted leafs 2 and 4 which would
	// trigger inserting a default branch in place of
	// their parent B.
	_, err := tree.Delete(ctx, keys[1])
	require.NoError(t, err)
	_, err = tree.Delete(ctx, keys[2])
	require.NoError(t, err)

	// We expect that the store only has one compacted leaf and one branch.
	require.Equal(t, 1, store.NumBranches())
	require.Equal(t, 0, store.NumLeaves())
	require.Equal(t, 1, store.NumCompactedLeaves())
}

// TestReplace tests that replacing keys works as expected.
func TestReplace(t *testing.T) {
	t.Parallel()

	const numLeaves = 100

	leaves1 := genTreeFromRange(numLeaves)
	leaves2 := genTreeFromRange(numLeaves)

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
		t.Run(storeName, func(t *testing.T) {
			t.Parallel()

			runTest(t, "full SMT", makeFullTree, makeStore)
			runTest(t, "smol SMT", makeSmolTree, makeStore)
		})
	}
}

// TestHistoryIndependence tests that given the same set of keys, two trees
// that insert the keys in an arbitrary order get the same root hash in the
// end.
func TestHistoryIndependence(t *testing.T) {
	t.Parallel()

	for storeName, makeStore := range genTestStores(t) {
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
			})

			t.Run("smol SMT", func(t *testing.T) {
				t.Parallel()

				store, err := makeStore()
				require.NoError(t, err)

				testDeletion(t,
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
	nonExistentKey := randKey()
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

func testProofEqulity(t *testing.T, tree1, tree2 mssmt.Tree, leaves []treeLeaf) {
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
				testProofEqulity(t, tree, smolTree, leaves)
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
