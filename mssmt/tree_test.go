package mssmt

import (
	"math"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randKey() [hashSize]byte {
	var key [hashSize]byte
	_, _ = rand.Read(key[:])
	return key
}

func randLeaf() *LeafNode {
	valueLen := rand.Intn(math.MaxUint8) + 1
	value := make([]byte, valueLen)
	_, _ = rand.Read(value[:])
	sum := rand.Uint64()
	return NewLeafNode(value, sum)
}

type treeLeaf struct {
	key  [hashSize]byte
	leaf *LeafNode
}

func randTree(numLeaves int) []treeLeaf {
	leaves := make([]treeLeaf, numLeaves)
	for i := 0; i < numLeaves; i++ {
		leaves[i] = treeLeaf{
			key:  randKey(),
			leaf: randLeaf(),
		}
	}
	return leaves
}

func genTreeFromRange(numLeaves int) []treeLeaf {
	leaves := make([]treeLeaf, numLeaves)
	for i := 0; i < numLeaves; i++ {
		var key [32]byte
		big.NewInt(int64(i)).FillBytes(key[:])

		leaves[i] = treeLeaf{
			key:  key,
			leaf: randLeaf(),
		}
	}

	return leaves
}

// TestInsertion asserts that we can insert N leaves and retrieve them by their
// insertion key. Keys that do not exist within the tree should return an empty
// leaf.
func testInsertion(t *testing.T, leaves []treeLeaf, tree Tree) {
	for _, item := range leaves {
		tree.Insert(item.key, item.leaf)
	}

	for _, item := range leaves {
		// The leaf was already inserted into the tree above, so verify
		// that we're able to look it up again.
		leafCopy := tree.Get(item.key)
		require.Equal(t, item.leaf, leafCopy)
	}

	// Finally veryify that we're able to loop up a random key (resulting
	// in the default empty leaf).
	emptyLeaf := tree.Get(randKey())
	require.True(t, emptyLeaf.IsEmpty())
}

func TestInsertion(t *testing.T) {
	leaves := randTree(10000)

	t.Run("full SMT", func(t *testing.T) {
		store := NewDefaultStore()
		tree := NewFullTree(store)

		testInsertion(t, leaves, tree)

	})

	t.Run("smol SMT", func(t *testing.T) {
		store := NewDefaultStore()
		smolTree := NewCompactedTree(store)

		testInsertion(t, leaves, smolTree)
		require.Equal(t, len(leaves), len(store.compactedLeaves))
	})
}

// TestReplace tests that replacing keys works as expected.
func TestReplace(t *testing.T) {
	const numLeaves = 1000

	leaves1 := genTreeFromRange(numLeaves)
	leaves2 := genTreeFromRange(numLeaves)

	testUpdate := func(tree Tree) {
		for _, item := range leaves1 {
			tree.Insert(item.key, item.leaf)
		}

		for _, item := range leaves1 {
			leafCopy := tree.Get(item.key)
			require.Equal(t, item.leaf, leafCopy)
		}

		for _, item := range leaves2 {
			tree.Insert(item.key, item.leaf)
		}

		for _, item := range leaves2 {
			leafCopy := tree.Get(item.key)
			require.Equal(t, item.leaf, leafCopy)
		}
	}

	t.Run("full SMT", func(t *testing.T) {
		store := NewDefaultStore()
		tree := NewFullTree(store)
		testUpdate(tree)
	})

	t.Run("smol SMT", func(t *testing.T) {
		store := NewDefaultStore()
		smolTree := NewCompactedTree(store)
		testUpdate(smolTree)
	})
}

// TestHistoryIndependence tests that given the same set of keys, two trees
// that insert the keys in an arbitrary order get the same root hash in the
// end.
func TestHistoryIndependence(t *testing.T) {
	// Create a tree and insert 100 random leaves in to the tree.
	leaves := randTree(100)

	// Create all empty trees.

	// First create the default SMT tree in the same order we created the
	// leaves.
	tree1 := NewFullTree(NewDefaultStore())
	for _, item := range leaves {
		tree1.Insert(item.key, item.leaf)
	}

	// Next recreate the same tree but by changing the insertion order
	// to a random permutation of the original range.
	tree2 := NewFullTree(NewDefaultStore())
	for i := range rand.Perm(len(leaves)) {
		tree2.Insert(leaves[i].key, leaves[i].leaf)
	}

	// Now create a compacted tree again with the original order.
	smolTree1 := NewCompactedTree(NewDefaultStore())
	for i := range leaves {
		smolTree1.Insert(leaves[i].key, leaves[i].leaf)
	}

	// Finally create a compacted tree but by changing the insertion order
	// to a random permutation of the original range.
	smolTree2 := NewCompactedTree(NewDefaultStore())
	for i := range rand.Perm(len(leaves)) {
		smolTree2.Insert(leaves[i].key, leaves[i].leaf)
	}

	// The root hash and sum of both full trees should be the same.
	require.Equal(t, tree1.Root().NodeKey(), tree2.Root().NodeKey())
	require.Equal(t, tree1.Root().NodeSum(), tree2.Root().NodeSum())

	// Similarly for the compacted trees.
	require.Equal(t, smolTree1.Root().NodeKey(), smolTree2.Root().NodeKey())
	require.Equal(t, smolTree1.Root().NodeSum(), smolTree2.Root().NodeSum())

	// Now check that the full tree has the same root as the compacted tree.
	// Due to transitivity this also means that all roots and sums are the
	// same.
	require.Equal(t, tree1.Root().NodeKey(), smolTree1.Root().NodeKey())
	require.Equal(t, tree1.Root().NodeSum(), smolTree1.Root().NodeSum())
}

// TestDeletion asserts that deleting all inserted leaves of a tree results in
// an empty tree.
func TestDeletion(t *testing.T) {
	leaves := randTree(10000)
	t.Run("full SMT", func(t *testing.T) {
		testDeletion(t, leaves, NewFullTree(NewDefaultStore()))
	})

	t.Run("smol SMT", func(t *testing.T) {
		testDeletion(t, leaves, NewCompactedTree(NewDefaultStore()))
	})
}

func testDeletion(t *testing.T, leaves []treeLeaf, tree Tree) {
	for _, item := range leaves {
		tree.Insert(item.key, item.leaf)
	}

	require.NotEqual(t, EmptyTree[0], tree.Root())
	for _, item := range leaves {
		_ = tree.Delete(item.key)
		emptyLeaf := tree.Get(item.key)
		require.True(t, emptyLeaf.IsEmpty())
	}
	require.Equal(t, EmptyTree[0], tree.Root())
}

func assertEqualProofAfterCompression(t *testing.T, proof *Proof) {
	t.Helper()

	// Compressed proofs should never have empty nodes.
	compressedProof := proof.Compress()
	for _, node := range compressedProof.Nodes {
		for _, emptyNode := range EmptyTree {
			require.False(t, IsEqualNode(node, emptyNode))
		}
	}
	require.Equal(t, proof, compressedProof.Decompress())
}

func testMerkleProof(t *testing.T, tree Tree, leaves []treeLeaf) {
	// Compute the proof for the first leaf and test some negative cases.
	for _, item := range leaves {
		proof := tree.MerkleProof(item.key)

		require.True(t,
			VerifyMerkleProof(
				item.key, item.leaf, proof, tree.Root()),
		)

		// If we alter the proof's leaf sum, then the proof should no
		// longer be valid.
		item.leaf.sum++
		require.False(t,
			VerifyMerkleProof(
				item.key, item.leaf, proof, tree.Root()),
		)
		item.leaf.sum--

		// If we delete the proof's leaf node from the tree, then it
		// should also no longer be valid.
		_ = tree.Delete(item.key)
		require.False(t,
			VerifyMerkleProof(
				item.key, item.leaf, proof, tree.Root()),
		)
	}

	// Create a new leaf that will not be inserted in the tree. Computing
	// its proof should result in a non-inclusion proof (an empty leaf
	// exists at said key).
	nonExistentKey := randKey()
	nonExistentLeaf := randLeaf()

	proof := tree.MerkleProof(nonExistentKey)

	assertEqualProofAfterCompression(t, proof)

	require.False(t, VerifyMerkleProof(
		nonExistentKey, nonExistentLeaf, proof, tree.Root(),
	))

	require.True(t, VerifyMerkleProof(
		nonExistentKey, EmptyLeafNode, proof, tree.Root(),
	))
}

func testProofEquality(t *testing.T, tree1, tree2 Tree, leaves []treeLeaf) {
	assertEqualProof := func(proof1, proof2 *Proof) {
		t.Helper()

		require.Equal(t, len(proof1.Nodes), len(proof2.Nodes))
		for i := range proof1.Nodes {
			require.Equal(t,
				proof1.Nodes[i].NodeKey(),
				proof2.Nodes[i].NodeKey(),
			)
			require.Equal(t,
				proof1.Nodes[i].NodeSum(),
				proof2.Nodes[i].NodeSum(),
			)
		}
	}

	for _, item := range leaves {
		proof1 := tree1.MerkleProof(item.key)
		proof2 := tree2.MerkleProof(item.key)

		require.True(t,
			VerifyMerkleProof(
				item.key, item.leaf, proof1, tree1.Root(),
			),
		)
		require.True(t,
			VerifyMerkleProof(
				item.key, item.leaf, proof2, tree2.Root(),
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
	tree := NewFullTree(NewDefaultStore())
	smolTree := NewCompactedTree(NewDefaultStore())

	leaves := randTree(1337)
	for _, item := range leaves {
		tree.Insert(item.key, item.leaf)
		smolTree.Insert(item.key, item.leaf)
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
}
