package mssmt

import (
	"math"
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

func randTree(numLeaves int) (*Tree, map[[hashSize]byte]*LeafNode) {
	tree := NewTree(NewDefaultStore())
	leaves := make(map[[hashSize]byte]*LeafNode, numLeaves)
	for i := 0; i < numLeaves; i++ {
		key := randKey()
		leaf := randLeaf()
		tree.Insert(key, leaf)
		leaves[key] = leaf
	}
	return tree, leaves
}

// TestInsertion asserts that we can insert N leaves and retrieve them by their
// insertion key. Keys that do not exist within the tree should return an empty
// leaf.
func TestInsertion(t *testing.T) {
	t.Parallel()

	tree, leaves := randTree(10000)
	for key, leaf := range leaves {
		// The leaf was already inserted into the tree above, so verify
		// that we're able to look it up again.
		leafCopy := tree.Get(key)
		require.Equal(t, leaf, leafCopy)
	}

	emptyLeaf := tree.Get(randKey())
	require.True(t, emptyLeaf.IsEmpty())
}

// TestDeletion asserts that deleting all inserted leaves of a tree results in
// an empty tree.
func TestDeletion(t *testing.T) {
	t.Parallel()

	tree, leaves := randTree(10000)
	require.NotEqual(t, EmptyTree[0], tree.Root())
	for key := range leaves {
		_ = tree.Delete(key)
		emptyLeaf := tree.Get(key)
		require.True(t, emptyLeaf.IsEmpty())
	}
	require.Equal(t, EmptyTree[0], tree.Root())
}

// TestMerkleProof asserts that merkle proofs (inclusion and non-inclusion) for
// leaf nodes are constructed, compressed, decompressed, and verified properly.
func TestMerkleProof(t *testing.T) {
	t.Parallel()

	assertEqualAfterCompression := func(proof *Proof) {
		t.Helper()

		// Compressed proofs should never have empty nodes.
		compressedProof := proof.Compress()
		for _, node := range compressedProof.Nodes {
			for _, emptyNode := range EmptyTree {
				require.NotEqual(
					t, node.NodeKey(), emptyNode.NodeKey(),
				)
			}
		}
		require.Equal(t, proof, compressedProof.Decompress())
	}

	// Create a random tree and verify each leaf's merkle proof.
	tree, leaves := randTree(1337)
	for key, leaf := range leaves {
		proof := tree.MerkleProof(key)
		assertEqualAfterCompression(proof)
		require.True(t, leaf.Equal(&proof.Leaf))
		require.True(t, VerifyMerkleProof(key, proof, tree.Root()))
	}

	// Compute the proof for the first leaf and test some negative cases.
	for key := range leaves {
		proof := tree.MerkleProof(key)
		require.True(t, VerifyMerkleProof(key, proof, tree.Root()))

		// If we alter the proof's leaf sum, then the proof should no
		// longer be valid.
		proof.Leaf.sum++
		require.False(t, VerifyMerkleProof(key, proof, tree.Root()))
		proof.Leaf.sum--

		// If we delete the proof's leaf node from the tree, then it
		// should also no longer be valid.
		_ = tree.Delete(key)
		require.False(t, VerifyMerkleProof(key, proof, tree.Root()))
	}

	// Create a new leaf that will not be inserted in the tree. Computing
	// its proof should result in a non-inclusion proof (an empty leaf
	// exists at said key).
	nonExistentKey := randKey()
	nonExistentLeaf := randLeaf()
	proof := tree.MerkleProof(nonExistentKey)
	assertEqualAfterCompression(proof)
	require.False(t, proof.ProvesInclusion())
	invalidProof := NewProof(*nonExistentLeaf, proof.Nodes)
	require.False(t, VerifyMerkleProof(
		nonExistentKey, invalidProof, tree.Root()),
	)
	require.True(t, VerifyMerkleProof(nonExistentKey, proof, tree.Root()))
}
