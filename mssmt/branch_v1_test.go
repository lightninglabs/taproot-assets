package mssmt

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// branchV1Preimage returns the BranchV1 preimage of a branch with children of
// the given hashes and sums.
func branchV1Preimage(leftHash NodeHash, leftSum uint64, rightHash NodeHash,
	rightSum uint64) []byte {

	preimage := append([]byte(nil), leftHash[:]...)
	preimage = binary.BigEndian.AppendUint64(preimage, leftSum)
	preimage = append(preimage, rightHash[:]...)

	return binary.BigEndian.AppendUint64(preimage, rightSum)
}

// TestBranchV1Hash tests the hash of BranchV1 branches.
func TestBranchV1Hash(t *testing.T) {
	t.Parallel()

	// A branch with non-empty children hashes the hash and the sum of
	// each child.
	left := NewLeafNode([]byte("left"), 3)
	right := NewLeafNode([]byte("right"), 5)
	branch := newBranch(BranchV1, left, right)
	require.Equal(
		t, NodeHash(sha256.Sum256(branchV1Preimage(
			left.NodeHash(), 3, right.NodeHash(), 5,
		))), branch.NodeHash(),
	)
	require.EqualValues(t, 8, branch.NodeSum())

	// A branch whose children are both the empty subtree of one height is
	// the empty subtree of the height above.
	for height := 1; height <= MaxTreeLevels; height++ {
		empty := newBranch(
			BranchV1, EmptyTree[height], EmptyTree[height],
		)
		require.Equal(
			t, EmptyTree[height-1].NodeHash(), empty.NodeHash(),
		)
		require.Zero(t, empty.NodeSum())
	}

	// A child with the hash of an empty subtree and a non-zero sum is
	// hashed with its sum.
	emptyHash := EmptyTree[10].NodeHash()
	branch = newBranch(
		BranchV1, NewComputedNode(emptyHash, 1), EmptyTree[10],
	)
	require.Equal(
		t, NodeHash(sha256.Sum256(branchV1Preimage(
			emptyHash, 1, emptyHash, 0,
		))), branch.NodeHash(),
	)

	// A branch whose children are both the root of the empty tree is
	// hashed with their sums.
	rootHash := EmptyTree[0].NodeHash()
	branch = newBranch(BranchV1, EmptyTree[0], EmptyTree[0])
	require.Equal(
		t, NodeHash(sha256.Sum256(branchV1Preimage(
			rootHash, 0, rootHash, 0,
		))), branch.NodeHash(),
	)
}

// genEmptyableProof draws a Proof whose siblings are each either the empty
// subtree of their height or a random node. The siblings below a drawn
// height are all empty subtrees.
func genEmptyableProof(t *rapid.T) *Proof {
	numEmpty := rapid.IntRange(0, MaxTreeLevels).Draw(t, "num_empty")

	nodes := make([]Node, MaxTreeLevels)
	for i := 0; i < MaxTreeLevels; i++ {
		empty := i < numEmpty ||
			rapid.Bool().Draw(t, "empty_sibling")
		if empty {
			nodes[i] = EmptyTree[MaxTreeLevels-i]
			continue
		}

		nodes[i] = genSibling(t)
	}

	return NewProof(nodes)
}

// TestVersionedRootSumEquivalence tests that rootSum and VersionedRoot agree
// for both branch versions, for proofs of empty and non-empty leaves with
// empty and non-empty siblings.
func TestVersionedRootSumEquivalence(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		key := genKey(t)
		leaf := EmptyLeafNode
		if rapid.Bool().Draw(t, "non_empty_leaf") {
			leaf = genLeaf(t)
		}
		proof := genEmptyableProof(t)

		for _, version := range []BranchVersion{BranchV0, BranchV1} {
			root, err := proof.VersionedRoot(version, *key, leaf)
			require.NoError(t, err)

			hash, sum, validSum := proof.rootSum(version, key, leaf)
			require.True(t, validSum)

			require.Equal(t, root.NodeHash(), hash)
			require.Equal(t, root.NodeSum(), sum)
		}
	})
}
