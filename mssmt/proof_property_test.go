package mssmt

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// genKey draws a random 32-byte MS-SMT key.
func genKey(t *rapid.T) *[hashSize]byte {
	var k [hashSize]byte
	bs := rapid.SliceOfN(rapid.Byte(), hashSize, hashSize).Draw(t, "key")
	copy(k[:], bs)
	return &k
}

// genLeaf draws a random LeafNode. The sum is drawn from a range that
// keeps cumulative sums below uint64 overflow under the property tests
// that walk a 256-level proof.
func genLeaf(t *rapid.T) *LeafNode {
	valLen := rapid.IntRange(1, 64).Draw(t, "leaf_value_len")
	val := rapid.SliceOfN(rapid.Byte(), valLen, valLen).Draw(
		t, "leaf_value",
	)
	sum := rapid.Uint64Range(0, 1<<32).Draw(t, "leaf_sum")
	return NewLeafNode(val, sum)
}

// genSibling draws a random sibling node as a ComputedNode (the shape
// the proof path actually sees once siblings are loaded).
func genSibling(t *rapid.T) Node {
	var h NodeHash
	bs := rapid.SliceOfN(rapid.Byte(), hashSize, hashSize).Draw(
		t, "sibling_hash",
	)
	copy(h[:], bs)
	sum := rapid.Uint64Range(0, 1<<32).Draw(t, "sibling_sum")
	return NewComputedNode(h, sum)
}

// genProof draws a random Proof with MaxTreeLevels siblings.
func genProof(t *rapid.T) *Proof {
	nodes := make([]Node, MaxTreeLevels)
	for i := 0; i < MaxTreeLevels; i++ {
		nodes[i] = genSibling(t)
	}
	return NewProof(nodes)
}

// TestRootSumEquivalence is the load-bearing property: for any
// well-formed (key, leaf, proof) tuple, the alloc-free rootSum helper
// must produce the same (hash, sum) as the existing walkUp-then-NodeHash
// path. If this ever fails, the optimization is unsound.
func TestRootSumEquivalence(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		key := genKey(t)
		leaf := genLeaf(t)
		proof := genProof(t)

		oldRoot := proof.Root(*key, leaf)
		newHash, newSum := proof.rootSum(key, leaf)

		require.Equal(
			t, oldRoot.NodeHash(), newHash,
			"rootSum hash diverges from walkUp+NodeHash",
		)
		require.Equal(
			t, oldRoot.NodeSum(), newSum,
			"rootSum sum diverges from walkUp+NodeSum",
		)
	})
}

// TestVerifyMerkleProofRoundTrip checks that a proof produced by a real
// tree verifies against that tree's root. Exercises the post-swap
// VerifyMerkleProof end-to-end.
func TestVerifyMerkleProofRoundTrip(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		ctx := context.Background()
		n := rapid.IntRange(1, 32).Draw(t, "num_leaves")

		tree := NewCompactedTree(NewDefaultStore())
		keys := make([][hashSize]byte, n)
		leaves := make([]*LeafNode, n)

		seen := make(map[[hashSize]byte]struct{}, n)
		for i := 0; i < n; i++ {
			k := *genKey(t)
			// Skip duplicate keys; we want n distinct leaves.
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			l := genLeaf(t)
			_, err := tree.Insert(ctx, k, l)
			require.NoError(t, err)
			keys[i] = k
			leaves[i] = l
		}

		root, err := tree.Root(ctx)
		require.NoError(t, err)

		for i := 0; i < n; i++ {
			if leaves[i] == nil {
				continue
			}
			proof, err := tree.MerkleProof(ctx, keys[i])
			require.NoError(t, err)

			require.True(
				t,
				VerifyMerkleProof(
					keys[i], leaves[i], proof, root,
				),
				"valid proof rejected",
			)

			// Compress/decompress must not change verifiability.
			rt, err := proof.Compress().Decompress()
			require.NoError(t, err)
			require.True(
				t,
				VerifyMerkleProof(
					keys[i], leaves[i], rt, root,
				),
				"valid proof rejected after compress "+
					"round-trip",
			)
		}
	})
}

// TestVerifyMerkleProofAdversarial draws a valid (key, leaf, proof,
// root), mutates exactly one of those four inputs by flipping a single
// byte, and requires verification to fail. This is the negative-case
// counterpart to TestRootSumEquivalence: the optimization must not
// silently accept tampered proofs.
func TestVerifyMerkleProofAdversarial(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		key := *genKey(t)
		leaf := genLeaf(t)
		proof := genProof(t)

		// Derive the "honest" root from this proof so we can mutate
		// against it.
		hash, sum := proof.rootSum(&key, leaf)
		root := NewComputedBranch(hash, sum)

		// Sanity check: untampered must verify.
		require.True(
			t, VerifyMerkleProof(key, leaf, proof, root),
			"untampered proof failed to verify",
		)

		target := rapid.IntRange(0, 3).Draw(t, "mutation_target")
		switch target {
		case 0:
			// Mutate the key.
			byteIdx := rapid.IntRange(0, hashSize-1).Draw(
				t, "key_byte",
			)
			tampered := key
			tampered[byteIdx] ^= 0xFF
			require.False(
				t,
				VerifyMerkleProof(
					tampered, leaf, proof, root,
				),
				"verify accepted tampered key",
			)

		case 1:
			// Replace the leaf with a different one. Bump the sum
			// so the leaf hash differs deterministically.
			tampered := NewLeafNode(
				leaf.Value, leaf.NodeSum()+1,
			)
			require.False(
				t,
				VerifyMerkleProof(
					key, tampered, proof, root,
				),
				"verify accepted tampered leaf",
			)

		case 2:
			// Mutate one byte of one sibling's hash.
			sibIdx := rapid.IntRange(
				0, MaxTreeLevels-1,
			).Draw(t, "sibling_idx")
			sib := proof.Nodes[sibIdx]
			h := sib.NodeHash()
			byteIdx := rapid.IntRange(0, hashSize-1).Draw(
				t, "sibling_byte",
			)
			h[byteIdx] ^= 0xFF
			tampered := NewProof(append(
				[]Node(nil), proof.Nodes...,
			))
			tampered.Nodes[sibIdx] = NewComputedNode(
				h, sib.NodeSum(),
			)
			require.False(
				t,
				VerifyMerkleProof(
					key, leaf, tampered, root,
				),
				"verify accepted tampered sibling",
			)

		case 3:
			// Mutate the root hash.
			rootHash := root.NodeHash()
			byteIdx := rapid.IntRange(0, hashSize-1).Draw(
				t, "root_byte",
			)
			rootHash[byteIdx] ^= 0xFF
			tampered := NewComputedBranch(rootHash, sum)
			require.False(
				t,
				VerifyMerkleProof(
					key, leaf, proof, tampered,
				),
				"verify accepted tampered root",
			)
		}
	})
}

// TestVerifyMerkleProofMalformedInputs pins the behaviour of the public
// VerifyMerkleProof entry point on degenerate inputs: nil leaf, nil
// proof, nil root, and a proof whose sibling list has the wrong length
// must all be rejected (returning false), not panic.
func TestVerifyMerkleProofMalformedInputs(t *testing.T) {
	t.Parallel()

	var key [hashSize]byte
	leaf := NewLeafNode([]byte("leaf"), 1)
	proof := NewProof(make([]Node, MaxTreeLevels))
	for i := range proof.Nodes {
		proof.Nodes[i] = EmptyTree[MaxTreeLevels-i]
	}
	hash, sum := proof.rootSum(&key, leaf)
	root := NewComputedBranch(hash, sum)

	require.False(
		t, VerifyMerkleProof(key, nil, proof, root),
		"nil leaf accepted",
	)
	require.False(
		t, VerifyMerkleProof(key, leaf, nil, root),
		"nil proof accepted",
	)
	require.False(
		t, VerifyMerkleProof(key, leaf, proof, nil),
		"nil root accepted",
	)

	short := NewProof(proof.Nodes[:MaxTreeLevels-1])
	require.False(
		t, VerifyMerkleProof(key, leaf, short, root),
		"short proof accepted",
	)
	long := NewProof(append(
		append([]Node(nil), proof.Nodes...), proof.Nodes[0],
	))
	require.False(
		t, VerifyMerkleProof(key, leaf, long, root),
		"long proof accepted",
	)
}

// TestVerifyMerkleProofSumOverflow exercises the path where sibling
// sums wrap uint64. The existing BranchNode path also wraps, so the
// only invariant here is "does not panic, and the result is consistent
// with what walkUp would produce on the same inputs".
func TestVerifyMerkleProofSumOverflow(t *testing.T) {
	t.Parallel()

	var key [hashSize]byte
	leaf := NewLeafNode([]byte("overflow-leaf"), ^uint64(0)-1)

	// Build a proof whose siblings are all max-value computed nodes —
	// summing these with the leaf sum will wrap repeatedly.
	nodes := make([]Node, MaxTreeLevels)
	for i := range nodes {
		var h NodeHash
		h[0] = byte(i + 1)
		nodes[i] = NewComputedNode(h, ^uint64(0))
	}
	proof := NewProof(nodes)

	// The expected root is whatever the existing path computes; we
	// just require both paths agree, and that no panic occurs.
	expected := proof.Root(key, leaf)
	require.True(
		t, VerifyMerkleProof(key, leaf, proof, expected),
		"overflow path: expected root not accepted",
	)
}
