package mssmt_test

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// testInsertLastWriteWins asserts that insertion is last-write-wins per
// key: applying a sequence of inserts that reuses keys produces the
// same tree as inserting only the final leaf observed for each key.
// This is the invariant that allows coalescing consecutive updates to
// the same key into a single insert of the latest value.
func testInsertLastWriteWins(t *rapid.T) {
	ctx := context.Background()

	// Draw a small pool of keys so the insertion sequence is likely
	// to hit the same key several times. Duplicate draws within the
	// pool are harmless; they only shrink the effective pool.
	numKeys := rapid.IntRange(1, 8).Draw(t, "num_keys")
	keys := make([][hashSize]byte, numKeys)
	for i := range keys {
		keyBytes := rapid.SliceOfN(
			rapid.Byte(), hashSize, hashSize,
		).Draw(t, "key")
		copy(keys[i][:], keyBytes)
	}

	// Draw the insertion sequence. Sums are bounded well below the
	// point where the tree's uint64 sum overflow check could
	// trigger.
	numInserts := rapid.IntRange(1, 32).Draw(t, "num_inserts")
	sequence := make([]treeLeaf, numInserts)
	for i := range sequence {
		keyIdx := rapid.IntRange(0, numKeys-1).Draw(t, "key_idx")
		value := rapid.SliceOfN(rapid.Byte(), 1, 64).Draw(t, "value")
		sum := rapid.Uint64Range(0, 1<<32).Draw(t, "sum")

		sequence[i] = treeLeaf{
			key:  keys[keyIdx],
			leaf: mssmt.NewLeafNode(value, sum),
		}
	}

	// Apply the full sequence in order.
	full := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	for _, item := range sequence {
		_, err := full.Insert(ctx, item.key, item.leaf)
		require.NoError(t, err)
	}

	// Reduce the sequence to the final leaf per key, keeping the
	// order of each key's first occurrence, and apply only those.
	finalLeaves := make(map[[hashSize]byte]*mssmt.LeafNode)
	var keyOrder [][hashSize]byte
	for _, item := range sequence {
		if _, ok := finalLeaves[item.key]; !ok {
			keyOrder = append(keyOrder, item.key)
		}
		finalLeaves[item.key] = item.leaf
	}

	coalesced := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	for _, key := range keyOrder {
		_, err := coalesced.Insert(ctx, key, finalLeaves[key])
		require.NoError(t, err)
	}

	fullRoot, err := full.Root(ctx)
	require.NoError(t, err)
	coalescedRoot, err := coalesced.Root(ctx)
	require.NoError(t, err)

	require.True(
		t, mssmt.IsEqualNode(fullRoot, coalescedRoot),
		"full root %v != coalesced root %v", fullRoot, coalescedRoot,
	)

	// Each key's final leaf must carry a valid inclusion proof in
	// the fully-inserted tree.
	for _, key := range keyOrder {
		proof, err := full.MerkleProof(ctx, key)
		require.NoError(t, err)
		require.True(t, mssmt.VerifyMerkleProof(
			key, finalLeaves[key], proof, fullRoot,
		))
	}
}

// TestInsertLastWriteWins runs the last-write-wins insertion property
// against the compacted tree.
func TestInsertLastWriteWins(t *testing.T) {
	t.Parallel()

	rapid.Check(t, testInsertLastWriteWins)
}
