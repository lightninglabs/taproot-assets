package mssmt_test

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
)

// TestBranchV1Trees tests that BranchV1 full and compacted trees agree on
// their roots and proofs, that their proofs verify for BranchV1 only, and that
// deleting all of their leaves leaves the empty tree.
func TestBranchV1Trees(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	leaves := randTree(100)

	v1 := mssmt.WithBranchVersion(mssmt.BranchV1)
	v0Tree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	fullTree := mssmt.NewFullTree(mssmt.NewDefaultStore(), v1)
	compactedTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore(), v1)
	trees := []mssmt.Tree{v0Tree, fullTree, compactedTree}

	for _, item := range leaves {
		for _, tree := range trees {
			_, err := tree.Insert(ctx, item.key, item.leaf)
			require.NoError(t, err)
		}
	}

	v0Root, err := v0Tree.Root(ctx)
	require.NoError(t, err)
	fullRoot, err := fullTree.Root(ctx)
	require.NoError(t, err)
	compactedRoot, err := compactedTree.Root(ctx)
	require.NoError(t, err)

	require.True(t, mssmt.IsEqualNode(fullRoot, compactedRoot))
	require.Equal(t, v0Root.NodeSum(), fullRoot.NodeSum())
	require.NotEqual(t, v0Root.NodeHash(), fullRoot.NodeHash())

	nonMember := leaves[0].key
	nonMember[hashSize-1] ^= 0xFF
	keys := [][hashSize]byte{nonMember}
	for _, item := range leaves {
		keys = append(keys, item.key)
	}

	for _, key := range keys {
		fullProof, err := fullTree.MerkleProof(ctx, key)
		require.NoError(t, err)
		compactedProof, err := compactedTree.MerkleProof(ctx, key)
		require.NoError(t, err)
		assertEqualProof(t, fullProof, compactedProof)

		leaf, err := compactedTree.Get(ctx, key)
		require.NoError(t, err)

		decompressed, err := compactedProof.Compress().Decompress()
		require.NoError(t, err)

		proofs := []*mssmt.Proof{compactedProof, decompressed}
		for _, proof := range proofs {
			require.True(t, mssmt.VerifyVersionedMerkleProof(
				mssmt.BranchV1, key, leaf, proof, compactedRoot,
			))
			require.False(t, mssmt.VerifyVersionedMerkleProof(
				mssmt.BranchV0, key, leaf, proof, compactedRoot,
			))
		}
	}

	for _, item := range leaves {
		for _, tree := range trees[1:] {
			_, err := tree.Delete(ctx, item.key)
			require.NoError(t, err)
		}
	}

	for _, tree := range trees[1:] {
		root, err := tree.Root(ctx)
		require.NoError(t, err)
		require.True(t, mssmt.IsEqualNode(mssmt.EmptyTree[0], root))
	}
}
