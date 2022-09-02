package mssmt_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/lightninglabs/taro/mssmt"
	"github.com/stretchr/testify/require"
)

func assertEqualProof(t *testing.T, expected, actual *mssmt.Proof) {
	t.Helper()

	for i, node := range expected.Nodes {
		other := actual.Nodes[i]
		require.True(t, mssmt.IsEqualNode(node, other))
	}
}

func assertEqualCompressedProof(t *testing.T, expected,
	actual *mssmt.CompressedProof) {

	t.Helper()

	for i, node := range expected.Nodes {
		other := actual.Nodes[i]
		require.True(t, mssmt.IsEqualNode(node, other))
	}
	require.Equal(t, expected.Bits, actual.Bits)
}

func TestBitPacking(t *testing.T) {
	t.Parallel()

	// Odd number of bits and greater than a byte to test edge case.
	bits := []bool{true, true, false, false, true, false, true, true, false}
	decompressedBits := mssmt.UnpackBits(mssmt.PackBits(bits))

	// Bits up to the expected length should match.
	require.Equal(t, bits, decompressedBits[:len(bits)])

	// Remaining bits should not be set.
	for _, isBitSet := range decompressedBits[len(bits):] {
		require.False(t, isBitSet)
	}
}

func TestProofEncoding(t *testing.T) {
	t.Parallel()

	leaves := randTree(10_000)
	tree := mssmt.NewFullTree(mssmt.NewDefaultStore())
	ctx := context.TODO()
	for _, item := range leaves {
		_, err := tree.Insert(ctx, item.key, item.leaf)
		require.NoError(t, err)
	}

	for _, item := range leaves {
		proof, err := tree.MerkleProof(ctx, item.key)
		require.NoError(t, err)
		compressed := proof.Compress()

		var buf bytes.Buffer
		err = compressed.Encode(&buf)
		require.NoError(t, err)

		var decodedCompressed mssmt.CompressedProof
		err = decodedCompressed.Decode(bytes.NewReader(buf.Bytes()))
		require.NoError(t, err)
		assertEqualCompressedProof(t, compressed, &decodedCompressed)

		decodedProof := decodedCompressed.Decompress()
		assertEqualProof(t, proof, decodedProof)
		assertEqualProof(t, proof, decodedProof.Copy())
	}
}
