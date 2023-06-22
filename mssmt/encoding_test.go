package mssmt_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
)

var (
	proofsTestVectorName = "mssmt_tree_proofs.json"
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

	testCase := &mssmt.ValidTestCase{
		Comment: "compressed proofs",
	}
	testVectors := &mssmt.TestVectors{
		ValidTestCases: []*mssmt.ValidTestCase{testCase},
	}

	leaves := randTree(10_000)
	tree := mssmt.NewFullTree(mssmt.NewDefaultStore())
	ctx := context.TODO()
	for _, item := range leaves {
		_, err := tree.Insert(ctx, item.key, item.leaf)
		require.NoError(t, err)

		testVectors.AllTreeLeaves = append(
			testVectors.AllTreeLeaves, mssmt.NewTestFromLeaf(
				t, item.key, item.leaf,
			),
		)
		testCase.InsertedLeaves = append(
			testCase.InsertedLeaves,
			hex.EncodeToString(item.key[:]),
		)
	}

	for idx, item := range leaves {
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

		decodedProof, err := decodedCompressed.Decompress()
		require.NoError(t, err)
		assertEqualProof(t, proof, decodedProof)
		assertEqualProof(t, proof, decodedProof.Copy())

		// Create test vector proofs for 10% of the leaves.
		if idx%10 == 0 {
			proofKeyHex := hex.EncodeToString(item.key[:])
			testCase.InclusionProofs = append(
				testCase.InclusionProofs, &mssmt.TestProofCase{
					ProofKey: proofKeyHex,
					CompressedProof: hex.EncodeToString(
						buf.Bytes(),
					),
				},
			)
		}
	}

	// Generate a bunch of exclusion proofs for random keys.
	for i := 0; i < 10; i++ {
		randomKey := test.RandHash()

		proof, err := tree.MerkleProof(ctx, randomKey)
		require.NoError(t, err)
		compressed := proof.Compress()

		var buf bytes.Buffer
		err = compressed.Encode(&buf)
		require.NoError(t, err)

		testCase.ExclusionProofs = append(
			testCase.ExclusionProofs, &mssmt.TestProofCase{
				ProofKey: hex.EncodeToString(randomKey[:]),
				CompressedProof: hex.EncodeToString(
					buf.Bytes(),
				),
			},
		)
	}

	root, err := tree.Root(ctx)
	require.NoError(t, err)

	testCase.RootHash = hex.EncodeToString(fn.ByteSlice(root.NodeHash()))
	testCase.RootSum = strconv.FormatUint(root.NodeSum(), 10)

	// Write test vectors to file. This is a no-op if the "gen_test_vectors"
	// build tag is not set.
	test.WriteTestVectors(t, proofsTestVectorName, testVectors)
}
