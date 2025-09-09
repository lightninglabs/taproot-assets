package mssmt

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// compressedProofBytes creates a compressed proof with the specified number of
// non-empty nodes. If numNodes is 0, all nodes will be empty. If numNodes is
// MaxTreeLevels, all node positions will be populated.
func compressedProofBytes(t *testing.T, numNodes int) []byte {
	t.Helper()

	if numNodes < 0 || numNodes > MaxTreeLevels {
		require.Fail(t, "numNodes must be between 0 and MaxTreeLevels")
	}

	// Create the specified number of non-empty nodes.
	nodes := make([]Node, numNodes)
	for i := 0; i < numNodes; i++ {
		hash := NodeHash{}
		// Make each hash unique.
		hash[0] = byte(i + 1)
		nodes[i] = NewComputedNode(hash, uint64((i+1)*100))
	}

	// Create bits array: false for non-empty nodes, true for empty nodes.
	bits := make([]bool, MaxTreeLevels)
	for i := 0; i < MaxTreeLevels; i++ {
		// First numNodes are false (non-empty), rest are true (empty).
		bits[i] = i >= numNodes
	}

	compressedProof := CompressedProof{
		Bits:  bits,
		Nodes: nodes,
	}

	var buf bytes.Buffer
	if err := compressedProof.Encode(&buf); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// TestNewProofFromCompressedBytes tests the NewProofFromCompressedBytes
// function with various valid and invalid compressed proof byte inputs.
func TestNewProofFromCompressedBytes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		// name describes the test case for identification.
		name string

		// input is the compressed proof bytes to test with.
		input []byte

		// expectError indicates whether an error is expected.
		expectError bool

		// errorMsg is the expected error message substring when
		// expectError is true.
		errorMsg string

		// expectNumNodes is the expected number of populated
		// (non-empty) nodes in the decompressed proof.
		// Only relevant when expectError is false.
		expectNumNodes int
	}{
		{
			name:           "valid compressed proof with one node",
			input:          compressedProofBytes(t, 1),
			expectError:    false,
			expectNumNodes: 1,
		},
		{
			name: "valid compressed proof with all empty " +
				"nodes",
			input:          compressedProofBytes(t, 0),
			expectError:    false,
			expectNumNodes: 0,
		},
		{
			name:           "empty bytes",
			input:          []byte{},
			expectError:    true,
			errorMsg:       "compressed proof bytes are empty",
			expectNumNodes: 0,
		},
		{
			name:           "single byte - insufficient data",
			input:          []byte{0x01},
			expectError:    true,
			errorMsg:       "decode compressed proof",
			expectNumNodes: 0,
		},
		{
			name: "only number of nodes field",
			// numNodes = 1, but no node data.
			input:          []byte{0x00, 0x01},
			expectError:    true,
			errorMsg:       "decode compressed proof",
			expectNumNodes: 0,
		},
		{
			name: "invalid node count - more nodes than expected",
			input: func() []byte {
				// Create a proof that claims to have 2 nodes
				// but bits indicate only 1.
				node1 := NewComputedNode(NodeHash{0x01}, 100)
				node2 := NewComputedNode(NodeHash{0x02}, 200)

				bits := make([]bool, MaxTreeLevels)
				// Only one non-empty node indicated.
				bits[0] = false
				for i := 1; i < MaxTreeLevels; i++ {
					bits[i] = true
				}

				// Manually create invalid bytes.
				var buf bytes.Buffer
				// Write 2 nodes.
				// numNodes = 2
				buf.Write([]byte{0x00, 0x02})
				// Node 1.
				hash1 := node1.NodeHash()
				buf.Write(hash1[:])
				// sum = 100
				buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x64})
				// Node 2.
				hash2 := node2.NodeHash()
				buf.Write(hash2[:])
				// sum = 200
				buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0xC8})
				// Write bits (indicating only 1 non-empty
				// node).
				bitsBytes := PackBits(bits)
				buf.Write(bitsBytes)

				return buf.Bytes()
			}(),
			expectError:    true,
			errorMsg:       "invalid compressed proof",
			expectNumNodes: 0,
		},
		{
			name: "invalid node count - fewer nodes than expected",
			input: func() []byte {
				// Create a proof that claims to have 0 nodes
				// but bits indicate 1.
				bits := make([]bool, MaxTreeLevels)
				// One non-empty node indicated.
				bits[0] = false
				// Another non-empty node indicated.
				bits[1] = false
				for i := 2; i < MaxTreeLevels; i++ {
					bits[i] = true
				}

				// Manually create invalid bytes.
				var buf bytes.Buffer
				// numNodes = 0, but bits expect 2.
				buf.Write([]byte{0x00, 0x00})
				// Write bits.
				bitsBytes := PackBits(bits)
				buf.Write(bitsBytes)

				return buf.Bytes()
			}(),
			expectError:    true,
			errorMsg:       "invalid compressed proof",
			expectNumNodes: 0,
		},
		{
			name: "trailing data after valid proof",
			input: func() []byte {
				validBytes := compressedProofBytes(t, 1)
				// Add extra bytes at the end.
				return append(validBytes, 0xFF, 0xFF)
			}(),
			expectError:    true,
			errorMsg:       "trailing data after compressed proof",
			expectNumNodes: 0,
		},
		{
			name:           "maximum valid nodes",
			input:          compressedProofBytes(t, MaxTreeLevels),
			expectError:    false,
			expectNumNodes: MaxTreeLevels,
		},
	}

	for idx := range testCases {
		tc := testCases[idx]

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			proof, err := NewProofFromCompressedBytes(tc.input)

			if tc.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errorMsg)

				// Verify that the returned proof is the zero
				// value.
				var zeroProof Proof
				require.Equal(t, zeroProof, proof)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, proof.Nodes)
			require.Len(t, proof.Nodes, MaxTreeLevels)

			// Count populated (non-empty) nodes.
			populatedCount := 0
			for idx, node := range proof.Nodes {
				// A node is populated if it doesn't match the
				// corresponding EmptyTree node.
				emptyTreeNode := EmptyTree[MaxTreeLevels-idx]
				if node.NodeHash() != emptyTreeNode.NodeHash() {
					populatedCount++
				}
			}
			require.Equal(
				t, tc.expectNumNodes, populatedCount,
				"expected %d populated nodes, got %d",
				tc.expectNumNodes, populatedCount,
			)

			// Verify that we can compress the proof again and get
			// similar bytes.
			compressedAgain := proof.Compress()
			require.NotNil(t, compressedAgain)

			// Verify that decompressing again yields the same
			// proof.
			proofAgain, err := compressedAgain.Decompress()
			require.NoError(t, err)
			require.NotNil(t, proofAgain)

			// Compare nodes (should be equal).
			require.Len(t, proofAgain.Nodes, len(proof.Nodes))
			for i, node := range proof.Nodes {
				isEqualNode := IsEqualNode(
					node, proofAgain.Nodes[i],
				)
				require.True(t, isEqualNode)
			}
		})
	}
}
