package mssmt

import (
	"bytes"
	"context"
	"encoding/hex"
	"math"
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

// RandLeafAmount generates a random leaf node sum amount.
func RandLeafAmount() uint64 {
	minSum := uint64(1)
	maxSum := uint64(math.MaxUint32)
	return (test.RandInt[uint64]() % maxSum) + minSum
}

// RandProof returns a random proof for testing.
func RandProof(t testing.TB) *Proof {
	var (
		store      = NewDefaultStore()
		tree  Tree = NewFullTree(store)
		key1       = test.RandHash()
		key2       = test.RandHash()
		err   error
	)
	tree, err = tree.Insert(
		context.Background(), key1, NewLeafNode([]byte("foo"), 10),
	)
	require.NoError(t, err)
	tree, err = tree.Insert(
		context.Background(), key2, NewLeafNode([]byte("bar"), 20),
	)
	require.NoError(t, err)

	proof, err := tree.MerkleProof(context.Background(), key2)
	require.NoError(t, err)
	return proof
}

func ParseProof(t testing.TB, proofHex string) Proof {
	t.Helper()

	proofBytes, err := hex.DecodeString(proofHex)
	require.NoError(t, err)

	var compressedProof CompressedProof
	err = compressedProof.Decode(bytes.NewReader(proofBytes))
	require.NoError(t, err)

	proof, err := compressedProof.Decompress()
	require.NoError(t, err)

	return *proof
}

func HexProof(t testing.TB, proof *Proof) string {
	t.Helper()

	compressedProof := proof.Compress()

	var buf bytes.Buffer
	err := compressedProof.Encode(&buf)
	require.NoError(t, err)

	return hex.EncodeToString(buf.Bytes())
}

func NewTestFromProof(t testing.TB, p *Proof) *TestProof {
	t.Helper()

	compressedProof := p.Compress()

	nodes := make(map[int]*TestNode)
	nodeIdx := 0

	for idx := range compressedProof.Bits {
		isEmpty := compressedProof.Bits[idx]
		if !isEmpty {
			n := compressedProof.Nodes[nodeIdx]
			nodes[idx] = &TestNode{
				Hash: n.NodeHash().String(),
				Sum:  n.NodeSum(),
			}
			nodeIdx++
		}
	}

	return &TestProof{
		Nodes: nodes,
	}
}

type TestProof struct {
	Nodes map[int]*TestNode `json:"nodes"`
}

func (tp *TestProof) ToProof(t testing.TB) *Proof {
	t.Helper()

	nodes := make([]Node, len(tp.Nodes))
	for idx := range tp.Nodes {
		nodes[idx] = tp.Nodes[idx].ToNode(t)
	}

	return &Proof{
		Nodes: nodes,
	}
}

func NewTestFromNode(t testing.TB, node Node) *TestNode {
	t.Helper()

	nodeHash := node.NodeHash()
	return &TestNode{
		Hash: hex.EncodeToString(nodeHash[:]),
		Sum:  node.NodeSum(),
	}
}

type TestNode struct {
	Hash string `json:"hash"`
	Sum  uint64 `json:"sum"`
}

func (tn *TestNode) ToNode(t testing.TB) ComputedNode {
	t.Helper()

	return NewComputedNode(test.Parse32Byte(t, tn.Hash), tn.Sum)
}
