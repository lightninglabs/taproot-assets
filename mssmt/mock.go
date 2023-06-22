package mssmt

import (
	"bytes"
	"context"
	"encoding/hex"
	"math"
	"strconv"
	"testing"

	"github.com/lightninglabs/taproot-assets/fn"
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

type ValidTestCase struct {
	RootHash        string           `json:"root_hash"`
	RootSum         string           `json:"root_sum"`
	InsertedLeaves  []string         `json:"inserted_leaves"`
	DeletedLeaves   []string         `json:"deleted_leaves"`
	ReplacedLeaves  []*TestLeaf      `json:"replaced_leaves"`
	InclusionProofs []*TestProofCase `json:"inclusion_proofs"`
	ExclusionProofs []*TestProofCase `json:"exclusion_proofs"`
	Comment         string           `json:"comment"`
}

func (tc *ValidTestCase) ShouldInsert(key string) bool {
	return fn.Any(tc.InsertedLeaves, func(k string) bool {
		return k == key
	})
}

func (tc *ValidTestCase) ShouldDelete(key string) bool {
	return fn.Any(tc.DeletedLeaves, func(k string) bool {
		return k == key
	})
}

type ErrorTestCase struct {
	InsertedLeaves []string `json:"inserted_leaves"`
	Error          string   `json:"error"`
	Comment        string   `json:"comment"`
}

func (ec *ErrorTestCase) ShouldInsert(key string) bool {
	return fn.Any(ec.InsertedLeaves, func(k string) bool {
		return k == key
	})
}

type TestVectors struct {
	AllTreeLeaves  []*TestLeaf      `json:"all_tree_leaves"`
	ValidTestCases []*ValidTestCase `json:"valid_test_cases"`
	ErrorTestCases []*ErrorTestCase `json:"error_test_cases"`
}

func (tv *TestVectors) FindLeaf(key string) *TestLeaf {
	for idx := range tv.AllTreeLeaves {
		leaf := tv.AllTreeLeaves[idx]
		if leaf.Key == key {
			return leaf
		}
	}
	return nil
}

type TestProofCase struct {
	ProofKey        string `json:"proof_key"`
	CompressedProof string `json:"compressed_proof"`
}

func (tpc *TestProofCase) ToProof(t testing.TB) *Proof {
	t.Helper()

	proofBytes, err := hex.DecodeString(tpc.CompressedProof)
	require.NoError(t, err)

	var compressedProof CompressedProof
	err = compressedProof.Decode(bytes.NewReader(proofBytes))
	require.NoError(t, err)

	proof, err := compressedProof.Decompress()
	require.NoError(t, err)

	return proof
}

func NewTestFromLeaf(t testing.TB, key [32]byte, leaf *LeafNode) *TestLeaf {
	t.Helper()

	return &TestLeaf{
		Key: hex.EncodeToString(key[:]),
		Node: &TestLeafNode{
			Value: hex.EncodeToString(leaf.Value),
			Sum:   strconv.FormatUint(leaf.NodeSum(), 10),
		},
	}
}

type TestLeaf struct {
	Key  string        `json:"key"`
	Node *TestLeafNode `json:"node"`
}

func (tl *TestLeaf) ToLeafNode(t testing.TB) *LeafNode {
	t.Helper()

	sum, err := strconv.ParseUint(tl.Node.Sum, 10, 64)
	require.NoError(t, err)

	return NewLeafNode(test.ParseHex(t, tl.Node.Value), sum)
}

type TestLeafNode struct {
	Value string `json:"value"`
	Sum   string `json:"sum"`
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
				Sum:  strconv.FormatUint(n.NodeSum(), 10),
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
		Sum:  strconv.FormatUint(node.NodeSum(), 10),
	}
}

type TestNode struct {
	Hash string `json:"hash"`
	Sum  string `json:"sum"`
}

func (tn *TestNode) ToNode(t testing.TB) ComputedNode {
	t.Helper()

	sum, err := strconv.ParseUint(tn.Sum, 10, 64)
	require.NoError(t, err)

	return NewComputedNode(test.Parse32Byte(t, tn.Hash), sum)
}
