package json

import (
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
)

func NewLeaf(key [32]byte, leaf *mssmt.LeafNode) *Leaf {
	return &Leaf{
		Key: hex.EncodeToString(key[:]),
		Node: &LeafNode{
			Value: hex.EncodeToString(leaf.Value),
			Sum:   strconv.FormatUint(leaf.NodeSum(), 10),
		},
	}
}

type Leaf struct {
	Key  string    `json:"key"`
	Node *LeafNode `json:"node"`
}

func (tl *Leaf) ToLeafNode(t testing.TB) *mssmt.LeafNode {
	t.Helper()

	sum, err := strconv.ParseUint(tl.Node.Sum, 10, 64)
	require.NoError(t, err)

	return mssmt.NewLeafNode(test.ParseHex(t, tl.Node.Value), sum)
}

type LeafNode struct {
	Value string `json:"value"`
	Sum   string `json:"sum"`
}

func NewMsSmtProof(p *mssmt.Proof) *MsSmtProof {
	compressedProof := p.Compress()

	nodes := make(map[int]*Node)
	nodeIdx := 0

	for idx := range compressedProof.Bits {
		isEmpty := compressedProof.Bits[idx]
		if !isEmpty {
			n := compressedProof.Nodes[nodeIdx]
			nodes[idx] = &Node{
				Hash: n.NodeHash().String(),
				Sum:  strconv.FormatUint(n.NodeSum(), 10),
			}
			nodeIdx++
		}
	}

	return &MsSmtProof{
		Nodes: nodes,
	}
}

type MsSmtProof struct {
	Nodes map[int]*Node `json:"nodes"`
}

func (tp *MsSmtProof) ToProof(t testing.TB) *mssmt.Proof {
	t.Helper()

	nodes := make([]mssmt.Node, len(tp.Nodes))
	for idx := range tp.Nodes {
		nodes[idx] = tp.Nodes[idx].ToNode(t)
	}

	return &mssmt.Proof{
		Nodes: nodes,
	}
}

func NewNode(node mssmt.Node) *Node {
	nodeHash := node.NodeHash()
	return &Node{
		Hash: hex.EncodeToString(nodeHash[:]),
		Sum:  strconv.FormatUint(node.NodeSum(), 10),
	}
}

type Node struct {
	Hash string `json:"hash"`
	Sum  string `json:"sum"`
}

func (tn *Node) ToNode(t testing.TB) mssmt.ComputedNode {
	t.Helper()

	sum, err := strconv.ParseUint(tn.Sum, 10, 64)
	require.NoError(t, err)

	return mssmt.NewComputedNode(test.Parse32Byte(t, tn.Hash), sum)
}
