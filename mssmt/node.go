package mssmt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

const (
	// hashSize is the size of hashes used in the MS-SMT.
	hashSize = sha256.Size
)

var (
	// EmptyLeafNode represents an empty leaf in a MS-SMT, one with a nil
	// value and 0 sum.
	EmptyLeafNode = NewLeafNode(nil, 0)
)

// NodeKey represents the key of a MS-SMT node.
type NodeKey [hashSize]byte

// String returns a NodeKey as a hex-encoded string.
func (k NodeKey) String() string {
	return hex.EncodeToString(k[:])
}

// Node represents a MS-SMT node. A node can either be a leaf or a branch.
type Node interface {
	// NodeKey returns the unique identifier for a MS-SMT node. It
	// represents the hash of the node committing to its internal data.
	NodeKey() NodeKey

	// NodeSum returns the sum commitment of the node.
	NodeSum() uint64

	// Equal determines whether a node is equal to another.
	Equal(Node) bool
}

// LeafNode represents a leaf node within a MS-SMT. Leaf nodes commit to a value
// and some integer value (the sum) associated with the value.
type LeafNode struct {
	// Cached nodeKey instance to prevent redundant computations.
	nodeKey *NodeKey

	Value []byte
	sum   uint64
}

// NewLeafNode constructs a new leaf node.
func NewLeafNode(value []byte, sum uint64) *LeafNode {
	return &LeafNode{
		Value: value,
		sum:   sum,
	}
}

// NodeKey returns the unique identifier for a MS-SMT node. It represents the
// hash of the leaf committing to its internal data.
func (n *LeafNode) NodeKey() NodeKey {
	if n.nodeKey != nil {
		return *n.nodeKey
	}

	h := sha256.New()
	h.Write(n.Value)
	binary.Write(h, binary.BigEndian, n.sum)
	n.nodeKey = (*NodeKey)(h.Sum(nil))
	return *n.nodeKey
}

// NodeSum returns the sum commitment of the leaf node.
func (n *LeafNode) NodeSum() uint64 {
	return n.sum
}

// Equal determines whether a leaf node is equal to another.
func (n *LeafNode) Equal(other Node) bool {
	switch leaf := other.(type) {
	case *LeafNode:
		return bytes.Equal(n.Value, leaf.Value) && n.sum == leaf.sum
	default:
		return false
	}
}

// IsEmpty returns whether this is an empty leaf.
func (n *LeafNode) IsEmpty() bool {
	return len(n.Value) == 0 && n.sum == 0
}

// BranchNode represents an intermediate or root node within a MS-SMT. It
// commits to its left and right children, along with their respective sum
// values.
type BranchNode struct {
	// Cached instances to prevent redundant computations.
	nodeKey *NodeKey
	sum     *uint64

	Left  Node
	Right Node
}

// NewBranch constructs a new branch backed by its left and right children.
func NewBranch(left, right Node) *BranchNode {
	return &BranchNode{
		Left:  left,
		Right: right,
	}
}

// NodeKey returns the unique identifier for a MS-SMT node. It represents the
// hash of the branch committing to its internal data.
func (n *BranchNode) NodeKey() NodeKey {
	if n.nodeKey != nil {
		return *n.nodeKey
	}

	left := n.Left.NodeKey()
	right := n.Right.NodeKey()

	h := sha256.New()
	h.Write(left[:])
	h.Write(right[:])
	binary.Write(h, binary.BigEndian, n.NodeSum())
	n.nodeKey = (*NodeKey)(h.Sum(nil))
	return *n.nodeKey
}

// NodeSum returns the sum commitment of the branch's left and right children.
func (n *BranchNode) NodeSum() uint64 {
	if n.sum != nil {
		return *n.sum
	}

	sum := n.Left.NodeSum() + n.Right.NodeSum()
	n.sum = &sum
	return sum
}

// Equal determines whether a branch node is equal to another.
func (n *BranchNode) Equal(other Node) bool {
	switch branch := other.(type) {
	case *BranchNode:
		return n.Left.NodeKey() == branch.Left.NodeKey() &&
			n.Left.NodeSum() == branch.Left.NodeSum() &&
			n.Right.NodeKey() == branch.Right.NodeKey() &&
			n.Right.NodeSum() == branch.Right.NodeSum()
	default:
		return false
	}
}
