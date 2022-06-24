package mssmt

import (
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

	// Copy returns a deep copy of the node.
	Copy() Node
}

// IsEqualNode determines whether a and b are equal based on their NodeKey and
// NodeSum.
func IsEqualNode(a, b Node) bool {
	return a.NodeKey() == b.NodeKey() && a.NodeSum() == b.NodeSum()
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
	_ = binary.Write(h, binary.BigEndian, n.sum)
	n.nodeKey = (*NodeKey)(h.Sum(nil))
	return *n.nodeKey
}

// NodeSum returns the sum commitment of the leaf node.
func (n *LeafNode) NodeSum() uint64 {
	return n.sum
}

// IsEmpty returns whether this is an empty leaf.
func (n *LeafNode) IsEmpty() bool {
	return len(n.Value) == 0 && n.sum == 0
}

// Copy returns a deep copy of the leaf node.
func (n *LeafNode) Copy() Node {
	var nodeKeyCopy *NodeKey
	if n.nodeKey != nil {
		nodeKeyCopy = new(NodeKey)
		*nodeKeyCopy = *n.nodeKey
	}

	valueCopy := make([]byte, 0, len(n.Value))
	copy(valueCopy, n.Value)

	return &LeafNode{
		nodeKey: nodeKeyCopy,
		Value:   valueCopy,
		sum:     n.sum,
	}
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
	_ = binary.Write(h, binary.BigEndian, n.NodeSum())
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

// Copy returns a deep copy of the branch node, with its children returned as
// `ComputedNode`.
func (n *BranchNode) Copy() Node {
	var nodeKeyCopy *NodeKey
	if n.nodeKey != nil {
		nodeKeyCopy = new(NodeKey)
		*nodeKeyCopy = *n.nodeKey
	}

	var sumCopy *uint64
	if n.sum != nil {
		sumCopy = new(uint64)
		*sumCopy = *n.sum
	}

	return &BranchNode{
		nodeKey: nodeKeyCopy,
		Left:    NewComputedNode(n.Left.NodeKey(), n.Left.NodeSum()),
		Right:   NewComputedNode(n.Right.NodeKey(), n.Right.NodeSum()),
		sum:     sumCopy,
	}
}

// ComputedNode is a node within a MS-SMT that has already had its NodeKey and
// NodeSum computed, i.e., its preimage is not available.
type ComputedNode struct {
	key NodeKey
	sum uint64
}

// NewComputedNode instantiates a new computed node.
func NewComputedNode(key NodeKey, sum uint64) ComputedNode {
	return ComputedNode{key: key, sum: sum}
}

// NodeKey returns the unique identifier for a MS-SMT node. It represents the
// hash of the node committing to its internal data.
func (n ComputedNode) NodeKey() NodeKey {
	return n.key
}

// NodeSum returns the sum commitment of the node.
func (n ComputedNode) NodeSum() uint64 {
	return n.sum
}

// Copy returns a deep copy of the branch node.
func (n ComputedNode) Copy() Node {
	return ComputedNode{
		key: n.key,
		sum: n.sum,
	}
}
