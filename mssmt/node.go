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

	// ZeroNodeHash represents the empty node hash that is all zeroes.
	ZeroNodeHash = NodeHash{}
)

// NodeHash represents the key of a MS-SMT node.
type NodeHash [hashSize]byte

// String returns a NodeHash as a hex-encoded string.
func (k NodeHash) String() string {
	return hex.EncodeToString(k[:])
}

// Node represents a MS-SMT node. A node can either be a leaf or a branch.
type Node interface {
	// NodeHash returns the unique identifier for a MS-SMT node. It
	// represents the hash of the node committing to its internal data.
	NodeHash() NodeHash

	// NodeSum returns the sum commitment of the node.
	NodeSum() uint64

	// Copy returns a deep copy of the node.
	Copy() Node
}

// IsEqualNode determines whether a and b are equal based on their NodeHash and
// NodeSum.
func IsEqualNode(a, b Node) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.NodeHash() == b.NodeHash() && a.NodeSum() == b.NodeSum()
}

// LeafNode represents a leaf node within a MS-SMT. Leaf nodes commit to a value
// and some integer value (the sum) associated with the value.
type LeafNode struct {
	// Cached nodeHash instance to prevent redundant computations.
	nodeHash *NodeHash

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

// NodeHash returns the unique identifier for a MS-SMT node. It represents the
// hash of the leaf committing to its internal data.
func (n *LeafNode) NodeHash() NodeHash {
	if n.nodeHash != nil {
		return *n.nodeHash
	}

	h := sha256.New()
	h.Write(n.Value)
	_ = binary.Write(h, binary.BigEndian, n.sum)
	n.nodeHash = (*NodeHash)(h.Sum(nil))
	return *n.nodeHash
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
	var nodeHashCopy *NodeHash
	if n.nodeHash != nil {
		nodeHashCopy = &NodeHash{}
		copy(nodeHashCopy[:], n.nodeHash[:])
	}

	valueCopy := make([]byte, len(n.Value))
	copy(valueCopy, n.Value)

	return &LeafNode{
		nodeHash: nodeHashCopy,
		Value:    valueCopy,
		sum:      n.sum,
	}
}

// CompactedLeafNode holds a leaf node that represents a whole "compacted"
// subtree omitting all default branches and leafs in the represented subtree.
type CompactedLeafNode struct {
	*LeafNode

	// key holds the leaf's key.
	key [32]byte

	// compactedNodeHash holds the topmost (omitted) node's node hash in the
	// subtree.
	compactedNodeHash NodeHash
}

// NewCompactedLeafNode creates a new compacted leaf at the passed height with
// the passed leaf key.
func NewCompactedLeafNode(height int, key *[32]byte,
	leaf *LeafNode) *CompactedLeafNode {

	var current Node = leaf
	for i := lastBitIndex; i >= height; i-- {
		if bitIndex(uint8(i), key) == 0 {
			current = NewBranch(current, EmptyTree[i+1])
		} else {
			current = NewBranch(EmptyTree[i+1], current)
		}
	}
	nodeHash := current.NodeHash()

	node := &CompactedLeafNode{
		LeafNode:          leaf,
		key:               *key,
		compactedNodeHash: nodeHash,
	}

	return node
}

// NodeHash returns the compacted subtree's node hash.
func (c *CompactedLeafNode) NodeHash() NodeHash {
	return c.compactedNodeHash
}

// Key returns the leaf key.
func (c *CompactedLeafNode) Key() [32]byte {
	return c.key
}

// Extract extracts the subtree represented by this compacted leaf and returns
// the topmost node in the tree.
func (c *CompactedLeafNode) Extract(height int) Node {
	var current Node = c.LeafNode

	// Walk up and recreate the missing branches.
	for j := MaxTreeLevels; j > height+1; j-- {
		var left, right Node
		if bitIndex(uint8(j-1), &c.key) == 0 {
			left, right = current, EmptyTree[j]
		} else {
			left, right = EmptyTree[j], current
		}

		current = NewBranch(left, right)
	}

	return current
}

// Copy returns a deep copy of the compacted leaf node.
func (c *CompactedLeafNode) Copy() Node {
	return &CompactedLeafNode{
		LeafNode:          c.LeafNode.Copy().(*LeafNode),
		key:               c.key,
		compactedNodeHash: c.compactedNodeHash,
	}
}

// BranchNode represents an intermediate or root node within a MS-SMT. It
// commits to its left and right children, along with their respective sum
// values.
type BranchNode struct {
	// Cached instances to prevent redundant computations.
	nodeHash *NodeHash
	sum      *uint64

	Left  Node
	Right Node
}

// NewComputedBranch creates a new branch without any reference it its
// children. This method of construction allows as to walk the tree down by
// only fetching minimal subtrees.
func NewComputedBranch(nodeHash NodeHash, sum uint64) *BranchNode {
	return &BranchNode{
		nodeHash: &nodeHash,
		sum:      &sum,
	}
}

// NewBranch constructs a new branch backed by its left and right children.
func NewBranch(left, right Node) *BranchNode {
	return &BranchNode{
		Left:  left,
		Right: right,
	}
}

// NodeHash returns the unique identifier for a MS-SMT node. It represents the
// hash of the branch committing to its internal data.
func (n *BranchNode) NodeHash() NodeHash {
	if n.nodeHash != nil {
		return *n.nodeHash
	}

	left := n.Left.NodeHash()
	right := n.Right.NodeHash()

	h := sha256.New()
	h.Write(left[:])
	h.Write(right[:])
	_ = binary.Write(h, binary.BigEndian, n.NodeSum())
	n.nodeHash = (*NodeHash)(h.Sum(nil))
	return *n.nodeHash
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
	var nodeHashCopy *NodeHash
	if n.nodeHash != nil {
		nodeHashCopy = &NodeHash{}
		copy(nodeHashCopy[:], n.nodeHash[:])
	}

	var sumCopy *uint64
	if n.sum != nil {
		sumCopy = new(uint64)
		*sumCopy = *n.sum
	}

	return &BranchNode{
		nodeHash: nodeHashCopy,
		Left:     NewComputedNode(n.Left.NodeHash(), n.Left.NodeSum()),
		Right:    NewComputedNode(n.Right.NodeHash(), n.Right.NodeSum()),
		sum:      sumCopy,
	}
}

// ComputedNode is a node within a MS-SMT that has already had its NodeHash and
// NodeSum computed, i.e., its preimage is not available.
type ComputedNode struct {
	hash NodeHash
	sum  uint64
}

// NewComputedNode instantiates a new computed node.
func NewComputedNode(hash NodeHash, sum uint64) ComputedNode {
	return ComputedNode{hash: hash, sum: sum}
}

// NodeHash returns the unique identifier for a MS-SMT node. It represents the
// hash of the node committing to its internal data.
func (n ComputedNode) NodeHash() NodeHash {
	return n.hash
}

// NodeSum returns the sum commitment of the node.
func (n ComputedNode) NodeSum() uint64 {
	return n.sum
}

// Copy returns a deep copy of the branch node.
func (n ComputedNode) Copy() Node {
	return ComputedNode{
		hash: n.hash,
		sum:  n.sum,
	}
}
