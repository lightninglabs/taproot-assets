package mssmt

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/lightninglabs/taproot-assets/mssmt/arith"
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

// NewNodeHashFromBytes creates a new NodeHash from a byte slice.
func NewNodeHashFromBytes(b []byte) (NodeHash, error) {
	var zero NodeHash

	if len(b) != hashSize {
		return zero, fmt.Errorf("invalid hash size: %d", len(b))
	}

	var h NodeHash
	copy(h[:], b)

	return h, nil
}

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
	// nodeHash caches the leaf's hash by value (with nodeHashOk acting
	// as the sentinel) so the cache itself never escapes to the heap.
	nodeHash   NodeHash
	nodeHashOk bool

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
	if n.nodeHashOk {
		return n.nodeHash
	}

	// Hash inline over a stack buffer: value-length is variable, but
	// the sum tail is always 8 bytes, so we write value then sum
	// directly into the digest without a separate hasher allocation
	// when value is small enough to share the stack frame.
	h := sha256.New()
	h.Write(n.Value)
	var sumBuf [8]byte
	binary.BigEndian.PutUint64(sumBuf[:], n.sum)
	h.Write(sumBuf[:])
	var out NodeHash
	h.Sum(out[:0])
	n.nodeHash = out
	n.nodeHashOk = true
	return n.nodeHash
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
	valueCopy := make([]byte, len(n.Value))
	copy(valueCopy, n.Value)

	return &LeafNode{
		nodeHash:   n.nodeHash,
		nodeHashOk: n.nodeHashOk,
		Value:      valueCopy,
		sum:        n.sum,
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
	// Cached (hash, sum) stored by value; the *Ok flags act as the
	// "have I computed this yet" sentinel. Storing by value keeps the
	// cache from escaping to the heap on every branch construction.
	nodeHash   NodeHash
	sum        uint64
	nodeHashOk bool
	sumOk      bool

	Left  Node
	Right Node
}

// NewComputedBranch creates a new branch without any reference it its
// children. This method of construction allows as to walk the tree down by
// only fetching minimal subtrees.
func NewComputedBranch(nodeHash NodeHash, sum uint64) *BranchNode {
	return &BranchNode{
		nodeHash:   nodeHash,
		nodeHashOk: true,
		sum:        sum,
		sumOk:      true,
	}
}

// NewBranch constructs a new branch backed by its left and right children.
func NewBranch(left, right Node) *BranchNode {
	return &BranchNode{
		Left:  left,
		Right: right,
	}
}

// newCheckedBranch constructs a branch after verifying its child sum.
func newCheckedBranch(left, right Node) (*BranchNode, error) {
	sum, err := arith.Add(left.NodeSum(), right.NodeSum()).Unpack()
	if err != nil {
		return nil, err
	}

	return &BranchNode{
		Left:  left,
		Right: right,
		sum:   sum,
		sumOk: true,
	}, nil
}

// NodeHash returns the unique identifier for a MS-SMT node. It represents the
// hash of the branch committing to its internal data.
//
// The hash input is always exactly 72 bytes (left hash || right hash || sum)
// so we lay it out in a stack-resident buffer and call sha256.Sum256 to
// avoid the per-call allocator/digest churn of sha256.New + Sum(nil).
func (n *BranchNode) NodeHash() NodeHash {
	if n.nodeHashOk {
		return n.nodeHash
	}

	left := n.Left.NodeHash()
	right := n.Right.NodeHash()
	sum := n.NodeSum()

	var buf [hashSize*2 + 8]byte
	copy(buf[:hashSize], left[:])
	copy(buf[hashSize:hashSize*2], right[:])
	binary.BigEndian.PutUint64(buf[hashSize*2:], sum)

	n.nodeHash = sha256.Sum256(buf[:])
	n.nodeHashOk = true
	return n.nodeHash
}

// NodeSum returns the sum commitment of the branch's left and right children.
func (n *BranchNode) NodeSum() uint64 {
	if n.sumOk {
		return n.sum
	}

	sum, err := arith.Add(n.Left.NodeSum(), n.Right.NodeSum()).Unpack()
	if err != nil {
		panic(err)
	}
	n.sum = sum
	n.sumOk = true
	return n.sum
}

// Copy returns a deep copy of the branch node, with its children returned as
// `ComputedNode`.
func (n *BranchNode) Copy() Node {
	var leftCopy, rightCopy Node
	if n.Left != nil {
		leftCopy = NewComputedNode(
			n.Left.NodeHash(), n.Left.NodeSum(),
		)
	}
	if n.Right != nil {
		rightCopy = NewComputedNode(
			n.Right.NodeHash(), n.Right.NodeSum(),
		)
	}

	return &BranchNode{
		nodeHash:   n.nodeHash,
		nodeHashOk: n.nodeHashOk,
		sum:        n.sum,
		sumOk:      n.sumOk,
		Left:       leftCopy,
		Right:      rightCopy,
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
