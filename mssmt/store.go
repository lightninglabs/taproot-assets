package mssmt

import "fmt"

// Store represents a generic key-value store to back the storage of non-empty
// leaf and branch nodes in a MS-SMT.
type Store interface {
	// InsertBranch stores a new branch keyed by its NodeKey.
	InsertBranch(*BranchNode)

	// InsertLeaf stores a new leaf keyed by its NodeKey (not the insertion
	// key).
	InsertLeaf(*LeafNode)

	// InsertCompactedLeaf stores a new compacted leaf keyed by its
	// NodeKey (not the insertion key).
	InsertCompactedLeaf(*CompactedLeafNode)

	// DeleteBranch deletes the branch node keyed by the given NodeKey.
	DeleteBranch(NodeKey)

	// DeleteLeaf deletes the leaf node keyed by the given NodeKey.
	DeleteLeaf(NodeKey)

	// DeleteCompactedLeaf deletes a compacted leaf keyed by the given
	// NodeKey.
	DeleteCompactedLeaf(NodeKey)

	// GetChildren returns the left and right child of the node keyed by the
	// given NodeKey.
	GetChildren(uint8, NodeKey) (Node, Node)
}

// DefaultStore is an in-memory implementation of the Store interface.
type DefaultStore struct {
	branches        map[NodeKey]*BranchNode
	leaves          map[NodeKey]*LeafNode
	compactedLeaves map[NodeKey]*CompactedLeafNode

	cntReads   int
	cntWrites  int
	cntDeletes int
}

var _ Store = (*DefaultStore)(nil)

// NewDefaultStore initializes a new DefaultStore.
func NewDefaultStore() *DefaultStore {
	return &DefaultStore{
		branches:        make(map[NodeKey]*BranchNode),
		leaves:          make(map[NodeKey]*LeafNode),
		compactedLeaves: make(map[NodeKey]*CompactedLeafNode),
	}
}

// InsertBranch stores a new branch keyed by its NodeKey.
func (c *DefaultStore) InsertBranch(branch *BranchNode) {
	c.branches[branch.NodeKey()] = branch
	c.cntWrites++
}

// InsertLeaf stores a new leaf keyed by its NodeKey.
func (c *DefaultStore) InsertLeaf(leaf *LeafNode) {
	c.leaves[leaf.NodeKey()] = leaf
	c.cntWrites++
}

// InsertCompactedLeaf stores a new compacted leaf keyed by its NodeKey (not
// the insertion key).
func (c *DefaultStore) InsertCompactedLeaf(leaf *CompactedLeafNode) {
	c.compactedLeaves[leaf.NodeKey()] = leaf
	c.cntWrites++
}

// DeleteBranch deletes the branch node keyed by the given NodeKey.
func (c *DefaultStore) DeleteBranch(key NodeKey) {
	delete(c.branches, key)
	c.cntDeletes++
}

// DeleteLeaf deletes the leaf node keyed by the given NodeKey.
func (c *DefaultStore) DeleteLeaf(key NodeKey) {
	delete(c.leaves, key)
	c.cntDeletes++
}

// DeleteCompactedLeaf deletes a compacted leaf keyed by the given NodeKey.
func (c *DefaultStore) DeleteCompactedLeaf(key NodeKey) {
	delete(c.compactedLeaves, key)
	c.cntDeletes++
}

// GetChildren returns the left and right child of the node keyed by the given
// NodeKey.
func (c *DefaultStore) GetChildren(height uint8, key NodeKey) (Node, Node) {
	getNode := func(height uint, key NodeKey) Node {
		if key == EmptyTree[height].NodeKey() {
			return EmptyTree[height]
		}
		if branch, ok := c.branches[key]; ok {
			c.cntReads++
			return branch
		}
		if leaf, ok := c.compactedLeaves[key]; ok {
			c.cntReads++
			return leaf
		}

		c.cntReads++
		return c.leaves[key]
	}

	node := getNode(uint(height), key)
	switch node := node.(type) {
	case *BranchNode:
		return getNode(uint(height)+1, node.Left.NodeKey()),
			getNode(uint(height)+1, node.Right.NodeKey())
	default:
		panic(fmt.Sprintf("unexpected node type %T with key %v", node,
			key))
	}
}
