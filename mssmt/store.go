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

	// DeleteBranch deletes the branch node keyed by the given NodeKey.
	DeleteBranch(NodeKey)

	// DeleteLeaf deletes the leaf node keyed by the given NodeKey.
	DeleteLeaf(NodeKey)

	// GetChildren returns the left and right child of the node keyed by the
	// given NodeKey.
	GetChildren(uint8, NodeKey) (Node, Node)
}

// DefaultStore is an in-memory implementation of the Store interface.
type DefaultStore struct {
	branches map[NodeKey]*BranchNode
	leaves   map[NodeKey]*LeafNode
}

var _ Store = (*DefaultStore)(nil)

// NewDefaultStore initializes a new DefaultStore.
func NewDefaultStore() *DefaultStore {
	return &DefaultStore{
		branches: make(map[NodeKey]*BranchNode),
		leaves:   make(map[NodeKey]*LeafNode),
	}
}

// InsertBranch stores a new branch keyed by its NodeKey.
func (c *DefaultStore) InsertBranch(branch *BranchNode) {
	c.branches[branch.NodeKey()] = branch
}

// InsertLeaf stores a new leaf keyed by its NodeKey.
func (c *DefaultStore) InsertLeaf(leaf *LeafNode) {
	c.leaves[leaf.NodeKey()] = leaf
}

// DeleteBranch deletes the branch node keyed by the given NodeKey.
func (c *DefaultStore) DeleteBranch(key NodeKey) {
	delete(c.branches, key)
}

// DeleteLeaf deletes the leaf node keyed by the given NodeKey.
func (c *DefaultStore) DeleteLeaf(key NodeKey) {
	delete(c.leaves, key)
}

// GetChildren returns the left and right child of the node keyed by the given
// NodeKey.
func (c *DefaultStore) GetChildren(height uint8, key NodeKey) (Node, Node) {
	getNode := func(height uint, key NodeKey) Node {
		if key == EmptyTree[height].NodeKey() {
			return EmptyTree[height]
		}
		if branch, ok := c.branches[key]; ok {
			return branch
		}
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
