package mssmt

import (
	"context"
	"fmt"
)

// TreeStore represents a generic database interface to update or view a
// generic MSSMT tree atomically.
type TreeStore interface {
	// Update updates the persistent tree in the passed update closure using
	// the update transaction.
	Update(context.Context, func(tx TreeStoreUpdateTx) error) error

	// View gives a view of the persistent tree in the passed view closure
	// using the view transaction.
	View(context.Context, func(tx TreeStoreViewTx) error) error
}

// TreeStoreViewTx is an interface encompassing all methods of a view only
// persistent tree transaction.
type TreeStoreViewTx interface {
	// GetChildren returns the left and right child of the node keyed by
	// the given NodeKey.
	GetChildren(int, NodeKey) (Node, Node, error)
}

// TreeStoreUpdateTx is an interface encompassing all methods of an updating
// persistent tree transaction.
type TreeStoreUpdateTx interface {
	TreeStoreViewTx

	// InsertBranch stores a new branch keyed by its NodeKey.
	InsertBranch(*BranchNode) error

	// InsertLeaf stores a new leaf keyed by its NodeKey (not the insertion
	// key).
	InsertLeaf(*LeafNode) error

	// InsertCompactedLeaf stores a new compacted leaf keyed by its
	// NodeKey (not the insertion key).
	InsertCompactedLeaf(*CompactedLeafNode) error

	// DeleteBranch deletes the branch node keyed by the given NodeKey.
	DeleteBranch(NodeKey) error

	// DeleteLeaf deletes the leaf node keyed by the given NodeKey.
	DeleteLeaf(NodeKey) error

	// DeleteCompactedLeaf deletes a compacted leaf keyed by the given
	// NodeKey.
	DeleteCompactedLeaf(NodeKey) error
}

// DefaultStore is an in-memory implementation of the TreeStore interface.
type DefaultStore struct {
	branches        map[NodeKey]*BranchNode
	leaves          map[NodeKey]*LeafNode
	compactedLeaves map[NodeKey]*CompactedLeafNode

	cntReads   int
	cntWrites  int
	cntDeletes int
}

var _ TreeStore = (*DefaultStore)(nil)

// NewDefaultStore initializes a new DefaultStore.
func NewDefaultStore() *DefaultStore {
	return &DefaultStore{
		branches:        make(map[NodeKey]*BranchNode),
		leaves:          make(map[NodeKey]*LeafNode),
		compactedLeaves: make(map[NodeKey]*CompactedLeafNode),
	}
}

// NumBranches returns the number of stored branches.
func (d *DefaultStore) NumBranches() int {
	return len(d.branches)
}

// NumLeaves returns the number of stored leaves.
func (d *DefaultStore) NumLeaves() int {
	return len(d.leaves)
}

// NumCompactedLeaves returns the number of stored compacted leaves.
func (d *DefaultStore) NumCompactedLeaves() int {
	return len(d.compactedLeaves)
}

// Update updates the persistent tree in the passed update closure using the
// update transaction.
func (d *DefaultStore) Update(_ context.Context,
	update func(tx TreeStoreUpdateTx) error) error {

	return update(d)
}

// View gives a view of the persistent tree in the passed view closure using
// the view transaction.
func (d *DefaultStore) View(_ context.Context,
	view func(tx TreeStoreViewTx) error) error {

	return view(d)
}

// InsertBranch stores a new branch keyed by its NodeKey.
func (d *DefaultStore) InsertBranch(branch *BranchNode) error {
	d.branches[branch.NodeKey()] = branch
	d.cntWrites++

	return nil
}

// InsertLeaf stores a new leaf keyed by its NodeKey.
func (d *DefaultStore) InsertLeaf(leaf *LeafNode) error {
	d.leaves[leaf.NodeKey()] = leaf
	d.cntWrites++

	return nil
}

// InsertCompactedLeaf stores a new compacted leaf keyed by its NodeKey (not
// the insertion key).
func (d *DefaultStore) InsertCompactedLeaf(leaf *CompactedLeafNode) error {
	d.compactedLeaves[leaf.NodeKey()] = leaf
	d.cntWrites++

	return nil
}

// DeleteBranch deletes the branch node keyed by the given NodeKey.
func (d *DefaultStore) DeleteBranch(key NodeKey) error {
	delete(d.branches, key)
	d.cntDeletes++

	return nil
}

// DeleteLeaf deletes the leaf node keyed by the given NodeKey.
func (d *DefaultStore) DeleteLeaf(key NodeKey) error {
	delete(d.leaves, key)
	d.cntDeletes++

	return nil
}

// DeleteCompactedLeaf deletes a compacted leaf keyed by the given NodeKey.
func (d *DefaultStore) DeleteCompactedLeaf(key NodeKey) error {
	delete(d.compactedLeaves, key)
	d.cntDeletes++

	return nil
}

// GetChildren returns the left and right child of the node keyed by the given
// NodeKey.
func (d *DefaultStore) GetChildren(height int, key NodeKey) (
	Node, Node, error) {

	getNode := func(height uint, key NodeKey) Node {
		if key == EmptyTree[height].NodeKey() {
			return EmptyTree[height]
		}
		if branch, ok := d.branches[key]; ok {
			d.cntReads++
			return branch
		}
		if leaf, ok := d.compactedLeaves[key]; ok {
			d.cntReads++
			return leaf
		}

		d.cntReads++
		return d.leaves[key]
	}

	node := getNode(uint(height), key)
	switch node := node.(type) {
	case *BranchNode:
		return getNode(uint(height)+1, node.Left.NodeKey()),
			getNode(uint(height)+1, node.Right.NodeKey()), nil

	default:
		return nil, nil, fmt.Errorf("unexpected node type %T with "+
			"key %v", node, key)
	}
}
