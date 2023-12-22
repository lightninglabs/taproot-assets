package mssmt

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/exp/maps"
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
	// the given NodeHash.
	GetChildren(int, NodeHash) (Node, Node, error)

	// RootNode returns the root node of the tree.
	RootNode() (Node, error)
}

// TreeStoreUpdateTx is an interface encompassing all methods of an updating
// persistent tree transaction.
type TreeStoreUpdateTx interface {
	TreeStoreViewTx

	// UpdateRoot updates the index that points to the root node for the
	// persistent tree.
	//
	// NOTE: For some implementations this may be a noop, as the index of
	// the backing storage is able to track the root node easily.
	UpdateRoot(*BranchNode) error

	// InsertBranch stores a new branch keyed by its NodeHash.
	InsertBranch(*BranchNode) error

	// InsertLeaf stores a new leaf keyed by its NodeHash (not the insertion
	// key).
	InsertLeaf(*LeafNode) error

	// InsertCompactedLeaf stores a new compacted leaf keyed by its
	// NodeHash (not the insertion key).
	InsertCompactedLeaf(*CompactedLeafNode) error

	// DeleteBranch deletes the branch node keyed by the given NodeHash.
	DeleteBranch(NodeHash) error

	// DeleteLeaf deletes the leaf node keyed by the given NodeHash.
	DeleteLeaf(NodeHash) error

	// DeleteCompactedLeaf deletes a compacted leaf keyed by the given
	// NodeHash.
	DeleteCompactedLeaf(NodeHash) error

	// DeleteRoot deletes the root node of the MS-SMT.
	DeleteRoot() error

	// DeleteAllNodes deletes all nodes in the MS-SMT.
	DeleteAllNodes() error
}

// TreeStoreDriver represents a concrete driver of the main TreeStore
// interface. A driver is identified by a globally unique string identifier,
// along with a 'New()' method which is responsible for initializing a
// particular TreeStore concrete implementation.
type TreeStoreDriver struct {
	// Name is the name of the minting store driver.
	Name string

	// New creates a new concrete instance of the TreeStore given a set of
	// arguments.
	New func(args ...any) (TreeStore, error)
}

var (
	treeStores           = make(map[string]*TreeStoreDriver)
	treeStoreRegisterMtx sync.Mutex
)

// RegisteredTreeStores returns a slice of all currently registered minting
// stores.
//
// NOTE: This function is safe for concurrent access.
func RegisteredTreeStores() []*TreeStoreDriver {
	treeStoreRegisterMtx.Lock()
	defer treeStoreRegisterMtx.Unlock()

	drivers := make([]*TreeStoreDriver, 0, len(treeStores))
	for _, driver := range treeStores {
		drivers = append(drivers, driver)
	}

	return drivers
}

// RegisterTreeStore registers a TreeStoreDriver which is capable of driving a
// concrete TreeStore interface. In the case that this driver has already been
// registered, an error is returned.
//
// NOTE: This function is safe for concurrent access.
func RegisterTreeStore(driver *TreeStoreDriver) error {
	treeStoreRegisterMtx.Lock()
	defer treeStoreRegisterMtx.Unlock()

	if _, ok := treeStores[driver.Name]; ok {
		return fmt.Errorf("tree store already registered")
	}

	treeStores[driver.Name] = driver
	return nil
}

// DefaultStore is an in-memory implementation of the TreeStore interface.
type DefaultStore struct {
	branches        map[NodeHash]*BranchNode
	leaves          map[NodeHash]*LeafNode
	compactedLeaves map[NodeHash]*CompactedLeafNode

	root *BranchNode

	cntReads   int
	cntWrites  int
	cntDeletes int
}

var _ TreeStore = (*DefaultStore)(nil)

// NewDefaultStore initializes a new DefaultStore.
func NewDefaultStore() *DefaultStore {
	return &DefaultStore{
		branches:        make(map[NodeHash]*BranchNode),
		leaves:          make(map[NodeHash]*LeafNode),
		compactedLeaves: make(map[NodeHash]*CompactedLeafNode),
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

// Stats returns store statistics as a string (useful for debugging).
func (d *DefaultStore) Stats() string {
	return fmt.Sprintf("branches=%v, leaves=%v, cleaves=%v, reads=%v, "+
		"writes=%v, deletes=%v\n", len(d.branches), len(d.leaves),
		len(d.compactedLeaves), d.cntReads, d.cntWrites, d.cntDeletes)
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

// UpdateRoot updates the index that points to the root node for the persistent
// tree.
//
// NOTE: For some implementations this may be a noop, as the index of the
// backing storage is able to track the root node easily.
func (d *DefaultStore) UpdateRoot(node *BranchNode) error {
	d.root = node
	return nil
}

// RootNode returns the root node of the tree.
func (d *DefaultStore) RootNode() (Node, error) {
	if d.root == nil {
		return EmptyTree[0], nil
	}

	return d.root, nil
}

// InsertBranch stores a new branch keyed by its NodeHash.
func (d *DefaultStore) InsertBranch(branch *BranchNode) error {
	d.branches[branch.NodeHash()] = branch
	d.cntWrites++

	return nil
}

// InsertLeaf stores a new leaf keyed by its NodeHash.
func (d *DefaultStore) InsertLeaf(leaf *LeafNode) error {
	d.leaves[leaf.NodeHash()] = leaf
	d.cntWrites++

	return nil
}

// InsertCompactedLeaf stores a new compacted leaf keyed by its NodeHash (not
// the insertion key).
func (d *DefaultStore) InsertCompactedLeaf(leaf *CompactedLeafNode) error {
	d.compactedLeaves[leaf.NodeHash()] = leaf
	d.cntWrites++

	return nil
}

// DeleteBranch deletes the branch node keyed by the given NodeHash.
func (d *DefaultStore) DeleteBranch(key NodeHash) error {
	delete(d.branches, key)
	d.cntDeletes++

	return nil
}

// DeleteLeaf deletes the leaf node keyed by the given NodeHash.
func (d *DefaultStore) DeleteLeaf(key NodeHash) error {
	delete(d.leaves, key)
	d.cntDeletes++

	return nil
}

// DeleteCompactedLeaf deletes a compacted leaf keyed by the given NodeHash.
func (d *DefaultStore) DeleteCompactedLeaf(key NodeHash) error {
	delete(d.compactedLeaves, key)
	d.cntDeletes++

	return nil
}

// DeleteRoot deletes the root node of the MS-SMT.
func (d *DefaultStore) DeleteRoot() error {
	d.root = nil
	d.cntDeletes++

	return nil
}

// DeleteAllNodes deletes all nodes in the MS-SMT.
func (d *DefaultStore) DeleteAllNodes() error {
	// Delete leaves, then compacted leaves, then branches.
	leafCount := len(d.leaves)
	maps.Clear(d.leaves)
	d.cntDeletes += leafCount

	compactedLeafCount := len(d.compactedLeaves)
	maps.Clear(d.compactedLeaves)
	d.cntDeletes += compactedLeafCount

	branchCount := len(d.branches)
	maps.Clear(d.branches)
	d.cntDeletes += branchCount

	return nil
}

// GetChildren returns the left and right child of the node keyed by the given
// NodeHash.
func (d *DefaultStore) GetChildren(height int, key NodeHash) (
	Node, Node, error) {

	getNode := func(height uint, key NodeHash) Node {
		if key == EmptyTree[height].NodeHash() {
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

		if leaf, ok := d.leaves[key]; ok {
			d.cntReads++
			return leaf
		}

		return EmptyTree[height]
	}

	node := getNode(uint(height), key)

	if key != EmptyTree[height].NodeHash() && node == EmptyTree[height] {
		return nil, nil, fmt.Errorf("node not found")
	}

	switch node := node.(type) {
	case *BranchNode:
		return getNode(uint(height)+1, node.Left.NodeHash()),
			getNode(uint(height)+1, node.Right.NodeHash()), nil

	default:
		return nil, nil, fmt.Errorf("unexpected node type %T with "+
			"key %v", node, key)
	}
}
