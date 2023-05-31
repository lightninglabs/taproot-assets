package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
)

type (
	// NewBranch is a type alias for the params to create a new mssmt
	// branch node.
	NewBranch = sqlc.InsertBranchParams

	// NewLeaf is a type alias for the params to create a new mssmt leaf
	// node.
	NewLeaf = sqlc.InsertLeafParams

	// NewCompactedLeaf is a type alias for the params to create a new
	// mssmt compacted leaf node.
	NewCompactedLeaf = sqlc.InsertCompactedLeafParams

	// StoredNode is a type alias for an arbitrary child of an mssmt branch.
	StoredNode = sqlc.FetchChildrenRow

	// DelNode wraps the args we need to delete a node.
	DelNode = sqlc.DeleteNodeParams

	// ChildQuery wraps the args we need to fetch the children of a node.
	ChildQuery = sqlc.FetchChildrenParams

	// UpdateRoot wraps the args we need to update a root node.
	UpdateRoot = sqlc.UpsertRootNodeParams
)

// TreeStore is a sub-set of the main sqlc.Querier interface that contains
// only the methods needed to manipulate and query stored MSSMT trees.
type TreeStore interface {
	// InsertBranch inserts a new branch to the store.
	InsertBranch(ctx context.Context, newNode NewBranch) error

	// InsertLeaf inserts a new leaf to the store.
	InsertLeaf(ctx context.Context, newNode NewLeaf) error

	// InsertCompactedLeaf inserts a new compacted leaf to the store.
	InsertCompactedLeaf(ctx context.Context, newNode NewCompactedLeaf) error

	// FetchChildren fetches the children (at most two currently) of the
	// passed branch hash key.
	FetchChildren(ctx context.Context, c ChildQuery) ([]StoredNode, error)

	// DeleteNode deletes a node (can be either branch, leaf of compacted
	// leaf) from the store.
	DeleteNode(ctx context.Context, n DelNode) (int64, error)

	// DeleteAllNodes deletes all nodes from the store.
	DeleteAllNodes(ctx context.Context, namespace string) (int64, error)

	// DeleteRoot deletes a root node from the store.
	DeleteRoot(ctx context.Context, namespace string) (int64, error)

	// FetchRootNode fetches the root node for the specified namespace.
	FetchRootNode(ctx context.Context,
		namespace string) (sqlc.MssmtNode, error)

	// UpsertRootNode allows us to update the root node in place for a
	// given namespace.
	UpsertRootNode(ctx context.Context, arg UpdateRoot) error
}

type TreeStoreTxOptions struct {
	// readOnly governs if a read only transaction is needed or not.
	readOnly bool
}

// ReadOnly returns true if the transaction should be read only.
//
// NOTE: This implements the TxOptions
func (t *TreeStoreTxOptions) ReadOnly() bool {
	return t.readOnly
}

// NewTreeStoreReadTx creates a new read transaction option set.
func NewTreeStoreReadTx() TreeStoreTxOptions {
	return TreeStoreTxOptions{
		readOnly: true,
	}
}

// BatchedTreeStore is a version of the AddrBook that's capable of batched
// database operations.
type BatchedTreeStore interface {
	TreeStore

	BatchedTx[TreeStore]
}

// TaprootAssetTreeStore is an persistent MS-SMT implementation backed by a live
// SQL database.
type TaprootAssetTreeStore struct {
	db        BatchedTreeStore
	namespace string
}

// NewTaprootAssetTreeStore creates a new TaprootAssetTreeStore instance given
// an open BatchedTreeStore storage backend. The namespace argument is required,
// as it allow us to store several distinct trees on disk in the same table.
func NewTaprootAssetTreeStore(db BatchedTreeStore,
	namespace string) *TaprootAssetTreeStore {

	return &TaprootAssetTreeStore{
		db:        db,
		namespace: namespace,
	}
}

var _ mssmt.TreeStore = (*TaprootAssetTreeStore)(nil)

// Update updates the persistent tree in the passed-in update closure using the
// update transaction.
func (t *TaprootAssetTreeStore) Update(ctx context.Context,
	update func(tx mssmt.TreeStoreUpdateTx) error) error {

	txBody := func(dbTx TreeStore) error {
		updateTx := &taprootAssetTreeStoreTx{
			ctx:       ctx,
			dbTx:      dbTx,
			namespace: t.namespace,
		}

		return update(updateTx)
	}

	var writeTxOpts TreeStoreTxOptions
	return t.db.ExecTx(ctx, &writeTxOpts, txBody)
}

// View gives a view of the persistent tree in the passed view closure using
// the view transaction.
func (t *TaprootAssetTreeStore) View(ctx context.Context,
	update func(tx mssmt.TreeStoreViewTx) error) error {

	txBody := func(dbTx TreeStore) error {
		viewTx := &taprootAssetTreeStoreTx{
			ctx:       ctx,
			dbTx:      dbTx,
			namespace: t.namespace,
		}

		return update(viewTx)
	}

	readTxOpts := TreeStoreTxOptions{
		readOnly: true,
	}

	return t.db.ExecTx(ctx, &readTxOpts, txBody)
}

type taprootAssetTreeStoreTx struct {
	ctx       context.Context
	dbTx      TreeStore
	namespace string
}

// InsertBranch stores a new branch keyed by its NodeHash.
func (t *taprootAssetTreeStoreTx) InsertBranch(branch *mssmt.BranchNode) error {
	hashKey := branch.NodeHash()
	lHashKey := branch.Left.NodeHash()
	rHashKey := branch.Right.NodeHash()

	if err := t.dbTx.InsertBranch(t.ctx, NewBranch{
		HashKey:   hashKey[:],
		LHashKey:  lHashKey[:],
		RHashKey:  rHashKey[:],
		Sum:       int64(branch.NodeSum()),
		Namespace: t.namespace,
	}); err != nil {
		return fmt.Errorf("unable to insert branch: %w", err)
	}

	return nil
}

// InsertLeaf stores a new leaf keyed by its NodeHash (not the insertion key).
func (t *taprootAssetTreeStoreTx) InsertLeaf(leaf *mssmt.LeafNode) error {
	hashKey := leaf.NodeHash()

	if err := t.dbTx.InsertLeaf(t.ctx, NewLeaf{
		HashKey:   hashKey[:],
		Value:     leaf.Value,
		Sum:       int64(leaf.NodeSum()),
		Namespace: t.namespace,
	}); err != nil {
		return fmt.Errorf("unable to insert leaf: %w", err)
	}

	return nil
}

// InsertCompactedLeaf stores a new compacted leaf keyed by its
// NodeHash (not the insertion key).
func (t *taprootAssetTreeStoreTx) InsertCompactedLeaf(
	leaf *mssmt.CompactedLeafNode) error {

	hashKey := leaf.NodeHash()
	key := leaf.Key()

	if err := t.dbTx.InsertCompactedLeaf(t.ctx, NewCompactedLeaf{
		HashKey:   hashKey[:],
		Key:       key[:],
		Value:     leaf.Value,
		Sum:       int64(leaf.NodeSum()),
		Namespace: t.namespace,
	}); err != nil {
		return fmt.Errorf("unable to insert compacted leaf: %w", err)
	}

	return nil
}

// DeleteRoot deletes the root node of the MS-SMT.
func (t *taprootAssetTreeStoreTx) DeleteRoot() error {
	_, err := t.dbTx.DeleteRoot(t.ctx, t.namespace)
	return err
}

// DeleteRoot deletes all nodes, including branch nodes, of the MS-SMT.
func (t *taprootAssetTreeStoreTx) DeleteAllNodes() error {
	_, err := t.dbTx.DeleteAllNodes(t.ctx, t.namespace)
	return err
}

// DeleteBranch deletes the branch node keyed by the given NodeHash.
func (t *taprootAssetTreeStoreTx) DeleteBranch(hashKey mssmt.NodeHash) error {
	_, err := t.dbTx.DeleteNode(t.ctx, DelNode{
		HashKey:   hashKey[:],
		Namespace: t.namespace,
	})
	return err
}

// DeleteLeaf deletes the leaf node keyed by the given NodeHash.
func (t *taprootAssetTreeStoreTx) DeleteLeaf(hashKey mssmt.NodeHash) error {
	_, err := t.dbTx.DeleteNode(t.ctx, DelNode{
		HashKey:   hashKey[:],
		Namespace: t.namespace,
	})
	return err
}

// DeleteCompactedLeaf deletes a compacted leaf keyed by the given NodeHash.
func (t *taprootAssetTreeStoreTx) DeleteCompactedLeaf(hashKey mssmt.NodeHash) error {
	_, err := t.dbTx.DeleteNode(t.ctx, DelNode{
		HashKey:   hashKey[:],
		Namespace: t.namespace,
	})
	return err
}

// newKey is a helper to convert a byte slice of the correct size to a 32 byte
// array.
func newKey(data []byte) ([32]byte, error) {
	var key [32]byte

	if len(data) != 32 {
		return key, fmt.Errorf("invalid key size")
	}

	copy(key[:], data)
	return key, nil
}

// GetChildren returns the left and right child of the node keyed by the given
// NodeHash.
func (t *taprootAssetTreeStoreTx) GetChildren(height int, hashKey mssmt.NodeHash) (
	mssmt.Node, mssmt.Node, error) {

	dbRows, err := t.dbTx.FetchChildren(t.ctx, ChildQuery{
		HashKey:   hashKey[:],
		Namespace: t.namespace,
	})
	if err != nil {
		return nil, nil, err
	}

	var (
		left  mssmt.Node = mssmt.EmptyTree[height+1]
		right mssmt.Node = mssmt.EmptyTree[height+1]
	)

	var lHashKey, rHashKey []byte

	for i, row := range dbRows {
		if i == 0 {
			// The root of the subtree, we're looking for the
			// children, so we skip this node.
			lHashKey = row.LHashKey
			rHashKey = row.RHashKey
			continue
		}

		isLeft := bytes.Equal(row.HashKey, lHashKey)
		isRight := bytes.Equal(row.HashKey, rHashKey)

		if !isLeft && !isRight {
			// Some child node further down the tree.
			continue
		}

		var node mssmt.Node

		// Since both children are nil, we can assume this is a leaf.
		if row.LHashKey == nil && row.RHashKey == nil {
			leaf := mssmt.NewLeafNode(
				row.Value, uint64(row.Sum),
			)

			// Precompute the node hash key.
			leaf.NodeHash()

			// We store the key for compacted leafs.
			if row.Key != nil {
				key, err := newKey(row.Key)
				if err != nil {
					return nil, nil, err
				}

				node = mssmt.NewCompactedLeafNode(
					height+1, &key, leaf,
				)
			} else {
				node = leaf
			}
		} else {
			hashKey, err := newKey(row.HashKey)
			if err != nil {
				return nil, nil, err
			}

			node = mssmt.NewComputedBranch(hashKey, uint64(row.Sum))
		}

		if isLeft {
			left = node
		} else {
			right = node
		}
	}

	return left, right, nil
}

// RootNode returns the root nodes of the MS-SMT. If the tree has no elements,
// then a nil node is returned.
func (t *taprootAssetTreeStoreTx) RootNode() (mssmt.Node, error) {
	var root mssmt.Node

	rootNode, err := t.dbTx.FetchRootNode(t.ctx, t.namespace)
	switch {
	// If there're no rows, then this means it's an empty tree, so we
	// return the root empty node.
	case errors.Is(err, sql.ErrNoRows):
		return mssmt.EmptyTree[0], nil

	case err != nil:
		return nil, err
	}

	nodeHash, err := newKey(rootNode.HashKey)
	if err != nil {
		return nil, err
	}

	root = mssmt.NewComputedBranch(nodeHash, uint64(rootNode.Sum))

	return root, nil
}

// UpdateRoot updates the index that points to the root node for the persistent
// tree.
func (t *taprootAssetTreeStoreTx) UpdateRoot(rootNode *mssmt.BranchNode) error {
	rootHash := rootNode.NodeHash()

	// We'll do a sanity check here to ensure that we're not trying to
	// insert a root hash. This might happen when we delete all the items
	// in a tree.
	//
	// If we try to insert this, then the foreign key constraint will fail,
	// as empty hashes are never stored (root would point to a node not in
	// the DB).
	if rootHash == mssmt.EmptyTree[0].NodeHash() {
		return nil
	}

	return t.dbTx.UpsertRootNode(t.ctx, UpdateRoot{
		RootHash:  rootHash[:],
		Namespace: t.namespace,
	})
}
