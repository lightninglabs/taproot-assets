package tarodb

import (
	"bytes"
	"context"
	"fmt"

	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/tarodb/sqlite"
)

type (
	// NewBranch is a type alias for the params to create a new mssmt
	// branch node.
	NewBranch = sqlite.InsertBranchParams

	// NewLeaf is a type alias for the params to create a new mssmt leaf
	// node.
	NewLeaf = sqlite.InsertLeafParams

	// NewCompactedLeaf is a type alias for the params to create a new
	// mssmt compacted leaf node.
	NewCompactedLeaf = sqlite.InsertCompactedLeafParams

	// StoredNode is a type alias for an arbitrary child of an mssmt branch.
	StoredNode = sqlite.FetchChildrenRow
)

// TreeStore is a sub-set of the main sqlite.Querier interface that contains
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
	FetchChildren(ctx context.Context, hashKey []byte) ([]StoredNode, error)

	// DeleteNode deletes a node (can be either branch, leaf of compacted
	// leaf) from the store.
	DeleteNode(ctx context.Context, hashKey []byte) (int64, error)
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

// BatchedAddrBook is a version of the AddrBook that's capable of batched
// database operations.
type BatchedTreeStore interface {
	TreeStore

	BatchedTx[TreeStore, TxOptions]
}

type TaroTreeStore struct {
	db BatchedTreeStore
}

// NewTaroAddressBook creates a new TaroAddressBook instance given a open
// BatchedAddrBook storage backend.
func NewTaroTreeStore(db BatchedTreeStore) *TaroTreeStore {
	return &TaroTreeStore{
		db: db,
	}
}

var _ mssmt.TreeStore = (*TaroTreeStore)(nil)

// Update updates the persistent tree in the passed update closure using the
// update transaction.
func (t *TaroTreeStore) Update(ctx context.Context,
	update func(tx mssmt.TreeStoreUpdateTx) error) error {

	txBody := func(dbTx TreeStore) error {
		updateTx := &taroTreeStoreTx{
			ctx:  ctx,
			dbTx: dbTx,
		}

		return update(updateTx)
	}

	var writeTxOpts TreeStoreTxOptions
	return t.db.ExecTx(ctx, &writeTxOpts, txBody)
}

// View gives a view of the persistent tree in the passed view closure using
// the view transaction.
func (t *TaroTreeStore) View(ctx context.Context,
	update func(tx mssmt.TreeStoreViewTx) error) error {

	txBody := func(dbTx TreeStore) error {
		viewTx := &taroTreeStoreTx{
			ctx:  ctx,
			dbTx: dbTx,
		}

		return update(viewTx)
	}

	readTxOpts := TreeStoreTxOptions{
		readOnly: true,
	}

	return t.db.ExecTx(ctx, &readTxOpts, txBody)
}

type taroTreeStoreTx struct {
	ctx  context.Context
	dbTx TreeStore
}

// InsertBranch stores a new branch keyed by its NodeHash.
func (t *taroTreeStoreTx) InsertBranch(branch *mssmt.BranchNode) error {
	hashKey := branch.NodeHash()
	lHashKey := branch.Left.NodeHash()
	rHashKey := branch.Right.NodeHash()

	if err := t.dbTx.InsertBranch(t.ctx, NewBranch{
		HashKey:  hashKey[:],
		LHashKey: lHashKey[:],
		RHashKey: rHashKey[:],
		Sum:      int64(branch.NodeSum()),
	}); err != nil {
		return fmt.Errorf("unable to insert branch: %w", err)
	}

	return nil
}

// InsertLeaf stores a new leaf keyed by its NodeHash (not the insertion key).
func (t *taroTreeStoreTx) InsertLeaf(leaf *mssmt.LeafNode) error {
	hashKey := leaf.NodeHash()

	if err := t.dbTx.InsertLeaf(t.ctx, NewLeaf{
		HashKey: hashKey[:],
		Value:   leaf.Value,
		Sum:     int64(leaf.NodeSum()),
	}); err != nil {
		return fmt.Errorf("unable to insert leaf: %w", err)
	}

	return nil
}

// InsertCompactedLeaf stores a new compacted leaf keyed by its
// NodeHash (not the insertion key).
func (t *taroTreeStoreTx) InsertCompactedLeaf(
	leaf *mssmt.CompactedLeafNode) error {

	hashKey := leaf.NodeHash()
	key := leaf.Key()

	if err := t.dbTx.InsertCompactedLeaf(t.ctx, NewCompactedLeaf{
		HashKey: hashKey[:],
		Key:     key[:],
		Value:   leaf.Value,
		Sum:     int64(leaf.NodeSum()),
	}); err != nil {
		return fmt.Errorf("unable to insert compacted leaf: %w", err)
	}

	return nil
}

// DeleteBranch deletes the branch node keyed by the given NodeHash.
func (t *taroTreeStoreTx) DeleteBranch(hashKey mssmt.NodeHash) error {
	_, err := t.dbTx.DeleteNode(t.ctx, hashKey[:])
	return err
}

// DeleteLeaf deletes the leaf node keyed by the given NodeHash.
func (t *taroTreeStoreTx) DeleteLeaf(hashKey mssmt.NodeHash) error {
	_, err := t.dbTx.DeleteNode(t.ctx, hashKey[:])
	return err
}

// DeleteCompactedLeaf deletes a compacted leaf keyed by the given NodeHash.
func (t *taroTreeStoreTx) DeleteCompactedLeaf(hashKey mssmt.NodeHash) error {
	_, err := t.dbTx.DeleteNode(t.ctx, hashKey[:])
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
func (t *taroTreeStoreTx) GetChildren(height int, hashKey mssmt.NodeHash) (
	mssmt.Node, mssmt.Node, error) {

	dbRows, err := t.dbTx.FetchChildren(t.ctx, hashKey[:])
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
