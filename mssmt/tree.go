package mssmt

import (
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/mssmt/arith"
)

const (
	// MaxTreeLevels represents the depth of the MS-SMT.
	MaxTreeLevels = hashSize * 8

	// lastBitIndex represents the index of the last bit for MS-SMT keys.
	lastBitIndex = MaxTreeLevels - 1
)

var (
	// EmptyTree stores a copy of all nodes up to the root in a MS-SMT in
	// which all the leaves are empty.
	EmptyTree []Node

	// EmptyTreeRootHash caches the value of a completely empty tree's root
	// hash. This can be used to detect a tree's emptiness without needing
	// to rely on the root sum alone.
	EmptyTreeRootHash NodeHash

	// ErrIntegerOverflow is an error returned when the result of an
	// arithmetic operation on two integer values exceeds the maximum value
	// that can be stored in the data type.
	ErrIntegerOverflow = arith.ErrOverflow
)

func init() {
	// Force the calculation of the node key for the empty node. This will
	// ensure the value is fully cached for the loop below.
	EmptyLeafNode.NodeHash()

	// Initialize the empty MS-SMT by starting from an empty leaf and
	// hashing all the way up to the root.
	EmptyTree = make([]Node, MaxTreeLevels+1)
	EmptyTree[MaxTreeLevels] = EmptyLeafNode
	for i := lastBitIndex; i >= 0; i-- {
		// Create the branch and force the calculation of the node key.
		// At this point we already have computed the keys of each of
		// the siblings, so those cached values can be used here. If we
		// don't do this, then concurrent callers will attempt to
		// read/populate this value causing a race condition.
		branch := NewBranch(EmptyTree[i+1], EmptyTree[i+1])
		branch.NodeHash()
		branch.NodeSum()

		EmptyTree[i] = branch
	}

	EmptyTreeRootHash = EmptyTree[0].NodeHash()
}

// FullTree represents a Merkle-Sum Sparse Merkle Tree (MS-SMT). A MS-SMT is an
// augmented version of a sparse merkle tree that includes a sum value, which is
// combined during the internal branch hashing operation. Such trees permit
// efficient proofs of non-inclusion, while also supporting efficient fault
// proofs of invalid merkle sum commitments.
type FullTree struct {
	store TreeStore
}

var _ Tree = (*FullTree)(nil)

// NewFullTree initializes an empty MS-SMT backed by `store`. As a result,
// `store` will only maintain non-empty relevant nodes, i.e., stale parents are
// deleted and empty nodes are never stored.
func NewFullTree(store TreeStore) *FullTree {
	return &FullTree{
		store: store,
	}
}

// Root returns the root node of the MS-SMT.
func (t *FullTree) Root(ctx context.Context) (*BranchNode, error) {
	var root Node
	err := t.store.View(ctx, func(tx TreeStoreViewTx) error {
		var err error
		root, err = tx.RootNode()
		return err
	})
	if err != nil {
		return nil, err
	}

	return root.(*BranchNode), nil
}

// bitIndex returns the bit found at `idx` for a NodeHash.
func bitIndex(idx uint8, key *[hashSize]byte) byte {
	byteVal := key[idx/8]
	return (byteVal >> (idx % 8)) & 1
}

// setBit returns a copy of the key with the bit at the given depth set to 1.
func setBit(key [hashSize]byte, depth int) [hashSize]byte {
	byteIndex := depth / 8
	bitIndex := depth % 8
	key[byteIndex] |= (1 << bitIndex)
	return key
}

// iterFunc is a type alias for closures to be invoked at every iteration of
// walking through a tree.
type iterFunc = func(height int, current, sibling, parent Node) error

// walkDown walks down the tree from the root node to the leaf indexed by `key`.
// The leaf node found is returned.
func (t *FullTree) walkDown(tx TreeStoreViewTx, key *[hashSize]byte,
	iter iterFunc) (*LeafNode, error) {

	current, err := tx.RootNode()
	if err != nil {
		return nil, err
	}

	for i := 0; i <= lastBitIndex; i++ {
		left, right, err := tx.GetChildren(i, current.NodeHash())
		if err != nil {
			return nil, err
		}

		var next, sibling Node
		if bitIndex(uint8(i), key) == 0 {
			next, sibling = left, right
		} else {
			next, sibling = right, left
		}
		if iter != nil {
			err := iter(i, next, sibling, current)
			if err != nil {
				return nil, err
			}
		}
		current = next
	}

	return current.(*LeafNode), nil
}

// walkUp walks up from the `start` leaf node up to the root with the help of
// `siblings`. The root branch node computed is returned.
func walkUp(key *[hashSize]byte, start Node, siblings []Node,
	iter iterFunc) (*BranchNode, error) {

	var current = start
	for i := lastBitIndex; i >= 0; i-- {
		sibling := siblings[lastBitIndex-i]
		if err := arith.CheckAdd(
			current.NodeSum(), sibling.NodeSum(),
		); err != nil {
			return nil, fmt.Errorf("proof branch sum error at "+
				"level %d: %w", i, err)
		}

		var parent Node
		if bitIndex(uint8(i), key) == 0 {
			parent = NewBranch(current, sibling)
		} else {
			parent = NewBranch(sibling, current)
		}
		if iter != nil {
			err := iter(i, current, sibling, parent)
			if err != nil {
				return nil, err
			}
		}
		current = parent
	}

	return current.(*BranchNode), nil
}

// insert builds the mutation queue for inserting (or deleting, when
// leaf is empty) a leaf at key. It performs only reads against tx; all
// writes are appended to muts so the caller can run overflow / parity
// checks before any storage state is touched.
//
// The returned priorSum is the sum of the leaf currently at key (zero
// if none), letting the caller compute an effective batch delta for
// the overflow check without doing a second walk.
func (t *FullTree) insert(tx TreeStoreUpdateTx, key *[hashSize]byte,
	leaf *LeafNode, muts *[]mutation) (root *BranchNode, priorSum uint64,
	err error) {

	// As we walk down to the leaf node, we'll keep track of the sibling
	// and parent for each node we visit. walkDown's return value is the
	// existing leaf at key (or empty); its sum is the priorSum the
	// overflow check needs.
	prevParents := make([]NodeHash, MaxTreeLevels)
	siblings := make([]Node, MaxTreeLevels)
	priorLeaf, err := t.walkDown(
		tx, key, func(i int, _, sibling, parent Node) error {
			prevParents[MaxTreeLevels-1-i] = parent.NodeHash()
			siblings[MaxTreeLevels-1-i] = sibling
			return nil
		})
	if err != nil {
		return nil, 0, err
	}
	if priorLeaf != nil && !priorLeaf.IsEmpty() {
		priorSum = priorLeaf.NodeSum()
	}

	// Now that we've arrived at the leaf node, we'll need to work our way
	// back up to the root, queuing storage writes for any stale and new
	// intermediate branch nodes.
	root, err = walkUp(
		key, leaf, siblings, func(i int, _, _, parent Node) error {
			// Replace the old parent with the new one. Our store
			// should never track empty branches.
			prevParent := prevParents[MaxTreeLevels-1-i]
			if prevParent != EmptyTree[i].NodeHash() {
				deleteBranch(muts, prevParent)
			}

			if parent.NodeHash() != EmptyTree[i].NodeHash() {
				insertBranch(muts, parent.(*BranchNode))
			}

			return nil
		},
	)
	if err != nil {
		return nil, 0, err
	}

	// Queue the per-leaf storage write. An empty leaf is a deletion at
	// key; a non-empty leaf is an insert/replacement.
	if leaf.IsEmpty() {
		deleteLeaf(muts, *key)
	} else {
		insertLeaf(muts, leaf)
	}

	return root, priorSum, nil
}

// Insert inserts a leaf node at the given key within the MS-SMT.
func (t *FullTree) Insert(ctx context.Context, key [hashSize]byte,
	leaf *LeafNode) (Tree, error) {

	err := t.store.Update(ctx, func(tx TreeStoreUpdateTx) error {
		currentRoot, err := tx.RootNode()
		if err != nil {
			return err
		}
		rootBranch := currentRoot.(*BranchNode)

		// Run the descent read-only: insert builds up a mutation
		// queue and reports priorSum (the sum of any existing leaf
		// being replaced). No storage state has changed yet.
		// Single Insert queues at most one delete+insert per
		// level plus one leaf write; pre-size to skip the
		// doubling tail.
		muts := make([]mutation, 0, singleInsertMutsCap)
		root, priorSum, err := t.insert(tx, &key, leaf, &muts)
		if err != nil {
			return err
		}

		// Effective-delta overflow check. Replacing a large leaf
		// with a small one drops the prior sum out of the root, so
		// the conservative rootSum + newSum check would reject
		// inputs that sequential Insert would accept.
		sumLeaf := leaf.NodeSum()
		if sumLeaf > priorSum {
			delta := sumLeaf - priorSum
			err := arith.CheckAdd(
				rootBranch.NodeSum(), delta,
			)
			if err != nil {
				return fmt.Errorf("full tree leaf insert "+
					"sum error, root: %d, effective "+
					"delta: %d; %w",
					rootBranch.NodeSum(), delta, err)
			}
		}

		// Flush the queued storage writes and update the root.
		if err := applyAll(tx, muts); err != nil {
			return err
		}
		return tx.UpdateRoot(root)
	})
	if err != nil {
		return nil, err
	}

	return t, nil
}

// Delete deletes the leaf node found at the given key within the MS-SMT.
func (t *FullTree) Delete(ctx context.Context, key [hashSize]byte) (
	Tree, error) {

	err := t.store.Update(ctx, func(tx TreeStoreUpdateTx) error {
		// Delete cannot increase the root sum, so the overflow
		// check is skipped; we just plan and flush.
		muts := make([]mutation, 0, singleInsertMutsCap)
		root, _, err := t.insert(tx, &key, EmptyLeafNode, &muts)
		if err != nil {
			return err
		}

		if err := applyAll(tx, muts); err != nil {
			return err
		}
		return tx.UpdateRoot(root)
	})
	if err != nil {
		return nil, err
	}

	return t, nil
}

// DeleteRoot deletes the root node of the MS-SMT.
func (t *FullTree) DeleteRoot(ctx context.Context) error {
	return t.store.Update(ctx, func(tx TreeStoreUpdateTx) error {
		return tx.DeleteRoot()
	})
}

// DeleteAllNodes deletes all nodes in the MS-SMT.
func (t *FullTree) DeleteAllNodes(ctx context.Context) error {
	return t.store.Update(ctx, func(tx TreeStoreUpdateTx) error {
		return tx.DeleteAllNodes()
	})
}

// Get returns the leaf node found at the given key within the MS-SMT.
func (t *FullTree) Get(ctx context.Context, key [hashSize]byte) (
	*LeafNode, error) {

	var leaf *LeafNode
	err := t.store.View(ctx, func(tx TreeStoreViewTx) error {
		var err error
		leaf, err = t.walkDown(tx, &key, nil)
		return err
	})
	if err != nil {
		return nil, err
	}

	return leaf, nil
}

// MerkleProof generates a merkle proof for the leaf node found at the given key
// within the MS-SMT. If a leaf node does not exist at the given key, then the
// proof should be considered a non-inclusion proof. This is noted by the
// returned `Proof` containing an empty leaf.
func (t *FullTree) MerkleProof(ctx context.Context, key [hashSize]byte) (
	*Proof, error) {

	proof := make([]Node, MaxTreeLevels)
	err := t.store.View(ctx, func(tx TreeStoreViewTx) error {
		_, err := t.walkDown(
			tx, &key, func(i int, _, sibling, _ Node) error {
				proof[MaxTreeLevels-1-i] = sibling
				return nil
			},
		)
		return err
	})
	if err != nil {
		return nil, err
	}

	return NewProof(proof), nil
}

// findLeaves recursively traverses the tree represented by the given node and
// collects all non-empty leaf nodes along with their reconstructed keys.
func findLeaves(ctx context.Context, tx TreeStoreViewTx, node Node,
	keyPrefix [hashSize]byte,
	depth int) (map[[hashSize]byte]*LeafNode, error) {

	// Base case: If it's a leaf node.
	if leafNode, ok := node.(*LeafNode); ok {
		if leafNode.IsEmpty() {
			return make(map[[hashSize]byte]*LeafNode), nil
		}
		return map[[hashSize]byte]*LeafNode{keyPrefix: leafNode}, nil
	}

	// Recursive step: If it's a branch node.
	if branchNode, ok := node.(*BranchNode); ok {
		// Optimization: if the branch is empty, return early.
		if IsEqualNode(branchNode, EmptyTree[depth]) {
			return make(map[[hashSize]byte]*LeafNode), nil
		}

		left, right, err := tx.GetChildren(depth, branchNode.NodeHash())
		if err != nil {
			return nil, fmt.Errorf("error getting children for "+
				"branch %s at depth %d: %w",
				branchNode.NodeHash(), depth, err)
		}

		// Recursively find leaves in the left subtree. The key prefix
		// remains the same as the 0 bit is implicitly handled by the
		// initial keyPrefix state.
		leftLeaves, err := findLeaves(
			ctx, tx, left, keyPrefix, depth+1,
		)
		if err != nil {
			return nil, err
		}

		// Recursively find leaves in the right subtree. Set the bit
		// corresponding to the current depth in the key prefix.
		rightKeyPrefix := setBit(keyPrefix, depth)

		rightLeaves, err := findLeaves(
			ctx, tx, right, rightKeyPrefix, depth+1,
		)
		if err != nil {
			return nil, err
		}

		// Merge the results.
		for k, v := range rightLeaves {
			leftLeaves[k] = v
		}
		return leftLeaves, nil
	}

	// Handle unexpected node types.
	return nil, fmt.Errorf("unexpected node type %T encountered "+
		"during leaf collection", node)
}

// Copy copies all the key-value pairs from the source tree into the target
// tree.
func (t *FullTree) Copy(ctx context.Context, targetTree Tree) error {
	var leaves map[[hashSize]byte]*LeafNode
	err := t.store.View(ctx, func(tx TreeStoreViewTx) error {
		root, err := tx.RootNode()
		if err != nil {
			return fmt.Errorf("error getting root node: %w", err)
		}

		// Optimization: If the source tree is empty, there's nothing
		// to copy.
		if IsEqualNode(root, EmptyTree[0]) {
			leaves = make(map[[hashSize]byte]*LeafNode)
			return nil
		}

		leaves, err = findLeaves(ctx, tx, root, [hashSize]byte{}, 0)
		if err != nil {
			return fmt.Errorf("error finding leaves: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Insert all found leaves into the target tree using InsertMany for
	// efficiency.
	_, err = targetTree.InsertMany(ctx, leaves)
	if err != nil {
		return fmt.Errorf("error inserting leaves into target "+
			"tree: %w", err)
	}

	return nil
}

// CopyFilter copies all the key-value pairs from the source tree into the
// target tree that pass the filter callback. The filter callback is invoked for
// each leaf-key pair.
func (t *FullTree) CopyFilter(ctx context.Context, targetTree Tree,
	filterFunc CopyFilterPredicate) error {

	var leaves map[[hashSize]byte]*LeafNode
	err := t.store.View(ctx, func(tx TreeStoreViewTx) error {
		root, err := tx.RootNode()
		if err != nil {
			return fmt.Errorf("error getting root node: %w", err)
		}

		// Optimization: If the source tree is empty, there's nothing
		// to copy.
		if IsEqualNode(root, EmptyTree[0]) {
			leaves = make(map[[hashSize]byte]*LeafNode)
			return nil
		}

		leaves, err = findLeaves(ctx, tx, root, [hashSize]byte{}, 0)
		if err != nil {
			return fmt.Errorf("error finding leaves: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Pass the leaves through the filter callback.
	if filterFunc != nil {
		var filteredLeaves = make(map[[hashSize]byte]*LeafNode)

		for leafKey, leafNode := range leaves {
			include, err := filterFunc(leafKey, *leafNode)
			if err != nil {
				return fmt.Errorf("filter function for key "+
					"%x: %w", leafKey, err)
			}

			if include {
				filteredLeaves[leafKey] = leafNode
			}
		}

		leaves = filteredLeaves
	}

	// Insert all found leaves into the target tree using InsertMany for
	// efficiency.
	_, err = targetTree.InsertMany(ctx, leaves)
	if err != nil {
		return fmt.Errorf("error inserting leaves into target "+
			"tree: %w", err)
	}

	return nil
}

// batchItem pairs an (immutable) key with its leaf for the batched
// insert recursion.
type batchItem struct {
	key  [hashSize]byte
	leaf *LeafNode
}

// mutsCap returns the starting capacity for an InsertMany mutation
// queue. The actual queue length depends on the tree shape (random
// keys produce O(N) mutations on CompactedTree thanks to subtree
// compaction; FullTree pays more on pathologically-deep batches)
// but a small linear-in-N starting cap covers the common case
// without holding a large unused buffer.
func mutsCap(n int) int {
	if n < 16 {
		return 32
	}
	return n * 4
}

// singleInsertMutsCap is the starting cap for the mutation queue
// of a single Insert/Delete. Covers the typical compacted-tree
// descent (~log(N) levels touched) without over-allocating; the
// rare FullTree pathological worst case (513) absorbs a few extra
// doublings, which is in the noise relative to the descent's own
// allocations.
const singleInsertMutsCap = 64

// InsertMany inserts multiple leaf nodes provided in the leaves map within a
// single database transaction. Internal nodes shared by multiple inserted
// leaves are computed once per batch, not once per leaf, so the per-call
// cost approaches O(N log N + N) rather than O(N * MaxTreeLevels).
func (t *FullTree) InsertMany(ctx context.Context,
	leaves map[[hashSize]byte]*LeafNode) (Tree, error) {

	if len(leaves) == 0 {
		return t, nil
	}

	// Materialise items in a slice the recursion can partition. The map
	// iteration order is unstable but the resulting tree is order-
	// independent, so any iteration order is fine.
	items := make([]batchItem, 0, len(leaves))
	var batchSum uint64
	for key, leaf := range leaves {
		items = append(items, batchItem{key: key, leaf: leaf})
		nextSum, err := arith.Add(batchSum, leaf.NodeSum()).Unpack()
		if err != nil {
			return nil, fmt.Errorf("full tree batch insert sum "+
				"error: %w", err)
		}
		batchSum = nextSum
	}

	err := t.store.Update(ctx, func(tx TreeStoreUpdateTx) error {
		currentRoot, err := tx.RootNode()
		if err != nil {
			return err
		}
		rootBranch := currentRoot.(*BranchNode)

		// batchInsert reads the tree, builds the new subtree in
		// memory, collects existingBatchSum (the sum of any leaves
		// at batch keys being replaced) and queues all storage
		// writes into muts. No store mutation yet.
		muts := make([]mutation, 0, mutsCap(len(items)))
		newRoot, existingBatchSum, err := t.batchInsert(
			tx, items, currentRoot, 0, &muts,
		)
		if err != nil {
			return fmt.Errorf("batch insert: %w", err)
		}

		// Effective-delta overflow check. Identical shape to the
		// single Insert check; rides on the descent that just
		// happened — no extra walks needed.
		if batchSum > existingBatchSum {
			delta := batchSum - existingBatchSum
			err := arith.CheckAdd(
				rootBranch.NodeSum(), delta,
			)
			if err != nil {
				return fmt.Errorf("full tree batch insert "+
					"sum error, root: %d, effective "+
					"delta: %d; %w",
					rootBranch.NodeSum(), delta, err)
			}
		}

		newRootBranch, ok := newRoot.(*BranchNode)
		if !ok {
			return fmt.Errorf("batch insert: unexpected root "+
				"node type %T", newRoot)
		}

		if err := applyAll(tx, muts); err != nil {
			return err
		}
		return tx.UpdateRoot(newRootBranch)
	})
	if err != nil {
		return nil, err
	}

	return t, nil
}

// batchInsert recursively descends into the subtree rooted at node,
// partitioning items by the bit at depth and computing the new
// subtree in memory. Storage writes are queued into muts rather than
// executed, so the caller can run the overflow check and flush only
// if it passes; existingSum returned by each recursive call is the
// sum of any leaves at batch keys that were replaced within that
// subtree, threaded up so the caller can compute the effective delta
// without a separate walk.
func (t *FullTree) batchInsert(tx TreeStoreUpdateTx, items []batchItem,
	node Node, depth int, muts *[]mutation) (Node, uint64, error) {

	if len(items) == 0 {
		return node, 0, nil
	}

	// At leaf depth, exactly one item lives here. The `node` parameter
	// is the prior leaf at this position (or EmptyLeafNode); its sum
	// is the existingSum we contribute to the overflow accounting.
	if depth == MaxTreeLevels {
		item := items[0]
		var existing uint64
		if prior, ok := node.(*LeafNode); ok && !prior.IsEmpty() {
			existing = prior.NodeSum()
		}
		if item.leaf.IsEmpty() {
			deleteLeaf(muts, item.key)
		} else {
			insertLeaf(muts, item.leaf)
		}
		return item.leaf, existing, nil
	}

	// Fetch the current children once for this whole subtree's update.
	left, right, err := tx.GetChildren(depth, node.NodeHash())
	if err != nil {
		return nil, 0, err
	}

	// Partition items by the next bit. Items whose bit is 0 go left.
	leftItems, rightItems := partitionByBit(items, depth)

	newLeft, newRight := left, right
	var leftSum, rightSum uint64
	if len(leftItems) > 0 {
		newLeft, leftSum, err = t.batchInsert(
			tx, leftItems, left, depth+1, muts,
		)
		if err != nil {
			return nil, 0, err
		}
	}
	if len(rightItems) > 0 {
		newRight, rightSum, err = t.batchInsert(
			tx, rightItems, right, depth+1, muts,
		)
		if err != nil {
			return nil, 0, err
		}
	}

	newParent, err := newCheckedBranch(newLeft, newRight)
	if err != nil {
		return nil, 0, fmt.Errorf("full tree batch insert sum "+
			"error at depth %d: %w", depth, err)
	}

	// Fast path: if the rebuilt parent has the same hash as the
	// existing branch (e.g., a one-sided batch where the recursed
	// side returned its subtree unchanged), the storage state at
	// this level is already correct — skip the delete + reinsert.
	if newParent.NodeHash() == node.NodeHash() {
		existingSum, err := arith.Add(leftSum, rightSum).Unpack()
		return node, existingSum, err
	}

	// Queue the old/new pair for this level. Mirrors the single-
	// insert walkUp emitter; both writes are deferred until the
	// caller verifies the overflow check passes.
	if node.NodeHash() != EmptyTree[depth].NodeHash() {
		deleteBranch(muts, node.NodeHash())
	}
	if newParent.NodeHash() != EmptyTree[depth].NodeHash() {
		insertBranch(muts, newParent)
	}

	existingSum, err := arith.Add(leftSum, rightSum).Unpack()
	return newParent, existingSum, err
}

// VerifyMerkleProof determines whether a merkle proof for the leaf found at the
// given key is valid.
func VerifyMerkleProof(key [hashSize]byte, leaf *LeafNode, proof *Proof,
	root Node) bool {

	if leaf == nil || proof == nil || root == nil {
		return false
	}
	if len(proof.Nodes) != MaxTreeLevels {
		return false
	}

	h, s, validSum := proof.rootSum(&key, leaf)
	if !validSum {
		return false
	}

	return h == root.NodeHash() && s == root.NodeSum()
}
