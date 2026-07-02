package mssmt

import (
	"context"
	"fmt"
	"math/bits"
)

// CompactedTree represents a compacted Merkle-Sum Sparse Merkle Tree (MS-SMT).
// The tree has the same properties as a normal MS-SMT tree and is able to
// create the same proofs and same root as the FullTree implemented in this
// package. The additional benefit of using the CompactedTree is that it will
// greatly reduce storage access resulting in more performant access when used
// for large trees.
type CompactedTree struct {
	store TreeStore
}

var _ Tree = (*CompactedTree)(nil)

// NewCompactedTree initializes an empty MS-SMT backed by `store`.
func NewCompactedTree(store TreeStore) *CompactedTree {
	return &CompactedTree{
		store: store,
	}
}

// Root returns the root node of the MS-SMT.
func (t *CompactedTree) Root(ctx context.Context) (*BranchNode, error) {
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

// stepOrder orders the passed branches according to our path given the key and
// the height.
func stepOrder(height int, key *[32]byte, left, right Node) (Node, Node) {
	if bitIndex(uint8(height), key) == 0 {
		return left, right
	}

	return right, left
}

// walkDown walks down the tree from the root node to the leaf indexed by `key`.
// The leaf node found is returned.
func (t *CompactedTree) walkDown(tx TreeStoreViewTx, key *[hashSize]byte,
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
		next, sibling := stepOrder(i, key, left, right)

		switch node := next.(type) {
		case *CompactedLeafNode:
			// Our next node is a compacted leaf. We just need to
			// expand it so we can continue our walk down the tree.
			next = node.Extract(i)

			// Sibling might be a compacted leaf too, in which case
			// we need to extract it as well.
			if compSibling, ok := sibling.(*CompactedLeafNode); ok {
				sibling = compSibling.Extract(i)
			}

			// Now that all required branches are reconstructed we
			// can continue the search for the leaf matching the
			// passed key.
			for j := i; j <= lastBitIndex; j++ {
				if iter != nil {
					err := iter(j, next, sibling, current)
					if err != nil {
						return nil, err
					}
				}
				current = next

				if j < lastBitIndex {
					// Since we have all the branches we
					// need extracted already we can just
					// continue walking down.
					branch := current.(*BranchNode)
					next, sibling = stepOrder(
						j+1, key, branch.Left,
						branch.Right,
					)
				}
			}

			return current.(*LeafNode), nil

		default:
			if iter != nil {
				err := iter(i, next, sibling, current)
				if err != nil {
					return nil, err
				}
			}
			current = next
		}
	}

	return current.(*LeafNode), nil
}

// merge is a helper function to create the common subtree from two leafs lying
// on the same (partial) path. The resulting subtree contains branch nodes from
// diverging bit of the passed key's. All storage writes are queued into muts.
func (t *CompactedTree) merge(height int, key1 [32]byte, leaf1 *LeafNode,
	key2 [32]byte, leaf2 *LeafNode,
	muts *[]mutation) *BranchNode {

	// Find the common prefix first.
	var commonPrefixLen int
	for i := 0; i <= lastBitIndex; i++ {
		if bitIndex(uint8(i), &key1) == bitIndex(uint8(i), &key2) {
			commonPrefixLen++
		} else {
			break
		}
	}

	// Now we create two compacted leaves and queue them as children
	// of a newly created branch.
	node1 := NewCompactedLeafNode(commonPrefixLen+1, &key1, leaf1)
	node2 := NewCompactedLeafNode(commonPrefixLen+1, &key2, leaf2)
	insertCompactedLeaf(muts, node1)
	insertCompactedLeaf(muts, node2)

	left, right := stepOrder(commonPrefixLen, &key1, node1, node2)
	parent := NewBranch(left, right)
	insertBranch(muts, parent)

	// From here we'll walk up to the current level and create branches
	// along the way. Optionally we could compact these branches too.
	for i := commonPrefixLen - 1; i >= height; i-- {
		left, right := stepOrder(i, &key1, parent, EmptyTree[i+1])
		parent = NewBranch(left, right)
		insertBranch(muts, parent)
	}

	return parent
}

// insert inserts the key at the current height either by adding a new compacted
// leaf, merging an existing leaf with the passed leaf in a new subtree or by
// recursing down further.
//
// All storage writes are queued into muts; reads still go through tx.
// priorSum is the sum of any leaf at the insertion key that was
// replaced (0 if none); it's threaded up so the public Insert can
// compute an effective overflow delta without a separate walk.
func (t *CompactedTree) insert(tx TreeStoreUpdateTx, key *[hashSize]byte,
	height int, root *BranchNode, leaf *LeafNode,
	muts *[]mutation) (branch *BranchNode, priorSum uint64, err error) {

	left, right, err := tx.GetChildren(height, root.NodeHash())
	if err != nil {
		return nil, 0, err
	}

	var next, sibling Node
	isLeft := bitIndex(uint8(height), key) == 0
	if isLeft {
		next, sibling = left, right
	} else {
		next, sibling = right, left
	}

	var newNode Node
	nextHeight := height + 1

	switch node := next.(type) {
	case *BranchNode:
		if node == EmptyTree[nextHeight] {
			// Empty subtree: collapse to a single compacted leaf
			// at nextHeight. No prior leaf existed at key.
			newLeaf := NewCompactedLeafNode(nextHeight, key, leaf)
			insertCompactedLeaf(muts, newLeaf)
			newNode = newLeaf
		} else {
			// Not an empty subtree, recurse to find the
			// insertion point.
			newNode, priorSum, err = t.insert(
				tx, key, nextHeight, node, leaf, muts,
			)
			if err != nil {
				return nil, 0, err
			}
		}

	case *CompactedLeafNode:
		// The compacted leaf at this position is always being
		// rewritten — queue its delete first.
		deleteCompactedLeaf(muts, node.NodeHash())

		if *key == node.key {
			// Replacement of an existing leaf at our key — its
			// sum is the priorSum we report.
			priorSum = node.LeafNode.NodeSum()

			if leaf.IsEmpty() {
				newNode = EmptyTree[nextHeight]
			} else {
				newLeaf := NewCompactedLeafNode(
					nextHeight, key, leaf,
				)
				insertCompactedLeaf(muts, newLeaf)
				newNode = newLeaf
			}
		} else {
			// Different key: the prior leaf isn't AT our key, so
			// priorSum stays 0 (merge relocates the existing
			// leaf into a new subtree alongside ours).
			newNode = t.merge(
				nextHeight, *key, leaf, node.key,
				node.LeafNode, muts,
			)
		}
	}

	// Queue the delete of the old root (unless it's the empty
	// placeholder), and the insert of the new branch (unless empty).
	if root != EmptyTree[height] {
		deleteBranch(muts, root.NodeHash())
	}

	if isLeft {
		branch = NewBranch(newNode, sibling)
	} else {
		branch = NewBranch(sibling, newNode)
	}

	if !IsEqualNode(branch, EmptyTree[height]) {
		insertBranch(muts, branch)
	}

	return branch, priorSum, nil
}

// Insert inserts a leaf node at the given key within the MS-SMT.
func (t *CompactedTree) Insert(ctx context.Context, key [hashSize]byte,
	leaf *LeafNode) (Tree, error) {

	dbErr := t.store.Update(ctx, func(tx TreeStoreUpdateTx) error {
		currentRoot, err := tx.RootNode()
		if err != nil {
			return err
		}
		rootBranch := currentRoot.(*BranchNode)

		// insert runs read-only: it builds the new tree shape in
		// memory, queues every write into muts and reports priorSum
		// (the sum of the leaf being replaced at key, or 0).
		muts := make([]mutation, 0, singleInsertMutsCap)
		root, priorSum, err := t.insert(
			tx, &key, 0, rootBranch, leaf, &muts,
		)
		if err != nil {
			return err
		}

		// Effective-delta overflow check; symmetric with the
		// FullTree variant.
		sumLeaf := leaf.NodeSum()
		if sumLeaf > priorSum {
			delta := sumLeaf - priorSum
			err := CheckSumOverflowUint64(
				rootBranch.NodeSum(), delta,
			)
			if err != nil {
				return fmt.Errorf("compact tree leaf "+
					"insert sum overflow, root: %d, "+
					"effective delta: %d; %w",
					rootBranch.NodeSum(), delta, err)
			}
		}

		if err := applyAll(tx, muts); err != nil {
			return err
		}
		return tx.UpdateRoot(root)
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return t, nil
}

// Delete deletes the leaf node found at the given key within the MS-SMT.
func (t *CompactedTree) Delete(ctx context.Context, key [hashSize]byte) (
	Tree, error) {

	err := t.store.Update(ctx, func(tx TreeStoreUpdateTx) error {
		currentRoot, err := tx.RootNode()
		if err != nil {
			return err
		}

		// Delete cannot increase the root sum, so the overflow
		// check is skipped; we just plan and flush.
		muts := make([]mutation, 0, singleInsertMutsCap)
		root, _, err := t.insert(
			tx, &key, 0, currentRoot.(*BranchNode),
			EmptyLeafNode, &muts,
		)
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
func (t *CompactedTree) DeleteRoot(ctx context.Context) error {
	return t.store.Update(ctx, func(tx TreeStoreUpdateTx) error {
		return tx.DeleteRoot()
	})
}

// DeleteAllNodes deletes all nodes in the MS-SMT.
func (t *CompactedTree) DeleteAllNodes(ctx context.Context) error {
	return t.store.Update(ctx, func(tx TreeStoreUpdateTx) error {
		return tx.DeleteAllNodes()
	})
}

// Get returns the leaf node found at the given key within the MS-SMT.
func (t *CompactedTree) Get(ctx context.Context, key [hashSize]byte) (
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
func (t *CompactedTree) MerkleProof(ctx context.Context, key [hashSize]byte) (
	*Proof, error) {

	proof := make([]Node, MaxTreeLevels)
	err := t.store.View(ctx, func(tx TreeStoreViewTx) error {
		var err error
		_, err = t.walkDown(
			tx, &key, func(i int, _, sibling, _ Node) error {
				sibling.NodeHash()
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

// collectLeavesRecursive is a recursive helper function that's used to traverse
// down an MS-SMT tree and collect all leaf nodes. It returns a map of leaf
// nodes indexed by their hash.
func collectLeavesRecursive(ctx context.Context, tx TreeStoreViewTx, node Node,
	depth int) (map[[hashSize]byte]*LeafNode, error) {

	// Base case: If it's a compacted leaf node.
	if compactedLeaf, ok := node.(*CompactedLeafNode); ok {
		if compactedLeaf.LeafNode.IsEmpty() {
			return make(map[[hashSize]byte]*LeafNode), nil
		}
		return map[[hashSize]byte]*LeafNode{
			compactedLeaf.Key(): compactedLeaf.LeafNode,
		}, nil
	}

	// Recursive step: If it's a branch node.
	if branchNode, ok := node.(*BranchNode); ok {
		// Optimization: if the branch is empty, return early.
		if depth < MaxTreeLevels &&
			IsEqualNode(branchNode, EmptyTree[depth]) {

			return make(map[[hashSize]byte]*LeafNode), nil
		}

		// Handle case where depth might exceed EmptyTree bounds if
		// logic error exists
		if depth >= MaxTreeLevels {
			// This shouldn't happen if called correctly, implies a
			// leaf.
			return nil, fmt.Errorf("invalid depth %d for branch "+
				"node", depth)
		}

		left, right, err := tx.GetChildren(depth, branchNode.NodeHash())
		if err != nil {
			// If children not found, it might be an empty branch
			// implicitly Check if the error indicates "not found"
			// or similar Depending on store impl, this might be how
			// empty is signaled For now, treat error as fatal.
			return nil, fmt.Errorf("error getting children for "+
				"branch %s at depth %d: %w",
				branchNode.NodeHash(), depth, err)
		}

		leftLeaves, err := collectLeavesRecursive(
			ctx, tx, left, depth+1,
		)
		if err != nil {
			return nil, err
		}

		rightLeaves, err := collectLeavesRecursive(
			ctx, tx, right, depth+1,
		)
		if err != nil {
			return nil, err
		}

		// Merge the results.
		for k, v := range rightLeaves {
			// Check for duplicate keys, although this shouldn't
			// happen in a valid SMT.
			if _, exists := leftLeaves[k]; exists {
				return nil, fmt.Errorf("duplicate key %x "+
					"found during leaf collection", k)
			}
			leftLeaves[k] = v
		}

		return leftLeaves, nil
	}

	// Handle unexpected node types or implicit empty nodes. If node is nil
	// or explicitly an EmptyLeafNode representation
	if node == nil || IsEqualNode(node, EmptyLeafNode) {
		return make(map[[hashSize]byte]*LeafNode), nil
	}

	// Check against EmptyTree branches if possible (requires depth)
	if depth < MaxTreeLevels && IsEqualNode(node, EmptyTree[depth]) {
		return make(map[[hashSize]byte]*LeafNode), nil
	}

	return nil, fmt.Errorf("unexpected node type %T encountered "+
		"during leaf collection at depth %d", node, depth)
}

// Copy copies all the key-value pairs from the source tree into the target
// tree.
func (t *CompactedTree) Copy(ctx context.Context, targetTree Tree) error {
	var leaves map[[hashSize]byte]*LeafNode
	err := t.store.View(ctx, func(tx TreeStoreViewTx) error {
		root, err := tx.RootNode()
		if err != nil {
			return fmt.Errorf("error getting root node: %w", err)
		}

		// Optimization: If the source tree is empty, there's nothing to
		// copy.
		if IsEqualNode(root, EmptyTree[0]) {
			leaves = make(map[[hashSize]byte]*LeafNode)
			return nil
		}

		// Start recursive collection from the root at depth 0.
		leaves, err = collectLeavesRecursive(ctx, tx, root, 0)
		if err != nil {
			return fmt.Errorf("error collecting leaves: %w", err)
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
		return fmt.Errorf("error inserting leaves into "+
			"target tree: %w", err)
	}

	return nil
}

// CopyFilter copies all the key-value pairs from the source tree into the
// target tree that pass the filter callback. The filter callback is invoked for
// each leaf-key pair.
func (t *CompactedTree) CopyFilter(ctx context.Context, targetTree Tree,
	filterFunc CopyFilterPredicate) error {

	var leaves map[[hashSize]byte]*LeafNode
	err := t.store.View(ctx, func(tx TreeStoreViewTx) error {
		root, err := tx.RootNode()
		if err != nil {
			return fmt.Errorf("error getting root node: %w", err)
		}

		// Optimization: If the source tree is empty, there's nothing to
		// copy.
		if IsEqualNode(root, EmptyTree[0]) {
			leaves = make(map[[hashSize]byte]*LeafNode)
			return nil
		}

		// Start recursive collection from the root at depth 0.
		leaves, err = collectLeavesRecursive(ctx, tx, root, 0)
		if err != nil {
			return fmt.Errorf("error collecting leaves: %w", err)
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
		return fmt.Errorf("error inserting leaves into "+
			"target tree: %w", err)
	}

	return nil
}

// InsertMany inserts multiple leaf nodes provided in the leaves map within a
// single database transaction. Internal nodes shared by multiple inserted
// leaves are computed once per batch, not once per leaf, so the per-call
// cost approaches O(N log N + N) rather than O(N * MaxTreeLevels).
func (t *CompactedTree) InsertMany(ctx context.Context,
	leaves map[[hashSize]byte]*LeafNode) (Tree, error) {

	if len(leaves) == 0 {
		return t, nil
	}

	items := make([]batchItem, 0, len(leaves))
	var batchSum uint64
	for key, leaf := range leaves {
		items = append(items, batchItem{key: key, leaf: leaf})
		nextSum, carry := bits.Add64(batchSum, leaf.NodeSum(), 0)
		if carry != 0 {
			return nil, fmt.Errorf("compact tree batch insert "+
				"sum overflow: %w", ErrIntegerOverflow)
		}
		batchSum = nextSum
	}

	dbErr := t.store.Update(ctx, func(tx TreeStoreUpdateTx) error {
		currentRoot, err := tx.RootNode()
		if err != nil {
			return err
		}
		rootBranch := currentRoot.(*BranchNode)

		// batchInsert reads the tree, builds the new subtree in
		// memory, collects existingBatchSum and queues writes into
		// muts. No mutation has touched storage yet — the overflow
		// check can reject the batch atomically.
		muts := make([]mutation, 0, mutsCap(len(items)))
		newRoot, existingBatchSum, err := t.batchInsert(
			tx, items, currentRoot, 0, &muts,
		)
		if err != nil {
			return fmt.Errorf("batch insert: %w", err)
		}

		if batchSum > existingBatchSum {
			delta := batchSum - existingBatchSum
			err := CheckSumOverflowUint64(
				rootBranch.NodeSum(), delta,
			)
			if err != nil {
				return fmt.Errorf("compact tree batch "+
					"insert sum overflow, root: %d, "+
					"effective delta: %d; %w",
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
	if dbErr != nil {
		return nil, dbErr
	}

	return t, nil
}

// batchInsert applies a set of items to the subtree rooted at node,
// located at depth. It mirrors the dispatch in CompactedTree.insert
// (empty branch / non-empty branch / compacted leaf) but processes
// the whole batch in one descent, materialising each touched internal
// node exactly once. All storage writes are queued into muts; reads
// still go through tx. existingSum returned is the sum of any leaves
// at batch keys that are being replaced within this subtree, threaded
// up so the public InsertMany wrapper can run the overflow check
// without a separate walk.
func (t *CompactedTree) batchInsert(tx TreeStoreUpdateTx,
	items []batchItem, node Node, depth int,
	muts *[]mutation) (Node, uint64, error) {

	if len(items) == 0 {
		return node, 0, nil
	}

	// A compacted leaf at this depth represents a single existing
	// leaf somewhere in this subtree. Absorb its (key, leaf) into the
	// batch — unless one of our items already overwrites the same
	// key — then rebuild the subtree from scratch.
	if cl, ok := node.(*CompactedLeafNode); ok {
		var overwritten, anyNonEmpty bool
		for _, item := range items {
			if item.key == cl.key {
				overwritten = true
			}
			if !item.leaf.IsEmpty() {
				anyNonEmpty = true
			}
		}

		// Fast path: the batch contains only deletes of absent
		// keys (none target cl.key) and inserts nothing. The
		// rebuild would re-emit cl unchanged, so skip the
		// delete-then-reinsert churn entirely.
		if !overwritten && !anyNonEmpty {
			return node, 0, nil
		}

		deleteCompactedLeaf(muts, cl.NodeHash())

		var existingSum uint64
		if overwritten {
			// The existing leaf is being replaced — contribute
			// its sum to existingSum.
			existingSum = cl.LeafNode.NodeSum()
		} else {
			// No batch item touches this key; absorb the
			// existing leaf so it survives the rebuild. The
			// absorbed sum is not a "replacement" — it stays
			// in the tree — so it does NOT contribute to
			// existingSum.
			items = append(items, batchItem{
				key: cl.key, leaf: cl.LeafNode,
			})
		}
		built, err := t.buildSubtree(items, depth, muts)
		if err != nil {
			return nil, 0, err
		}
		return built, existingSum, nil
	}

	branch := node.(*BranchNode)

	// An empty subtree at this depth: build from scratch. buildSubtree
	// will compact down to a single CompactedLeafNode when the batch
	// reduces to one non-empty leaf. We gate this on depth > 0
	// because the root node must remain a *BranchNode. No prior
	// leaves exist here, so existingSum is zero.
	if depth > 0 && branch.NodeHash() == EmptyTree[depth].NodeHash() {
		built, err := t.buildSubtree(items, depth, muts)
		if err != nil {
			return nil, 0, err
		}
		return built, 0, nil
	}

	// Non-empty branch: fetch children once, partition items by the
	// next bit, recurse into each non-empty side.
	left, right, err := tx.GetChildren(depth, branch.NodeHash())
	if err != nil {
		return nil, 0, err
	}

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

	newParent := NewBranch(newLeft, newRight)

	// Fast path: if the rebuilt parent matches the existing branch
	// (e.g., a one-sided batch where the recursed side returned its
	// subtree unchanged), the storage state at this level is
	// already correct — skip the delete + reinsert churn.
	if newParent.NodeHash() == branch.NodeHash() {
		return branch, leftSum + rightSum, nil
	}

	if branch.NodeHash() != EmptyTree[depth].NodeHash() {
		deleteBranch(muts, branch.NodeHash())
	}
	if newParent.NodeHash() != EmptyTree[depth].NodeHash() {
		insertBranch(muts, newParent)
	}

	return newParent, leftSum + rightSum, nil
}

// buildSubtree constructs a subtree at depth from a fresh item set,
// applying compaction at the natural boundary: zero non-empty items
// → empty subtree; exactly one non-empty item → CompactedLeafNode at
// this depth; two or more → partition and recurse, queuing one
// branch per touched level. No reads; all writes are queued into
// muts.
//
// items must be uniquely owned by the caller — buildSubtree compacts
// in place via items[:0]. Currently every caller passes a slice
// returned from partitionByBit or freshly extended in batchInsert's
// CompactedLeafNode branch, so the invariant holds; a future caller
// that wants to retain items must copy first.
func (t *CompactedTree) buildSubtree(items []batchItem, depth int,
	muts *[]mutation) (Node, error) {

	// Filter deletions of absent keys: an empty leaf into an empty
	// subtree is a no-op.
	nonEmpty := items[:0]
	for _, item := range items {
		if !item.leaf.IsEmpty() {
			nonEmpty = append(nonEmpty, item)
		}
	}
	items = nonEmpty

	if len(items) == 0 {
		return EmptyTree[depth], nil
	}

	if len(items) == 1 {
		item := items[0]
		clNode := NewCompactedLeafNode(depth, &item.key, item.leaf)
		insertCompactedLeaf(muts, clNode)
		return clNode, nil
	}

	leftItems, rightItems := partitionByBit(items, depth)

	newLeft, err := t.buildSubtree(leftItems, depth+1, muts)
	if err != nil {
		return nil, err
	}
	newRight, err := t.buildSubtree(rightItems, depth+1, muts)
	if err != nil {
		return nil, err
	}

	newParent := NewBranch(newLeft, newRight)
	if newParent.NodeHash() != EmptyTree[depth].NodeHash() {
		insertBranch(muts, newParent)
	}
	return newParent, nil
}

// partitionByBit splits items into (left, right) by the value of the
// bit at depth in each item's key. The partition is done in place with
// a two-pointer swap — items is reordered but no fresh slice is
// allocated. The returned sub-slices use 3-index slicing so a
// subsequent append on either side cannot clobber the sibling side.
// Callers must own items (see buildSubtree's caller-owns invariant);
// the descent is order-independent so the reorder is invisible to the
// resulting tree.
func partitionByBit(items []batchItem, depth int) (left, right []batchItem) {
	i, j := 0, len(items)-1
	for i <= j {
		k := items[i].key
		if bitIndex(uint8(depth), &k) == 0 {
			i++
		} else {
			items[i], items[j] = items[j], items[i]
			j--
		}
	}
	n := len(items)
	return items[:i:i], items[i:n:n]
}
