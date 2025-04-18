package mssmt

import (
	"context"
	"fmt"
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
// diverging bit of the passed key's.
func (t *CompactedTree) merge(tx TreeStoreUpdateTx, height int, key1 [32]byte,
	leaf1 *LeafNode, key2 [32]byte, leaf2 *LeafNode) (*BranchNode, error) {

	// Find the common prefix first.
	var commonPrefixLen int
	for i := 0; i <= lastBitIndex; i++ {
		if bitIndex(uint8(i), &key1) == bitIndex(uint8(i), &key2) {
			commonPrefixLen++
		} else {
			break
		}
	}

	// Now we create two compacted leaves and insert them as children of
	// a newly created branch.
	node1 := NewCompactedLeafNode(commonPrefixLen+1, &key1, leaf1)
	node2 := NewCompactedLeafNode(commonPrefixLen+1, &key2, leaf2)
	if err := tx.InsertCompactedLeaf(node1); err != nil {
		return nil, err
	}

	if err := tx.InsertCompactedLeaf(node2); err != nil {
		return nil, err
	}

	left, right := stepOrder(commonPrefixLen, &key1, node1, node2)
	parent := NewBranch(left, right)
	if err := tx.InsertBranch(parent); err != nil {
		return nil, err
	}

	// From here we'll walk up to the current level and create branches
	// along the way. Optionally we could compact these branches too.
	for i := commonPrefixLen - 1; i >= height; i-- {
		left, right := stepOrder(i, &key1, parent, EmptyTree[i+1])
		parent = NewBranch(left, right)
		if err := tx.InsertBranch(parent); err != nil {
			return nil, err
		}
	}

	return parent, nil
}

// insert inserts the key at the current height either by adding a new compacted
// leaf, merging an existing leaf with the passed leaf in a new subtree or by
// recursing down further.
func (t *CompactedTree) insert(tx TreeStoreUpdateTx, key *[hashSize]byte,
	height int, root *BranchNode, leaf *LeafNode) (*BranchNode, error) {

	left, right, err := tx.GetChildren(height, root.NodeHash())
	if err != nil {
		return nil, err
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
			// This is an empty subtree, so we can just walk up
			// from the leaf to recreate the node key for this
			// subtree then replace it with a compacted leaf.
			newLeaf := NewCompactedLeafNode(nextHeight, key, leaf)
			err = tx.InsertCompactedLeaf(newLeaf)
			if err != nil {
				return nil, err
			}

			newNode = newLeaf
		} else {
			// Not an empty subtree, recurse down the tree to find
			// the insertion point for the leaf.
			newNode, err = t.insert(tx, key, nextHeight, node, leaf)
			if err != nil {
				return nil, err
			}
		}

	case *CompactedLeafNode:
		// First delete the old leaf.
		err = tx.DeleteCompactedLeaf(node.NodeHash())
		if err != nil {
			return nil, err
		}

		if *key == node.key {
			// Replace of an existing leaf.
			if leaf.IsEmpty() {
				newNode = EmptyTree[nextHeight]
			} else {
				newLeaf := NewCompactedLeafNode(
					nextHeight, key, leaf,
				)

				err := tx.InsertCompactedLeaf(newLeaf)
				if err != nil {
					return nil, err
				}

				newNode = newLeaf
			}
		} else {
			// Merge the two leaves into a subtree.
			newNode, err = t.merge(
				tx, nextHeight, *key, leaf, node.key,
				node.LeafNode,
			)
			if err != nil {
				return nil, err
			}
		}
	}

	// Delete the old root.
	if root != EmptyTree[height] {
		err = tx.DeleteBranch(root.NodeHash())
		if err != nil {
			return nil, err
		}
	}

	// Create the new root.
	var branch *BranchNode
	if isLeft {
		branch = NewBranch(newNode, sibling)
	} else {
		branch = NewBranch(sibling, newNode)
	}

	// Only insert this new branch if not a default one.
	if !IsEqualNode(branch, EmptyTree[height]) {
		err = tx.InsertBranch(branch)
		if err != nil {
			return nil, err
		}
	}

	return branch, nil
}

// Insert inserts a leaf node at the given key within the MS-SMT.
func (t *CompactedTree) Insert(ctx context.Context, key [hashSize]byte,
	leaf *LeafNode) (Tree, error) {

	dbErr := t.store.Update(ctx, func(tx TreeStoreUpdateTx) error {
		currentRoot, err := tx.RootNode()
		if err != nil {
			return err
		}

		// First we'll check if the sum of the root and new leaf will
		// overflow. If so, we'll return an error.
		sumRoot := currentRoot.NodeSum()
		sumLeaf := leaf.NodeSum()
		err = CheckSumOverflowUint64(sumRoot, sumLeaf)
		if err != nil {
			return fmt.Errorf("compact tree leaf insert sum "+
				"overflow, root: %d, leaf: %d; %w", sumRoot,
				sumLeaf, err)
		}

		root, err := t.insert(
			tx, &key, 0, currentRoot.(*BranchNode), leaf,
		)
		if err != nil {
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

		root, err := t.insert(
			tx, &key, 0, currentRoot.(*BranchNode), EmptyLeafNode,
		)
		if err != nil {
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

// InsertMany inserts multiple leaf nodes provided in the leaves map within a
// single database transaction.
func (t *CompactedTree) InsertMany(ctx context.Context,
	leaves map[[hashSize]byte]*LeafNode) (Tree, error) {

	if len(leaves) == 0 {
		return t, nil
	}

	dbErr := t.store.Update(ctx, func(tx TreeStoreUpdateTx) error {
		currentRoot, err := tx.RootNode()
		if err != nil {
			return err
		}
		rootBranch := currentRoot.(*BranchNode)

		for key, leaf := range leaves {
			// Check for potential sum overflow before each
			// insertion.
			sumRoot := rootBranch.NodeSum()
			sumLeaf := leaf.NodeSum()
			err = CheckSumOverflowUint64(sumRoot, sumLeaf)
			if err != nil {
				return fmt.Errorf("compact tree leaf insert "+
					"sum overflow, root: %d, leaf: %d; %w",
					sumRoot, sumLeaf, err)
			}

			// Insert the leaf using the internal helper.
			newRoot, err := t.insert(
				tx, &key, 0, rootBranch, leaf,
			)
			if err != nil {
				return fmt.Errorf("error inserting leaf "+
					"with key %x: %w", key, err)
			}
			rootBranch = newRoot

			// Update the root within the transaction for
			// consistency, even though the insert logic passes the
			// root explicitly.
			err = tx.UpdateRoot(rootBranch)
			if err != nil {
				return fmt.Errorf("error updating root "+
					"during InsertMany: %w", err)
			}
		}

		// The root is already updated by the last iteration of the
		// loop. No final update needed here, but returning nil error
		// signals success.
		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return t, nil
}
