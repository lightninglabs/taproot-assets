package mssmt

import (
	"bytes"
	"context"
	"fmt"
	"sort"
)

// BatchedInsertionEntry represents an entry used for batched
// insertions into the MS-SMT. It consists of a key and the
// associated leaf node to insert.
type BatchedInsertionEntry struct {
	Key  [32]byte
	Leaf *LeafNode
}

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

  
// processCompactedLeaf handles the insertion of a batch of entries into a slot
// that is currently occupied by a compacted leaf. A compacted leaf represents a
// compressed subtree where all branches between a specific height and the actual
// leaf are assumed to be default. Depending on the batched insertion entries,
// this function determines whether to update (i.e. replace) the existing leaf or 
// to merge it with a conflicting new entry.
// 
// The logic is as follows:
// 
// 1. When exactly one entry is provided:
//    - If the entry's key matches the compacted leaf’s key, the function treats it
//      as a replacement. It deletes the existing compacted leaf from the store and
//      inserts a new compacted leaf built from the provided leaf data.
//    - If the entry’s key differs from the compacted leaf’s key, a conflict is
//      detected and the function calls the merge helper to combine the new leaf with
//      the existing leaf into a merged branch.
// 
// 2. When multiple entries are provided:
//    - First, it checks whether all entries share the same key as the compacted leaf.
//      If they do, the function performs a replacement using the data from the last entry
//      in the batch.
//    - Otherwise, it finds the first entry with a key that differs from the compacted leaf
//      and then invokes the merge helper to merge that conflicting leaf with the current one.
// 
// In every case, the function returns the updated node (either a new compacted leaf or a 
// merged branch) and any error encountered during the processing.

func (t *CompactedTree) processCompactedLeaf(tx TreeStoreUpdateTx, height int,
	entries []BatchedInsertionEntry, cl *CompactedLeafNode) (Node, error) {

	// processCompactedLeaf handles the case when the current child node is
	// a compacted leaf. Depending on the batch of new entries, it will either
	// replace the leaf or merge it with a conflicting entry.

	// Case 1: Only one new entry.
	if len(entries) == 1 {
		entry := entries[0]
		if entry.Key == cl.Key() {
			// Replacement: key matches, so update the compacted leaf with the
			// new leaf data.
			newLeaf := NewCompactedLeafNode(height+1, &entry.Key, entry.Leaf)
			if err := tx.DeleteCompactedLeaf(cl.NodeHash()); err != nil {
				return nil, err
			}
			if err := tx.InsertCompactedLeaf(newLeaf); err != nil {
				return nil, err
			}
			return newLeaf, nil
		}
		// Conflict: key differs – merge the new entry with the existing leaf.
		return t.merge(tx, height+1, entry.Key, entry.Leaf, cl.Key(), cl.LeafNode)
	}

	// Case 2: Multiple entries.
	// First, check whether every entry has the same key as the compacted leaf.
	allMatch := true
	for _, entry := range entries {
		if entry.Key != cl.Key() {
			allMatch = false
			break
		}
	}
	if allMatch {
		// All entries match; replace with the last entry's data.
		lastEntry := entries[len(entries)-1]
		newLeaf := NewCompactedLeafNode(height+1, &lastEntry.Key, lastEntry.Leaf)
		if err := tx.DeleteCompactedLeaf(cl.NodeHash()); err != nil {
			return nil, err
		}
		if err := tx.InsertCompactedLeaf(newLeaf); err != nil {
			return nil, err
		}
		return newLeaf, nil
	}

	// Otherwise, find the first entry that differs and perform a merge.
	var mergeEntry *BatchedInsertionEntry
	for _, entry := range entries {
		if entry.Key != cl.Key() {
			mergeEntry = &entry
			break
		}
	}
	if mergeEntry == nil {
		return nil, fmt.Errorf("unexpected nil merge entry")
	}
	return t.merge(tx, height+1, mergeEntry.Key, mergeEntry.Leaf,
		cl.Key(), cl.LeafNode)
}

// processSubtree processes a subtree of the MS-SMT based on the provided
// height, entries, and child node. It handles the case where the child node is
// either empty or a compacted leaf, and returns the updated child node.
func (t *CompactedTree) processSubtree(tx TreeStoreUpdateTx, height int,
	entries []BatchedInsertionEntry, child Node) (Node, error) {

	// If the child is not the default empty node, then we need to process
	// it accordingly.
	if child != EmptyTree[height+1] {
		// If the child is a compacted leaf then delegate to our helper.
		if cl, ok := child.(*CompactedLeafNode); ok {
			return t.processCompactedLeaf(tx, height, entries, cl)
		}

		// Otherwise, child is assumed to be a branch node:
		baseChild := child.(*BranchNode)
		return t.batchedInsert(tx, entries, height+1, baseChild)
	}

	// If the child is empty:
	if len(entries) == 1 {
		// With a single entry, simply create a new compacted leaf.
		entry := entries[0]
		newLeaf := NewCompactedLeafNode(height+1, &entry.Key, entry.Leaf)
		if err := tx.InsertCompactedLeaf(newLeaf); err != nil {
			return nil, err
		}
		return newLeaf, nil
	}

	// When multiple entries share an empty child, use an empty branch node
	// to recursively process the batch.
	baseChild := EmptyTree[height+1].(*BranchNode)
	return t.batchedInsert(tx, entries, height+1, baseChild)
}

// partitionEntries splits the given batched insertion entries into
// two slices based on the bit at the provided height.
// Entries with bit 0 go into leftEntries and those with bit 1 into rightEntries.
func partitionEntries(entries []BatchedInsertionEntry, height int) (leftEntries, rightEntries []BatchedInsertionEntry) {
	for _, entry := range entries {
		if bitIndex(uint8(height), &entry.Key) == 0 {
			leftEntries = append(leftEntries, entry)
		} else {
			rightEntries = append(rightEntries, entry)
		}
	}
	return
}

// batchedInsert recursively inserts a batch of leaf nodes into the MS-SMT.
// It partitions the given entries based on the bit at the specified height
// and processes both left and right subtrees accordingly.
func (t *CompactedTree) batchedInsert(tx TreeStoreUpdateTx, entries []BatchedInsertionEntry, height int, root *BranchNode) (*BranchNode, error) {
	// Base-case: If we've reached the bottom, simply return the current branch.
	if height >= lastBitIndex {
		return root, nil
	}

	// Guard against empty batch.
	if len(entries) == 0 {
		return root, nil
	}

	leftEntries, rightEntries := partitionEntries(entries, height)

	// Get the current children from the node.
	leftChild, rightChild, err := tx.GetChildren(height, root.NodeHash())
	if err != nil {
		return nil, err
	}

	// Process left subtree using the helper function.
	if len(leftEntries) > 0 {
		newLeft, err := t.processSubtree(tx, height, leftEntries, leftChild)
		if err != nil {
			return nil, err
		}
		leftChild = newLeft
	}

	// Process right subtree using the helper function.
	if len(rightEntries) > 0 {
		newRight, err := t.processSubtree(tx, height, rightEntries, rightChild)
		if err != nil {
			return nil, err
		}
		rightChild = newRight
	}

	// Create the updated branch from the new left and right children.
	var updatedBranch *BranchNode
	updatedBranch = NewBranch(leftChild, rightChild)

	// Delete the old branch and insert the new one.
	if root != EmptyTree[height] {
		if err := tx.DeleteBranch(root.NodeHash()); err != nil {
			return nil, err
		}
	}
	if !IsEqualNode(updatedBranch, EmptyTree[height]) {
		if err := tx.InsertBranch(updatedBranch); err != nil {
			return nil, err
		}
	}

	return updatedBranch, nil
}

// BatchedInsert inserts multiple leaf nodes at the given keys within the MS-SMT.
func (t *CompactedTree) BatchedInsert(ctx context.Context, entries []BatchedInsertionEntry) (Tree, error) {
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].Key[:], entries[j].Key[:]) < 0
	})

	err := t.store.Update(ctx, func(tx TreeStoreUpdateTx) error {
		currentRoot, err := tx.RootNode()
		if err != nil {
			return err
		}
		branchRoot := currentRoot.(*BranchNode)

		// (Optional) Loop over entries and check for sum overflow.
		for _, entry := range entries {
			if err := CheckSumOverflowUint64(branchRoot.NodeSum(), entry.Leaf.NodeSum()); err != nil {
				return fmt.Errorf("batched insert key %v sum overflow: %w", entry.Key, err)
			}
		}

		// Call the new batchedInsert method.
		newRoot, err := t.batchedInsert(tx, entries, 0, branchRoot)
		if err != nil {
			return err
		}
		return tx.UpdateRoot(newRoot)
	})
	if err != nil {
		return nil, err
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
