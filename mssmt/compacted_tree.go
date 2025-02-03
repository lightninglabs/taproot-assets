package mssmt

import (
	"context"
	"bytes"
	"fmt"
	"sort"
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

// batched_insert handles the insertion of multiple entries in one go.
func (t *CompactedTree) batched_insert(tx TreeStoreUpdateTx, entries []BatchedInsertionEntry, height int, root *BranchNode) (*BranchNode, error) {
	// Base-case: If we've reached the bottom, simply return the current branch.
	if height >= lastBitIndex {
		return root, nil
	}

	// Guard against empty batch.
	if len(entries) == 0 {
		return root, nil
	}

	// Partition entries into two groups based on bit at current height.
	var leftEntries, rightEntries []BatchedInsertionEntry
	for _, entry := range entries {
		if bitIndex(uint8(height), &entry.Key) == 0 {
			leftEntries = append(leftEntries, entry)
		} else {
			rightEntries = append(rightEntries, entry)
		}
	}

	// Get the current children from the node.
	leftChild, rightChild, err := tx.GetChildren(height, root.NodeHash())
	if err != nil {
		return nil, err
	}

	// Process left subtree:
	var newLeft Node
	if len(leftEntries) > 0 {
		// Check if the current left child is not empty.
		if leftChild != EmptyTree[height+1] {
			// If the existing child is a compacted leaf, we must handle potential collisions.
			if cl, ok := leftChild.(*CompactedLeafNode); ok {
				if len(leftEntries) == 1 {
					entry := leftEntries[0]
					if entry.Key == cl.Key() {
						// Replacement: update the compacted leaf.
						newLeaf := NewCompactedLeafNode(height+1, &entry.Key, entry.Leaf)
						if err := tx.DeleteCompactedLeaf(cl.NodeHash()); err != nil {
							return nil, err
						}
						if err := tx.InsertCompactedLeaf(newLeaf); err != nil {
							return nil, err
						}
						newLeft = newLeaf
					} else {
						// Collision – keys differ: call merge to combine the new entry with the existing compacted leaf.
						newLeft, err = t.merge(tx, height+1, entry.Key, entry.Leaf, cl.Key(), cl.LeafNode)
						if err != nil {
							return nil, err
						}
					}
				} else {
					// Multiple batch entries – check if they all match the existing key.
					allMatch := true
					for _, entry := range leftEntries {
						if entry.Key != cl.Key() {
							allMatch = false
							break
						}
					}
					if allMatch {
						// All entries match; take the last one as replacement.
						lastEntry := leftEntries[len(leftEntries)-1]
						newLeaf := NewCompactedLeafNode(height+1, &lastEntry.Key, lastEntry.Leaf)
						if err := tx.DeleteCompactedLeaf(cl.NodeHash()); err != nil {
							return nil, err
						}
						if err := tx.InsertCompactedLeaf(newLeaf); err != nil {
							return nil, err
						}
						newLeft = newLeaf
					} else {
						// At least one entry has a different key – merge using the first differing entry.
						var mergeEntry *BatchedInsertionEntry
						for _, entry := range leftEntries {
							if entry.Key != cl.Key() {
								mergeEntry = &entry
								break
							}
						}
						if mergeEntry == nil {
							return nil, fmt.Errorf("unexpected nil merge entry")
						}
						newLeft, err = t.merge(tx, height+1, mergeEntry.Key, mergeEntry.Leaf, cl.Key(), cl.LeafNode)
						if err != nil {
							return nil, err
						}
					}
				}
			} else {
				// leftChild is not a compacted leaf, so it must be a branch; recurse normally.
				baseLeft := leftChild.(*BranchNode)
				newLeft, err = t.batched_insert(tx, leftEntries, height+1, baseLeft)
				if err != nil {
					return nil, err
				}
			}
		} else {
			// The left child is empty.
			if len(leftEntries) == 1 {
				entry := leftEntries[0]
				newLeft = NewCompactedLeafNode(height+1, &entry.Key, entry.Leaf)
				if err := tx.InsertCompactedLeaf(newLeft.(*CompactedLeafNode)); err != nil {
					return nil, err
				}
			} else {
				baseLeft := EmptyTree[height+1].(*BranchNode)
				newLeft, err = t.batched_insert(tx, leftEntries, height+1, baseLeft)
				if err != nil {
					return nil, err
				}
			}
		}
		// Use newLeft as the computed left child.
		leftChild = newLeft
	}

	// Process right subtree:
	var newRight Node
	if len(rightEntries) > 0 {
		// Check if the current right child is not empty.
		if rightChild != EmptyTree[height+1] {
			// If the existing child is a compacted leaf, we must handle potential collisions.
			if cr, ok := rightChild.(*CompactedLeafNode); ok {
				if len(rightEntries) == 1 {
					entry := rightEntries[0]
					if entry.Key == cr.Key() {
						// Replacement: update the compacted leaf.
						newLeaf := NewCompactedLeafNode(height+1, &entry.Key, entry.Leaf)
						if err := tx.DeleteCompactedLeaf(cr.NodeHash()); err != nil {
							return nil, err
						}
						if err := tx.InsertCompactedLeaf(newLeaf); err != nil {
							return nil, err
						}
						newRight = newLeaf
					} else {
						// Collision – keys differ: call merge to combine the new entry with the existing compacted leaf.
						newRight, err = t.merge(tx, height+1, entry.Key, entry.Leaf, cr.Key(), cr.LeafNode)
						if err != nil {
							return nil, err
						}
					}
				} else {
					// Multiple batch entries – check if they all match the existing key.
					allMatch := true
					for _, entry := range rightEntries {
						if entry.Key != cr.Key() {
							allMatch = false
							break
						}
					}
					if allMatch {
						// All entries match; take the last one as replacement.
						lastEntry := rightEntries[len(rightEntries)-1]
						newLeaf := NewCompactedLeafNode(height+1, &lastEntry.Key, lastEntry.Leaf)
						if err := tx.DeleteCompactedLeaf(cr.NodeHash()); err != nil {
							return nil, err
						}
						if err := tx.InsertCompactedLeaf(newLeaf); err != nil {
							return nil, err
						}
						newRight = newLeaf
					} else {
						// At least one entry has a different key – merge using the first differing entry.
						var mergeEntry *BatchedInsertionEntry
						for _, entry := range rightEntries {
							if entry.Key != cr.Key() {
								mergeEntry = &entry
								break
							}
						}
						if mergeEntry == nil {
							return nil, fmt.Errorf("unexpected nil merge entry")
						}
						newRight, err = t.merge(tx, height+1, mergeEntry.Key, mergeEntry.Leaf, cr.Key(), cr.LeafNode)
						if err != nil {
							return nil, err
						}
					}
				}
			} else {
				// rightChild is not a compacted leaf, so it must be a branch; recurse normally.
				baseRight := rightChild.(*BranchNode)
				newRight, err = t.batched_insert(tx, rightEntries, height+1, baseRight)
				if err != nil {
					return nil, err
				}
			}
		} else {
			// The right child is empty.
			if len(rightEntries) == 1 {
				entry := rightEntries[0]
				newRight = NewCompactedLeafNode(height+1, &entry.Key, entry.Leaf)
				if err := tx.InsertCompactedLeaf(newRight.(*CompactedLeafNode)); err != nil {
					return nil, err
				}
			} else {
				baseRight := EmptyTree[height+1].(*BranchNode)
				newRight, err = t.batched_insert(tx, rightEntries, height+1, baseRight)
				if err != nil {
					return nil, err
				}
			}
		}
		// Use newRight as the computed right child.
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

		// Call the new batched_insert method.
		newRoot, err := t.batched_insert(tx, entries, 0, branchRoot)
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

// BatchedInsertionEntry represents one leaf insertion.
type BatchedInsertionEntry struct {
	Key  [hashSize]byte
	Leaf *LeafNode
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
			// Our next node is a compacted leaf. We simply return the underlying leaf.
			return node.LeafNode, nil

			for j := i; j <= lastBitIndex; j++ {
				if iter != nil {
					err := iter(j, next, sibling, current)
					if err != nil {
						return nil, err
					}
				}
				current = next

				if j < lastBitIndex {
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
