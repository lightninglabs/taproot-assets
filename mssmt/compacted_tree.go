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
