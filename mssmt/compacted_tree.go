package mssmt

// CompactedTree represents a compacted Merkle-Sum Sparse Merkle Tree (MS-SMT).
// The tree has the same properties as a normal MS-SMT tree and is able to
// create the same proofs and same root as the FullTree implemented in this
// package. The additional benefit of using the CompactedTree is that it will
// greatly reduce storage access resulting in more performant access when used
// for large trees.
type CompactedTree struct {
	root  Node
	store Store
}

var _ Tree = (*CompactedTree)(nil)

// NewCompactedTree initializes an empty MS-SMT backed by `store`.
func NewCompactedTree(store Store) *CompactedTree {
	return &CompactedTree{
		root:  EmptyTree[0],
		store: store,
	}
}

// Root returns the root node of the MS-SMT.
func (t *CompactedTree) Root() *BranchNode {
	return t.root.(*BranchNode)
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
func (t *CompactedTree) walkDown(key *[hashSize]byte, iter iterFunc) *LeafNode {
	current := t.root

	for i := 0; i <= lastBitIndex; i++ {
		left, right := t.store.GetChildren(uint8(i), current.NodeKey())
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
					iter(uint8(j), next, sibling, current)
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

			return current.(*LeafNode)

		default:
			if iter != nil {
				iter(uint8(i), next, sibling, current)
			}
			current = next
		}
	}

	return current.(*LeafNode)
}

// merge is a helper function to create the common subtree from two leafs lying
// on the same (partial) path. The resulting subtree contains branch nodes from
// diverging bit of the passed key's.
func (t *CompactedTree) merge(height int, key1 [32]byte, leaf1 *LeafNode,
	key2 [32]byte, leaf2 *LeafNode) *BranchNode {

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
	t.store.InsertCompactedLeaf(node1)
	t.store.InsertCompactedLeaf(node2)

	left, right := stepOrder(commonPrefixLen, &key1, node1, node2)
	parent := NewBranch(left, right)
	t.store.InsertBranch(parent)

	// From here we'll walk up to the current level and create branches
	// along the way. Optionally we could compact these branches too.
	for i := commonPrefixLen - 1; i >= height; i-- {
		left, right := stepOrder(i, &key1, parent, EmptyTree[i+1])
		parent = NewBranch(left, right)
		t.store.InsertBranch(parent)
	}

	return parent

}

// insert inserts the key at the current height either by adding a new compacted
// leaf, merging an existing leaf with the passed leaf in a new subtree or by
// recursing down further.
func (t *CompactedTree) insert(key *[hashSize]byte, height int,
	root *BranchNode, leaf *LeafNode) *BranchNode {

	left, right := t.store.GetChildren(uint8(height), root.NodeKey())

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
			t.store.InsertCompactedLeaf(newLeaf)
			newNode = newLeaf
		} else {
			// Not an empty subtree, recurse down the tree to find
			// the insertion point for the leaf.
			newNode = t.insert(key, nextHeight, node, leaf)
		}

	case *CompactedLeafNode:
		// First delete the old leaf.
		t.store.DeleteCompactedLeaf(node.NodeKey())

		if *key == node.key {
			// Replace of an existing leaf.
			if leaf.IsEmpty() {
				newNode = EmptyTree[nextHeight]
			} else {
				newLeaf := NewCompactedLeafNode(
					nextHeight, key, leaf,
				)
				t.store.InsertCompactedLeaf(newLeaf)
				newNode = newLeaf
			}
		} else {
			// Merge the two leaves into a subtree.
			newNode = t.merge(
				nextHeight, *key, leaf, node.key, node.LeafNode,
			)
		}
	}

	// Delete the old root.
	if root != EmptyTree[height] {
		t.store.DeleteBranch(root.NodeKey())
	}

	// Create the new root.
	var branch *BranchNode
	if isLeft {
		branch = NewBranch(newNode, sibling)
	} else {
		branch = NewBranch(sibling, newNode)
	}
	t.store.InsertBranch(branch)

	return branch
}

// Insert inserts a leaf node at the given key within the MS-SMT.
func (t *CompactedTree) Insert(key [hashSize]byte, leaf *LeafNode) Tree {
	t.root = t.insert(&key, 0, t.root.(*BranchNode), leaf)
	return t
}

// Delete deletes the leaf node found at the given key within the MS-SMT.
func (t *CompactedTree) Delete(key [hashSize]byte) Tree {
	t.root = t.insert(&key, 0, t.root.(*BranchNode), EmptyLeafNode)
	return t
}

// Get returns the leaf node found at the given key within the MS-SMT.
func (t *CompactedTree) Get(key [hashSize]byte) *LeafNode {
	return t.walkDown(&key, nil)
}

// MerkleProof generates a merkle proof for the leaf node found at the given key
// within the MS-SMT. If a leaf node does not exist at the given key, then the
// proof should be considered a non-inclusion proof. This is noted by the
// returned `Proof` containing an empty leaf.
func (t *CompactedTree) MerkleProof(key [hashSize]byte) *Proof {
	proof := make([]Node, MaxTreeLevels)
	_ = t.walkDown(&key, func(i uint8, _, sibling, _ Node) {
		sibling.NodeKey()
		proof[MaxTreeLevels-1-i] = sibling
	})
	return NewProof(proof)
}
