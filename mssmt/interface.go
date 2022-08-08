package mssmt

// Tree is an interface defining an abstract MSSMT tree type.
type Tree interface {
	// Root returns the root node of the MS-SMT.
	Root() *BranchNode

	// Insert inserts a leaf node at the given key within the MS-SMT.
	Insert(key [hashSize]byte, leaf *LeafNode) Tree

	// Delete deletes the leaf node found at the given key within the
	// MS-SMT.
	Delete(key [hashSize]byte) Tree

	// Get returns the leaf node found at the given key within the MS-SMT.
	Get(key [hashSize]byte) *LeafNode

	// MerkleProof generates a merkle proof for the leaf node found at the
	// given key within the MS-SMT. If a leaf node does not exist at the
	// given key, then the proof should be considered a non-inclusion
	// proof. This is noted by the returned `Proof` containing an empty
	// leaf.
	MerkleProof(key [hashSize]byte) *Proof
}
