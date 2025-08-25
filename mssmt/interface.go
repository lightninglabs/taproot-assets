package mssmt

import "context"

// CopyFilterPredicate is a type alias for a filter function used in CopyFilter.
// It takes a key and leaf node as input and returns a boolean indicating
// whether to include the leaf in the copy operation. A true value means the
// leaf should be included, while false means it should be excluded.
type CopyFilterPredicate = func([hashSize]byte, LeafNode) (bool, error)

// Tree is an interface defining an abstract MSSMT tree type.
type Tree interface {
	// Root returns the root node of the MS-SMT.
	Root(ctx context.Context) (*BranchNode, error)

	// Insert inserts a leaf node at the given key within the MS-SMT.
	Insert(ctx context.Context, key [hashSize]byte, leaf *LeafNode) (
		Tree, error)

	// Delete deletes the leaf node found at the given key within the
	// MS-SMT.
	Delete(ctx context.Context, key [hashSize]byte) (Tree, error)

	// DeleteRoot deletes the root node of the MS-SMT.
	DeleteRoot(ctx context.Context) error

	// DeleteAllNodes deletes all non-root nodes within the MS-SMT.
	DeleteAllNodes(ctx context.Context) error

	// Get returns the leaf node found at the given key within the MS-SMT.
	Get(ctx context.Context, key [hashSize]byte) (*LeafNode, error)

	// MerkleProof generates a merkle proof for the leaf node found at the
	// given key within the MS-SMT. If a leaf node does not exist at the
	// given key, then the proof should be considered a non-inclusion
	// proof. This is noted by the returned `Proof` containing an empty
	// leaf.
	MerkleProof(ctx context.Context, key [hashSize]byte) (*Proof, error)

	// InsertMany inserts multiple leaf nodes provided in the leaves map
	// within a single database transaction.
	InsertMany(ctx context.Context, leaves map[[hashSize]byte]*LeafNode) (
		Tree, error)

	// Copy copies all the key-value pairs from the source tree into the
	// target tree.
	Copy(ctx context.Context, targetTree Tree) error

	// CopyFilter copies all the key-value pairs from the source tree into
	// the target tree that pass the filter callback. The filter callback is
	// invoked for each leaf-key pair.
	CopyFilter(ctx context.Context, targetTree Tree,
		filterFunc CopyFilterPredicate) error
}
