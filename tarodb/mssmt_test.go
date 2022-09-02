package tarodb

import (
	"context"
	"database/sql"
	"testing"

	"github.com/lightninglabs/taro/mssmt"
	"github.com/stretchr/testify/require"
)

// newTaroTreeStore makes a new instance of the TaroTreeStore backed by sqlite
// by default.
func newTaroTreeStore(t *testing.T) (*TaroTreeStore, *SqliteStore, func()) {
	db, cleanUp := newTestSqliteDB(t)

	txCreator := func(tx Tx) TreeStore {
		sqlTx, _ := tx.(*sql.Tx)
		return db.WithTx(sqlTx)
	}

	treeDB := NewTransactionExecutor[TreeStore, TxOptions](
		db, txCreator,
	)

	return NewTaroTreeStore(treeDB), db, cleanUp
}

// assertNodesEq is a helper to check equivalency or equality based on the
// expected node's type.
func assertNodesEq(t *testing.T, expected mssmt.Node, node mssmt.Node) {
	switch expected.(type) {
	case *mssmt.BranchNode:
		// For branches we use IsEqualNode since we may fetch the
		// branch precomputed without any reference to its children.
		require.True(t, mssmt.IsEqualNode(expected, node))

	case *mssmt.LeafNode:
		require.Equal(t, expected, node)

	case *mssmt.CompactedLeafNode:
		require.Equal(t, expected, node)
	}
}

// deleteNode is a helper function to delete the passed node according to its
// concrete type.
func deleteNode(t *testing.T, tx mssmt.TreeStoreUpdateTx, node mssmt.Node) {
	t.Helper()

	hashKey := node.NodeHash()

	switch n := node.(type) {
	case *mssmt.BranchNode:
		require.NoError(t, tx.DeleteBranch(hashKey))

	case *mssmt.LeafNode:
		require.NoError(t, tx.DeleteLeaf(hashKey))

	case *mssmt.CompactedLeafNode:
		require.NoError(t, tx.DeleteCompactedLeaf(hashKey))

	default:
		t.Fatalf("invalid node type: %T", n)
	}
}

// TestTreeDeletion tests that deleting leaves, compacted leaves and branches
// works as expected. Note that deleting a branch does not delete its subtree
// recursively.
func TestTreeDeletion(t *testing.T) {
	// Prepare some leaves and compacted leaves.
	l1 := mssmt.NewLeafNode([]byte{1, 2, 3}, 1)
	l2 := mssmt.NewLeafNode([]byte{4, 5, 6}, 2)

	k1 := [32]byte{1}
	k2 := [32]byte{2}

	// Note that the compacted leaf's height is not stored in the database
	// and is only set arbitarily.
	cl1 := mssmt.NewCompactedLeafNode(100, &k1, l1)
	cl2 := mssmt.NewCompactedLeafNode(100, &k2, l2)

	b1 := mssmt.NewBranch(cl2, mssmt.EmptyTree[101])
	b2 := mssmt.NewBranch(mssmt.EmptyTree[101], cl2)
	tests := []struct {
		name   string
		root   int
		branch *mssmt.BranchNode
	}{
		{
			name:   "test 1",
			root:   255,
			branch: mssmt.NewBranch(l1, l2),
		},
		{
			name:   "test 2",
			root:   99,
			branch: mssmt.NewBranch(cl1, cl2),
		},
		{
			name:   "test 3",
			root:   255,
			branch: mssmt.NewBranch(l1, mssmt.EmptyTree[256]),
		},
		{
			name:   "test 4",
			root:   255,
			branch: mssmt.NewBranch(mssmt.EmptyTree[256], l1),
		},
		{
			name:   "test 5",
			root:   99,
			branch: mssmt.NewBranch(mssmt.EmptyTree[100], cl1),
		},
		{
			name:   "test 6",
			root:   99,
			branch: mssmt.NewBranch(cl1, mssmt.EmptyTree[100]),
		},
		{
			//      R
			//     / \
			//  CL1  B
			//      / \
			//   CL2  E
			name:   "test 7",
			root:   99,
			branch: mssmt.NewBranch(cl1, b1),
		},
		{
			//     R
			//    / \
			// CL1  B
			//     / \
			//    E  CL2
			name:   "test 8",
			root:   99,
			branch: mssmt.NewBranch(cl1, b2),
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			store, _, cleanUp := newTaroTreeStore(t)
			defer cleanUp()
			require.NoError(t, store.Update(context.Background(),
				func(tx mssmt.TreeStoreUpdateTx) error {
					require.NoError(t, tx.InsertLeaf(l1))
					require.NoError(t, tx.InsertLeaf(l2))
					require.NoError(
						t, tx.InsertCompactedLeaf(cl1),
					)
					require.NoError(
						t, tx.InsertCompactedLeaf(cl2),
					)

					require.NoError(t, tx.InsertBranch(b1))
					require.NoError(t, tx.InsertBranch(b2))
					require.NoError(
						t, tx.InsertBranch(test.branch),
					)

					rootKey := test.branch.NodeHash()

					// First make sure we inserted our test
					// branch correctly.
					n1, n2, err := tx.GetChildren(
						test.root, rootKey,
					)

					require.NoError(t, err)

					assertNodesEq(
						t, test.branch.Left, n1,
					)

					assertNodesEq(
						t, test.branch.Right, n2,
					)

					empty := mssmt.EmptyTree[test.root+1]

					// Now delete the left child and check
					// if we can retrieve the branch
					// correctly.
					if test.branch.Left != empty {
						deleteNode(
							t, tx,
							test.branch.Left,
						)
					}
					n1, n2, err = tx.GetChildren(
						test.root, rootKey,
					)

					require.NoError(t, err)
					require.Equal(t, empty, n1)

					assertNodesEq(
						t, test.branch.Right, n2,
					)

					// Now delete the right child and check
					// again if we can retrieve the branch
					// correctly.
					if test.branch.Right != empty {
						deleteNode(
							t, tx,
							test.branch.Right,
						)
					}
					n1, n2, err = tx.GetChildren(
						test.root, rootKey,
					)

					require.NoError(t, err)
					require.Equal(t, n1, empty)
					require.Equal(t, n2, empty)

					return nil
				},
			))
		})
	}
}

// TestTreeInsertion tests that inserting leaves, branches and compacted leaves
// in an orderly manner results in the expected tree structure in the database.
func TestTreeInsertion(t *testing.T) {
	// Leaves are on level 256.
	l1 := mssmt.NewLeafNode([]byte{1, 2, 3}, 1)
	l2 := mssmt.NewLeafNode([]byte{4, 5, 6}, 2)
	l3 := mssmt.NewLeafNode([]byte{7, 8, 9}, 3)
	l4 := mssmt.NewLeafNode([]byte{10, 11, 12}, 4)

	// Compacted leaves are scattered in the tree.
	k1 := [32]byte{1}
	k2 := [32]byte{2}
	k3 := [32]byte{3}
	k4 := [32]byte{4}

	cl1 := mssmt.NewCompactedLeafNode(100, &k1, l1)
	cl2 := mssmt.NewCompactedLeafNode(100, &k2, l2)
	cl3 := mssmt.NewCompactedLeafNode(99, &k3, l3)
	cl4 := mssmt.NewCompactedLeafNode(99, &k4, l4)

	branchCL1CL2 := mssmt.NewBranch(cl1, cl2)
	branchCL1CL2CL3 := mssmt.NewBranch(branchCL1CL2, cl3)
	branchCL4EB := mssmt.NewBranch(cl4, mssmt.EmptyTree[99])

	// These branches are on level 255.
	el := mssmt.EmptyTree[256]
	branchL1L2 := mssmt.NewBranch(l1, l2)
	branchL3L4 := mssmt.NewBranch(l3, l4)
	branchL1EL := mssmt.NewBranch(l1, el)
	branchELL1 := mssmt.NewBranch(el, l1)

	// These branches are on level 254.
	branchL1L2EB := mssmt.NewBranch(branchL1L2, mssmt.EmptyTree[255])
	branchEBL3L4 := mssmt.NewBranch(mssmt.EmptyTree[255], branchL3L4)

	tests := []struct {
		name            string
		root            int
		leaves          []*mssmt.LeafNode
		compactedLeaves []*mssmt.CompactedLeafNode
		branches        [][]*mssmt.BranchNode
	}{
		{
			//       R
			//     /  \
			//    B1  Empty
			//   /  \
			//  L1  L2
			name: "test 1",
			root: 254,
			leaves: []*mssmt.LeafNode{
				l1, l2,
			},
			branches: [][]*mssmt.BranchNode{
				{
					// R.
					mssmt.NewBranch(
						branchL1L2,
						mssmt.EmptyTree[255],
					),
				},
				{
					// B1.
					branchL1L2,
				},
			},
		},
		{
			//         R
			//       /  \
			//  Empty    B1
			//          /  \
			//         L1  L2
			name: "test 2",
			root: 254,
			leaves: []*mssmt.LeafNode{
				l1, l2,
			},
			branches: [][]*mssmt.BranchNode{
				{
					// R.
					mssmt.NewBranch(
						mssmt.EmptyTree[255],
						branchL1L2,
					),
				},
				{
					// B1.
					branchL1L2,
				},
			},
		},
		{
			//       R
			//     /  \
			//    B2  Empty
			//   /  \
			//  L1  Empty
			name: "test 3",
			root: 254,
			leaves: []*mssmt.LeafNode{
				l1,
			},
			branches: [][]*mssmt.BranchNode{
				{
					// R.
					mssmt.NewBranch(
						branchL1EL,
						mssmt.EmptyTree[255],
					),
				},
				{
					// B2.
					branchL1EL,
				},
			},
		},
		{
			//         R
			//       /  \
			//      B2  Empty
			//     /  \
			// Empty  L1
			name: "test 4",
			root: 254,
			leaves: []*mssmt.LeafNode{
				l1,
			},
			branches: [][]*mssmt.BranchNode{
				{
					// R.
					mssmt.NewBranch(
						branchELL1,
						mssmt.EmptyTree[255],
					),
				},
				{
					// B2.
					branchELL1,
				},
			},
		},
		{
			//        R
			//      /  \
			//  Empty  B2
			//        /  \
			//      L1  Empty
			name: "test 5",
			root: 254,
			leaves: []*mssmt.LeafNode{
				l1,
			},
			branches: [][]*mssmt.BranchNode{
				{
					// R.
					mssmt.NewBranch(
						mssmt.EmptyTree[255],
						branchL1EL,
					),
				},
				{
					// B2.
					branchL1EL,
				},
			},
		},
		{
			//         R
			//       /  \
			//   Empty  B2
			//         /  \
			//     Empty  L1
			name: "test 6",
			root: 254,
			leaves: []*mssmt.LeafNode{
				l1,
			},
			branches: [][]*mssmt.BranchNode{
				{
					// R.
					mssmt.NewBranch(
						mssmt.EmptyTree[255],
						branchELL1,
					),
				},
				{
					// B2.
					branchELL1,
				},
			},
		},
		{
			//          R
			//        /   \
			//      B1     B2
			//     /  \   /  \
			//    L1  L2 L3  L4
			name: "test 7",
			root: 254,
			leaves: []*mssmt.LeafNode{
				l1, l2, l3, l4,
			},
			branches: [][]*mssmt.BranchNode{
				{
					// R.
					mssmt.NewBranch(
						branchL1L2,
						branchL3L4,
					),
				},
				{
					// B1, B2.
					branchL1L2, branchL3L4,
				},
			},
		},
		{
			//             R
			//           /  \
			//         B3    B4
			//        /  \  /  \
			//      B1   E E   B2
			//     / \        /  \
			//    L1 L2      L3  L4
			name: "test 8",
			root: 253,
			leaves: []*mssmt.LeafNode{
				l1, l2, l3, l4,
			},
			branches: [][]*mssmt.BranchNode{
				{
					// R.
					mssmt.NewBranch(
						branchL1L2EB, branchEBL3L4,
					),
				},
				{
					// B3, B4.
					branchL1L2EB, branchEBL3L4,
				},
				{
					// B1, B2.
					branchL1L2, branchL3L4,
				},
			},
		},
		{
			//            R
			//          /   \
			//        B2     B3
			//       /  \   /  \
			//     B1  CL3 CL4 E
			//    /  \
			//  CL1 CL2
			name: "test 9",
			root: 97,
			compactedLeaves: []*mssmt.CompactedLeafNode{
				cl1, cl2, cl3, cl4,
			},
			branches: [][]*mssmt.BranchNode{
				{
					// R.
					mssmt.NewBranch(
						branchCL1CL2CL3, branchCL4EB,
					),
				},
				{
					// B2, B3.
					branchCL1CL2CL3, branchCL4EB,
				},
				{
					// B1.
					branchCL1CL2,
				},
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			store, _, cleanUp := newTaroTreeStore(t)
			defer cleanUp()
			require.NoError(t, store.Update(context.Background(),
				func(tx mssmt.TreeStoreUpdateTx) error {
					for _, leaf := range test.leaves {
						require.NoError(t,
							tx.InsertLeaf(leaf),
						)
					}

					for _, leaf := range test.compactedLeaves {
						require.NoError(t,
							tx.InsertCompactedLeaf(
								leaf,
							),
						)
					}

					for _, level := range test.branches {
						for _, branch := range level {
							require.NoError(t,
								tx.InsertBranch(
									branch,
								),
							)
						}
					}
					return nil
				},
			))

			require.NoError(t, store.View(context.Background(),
				func(tx mssmt.TreeStoreViewTx) error {
					for i, level := range test.branches {
						for _, branch := range level {
							n1, n2, err := tx.GetChildren(
								test.root+i,
								branch.NodeHash(),
							)

							require.NoError(t, err)

							assertNodesEq(t,
								branch.Left,
								n1,
							)

							assertNodesEq(t,
								branch.Right,
								n2,
							)
						}
					}

					return nil
				},
			))
		})
	}
}
