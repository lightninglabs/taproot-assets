package tapdb

import (
	"context"
	"crypto/rand"
	"database/sql"
	"testing"

	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/stretchr/testify/require"
)

// newTaprootAssetTreeStore makes a new instance of the TaprootAssetTreeStore
// backed by sqlite by default.
func newTaprootAssetTreeStore(t *testing.T,
	namespace string) (*TaprootAssetTreeStore, sqlc.Querier) {

	db := NewTestDB(t)

	txCreator := func(tx *sql.Tx) TreeStore {
		return db.WithTx(tx)
	}

	treeDB := NewTransactionExecutor(db, txCreator)

	return NewTaprootAssetTreeStore(treeDB, namespace), db
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
	_ = l1.NodeHash()
	_ = l2.NodeHash()

	k1 := [32]byte{1}
	k2 := [32]byte{2}

	// Note that the compacted leaf's height is not stored in the database
	// and is only set arbitrarily.
	cl1 := mssmt.NewCompactedLeafNode(100, &k1, l1)
	cl2 := mssmt.NewCompactedLeafNode(100, &k2, l2)

	b1 := mssmt.NewBranch(cl2, mssmt.EmptyTree[101])
	b2 := mssmt.NewBranch(mssmt.EmptyTree[101], cl2)
	_ = b1.NodeHash()
	_ = b2.NodeHash()
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

			store, _ := newTaprootAssetTreeStore(t, test.name)

			insertAllNodes := func(t *testing.T,
				tx mssmt.TreeStoreUpdateTx) {

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
			}

			require.NoError(t, store.Update(context.Background(),
				func(tx mssmt.TreeStoreUpdateTx) error {
					// An empty tree should have a root
					// hash of the empty hash.
					dbRoot, err := tx.RootNode()
					require.NoError(t, err)
					require.Equal(
						t, mssmt.EmptyTree[0], dbRoot,
					)

					insertAllNodes(t, tx)
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

					// Now, delete all nodes to remove those
					// not deleted explicitly above. Rebuild
					// the tree and delete all nodes again.
					// We should not be able to fetch the
					// children of the test branch.
					err = tx.DeleteAllNodes()
					require.NoError(t, err)
					insertAllNodes(t, tx)

					err = tx.DeleteAllNodes()
					require.NoError(t, err)

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
	_ = l1.NodeHash()
	_ = l2.NodeHash()
	_ = l3.NodeHash()
	_ = l4.NodeHash()

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
	_ = branchCL1CL2.NodeHash()
	_ = branchCL1CL2CL3.NodeHash()
	_ = branchCL4EB.NodeHash()

	// These branches are on level 255.
	el := mssmt.EmptyTree[256]
	branchL1L2 := mssmt.NewBranch(l1, l2)
	branchL3L4 := mssmt.NewBranch(l3, l4)
	branchL1EL := mssmt.NewBranch(l1, el)
	branchELL1 := mssmt.NewBranch(el, l1)
	_ = branchL1L2.NodeHash()
	_ = branchL3L4.NodeHash()
	_ = branchL1EL.NodeHash()
	_ = branchELL1.NodeHash()

	// These branches are on level 254.
	branchL1L2EB := mssmt.NewBranch(branchL1L2, mssmt.EmptyTree[255])
	branchEBL3L4 := mssmt.NewBranch(mssmt.EmptyTree[255], branchL3L4)
	_ = branchL1L2EB.NodeHash()
	_ = branchEBL3L4.NodeHash()

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

			store, _ := newTaprootAssetTreeStore(t, test.name)

			require.NoError(t, store.Update(context.Background(),
				func(tx mssmt.TreeStoreUpdateTx) error {
					// An empty tree should have a root
					// hash of the empty hash.
					dbRoot, err := tx.RootNode()
					require.NoError(t, err)
					require.Equal(
						t, mssmt.EmptyTree[0], dbRoot,
					)

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

// TestTreeNamespaceIsolation tests that we're able to query for distinct trees
// on disk.
func TestTreeNamespaceIsolation(t *testing.T) {
	t.Parallel()

	name1 := "test1"
	name2 := "test2"

	// We'll use a simple tree that only has one leaf. The only leaf is a
	// compacted leaf which sits up at the very top of the tree.
	leafValue := []byte("kek")
	leaf := mssmt.NewLeafNode(leafValue, 2)
	leafHash := [32]byte(leaf.NodeHash())
	compactedLeaf := mssmt.NewCompactedLeafNode(1, &leafHash, leaf)
	root := mssmt.NewBranch(compactedLeaf, mssmt.EmptyTree[1])

	store1, _ := newTaprootAssetTreeStore(t, name1)
	store2, _ := newTaprootAssetTreeStore(t, name2)

	// With both stores created, we'll insert the left and right branches
	// of the root, then the root itself.
	ctxb := context.Background()
	err := store1.Update(ctxb, func(tx mssmt.TreeStoreUpdateTx) error {
		if err := tx.InsertCompactedLeaf(compactedLeaf); err != nil {
			return err
		}
		if err := tx.InsertBranch(root); err != nil {
			return err
		}

		if err := tx.UpdateRoot(root); err != nil {
			return err
		}

		return nil
	})
	require.NoError(t, err)

	// The second store should still be untouched, returning the empty tree
	// root hash.
	err = store2.View(ctxb, func(tx mssmt.TreeStoreViewTx) error {
		dbRoot, err := tx.RootNode()
		require.NoError(t, err)
		require.Equal(
			t, mssmt.EmptyTree[0], dbRoot,
		)
		return nil
	})
	require.NoError(t, err)

	// The root hash of the first store should match the root above.
	err = store1.View(ctxb, func(tx mssmt.TreeStoreViewTx) error {
		dbRoot, err := tx.RootNode()
		require.NoError(t, err)
		assertNodesEq(t, root, dbRoot)
		return nil
	})
	require.NoError(t, err)

	// We'll now update the root hash of the first store again to ensure
	// the upset logic works.
	root = mssmt.NewBranch(mssmt.EmptyTree[1], compactedLeaf)
	err = store1.Update(ctxb, func(tx mssmt.TreeStoreUpdateTx) error {
		if err := tx.InsertBranch(root); err != nil {
			return err
		}
		return tx.UpdateRoot(root)
	})
	require.NoError(t, err)
	err = store1.View(ctxb, func(tx mssmt.TreeStoreViewTx) error {
		dbRoot, err := tx.RootNode()
		require.NoError(t, err)
		assertNodesEq(t, root, dbRoot)
		return nil
	})
	require.NoError(t, err)

	// We'll now delete the root hash. Fetching the root after deletion
	// should return the empty tree root hash.
	err = store1.Update(ctxb, func(tx mssmt.TreeStoreUpdateTx) error {
		if err := tx.DeleteRoot(); err != nil {
			return err
		}
		dbRoot, err := tx.RootNode()
		require.NoError(t, err)
		require.Equal(
			t, mssmt.EmptyTree[0], dbRoot,
		)
		return nil
	})
	require.NoError(t, err)
}

// TestCompactedTreeAbsentDelete deletes a key that is not in the tree, then
// inserts keys whose path crosses the empty slot the delete wrote a row for.
// The DB-backed tree must match the in-memory reference.
func TestCompactedTreeAbsentDelete(t *testing.T) {
	ctx := context.Background()

	db := NewTestDB(t)
	txCreator := func(tx *sql.Tx) TreeStore { return db.WithTx(tx) }
	treeDB := NewTransactionExecutor(db, txCreator)

	dbTree := mssmt.NewCompactedTree(
		NewTaprootAssetTreeStore(treeDB, "absent-delete"),
	)
	refTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())

	// key returns a random key whose leading bits are the given path.
	key := func(path ...byte) [32]byte {
		var k [32]byte
		_, _ = rand.Read(k[:])
		for i, b := range path {
			if b == 1 {
				k[i/8] |= 1 << (i % 8)
			} else {
				k[i/8] &^= 1 << (i % 8)
			}
		}
		return k
	}
	leaf := func(sum uint64) *mssmt.LeafNode {
		v := make([]byte, 16)
		_, _ = rand.Read(v)
		return mssmt.NewLeafNode(v, sum)
	}

	kx, absent := key(0, 0, 1), key(0, 0, 0)
	y, z, w := key(1, 0, 0, 0), key(1, 0, 0, 1), key(1, 0, 1)
	lx, ly, lz, lw := leaf(1), leaf(2), leaf(3), leaf(4)

	for _, tree := range []*mssmt.CompactedTree{dbTree, refTree} {
		_, err := tree.Insert(ctx, kx, lx)
		require.NoError(t, err)

		// The key is absent, so the root must not change.
		_, err = tree.Delete(ctx, absent)
		require.NoError(t, err)

		for _, kv := range []struct {
			k [32]byte
			l *mssmt.LeafNode
		}{{y, ly}, {z, lz}, {w, lw}} {
			_, err = tree.Insert(ctx, kv.k, kv.l)
			require.NoError(t, err)
		}
	}

	refRoot, err := refTree.Root(ctx)
	require.NoError(t, err)
	dbRoot, err := dbTree.Root(ctx)
	require.NoError(t, err)
	require.Equal(t, refRoot.NodeHash(), dbRoot.NodeHash(), "root mismatch")

	got, err := dbTree.Get(ctx, w)
	require.NoError(t, err)
	require.Equal(t, lw.Value, got.Value, "Get(w) returned wrong leaf")

	proof, err := dbTree.MerkleProof(ctx, w)
	require.NoError(t, err)
	require.True(t, mssmt.VerifyMerkleProof(w, lw, proof, dbRoot))
}

// TestCompactedTreeAbsentDeleteEmptyAndSingleLeaf tests absent key deletion
// on an empty tree and on a 1-leaf tree, verifying that no extraneous rows
// are inserted into mssmt_nodes and roots match in-memory reference trees.
// Specifically, it pins two distinct paths against a 1-leaf tree:
// 1. An absent key that takes the empty sibling branch (node == EmptyTree[nextHeight]).
// 2. An absent key that shares the leaf's prefix bit (*key != node.key).
func TestCompactedTreeAbsentDeleteEmptyAndSingleLeaf(t *testing.T) {
	ctx := context.Background()

	db := NewTestDB(t)
	txCreator := func(tx *sql.Tx) TreeStore { return db.WithTx(tx) }
	treeDB := NewTransactionExecutor(db, txCreator)
	namespace := "absent-delete-edge-cases"

	treeStore := NewTaprootAssetTreeStore(treeDB, namespace)
	dbTree := mssmt.NewCompactedTree(treeStore)
	refTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())

	countRows := func() int {
		var count int
		row := db.QueryRowContext(
			ctx,
			"SELECT COUNT(*) FROM mssmt_nodes WHERE namespace = $1",
			namespace,
		)
		require.NoError(t, row.Scan(&count))
		return count
	}

	key := func(path ...byte) [32]byte {
		var k [32]byte
		_, _ = rand.Read(k[:])
		for i, b := range path {
			if b == 1 {
				k[i/8] |= 1 << (i % 8)
			} else {
				k[i/8] &^= 1 << (i % 8)
			}
		}
		return k
	}

	// 1. Delete absent key from empty tree.
	absentKey := key(0, 0, 0)
	_, err := dbTree.Delete(ctx, absentKey)
	require.NoError(t, err)
	_, err = refTree.Delete(ctx, absentKey)
	require.NoError(t, err)

	dbRoot, err := dbTree.Root(ctx)
	require.NoError(t, err)
	refRoot, err := refTree.Root(ctx)
	require.NoError(t, err)
	require.Equal(t, mssmt.EmptyTree[0], dbRoot)
	require.Equal(t, refRoot.NodeHash(), dbRoot.NodeHash())
	require.Equal(t, 0, countRows(), "no rows should be written for empty tree delete")

	// 2. Insert one leaf starting with bit 0 (left child at height 0).
	k1 := key(0, 1)
	leaf1 := mssmt.NewLeafNode([]byte("value1"), 10)

	_, err = dbTree.Insert(ctx, k1, leaf1)
	require.NoError(t, err)
	_, err = refTree.Insert(ctx, k1, leaf1)
	require.NoError(t, err)

	rowsBefore := countRows()

	// 3. Delete absent key that walks into the empty sibling branch
	// (bit 0 is 1, so it takes the right child which is EmptyTree[1]).
	absentEmptySibling := key(1, 0)
	_, err = dbTree.Delete(ctx, absentEmptySibling)
	require.NoError(t, err)
	_, err = refTree.Delete(ctx, absentEmptySibling)
	require.NoError(t, err)

	dbRoot, err = dbTree.Root(ctx)
	require.NoError(t, err)
	refRoot, err = refTree.Root(ctx)
	require.NoError(t, err)
	require.Equal(t, refRoot.NodeHash(), dbRoot.NodeHash())
	require.Equal(t, rowsBefore, countRows(), "no extra rows on empty-sibling absent delete")

	// 4. Delete absent key that shares bit 0 with k1, hitting the existing
	// compacted leaf with a differing key (*key != node.key).
	absentCollidingLeaf := key(0, 0)
	_, err = dbTree.Delete(ctx, absentCollidingLeaf)
	require.NoError(t, err)
	_, err = refTree.Delete(ctx, absentCollidingLeaf)
	require.NoError(t, err)

	dbRoot, err = dbTree.Root(ctx)
	require.NoError(t, err)
	refRoot, err = refTree.Root(ctx)
	require.NoError(t, err)
	require.Equal(t, refRoot.NodeHash(), dbRoot.NodeHash())
	require.Equal(t, rowsBefore, countRows(), "no extra rows on colliding-leaf absent delete")

	// Verify Get and MerkleProof for existing key.
	got, err := dbTree.Get(ctx, k1)
	require.NoError(t, err)
	require.Equal(t, leaf1.Value, got.Value)

	proof, err := dbTree.MerkleProof(ctx, k1)
	require.NoError(t, err)
	require.True(t, mssmt.VerifyMerkleProof(k1, leaf1, proof, dbRoot))
}

// TestCompactedTreeStaleEmptyRowResilience verifies that if a database already
// contains a stale empty compacted leaf row (simulating dirty state from before
// the fix), GetChildren ignores it, and subsequent inserts and proofs operate
// correctly without state corruption.
func TestCompactedTreeStaleEmptyRowResilience(t *testing.T) {
	ctx := context.Background()

	db := NewTestDB(t)
	txCreator := func(tx *sql.Tx) TreeStore { return db.WithTx(tx) }
	treeDB := NewTransactionExecutor(db, txCreator)
	namespace := "stale-row-resilience"

	treeStore := NewTaprootAssetTreeStore(treeDB, namespace)
	dbTree := mssmt.NewCompactedTree(treeStore)
	refTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())

	key := func(path ...byte) [32]byte {
		var k [32]byte
		_, _ = rand.Read(k[:])
		for i, b := range path {
			if b == 1 {
				k[i/8] |= 1 << (i % 8)
			} else {
				k[i/8] &^= 1 << (i % 8)
			}
		}
		return k
	}
	leaf := func(sum uint64) *mssmt.LeafNode {
		v := make([]byte, 16)
		_, _ = rand.Read(v)
		return mssmt.NewLeafNode(v, sum)
	}

	// Insert the stale empty leaf row at height 3 into mssmt_nodes using
	// key(0,0,0), exactly mimicking what the pre-fix absent delete wrote.
	emptyHashAt3 := mssmt.EmptyTree[3].NodeHash()
	absentKey := key(0, 0, 0)

	// Directly insert the stale row into the DB via raw SQL to bypass the
	// new adapter guard.
	_, err := db.ExecContext(
		ctx,
		"INSERT INTO mssmt_nodes (hash_key, l_hash_key, r_hash_key, key, value, sum, namespace) "+
			"VALUES ($1, NULL, NULL, $2, $3, 0, $4)",
		emptyHashAt3[:], absentKey[:], []byte{}, namespace,
	)
	require.NoError(t, err)

	// Now insert keys whose path encounters EmptyTree[3].
	kx := key(0, 0, 1)
	y, z, w := key(1, 0, 0, 0), key(1, 0, 0, 1), key(1, 0, 1)
	lx, ly, lz, lw := leaf(1), leaf(2), leaf(3), leaf(4)

	for _, tree := range []*mssmt.CompactedTree{dbTree, refTree} {
		_, err := tree.Insert(ctx, kx, lx)
		require.NoError(t, err)

		for _, kv := range []struct {
			k [32]byte
			l *mssmt.LeafNode
		}{{y, ly}, {z, lz}, {w, lw}} {
			_, err = tree.Insert(ctx, kv.k, kv.l)
			require.NoError(t, err)
		}
	}

	refRoot, err := refTree.Root(ctx)
	require.NoError(t, err)
	dbRoot, err := dbTree.Root(ctx)
	require.NoError(t, err)
	require.Equal(t, refRoot.NodeHash(), dbRoot.NodeHash(), "root mismatch despite stale row")

	got, err := dbTree.Get(ctx, w)
	require.NoError(t, err)
	require.Equal(t, lw.Value, got.Value, "Get(w) returned wrong leaf")

	proof, err := dbTree.MerkleProof(ctx, w)
	require.NoError(t, err)
	require.True(t, mssmt.VerifyMerkleProof(w, lw, proof, dbRoot))

	// Assert that the stale empty row remains present on disk, proving
	// that GetChildren ignored it rather than deleting or modifying it.
	var staleRowCount int
	row := db.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM mssmt_nodes WHERE namespace = $1 AND hash_key = $2",
		namespace, emptyHashAt3[:],
	)
	require.NoError(t, row.Scan(&staleRowCount))
	require.Equal(t, 1, staleRowCount, "stale empty row must remain in DB (ignored)")
}

// TestTreeIdenticalSiblingHashes tests that when two sibling nodes share the
// exact same node hash (for example, identical leaf value, sum, and remaining path),
// tapdb.GetChildren sets both left and right children from the single shared
// database row, and Get(), Root(), and MerkleProof() succeed for both keys on
// both FullTree and CompactedTree.
func TestTreeIdenticalSiblingHashes(t *testing.T) {
	ctx := context.Background()

	sharedLeaf := mssmt.NewLeafNode([]byte("shared-leaf-value"), 50)

	t.Run("CompactedTree", func(t *testing.T) {
		db := NewTestDB(t)
		txCreator := func(tx *sql.Tx) TreeStore { return db.WithTx(tx) }
		treeDB := NewTransactionExecutor(db, txCreator)
		namespace := "identical-sibling-compacted"

		treeStore := NewTaprootAssetTreeStore(treeDB, namespace)
		dbTree := mssmt.NewCompactedTree(treeStore)
		refTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())

		// Construct two keys that differ only at bit 0.
		// Since bits 1..255 are identical, their compacted leaf subtrees
		// constructed at height 1 have identical node hashes.
		var k0, k1 [32]byte
		k0[0] = 0x00 // bit 0 = 0
		k1[0] = 0x01 // bit 0 = 1
		for i := 1; i < 32; i++ {
			k0[i] = byte(i * 7)
			k1[i] = byte(i * 7)
		}

		for _, tree := range []*mssmt.CompactedTree{dbTree, refTree} {
			_, err := tree.Insert(ctx, k0, sharedLeaf)
			require.NoError(t, err)
			_, err = tree.Insert(ctx, k1, sharedLeaf)
			require.NoError(t, err)
		}

		dbRoot, err := dbTree.Root(ctx)
		require.NoError(t, err)
		refRoot, err := refTree.Root(ctx)
		require.NoError(t, err)
		require.Equal(t, refRoot.NodeHash(), dbRoot.NodeHash())

		// Verify that a single node row was stored for the compacted leaves
		// because they share the same hash_key.
		leafHash := mssmt.NewCompactedLeafNode(1, &k0, sharedLeaf).NodeHash()
		var leafRowCount int
		row := db.QueryRowContext(
			ctx,
			"SELECT COUNT(*) FROM mssmt_nodes WHERE namespace = $1 AND hash_key = $2",
			namespace, leafHash[:],
		)
		require.NoError(t, row.Scan(&leafRowCount))
		require.Equal(t, 1, leafRowCount)

		// Both keys must be retrieved correctly from the database.
		got0, err := dbTree.Get(ctx, k0)
		require.NoError(t, err)
		require.Equal(t, sharedLeaf.Value, got0.Value)

		got1, err := dbTree.Get(ctx, k1)
		require.NoError(t, err)
		require.Equal(t, sharedLeaf.Value, got1.Value)

		// Both Merkle proofs must verify against dbRoot.
		proof0, err := dbTree.MerkleProof(ctx, k0)
		require.NoError(t, err)
		require.True(t, mssmt.VerifyMerkleProof(k0, sharedLeaf, proof0, dbRoot))

		proof1, err := dbTree.MerkleProof(ctx, k1)
		require.NoError(t, err)
		require.True(t, mssmt.VerifyMerkleProof(k1, sharedLeaf, proof1, dbRoot))
	})

	t.Run("FullTree", func(t *testing.T) {
		db := NewTestDB(t)
		txCreator := func(tx *sql.Tx) TreeStore { return db.WithTx(tx) }
		treeDB := NewTransactionExecutor(db, txCreator)
		namespace := "identical-sibling-full"

		treeStore := NewTaprootAssetTreeStore(treeDB, namespace)
		dbTree := mssmt.NewFullTree(treeStore)
		refTree := mssmt.NewFullTree(mssmt.NewDefaultStore())

		// Construct two keys that differ only at bit 255 (the last bit).
		var k0, k1 [32]byte
		k0[31] = 0x00 // bit 255 = 0
		k1[31] = 0x80 // bit 255 = 1 (bit 7 of byte 31)
		for i := 0; i < 31; i++ {
			k0[i] = byte(i * 3)
			k1[i] = byte(i * 3)
		}

		for _, tree := range []*mssmt.FullTree{dbTree, refTree} {
			_, err := tree.Insert(ctx, k0, sharedLeaf)
			require.NoError(t, err)
			_, err = tree.Insert(ctx, k1, sharedLeaf)
			require.NoError(t, err)
		}

		dbRoot, err := dbTree.Root(ctx)
		require.NoError(t, err)
		refRoot, err := refTree.Root(ctx)
		require.NoError(t, err)
		require.Equal(t, refRoot.NodeHash(), dbRoot.NodeHash())

		// Verify Get and MerkleProof for both sibling keys.
		got0, err := dbTree.Get(ctx, k0)
		require.NoError(t, err)
		require.Equal(t, sharedLeaf.Value, got0.Value)

		got1, err := dbTree.Get(ctx, k1)
		require.NoError(t, err)
		require.Equal(t, sharedLeaf.Value, got1.Value)

		proof0, err := dbTree.MerkleProof(ctx, k0)
		require.NoError(t, err)
		require.True(t, mssmt.VerifyMerkleProof(k0, sharedLeaf, proof0, dbRoot))

		proof1, err := dbTree.MerkleProof(ctx, k1)
		require.NoError(t, err)
		require.True(t, mssmt.VerifyMerkleProof(k1, sharedLeaf, proof1, dbRoot))
	})
}
