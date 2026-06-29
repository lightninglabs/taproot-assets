package mssmt

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// treeCtor names a Tree constructor for the parametric property tests.
type treeCtor struct {
	name string
	make func() Tree
}

var batchTreeCtors = []treeCtor{
	{
		name: "FullTree",
		make: func() Tree { return NewFullTree(NewDefaultStore()) },
	},
	{
		name: "CompactedTree",
		make: func() Tree {
			return NewCompactedTree(NewDefaultStore())
		},
	},
}

// drawBatchKey draws a 32-byte key.
func drawBatchKey(t *rapid.T, label string) [hashSize]byte {
	var k [hashSize]byte
	bs := rapid.SliceOfN(rapid.Byte(), hashSize, hashSize).Draw(t, label)
	copy(k[:], bs)
	return k
}

// drawBatchLeaf draws a LeafNode with a bounded sum so cumulative sums
// across batches do not overflow uint64.
func drawBatchLeaf(t *rapid.T, label string) *LeafNode {
	valLen := rapid.IntRange(1, 32).Draw(t, label+"_len")
	val := rapid.SliceOfN(rapid.Byte(), valLen, valLen).Draw(
		t, label+"_val",
	)
	sum := rapid.Uint64Range(0, 1<<32).Draw(t, label+"_sum")
	return NewLeafNode(val, sum)
}

// drawBatchMap draws a distinct-key map of (key -> leaf) of size n.
// Duplicate-key draws are tolerated since the map deduplicates.
func drawBatchMap(t *rapid.T,
	n int) map[[hashSize]byte]*LeafNode {

	m := make(map[[hashSize]byte]*LeafNode, n)
	for i := 0; i < n; i++ {
		k := drawBatchKey(t, "k")
		m[k] = drawBatchLeaf(t, "leaf")
	}
	return m
}

// TestInsertManyEquivalence is the load-bearing batch-insert property:
// for any random distinct-key (key -> leaf) map, InsertMany must
// produce the same root hash and root sum as inserting the items
// sequentially via Insert. Run against both Tree implementations.
func TestInsertManyEquivalence(t *testing.T) {
	t.Parallel()

	for _, ctor := range batchTreeCtors {
		ctor := ctor
		t.Run(ctor.name, func(t *testing.T) {
			t.Parallel()

			rapid.Check(t, func(t *rapid.T) {
				n := rapid.IntRange(0, 32).Draw(t, "n")
				items := drawBatchMap(t, n)

				ctx := context.Background()

				loopTree := ctor.make()
				for k, l := range items {
					_, err := loopTree.Insert(ctx, k, l)
					require.NoError(t, err)
				}
				loopRoot, err := loopTree.Root(ctx)
				require.NoError(t, err)

				batchTree := ctor.make()
				_, err = batchTree.InsertMany(ctx, items)
				require.NoError(t, err)
				batchRoot, err := batchTree.Root(ctx)
				require.NoError(t, err)

				require.Equal(
					t, loopRoot.NodeHash(),
					batchRoot.NodeHash(),
					"InsertMany root hash diverges from "+
						"Insert-loop",
				)
				require.Equal(
					t, loopRoot.NodeSum(),
					batchRoot.NodeSum(),
					"InsertMany root sum diverges from "+
						"Insert-loop",
				)
			})
		})
	}
}

// TestInsertManyRoundTrip confirms that every leaf inserted via
// InsertMany can be Get-able and its MerkleProof verifies against the
// resulting root.
func TestInsertManyRoundTrip(t *testing.T) {
	t.Parallel()

	for _, ctor := range batchTreeCtors {
		ctor := ctor
		t.Run(ctor.name, func(t *testing.T) {
			t.Parallel()

			rapid.Check(t, func(t *rapid.T) {
				n := rapid.IntRange(1, 32).Draw(t, "n")
				items := drawBatchMap(t, n)

				ctx := context.Background()

				tree := ctor.make()
				_, err := tree.InsertMany(ctx, items)
				require.NoError(t, err)

				root, err := tree.Root(ctx)
				require.NoError(t, err)

				for k, expected := range items {
					if expected.IsEmpty() {
						continue
					}
					got, err := tree.Get(ctx, k)
					require.NoError(t, err)
					require.Equal(
						t, expected.NodeHash(),
						got.NodeHash(),
						"Get(k) returned a different "+
							"leaf",
					)

					proof, err := tree.MerkleProof(ctx, k)
					require.NoError(t, err)
					require.True(
						t,
						VerifyMerkleProof(
							k, got, proof, root,
						),
						"MerkleProof failed to verify "+
							"after InsertMany",
					)
				}
			})
		})
	}
}

// TestInsertManyOverPopulated draws an initial batch, inserts it via
// InsertMany, then draws a second batch and applies it via InsertMany
// on top. Compares against a tree built by Insert-loop over the union.
// This exercises the path where InsertMany lands on a tree containing
// CompactedLeafNodes from a prior batch.
func TestInsertManyOverPopulated(t *testing.T) {
	t.Parallel()

	for _, ctor := range batchTreeCtors {
		ctor := ctor
		t.Run(ctor.name, func(t *testing.T) {
			t.Parallel()

			rapid.Check(t, func(t *rapid.T) {
				n1 := rapid.IntRange(1, 16).Draw(t, "n1")
				n2 := rapid.IntRange(1, 16).Draw(t, "n2")
				first := drawBatchMap(t, n1)
				second := drawBatchMap(t, n2)

				ctx := context.Background()

				// Build via two InsertMany calls.
				batchTree := ctor.make()
				_, err := batchTree.InsertMany(ctx, first)
				require.NoError(t, err)
				_, err = batchTree.InsertMany(ctx, second)
				require.NoError(t, err)
				batchRoot, err := batchTree.Root(ctx)
				require.NoError(t, err)

				// Build by inserting every item one at a time.
				// second overrides first on key collisions.
				loopTree := ctor.make()
				for k, l := range first {
					_, err := loopTree.Insert(ctx, k, l)
					require.NoError(t, err)
				}
				for k, l := range second {
					_, err := loopTree.Insert(ctx, k, l)
					require.NoError(t, err)
				}
				loopRoot, err := loopTree.Root(ctx)
				require.NoError(t, err)

				require.Equal(
					t, loopRoot.NodeHash(),
					batchRoot.NodeHash(),
				)
				require.Equal(
					t, loopRoot.NodeSum(),
					batchRoot.NodeSum(),
				)
			})
		})
	}
}

// TestInsertManySumOverflow constructs a batch whose cumulative sum
// would overflow uint64 and requires InsertMany to return an error
// rather than panicking or producing a wrapped result.
func TestInsertManySumOverflow(t *testing.T) {
	t.Parallel()

	for _, ctor := range batchTreeCtors {
		ctor := ctor
		t.Run(ctor.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			tree := ctor.make()

			var k1, k2 [hashSize]byte
			k1[0] = 0x01
			k2[0] = 0x02
			items := map[[hashSize]byte]*LeafNode{
				k1: NewLeafNode([]byte("a"), ^uint64(0)-1),
				k2: NewLeafNode([]byte("b"), 10),
			}

			_, err := tree.InsertMany(ctx, items)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrIntegerOverflow)
		})
	}
}

// TestInsertManyOverflowReplacement covers the case where the batch
// replaces an existing large-sum leaf with a smaller one. Sequential
// Insert succeeds (the replaced sum drops out of the root before the
// next item is added); InsertMany must match that behaviour rather
// than rejecting on a naive currentRoot + batchSum check.
func TestInsertManyOverflowReplacement(t *testing.T) {
	t.Parallel()

	for _, ctor := range batchTreeCtors {
		ctor := ctor
		t.Run(ctor.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			var k1, k2 [hashSize]byte
			k1[0] = 0x01
			k2[0] = 0x02

			loopTree := ctor.make()
			_, err := loopTree.Insert(
				ctx, k1,
				NewLeafNode([]byte("big"), ^uint64(0)-5),
			)
			require.NoError(t, err)
			_, err = loopTree.Insert(
				ctx, k1, NewLeafNode([]byte("small"), 1),
			)
			require.NoError(t, err)
			_, err = loopTree.Insert(
				ctx, k2, NewLeafNode([]byte("c"), 10),
			)
			require.NoError(t, err)
			loopRoot, err := loopTree.Root(ctx)
			require.NoError(t, err)

			batchTree := ctor.make()
			_, err = batchTree.Insert(
				ctx, k1,
				NewLeafNode([]byte("big"), ^uint64(0)-5),
			)
			require.NoError(t, err)

			_, err = batchTree.InsertMany(
				ctx,
				map[[hashSize]byte]*LeafNode{
					k1: NewLeafNode([]byte("small"), 1),
					k2: NewLeafNode([]byte("c"), 10),
				},
			)
			require.NoError(
				t, err,
				"InsertMany rejected a batch that "+
					"sequential Insert accepts",
			)

			batchRoot, err := batchTree.Root(ctx)
			require.NoError(t, err)
			require.Equal(
				t, loopRoot.NodeHash(),
				batchRoot.NodeHash(),
			)
			require.Equal(
				t, loopRoot.NodeSum(),
				batchRoot.NodeSum(),
			)
		})
	}
}
