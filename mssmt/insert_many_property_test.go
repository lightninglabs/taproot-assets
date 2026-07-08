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

// drawBatchLeaf draws a LeafNode with a bounded sum so cumulative
// sums across batches do not overflow uint64. With probability ~25%
// it draws an EmptyLeafNode instead — these exercise the deletion
// paths in batchInsert/buildSubtree (delete-of-present-key, delete-
// of-absent-key, empty leaf into empty subtree) that are silently
// uncovered if all draws are non-empty.
func drawBatchLeaf(t *rapid.T, label string) *LeafNode {
	if rapid.IntRange(0, 3).Draw(t, label+"_empty") == 0 {
		return EmptyLeafNode
	}
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

// TestExistingSumGroundTruth pins the descent's existingSum
// accounting against an independent ground truth: for any random
// batch on a random tree, the sum that the descent collects must
// equal the sum of tree.Get(k).NodeSum() over k in the batch.
//
// This is the load-bearing invariant the overflow check relies on.
// If the descent over- or under-counts existingSum, the overflow
// gate either rejects valid batches or accepts overflowing ones.
func TestExistingSumGroundTruth(t *testing.T) {
	t.Parallel()

	for _, ctor := range batchTreeCtors {
		ctor := ctor
		t.Run(ctor.name, func(t *testing.T) {
			t.Parallel()

			rapid.Check(t, func(t *rapid.T) {
				ctx := context.Background()

				// Build a tree with a random initial
				// population.
				nInit := rapid.IntRange(0, 16).Draw(t, "n_init")
				initial := drawBatchMap(t, nInit)
				tree := ctor.make()
				_, err := tree.InsertMany(ctx, initial)
				require.NoError(t, err)

				// Draw a random batch. Some keys may overlap
				// with the initial population; some won't.
				// Make overlap likely by occasionally
				// re-using keys from the initial set.
				nBatch := rapid.IntRange(0, 16).Draw(
					t, "n_batch",
				)
				batch := make(map[[hashSize]byte]*LeafNode)
				initialKeys := make(
					[][hashSize]byte, 0, len(initial),
				)
				for k := range initial {
					initialKeys = append(initialKeys, k)
				}
				for i := 0; i < nBatch; i++ {
					var k [hashSize]byte
					reuse := len(initialKeys) > 0 &&
						rapid.IntRange(0, 1).Draw(
							t, "reuse",
						) == 0
					if reuse {
						idx := rapid.IntRange(
							0, len(initialKeys)-1,
						).Draw(t, "reuse_idx")
						k = initialKeys[idx]
					} else {
						k = drawBatchKey(t, "k")
					}
					batch[k] = drawBatchLeaf(t, "leaf")
				}

				// Ground truth: sum of existing leaves at
				// the batch's keys.
				var truth uint64
				for k := range batch {
					existing, err := tree.Get(ctx, k)
					require.NoError(t, err)
					if existing == nil ||
						existing.IsEmpty() {

						continue
					}
					truth += existing.NodeSum()
				}

				// Run the descent and capture what it
				// reports. We do this by side: call
				// InsertMany and then derive the implied
				// existingSum from the root-sum delta.
				oldRoot, err := tree.Root(ctx)
				require.NoError(t, err)
				oldSum := oldRoot.NodeSum()

				var batchSum uint64
				for _, leaf := range batch {
					batchSum += leaf.NodeSum()
				}

				_, err = tree.InsertMany(ctx, batch)
				require.NoError(t, err)

				newRoot, err := tree.Root(ctx)
				require.NoError(t, err)
				newSum := newRoot.NodeSum()

				// Implied existingSum from the observed
				// root-sum delta: newSum = oldSum - existing
				// + batchSum, so existing = oldSum +
				// batchSum - newSum (in uint64 arithmetic,
				// which won't wrap given our bounded draws).
				impliedExisting := oldSum + batchSum - newSum
				require.Equal(
					t, truth, impliedExisting,
					"descent's existingSum diverges from "+
						"ground truth",
				)
			})
		})
	}
}

// TestInsertManyOverflowAtomicity pins the atomicity claim of the
// descent/flush split: when overflow is detected on the
// rootSum+effectiveDelta gate (NOT on the early batchSum carry),
// the descent has already built the new-tree shape in memory and
// queued mutations, but the flush must NOT have happened. The
// tree's storage state must be byte-identical to its pre-call
// state.
//
// This is distinct from TestInsertManySumOverflow, which trips on
// the early batchSum accumulation carry before the descent runs.
// Here batchSum is small; what overflows is rootSum + batchSum.
func TestInsertManyOverflowAtomicity(t *testing.T) {
	t.Parallel()

	for _, ctor := range batchTreeCtors {
		ctor := ctor
		t.Run(ctor.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			tree := ctor.make()

			// Pre-populate: one leaf with a sum near uint64
			// max. rootSum becomes MaxUint64-10.
			var seedKey [hashSize]byte
			seedKey[0] = 0x01
			seedLeaf := NewLeafNode(
				[]byte("seed"), ^uint64(0)-10,
			)
			_, err := tree.Insert(ctx, seedKey, seedLeaf)
			require.NoError(t, err)

			// Snapshot the pre-call state.
			preRoot, err := tree.Root(ctx)
			require.NoError(t, err)
			preRootHash := preRoot.NodeHash()
			preRootSum := preRoot.NodeSum()
			preSeed, err := tree.Get(ctx, seedKey)
			require.NoError(t, err)

			// Batch: insert a small-sum leaf at a different
			// key. batchSum = 100 — no carry on accumulation.
			// existingSum = 0 — the key is not present. Then
			// rootSum (MaxUint64-10) + delta (100) overflows
			// the descent gate.
			var batchKey [hashSize]byte
			batchKey[0] = 0x02
			batch := map[[hashSize]byte]*LeafNode{
				batchKey: NewLeafNode([]byte("b"), 100),
			}
			_, err = tree.InsertMany(ctx, batch)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrIntegerOverflow)

			// Atomicity: the tree must look exactly as it did
			// before the failed call.
			postRoot, err := tree.Root(ctx)
			require.NoError(t, err)
			require.Equal(
				t, preRootHash, postRoot.NodeHash(),
				"root hash changed despite overflow error",
			)
			require.Equal(
				t, preRootSum, postRoot.NodeSum(),
				"root sum changed despite overflow error",
			)
			postSeed, err := tree.Get(ctx, seedKey)
			require.NoError(t, err)
			require.Equal(
				t, preSeed.NodeHash(), postSeed.NodeHash(),
				"seeded leaf hash changed despite "+
					"overflow error",
			)
			require.Equal(
				t, preSeed.NodeSum(), postSeed.NodeSum(),
				"seeded leaf sum changed despite "+
					"overflow error",
			)
			batchLeaf, err := tree.Get(ctx, batchKey)
			require.NoError(t, err)
			require.True(
				t, batchLeaf.IsEmpty(),
				"batch leaf was written despite overflow "+
					"error",
			)
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

// TestInsertOverflowReplacementParity asserts that Insert and
// InsertMany use the same replacement-aware overflow check: a leaf
// that REPLACES an existing leaf is judged against the effective
// delta (newSum - priorSum), not the conservative sum(rootSum,
// newSum) that both APIs used historically. Without this, a leaf
// that fits the final tree could be rejected on either API.
func TestInsertOverflowReplacementParity(t *testing.T) {
	t.Parallel()

	for _, ctor := range batchTreeCtors {
		ctor := ctor
		t.Run(ctor.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			var k [hashSize]byte
			k[0] = 0x01

			// Seed the tree with a leaf whose sum is one short of
			// MaxUint64. Replacing it with a small-sum leaf is a
			// valid operation; the final root sum drops below
			// uint64 max.
			tree := ctor.make()
			_, err := tree.Insert(
				ctx, k,
				NewLeafNode([]byte("big"), ^uint64(0)-5),
			)
			require.NoError(t, err)

			// Both APIs must accept the replacement.
			_, err = tree.Insert(
				ctx, k, NewLeafNode([]byte("small"), 10),
			)
			require.NoError(
				t, err,
				"Insert rejected a valid replacement",
			)

			batchTree := ctor.make()
			_, err = batchTree.Insert(
				ctx, k,
				NewLeafNode([]byte("big"), ^uint64(0)-5),
			)
			require.NoError(t, err)
			_, err = batchTree.InsertMany(
				ctx,
				map[[hashSize]byte]*LeafNode{
					k: NewLeafNode([]byte("small"), 10),
				},
			)
			require.NoError(
				t, err,
				"InsertMany rejected a valid replacement",
			)
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
