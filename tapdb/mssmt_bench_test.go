package tapdb

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
)

// benchPopulate is the shape of a routine that populates a fresh
// CompactedTree inside an already-open outer transaction.
type benchPopulate func(context.Context, BaseUniverseStore, string,
	map[[32]byte]*mssmt.LeafNode) error

// benchRandLeaves draws a map of n leaves with random keys and
// bounded random sums, suitable for populating a fresh CompactedTree
// under benchmark.
func benchRandLeaves(n int) map[[32]byte]*mssmt.LeafNode {
	out := make(map[[32]byte]*mssmt.LeafNode, n)
	for i := 0; i < n; i++ {
		valueLen := test.RandInt31n(math.MaxUint8) + 1
		leaf := mssmt.NewLeafNode(
			test.RandBytes(int(valueLen)),
			mssmt.RandLeafAmount(),
		)
		out[test.RandHash()] = leaf
	}
	return out
}

// newBenchUniverseTxer stands up a fresh SQLite-backed BatchedUniverseTree,
// mirroring the shape callers like burn_tree / ignore_tree use in
// production.
func newBenchUniverseTxer(tb testing.TB) BatchedUniverseTree {
	db := NewTestDB(tb)
	return NewTransactionExecutor(
		db, func(tx *sql.Tx) BaseUniverseStore {
			return db.WithTx(tx)
		},
	)
}

// benchInsertLoop populates a fresh CompactedTree by calling Insert
// once per (key, leaf) pair within a single outer transaction.
func benchInsertLoop(ctx context.Context, db BaseUniverseStore,
	ns string, leaves map[[32]byte]*mssmt.LeafNode) error {

	tree := mssmt.NewCompactedTree(newTreeStoreWrapperTx(db, ns))
	for k, v := range leaves {
		if _, err := tree.Insert(ctx, k, v); err != nil {
			return err
		}
	}
	return nil
}

// benchInsertMany populates a fresh CompactedTree by calling InsertMany
// with the full batch within a single outer transaction.
func benchInsertMany(ctx context.Context, db BaseUniverseStore,
	ns string, leaves map[[32]byte]*mssmt.LeafNode) error {

	tree := mssmt.NewCompactedTree(newTreeStoreWrapperTx(db, ns))
	_, err := tree.InsertMany(ctx, leaves)
	return err
}

// runInsertBench times b.N repetitions of populate against a fresh
// SQLite-backed tree. Each iteration builds its own tree in its own
// namespace so the runs don't observe each other.
func runInsertBench(b *testing.B, ctx context.Context, prefix string,
	leaves map[[32]byte]*mssmt.LeafNode, populate benchPopulate) {

	writeTx := BaseUniverseStoreOptions{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		txer := newBenchUniverseTxer(b)
		ns := fmt.Sprintf("%s-%d", prefix, i)
		b.StartTimer()

		err := txer.ExecTx(
			ctx, &writeTx,
			func(db BaseUniverseStore) error {
				return populate(ctx, db, ns, leaves)
			},
		)
		require.NoError(b, err)
	}
}

// BenchmarkTreeInsertMany contrasts Insert-in-loop against a single
// InsertMany call on a SQLite-backed CompactedTree. Both variants run
// inside a single outer transaction and use the treeStoreWrapperTx pattern
// that real callers (burn_tree, ignore_tree, supply_tree) use — so the
// comparison isolates the batching win from fresh-tx overhead.
//
// The measured delta is a lower bound on the real DB win: Postgres over a
// socket in production pays more per round-trip than a local SQLite file,
// so the reduction in tx.InsertX / tx.DeleteX calls should translate to a
// larger wall-clock improvement there.
func BenchmarkTreeInsertMany(b *testing.B) {
	ctx := context.Background()

	for _, batch := range []int{100, 1_000} {
		leaves := benchRandLeaves(batch)

		b.Run(fmt.Sprintf("InsertLoop/batch=%d", batch),
			func(b *testing.B) {
				runInsertBench(
					b, ctx, "loop", leaves,
					benchInsertLoop,
				)
			})

		b.Run(fmt.Sprintf("InsertMany/batch=%d", batch),
			func(b *testing.B) {
				runInsertBench(
					b, ctx, "many", leaves,
					benchInsertMany,
				)
			})
	}
}

// benchProve reads the root of the tree in the given namespace alongside a
// MerkleProof for key.
func benchProve(ctx context.Context, db BaseUniverseStore, ns string,
	key [32]byte) (*mssmt.Proof, *mssmt.BranchNode, error) {

	tree := mssmt.NewCompactedTree(newTreeStoreWrapperTx(db, ns))

	root, err := tree.Root(ctx)
	if err != nil {
		return nil, nil, err
	}

	proof, err := tree.MerkleProof(ctx, key)
	if err != nil {
		return nil, nil, err
	}

	return proof, root, nil
}

// BenchmarkTreeMerkleProof times a single MerkleProof against a populated,
// DB-backed CompactedTree. Proof generation walks one GetChildren query per
// level from the root, so its cost should track the depth of the tree, not
// its size; comparing tree sizes exposes any per-level query whose work
// grows with the subtree beneath the node.
func BenchmarkTreeMerkleProof(b *testing.B) {
	ctx := context.Background()

	for _, size := range []int{1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("leaves=%d", size), func(b *testing.B) {
			leaves := benchRandLeaves(size)
			keys := make([][32]byte, 0, size)
			for k := range leaves {
				keys = append(keys, k)
			}

			const ns = "proof"
			txer := newBenchUniverseTxer(b)
			writeTx := BaseUniverseStoreOptions{}
			err := txer.ExecTx(
				ctx, &writeTx,
				func(db BaseUniverseStore) error {
					return benchInsertMany(
						ctx, db, ns, leaves,
					)
				},
			)
			require.NoError(b, err)

			readTx := NewBaseUniverseReadTx()
			prove := func(key [32]byte) (*mssmt.Proof,
				*mssmt.BranchNode) {

				var (
					proof *mssmt.Proof
					root  *mssmt.BranchNode
				)
				err := txer.ExecTx(
					ctx, &readTx,
					func(db BaseUniverseStore) error {
						var err error
						proof, root, err = benchProve(
							ctx, db, ns, key,
						)
						return err
					},
				)
				require.NoError(b, err)

				return proof, root
			}

			// Check that the proofs being timed are valid.
			proof, root := prove(keys[0])
			require.True(b, mssmt.VerifyMerkleProof(
				keys[0], leaves[keys[0]], proof, root,
			))

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				prove(keys[i%len(keys)])
			}
		})
	}
}
