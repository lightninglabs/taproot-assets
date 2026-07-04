package tapdb

import (
	"context"
	"database/sql"
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// tamperMultiverseLeaf overwrites a universe's multiverse leaf with a
// bogus root, diverging it from the universe's actual root.
func tamperMultiverseLeaf(t require.TestingT, ctx context.Context,
	multiverse *MultiverseStore, id universe.Identifier) {

	var bogusHash mssmt.NodeHash
	copy(bogusHash[:], test.RandBytes(32))
	bogusRoot := mssmt.NewComputedBranch(
		bogusHash, uint64(test.RandInt[uint32]()),
	)

	var writeTx BaseMultiverseOptions
	err := multiverse.db.ExecTx(
		ctx, &writeTx, func(store BaseMultiverseStore) error {
			return upsertMultiverseLeafEntry(
				ctx, store, id, bogusRoot,
			)
		},
	)
	require.NoError(t, err)
}

// TestReconcileMultiverse asserts that startup reconciliation detects
// and repairs both kinds of divergence between the universe trees and
// the shared multiverse trees: a missing multiverse leaf (crash between
// universe commit and multiverse write) and a stale one.
func TestReconcileMultiverse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, _ := newTestMultiverse(t)

	// A healthy store must show no divergence, including when empty.
	updates, err := multiverse.multiverseDivergence(ctx)
	require.NoError(t, err)
	require.Empty(t, updates)

	// Insert a few items through the normal path.
	items := make([]*universe.Item, 3)
	for i := range items {
		items[i] = genRandomAsset(t)
	}
	require.NoError(t, multiverse.UpsertProofLeafBatch(ctx, items))

	updates, err = multiverse.multiverseDivergence(ctx)
	require.NoError(t, err)
	require.Empty(t, updates)

	// Orphan a new universe: leaf committed, multiverse never
	// updated.
	orphan := genRandomAsset(t)
	_, err = insertUniverseLeafOnly(ctx, multiverse, orphan)
	require.NoError(t, err)

	// Tamper an existing universe's multiverse entry.
	tamperMultiverseLeaf(t, ctx, multiverse, items[0].ID)

	updates, err = multiverse.multiverseDivergence(ctx)
	require.NoError(t, err)
	require.Len(t, updates, 2)

	// Reconciliation must repair both.
	require.NoError(t, multiverse.ReconcileMultiverse(ctx))

	updates, err = multiverse.multiverseDivergence(ctx)
	require.NoError(t, err)
	require.Empty(t, updates)

	// Reconciling a healthy store must be a no-op.
	require.NoError(t, multiverse.ReconcileMultiverse(ctx))
}

// TestReconcileMultiverseProps property-tests reconciliation: from any
// mix of healthy universes, orphaned universes (universe leaf committed
// but multiverse never updated) and tampered multiverse entries,
// ReconcileMultiverse must restore a state with no divergence. The
// store persists across property iterations, so repairs are also
// checked against cumulative state.
func TestReconcileMultiverseProps(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, _ := newTestMultiverse(t)

	rapid.Check(t, func(rt *rapid.T) {
		// Draw a batch of new universes, each healthy, orphaned or
		// with a tampered multiverse entry.
		numUniverses := rapid.IntRange(1, 4).Draw(rt, "num_universes")

		var expectDiverged int
		for i := 0; i < numUniverses; i++ {
			item := genRandomAsset(t)

			kind := rapid.SampledFrom([]string{
				"healthy", "orphaned", "tampered",
			}).Draw(rt, "kind")

			switch kind {
			case "healthy":
				_, err := multiverse.UpsertProofLeaf(
					ctx, item.ID, item.Key, item.Leaf,
					item.MetaReveal,
				)
				require.NoError(rt, err)

			case "orphaned":
				_, err := insertUniverseLeafOnly(
					ctx, multiverse, item,
				)
				require.NoError(rt, err)
				expectDiverged++

			case "tampered":
				_, err := multiverse.UpsertProofLeaf(
					ctx, item.ID, item.Key, item.Leaf,
					item.MetaReveal,
				)
				require.NoError(rt, err)

				tamperMultiverseLeaf(
					rt, ctx, multiverse, item.ID,
				)
				expectDiverged++
			}
		}

		// Exactly the orphaned and tampered universes must show
		// up as diverged: the previous iteration ended reconciled.
		updates, err := multiverse.multiverseDivergence(ctx)
		require.NoError(rt, err)
		require.Len(rt, updates, expectDiverged)

		require.NoError(rt, multiverse.ReconcileMultiverse(ctx))

		updates, err = multiverse.multiverseDivergence(ctx)
		require.NoError(rt, err)
		require.Empty(rt, updates)
	})
}

// TestReconcileMultiverseSyncerCache asserts that repairs made during
// startup reconciliation do not seed a partial syncer cache: with the
// cache enabled but not yet filled, the repair flushes install nothing,
// and the first syncer query afterwards returns the complete root set
// rather than just the repaired subset.
func TestReconcileMultiverseSyncerCache(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	db := NewTestDB(t)
	dbTxer := NewTransactionExecutor(
		db, func(tx *sql.Tx) BaseMultiverseStore {
			return db.WithTx(tx)
		},
	)
	cfg := DefaultMultiverseStoreConfig()
	cfg.Caches.SyncerCacheEnabled = true
	multiverse, err := NewMultiverseStore(dbTxer, cfg)
	require.NoError(t, err)

	// A few healthy universes, plus one orphaned universe whose leaf
	// committed without its multiverse update.
	const numHealthy = 4
	for i := 0; i < numHealthy; i++ {
		item := genRandomAsset(t)
		_, err := multiverse.UpsertProofLeaf(
			ctx, item.ID, item.Key, item.Leaf, item.MetaReveal,
		)
		require.NoError(t, err)
	}

	orphan := genRandomAsset(t)
	_, err = insertUniverseLeafOnly(ctx, multiverse, orphan)
	require.NoError(t, err)

	// Reconciliation repairs the orphan, which drives a flush
	// callback into the still-unfilled syncer cache.
	require.NoError(t, multiverse.ReconcileMultiverse(ctx))

	// A syncer query must now return every universe, not just the
	// repaired one.
	roots, err := multiverse.RootNodes(ctx, universe.RootNodesQuery{
		SortDirection: universe.SortAscending,
		Limit:         universe.RequestPageSize,
	})
	require.NoError(t, err)
	require.Len(t, roots, numHealthy+1)
}
