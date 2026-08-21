package tapdb

import (
	"context"
	"database/sql"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
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

	// Take the multiverse write lock, as every multiverse writer
	// must.
	multiverse.multiverseWriteMu.Lock()
	defer multiverse.multiverseWriteMu.Unlock()

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

// TestReconcileMultiversePagination asserts that the divergence scan
// finds divergence on every page of its keyset-paginated universe root
// scan, not just the first, and that a canceled context interrupts
// reconciliation.
func TestReconcileMultiversePagination(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	multiverse, _ := newTestMultiverse(t)

	// Force several pages with a handful of universes.
	multiverse.reconcilePageSize = 2

	const numUniverses = 7
	var numOrphaned int
	for i := 0; i < numUniverses; i++ {
		item := genRandomAsset(t)

		// Alternate healthy and orphaned universes, so divergence
		// appears on every page of the scan.
		if i%2 == 0 {
			_, err := multiverse.UpsertProofLeaf(
				ctx, item.ID, item.Key, item.Leaf,
				item.MetaReveal,
			)
			require.NoError(t, err)
			continue
		}

		_, err := insertUniverseLeafOnly(ctx, multiverse, item)
		require.NoError(t, err)
		numOrphaned++
	}

	diverged, err := multiverse.multiverseDivergence(ctx)
	require.NoError(t, err)
	require.Len(t, diverged, numOrphaned)

	require.NoError(t, multiverse.ReconcileMultiverse(ctx))

	diverged, err = multiverse.multiverseDivergence(ctx)
	require.NoError(t, err)
	require.Empty(t, diverged)

	// A canceled context interrupts reconciliation rather than
	// running it to completion.
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, multiverse.ReconcileMultiverse(canceledCtx))
}

// TestReconcileMultiverseSupplyTrees asserts that reconciliation
// ignores universe roots of proof types without a multiverse tree: the
// supply-commitment sub-trees (mint supply, burns, ignores) share the
// universe_roots table but have no multiverse leaves, so they must
// neither be reported as diverged nor be touched by a repair, while
// ordinary issuance/transfer divergence alongside them is still
// repaired.
func TestReconcileMultiverseSupplyTrees(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// A multiverse store and a supply tree store sharing one database,
	// as in the daemon.
	db := NewTestDB(t)
	multiverseTxer := NewTransactionExecutor(
		db, func(tx *sql.Tx) BaseMultiverseStore {
			return db.WithTx(tx)
		},
	)
	multiverse, err := NewMultiverseStore(
		multiverseTxer, DefaultMultiverseStoreConfig(),
	)
	require.NoError(t, err)
	t.Cleanup(multiverse.Stop)

	uniTxer := NewTransactionExecutor(
		db, func(tx *sql.Tx) BaseUniverseStore {
			return db.WithTx(tx)
		},
	)
	supplyStore := NewSupplyTreeStore(uniTxer)

	// A grouped asset with its genesis and group key on record, as the
	// supply tree paths require.
	groupPrivKey := asset.PrivKeyGen.Example()
	groupPub := groupPrivKey.PubKey()
	groupKey := &asset.GroupKey{GroupPubKey: *groupPub}

	baseGenesis := asset.GenesisGen.Example()
	baseAssetID := baseGenesis.ID()
	genesisPointID, err := upsertGenesisPoint(
		ctx, uniTxer, baseGenesis.FirstPrevOut,
	)
	require.NoError(t, err)
	genAssetID, err := upsertGenesis(
		ctx, uniTxer, genesisPointID, baseGenesis,
	)
	require.NoError(t, err)
	_, err = upsertGroupKey(
		ctx, groupKey, uniTxer, genesisPointID, genAssetID,
	)
	require.NoError(t, err)

	spec, err := asset.NewSpecifier(
		&baseAssetID, &groupKey.GroupPubKey, nil, true,
	)
	require.NoError(t, err)

	// Populate all three supply sub-trees through the production
	// helper.
	events := []supplycommit.SupplyUpdateEvent{
		randMintEventGen(groupPub).Example(),
		randBurnEventGen(baseGenesis, groupKey, uniTxer).Example(),
		randIgnoreEventGen(baseAssetID, uniTxer).Example(),
	}
	_, err = supplyStore.ApplySupplyUpdates(ctx, spec, events)
	require.NoError(t, err)

	// The sub-trees must be visible to the universe root scan the
	// divergence check pages through, or this test asserts nothing.
	// Ignore roots carry no asset ID, so the scan's genesis join drops
	// them before they could ever be misread as diverged; the mint
	// supply and burn roots are the ones that reach the proof type
	// check.
	roots, err := multiverse.queryRootNodes(
		ctx, sqlc.UniverseRootsParams{
			SortDirection: sqlInt16(universe.SortAscending),
			NumLimit:      universe.RequestPageSize,
		}, false,
	)
	require.NoError(t, err)
	seenProofTypes := fn.NewSet[universe.ProofType]()
	for _, root := range roots {
		seenProofTypes.Add(root.ID.ProofType)
	}
	require.True(t, seenProofTypes.Contains(universe.ProofTypeMintSupply))
	require.True(t, seenProofTypes.Contains(universe.ProofTypeBurn))

	subTreeRoots := func() map[supplycommit.SupplySubTree]mssmt.NodeHash {
		trees, err := supplyStore.FetchSubTrees(
			ctx, spec, fn.None[uint32](),
		).Unpack()
		require.NoError(t, err)

		hashes := make(map[supplycommit.SupplySubTree]mssmt.NodeHash)
		for treeType, tree := range trees {
			root, err := tree.Root(ctx)
			require.NoError(t, err)
			hashes[treeType] = root.NodeHash()
		}

		return hashes
	}
	before := subTreeRoots()
	require.Len(t, before, 3)

	// The supply sub-trees have no multiverse leaves, and must not be
	// reported as diverged.
	diverged, err := multiverse.multiverseDivergence(ctx)
	require.NoError(t, err)
	require.Empty(t, diverged)

	// Reconciling must succeed — this is the startup path of any node
	// holding supply commitments — and must leave the sub-trees
	// untouched.
	require.NoError(t, multiverse.ReconcileMultiverse(ctx))
	require.Equal(t, before, subTreeRoots())

	// Ordinary divergence alongside the supply sub-trees must still be
	// detected and repaired.
	orphan := genRandomAsset(t)
	_, err = insertUniverseLeafOnly(ctx, multiverse, orphan)
	require.NoError(t, err)

	diverged, err = multiverse.multiverseDivergence(ctx)
	require.NoError(t, err)
	require.Len(t, diverged, 1)

	require.NoError(t, multiverse.ReconcileMultiverse(ctx))

	diverged, err = multiverse.multiverseDivergence(ctx)
	require.NoError(t, err)
	require.Empty(t, diverged)
	require.Equal(t, before, subTreeRoots())
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
	t.Cleanup(multiverse.Stop)

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
