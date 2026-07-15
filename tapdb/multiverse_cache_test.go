package tapdb

import (
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestMultiverseRootsCachePerformance tests the cache hit vs. miss ratio of the
// multiverse store's root node cache.
func TestMultiverseRootsCachePerformance(t *testing.T) {
	ctx := context.Background()
	multiverse, _ := newTestMultiverse(t)

	// We insert many assets into the multiverse store.
	const numAssets = 300
	var (
		batch     []*universe.Item
		allLeaves []*universe.Item
	)
	for i := 0; i < numAssets; i++ {
		leaf := genRandomAsset(t)
		batch = append(batch, leaf)
		allLeaves = append(allLeaves, leaf)

		if i != 0 && (i+1)%100 == 0 {
			err := multiverse.UpsertProofLeafBatch(ctx, batch)
			require.NoError(t, err)

			t.Logf("Inserted %d assets", i+1)
			batch = nil
		}
	}

	// Let's fetch all roots. The cache should be completely empty at this
	// point, so we should have all misses.
	const pageSize = 64
	roots := queryRoots(t, multiverse, pageSize)
	require.Len(t, roots, numAssets)
	assertAllLeavesInRoots(t, allLeaves, roots)

	// We need to round up, since we need to make another query for the
	// remainder. And the way the cache query is built (query, if not found,
	// acquire lock, query again), we always make two queries for each page.
	numMisses := ((numAssets / pageSize) + 1) * 2
	require.EqualValues(t, 0, multiverse.rootNodeCache.hit.Load())
	require.EqualValues(
		t, numMisses, multiverse.rootNodeCache.miss.Load(),
	)

	// Now we'll fetch all assets again, this should be a cache hit for all
	// of them.
	roots = queryRoots(t, multiverse, pageSize)
	require.Len(t, roots, numAssets)
	assertAllLeavesInRoots(t, allLeaves, roots)

	numHits := (numAssets / pageSize) + 1
	require.EqualValues(t, numHits, multiverse.rootNodeCache.hit.Load())
	require.EqualValues(
		t, numMisses, multiverse.rootNodeCache.miss.Load(),
	)

	// We now turn on the syncer proof and make sure all our queries are
	// served by that cache.
	multiverse.syncerCache.enabled = true
	multiverse.cfg.Caches.SyncerCacheEnabled = true
	roots = queryRoots(t, multiverse, pageSize)
	require.Len(t, roots, numAssets)
	assertAllLeavesInRoots(t, allLeaves, roots)

	// The old page based cache should still have exactly the same numbers
	// as before.
	require.EqualValues(t, numHits, multiverse.rootNodeCache.hit.Load())
	require.EqualValues(
		t, numMisses, multiverse.rootNodeCache.miss.Load(),
	)

	// The new syncer cache should only have two misses, one from when the
	// cache was empty, one from after acquiring the write lock and all
	// other queries should be hits.
	require.EqualValues(t, 2, multiverse.syncerCache.miss.Load())
	require.EqualValues(t, numHits, multiverse.syncerCache.hit.Load())
}

// requireSameRoots asserts that two root slices are semantically equal:
// same order, identity, name and root node value. We can't use
// require.Equal directly, since the concrete mssmt.Node type behind a root
// differs depending on how the root was constructed.
func requireSameRoots(t require.TestingT, want, got []universe.Root) {
	require.Len(t, got, len(want))
	for i := range want {
		require.Equal(t, want[i].ID.Key(), got[i].ID.Key())
		require.Equal(t, want[i].AssetName, got[i].AssetName)
		require.Equal(
			t, want[i].Node.NodeHash(), got[i].Node.NodeHash(),
		)
		require.Equal(t, want[i].Node.NodeSum(), got[i].Node.NodeSum())
	}
}

// TestRootNodeCacheTargetedInvalidation tests that inserting a proof leaf
// into an existing universe only evicts the cached pages containing that
// universe's root, keeping all other pages warm, while inserting a leaf
// that creates a new universe invalidates the whole page cache.
func TestRootNodeCacheTargetedInvalidation(t *testing.T) {
	ctx := context.Background()
	db := NewTestDB(t)
	multiverse, _ := newTestMultiverseWithDb(t, db.BaseDB)

	misses := func() int64 {
		return multiverse.rootNodeCache.miss.Load()
	}

	// freshView reads all roots through a second store over the same
	// database. Its cache starts cold, so it always serves the ground
	// truth to compare the cached view against.
	const pageSize = 4
	freshView := func() []universe.Root {
		fresh, _ := newTestMultiverseWithDb(t, db.BaseDB)
		return queryRoots(t, fresh, pageSize)
	}

	// We insert a handful of assets, each one creating its own universe.
	const numAssets = 9
	items := make([]*universe.Item, numAssets)
	for i := range items {
		items[i] = genRandomAsset(t)
		_, err := multiverse.UpsertProofLeaf(
			ctx, items[i].ID, items[i].Key, items[i].Leaf, nil,
		)
		require.NoError(t, err)
	}

	// upsertLeaf inserts an additional leaf into the universe of the
	// given item, which is an update of an existing universe root.
	upsertLeaf := func(item *universe.Item) *universe.Proof {
		leaf := randMintingLeaf(
			t, item.Leaf.Genesis, item.ID.GroupKey,
		)
		uniProof, err := multiverse.UpsertProofLeaf(
			ctx, item.ID, randLeafKey(t), &leaf, nil,
		)
		require.NoError(t, err)

		return uniProof
	}

	// Page through all roots once to fill the page cache, then re-read
	// to make sure the pages are served from the cache.
	roots := queryRoots(t, multiverse, pageSize)
	require.Len(t, roots, numAssets)
	missesAfterFill := misses()

	roots = queryRoots(t, multiverse, pageSize)
	require.Equal(t, missesAfterFill, misses())
	requireSameRoots(t, freshView(), roots)

	// Inserting a second leaf into an existing universe must evict only
	// the page containing that universe's root. Re-reading all roots
	// then costs exactly one page refill (a refill counts two misses:
	// one before and one after taking the write lock), the other pages
	// stay warm, and the refilled page serves the new root value.
	// items[0] was inserted first, so its root sits on the first page.
	target := items[0]
	newProof := upsertLeaf(target)

	before := misses()
	roots = queryRoots(t, multiverse, pageSize)
	require.Equal(t, before+2, misses())
	requireSameRoots(t, freshView(), roots)

	found := false
	for _, root := range roots {
		if root.ID.Bytes() == target.ID.Bytes() {
			require.Equal(
				t, newProof.UniverseRoot.NodeHash(),
				root.Node.NodeHash(),
			)
			require.Equal(
				t, newProof.UniverseRoot.NodeSum(),
				root.Node.NodeSum(),
			)
			found = true
		}
	}
	require.True(t, found)

	// Inserting a proof that creates a new universe changes the page
	// composition, so it must invalidate all cached pages: re-reading
	// refills all three of them.
	newItem := genRandomAsset(t)
	_, err := multiverse.UpsertProofLeaf(
		ctx, newItem.ID, newItem.Key, newItem.Leaf, nil,
	)
	require.NoError(t, err)

	before = misses()
	roots = queryRoots(t, multiverse, pageSize)
	require.Equal(t, before+6, misses())
	require.Len(t, roots, numAssets+1)
	requireSameRoots(t, freshView(), roots)

	// Pages that carry grouped asset amounts are evicted on update just
	// like plain pages, while pages not containing the updated root
	// stay warm.
	amountsQuery := universe.RootNodesQuery{
		WithAmountsById: true,
		SortDirection:   universe.SortAscending,
		Offset:          0,
		Limit:           pageSize,
	}
	_, err = multiverse.RootNodes(ctx, amountsQuery)
	require.NoError(t, err)

	upsertLeaf(target)

	before = misses()
	roots = queryRoots(t, multiverse, pageSize)
	require.Equal(t, before+2, misses())
	requireSameRoots(t, freshView(), roots)

	before = misses()
	_, err = multiverse.RootNodes(ctx, amountsQuery)
	require.NoError(t, err)
	require.Equal(t, before+2, misses())

	// A batch consisting purely of updates must also evict only the
	// pages containing the updated roots. Both updated universes sit on
	// the first page, so re-reading costs a single page refill.
	updateItems := make([]*universe.Item, 2)
	for i := range updateItems {
		src := items[i+1]
		leaf := randMintingLeaf(t, src.Leaf.Genesis, src.ID.GroupKey)
		updateItems[i] = &universe.Item{
			ID:   src.ID,
			Key:  randLeafKey(t),
			Leaf: &leaf,
		}
	}
	require.NoError(t, multiverse.UpsertProofLeafBatch(ctx, updateItems))

	before = misses()
	roots = queryRoots(t, multiverse, pageSize)
	require.Equal(t, before+2, misses())
	requireSameRoots(t, freshView(), roots)

	// A batch that contains at least one universe creation must
	// invalidate all cached pages.
	leaf := randMintingLeaf(
		t, items[3].Leaf.Genesis, items[3].ID.GroupKey,
	)
	mixedBatch := []*universe.Item{
		genRandomAsset(t),
		{
			ID:   items[3].ID,
			Key:  randLeafKey(t),
			Leaf: &leaf,
		},
	}
	require.NoError(t, multiverse.UpsertProofLeafBatch(ctx, mixedBatch))

	before = misses()
	roots = queryRoots(t, multiverse, pageSize)
	require.Equal(t, before+6, misses())
	require.Len(t, roots, numAssets+2)
	requireSameRoots(t, freshView(), roots)

	// Deleting the last leaf of a universe removes the universe
	// entirely, which also wipes the page cache. Re-inserting the same
	// universe afterwards must be detected as a creation and wipe the
	// refilled pages again, even though a root with the same ID existed
	// before the deletion.
	victim := items[5]
	_, err = multiverse.DeleteProofLeaf(ctx, victim.ID, victim.Key)
	require.NoError(t, err)

	roots = queryRoots(t, multiverse, pageSize)
	require.Len(t, roots, numAssets+1)
	requireSameRoots(t, freshView(), roots)

	before = misses()
	_, err = multiverse.UpsertProofLeaf(
		ctx, victim.ID, victim.Key, victim.Leaf, nil,
	)
	require.NoError(t, err)

	roots = queryRoots(t, multiverse, pageSize)
	require.Equal(t, before+6, misses())
	require.Len(t, roots, numAssets+2)
	requireSameRoots(t, freshView(), roots)
}

// TestRootNodeCacheProperties is a model-based property test for the
// targeted invalidation of the root node page cache. The model is a
// database of universe roots in insertion (universe_roots.id) order. The
// central invariant is that the cache never serves a stale page: any page
// it returns must be identical to what a fresh database read would
// produce. Additionally, pages handed out to readers must never be
// mutated afterwards.
func TestRootNodeCacheProperties(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		cache := newRootNodeCache(10_000)

		// db models the universe_roots table: roots in insertion
		// order, with the invariant-relevant behavior that updates
		// change a row's value but never its position, while
		// creations append.
		var db []universe.Root

		// nonce makes generated identities and node values unique
		// and deterministic, which keeps rapid's shrinking stable.
		var nonce uint32
		newNode := func() mssmt.Node {
			nonce++
			var hash mssmt.NodeHash
			binary.BigEndian.PutUint32(hash[:4], nonce)

			return mssmt.NewComputedBranch(hash, uint64(nonce))
		}
		newRoot := func() universe.Root {
			nonce++
			var id universe.Identifier
			binary.BigEndian.PutUint32(id.AssetID[:4], nonce)
			id.ProofType = universe.ProofTypeIssuance

			return universe.Root{
				ID:        id,
				AssetName: fmt.Sprintf("asset-%d", nonce),
				Node:      newNode(),
			}
		}

		// pageFor computes the page a fresh database read would
		// return for the given query.
		pageFor := func(q universe.RootNodesQuery) []universe.Root {
			ordered := slices.Clone(db)
			if q.SortDirection == universe.SortDescending {
				slices.Reverse(ordered)
			}

			start := int(q.Offset)
			if start >= len(ordered) {
				return nil
			}
			end := min(start+int(q.Limit), len(ordered))

			return slices.Clone(ordered[start:end])
		}

		// tracked accumulates every query whose page was ever
		// cached. The cache is free to no longer hold any of them
		// (wipes and evictions are always allowed), but if it does
		// serve a page for one, that page must be fresh.
		tracked := make(map[rootPageQueryKey]universe.RootNodesQuery)

		// handed retains pages previously returned by the cache
		// together with a snapshot of their content, to assert that
		// the cache never mutates a page it already handed out.
		type handedPage struct {
			live []universe.Root
			snap []universe.Root
		}
		var handed []handedPage

		drawQuery := func(rt *rapid.T) universe.RootNodesQuery {
			return universe.RootNodesQuery{
				WithAmountsById: rapid.Bool().Draw(
					rt, "withAmounts",
				),
				SortDirection: rapid.SampledFrom(
					[]universe.SortDirection{
						universe.SortAscending,
						universe.SortDescending,
					},
				).Draw(rt, "dir"),
				Offset: rapid.Int32Range(
					0, int32(len(db)-1),
				).Draw(rt, "offset"),
				Limit: rapid.Int32Range(1, 5).Draw(
					rt, "limit",
				),
			}
		}

		rt.Repeat(map[string]func(*rapid.T){
			// Cache a page, as the fill path in RootNodes does
			// after a cache miss.
			"fill": func(rt *rapid.T) {
				if len(db) == 0 {
					return
				}

				q := drawQuery(rt)
				page := pageFor(q)
				cache.cacheRoots(q, page)
				tracked[newRootPageQuery(q)] = q
			},

			// Insert a leaf into an existing universe: its root
			// changes value but keeps its position.
			"update": func(rt *rapid.T) {
				if len(db) == 0 {
					return
				}

				idx := rapid.IntRange(0, len(db)-1).Draw(
					rt, "target",
				)
				db[idx].Node = newNode()
				cache.handleRootUpdate(
					db[idx], universeRootUpdated,
				)
			},

			// Insert the first leaf of a new universe: a new root
			// appears and shifts the page composition.
			"create": func(rt *rapid.T) {
				root := newRoot()
				db = append(db, root)
				cache.handleRootUpdate(
					root, universeRootCreated,
				)
			},

			// Delete a universe: its root disappears, which
			// shifts the page composition. The store handles
			// both deletion paths with a full cache wipe.
			"delete": func(rt *rapid.T) {
				if len(db) == 0 {
					return
				}

				idx := rapid.IntRange(0, len(db)-1).Draw(
					rt, "victim",
				)
				db = slices.Delete(db, idx, idx+1)
				cache.wipeCache()
			},

			// Invariant check, run after every action: the cache
			// may miss on any tracked query, but a page it does
			// serve must match a fresh database read.
			"": func(rt *rapid.T) {
				for _, q := range tracked {
					got := cache.fetchRoots(q, false)
					if len(got) == 0 {
						continue
					}

					requireSameRoots(rt, pageFor(q), got)

					handed = append(handed, handedPage{
						live: got,
						snap: slices.Clone(got),
					})
				}

				// Cap the retained pages to keep the check
				// cheap.
				if len(handed) > 50 {
					handed = handed[len(handed)-50:]
				}

				for _, h := range handed {
					requireSameRoots(rt, h.snap, h.live)
				}
			},
		})
	})
}

// TestRootNodeCacheConcurrency exercises the root node page cache with
// concurrent writers and readers. Invalidation runs after the database
// transaction commits, so a reader may briefly observe a page that predates
// a concurrent commit; once all writers are done, however, the cache must
// have converged: every page it still serves has to match a fresh database
// read. Under the race detector this also validates the locking of the
// fill, wipe and eviction paths.
func TestRootNodeCacheConcurrency(t *testing.T) {
	ctx := context.Background()
	db := NewTestDB(t)
	multiverse, _ := newTestMultiverseWithDb(t, db.BaseDB)

	// The concurrency is deliberately modest: postgres runs these
	// transactions under serializable isolation, and too many overlapping
	// writers and readers exhaust the default predicate lock allowance
	// of the test fixture (SQLSTATE 53200), which is not a retryable
	// serialization failure.
	const (
		numSeed    = 16
		pageSize   = int32(4)
		numWriters = 2
		numReaders = 2
		numOps     = 20
	)

	// Seed a set of universes for the update operations to target.
	seed := make([]*universe.Item, numSeed)
	for i := range seed {
		seed[i] = genRandomAsset(t)
		_, err := multiverse.UpsertProofLeaf(
			ctx, seed[i].ID, seed[i].Key, seed[i].Leaf, nil,
		)
		require.NoError(t, err)
	}

	// The test helpers draw their randomness through the test object, so
	// we pre-generate every writer's workload on the main goroutine.
	// Most operations update an existing universe, with an occasional
	// creation sprinkled in so wipes race with fills and evictions.
	newUpdate := func(src *universe.Item) *universe.Item {
		leaf := randMintingLeaf(t, src.Leaf.Genesis, src.ID.GroupKey)
		return &universe.Item{
			ID:   src.ID,
			Key:  randLeafKey(t),
			Leaf: &leaf,
		}
	}
	workloads := make([][]*universe.Item, numWriters)
	for w := range workloads {
		workloads[w] = make([]*universe.Item, numOps)
		for op := range workloads[w] {
			if op%5 == 0 {
				workloads[w][op] = genRandomAsset(t)
				continue
			}

			workloads[w][op] = newUpdate(seed[(w+op)%numSeed])
		}
	}

	pageQuery := func(offset int32) universe.RootNodesQuery {
		return universe.RootNodesQuery{
			SortDirection: universe.SortAscending,
			Offset:        offset,
			Limit:         pageSize,
		}
	}

	// readAll pages through all roots, filling the cache as it goes.
	readAll := func() error {
		for offset := int32(0); ; offset += pageSize {
			page, err := multiverse.RootNodes(
				ctx, pageQuery(offset),
			)
			if err != nil {
				return err
			}
			if int32(len(page)) < pageSize {
				return nil
			}
		}
	}

	errs := make(chan error, numWriters+numReaders)

	// Half the writers upsert leaves one at a time, the other half in
	// batches, so both invalidation paths run concurrently.
	var writers sync.WaitGroup
	for w := 0; w < numWriters; w++ {
		writers.Add(1)
		go func(ops []*universe.Item, useBatch bool) {
			defer writers.Done()

			if useBatch {
				const chunk = 5
				for i := 0; i < len(ops); i += chunk {
					end := min(i+chunk, len(ops))
					err := multiverse.UpsertProofLeafBatch(
						ctx, ops[i:end],
					)
					if err != nil {
						errs <- err
						return
					}
				}

				return
			}

			for _, op := range ops {
				_, err := multiverse.UpsertProofLeaf(
					ctx, op.ID, op.Key, op.Leaf, nil,
				)
				if err != nil {
					errs <- err
					return
				}
			}
		}(workloads[w], w%2 == 1)
	}

	// Readers keep paging through the roots until the writers are done.
	done := make(chan struct{})
	var readers sync.WaitGroup
	for r := 0; r < numReaders; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()

			for {
				select {
				case <-done:
					return
				case <-time.After(time.Millisecond):
				}

				if err := readAll(); err != nil {
					errs <- err
					return
				}
			}
		}()
	}

	writers.Wait()
	close(done)
	readers.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	// With all writers done, every page the cache still serves must
	// match what a fresh store reads from the database.
	fresh, _ := newTestMultiverseWithDb(t, db.BaseDB)
	for offset := int32(0); ; offset += pageSize {
		q := pageQuery(offset)

		cachedPage, err := multiverse.RootNodes(ctx, q)
		require.NoError(t, err)

		freshPage, err := fresh.RootNodes(ctx, q)
		require.NoError(t, err)

		requireSameRoots(t, freshPage, cachedPage)

		if int32(len(freshPage)) < pageSize {
			break
		}
	}
}

// TestMultiverseSyncerCache tests the syncer cache of the multiverse store.
func TestMultiverseSyncerCache(t *testing.T) {
	ctx := context.Background()
	multiverse, _ := newTestMultiverse(t)
	multiverse.syncerCache.enabled = true
	multiverse.cfg.Caches.SyncerCacheEnabled = true

	// We insert a couple of assets into the multiverse store.
	const (
		numAssets = 50
		pageSize  = 10
	)
	var allLeaves []*universe.Item
	for i := 0; i < numAssets; i++ {
		leaf := genRandomAsset(t)
		allLeaves = append(allLeaves, leaf)
	}

	err := multiverse.UpsertProofLeafBatch(ctx, allLeaves)
	require.NoError(t, err)

	// We query all roots and make sure they are all there. This will also
	// cause the syncer cache to be filled.
	originalRoots := queryRoots(t, multiverse, pageSize)
	require.Len(t, originalRoots, numAssets)
	assertAllLeavesInRoots(t, allLeaves, originalRoots)

	// Because we've enabled the cache from the beginning, the leaves
	// inserted into the DB above should already be in the cache. That means
	// we should have zero misses.
	hitsPerFetch := numAssets / pageSize
	require.EqualValues(t, 0, multiverse.syncerCache.miss.Load())
	require.EqualValues(t, hitsPerFetch, multiverse.syncerCache.hit.Load())

	// We now randomly remove and re-insert some of the assets. The result
	// should always be identical to the original one.
	for i := 0; i < numAssets*100; i++ {
		// Remove a random root from the cache.
		root := originalRoots[test.RandIntn(len(originalRoots))]
		cache := multiverse.syncerCache
		cache.remove(root.ID.Key())

		// The key should be removed from the cache.
		require.Len(t, cache.universeKeyList, numAssets-1)
		require.Len(t, cache.universeRoots, numAssets-1)
		require.NotContains(t, cache.universeKeyList, root.ID.Key())
		require.NotContains(t, cache.universeRoots, root.ID.Key())

		// Re-insert the root.
		cache.addOrReplace(root)

		require.Len(t, cache.universeKeyList, numAssets)
		require.Len(t, cache.universeRoots, numAssets)
		require.Contains(t, cache.universeKeyList, root.ID.Key())
		require.Contains(t, cache.universeRoots, root.ID.Key())

		roots := queryRoots(t, multiverse, pageSize)
		require.Len(t, roots, numAssets)
		require.Equal(t, originalRoots, roots)

		// No matter how we manipulate the entries, we should always hit
		// the cache for syncer queries.
		hits := hitsPerFetch * (i + 2)
		require.EqualValues(t, 0, multiverse.syncerCache.miss.Load())
		require.EqualValues(t, hits, multiverse.syncerCache.hit.Load())
	}
}

func genRandomAsset(t *testing.T) *universe.Item {
	proofType := universe.ProofTypeIssuance
	if test.RandBool() {
		proofType = universe.ProofTypeTransfer
	}

	assetGen := asset.RandGenesis(t, asset.Normal)
	id := randUniverseID(t, test.RandBool(), withProofType(proofType))
	leaf := randMintingLeaf(t, assetGen, id.GroupKey)
	id.AssetID = leaf.Asset.ID()
	targetKey := randLeafKey(t)

	// For transfer proofs, we'll modify the witness asset proof to look
	// more like a transfer.
	if proofType == universe.ProofTypeTransfer {
		prevWitnesses := leaf.Asset.PrevWitnesses
		prevWitnesses[0].TxWitness = [][]byte{
			{1}, {1}, {1},
		}
		prevID := prevWitnesses[0].PrevID
		prevID.OutPoint.Hash = [32]byte{1}
	}

	return &universe.Item{
		ID:           id,
		Key:          targetKey,
		Leaf:         &leaf,
		LogProofSync: false,
	}
}

// TestSyncerCacheMemoryUsage tests the memory usage of the syncer cache.
func TestSyncerCacheMemoryUsage(t *testing.T) {
	for _, numRoots := range []uint64{500, 5_000, 50_000} {
		allRoots := make([]universe.Root, numRoots)
		start := time.Now()
		for i := uint64(0); i < numRoots; i++ {
			proofType := universe.ProofTypeIssuance
			if test.RandBool() {
				proofType = universe.ProofTypeTransfer
			}

			assetGen := asset.RandGenesis(t, asset.Normal)
			id := randUniverseID(
				t, test.RandBool(), withProofType(proofType),
			)
			allRoots[i] = universe.Root{
				ID:        id,
				AssetName: assetGen.Tag,
				Node: mssmt.NewComputedBranch(
					id.Bytes(), 1,
				),
			}
		}
		t.Logf("Generated %d roots in %v", numRoots, time.Since(start))

		t.Run(fmt.Sprintf("%d roots", numRoots), func(t *testing.T) {
			res := testing.Benchmark(func(b *testing.B) {
				b.ReportAllocs()

				cache := newSyncerRootNodeCache(true, numRoots)
				cache.replaceCache(allRoots)
			})

			t.Logf("Memory usage for %d roots: %d bytes",
				numRoots, res.MemBytes)
			t.Logf("Memory usage per root: %d bytes",
				res.MemBytes/numRoots)
			t.Logf("Benchmark took %v", res.T)
		})
	}
}

// TestUniverseProofCache exercises the basic behaviors of the universe proof
// cache to ensure inserts, fetches, evictions, and removals behave as
// expected.
func TestUniverseProofCache(t *testing.T) {
	t.Parallel()

	// 1 MiB cache for most subtests.
	const testCacheSizeBytes = 1 << 20

	t.Run("insert and fetch", func(t *testing.T) {
		cache := newUniverseProofCache(testCacheSizeBytes)

		id := randUniverseID(t, false)
		leafKey := randLeafKey(t)
		proofs := newTestUniverseProofs(t, 1)

		// The cache should miss until an entry is inserted.
		require.Nil(t, cache.fetchProof(id, leafKey))
		require.EqualValues(t, 0, cache.hit.Load())
		require.EqualValues(t, 1, cache.miss.Load())

		cache.insertProofs(id, leafKey, proofs)

		cached := cache.fetchProof(id, leafKey)
		require.Equal(t, proofs, cached)
		require.EqualValues(t, 1, cache.hit.Load())
		require.EqualValues(t, 1, cache.miss.Load())
	})

	t.Run("eviction respects capacity", func(t *testing.T) {
		// Configure the cache to hold only two entries worth of data so
		// the eviction order is deterministic once a third entry
		// arrives.
		baseProofs := newTestUniverseProofs(t, 1)
		proofSize := proofCacheEntrySize(t, baseProofs)
		maxBytes := proofSize * 2
		cache := newUniverseProofCache(maxBytes)

		id := randUniverseID(t, false)
		keys := []universe.LeafKey{
			randLeafKey(t),
			randLeafKey(t),
			randLeafKey(t),
		}

		for _, key := range keys {
			cache.insertProofs(id, key, cloneProofSlice(baseProofs))
		}

		require.Equal(t, 2, cache.cache.Len())
		require.LessOrEqual(t, cache.cache.Size(), maxBytes)

		// The oldest entry should have been evicted while the most
		// recently inserted entries remain.
		require.Nil(t, cache.fetchProof(id, keys[0]))
		require.NotNil(t, cache.fetchProof(id, keys[1]))
		require.NotNil(t, cache.fetchProof(id, keys[2]))
	})

	t.Run("removals", func(t *testing.T) {
		cache := newUniverseProofCache(testCacheSizeBytes)

		id1 := randUniverseID(t, false)
		id2 := randUniverseID(t, false)

		leaf1 := randLeafKey(t)
		leaf2 := randLeafKey(t)

		cache.insertProofs(id1, leaf1, newTestUniverseProofs(t, 1))
		cache.insertProofs(id1, leaf2, newTestUniverseProofs(t, 1))
		cache.insertProofs(id2, leaf1, newTestUniverseProofs(t, 1))

		cache.RemoveLeafKeyProofs(id1, leaf1)
		require.Nil(t, cache.fetchProof(id1, leaf1))
		require.NotNil(t, cache.fetchProof(id1, leaf2))
		require.NotNil(t, cache.fetchProof(id2, leaf1))

		cache.RemoveUniverseProofs(id1)
		require.Nil(t, cache.fetchProof(id1, leaf2))
		require.NotNil(t, cache.fetchProof(id2, leaf1))
	})

	t.Run("cache logger default size formatting", func(t *testing.T) {
		cache := newUniverseProofCache(testCacheSizeBytes)

		require.NotNil(t, cache.cacheLogger.cacheSize)
		require.Equal(
			t, humanize.Bytes(0), cache.cacheLogger.cacheSize(),
		)

		id := randUniverseID(t, false)
		leafKey := randLeafKey(t)
		proofs := newTestUniverseProofs(t, 1)

		cache.insertProofs(id, leafKey, proofs)
		require.Equal(t, humanize.Bytes(cache.cache.Size()),
			cache.cacheLogger.cacheSize())

		cache.RemoveLeafKeyProofs(id, leafKey)
		require.Equal(
			t, humanize.Bytes(0), cache.cacheLogger.cacheSize(),
		)
	})

	t.Run("secondary index stays in sync", func(t *testing.T) {
		// Validate the byID secondary index against the LRU's
		// own contents across the operations that mutate it:
		// explicit removes (leaf and universe), capacity-driven
		// evictions, and replace-in-place. The index is what
		// makes RemoveUniverseProofs O(k) instead of O(N), so a
		// drift between it and the LRU would silently regress
		// to phantom entries or to leaves that escape eviction.
		baseProofs := newTestUniverseProofs(t, 1)
		proofSize := proofCacheEntrySize(t, baseProofs)
		cache := newUniverseProofCache(proofSize * 2)

		id1 := randUniverseID(t, false)
		id2 := randUniverseID(t, false)
		key1 := randLeafKey(t)
		key2 := randLeafKey(t)
		key3 := randLeafKey(t)

		assertIndexMatchesCache := func() {
			t.Helper()
			cached := make(
				map[UniverseProofKey]struct{},
				cache.cache.Len(),
			)
			cache.cache.Range(
				func(k UniverseProofKey,
					_ *cachedProofs) bool {

					cached[k] = struct{}{}
					return true
				},
			)

			var indexed int
			for idKey, set := range cache.byID {
				require.NotEmpty(
					t, set, "empty per-id set "+
						"should have been pruned",
				)
				for lk := range set {
					indexed++
					key := UniverseProofKey{
						uniIDKey:     idKey,
						leafKeyBytes: lk,
					}
					_, ok := cached[key]
					require.True(t, ok,
						"index has phantom "+
							"entry for %v", key)
				}
			}
			require.Equal(
				t, len(cached), indexed,
				"index missing entries present in LRU",
			)
		}

		// Two inserts under id1 fill the cache to capacity.
		cache.insertProofs(id1, key1, cloneProofSlice(baseProofs))
		cache.insertProofs(id1, key2, cloneProofSlice(baseProofs))
		assertIndexMatchesCache()

		// A third insert under id2 evicts key1 (LRU tail). The
		// onDelete callback must prune key1 from byID[id1].
		cache.insertProofs(id2, key3, cloneProofSlice(baseProofs))
		require.Nil(t, cache.fetchProof(id1, key1))
		assertIndexMatchesCache()

		// Replacing an existing key in place does not fire
		// onDelete; the index should remain identical.
		cache.insertProofs(id2, key3, cloneProofSlice(baseProofs))
		assertIndexMatchesCache()

		// RemoveUniverseProofs(id1) drops the remaining id1
		// entry and its id-level set; id2 stays untouched.
		cache.RemoveUniverseProofs(id1)
		require.Nil(t, cache.fetchProof(id1, key2))
		require.NotNil(t, cache.fetchProof(id2, key3))
		_, present := cache.byID[id1.Key()]
		require.False(
			t, present, "byID set for id1 must be pruned "+
				"after RemoveUniverseProofs",
		)
		assertIndexMatchesCache()

		// Final RemoveLeafKeyProofs empties the cache.
		cache.RemoveLeafKeyProofs(id2, key3)
		require.Equal(t, 0, cache.cache.Len())
		require.Empty(t, cache.byID)
	})
}

func queryRoots(t *testing.T, multiverse *MultiverseStore,
	pageSize int32) []universe.Root {

	var (
		offset int32
		roots  []universe.Root
	)
	for {
		newRoots, err := multiverse.RootNodes(
			context.Background(), universe.RootNodesQuery{
				WithAmountsById: false,
				SortDirection:   universe.SortAscending,
				Offset:          offset,
				Limit:           pageSize,
			},
		)
		require.NoError(t, err)

		roots = append(roots, newRoots...)
		offset += pageSize

		if len(newRoots) < int(pageSize) {
			break
		}
	}

	return roots
}

func assertAllLeavesInRoots(t *testing.T, allLeaves []*universe.Item,
	roots []universe.Root) {

	for idx, leaf := range allLeaves {
		haveRoot := false
		for _, root := range roots {
			if root.ID.Bytes() == leaf.ID.Bytes() {
				haveRoot = true
				break
			}
		}

		require.Truef(t, haveRoot, "no root found for leaf with ID %s "+
			"idx %d", leaf.ID.StringForLog(), idx)
	}
}

// newTestUniverseProofs returns a slice of random universe proofs for use in
// cache tests.
func newTestUniverseProofs(t *testing.T, count int) []*universe.Proof {
	t.Helper()

	proofs := make([]*universe.Proof, count)
	for i := 0; i < count; i++ {
		leaf := randMintingLeaf(
			t, asset.RandGenesis(t, asset.Normal), nil,
		)
		leafCopy := leaf

		proofs[i] = &universe.Proof{
			Leaf:                     &leafCopy,
			LeafKey:                  randLeafKey(t),
			UniverseRoot:             leafCopy.SmtLeafNode(),
			UniverseInclusionProof:   &mssmt.Proof{},
			MultiverseRoot:           leafCopy.SmtLeafNode(),
			MultiverseInclusionProof: &mssmt.Proof{},
		}
	}

	return proofs
}

// proofCacheEntrySize returns the computed cache size for a single cache entry.
func proofCacheEntrySize(t *testing.T, proofs []*universe.Proof) uint64 {
	t.Helper()

	cached := newCachedProofs(proofs)
	size, err := (&cached).Size()
	require.NoError(t, err)
	require.NotZero(t, size)

	return size
}

// cloneProofSlice returns a shallow copy of the provided proof slice so that
// callers can reuse deterministic proof fixtures without sharing slice headers.
func cloneProofSlice(proofs []*universe.Proof) []*universe.Proof {
	cloned := make([]*universe.Proof, len(proofs))
	copy(cloned, proofs)

	return cloned
}
