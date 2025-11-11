package tapdb

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
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

	cached := cachedProofs(proofs)
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
