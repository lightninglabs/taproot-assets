package tapdb

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
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