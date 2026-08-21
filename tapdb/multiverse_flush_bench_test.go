package tapdb

import (
	"context"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
)

// BenchmarkMultiverseFlushRound measures the wall-clock cost of one
// coalescer flush transaction by the number of distinct dirty
// universes it carries. Its purpose is sizing maxFlushBatchSize
// against defaultFlushTimeout for a given backend: every timed
// operation is exactly one flush round in one database transaction.
//
// Run with a bounded iteration count, on the backend of interest:
//
//	go test ./tapdb -tags="test_db_postgres" \
//	    -bench MultiverseFlushRound -benchtime 3x -run '^$'
func BenchmarkMultiverseFlushRound(b *testing.B) {
	ctx := context.Background()

	for _, size := range []int{64, 256, 1024, 2048} {
		b.Run(fmt.Sprintf("universes_%d", size), func(b *testing.B) {
			benchmarkFlushRound(b, ctx, size)
		})
	}
}

// benchmarkFlushRound times flush rounds carrying size distinct
// universes each.
func benchmarkFlushRound(b *testing.B, ctx context.Context, size int) {
	multiverse, _ := newTestMultiverse(b)

	// One universe per slot, each holding one committed leaf and one
	// flushed multiverse entry, as on a node that has synced these
	// universes before.
	gens := make([]asset.Genesis, size)
	ids := make([]universe.Identifier, size)
	for i := range ids {
		gens[i] = asset.RandGenesis(b, asset.Normal)
		id := randUniverseID(
			b, false, withProofType(universe.ProofTypeIssuance),
		)
		leaf := randMintingLeaf(b, gens[i], id.GroupKey)
		id.AssetID = leaf.Asset.ID()
		ids[i] = id

		item := &universe.Item{
			ID:   id,
			Key:  randLeafKey(b),
			Leaf: &leaf,
		}
		_, err := insertUniverseLeafOnly(ctx, multiverse, item)
		require.NoError(b, err)
	}
	require.NoError(b, multiverse.rootCoalescer.updateRoots(ctx, ids))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		// Dirty every universe with a fresh committed leaf, outside
		// the timed section: the flush is what is being measured.
		b.StopTimer()
		for i := range ids {
			leaf := randMintingLeaf(b, gens[i], ids[i].GroupKey)
			item := &universe.Item{
				ID:   ids[i],
				Key:  randLeafKey(b),
				Leaf: &leaf,
			}
			_, err := insertUniverseLeafOnly(ctx, multiverse, item)
			require.NoError(b, err)
		}
		b.StartTimer()

		// One submission of every universe: a single flush round in
		// a single transaction.
		err := multiverse.rootCoalescer.updateRoots(ctx, ids)
		require.NoError(b, err)
	}
}
