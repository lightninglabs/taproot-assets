package tapdb

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
)

// benchIngestItems pre-generates n random minting leaves under a fresh
// issuance universe.
func benchIngestItems(b *testing.B, n int) []*universe.Item {
	b.Helper()

	assetGen := asset.RandGenesis(b, asset.Normal)
	id := universe.Identifier{
		AssetID:   assetGen.ID(),
		ProofType: universe.ProofTypeIssuance,
	}

	items := make([]*universe.Item, n)
	for i := 0; i < n; i++ {
		leaf := randMintingLeaf(b, assetGen, nil)
		items[i] = &universe.Item{
			ID:   id,
			Key:  randLeafKey(b),
			Leaf: &leaf,
		}
	}

	return items
}

// BenchmarkMultiverseLeafIngest measures the write-path cost of
// universe leaf insertion via UpsertProofLeafBatch: each op inserts a
// batch of pre-generated leaves under a fresh universe root, so per-op
// work stays constant across the run. batch=1 approximates a single
// proof push in its own tx, batch=200 the sync-side batch insert.
func BenchmarkMultiverseLeafIngest(b *testing.B) {
	for _, batch := range []int{1, 50, 200} {
		name := fmt.Sprintf("batch=%d", batch)
		b.Run(name, func(b *testing.B) {
			ctx := context.Background()
			store, _ := newTestMultiverse(b)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				items := benchIngestItems(b, batch)
				b.StartTimer()

				_, err := store.UpsertProofLeafBatch(ctx, items)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkMultiverseLeafIngestSingle measures single-leaf insertion
// into an already-populated universe: a 400-leaf universe is seeded
// once, then each op lands one new pre-generated leaf in its own tx.
// This is the shape of a steady stream of federation proof pushes.
func BenchmarkMultiverseLeafIngestSingle(b *testing.B) {
	const seedLeaves = 400

	ctx := context.Background()
	store, _ := newTestMultiverse(b)

	seed := benchIngestItems(b, seedLeaves)
	_, err := store.UpsertProofLeafBatch(ctx, seed)
	require.NoError(b, err)

	id := seed[0].ID
	assetGen := seed[0].Leaf.Genesis
	keys := make([]universe.LeafKey, b.N)
	leaves := make([]universe.Leaf, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = randLeafKey(b)
		leaves[i] = randMintingLeaf(b, assetGen, nil)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.UpsertProofLeaf(
			ctx, id, keys[i], &leaves[i], nil,
		)
		require.NoError(b, err)
	}
}

// BenchmarkMultiverseLeafIngestConcurrent measures cross-universe write
// parallelism: each op runs four goroutines, each inserting a 50-leaf
// batch under its own fresh universe root, and waits for all four.
func BenchmarkMultiverseLeafIngestConcurrent(b *testing.B) {
	const (
		workers = 4
		batch   = 50
	)

	ctx := context.Background()
	store, _ := newTestMultiverse(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		batches := make([][]*universe.Item, workers)
		for w := range batches {
			batches[w] = benchIngestItems(b, batch)
		}
		b.StartTimer()

		var wg sync.WaitGroup
		errs := make(chan error, workers)
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(items []*universe.Item) {
				defer wg.Done()
				_, err := store.UpsertProofLeafBatch(
					ctx, items,
				)
				errs <- err
			}(batches[w])
		}
		wg.Wait()
		close(errs)

		for err := range errs {
			require.NoError(b, err)
		}
	}
}
