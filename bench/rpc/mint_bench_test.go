package rpc

import (
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/lightninglabs/taproot-assets/bench/fixture"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
)

// BenchmarkListBatches covers ListBatches against an empty MintingStore.
// Populated-batch variants belong in the scenario suite.
//
// bench:rpc=mintrpc.Mint.ListBatches
func BenchmarkListBatches(b *testing.B) {
	f := fixture.NewMint(b)
	fixture.QueryBench(b, f.Server.ListBatches,
		&mintrpc.ListBatchRequest{})
}

// BenchmarkMintAsset covers MintAsset — enqueues one fresh seedling per
// iteration and waits for the first update from the planter. The batch
// is cancelled between iterations (under StopTimer) so each call lands
// against an empty pending batch; otherwise the per-call cost would
// grow with b.N as the batch accumulated.
//
// bench:rpc=mintrpc.Mint.MintAsset
func BenchmarkMintAsset(b *testing.B) {
	f := fixture.NewMint(b)
	ctx := b.Context()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var nameBytes [16]byte
		_, _ = rand.Read(nameBytes[:])
		req := &mintrpc.MintAssetRequest{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_NORMAL,
				Name:      hex.EncodeToString(nameBytes[:]),
				Amount:    1000,
			},
		}
		if _, err := f.Server.MintAsset(ctx, req); err != nil {
			b.Fatal(err)
		}

		b.StopTimer()
		// CancelBatch returns an error if the batch is already gone;
		// that is fine — we only need the side effect of clearing
		// state for the next iteration.
		_, _ = f.Planter.CancelBatch()
		b.StartTimer()
	}
}

// BenchmarkSealBatch covers SealBatch on a real frozen batch. Each
// iteration stages a fresh batch under StopTimer: enqueue one Normal
// seedling, fund the batch (driving it to frozen state), then time the
// SealBatch RPC. After sealing, the batch is finalized so the planter
// is back in a clean state for the next iteration.
//
// Setup/teardown dominate wall-clock but are excluded from the timing
// window; the reported per-op cost is the SealBatch handler itself.
//
// bench:rpc=mintrpc.Mint.SealBatch
func BenchmarkSealBatch(b *testing.B) {
	d := fixture.NewMintDriver(b)
	ctx := b.Context()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		d.EnqueueSeedlings(b, 1)
		d.FundPendingBatch(b)
		b.StartTimer()

		_, err := d.Server.SealBatch(ctx, &mintrpc.SealBatchRequest{})
		if err != nil {
			b.Fatal(err)
		}

		b.StopTimer()
		// Drive the sealed batch the rest of the way so the planter
		// is empty again for the next iteration.
		d.FinalizeBatch(b)
		b.StartTimer()
	}
}

// BenchmarkCancelBatch covers CancelBatch against an empty Planter. This
// exercises the planter's batch-state machine cheap path (no batch to
// cancel returns an error; we re-run the handler N times to measure the
// fast path on the empty state). The handler still returns the same error
// each iteration, which is fine for cost measurement.
//
// bench:rpc=mintrpc.Mint.CancelBatch
func BenchmarkCancelBatch(b *testing.B) {
	f := fixture.NewMint(b)

	ctx := b.Context()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Ignore the expected error; we are measuring the per-call cost
		// on the empty-batch path.
		_, _ = f.Server.CancelBatch(
			ctx, &mintrpc.CancelBatchRequest{},
		)
	}
}
