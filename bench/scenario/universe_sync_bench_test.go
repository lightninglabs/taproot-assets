package scenario

import (
	"context"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/bench/fixture"
	"github.com/lightninglabs/taproot-assets/universe"
)

// BenchmarkUniverseSync_FreshLocal drives a full sync into an empty
// local universe. This is the dominant cost the first time an operator
// joins a federation: every remote leaf crosses the wire and hits the
// registrar. Parameter sweeps expose how throughput and DB tx
// contention scale with the shape of the workload.
func BenchmarkUniverseSync_FreshLocal(b *testing.B) {
	for _, roots := range []int{10, 50} {
		for _, leaves := range []int{50, 200} {
			name := fmt.Sprintf("roots=%d/leaves=%d",
				roots, leaves)
			b.Run(name, func(b *testing.B) {
				runSyncBench(b, fixture.SeedSpec{
					Issuance: fixture.RootSweep{
						Roots:  roots,
						Leaves: leaves,
					},
					LocalOverlap: fixture.NewFraction(0),
				})
			})
		}
	}
}

// BenchmarkUniverseSync_MostlySynced is the key test for issue #2026's
// SetDiff fix. Local already has 90% of remote's leaves; correct
// behavior is to fetch only the missing 10%. Today's pointer-identity
// diff re-fetches everything — the leaves_inserted metric quantifies
// the over-fetch.
func BenchmarkUniverseSync_MostlySynced(b *testing.B) {
	for _, roots := range []int{10, 50} {
		for _, leaves := range []int{50, 200} {
			name := fmt.Sprintf("roots=%d/leaves=%d",
				roots, leaves)
			b.Run(name, func(b *testing.B) {
				runSyncBench(b, fixture.SeedSpec{
					Issuance: fixture.RootSweep{
						Roots:  roots,
						Leaves: leaves,
					},
					LocalOverlap: fixture.NewFraction(0.9),
				})
			})
		}
	}
}

// BenchmarkUniverseSync_Mixed interleaves issuance and transfer roots
// at roughly the same rate. It is the target for the Phase 2 ordering
// fix: today the syncer processes roots in the order the remote
// returned them, so a transfer root can race ahead of its issuance and
// surface a dep_missing metric. Post-Phase 2 that column should be
// zero.
func BenchmarkUniverseSync_Mixed(b *testing.B) {
	for _, leaves := range []int{50, 200} {
		name := fmt.Sprintf("leaves=%d", leaves)
		b.Run(name, func(b *testing.B) {
			runSyncBench(b, fixture.SeedSpec{
				Issuance: fixture.RootSweep{
					Roots:  20,
					Leaves: leaves,
				},
				Transfer: fixture.RootSweep{
					Roots:  20,
					Leaves: leaves,
				},
				LocalOverlap: fixture.NewFraction(0),
			})
		})
	}
}

// runSyncBench is the shared shape: build a fixture, seed it, then run
// b.N sync passes. Each iteration reseeds so the syncer sees the same
// diff each time — otherwise the second iteration would find nothing
// to sync and skew the numbers.
func runSyncBench(b *testing.B, spec fixture.SeedSpec) {
	b.Helper()

	ctx := context.Background()
	cfg := fixture.GlobalSyncConfig()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		f := fixture.NewSyncFixture(b, fixture.SyncFixtureOpts{})
		f.Seed(b, spec)
		b.StartTimer()

		_, err := f.Syncer.SyncUniverse(
			ctx, universe.ServerAddr{}, universe.SyncFull, cfg,
		)
		if err != nil {
			b.Fatalf("sync: %v", err)
		}

		b.StopTimer()
		f.Metrics.Report(b)
		b.StartTimer()
	}
}
