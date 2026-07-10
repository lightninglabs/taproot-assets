package scenario

import (
	"context"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/bench/fixture"
	"github.com/lightninglabs/taproot-assets/universe"
)

// steadyStateDelta is the number of leaves each divergent root is
// missing locally: the "d" in the steady-state cost model, i.e. what a
// mostly-synced node actually needs from one federation tick.
const steadyStateDelta = 4

// BenchmarkUniverseSync_SteadyState measures discovery cost on a
// mostly-synced node: all universes are locally present, one gained
// steadyStateDelta new leaves remotely since the last tick. The
// interesting output is not ns/op but the discovery metrics — how many
// round trips and bytes of enumeration it takes to find d new leaves.
// The delta-sync work (SOLUTION.md) should collapse discovery_share
// towards zero; the enumeration baseline reported here is the "before"
// column.
func BenchmarkUniverseSync_SteadyState(b *testing.B) {
	for _, roots := range []int{10, 50} {
		for _, leaves := range []int{100, 400} {
			name := fmt.Sprintf("roots=%d/leaves=%d/delta=%d",
				roots, leaves, steadyStateDelta)
			b.Run(name, func(b *testing.B) {
				overlap := float64(leaves-steadyStateDelta) /
					float64(leaves)
				runSteadySyncBench(b, fixture.SeedSpec{
					Issuance: fixture.RootSweep{
						Roots:  roots,
						Leaves: leaves,
					},
					LocalOverlap: fixture.NewFraction(
						overlap,
					),
					DivergentRoots: 1,
				})
			})
		}
	}
}

// BenchmarkUniverseSync_SteadyStateDelta is the delta-sync counterpart
// of BenchmarkUniverseSync_SteadyState: both sides start fully synced
// (cursor at the remote's high-water mark), the remote gains
// steadyStateDelta new leaves in one universe, and one tick runs via
// SyncUniverseDelta. Discovery cost should be O(delta): one delta page
// round trip carrying exactly the new leaves, no root or leaf-key
// enumeration at all.
func BenchmarkUniverseSync_SteadyStateDelta(b *testing.B) {
	for _, roots := range []int{10, 50} {
		for _, leaves := range []int{100, 400} {
			name := fmt.Sprintf("roots=%d/leaves=%d/delta=%d",
				roots, leaves, steadyStateDelta)
			b.Run(name, func(b *testing.B) {
				runDeltaSteadyBench(b, fixture.SeedSpec{
					Issuance: fixture.RootSweep{
						Roots:  roots,
						Leaves: leaves,
					},
					LocalOverlap: fixture.NewFraction(1),
				})
			})
		}
	}
}

// runSteadySyncBench mirrors runSyncBench but additionally reports the
// discovery metrics, which are the point of the steady-state scenario.
func runSteadySyncBench(b *testing.B, spec fixture.SeedSpec) {
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
		f.Discovery.Report(b)
		b.StartTimer()
	}
}

// runDeltaSteadyBench seeds a fully synced fixture, records the cursor,
// applies steadyStateDelta new remote leaves to the first issuance
// universe, then times a single delta sync tick.
func runDeltaSteadyBench(b *testing.B, spec fixture.SeedSpec) {
	b.Helper()

	ctx := context.Background()
	cfg := fixture.GlobalSyncConfig()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		f := fixture.NewSyncFixture(b, fixture.SyncFixtureOpts{})
		f.Seed(b, spec)
		cursor := f.RemoteMaxSeq(b)
		f.AddRemoteDivergence(
			b, universe.ProofTypeIssuance, 0, steadyStateDelta,
		)
		b.StartTimer()

		res, err := f.Syncer.SyncUniverseDelta(
			ctx, universe.ServerAddr{}, cursor, cfg,
		)
		if err != nil {
			b.Fatalf("delta sync: %v", err)
		}

		b.StopTimer()
		if res.NewCursor <= cursor {
			b.Fatalf("cursor did not advance: %d -> %d", cursor,
				res.NewCursor)
		}
		f.Metrics.Report(b)
		f.Discovery.Report(b)
		b.StartTimer()
	}
}
