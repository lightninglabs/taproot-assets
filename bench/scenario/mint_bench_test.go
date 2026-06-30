package scenario

import (
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/bench/fixture"
)

// BenchmarkMintBatch drives the planter from empty through to a confirmed
// batch of N assets, parameterised over batch size. This is the end-to-end
// cost the per-RPC mint benches do not capture: each per-RPC bench
// measures one step (MintAsset, FundBatch, ...); the scenario measures
// the entire flow.
//
// The driver fixture is expensive (sqlite tmpfile, planter goroutines,
// chain pump). It is created per sub-benchmark, not per iteration; each
// iteration enqueues N fresh seedlings and finalizes a fresh batch on
// the same fixture.
func BenchmarkMintBatch(b *testing.B) {
	for _, n := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("size=%d", n), func(b *testing.B) {
			d := fixture.NewMintDriver(b)

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				d.MintOne(b, n)
			}
		})
	}
}
