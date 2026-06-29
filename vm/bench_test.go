package vm

// VM benchmarks exercise vm.Execute over representative state transitions:
// a collectible transfer (single key-spend witness), a normal multi-input
// transfer (key spend + tapscript script spend), and a split transition.
//
// The transition fixtures are built once per sub-benchmark and the engine is
// re-constructed per iteration so allocations and validation cost are both
// captured.

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/commitment"
)

// benchExecute runs vm.Execute once per iteration over the transition built
// by f. The transition is built outside the timing loop; only engine
// construction + Execute are measured.
func benchExecute(b *testing.B, f stateTransitionFunc) {
	newAsset, splitSet, inputSet, blockHeight := f(b)

	splitAssets := make([]*commitment.SplitAsset, 0, len(splitSet))
	for _, sa := range splitSet {
		splitAssets = append(splitAssets, sa)
	}

	opts := []NewEngineOpt{
		WithChainLookup(&mockChainLookup{}),
		WithBlockHeight(blockHeight),
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine, err := New(newAsset, splitAssets, inputSet, opts...)
		if err != nil {
			b.Fatal(err)
		}
		if err := engine.Execute(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkExecuteCollectible benchmarks a single-witness collectible
// state transition.
func BenchmarkExecuteCollectible(b *testing.B) {
	benchExecute(b, collectibleStateTransition)
}

// BenchmarkExecuteNormal benchmarks a two-input normal-asset transfer with
// one key-spend witness and one tapscript script-spend witness.
func BenchmarkExecuteNormal(b *testing.B) {
	benchExecute(b, genNormalStateTransition(6, 0, 0, false, false))
}

// BenchmarkExecuteSplit benchmarks a split-output state transition.
func BenchmarkExecuteSplit(b *testing.B) {
	benchExecute(b, splitStateTransition)
}
