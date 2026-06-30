package commitment

import (
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/stretchr/testify/require"
)

// benchAssets returns n random Normal assets that all share the same genesis,
// so they belong to the same AssetCommitment.
func benchAssets(b *testing.B, n int) []*asset.Asset {
	b.Helper()

	genesis := asset.RandGenesis(b, asset.Normal)

	assets := make([]*asset.Asset, n)
	for i := 0; i < n; i++ {
		scriptKey := asset.RandScriptKey(b)
		assets[i] = asset.RandAssetWithValues(
			b, genesis, nil, scriptKey,
		)
	}

	return assets
}

// benchAssetCommitments returns n AssetCommitments, each backed by a distinct
// genesis so they live under distinct TapCommitmentKeys.
func benchAssetCommitments(b *testing.B, n int) []*AssetCommitment {
	b.Helper()

	commits := make([]*AssetCommitment, n)
	for i := 0; i < n; i++ {
		a := asset.RandAsset(b, asset.Normal)
		c, err := NewAssetCommitment(a)
		require.NoError(b, err)
		commits[i] = c
	}

	return commits
}

// BenchmarkNewAssetCommitment measures the cost of grouping N assets sharing
// a genesis into a single AssetCommitment.
func BenchmarkNewAssetCommitment(b *testing.B) {
	for _, n := range []int{1, 16, 256} {
		b.Run(fmt.Sprintf("assets=%d", n), func(b *testing.B) {
			assets := benchAssets(b, n)

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := NewAssetCommitment(assets...)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkNewTapCommitment measures the cost of constructing a TapCommitment
// from N distinct AssetCommitments.
func BenchmarkNewTapCommitment(b *testing.B) {
	for _, n := range []int{1, 16, 256} {
		b.Run(fmt.Sprintf("commits=%d", n), func(b *testing.B) {
			commits := benchAssetCommitments(b, n)

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := NewTapCommitment(nil, commits...)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkTapCommitmentUpsert measures the cost of upserting one more
// AssetCommitment into a TapCommitment of size N. The tree is rebuilt at
// size N before every timed call so the measurement reflects the
// labelled steady state and does not drift up as the bench loop runs.
func BenchmarkTapCommitmentUpsert(b *testing.B) {
	for _, n := range []int{16, 256, 4096} {
		b.Run(fmt.Sprintf("existing=%d", n), func(b *testing.B) {
			base := benchAssetCommitments(b, n)
			extra := benchAssetCommitments(b, b.N)

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				tc, err := NewTapCommitment(nil, base...)
				require.NoError(b, err)
				b.StartTimer()

				if err := tc.Upsert(extra[i]); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkTapCommitmentDelete measures the cost of deleting one
// AssetCommitment from a TapCommitment of size N+1. The tree is rebuilt
// at size N+1 before every timed call so the measurement reflects the
// labelled steady state and does not drift down across the bench loop.
func BenchmarkTapCommitmentDelete(b *testing.B) {
	for _, n := range []int{16, 256, 4096} {
		b.Run(fmt.Sprintf("existing=%d", n), func(b *testing.B) {
			base := benchAssetCommitments(b, n)
			victims := benchAssetCommitments(b, b.N)

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				all := append(
					append([]*AssetCommitment{}, base...),
					victims[i],
				)
				tc, err := NewTapCommitment(nil, all...)
				require.NoError(b, err)
				b.StartTimer()

				if err := tc.Delete(victims[i]); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkProofDeriveByAssetInclusion measures the cost of reconstructing a
// TapCommitment root from an inclusion proof — the operation done on every
// receive-side proof verification.
func BenchmarkProofDeriveByAssetInclusion(b *testing.B) {
	for _, n := range []int{1, 16, 256} {
		b.Run(fmt.Sprintf("assets=%d", n), func(b *testing.B) {
			assets := benchAssets(b, n)
			ac, err := NewAssetCommitment(assets...)
			require.NoError(b, err)

			tc, err := NewTapCommitment(nil, ac)
			require.NoError(b, err)

			target := assets[0]
			_, proof, err := tc.Proof(
				target.TapCommitmentKey(),
				target.AssetCommitmentKey(),
			)
			require.NoError(b, err)

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := proof.DeriveByAssetInclusion(target)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
