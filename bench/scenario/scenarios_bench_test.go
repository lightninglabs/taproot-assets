// Package scenario contains benchmarks for multi-subsystem flows at scale.
// These complement the per-RPC benches under bench/rpc/: per-RPC benches
// measure single-call cost; scenarios sweep parameters to characterise how
// the dominant flows scale with size.
//
// Scenarios that need lnd-dependent flows (full mint, full send/receive)
// rely on the same fixtures as the per-RPC benches and currently bench
// the parts that run without a real Signer. Versions that drive the
// signer mocks through the full flow will land alongside the
// in-process integration fixtures.
package scenario

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

// BenchmarkAssetCommitmentScale exercises the full TapCommitment build +
// per-asset inclusion-proof verification path at varying asset counts.
// This is the dominant per-mint cost and covers the commitment +
// mssmt + asset-key interactions in one realistic shape.
func BenchmarkAssetCommitmentScale(b *testing.B) {
	for _, n := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("assets=%d", n), func(b *testing.B) {
			assets := buildAssets(b, n)

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ac, err := commitment.NewAssetCommitment(
					assets...,
				)
				require.NoError(b, err)

				tc, err := commitment.NewTapCommitment(nil, ac)
				require.NoError(b, err)

				for _, a := range assets {
					_, p, err := tc.Proof(
						a.TapCommitmentKey(),
						a.AssetCommitmentKey(),
					)
					require.NoError(b, err)

					_, err = p.DeriveByAssetInclusion(a)
					require.NoError(b, err)
				}
			}
		})
	}
}

// BenchmarkProofFileRoundTrip exercises proof file encode + decode at
// varying proof counts. Proof files dominate the receiver-side cost of
// proof distribution; this bench measures how that scales with chain
// length.
func BenchmarkProofFileRoundTrip(b *testing.B) {
	for _, n := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("proofs=%d", n), func(b *testing.B) {
			genesisProof := buildGenesisProof(b)
			proofs := make([]proof.Proof, n)
			for i := range proofs {
				proofs[i] = genesisProof
			}

			f, err := proof.NewFile(proof.V0, proofs...)
			require.NoError(b, err)

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var buf bytes.Buffer
				require.NoError(b, f.Encode(&buf))

				decoded, err := proof.NewFile(proof.V0)
				require.NoError(b, err)
				require.NoError(b, decoded.Decode(&buf))
			}
		})
	}
}

// BenchmarkMssmtBulkInsert populates a fresh tree with N leaves and
// generates an inclusion proof for one. This is the dominant universe-
// write shape: insert a leaf and prove inclusion. Parameter sweep covers
// the regime universe servers operate in.
func BenchmarkMssmtBulkInsert(b *testing.B) {
	for _, n := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("leaves=%d", n), func(b *testing.B) {
			leaves := randMssmtLeaves(n)
			ctx := context.Background()

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tree := mssmt.NewCompactedTree(
					mssmt.NewDefaultStore(),
				)
				for _, l := range leaves {
					_, err := tree.Insert(
						ctx, l.key, l.leaf,
					)
					require.NoError(b, err)
				}

				_, err := tree.MerkleProof(ctx, leaves[0].key)
				require.NoError(b, err)
			}
		})
	}
}

// buildAssets returns n Normal assets sharing a genesis.
func buildAssets(b *testing.B, n int) []*asset.Asset {
	b.Helper()
	gen := asset.RandGenesis(b, asset.Normal)
	assets := make([]*asset.Asset, n)
	for i := 0; i < n; i++ {
		scriptKey := asset.RandScriptKey(b)
		assets[i] = asset.RandAssetWithValues(
			b, gen, nil, scriptKey,
		)
	}
	return assets
}

// buildGenesisProof returns a representative genesis proof using the
// public proof.RandProof helper.
func buildGenesisProof(b *testing.B) proof.Proof {
	b.Helper()
	// proof.RandProof has nontrivial setup overhead — we build it once
	// per sub-benchmark via the Helper indirection so b.ResetTimer in
	// the caller drops it from the timing window.
	return mintRandomProof(b)
}

// mintRandomProof builds one valid Proof via the proof package's public
// helpers, paired with a minimally-constructed block transaction.
func mintRandomProof(b *testing.B) proof.Proof {
	b.Helper()
	// Reuse the testdata proof-file by decoding the first proof out of
	// it; this avoids re-implementing the proof construction inline.
	const path = "../../proof/testdata/proof-file.hex"
	rawHex, err := readHexFile(path)
	require.NoError(b, err)
	f, err := proof.NewFile(proof.V0)
	require.NoError(b, err)
	require.NoError(b, f.Decode(bytes.NewReader(rawHex)))
	first, err := f.ProofAt(0)
	require.NoError(b, err)
	return *first
}

// randMssmtLeaves returns n random mssmt leaves and their keys.
func randMssmtLeaves(n int) []mssmtLeaf {
	out := make([]mssmtLeaf, n)
	for i := range out {
		var k [32]byte
		_, _ = rand.Read(k[:])
		out[i] = mssmtLeaf{
			key:  k,
			leaf: mssmt.NewLeafNode([]byte("x"), 1),
		}
	}
	return out
}

type mssmtLeaf struct {
	key  [32]byte
	leaf *mssmt.LeafNode
}
