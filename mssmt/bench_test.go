//go:build !race

package mssmt_test

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
)

func randElem[V any](elems []V) V {
	return elems[rand.Int()%len(elems)]
}

func randMapElem[K comparable, V any](elems map[K]V) (K, V) {
	for k, v := range elems {
		return k, v
	}
	panic("unreachable")
}

func benchmarkInsert(b *testing.B, tree mssmt.Tree, leaves []treeLeaf,
	_ map[[32]byte]*mssmt.Proof) {

	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		item := randElem(leaves)
		_, err := tree.Insert(ctx, item.key, item.leaf)
		require.NoError(b, err)
	}
}

func benchmarkGet(b *testing.B, tree mssmt.Tree, leaves []treeLeaf,
	_ map[[32]byte]*mssmt.Proof) {

	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		item := randElem(leaves)
		_, err := tree.Get(ctx, item.key)
		require.NoError(b, err)
	}
}

func benchmarkMerkleProof(b *testing.B, tree mssmt.Tree, leaves []treeLeaf,
	proofs map[[32]byte]*mssmt.Proof) {

	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		item := randElem(leaves)
		_, err := tree.MerkleProof(ctx, item.key)
		require.NoError(b, err)
	}
}

func benchmarkVerifyMerkleProof(b *testing.B, tree mssmt.Tree,
	leaves []treeLeaf, proofs map[[32]byte]*mssmt.Proof) {

	treeRoot, _ := tree.Root(context.Background())

	for i := 0; i < b.N; i++ {
		item := randElem(leaves)
		_ = mssmt.VerifyMerkleProof(
			item.key, item.leaf, proofs[item.key], treeRoot,
		)
	}
}

func benchmarkMerkleProofCompress(b *testing.B, _ mssmt.Tree, _ []treeLeaf,
	proofs map[[32]byte]*mssmt.Proof) {

	for i := 0; i < b.N; i++ {
		_, proof := randMapElem(proofs)
		_, _ = proof.Compress().Decompress()
	}
}

// benchmarkCompress isolates the compression half of the round-trip — the
// half paid by the sender of a proof.
func benchmarkCompress(b *testing.B, _ mssmt.Tree, _ []treeLeaf,
	proofs map[[32]byte]*mssmt.Proof) {

	for i := 0; i < b.N; i++ {
		_, proof := randMapElem(proofs)
		_ = proof.Compress()
	}
}

// benchmarkDecompress isolates the decompression half — paid by every
// receiver who verifies a proof off the wire.
func benchmarkDecompress(b *testing.B, _ mssmt.Tree, _ []treeLeaf,
	proofs map[[32]byte]*mssmt.Proof) {

	// Precompute the compressed proofs so the decompression cost is what
	// we actually measure.
	compressed := make([]*mssmt.CompressedProof, 0, len(proofs))
	for _, p := range proofs {
		compressed = append(compressed, p.Compress())
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cp := compressed[i%len(compressed)]
		_, _ = cp.Decompress()
	}
}

type benchmarkFunc = func(*testing.B, mssmt.Tree, []treeLeaf,
	map[[32]byte]*mssmt.Proof)

type benchmark struct {
	name string
	f    benchmarkFunc
}

func newBenchmark(name string, f benchmarkFunc) benchmark {
	return benchmark{name: name, f: f}
}

var benchmarks = []benchmark{
	newBenchmark("Insert", benchmarkInsert),
	newBenchmark("Get", benchmarkGet),
	newBenchmark("MerkleProof", benchmarkMerkleProof),
	newBenchmark("VerifyMerkleProof", benchmarkVerifyMerkleProof),
	newBenchmark("MerkleProofCompress", benchmarkMerkleProofCompress),
	newBenchmark("Compress", benchmarkCompress),
	newBenchmark("Decompress", benchmarkDecompress),
}

func benchmarkTree(b *testing.B, makeTree func() mssmt.Tree) {
	for _, numLeaves := range []int{10, 1_000, 100_000} {
		leaves := randTree(numLeaves)

		var err error
		tree := makeTree()
		ctx := context.Background()
		for _, item := range leaves {
			_, err = tree.Insert(ctx, item.key, item.leaf)
			require.NoError(b, err)
		}

		proofs := make(map[[32]byte]*mssmt.Proof, numLeaves)
		for _, item := range leaves {
			proofs[item.key], err = tree.MerkleProof(ctx, item.key)
			require.NoError(b, err)
		}

		for _, benchmark := range benchmarks {
			name := fmt.Sprintf("%v-%v", benchmark.name, numLeaves)
			success := b.Run(name, func(b *testing.B) {
				b.ResetTimer()
				b.ReportAllocs()
				benchmark.f(b, tree, leaves, proofs)
			})
			if !success {
				break
			}
		}
	}
}

func BenchmarkTree(b *testing.B) {
	benchmarkTree(b, func() mssmt.Tree {
		return mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	})
}

// BenchmarkInsertManyPopulated measures a single InsertMany call against a
// CompactedTree that already holds `seed` leaves. The existing tree-wide
// InsertMany benches only ever ran against a fresh tree; this one exposes
// the populated-tree path, where the phase-split reform removed the O(N)
// per-key pre-walk from the overflow check.
func BenchmarkInsertManyPopulated(b *testing.B) {
	ctx := context.Background()

	for _, seed := range []int{1_000, 10_000} {
		for _, batch := range []int{100, 1_000} {
			name := fmt.Sprintf("seed=%d/batch=%d", seed, batch)
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()

				for i := 0; i < b.N; i++ {
					b.StopTimer()
					tree := mssmt.NewCompactedTree(
						mssmt.NewDefaultStore(),
					)
					for _, item := range randTree(seed) {
						_, err := tree.Insert(
							ctx, item.key,
							item.leaf,
						)
						require.NoError(b, err)
					}
					batchLeaves := randTree(batch)
					m := make(
						map[[32]byte]*mssmt.LeafNode,
						batch,
					)
					for _, item := range batchLeaves {
						m[item.key] = item.leaf
					}
					b.StartTimer()

					_, err := tree.InsertMany(ctx, m)
					require.NoError(b, err)
				}
			})
		}
	}
}
