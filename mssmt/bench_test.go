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
