package mssmt

import (
	"fmt"
	"math/rand"
	"testing"
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

func benchmarkInsert(b *testing.B, tree Tree, leaves []treeLeaf,
	_ map[[32]byte]*Proof) {

	for i := 0; i < b.N; i++ {
		item := randElem(leaves)
		_ = tree.Insert(item.key, item.leaf)
	}
}

func benchmarkGet(b *testing.B, tree Tree, leaves []treeLeaf,
	_ map[[32]byte]*Proof) {

	for i := 0; i < b.N; i++ {
		item := randElem(leaves)
		_ = tree.Get(item.key)
	}
}

func benchmarkMerkleProof(b *testing.B, tree Tree, leaves []treeLeaf,
	proofs map[[32]byte]*Proof) {

	for i := 0; i < b.N; i++ {
		item := randElem(leaves)
		_ = tree.MerkleProof(item.key)
	}
}

func benchmarkVerifyMerkleProof(b *testing.B, tree Tree, leaves []treeLeaf,
	proofs map[[32]byte]*Proof) {

	for i := 0; i < b.N; i++ {
		item := randElem(leaves)
		_ = VerifyMerkleProof(
			item.key, item.leaf, proofs[item.key], tree.Root(),
		)
	}
}

func benchmarkMerkleProofCompress(b *testing.B, _ Tree, _ []treeLeaf,
	proofs map[[32]byte]*Proof) {

	for i := 0; i < b.N; i++ {
		_, proof := randMapElem(proofs)
		_ = proof.Compress().Decompress()
	}
}

type benchmarkFunc = func(*testing.B, Tree, []treeLeaf, map[[32]byte]*Proof)

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

func benchmarkTree(b *testing.B, makeTree func() Tree) {
	for _, numLeaves := range []int{10, 1_000, 100_000} {
		leaves := randTree(numLeaves)

		tree := makeTree()
		for _, item := range leaves {
			tree.Insert(item.key, item.leaf)
		}

		proofs := make(map[[32]byte]*Proof, numLeaves)
		for _, item := range leaves {
			proofs[item.key] = tree.MerkleProof(item.key)
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
	benchmarkTree(b, func() Tree {
		return NewCompactedTree(NewDefaultStore())
	})
}
