package mssmt

import (
	"fmt"
	"testing"
)

func randElem[K comparable, V any](elems map[K]V) (K, V) {
	for k, v := range elems {
		return k, v
	}
	panic("unreachable")
}

func benchmarkInsert(b *testing.B, tree *Tree, leaves map[[32]byte]*LeafNode,
	_ map[[32]byte]*Proof) {

	for i := 0; i < b.N; i++ {
		key, leaf := randElem(leaves)
		_ = tree.Insert(key, leaf)
	}
}

func benchmarkGet(b *testing.B, tree *Tree, leaves map[[32]byte]*LeafNode,
	_ map[[32]byte]*Proof) {

	for i := 0; i < b.N; i++ {
		key, _ := randElem(leaves)
		_ = tree.Get(key)
	}
}

func benchmarkMerkleProof(b *testing.B, tree *Tree, _ map[[32]byte]*LeafNode,
	proofs map[[32]byte]*Proof) {

	for i := 0; i < b.N; i++ {
		key, _ := randElem(proofs)
		_ = tree.MerkleProof(key)
	}
}

func benchmarkVerifyMerkleProof(b *testing.B, tree *Tree,
	leaves map[[32]byte]*LeafNode, proofs map[[32]byte]*Proof) {

	for i := 0; i < b.N; i++ {
		key, leaf := randElem(leaves)
		_ = VerifyMerkleProof(key, leaf, proofs[key], tree.Root())
	}
}

func benchmarkMerkleProofCompress(b *testing.B, _ *Tree,
	_ map[[32]byte]*LeafNode, proofs map[[32]byte]*Proof) {

	for i := 0; i < b.N; i++ {
		_, proof := randElem(proofs)
		_ = proof.Compress().Decompress()
	}
}

type benchmarkFunc = func(*testing.B, *Tree, map[[32]byte]*LeafNode,
	map[[32]byte]*Proof)

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

func BenchmarkTree(b *testing.B) {
	for _, numLeaves := range []int{10, 1_000, 100_000} {
		tree, leaves := randTree(numLeaves)
		proofs := make(map[[32]byte]*Proof, numLeaves)
		for key := range leaves {
			proofs[key] = tree.MerkleProof(key)
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
