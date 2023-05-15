package mssmt_test

import (
	"math"
	"math/big"
	"math/rand"
	"time"

	"github.com/lightninglabs/taproot-assets/mssmt"
)

const hashSize = 32

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randKey() [hashSize]byte {
	var key [hashSize]byte
	_, _ = rand.Read(key[:])
	return key
}

func randLeaf() *mssmt.LeafNode {
	valueLen := rand.Intn(math.MaxUint8) + 1
	value := make([]byte, valueLen)
	_, _ = rand.Read(value[:])
	sum := mssmt.RandLeafAmount()
	return mssmt.NewLeafNode(value, sum)
}

type treeLeaf struct {
	key  [hashSize]byte
	leaf *mssmt.LeafNode
}

func randTree(numLeaves int) []treeLeaf {
	leaves := make([]treeLeaf, numLeaves)
	for i := 0; i < numLeaves; i++ {
		leaves[i] = treeLeaf{
			key:  randKey(),
			leaf: randLeaf(),
		}
	}
	return leaves
}

func genTreeFromRange(numLeaves int) []treeLeaf {
	leaves := make([]treeLeaf, numLeaves)
	for i := 0; i < numLeaves; i++ {
		var key [32]byte
		big.NewInt(int64(i)).FillBytes(key[:])

		leaves[i] = treeLeaf{
			key:  key,
			leaf: randLeaf(),
		}
	}

	return leaves
}
