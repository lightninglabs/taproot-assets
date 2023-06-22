package mssmt_test

import (
	"math"
	"math/big"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
)

const hashSize = 32

func randLeaf() *mssmt.LeafNode {
	valueLen := test.RandInt31n(math.MaxUint8) + 1
	value := test.RandBytes(int(valueLen))
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
			key:  test.RandHash(),
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
