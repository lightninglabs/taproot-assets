package mssmt

import (
	"math"
	"math/rand"
)

// RandLeafAmount generates a random leaf node sum amount.
func RandLeafAmount() uint64 {
	minSum := uint64(1)
	maxSum := uint64(math.MaxUint32)
	return (rand.Uint64() % maxSum) + minSum
}
