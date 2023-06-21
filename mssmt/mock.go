package mssmt

import (
	"math"

	"github.com/lightninglabs/taproot-assets/internal/test"
)

// RandLeafAmount generates a random leaf node sum amount.
func RandLeafAmount() uint64 {
	minSum := uint64(1)
	maxSum := uint64(math.MaxUint32)
	return (test.RandInt[uint64]() % maxSum) + minSum
}
