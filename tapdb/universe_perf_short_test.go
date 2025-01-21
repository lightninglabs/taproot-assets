//go:build !longtests

package tapdb

import "time"

var (
	numAssets        = 100
	numLeavesPerTree = 300
	numQueries       = 100

	testTimeout = 5 * time.Minute
)
