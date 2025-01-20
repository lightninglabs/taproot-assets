//go:build longtests

package tapdb

import "time"

// longTestScale is the scale factor for long tests.
const longTestScale = 5

var (
	numAssets        = 100 * longTestScale
	numLeavesPerTree = 300 * longTestScale
	numQueries       = 100 * longTestScale

	testTimeout = 5 * time.Minute * longTestScale
)
