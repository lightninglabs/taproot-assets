//go:build itest

package custom_channels

import "flag"

var (
	// splitTranches is the number of tranches to split custom channel tests
	// into for parallel CI execution.
	splitTranches = flag.Int(
		"splittranches", 1,
		"number of tranches to split tests into",
	)

	// runTranche selects which tranche (0-indexed) of tests to run.
	runTranche = flag.Int(
		"runtranche", 0,
		"index of the test tranche to run (0-indexed)",
	)
)

// filterByTranche returns the subset of test cases assigned to the given
// tranche. Tests are distributed round-robin across tranches.
func filterByTranche(tests []*ccTestCase, tranche,
	numTranches int) []*ccTestCase {

	var filtered []*ccTestCase
	for i, tc := range tests {
		if i%numTranches == tranche {
			filtered = append(filtered, tc)
		}
	}

	return filtered
}
