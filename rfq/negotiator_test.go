package rfq

import (
	"testing"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestPricesWithinBounds tests the pricesWithinBounds function.
func TestPricesWithinBounds(t *testing.T) {
	type testCase struct {
		// firstPrice is the price to compare with secondPrice.
		firstPrice lnwire.MilliSatoshi

		// secondPrice is the price to compare with firstPrice.
		secondPrice lnwire.MilliSatoshi

		// tolerancePpm is the tolerance in parts per million (PPM) that
		// the second price can deviate from the first price and still
		// be considered within bounds.
		tolerancePpm uint64

		// withinBounds is the expected result of the bounds check.
		withinBounds bool
	}

	testCases := []testCase{
		{
			// Case where secondPrice is 10% less than firstPrice,
			// tolerance allows 11.11% (111111 PPM). Diff within
			// bounds.
			firstPrice:   100000,
			secondPrice:  90000,
			tolerancePpm: 111111, // 11.11% tolerance in PPM
			withinBounds: true,
		},
		{
			// Case where firstPrice is 15% less than secondPrice,
			// tolerance allows 17.65% (176470 PPM). Diff within
			// bounds.
			firstPrice:   85000,
			secondPrice:  100000,
			tolerancePpm: 176470, // 17.65% tolerance in PPM
			withinBounds: true,
		},
		{
			// Case where secondPrice is 15% less than firstPrice,
			// tolerance allows 10% (100000 PPM). Diff outside
			// bounds.
			firstPrice:   100000,
			secondPrice:  85000,
			tolerancePpm: 100000, // 10% tolerance in PPM
			withinBounds: false,
		},
		{
			// Case where firstPrice and secondPrice are equal,
			// tolerance is 0 PPM. Diff within bounds.
			firstPrice:   100000,
			secondPrice:  100000,
			tolerancePpm: 0, // 0% tolerance in PPM
			withinBounds: true,
		},
		{
			// Case where secondPrice is 1% more than firstPrice,
			// tolerance allows 0.99% (9900 PPM). Diff outside
			// bounds.
			firstPrice:   100000,
			secondPrice:  101000,
			tolerancePpm: 9900, // 0.99% tolerance in PPM
			withinBounds: false,
		},
		{
			// Case where secondPrice is 5% less than firstPrice,
			// tolerance allows 5% (50000 PPM). Diff within bounds.
			firstPrice:   100000,
			secondPrice:  95000,
			tolerancePpm: 50000, // 5% tolerance in PPM
			withinBounds: true,
		},
		{
			// Case where secondPrice is 10% less than firstPrice,
			// tolerance allows 9% (90000 PPM). Diff outside bounds.
			firstPrice:   100000,
			secondPrice:  90000,
			tolerancePpm: 90000, // 9% tolerance in PPM
			withinBounds: false,
		},
		{
			// Case where secondPrice is 9% less than firstPrice,
			// tolerance allows 10% (100000 PPM). Diff within
			// bounds.
			firstPrice:   100000,
			secondPrice:  91000,
			tolerancePpm: 100000, // 10% tolerance in PPM
			withinBounds: true,
		},
		{
			// Case where both prices are zero, should be within
			// bounds.
			firstPrice:   0,
			secondPrice:  0,
			tolerancePpm: 100000, // any tolerance in PPM
			withinBounds: true,
		},
		{
			// Case where firstPrice is zero and secondPrice is
			// non-zero, should not be within bounds.
			firstPrice:   0,
			secondPrice:  100000,
			tolerancePpm: 100000, // any tolerance in PPM
			withinBounds: false,
		},
		{
			// Case where secondPrice is zero and firstPrice is
			// non-zero, should not be within bounds.
			firstPrice:   100000,
			secondPrice:  0,
			tolerancePpm: 100000, // any tolerance in PPM
			withinBounds: false,
		},
	}

	// Run the test cases.
	for idx, tc := range testCases {
		result := pricesWithinBounds(
			tc.firstPrice, tc.secondPrice, tc.tolerancePpm,
		)

		// Compare bounds check result with expected test case within
		// bounds flag.
		require.Equal(
			t, tc.withinBounds, result, "Test case %d failed", idx,
		)
	}
}
