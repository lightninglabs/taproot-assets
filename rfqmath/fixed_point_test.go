package rfqmath

import (
	"math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func testScaleTo[N Int[N]](t *rapid.T) {
	coefficient := rapid.Uint64().Draw(t, "coefficient")
	scale := uint8(rapid.IntRange(0, 18).Draw(t, "scale"))
	newScale := uint8(rapid.IntRange(0, 18).Draw(t, "newScale"))

	fp := FixedPointFromUint64[N](coefficient, scale)
	scaledFp := fp.ScaleTo(newScale)

	// Scaling to the same scale should not change the coefficient.
	if scale == newScale {
		require.True(
			t, fp.Equals(scaledFp), "scaling to same scale "+
				"changed coefficient: %v to %v", fp, scaledFp,
		)
	}

	// Scaling up then down should approximate the original coefficient.
	if newScale > scale {
		backScaled := scaledFp.ScaleTo(scale)
		require.True(
			t, fp.Equals(backScaled),
			"scaling up then down didn't return to original: %v "+
				"to %v to %v", fp, scaledFp, backScaled,
		)
	}

	// The internal scale should reflect the new scale.
	require.Equal(
		t, newScale, scaledFp.Scale, "scaled FixedPoint has "+
			"incorrect scale: got %d, want %d", scaledFp.Scale,
		newScale,
	)
}

func testFixedPointMultiplication[N Int[N]](t *rapid.T) {
	a := rapid.Uint64().Draw(t, "a")
	b := rapid.Uint64().Draw(t, "b")
	scale := uint8(rapid.IntRange(0, 9).Draw(t, "scale"))

	fpA := FixedPointFromUint64[N](a, scale)
	fpB := FixedPointFromUint64[N](b, scale)
	result := fpA.Mul(fpB)

	// a * b should equal b * a.
	require.True(
		t, result.Equals(fpB.Mul(fpA)),
		"multiplication not commutative: %v * %v != %v * %v", fpA,
		fpB, fpB, fpA,
	)

	// a * 1 should equal a.
	one := FixedPointFromUint64[N](1, scale)
	require.True(
		t, fpA.Equals(fpA.Mul(one)),
		"multiplication by 1 changed value: %v * 1 = %v", fpA,
		fpA.Mul(one),
	)

	// The result should have the same scale as the operands.
	require.Equal(
		t, scale, result.Scale, "multiplication changed scale: %v * "+
			"%v has scale %d, expected %d",
		fpA, fpB, result.Scale, scale,
	)

	// (a * b) / b should be equal to a, for non zero values of b.
	if !fpB.Equals(FixedPointFromUint64[N](0, scale)) {
		divided := result.Div(fpB)
		require.True(
			t, fpA.Equals(divided), "precision loss in "+
				"multiplication: (%v * %v) / %v = %v, "+
				"expected approx %v",
			fpA, fpB, fpB, divided, fpA)
	}
}

func testFixedPointDivision[N Int[N]](t *rapid.T) {
	// Generate a random a, b, and scale. We make sure b is not 0 to avoid
	// division by zero.
	a := rapid.Uint64().Draw(t, "a")
	b := rapid.Uint64Range(1, math.MaxUint32).Draw(t, "b")
	scale := uint8(rapid.IntRange(1, 9).Draw(t, "scale"))

	fpA := FixedPointFromUint64[N](a, scale)
	fpB := FixedPointFromUint64[N](b, scale)
	result := fpA.Div(fpB)

	// If a and b are the same, then the result should be 1.
	if a == b {
		require.True(
			t,
			result.Equals(FixedPointFromUint64[N](1, scale)),
			"division of equal values is not 1: %v / %v = %v", fpA,
			fpB, result,
		)
	}

	// TODO(roasbeef): property against (a * b) / b = a
	//  * need programmatic check for allowed precision loss based on scale
	//  * require.InDelta

	// Property: a / 1 should equal a
	one := FixedPointFromUint64[N](1, scale)
	require.True(
		t, fpA.Equals(fpA.Div(one)), "division by 1 changed "+
			"value: %v / 1 = %v", fpA, fpA.Div(one),
	)
}

func testEquality[N Int[N]](t *rapid.T) {
	coefficient := rapid.Uint64().Draw(t, "coefficient")
	scale := uint8(rapid.IntRange(0, 18).Draw(t, "scale"))

	fp1 := FixedPointFromUint64[N](coefficient, scale)
	fp2 := FixedPointFromUint64[N](coefficient, scale)

	// Two FixedPoints with the same coefficient and scale should be equal.
	require.True(
		t, fp1.Equals(fp2), "equal FixedPoints not considered equal: "+
			"%v and %v", fp1, fp2,
	)

	// Two FixedPoints with different values should not be equal.
	fp3 := FixedPointFromUint64[N](coefficient+1, scale)
	require.False(
		t, fp1.Equals(fp3), "different FixedPoints considered equal: "+
			"%v and %v", fp1, fp3,
	)

	// Two FixedPoints with different scales should not be equal.
	fp4 := FixedPointFromUint64[N](coefficient, scale+1)
	require.False(
		t, fp1.Equals(fp4), "different FixedPoints considered equal: "+
			"%v and %v", fp1, fp4,
	)
}

func testFromUint64[N Int[N]](t *rapid.T) {
	coefficient := rapid.Uint64().Draw(t, "coefficient")
	scale := uint8(rapid.IntRange(0, 18).Draw(t, "scale"))

	fp := FixedPointFromUint64[N](coefficient, scale)

	// The created FixedPoint should have the correct scale.
	require.Equal(t, scale, fp.Scale)

	// Scaling back to 0 should give the original coefficient.
	scaledBack := fp.ScaleTo(0)
	require.Equal(t, coefficient, scaledBack.Coefficient.ToUint64())
}

// testCasesWithinTolerance is a table-driven test for the WithinTolerance
// method.
func testCasesWithinTolerance[N Int[N]](t *testing.T) {
	type testCase struct {
		// firstFp is the fixed-point to compare with secondFp.
		firstFp FixedPoint[N]

		// secondFp is the fixed-point to compare with firstFp.
		secondFp FixedPoint[N]

		// tolerancePpm is the tolerance in parts per million (PPM) that
		// the second price can deviate from the first price and still
		// be considered within bounds.
		tolerancePpm uint64

		// withinBounds is the expected result of the bounds check.
		withinBounds bool
	}

	testCases := []testCase{
		{
			// Case where secondFp is 10% less than firstFp,
			// tolerance allows 11.11% (111111 PPM). Diff within
			// bounds.
			firstFp:      FixedPointFromUint64[N](1000000, 1),
			secondFp:     FixedPointFromUint64[N](900000, 1),
			tolerancePpm: 111111, // 11.11% tolerance in PPM
			withinBounds: true,
		},
		{
			// Case where firstFp is 15% less than secondFp,
			// tolerance allows 17.65% (176470 PPM). Diff within
			// bounds.
			firstFp:      FixedPointFromUint64[N](8_500_00, 1),
			secondFp:     FixedPointFromUint64[N](1_000_000, 1),
			tolerancePpm: 176470, // 17.65% tolerance in PPM
			withinBounds: true,
		},
		{
			// Case where firstFp is 15% less than secondFp,
			// tolerance allows 17.65% (176470 PPM). Diff within
			// bounds.
			firstFp:      FixedPointFromUint64[N](85_000, 3),
			secondFp:     FixedPointFromUint64[N](100_000, 2),
			tolerancePpm: 176470, // 17.65% tolerance in PPM
			withinBounds: true,
		},
		{
			// Case where secondFp is 15% less than firstFp,
			// tolerance allows 10% (100000 PPM). Diff outside
			// bounds.
			firstFp:      FixedPointFromUint64[N](85_000, 3),
			secondFp:     FixedPointFromUint64[N](100_000, 2),
			tolerancePpm: 100000, // 10% tolerance in PPM
			withinBounds: false,
		},
		{
			// Case where firstFp and secondFp are equal,
			// tolerance is 0 PPM. Diff within bounds.
			firstFp:      FixedPointFromUint64[N](100_000, 2),
			secondFp:     FixedPointFromUint64[N](100_000, 4),
			tolerancePpm: 0, // 0% tolerance in PPM
			withinBounds: true,
		},
		{
			// Case where firstFp and secondFp are equal,
			// tolerance is 0 PPM. Diff within bounds.
			firstFp:      FixedPointFromUint64[N](100_000, 2),
			secondFp:     FixedPointFromUint64[N](100_000, 2),
			tolerancePpm: 0, // 0% tolerance in PPM
			withinBounds: true,
		},
		{
			// Case where secondFp is 1% more than firstFp,
			// tolerance allows 0.99% (9900 PPM). Diff outside
			// bounds.
			firstFp:      FixedPointFromUint64[N](100_000, 2),
			secondFp:     FixedPointFromUint64[N](101_000, 3),
			tolerancePpm: 9900, // 0.99% tolerance in PPM
			withinBounds: false,
		},
		{
			// Case where secondFp is 5% less than firstFp,
			// tolerance allows 5% (50000 PPM). Diff within bounds.
			firstFp:      FixedPointFromUint64[N](100_000, 1),
			secondFp:     FixedPointFromUint64[N](95000, 2),
			tolerancePpm: 50000, // 5% tolerance in PPM
			withinBounds: true,
		},
		{
			// Case where secondFp is greater than firstFp,
			// tolerance allows 5% (50000 PPM). Diff within bounds.
			firstFp: FixedPoint[N]{
				Coefficient: NewInt[N]().FromUint64(314),
				Scale:       2,
			},
			secondFp: FixedPoint[N]{
				Coefficient: NewInt[N]().FromUint64(
					314_159_265_359,
				),
				Scale: 11,
			},

			tolerancePpm: 50000, // 5% tolerance in PPM
			withinBounds: true,
		},
		{
			// Case where secondFp is 10% less than firstFp,
			// tolerance allows 9% (90000 PPM). Diff outside bounds.
			firstFp:      FixedPointFromUint64[N](100_000, 3),
			secondFp:     FixedPointFromUint64[N](90_000, 1),
			tolerancePpm: 90000, // 9% tolerance in PPM
			withinBounds: false,
		},
		{
			// Case where secondFp is 9% less than firstFp,
			// tolerance allows 10% (100000 PPM). Diff within
			// bounds.
			firstFp:      FixedPointFromUint64[N](100_000, 4),
			secondFp:     FixedPointFromUint64[N](91_000, 1),
			tolerancePpm: 100000, // 10% tolerance in PPM
			withinBounds: true,
		},
		{
			// Case where both prices are zero, should be within
			// bounds.
			firstFp:      FixedPointFromUint64[N](0, 0),
			secondFp:     FixedPointFromUint64[N](0, 0),
			tolerancePpm: 1_000_00, // tolerance not effectual
			withinBounds: true,
		},
		{
			// Case where firstFp is zero and secondFp is
			// non-zero, should not be within bounds.
			firstFp:      FixedPointFromUint64[N](0, 0),
			secondFp:     FixedPointFromUint64[N](100_000, 4),
			tolerancePpm: 1_000_00, // tolerance not effectual
			withinBounds: false,
		},
		{
			// Case where secondFp is zero and firstFp is
			// non-zero, should not be within bounds.
			firstFp:      FixedPointFromUint64[N](100_000, 4),
			secondFp:     FixedPointFromUint64[N](0, 0),
			tolerancePpm: 1_000_00, // tolerance not effectual
			withinBounds: false,
		},
	}

	// Create a zero coefficient to test the error case.
	zeroCoefficient := NewInt[N]().FromUint64(0)

	// Run the test cases.
	for idx, tc := range testCases {
		result, err := tc.firstFp.WithinTolerance(
			tc.secondFp, NewInt[N]().FromUint64(tc.tolerancePpm),
		)

		// If either of the coefficients are zero, we expect an error.
		if tc.firstFp.Coefficient.Equals(zeroCoefficient) ||
			tc.secondFp.Coefficient.Equals(zeroCoefficient) {

			require.Error(t, err)
			require.False(t, result)
			continue
		}

		require.NoError(t, err, "Test case %d failed", idx)

		// Compare bounds check result with expected test case within
		// bounds flag.
		require.Equal(
			t, tc.withinBounds, result, "Test case %d failed", idx,
		)
	}
}

// testWithinToleranceEqualValues is a property-based test which ensures that
// the WithinTolerance method returns true when the fixed-point values are equal
// regardless of the tolerance.
func testWithinToleranceEqualValues(t *rapid.T) {
	tolerancePpm := rapid.Int64Min(0).Draw(t, "tolerance")

	// Generate a random coefficient and scale.
	coefficient := rapid.Int64Min(1).Draw(t, "coefficient")
	scale := rapid.Uint8Range(0, 18).Draw(t, "scale")

	// Create two identical FixedPoint[BigInt] values.
	f1 := FixedPoint[BigInt]{
		Coefficient: NewBigInt(big.NewInt(coefficient)),
		Scale:       scale,
	}

	f2 := FixedPoint[BigInt]{
		Coefficient: NewBigInt(big.NewInt(coefficient)),
		Scale:       scale,
	}

	tolerancePpmBigInt := NewBigInt(big.NewInt(tolerancePpm))

	// The result should always be true when the fixed-point values
	// are equal.
	result, err := f1.WithinTolerance(f2, tolerancePpmBigInt)
	require.NoError(t, err)

	if !result {
		t.Fatalf("WithinTolerance should be true when values " +
			"are equal, but got false")
	}
}

// testWithinToleranceZeroTolerance is a property-based test which ensures that
// the WithinTolerance method returns true if both fixed-point values are equal
// and the tolerance is zero.
func testWithinToleranceZeroTolerance(t *rapid.T) {
	// Use a tolerance of zero.
	tolerancePpmBigInt := NewBigInt(big.NewInt(0))

	// Generate two equal fixed-points.
	coefficient := rapid.Int64Min(1).Draw(t, "coefficient")
	scale := rapid.Uint8Range(0, 18).Draw(t, "scale")
	f1 := FixedPoint[BigInt]{
		Coefficient: NewBigInt(big.NewInt(coefficient)),
		Scale:       scale,
	}

	f2 := FixedPoint[BigInt]{
		Coefficient: NewBigInt(big.NewInt(coefficient)),
		Scale:       scale,
	}

	result, err := f1.WithinTolerance(f2, tolerancePpmBigInt)
	require.NoError(t, err)
	require.True(t, result)
}

// testAddToleranceProp is a property-based test which tests that the
// AddTolerance helper correctly applies the provided tolerance margin to any
// given value.
func testAddToleranceProp(t *rapid.T) {
	value := NewBigIntFromUint64(rapid.Uint64Min(1).Draw(t, "value"))
	tolerancePpm := NewBigIntFromUint64(
		rapid.Uint64Range(0, 1_000_000).Draw(t, "tolerance_ppm"),
	)

	result := AddTolerance(value, tolerancePpm)

	if tolerancePpm.ToUint64() == 0 {
		require.True(t, result.Equals(value))
		return
	}

	// First off, let's just check that the result is at all greater than
	// the input.
	require.True(t, result.Gte(value))

	// Let's now convert the values to a fixed point type in order to use
	// the WithinTolerance method.
	valueFixed := BigIntFixedPoint{
		Coefficient: value,
		Scale:       0,
	}
	resultFixed := BigIntFixedPoint{
		Coefficient: result,
		Scale:       0,
	}

	// The value with the applied tolerance and the original value should be
	// within tolerance.
	res, err := resultFixed.WithinTolerance(valueFixed, tolerancePpm)
	require.NoError(t, err)
	require.True(t, res)
}

// testWithinToleranceSymmetric is a property-based test which ensures that the
// WithinTolerance method is symmetric (swapping the order of the fixed-point
// values does not change the result).
func testWithinToleranceSymmetric(t *rapid.T) {
	// Generate random coefficients, scales, and tolerance
	coefficient := rapid.Int64Min(1).Draw(t, "coefficient_1")
	coefficient2 := rapid.Int64Min(1).Draw(t, "coefficient_2")
	scale1 := rapid.Uint8Range(0, 18).Draw(t, "scale_1")
	scale2 := rapid.Uint8Range(0, 18).Draw(t, "scale_2")
	tolerancePpm := rapid.Int64Range(0, 1_000_000).Draw(t, "tolerance")

	f1 := FixedPoint[BigInt]{
		Coefficient: NewBigInt(big.NewInt(coefficient)),
		Scale:       scale1,
	}

	f2 := FixedPoint[BigInt]{
		Coefficient: NewBigInt(big.NewInt(coefficient2)),
		Scale:       scale2,
	}

	tolerancePpmBigInt := NewBigInt(big.NewInt(tolerancePpm))

	result1, err := f1.WithinTolerance(f2, tolerancePpmBigInt)
	require.NoError(t, err)

	result2, err := f2.WithinTolerance(f1, tolerancePpmBigInt)
	require.NoError(t, err)

	if result1 != result2 {
		t.Fatalf("WithinTolerance is not symmetric: "+
			"f1.WithinTolerance(f2)=%v, "+
			"f2.WithinTolerance(f1)=%v", result1, result2)
	}
}

// testWithinToleranceMaxTolerance is a property-based test which ensures that
// the WithinTolerance method returns true when the tolerance is at its maximum
// value.
func testWithinToleranceMaxTolerance(t *rapid.T) {
	// Set tolerancePpm to any value above 100%.
	tolerancePpm := rapid.Int64Min(1_000_000).Draw(t, "tolerance")
	tolerancePpmBigInt := NewBigInt(big.NewInt(tolerancePpm))

	// Generate random fixed-point values.
	coefficient1 := rapid.Int64Min(1).Draw(t, "coefficient_1")
	scale1 := rapid.Uint8Range(0, 18).Draw(t, "scale_1")
	f1 := FixedPoint[BigInt]{
		Coefficient: NewBigInt(big.NewInt(coefficient1)),
		Scale:       scale1,
	}

	coefficient2 := rapid.Int64Min(1).Draw(t, "coefficient_2")
	scale2 := rapid.Uint8Range(0, 18).Draw(t, "scale_2")
	f2 := FixedPoint[BigInt]{
		Coefficient: NewBigInt(big.NewInt(coefficient2)),
		Scale:       scale2,
	}

	// The result should always be true when tolerancePpm is at its max or
	// larger.
	result, err := f1.WithinTolerance(f2, tolerancePpmBigInt)
	require.NoError(t, err)

	if !result {
		t.Fatalf("WithinTolerance should be true when tolerancePpm " +
			"is large, but got false")
	}
}

// testWithinToleranceCoefficientZeroError is a property-based test which
// ensures that the WithinTolerance method returns an error when either or both
// of the fixed-point values have a coefficient of zero.
func testWithinToleranceCoefficientZeroError(t *rapid.T) {
	// Set tolerancePpm to any value above 100%.
	tolerancePpm := rapid.Int64Min(1_000_000).Draw(t, "tolerance")
	tolerancePpmBigInt := NewBigInt(big.NewInt(tolerancePpm))

	// Generate a random mode to determine which coefficient(s) to set to
	// zero.
	mode := rapid.Int64Range(0, 2).Draw(t, "mode")

	var coefficient1, coefficient2 int64
	switch mode {
	case 0:
		coefficient1 = 0
		coefficient2 = rapid.Int64Min(1).Draw(t, "coefficient_2")
	case 1:
		coefficient1 = rapid.Int64Min(1).Draw(t, "coefficient_1")
		coefficient2 = 0
	case 2:
		coefficient1 = 0
		coefficient2 = 0
	}

	// Generate random fixed-point values from the coefficients.
	scale1 := rapid.Uint8Range(0, 18).Draw(t, "scale_1")
	f1 := FixedPoint[BigInt]{
		Coefficient: NewBigInt(big.NewInt(coefficient1)),
		Scale:       scale1,
	}

	scale2 := rapid.Uint8Range(0, 18).Draw(t, "scale_2")
	f2 := FixedPoint[BigInt]{
		Coefficient: NewBigInt(big.NewInt(coefficient2)),
		Scale:       scale2,
	}

	// We always expect an error when either or both coefficients are zero.
	result, err := f1.WithinTolerance(f2, tolerancePpmBigInt)
	require.Error(t, err)
	require.False(t, result)
}

// testWithinToleranceFloatReproduce is a property-based test that verifies
// the reproducibility of the WithinTolerance method's result using calculations
// on float64 values.
func testWithinToleranceFloatReproduce(t *rapid.T) {
	// Generate a random tolerance in parts per million (PPM).
	tolerancePpm := rapid.Int64Range(0, 1_000_000).Draw(t, "tolerance")
	tolerancePpmBigInt := NewBigInt(big.NewInt(tolerancePpm))

	// Generate random fixed-point values.
	coefficientsRange := rapid.Int64Range(1, 1_000_000_000)

	coefficient1 := coefficientsRange.Draw(t, "coefficient_1")
	scale1 := rapid.Uint8Range(0, 9).Draw(t, "scale_1")
	f1 := FixedPoint[BigInt]{
		Coefficient: NewBigInt(big.NewInt(coefficient1)),
		Scale:       scale1,
	}

	coefficient2 := coefficientsRange.Draw(t, "coefficient_2")
	scale2 := rapid.Uint8Range(0, 9).Draw(t, "scale_2")
	f2 := FixedPoint[BigInt]{
		Coefficient: NewBigInt(big.NewInt(coefficient2)),
		Scale:       scale2,
	}

	// Compute the result using the WithinTolerance method.
	result, err := f1.WithinTolerance(f2, tolerancePpmBigInt)
	require.NoError(t, err)

	// Compute expected result using float64.
	f1Float := f1.ToFloat64()
	f2Float := f2.ToFloat64()

	delta := math.Abs(f1Float - f2Float)
	maxVal := math.Max(math.Abs(f1Float), math.Abs(f2Float))

	tolerance := (float64(tolerancePpm) / 1_000_000) * maxVal

	expected := delta <= tolerance

	if result != expected {
		t.Fatalf("WithinTolerance mismatch:\n"+
			"f1 = %v (float: %f),\n"+
			"f2 = %v (float: %f),\n"+
			"tolerancePpm = %v,\n"+
			"delta = %e,\n"+
			"tolerance = %e,\n"+
			"result = %v,\n"+
			"expected = %v",
			f1, f1Float, f2, f2Float, tolerancePpm, delta,
			tolerance, result, expected)
	}
}

// testWithinTolerance runs a series of tests to ensure the WithinTolerance
// method behaves as expected.
func testWithinTolerance(t *testing.T) {
	t.Parallel()

	t.Run("testcases_within_tolerance", testCasesWithinTolerance[BigInt])

	t.Run(
		"within_tolerance_equal_values",
		rapid.MakeCheck(testWithinToleranceEqualValues),
	)

	t.Run(
		"within_tolerance_zero_tolerance",
		rapid.MakeCheck(testWithinToleranceZeroTolerance),
	)

	t.Run(
		"within_tolerance_symmetric",
		rapid.MakeCheck(testWithinToleranceSymmetric),
	)

	t.Run(
		"within_tolerance_max_tolerance",
		rapid.MakeCheck(testWithinToleranceMaxTolerance),
	)

	t.Run(
		"within_tolerance_coefficient_zero_error",
		rapid.MakeCheck(testWithinToleranceCoefficientZeroError),
	)

	t.Run(
		"within_tolerance_float_reproduce",
		rapid.MakeCheck(testWithinToleranceFloatReproduce),
	)

	t.Run(
		"add_tolerance_property",
		rapid.MakeCheck(testAddToleranceProp),
	)
}

// TestFixedPoint runs a series of property-based tests on the FixedPoint type
// exercising key invariant properties.
func TestFixedPoint(t *testing.T) {
	t.Parallel()

	t.Run("scale_to", rapid.MakeCheck(testScaleTo[BigInt]))

	t.Run("multiplication", func(t *testing.T) {
		rapid.Check(t, testFixedPointMultiplication[BigInt])
	})

	t.Run("division", rapid.MakeCheck(testFixedPointDivision[BigInt]))

	t.Run("equality", rapid.MakeCheck(testEquality[BigInt]))

	t.Run("from_uint64", rapid.MakeCheck(testFromUint64[BigInt]))

	t.Run("within_tolerance", testWithinTolerance)
}
