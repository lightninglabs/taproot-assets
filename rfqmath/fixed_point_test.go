package rfqmath

import (
	"math"
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
}
