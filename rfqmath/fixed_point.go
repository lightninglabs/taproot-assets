package rfqmath

import (
	"fmt"
	"math"
	"strconv"
)

// FixedPoint is used to represent fixed point arithmetic for currency related
// calculations. A fixed point consists of a value, and a scale. The value is
// the integer representation of the number. The scale is used to represent the
// fractional/decimal component.
type FixedPoint[T Int[T]] struct {
	// Coefficient is the value of the FixedPoint integer.
	Coefficient T

	// Scale is used to represent the fractional component. This always
	// represents a power of 10. Eg: a scale value of 2 (two decimal
	// places) maps to a multiplication by 100.
	Scale uint8
}

// SetIntValue assigns the specified integer value to the FixedPoint. The
// coefficient is set to the given value, and the scale is reset to 0.
func (f FixedPoint[T]) SetIntValue(value T) FixedPoint[T] {
	f.Coefficient = value
	f.Scale = 0

	return f
}

// String returns the string version of the fixed point value.
func (f FixedPoint[T]) String() string {
	coefficient := f.Coefficient.ToFloat() / math.Pow10(int(f.Scale))
	return fmt.Sprintf("%.*f", f.Scale, coefficient)
}

// ScaleTo returns a new FixedPoint that is scaled up or down to the given
// scale.
func (f FixedPoint[T]) ScaleTo(newScale uint8) FixedPoint[T] {
	// Scale diff is the difference between the current scale and the new
	// scale. If this is negative, we need to scale down.
	scaleDiff := int32(newScale) - int32(f.Scale)

	absoluteScale := int(math.Abs(float64(scaleDiff)))
	scaleMultiplier := NewInt[T]().FromFloat(math.Pow10(absoluteScale))

	// We'll explicitly handle the scale down vs scale up case.
	var newCoefficient T
	switch {
	// No change in scale.
	case scaleDiff == 0:
		newCoefficient = f.Coefficient

	// Larger scale, so we'll multiply by 10^scaleDiff.
	case scaleDiff > 0:
		newCoefficient = f.Coefficient.Mul(scaleMultiplier)

	// Smaller scale, so we'll divide by 10^scaleDiff.
	case scaleDiff < 0:
		newCoefficient = f.Coefficient.Div(scaleMultiplier)
	}

	return FixedPoint[T]{
		Coefficient: newCoefficient,
		Scale:       newScale,
	}
}

// ToUint64 returns a new FixedPoint that is scaled down from the existing scale
// and mapped to a uint64 representing the amount of units. This should be used
// to go from FixedPoint to an amount of "units".
func (f FixedPoint[T]) ToUint64() uint64 {
	return f.Coefficient.ToUint64()
}

// ToFloat64 returns a float64 representation of the FixedPoint value.
func (f FixedPoint[T]) ToFloat64() float64 {
	floatStr := f.String()
	float, _ := strconv.ParseFloat(floatStr, 64)
	return float
}

// Mul returns a new FixedPoint that is the result of multiplying the existing
// int by the passed one.
//
// NOTE: This function assumes that the scales of the two FixedPoint values are
// identical. If the scales differ, the result may be incorrect.
func (f FixedPoint[T]) Mul(other FixedPoint[T]) FixedPoint[T] {
	multiplier := NewInt[T]().FromFloat(math.Pow10(int(f.Scale)))

	result := f.Coefficient.Mul(other.Coefficient).Div(multiplier)

	return FixedPoint[T]{
		Coefficient: result,
		Scale:       f.Scale,
	}
}

// Div returns a new FixedPoint that is the result of dividing the existing int
// by the passed one.
//
// NOTE: This function assumes that the scales of the two FixedPoint values are
// identical. If the scales differ, the result may be incorrect.
func (f FixedPoint[T]) Div(other FixedPoint[T]) FixedPoint[T] {
	multiplier := NewInt[T]().FromFloat(math.Pow10(int(f.Scale)))

	result := f.Coefficient.Mul(multiplier).Div(other.Coefficient)

	return FixedPoint[T]{
		Coefficient: result,
		Scale:       f.Scale,
	}
}

// Equals returns true if the two FixedPoint values are equal.
func (f FixedPoint[T]) Equals(other FixedPoint[T]) bool {
	return f.Coefficient.Equals(other.Coefficient) && f.Scale == other.Scale
}

// WithinTolerance returns true if the two FixedPoint values are within the
// given tolerance, specified in parts per million (PPM).
//
// The tolerance is applied relative to the larger of the two values to ensure
// that a 100% tolerance (1,000,000 PPM) always results in a match for any two
// nonzero values.
//
// This max-based approach (e.g. ask) is more lenient than using the smaller
// value (e.g., bid) as the reference. For example, if the two values are 100
// and 105, a 5% tolerance (50,000 PPM) allows a maximum difference of:
// - Bid-based: 100 × 0.05 = 5 (so 105 is the limit)
// - Max-based: 105 × 0.05 = 5.25 (so 105 is still within tolerance)
//
// This means max-based tolerance accepts slightly wider spreads, making it
// less strict in bid-ask scenarios.
func (f FixedPoint[T]) WithinTolerance(
	other FixedPoint[T], tolerancePpm T) (bool, error) {

	// If either of the coefficients are zero, we cannot check tolerance.
	zero := NewInt[T]().FromUint64(0)
	if f.Coefficient.Equals(zero) || other.Coefficient.Equals(zero) {
		return false, fmt.Errorf("cannot check tolerance with zero " +
			"value")
	}

	// Determine the larger scale between the two fixed-point numbers.
	// Both values will be scaled to this larger scale to ensure a
	// consistent comparison.
	var largerScale uint8
	if f.Scale > other.Scale {
		largerScale = f.Scale
	} else {
		largerScale = other.Scale
	}

	subjectFp := f.ScaleTo(largerScale)
	otherFp := other.ScaleTo(largerScale)

	var (
		// delta will be the absolute difference between the two
		// coefficients.
		delta T

		// maxCoefficient is the larger of the two coefficients.
		maxCoefficient T
	)
	if subjectFp.Coefficient.Gt(otherFp.Coefficient) {
		delta = subjectFp.Coefficient.Sub(otherFp.Coefficient)
		maxCoefficient = subjectFp.Coefficient
	} else {
		delta = otherFp.Coefficient.Sub(subjectFp.Coefficient)
		maxCoefficient = otherFp.Coefficient
	}

	// Calculate the tolerance in absolute terms based on the largest
	// coefficient.
	//
	// tolerancePpm is parts per million, therefore we multiply the delta by
	// 1,000,000 instead of dividing the tolerance.
	scaledDelta := delta.Mul(NewInt[T]().FromUint64(1_000_000))

	// Compare the scaled delta to the product of the maximum coefficient
	// and the tolerance.
	toleranceCoefficient := maxCoefficient.Mul(tolerancePpm)
	result := toleranceCoefficient.Gte(scaledDelta)
	return result, nil
}

// AddTolerance applies the given tolerance expressed in parts per million (ppm)
// to the provided amount.
func AddTolerance(value, tolerancePpm BigInt) BigInt {
	// A placeholder variable for ppm value denominator (1 million).
	ppmBase := NewBigIntFromUint64(1_000_000)

	// Convert the tolerancePpm value to the actual units that express this
	// margin.
	toleranceUnits := value.Mul(tolerancePpm).Div(ppmBase)

	res := value.Add(toleranceUnits)

	// We now add the tolerance margin to the original value and return the
	// result.
	return res
}

// FixedPointFromUint64 creates a new FixedPoint from the given integer and
// scale. Note that the input here should be *unscaled*.
func FixedPointFromUint64[N Int[N]](value uint64, scale uint8) FixedPoint[N] {
	scaleN := NewInt[N]().FromFloat(math.Pow10(int(scale)))
	coefficientN := NewInt[N]().FromUint64(value)

	return FixedPoint[N]{
		Coefficient: scaleN.Mul(coefficientN),
		Scale:       scale,
	}
}

// BigIntFixedPoint is a fixed-point number with a BigInt coefficient.
type BigIntFixedPoint = FixedPoint[BigInt]

// NewBigIntFixedPoint creates a new BigInt fixed-point given a coefficient and
// scale.
func NewBigIntFixedPoint(coefficient uint64, scale uint8) BigIntFixedPoint {
	return BigIntFixedPoint{
		Coefficient: NewBigIntFromUint64(coefficient),
		Scale:       scale,
	}
}
