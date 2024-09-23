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

// Mul multiplies the current FixedPoint value by another and returns the result
// as a new FixedPoint value.
func (f FixedPoint[T]) Mul(other FixedPoint[T]) FixedPoint[T] {
	// Multiply the coefficients of the two FixedPoint values.
	coefficientProduct := f.Coefficient.Mul(other.Coefficient)

	// Our goals are twofold: to incorporate both scale values into the
	// result and to avoid unnecessarily large scale values in the final
	// result. A naive approach would be to set the final scale as the sum
	// of the two scales, but this would result in an unnecessarily large
	// scale.
	//
	// To minimize the final scale, we divide the product of the
	// coefficients by the smaller of the two scale values. The larger scale
	// is then used as the final scale for the result.
	//
	// Determine which fixed-point has the smaller and larger scale.
	var (
		smallScale uint8
		bigScale   uint8
	)

	if other.Scale < f.Scale {
		smallScale = other.Scale
		bigScale = f.Scale
	} else {
		smallScale = f.Scale
		bigScale = other.Scale
	}

	// Scale the coefficient product down using the smaller scale.
	divisor := NewInt[T]().FromFloat(math.Pow10(int(smallScale)))
	downScaleProduct := coefficientProduct.Div(divisor)

	// Return a new FixedPoint with the adjusted coefficient and the
	// larger scale.
	return FixedPoint[T]{
		Coefficient: downScaleProduct,
		Scale:       bigScale,
	}
}

// Div returns a new FixedPoint that is the result of dividing the existing int
// by the passed one.
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
