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
	// Value is the value of the FixedPoint integer.
	Value T

	// Scale is used to represent the fractional component. This always
	// represents a power of 10. Eg: a scale value of 2 (two decimal
	// places) maps to a multiplication by 100.
	Scale int
}

// String returns the string version of the fixed point value.
func (f FixedPoint[T]) String() string {
	value := f.Value.ToFloat() / math.Pow10(f.Scale)
	return fmt.Sprintf("%.*f", f.Scale, value)
}

// ScaleTo returns a new FixedPoint that is scaled up or down to the given
// scale.
func (f FixedPoint[T]) ScaleTo(newScale int) FixedPoint[T] {
	// Scale diff is the difference between the current scale and the new
	// scale. If this is negative, we need to scale down.
	scaleDiff := newScale - f.Scale

	absoluteScale := int(math.Abs(float64(scaleDiff)))
	scaleMultiplier := NewInt[T]().FromFloat(math.Pow10(absoluteScale))

	// We'll explicitly handle the scale down vs scale up case.
	var newValue T
	switch {
	// No change in scale.
	case scaleDiff == 0:
		newValue = f.Value

	// Larger scale, so we'll multiply by 10^scaleDiff.
	case scaleDiff > 0:
		newValue = f.Value.Mul(scaleMultiplier)

	// Smaller scale, so we'll divide by 10^scaleDiff.
	case scaleDiff < 0:
		newValue = f.Value.Div(scaleMultiplier)
	}

	return FixedPoint[T]{
		Value: newValue,
		Scale: newScale,
	}
}

// ToUint64 returns a new FixedPoint that is scaled down from the existing scale
// and mapped to a uint64 representing the amount of units. This should be used
// to go from FixedPoint to an amount of "units".
func (f FixedPoint[T]) ToUint64() uint64 {
	return f.Value.ToUint64()
}

// ToFloat64 returns a float64 representation of the FixedPoint value.
func (f FixedPoint[T]) ToFloat64() float64 {
	floatStr := f.String()
	float, _ := strconv.ParseFloat(floatStr, 64)
	return float
}

// Mul returns a new FixedPoint that is the result of multiplying the existing
// int by the passed one.
func (f FixedPoint[T]) Mul(other FixedPoint[T]) FixedPoint[T] {
	multiplier := NewInt[T]().FromFloat(math.Pow10(f.Scale))

	result := f.Value.Mul(other.Value).Div(multiplier)

	return FixedPoint[T]{
		Value: result,
		Scale: f.Scale,
	}
}

// Div returns a new FixedPoint that is the result of dividing the existing int
// by the passed one.
func (f FixedPoint[T]) Div(other FixedPoint[T]) FixedPoint[T] {
	multiplier := NewInt[T]().FromFloat(math.Pow10(f.Scale))

	result := f.Value.Mul(multiplier).Div(other.Value)

	return FixedPoint[T]{
		Value: result,
		Scale: f.Scale,
	}
}

// Equals returns true if the two FixedPoint values are equal.
func (f FixedPoint[T]) Equals(other FixedPoint[T]) bool {
	return f.Value.Equals(other.Value) && f.Scale == other.Scale
}

// FixedPointFromUint64 creates a new FixedPoint from the given integer and
// scale. Note that the input here should be *unscaled*.
func FixedPointFromUint64[N Int[N]](value uint64, scale int) FixedPoint[N] {
	scaleN := NewInt[N]().FromFloat(math.Pow10(scale))
	valueN := NewInt[N]().FromUint64(value)

	return FixedPoint[N]{
		Value: scaleN.Mul(valueN),
		Scale: scale,
	}
}
