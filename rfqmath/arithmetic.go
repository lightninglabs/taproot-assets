package rfqmath

import (
	"math/big"

	"golang.org/x/exp/constraints"
)

// Arithmetic defines the basic arithmetic operations. The structure of the
// interfaces allows for chaining the arithmetic operations.
type Arithmetic[N any] interface {
	// Add returns the sum of the two numbers.
	Add(N) N

	// Mul returns the product of the two numbers.
	Mul(N) N

	// Sub returns the difference of the two numbers.
	Sub(N) N

	// Div returns the division of the two numbers.
	Div(N) N
}

// Int is an interface that represents an integer types and the operations we
// care about w.r.t that type.
type Int[N any] interface {
	// Arithmetic asserts that the target type of this interface satisfies
	// the Arithmetic interface. This lets us get around limitations
	// regarding recursive types in Go.
	Arithmetic[N]

	// Equals returns true if the two integers are equal.
	Equals(other N) bool

	// Gt returns true if the integer is greater than the other integer.
	Gt(other N) bool

	// Gte returns true if the integer is greater than or equal to the other
	// integer.
	Gte(other N) bool

	// ToFloat converts the integer to a float.
	ToFloat() float64

	// FromFloat converts a float to the integer type.
	FromFloat(float64) N

	// ToUint64 converts the integer to a uint64.
	ToUint64() uint64

	// FromUint64 converts a uint64 to the integer type.
	FromUint64(uint64) N
}

// NewInt creates a new integer of the target type.
func NewInt[N Int[N]]() N {
	var n N
	return n
}

// GoInt is a concrete implementation of the Int interface for the set of
// built-in integer types. It ends up mapping the integers to a uint64
// internally for operations.
type GoInt[T constraints.Unsigned] struct {
	value T
}

// NewGoInt creates a new GoInt from the given integer.
func NewGoInt[T constraints.Unsigned](value T) GoInt[T] {
	return GoInt[T]{
		value: value,
	}
}

// Add returns the sum of the two integers.
func (b GoInt[T]) Add(other GoInt[T]) GoInt[T] {
	return GoInt[T]{
		value: b.value + other.value,
	}
}

// Mul returns the product of the two integers.
func (b GoInt[T]) Mul(other GoInt[T]) GoInt[T] {
	return GoInt[T]{
		value: b.value * other.value,
	}
}

// Sub returns the difference of the two integers.
func (b GoInt[T]) Sub(other GoInt[T]) GoInt[T] {
	return GoInt[T]{
		value: b.value - other.value,
	}
}

// Div returns the division of the two integers.
func (b GoInt[T]) Div(other GoInt[T]) GoInt[T] {
	return GoInt[T]{
		value: b.value / other.value,
	}
}

// ToFloat converts the integer to a float.
func (b GoInt[T]) ToFloat() float64 {
	return float64(b.value)
}

// FromFloat converts a float to the integer type.
func (b GoInt[T]) FromFloat(f float64) GoInt[T] {
	b.value = T(f)
	return b
}

// ToUint64 converts the integer to a uint64.
func (b GoInt[T]) ToUint64() uint64 {
	return uint64(b.value)
}

// FromUint64 converts a uint64 to the integer type.
func (b GoInt[T]) FromUint64(u uint64) GoInt[T] {
	b.value = T(u)
	return b
}

// Equals returns true if the two integers are equal.
func (b GoInt[T]) Equals(other GoInt[T]) bool {
	return b.value == other.value
}

// Gt returns true if the integer is greater than the other integer.
func (b GoInt[T]) Gt(other GoInt[T]) bool {
	return b.value > other.value
}

// Gte returns true if the integer is greater than or equal to the other
// integer.
func (b GoInt[T]) Gte(other GoInt[T]) bool {
	return b.value >= other.value
}

// A compile-time constraint to ensure that the GoInt type implements the Int
// interface.
var _ Int[GoInt[uint]] = GoInt[uint]{}

// BigInt is a concrete implementation of the Int interface using Go's big
// integer type.
type BigInt struct {
	value *big.Int
}

// NewBigInt creates a new BigInt from the given integer.
func NewBigInt(value *big.Int) BigInt {
	return BigInt{
		value: value,
	}
}

// NewBigIntFromUint64 creates a new BigInt from the given uint64.
func NewBigIntFromUint64(value uint64) BigInt {
	return BigInt{
		value: big.NewInt(0).SetUint64(value),
	}
}

// copyInt returns a copy of the internal big.Int. This is used to ensure we
// don't mutate the underlying bit.Int during arithmetic operations.
func (b BigInt) copyInt() *big.Int {
	return new(big.Int).Set(b.value)
}

// Add returns the sum of the two integers.
func (b BigInt) Add(other BigInt) BigInt {
	return BigInt{
		value: b.copyInt().Add(b.value, other.value),
	}
}

// Mul returns the product of the two integers.
func (b BigInt) Mul(other BigInt) BigInt {
	return BigInt{
		value: b.copyInt().Mul(b.value, other.value),
	}
}

// Sub returns the difference of the two integers.
func (b BigInt) Sub(other BigInt) BigInt {
	return BigInt{
		value: b.copyInt().Sub(b.value, other.value),
	}
}

// Div returns the division of the two integers.
func (b BigInt) Div(other BigInt) BigInt {
	return BigInt{
		value: b.copyInt().Div(b.value, other.value),
	}
}

// ToFloat converts the integer to a float.
func (b BigInt) ToFloat() float64 {
	floatVal, _ := b.value.Float64()
	return floatVal
}

// FromFloat converts a float to the integer type.
func (b BigInt) FromFloat(f float64) BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}

	b.value.SetInt64(int64(f))
	return b
}

// FromUint64 converts a uint64 to the integer type.
func (b BigInt) FromUint64(u uint64) BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}

	b.value.SetUint64(u)
	return b
}

// ToUint64 converts the integer to a uint64.
func (b BigInt) ToUint64() uint64 {
	return b.value.Uint64()
}

// Bytes returns the absolute value of b as a big-endian byte slice.
func (b BigInt) Bytes() []byte {
	return b.value.Bytes()
}

// FromBytes interprets `buf` as a big-endian unsigned integer and returns a new
// BigInt with that value.
func (b BigInt) FromBytes(buf []byte) BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}

	b.value.SetBytes(buf)
	return b
}

// String returns the decimal representation of the BigInt as a string.
// It provides a human-readable format suitable for use in RPC messages and JSON
// serialization.
func (b BigInt) String() string {
	return b.value.String()
}

// Equals returns true if the two integers are equal.
func (b BigInt) Equals(other BigInt) bool {
	return b.value.Cmp(other.value) == 0
}

// Gt returns true if the integer is greater than the other integer.
func (b BigInt) Gt(other BigInt) bool {
	return b.value.Cmp(other.value) == 1
}

// Gte returns true if the integer is greater than or equal to the other
// integer.
func (b BigInt) Gte(other BigInt) bool {
	return b.Equals(other) || b.Gt(other)
}

// A compile-time constraint to ensure that the BigInt type implements the Int
// interface.
var _ Int[BigInt] = BigInt{}
