package chanutils

// Reducer represents a function that takes an accumulator and the value, then
// returns a new accumulator.
type Reducer[T, V any] func(accum T, value V) T

// Reduce takes a slice of something, and a reducer, and produces a final
// accumulated value.
func Reduce[T any, V any, S []V](s S, f Reducer[T, V]) T {
	var accum T

	for _, x := range s {
		accum = f(accum, x)
	}

	return accum
}

// Copyable is a generic interface for a type that's able to return a deep copy
// of itself.
type Copyable[T any] interface {
	Copy() T
}

// CopyAll creates a new slice where each item of the slice is a deep copy of
// the elements of the input slice.
func CopyAll[T Copyable[T]](xs []T) []T {
	newItems := make([]T, len(xs))
	for i := range xs {
		newItems[i] = xs[i].Copy()
	}

	return newItems
}
