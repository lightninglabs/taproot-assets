package fn

import "fmt"

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

// Map applies the given mapping function to each element of the given slice
// and generates a new slice.
func Map[I, O any, S []I](s S, f func(I) O) []O {
	output := make([]O, len(s))

	for i, x := range s {
		output[i] = f(x)
	}

	return output
}

// Filter applies the given predicate function to each element of the given
// slice and generates a new slice containing only the elements for which the
// predicate returned true.
func Filter[T any](s []T, f func(T) bool) []T {
	output := make([]T, 0, len(s))

	for _, x := range s {
		if f(x) {
			output = append(output, x)
		}
	}

	return output
}

// FilterMap applies the given predicate function to each element of the given
// map and generates a new slice containing only the elements for which the
// predicate returned true.
func FilterMap[T any, K comparable](s map[K]T, f func(T) bool) []T {
	output := make([]T, 0, len(s))

	for _, x := range s {
		if f(x) {
			output = append(output, x)
		}
	}

	return output
}

// MapErr applies the given fallible mapping function to each element of the
// given slice and generates a new slice. This is identical to Map, but
// returns early if any single mapping fails.
func MapErr[I, O any, S []I](s S, f func(I) (O, error)) ([]O, error) {
	output := make([]O, len(s))
	var err error

	for i, x := range s {
		output[i], err = f(x)
		if err != nil {
			return nil, err
		}
	}

	return output, nil
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

// CopyableErr is a generic interface for a type that's able to return a deep copy
// of itself. This is identical to Copyable, but should be used in cases where
// the copy method can return an error.
type CopyableErr[T any] interface {
	Copy() (T, error)
}

// CopyAllErr creates a new slice where each item of the slice is a deep copy of
// the elements of the input slice. This is identical to CopyAll, but should be
// used in cases where the copy method can return an error.
func CopyAllErr[T CopyableErr[T]](xs []T) ([]T, error) {
	var err error

	newItems := make([]T, len(xs))
	for i := range xs {
		newItems[i], err = xs[i].Copy()
		if err != nil {
			return nil, err
		}
	}

	return newItems, nil
}

// All returns true if the passed predicate returns true for all items in the
// slice.
func All[T any](xs []T, pred func(T) bool) bool {
	for i := range xs {
		if !pred(xs[i]) {
			return false
		}
	}

	return true
}

// AllMapItems returns true if the passed predicate returns true for all items
// in the map.
func AllMapItems[T any, K comparable](xs map[K]T, pred func(T) bool) bool {
	for i := range xs {
		if !pred(xs[i]) {
			return false
		}
	}

	return true
}

// Any returns true if the passed predicate returns true for any item in the
// slice.
func Any[T any](xs []T, pred func(T) bool) bool {
	for i := range xs {
		if pred(xs[i]) {
			return true
		}
	}

	return false
}

// AnyMapItem returns true if the passed predicate returns true for any item in
// the map.
func AnyMapItem[T any, K comparable](xs map[K]T, pred func(T) bool) bool {
	for i := range xs {
		if pred(xs[i]) {
			return true
		}
	}

	return false
}

// NotAny returns true if the passed predicate returns false for all items in
// the slice.
func NotAny[T any](xs []T, pred func(T) bool) bool {
	return !Any(xs, pred)
}

// NotAnyMapItem returns true if the passed predicate returns false for all
// items in the map.
func NotAnyMapItem[T any, K comparable](xs map[K]T, pred func(T) bool) bool {
	return !AnyMapItem(xs, pred)
}

// Count returns the number of items in the slice that match the predicate.
func Count[T any](xs []T, pred func(T) bool) int {
	var count int

	for i := range xs {
		if pred(xs[i]) {
			count++
		}
	}

	return count
}

// CountMapItems returns the number of items in the map that match the
// predicate.
func CountMapItems[T any, K comparable](xs map[K]T, pred func(T) bool) int {
	var count int

	for i := range xs {
		if pred(xs[i]) {
			count++
		}
	}

	return count
}

// First returns the first item in the slice that matches the predicate, or an
// error if none matches.
func First[T any](xs []*T, pred func(*T) bool) (*T, error) {
	for i := range xs {
		if pred(xs[i]) {
			return xs[i], nil
		}
	}

	return nil, fmt.Errorf("no item found")
}

// Last returns the last item in the slice that matches the predicate, or an
// error if none matches.
func Last[T any](xs []*T, pred func(*T) bool) (*T, error) {
	var matches []*T
	for i := range xs {
		if pred(xs[i]) {
			matches = append(matches, xs[i])
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no item found")
	}

	return matches[len(matches)-1], nil
}
