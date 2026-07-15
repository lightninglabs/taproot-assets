package arith

import (
	"errors"

	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"golang.org/x/exp/constraints"
)

var (
	// ErrOverflow is returned when an arithmetic operation exceeds the
	// maximum value that can be represented by the underlying type.
	ErrOverflow = errors.New("integer overflow")
)

// Add returns the sum of a and b. If the addition overflows the underlying
// unsigned integer type, an error result is returned.
func Add[T constraints.Unsigned](a, b T) lfn.Result[T] {
	sum := a + b
	if sum < a {
		return lfn.Err[T](ErrOverflow)
	}

	return lfn.Ok(sum)
}

// CheckAdd checks whether adding a and b would overflow the underlying
// unsigned integer type.
func CheckAdd[T constraints.Unsigned](a, b T) error {
	if a+b < a {
		return ErrOverflow
	}

	return nil
}
