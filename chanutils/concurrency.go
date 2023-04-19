package chanutils

import (
	"context"
	"runtime"

	"golang.org/x/sync/errgroup"
)

// ErrFunc is a type def for a function that takes a context (to allow early
// cancellation) and a series of value returning an error. This is typically
// used a closure to perform concurrent work over a homogeneous slice of
// values.
type ErrFunc[V any] func(context.Context, V) error

// ErrGroup is iterating through values and calls func then waiting for all
// goroutines to report back.  Active goroutines limited with number of CPU.
// Context will be passed in executable func and canceled the first time a
// function passed returns a non-nil error.  Returns the first non-nil error
// (if any).
//
// TODO(roasbeef): rename Par?
func ErrGroup[V any](ctx context.Context, s []V, f ErrFunc[V]) error {
	errGroup, ctx := errgroup.WithContext(ctx)
	errGroup.SetLimit(runtime.NumCPU())

	for _, v := range s {
		v := v
		errGroup.Go(func() error {
			return f(ctx, v)
		})
	}

	return errGroup.Wait()
}
