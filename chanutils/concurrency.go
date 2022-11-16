package chanutils

import (
	"context"
	"runtime"

	"golang.org/x/sync/errgroup"
)

// ErrGroup is iterating through values and calls func
// then waiting for all goroutines to report back.
// Active goroutines limited with number of CPU.
// Context will be passed in executable func
// and canceled the first time a function passed returns a non-nil error.
// Returns the first non-nil error (if any).
func ErrGroup[V any, S []V](
	ctx context.Context,
	f func(context.Context, V) error,
	s S) error {

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
