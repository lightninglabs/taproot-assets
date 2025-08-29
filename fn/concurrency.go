package fn

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"golang.org/x/sync/errgroup"
)

// ErrFunc is a type def for a function that takes a context (to allow early
// cancellation) and a series of value returning an error. This is typically
// used a closure to perform concurrent work over a homogeneous slice of
// values.
type ErrFunc[V any] func(context.Context, V) error

// ParSlice can be used to execute a function on each element of a slice in
// parallel. This function is fully blocking and will wait for all goroutines
// to either succeed, or for the first to error out.  Active goroutines limited
// with number of CPU.  Context will be passed in executable func and canceled
// the first time a function passed returns a non-nil error.  Returns the first
// non-nil error (if any).
func ParSlice[V any](ctx context.Context, s []V, f ErrFunc[V]) error {
	errGroup, ctx := errgroup.WithContext(ctx)
	errGroup.SetLimit(runtime.GOMAXPROCS(0))

	for _, v := range s {
		// Snapshot v now so the goroutine sees the intended value
		// even if the caller mutates the slice s later. This is a
		// shallow copy only, if V contains pointers, their contents can
		// still change.
		v := v

		errGroup.Go(func() error {
			return f(ctx, v)
		})
	}

	return errGroup.Wait()
}

// ParSliceErrCollect can be used to execute a function on each element of a
// slice in parallel. This function is fully blocking and will wait for all
// goroutines to finish (subject to context cancellation/timeout). Any errors
// will be collected and returned as a map of slice element index to error.
// Active goroutines limited with number of CPU.
func ParSliceErrCollect[V any](ctx context.Context, s []V,
	f ErrFunc[V]) (map[int]error, error) {

	errGroup, groupCtx := errgroup.WithContext(ctx)
	errGroup.SetLimit(runtime.GOMAXPROCS(0))

	var (
		instanceErrorsMu sync.Mutex
		instanceErrors   = make(map[int]error, len(s))
	)

	for idx := range s {
		// Snapshot s[idx] now so the goroutine sees the intended value
		// even if the caller mutates the slice later. This is a shallow
		// copy only, if V contains pointers, their contents can still
		// change.
		v := s[idx]

		errGroup.Go(func() error {
			// If already canceled, skip work without signaling an
			// error.
			select {
			case <-groupCtx.Done():
				return nil
			default:
			}

			err := f(groupCtx, v)
			if err != nil {
				instanceErrorsMu.Lock()
				instanceErrors[idx] = err
				instanceErrorsMu.Unlock()
			}

			// Do not return an error here. If we did, errGroup
			// would cancel the context and stop all other element
			// processors. Instead, record the error locally
			// and return it after all goroutines finish.
			return nil
		})
	}

	// Wait for all goroutines to finish. In this design, goroutines do not
	// return errors, so Wait should normally return nil. We handle context
	// cancellation separately with an explicit ctx.Err() check.
	if err := errGroup.Wait(); err != nil {
		return nil, fmt.Errorf("failed to wait on error group in "+
			"ParSliceErrorCollect: %w", err)
	}

	// If the caller's context was canceled or timed out, surface that.
	// Return whatever per-item errors were collected before cancellation.
	if err := ctx.Err(); err != nil {
		return instanceErrors, err
	}

	return instanceErrors, nil
}
