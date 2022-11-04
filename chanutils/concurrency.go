package chanutils

import "golang.org/x/sync/errgroup"

// ErrGroup is iterating through values and calls func
// then waiting for all goroutines to report back. 
// Returns the first non-nil error (if any).
func ErrGroup[V any, S []V](f func(V) error, s S) error {
	eg := &errgroup.Group{}

	for _, v := range s {
		v := v
		eg.Go(func() error {
			return f(v)
		})

	}

	return eg.Wait()
}
