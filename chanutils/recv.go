package chanutils

import (
	"fmt"
	"time"
)

// RecvOrTimeout attempts to recv over chan c, returning the value. If the
// timeout passes before the recv succeeds, an error is returned
func RecvOrTimeout[T any](c <-chan T, timeout time.Duration) (*T, error) {
	select {
	case m := <-c:
		return &m, nil

	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout hit")
	}
}

// RecvResp takes three channels: a response channel, an error channel and a
// quit channel. If either of these channels are sent on, then the function
// will exit with that response. This can be used to wait for a response,
// error, or a quit signal.
func RecvResp[T any](r <-chan T, e <-chan error, q <-chan struct{}) (T, error) {
	var noResp T

	select {
	case resp := <-r:
		return resp, nil

	case err := <-e:
		return noResp, err

	case <-q:
		return noResp, fmt.Errorf("quitting")
	}
}

// Collect receives all values from a channel and returns them as a slice.
//
// NOTE: This function closes the channel to be able to collect all items at
// once.
//
// TODO(roasbeef): instead could take a number of items to recv?
func Collect[T any](c chan T) []T {
	close(c)

	var out []T
	for m := range c {
		out = append(out, m)
	}

	return out
}
