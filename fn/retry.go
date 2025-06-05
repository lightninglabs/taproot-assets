package fn

import (
	"context"
	"time"
)

// RetryConfig defines the parameters for exponential backoff retry behavior.
type RetryConfig struct {
	// MaxRetries specifies how many times to retry after the initial
	// attempt fails.
	MaxRetries int

	// InitialBackoff sets the delay before the first retry attempt.
	InitialBackoff time.Duration

	// BackoffMultiplier determines the exponential growth rate of the
	// backoff duration between successive retries.
	BackoffMultiplier float64

	// MaxBackoff caps the delay between retries to prevent excessive
	// wait times.
	MaxBackoff time.Duration
}

// DefaultRetryConfig provides sensible defaults for retrying RPC calls in
// load-balanced environments where transient failures are expected.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:        10,
		InitialBackoff:    100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		MaxBackoff:        5 * time.Second,
	}
}

// RetryFuncN executes the provided function with exponential backoff retry
// logic. This is particularly useful for RPC calls in load-balanced
// environments where nodes may temporarily return inconsistent results. The
// function respects context cancellation and returns immediately if the context
// is cancelled.
func RetryFuncN[T any](ctx context.Context,
	config RetryConfig, fn func() (T, error)) (T, error) {

	var (
		result T
		err    error
	)

	backoff := config.InitialBackoff

	// We'll retry the function up to MaxRetries times, backing off each
	// time until it succeeds.
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		result, err = fn()
		if err == nil {
			return result, nil
		}

		if attempt == config.MaxRetries {
			return result, err
		}

		// Cap the backoff at the configured maximum to prevent
		// excessive delays.
		if backoff > config.MaxBackoff {
			backoff = config.MaxBackoff
		}

		// Wait for the backoff duration or until the context is
		// cancelled, whichever comes first.
		select {
		case <-ctx.Done():
			return result, ctx.Err()

		case <-time.After(backoff):
			// Apply the multiplier to implement exponential
			// backoff.
			backoff = time.Duration(
				float64(backoff) * config.BackoffMultiplier,
			)
		}
	}

	return result, err
}
