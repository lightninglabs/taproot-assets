package fn

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestRetryFuncNSuccessReturnsImmediately verifies that a successful function
// returns immediately without any retries.
func TestRetryFuncNSuccessReturnsImmediately(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random retry config with reasonable bounds.
		config := RetryConfig{
			MaxRetries: rapid.IntRange(1, 10).Draw(t, "maxRetries"),
			InitialBackoff: time.Duration(
				rapid.IntRange(1, 100).Draw(
					t, "initialBackoffMs",
				),
			) * time.Millisecond,
			BackoffMultiplier: rapid.Float64Range(
				1.1, 3.0,
			).Draw(t, "backoffMultiplier"),
			MaxBackoff: time.Duration(
				rapid.IntRange(100, 5000).Draw(
					t, "maxBackoffMs",
				),
			) * time.Millisecond,
		}

		// Generate a random value to return.
		expectedValue := rapid.Int().Draw(t, "expectedValue")

		// Track how many times the function is called.
		var callCount atomic.Int32

		ctx := context.Background()
		start := time.Now()

		result, err := RetryFuncN(ctx, config, func() (int, error) {
			callCount.Add(1)
			return expectedValue, nil
		})

		elapsed := time.Since(start)

		// The function should only be called once.
		require.Equal(t, int32(1), callCount.Load())

		// No error should be returned.
		require.NoError(t, err)

		// The correct value should be returned.
		require.Equal(t, expectedValue, result)

		// The function should return almost immediately (allowing for
		// some execution overhead).
		require.Less(t, elapsed, 10*time.Millisecond)
	})
}

// TestRetryFuncNRetriesExactlyMaxRetries verifies that a function that always
// fails is retried exactly MaxRetries times.
func TestRetryFuncNRetriesExactlyMaxRetries(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random retry config.
		maxRetries := rapid.IntRange(0, 5).Draw(t, "maxRetries")
		config := RetryConfig{
			MaxRetries: maxRetries,
			InitialBackoff: time.Duration(
				rapid.IntRange(1, 10).Draw(
					t, "initialBackoffMs",
				),
			) * time.Millisecond,
			BackoffMultiplier: rapid.Float64Range(
				1.1, 2.0,
			).Draw(t, "backoffMultiplier"),
			MaxBackoff: time.Duration(
				rapid.IntRange(50, 100).Draw(t, "maxBackoffMs"),
			) * time.Millisecond,
		}

		// Track how many times the function is called.
		var callCount atomic.Int32

		// Create a consistent error for all attempts.
		expectedErr := errors.New("persistent failure")

		ctx := context.Background()

		_, err := RetryFuncN(ctx, config, func() (int, error) {
			callCount.Add(1)
			return 0, expectedErr
		})

		// The function should be called exactly MaxRetries + 1 times
		// (initial attempt + retries).
		require.Equal(t, int32(maxRetries+1), callCount.Load())

		// The final error should be returned.
		require.Equal(t, expectedErr, err)
	})
}

// TestRetryFuncNBackoffIncreases verifies that the backoff duration increases
// exponentially between retries.
func TestRetryFuncNBackoffIncreases(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate retry config with at least 2 retries to observe
		// backoff behavior.
		config := RetryConfig{
			MaxRetries: rapid.IntRange(2, 4).Draw(t, "maxRetries"),
			InitialBackoff: time.Duration(
				rapid.IntRange(5, 20).Draw(
					t, "initialBackoffMs",
				),
			) * time.Millisecond,
			BackoffMultiplier: rapid.Float64Range(
				1.5, 2.5,
			).Draw(t, "backoffMultiplier"),
			MaxBackoff: time.Duration(
				rapid.IntRange(200, 500).Draw(
					t, "maxBackoffMs",
				),
			) * time.Millisecond,
		}

		// Track call times to measure backoff.
		var callTimes []time.Time

		ctx := context.Background()

		_, err := RetryFuncN(ctx, config, func() (int, error) {
			callTimes = append(callTimes, time.Now())
			return 0, errors.New("fail")
		})

		require.Error(t, err)
		require.Len(t, callTimes, config.MaxRetries+1)

		expectedBackoff := config.InitialBackoff
		for i := 1; i < len(callTimes); i++ {
			actualBackoff := callTimes[i].Sub(callTimes[i-1])

			// Allow for some timing variance (20% tolerance plus
			// 5ms for scheduling delays).
			tolerance := float64(expectedBackoff)*0.2 +
				float64(5*time.Millisecond)

			// The actual backoff should be close to the expected
			// backoff.
			require.InDelta(
				t, float64(expectedBackoff),
				float64(actualBackoff),
				tolerance,
			)

			// Calculate the next expected backoff, capping at
			// MaxBackoff.
			expectedBackoff = time.Duration(
				float64(expectedBackoff) *
					config.BackoffMultiplier,
			)
			if expectedBackoff > config.MaxBackoff {
				expectedBackoff = config.MaxBackoff
			}
		}
	})
}

// TestRetryFuncNContextCancellation verifies that context cancellation stops
// the retry loop immediately.
func TestRetryFuncNContextCancellation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a retry config with shorter timeouts for faster test
		// execution.
		config := RetryConfig{
			MaxRetries: rapid.IntRange(2, 5).Draw(t, "maxRetries"),
			InitialBackoff: time.Duration(
				rapid.IntRange(10, 50).Draw(
					t, "initialBackoffMs",
				),
			) * time.Millisecond,
			BackoffMultiplier: 1.5,
			MaxBackoff:        100 * time.Millisecond,
		}

		// Track how many times the function is called.
		var callCount atomic.Int32

		// Cancel the context after the first attempt to ensure we
		// cancel during a backoff wait.
		ctx, cancel := context.WithCancel(context.Background())

		// Schedule cancellation after a short delay.
		go func() {
			time.Sleep(5 * time.Millisecond)
			cancel()
		}()

		_, err := RetryFuncN(ctx, config, func() (int, error) {
			callCount.Add(1)
			return 0, errors.New("fail")
		})

		// The error should be the context cancellation error.
		require.Equal(t, context.Canceled, err)

		// The function should have been called at least once but not
		// more than MaxRetries+1 times.
		calls := callCount.Load()
		require.GreaterOrEqual(t, calls, int32(1))
		require.LessOrEqual(t, calls, int32(config.MaxRetries+1))
	})
}

// TestRetryFuncNEventualSuccess verifies that if a function succeeds after some
// failures, the correct result is returned.
func TestRetryFuncNEventualSuccess(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		config := RetryConfig{
			MaxRetries: rapid.IntRange(3, 10).Draw(t, "maxRetries"),
			InitialBackoff: time.Duration(
				rapid.IntRange(1, 10).Draw(
					t, "initialBackoffMs",
				),
			) * time.Millisecond,
			BackoffMultiplier: 2.0,
			MaxBackoff:        50 * time.Millisecond,
		}

		// Determine after how many attempts the function should
		// succeed.
		succeedAfter := rapid.IntRange(
			1, config.MaxRetries+1,
		).Draw(t, "succeedAfter")

		expectedValue := rapid.Int().Draw(t, "expectedValue")

		// Track how many times the function is called.
		var callCount atomic.Int32

		ctx := context.Background()

		result, err := RetryFuncN(ctx, config, func() (int, error) {
			count := callCount.Add(1)
			if int(count) >= succeedAfter {
				return expectedValue, nil
			}
			return 0, errors.New("temporary failure")
		})

		// The function should succeed.
		require.NoError(t, err)
		require.Equal(t, expectedValue, result)

		// The function should be called exactly succeedAfter times.
		require.Equal(t, int32(succeedAfter), callCount.Load())
	})
}
