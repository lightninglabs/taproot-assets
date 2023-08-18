package tapdb

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExecutorOptionRetryDelay(t *testing.T) {
	t.Parallel()

	opts := defaultTxExecutorOptions()

	halfDelay := opts.initialRetryDelay / 2

	// Expect a random delay between -0.5 and +0.5 of the initial delay.
	require.InDelta(
		t, opts.initialRetryDelay, opts.randRetryDelay(0),
		float64(halfDelay),
	)

	// Expect the second attempt to be double the initial delay.
	require.InDelta(
		t, opts.initialRetryDelay*2, opts.randRetryDelay(1),
		float64(halfDelay*2),
	)

	// Expect the value to be capped at the maximum delay.
	require.Equal(t, opts.maxRetryDelay, opts.randRetryDelay(100))
}
