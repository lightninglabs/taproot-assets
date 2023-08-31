package fn

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	testTimeout = 100 * time.Millisecond
)

func TestCollectBatch(t *testing.T) {
	t.Parallel()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, testTimeout)
	defer cancel()

	// First, test the expected normal case where we receive all the items
	// and the channel is closed.
	var (
		c           = make(chan int, 10)
		numReceived = 0
	)

	for i := 0; i < 10; i++ {
		c <- i
	}
	close(c)

	err := CollectBatch(
		ctxt, c, 3, func(ctx context.Context, batch []int) error {
			numReceived += len(batch)

			return nil
		},
	)
	require.NoError(t, err)
	require.Equal(t, 10, numReceived)

	// If we don't close the channel, then we expect to run into the
	// timeout and only receive 9 out of 10 items (the last batch is never
	// completed).
	c = make(chan int, 10)
	numReceived = 0
	for i := 0; i < 10; i++ {
		c <- i
	}
	err = CollectBatch(
		ctxt, c, 3, func(ctx context.Context, batch []int) error {
			numReceived += len(batch)

			return nil
		},
	)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, 9, numReceived)
}
