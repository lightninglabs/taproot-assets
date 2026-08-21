package fn

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestConcurrentQueueUnbounded verifies basic FIFO ordering with
// no overflow cap.
func TestConcurrentQueueUnbounded(t *testing.T) {
	t.Parallel()

	const n = 100

	q := NewConcurrentQueue[int](10)
	q.Start()

	go func() {
		for i := 0; i < n; i++ {
			q.ChanIn() <- i
		}
		close(q.chanIn)
	}()

	var got []int
	for v := range q.ChanOut() {
		got = append(got, v)
	}

	require.Len(t, got, n)
	for i := 0; i < n; i++ {
		require.Equal(t, i, got[i])
	}
}

// TestConcurrentQueueMaxOverflow verifies that WithMaxOverflow
// caps the overflow list, dropping the oldest items when the
// reader is stalled.
func TestConcurrentQueueMaxOverflow(t *testing.T) {
	t.Parallel()

	const (
		bufSize     = 1
		maxOverflow = 5
		total       = 20
	)

	q := NewConcurrentQueue[int](
		bufSize, WithMaxOverflow(maxOverflow),
	)
	q.Start()

	// Push all items while nobody is reading. The output
	// channel (capacity 1) holds the first item directly;
	// the rest spill into the overflow list, which trims
	// to maxOverflow.
	for i := 0; i < total; i++ {
		q.ChanIn() <- i
	}

	close(q.chanIn)

	var got []int
	for v := range q.ChanOut() {
		got = append(got, v)
	}

	// We receive the item in chanOut (the very first push)
	// plus the maxOverflow survivors.
	require.Len(t, got, bufSize+maxOverflow)

	// The first item bypassed overflow entirely.
	require.Equal(t, 0, got[0])

	// The remaining items are the tail of the input
	// sequence, in FIFO order.
	for i := 1; i < len(got); i++ {
		expected := total - maxOverflow + (i - 1)
		require.Equal(t, expected, got[i])
	}

	// After drain, the overflow counter should be zero.
	require.Equal(t, int64(0), q.OverflowLen())
}

// TestConcurrentQueueOverflowLenProperty uses property-based
// testing to verify that OverflowLen never exceeds maxOverflow
// after the goroutine settles, regardless of push count or
// queue parameters.
func TestConcurrentQueueOverflowLenProperty(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		bufSize := rapid.IntRange(1, 10).Draw(
			t, "bufSize",
		)
		maxOverflow := rapid.IntRange(1, 50).Draw(
			t, "maxOverflow",
		)
		numPushes := rapid.IntRange(
			1, bufSize+maxOverflow*3,
		).Draw(t, "numPushes")

		q := NewConcurrentQueue[int](
			bufSize, WithMaxOverflow(maxOverflow),
		)
		q.Start()

		for i := 0; i < numPushes; i++ {
			q.ChanIn() <- i

			// Let the goroutine settle, then check
			// the invariant.
			require.Eventually(t, func() bool {
				return q.OverflowLen() <=
					int64(maxOverflow)
			}, time.Second, time.Millisecond)
		}

		q.Stop()
	})
}

// TestConcurrentQueueOverflowDropCallback verifies that the overflow drop
// callback is invoked with each dropped item, oldest first, when the
// overflow cap is exceeded.
func TestConcurrentQueueOverflowDropCallback(t *testing.T) {
	t.Parallel()

	dropped := make(chan int, 10)

	q := NewConcurrentQueue[int](1, WithMaxOverflow(2))
	q.SetOnOverflowDrop(func(item int) {
		dropped <- item
	})
	q.Start()
	t.Cleanup(q.Stop)

	// Push 5 items with no reader: 1 fills the output buffer, 2 fill
	// the overflow list, and the remaining 2 each evict the oldest
	// overflow item.
	for i := 0; i < 5; i++ {
		q.ChanIn() <- i
	}

	// The two oldest overflow items (1 and 2) must be reported as
	// dropped.
	for _, want := range []int{1, 2} {
		select {
		case got := <-dropped:
			require.Equal(t, want, got)
		case <-time.After(2 * time.Second):
			t.Fatalf("expected drop callback for item %d", want)
		}
	}
}
