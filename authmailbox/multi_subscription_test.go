package authmailbox

import (
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/stretchr/testify/require"
)

// TestMultiSubscriptionQueueBounded verifies that the shared message
// queue of a MultiSubscription is bounded: if the consumer stalls
// while a mailbox server keeps delivering messages, the overflow list
// is capped and the oldest bundles are dropped instead of growing
// without limit.
func TestMultiSubscriptionQueueBounded(t *testing.T) {
	t.Parallel()

	multiSub := NewMultiSubscription(ClientConfig{})
	t.Cleanup(func() {
		require.NoError(t, multiSub.Stop())
	})

	// Push more bundles than the output channel buffer plus the
	// overflow cap while nobody is reading from the queue.
	totalPushes := fn.DefaultQueueSize + maxMsgQueueOverflow + 5
	for i := 0; i < totalPushes; i++ {
		multiSub.msgQueue.ChanIn() <- &ReceivedMessages{}
	}

	// The overflow list must never exceed the configured cap.
	require.LessOrEqual(
		t, multiSub.msgQueue.OverflowLen(),
		int64(maxMsgQueueOverflow),
	)

	// Drain the queue. We should only ever get the buffered items plus
	// the capped overflow survivors, not everything that was pushed.
	received := 0
	for {
		select {
		case <-multiSub.MessageChan():
			received++
		case <-time.After(200 * time.Millisecond):
			require.Equal(
				t, fn.DefaultQueueSize+maxMsgQueueOverflow,
				received,
			)
			return
		}
	}
}
