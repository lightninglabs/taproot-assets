package authmailbox

import (
	"testing"
	"time"

	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// testReceivedMessages returns a bundle with an ID that can be used to assert
// ordering without requiring a complete mailbox message.
func testReceivedMessages(id uint64) *ReceivedMessages {
	return &ReceivedMessages{
		Messages: []*mboxrpc.MailboxMessage{{MessageId: id}},
	}
}

// receivedMessageID returns the ID embedded by testReceivedMessages.
func receivedMessageID(bundle *ReceivedMessages) uint64 {
	return bundle.Messages[0].MessageId
}

// TestMultiSubscriptionQueueBackpressure verifies that the shared queue has
// exactly the intended capacity, preserves every bundle, and blocks a producer
// once that capacity is exhausted.
func TestMultiSubscriptionQueueBackpressure(t *testing.T) {
	t.Parallel()

	multiSub := NewMultiSubscription(ClientConfig{})
	require.Equal(t, maxMsgQueueSize, cap(multiSub.msgQueue.messages))

	for i := 0; i < maxMsgQueueSize; i++ {
		multiSub.msgQueue.ChanIn() <- testReceivedMessages(uint64(i))
	}

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)

		multiSub.msgQueue.ChanIn() <- testReceivedMessages(
			maxMsgQueueSize,
		)
	}()

	select {
	case <-sendDone:
		t.Fatal("producer did not block when the queue was full")
	case <-time.After(100 * time.Millisecond):
	}

	first := <-multiSub.MessageChan()
	require.Equal(t, uint64(0), receivedMessageID(first))

	select {
	case <-sendDone:
	case <-time.After(time.Second):
		t.Fatal("producer still blocked after queue space freed")
	}

	for i := 1; i <= maxMsgQueueSize; i++ {
		bundle := <-multiSub.MessageChan()
		require.Equal(t, uint64(i), receivedMessageID(bundle))
	}
}

// TestBoundedMessageQueueFIFOProperty verifies over generated input sequences
// that the queue preserves every bundle in FIFO order, including sequences
// large enough to force producer backpressure.
func TestBoundedMessageQueueFIFOProperty(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		ids := rapid.SliceOfN(
			rapid.Uint64(), 0, maxMsgQueueSize*2,
		).Draw(t, "ids")
		queue := newBoundedMessageQueue()

		require.Equal(t, maxMsgQueueSize, cap(queue.messages))

		// Fill as much of the queue as possible synchronously. Sending
		// the rest concurrently exercises the blocking boundary.
		initial := min(len(ids), maxMsgQueueSize)
		for _, id := range ids[:initial] {
			queue.ChanIn() <- testReceivedMessages(id)
		}

		sendDone := make(chan struct{})
		go func() {
			defer close(sendDone)

			for _, id := range ids[initial:] {
				queue.ChanIn() <- testReceivedMessages(id)
			}
		}()

		for _, want := range ids {
			bundle := <-queue.ChanOut()
			require.Equal(t, want, receivedMessageID(bundle))

			queueLen := len(queue.messages)
			require.LessOrEqual(t, queueLen, maxMsgQueueSize)
		}

		select {
		case <-sendDone:
		case <-time.After(time.Second):
			t.Fatal("producer did not finish after queue drained")
		}
	})
}
