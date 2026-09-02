package authmailbox

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	mboxrpc "github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	"github.com/stretchr/testify/require"
)

// countingClientStream records each receive attempt. Embedding clientStream
// supplies the remaining gRPC stream methods, none of which this test calls.
type countingClientStream struct {
	clientStream

	responses <-chan *toClientMsg
	recvCount atomic.Uint32
}

// Recv returns the next test response and records the attempt.
func (s *countingClientStream) Recv() (*toClientMsg, error) {
	s.recvCount.Add(1)

	return <-s.responses, nil
}

// TestReceiveSubscriptionQueueBackpressuresStream verifies that a full queue
// stops the receive loop from reading another server response. This is the
// application-level boundary at which gRPC transport flow control takes over.
func TestReceiveSubscriptionQueueBackpressuresStream(t *testing.T) {
	t.Parallel()

	responses := make(chan *toClientMsg, 2)
	for i := uint64(0); i < 2; i++ {
		responses <- &toClientMsg{
			ResponseType: &mboxrpc.ReceiveMessagesResponse_Messages{
				Messages: &mboxrpc.MailboxMessages{
					Messages: []*mboxrpc.MailboxMessage{{
						MessageId: i,
					}},
				},
			},
		}
	}

	stream := &countingClientStream{responses: responses}
	msgChan := make(chan *ReceivedMessages, 1)
	msgChan <- &ReceivedMessages{}
	subscription := &receiveSubscription{
		serverStream: stream,
		msgChan:      msgChan,
		quit:         make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)

		subscription.readIncomingStream(context.Background())
	}()

	require.Eventually(t, func() bool {
		return stream.recvCount.Load() == 1
	}, time.Second, time.Millisecond)
	require.Never(t, func() bool {
		return stream.recvCount.Load() > 1
	}, 100*time.Millisecond, time.Millisecond)

	close(subscription.quit)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("receive loop did not stop while delivery blocked")
	}
}

// TestReceiveSubscriptionStopWhileQueueBlocked verifies that subscription
// shutdown cannot hang when delivery is applying backpressure to its stream.
func TestReceiveSubscriptionStopWhileQueueBlocked(t *testing.T) {
	t.Parallel()

	msgChan := make(chan *ReceivedMessages, 1)
	msgChan <- &ReceivedMessages{}

	subscription := &receiveSubscription{
		msgChan: msgChan,
		quit:    make(chan struct{}),
	}

	delivered := make(chan bool, 1)
	subscription.wg.Add(1)
	go func() {
		defer subscription.wg.Done()

		delivered <- subscription.deliverMessage(
			context.Background(), &ReceivedMessages{},
		)
	}()

	select {
	case <-delivered:
		t.Fatal("delivery did not block when the queue was full")
	case <-time.After(100 * time.Millisecond):
	}

	stopped := make(chan error, 1)
	go func() {
		stopped <- subscription.Stop()
	}()

	select {
	case wasDelivered := <-delivered:
		require.False(t, wasDelivered)
	case <-time.After(time.Second):
		t.Fatal("blocked delivery did not observe shutdown")
	}

	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("subscription shutdown blocked on queue delivery")
	}
}

// TestReceiveSubscriptionCancelWhileQueueBlocked verifies that cancellation
// also interrupts a delivery blocked by backpressure.
func TestReceiveSubscriptionCancelWhileQueueBlocked(t *testing.T) {
	t.Parallel()

	msgChan := make(chan *ReceivedMessages, 1)
	msgChan <- &ReceivedMessages{}

	subscription := &receiveSubscription{
		msgChan: msgChan,
		quit:    make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())

	delivered := make(chan bool, 1)
	go func() {
		delivered <- subscription.deliverMessage(
			ctx, &ReceivedMessages{},
		)
	}()

	select {
	case <-delivered:
		t.Fatal("delivery did not block when the queue was full")
	case <-time.After(100 * time.Millisecond):
	}

	cancel()

	select {
	case wasDelivered := <-delivered:
		require.False(t, wasDelivered)
	case <-time.After(time.Second):
		t.Fatal("blocked delivery did not observe context cancellation")
	}
}
