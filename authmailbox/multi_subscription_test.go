package authmailbox

import (
	"context"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/keychain"
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

// mockReceiveSubscription is a no-op ReceiveSubscription for tests.
type mockReceiveSubscription struct {
	stopped  chan struct{}
	stopOnce sync.Once
}

func (m *mockReceiveSubscription) IsSubscribed() bool {
	return true
}

func (m *mockReceiveSubscription) Stop() error {
	m.stopOnce.Do(func() {
		close(m.stopped)
	})
	return nil
}

// TestMultiSubscriptionOverflowTriggersReplay verifies that when the shared
// message queue drops a bundle due to the overflow cap, the subscription for
// the affected receiver is re-established with its original filter, causing
// the mailbox server to replay the dropped messages from its durable store.
func TestMultiSubscriptionOverflowTriggersReplay(t *testing.T) {
	t.Parallel()

	multiSub := NewMultiSubscription(ClientConfig{})
	t.Cleanup(func() {
		require.NoError(t, multiSub.Stop())
	})

	receiverPub := test.RandPubKey(t)
	receiverKey := keychain.KeyDescriptor{PubKey: receiverPub}
	key := asset.ToSerialized(receiverPub)
	filter := MessageFilter{StartBlock: 100}

	// Install a client with an existing subscription for the receiver,
	// with an observable cancel function.
	oldSub := &mockReceiveSubscription{stopped: make(chan struct{})}
	oldCtx, oldCancel := context.WithCancel(context.Background())

	serverURL := url.URL{Scheme: "authmailbox", Host: "localhost:1234"}
	mboxClient := NewClient(&ClientConfig{
		ServerAddress: serverURL.Host,
		Insecure:      true,
	})
	require.NoError(t, mboxClient.Start())

	multiSub.clients[serverURL] = &clientSubscriptions{
		client: mboxClient,
		subscriptions: map[asset.SerializedKey]ReceiveSubscription{
			key: oldSub,
		},
		cancels: map[asset.SerializedKey]context.CancelFunc{
			key: oldCancel,
		},
		params: map[asset.SerializedKey]subscribeParams{
			key: {receiverKey: receiverKey, filter: filter},
		},
	}

	// Stub out subscription creation and capture the replay parameters.
	type replay struct {
		receiverKey keychain.KeyDescriptor
		filter      MessageFilter
	}
	replayCalls := make(chan replay, 1)
	newSub := &mockReceiveSubscription{stopped: make(chan struct{})}

	multiSub.startSubscription = func(_ context.Context, _ *Client,
		_ chan<- *ReceivedMessages, rKey keychain.KeyDescriptor,
		f MessageFilter) (ReceiveSubscription, error) {

		select {
		case replayCalls <- replay{receiverKey: rKey, filter: f}:
		default:
		}

		return newSub, nil
	}

	// Overflow the queue with bundles for this receiver while nobody
	// drains it.
	totalPushes := fn.DefaultQueueSize + maxMsgQueueOverflow + 5
	for i := 0; i < totalPushes; i++ {
		multiSub.msgQueue.ChanIn() <- &ReceivedMessages{
			Receiver: receiverKey,
		}
	}

	// The drop must trigger a replay with the original subscribe
	// parameters.
	select {
	case r := <-replayCalls:
		require.Equal(t, receiverKey, r.receiverKey)
		require.Equal(t, filter, r.filter)
	case <-time.After(5 * time.Second):
		t.Fatal("expected a replay resubscription after queue overflow")
	}

	// The old subscription must have been canceled and stopped, and the
	// new one installed.
	require.ErrorIs(t, oldCtx.Err(), context.Canceled)
	select {
	case <-oldSub.stopped:
	case <-time.After(time.Second):
		t.Fatal("expected old subscription to be stopped")
	}

	multiSub.RLock()
	require.Same(t, newSub, multiSub.clients[serverURL].subscriptions[key])
	multiSub.RUnlock()
}
