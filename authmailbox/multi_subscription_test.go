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

	// While the queue is saturated, no replay may fire yet: replaying
	// into a full queue would just drop the replayed messages again.
	select {
	case <-replayCalls:
		t.Fatal("replay fired while the queue was still saturated")
	case <-time.After(1500 * time.Millisecond):
	}

	// Drain the queue, which allows the replay to proceed. Only the
	// buffered plus capped overflow items survived; the rest were
	// dropped.
	for i := 0; i < fn.DefaultQueueSize+maxMsgQueueOverflow; i++ {
		select {
		case <-multiSub.MessageChan():
		case <-time.After(2 * time.Second):
			t.Fatal("timed out draining the message queue")
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

// TestMultiSubscriptionDropsCoalescedLossless verifies that drops for
// different receivers are coalesced without loss: while the handler is busy
// or the queue is saturated, a drop for receiver B must still be replayed
// even if receiver A's drop is being processed first.
func TestMultiSubscriptionDropsCoalescedLossless(t *testing.T) {
	t.Parallel()

	multiSub := NewMultiSubscription(ClientConfig{})
	t.Cleanup(func() {
		require.NoError(t, multiSub.Stop())
	})

	serverURL := url.URL{Scheme: "authmailbox", Host: "localhost:1234"}
	mboxClient := NewClient(&ClientConfig{
		ServerAddress: serverURL.Host,
		Insecure:      true,
	})
	require.NoError(t, mboxClient.Start())

	// Install two receivers on the same client.
	params := make(map[asset.SerializedKey]subscribeParams)
	receiverKeys := make([]keychain.KeyDescriptor, 2)
	for i := range receiverKeys {
		pub := test.RandPubKey(t)
		receiverKeys[i] = keychain.KeyDescriptor{PubKey: pub}
		params[asset.ToSerialized(pub)] = subscribeParams{
			receiverKey: receiverKeys[i],
			filter:      MessageFilter{StartBlock: 100},
		}
	}

	multiSub.clients[serverURL] = &clientSubscriptions{
		client:        mboxClient,
		subscriptions: map[asset.SerializedKey]ReceiveSubscription{},
		cancels:       map[asset.SerializedKey]context.CancelFunc{},
		params:        params,
	}

	replayed := make(chan keychain.KeyDescriptor, 4)
	multiSub.startSubscription = func(_ context.Context, _ *Client,
		_ chan<- *ReceivedMessages, rKey keychain.KeyDescriptor,
		_ MessageFilter) (ReceiveSubscription, error) {

		replayed <- rKey
		sub := &mockReceiveSubscription{stopped: make(chan struct{})}
		return sub, nil
	}

	// Overflow the queue with bundles for both receivers interleaved.
	totalPushes := fn.DefaultQueueSize + maxMsgQueueOverflow + 10
	for i := 0; i < totalPushes; i++ {
		multiSub.msgQueue.ChanIn() <- &ReceivedMessages{
			Receiver: receiverKeys[i%2],
		}
	}

	// Drain the queue so the replays can proceed.
	for i := 0; i < fn.DefaultQueueSize+maxMsgQueueOverflow; i++ {
		select {
		case <-multiSub.MessageChan():
		case <-time.After(2 * time.Second):
			t.Fatal("timed out draining the message queue")
		}
	}

	// Both receivers must eventually get a replay, even though their
	// drops raced a single handler.
	got := make(map[string]bool)
	require.Eventually(t, func() bool {
		select {
		case r := <-replayed:
			got[string(r.PubKey.SerializeCompressed())] = true
		default:
		}

		return len(got) == 2
	}, 5*time.Second, 10*time.Millisecond, "both receivers replayed")
}

// TestMultiSubscriptionStopDuringReplay verifies that Stop does not hang
// when a replay resubscription is blocked in a network call: the replay
// context is tied to the MultiSubscription lifetime and canceled on Stop.
func TestMultiSubscriptionStopDuringReplay(t *testing.T) {
	t.Parallel()

	multiSub := NewMultiSubscription(ClientConfig{})

	serverURL := url.URL{Scheme: "authmailbox", Host: "localhost:1234"}
	mboxClient := NewClient(&ClientConfig{
		ServerAddress: serverURL.Host,
		Insecure:      true,
	})
	require.NoError(t, mboxClient.Start())

	receiverPub := test.RandPubKey(t)
	receiverKey := keychain.KeyDescriptor{PubKey: receiverPub}
	key := asset.ToSerialized(receiverPub)

	multiSub.clients[serverURL] = &clientSubscriptions{
		client:        mboxClient,
		subscriptions: map[asset.SerializedKey]ReceiveSubscription{},
		cancels:       map[asset.SerializedKey]context.CancelFunc{},
		params: map[asset.SerializedKey]subscribeParams{
			key: {
				receiverKey: receiverKey,
				filter:      MessageFilter{},
			},
		},
	}

	// The stub blocks until its context is canceled, mimicking a server
	// that never answers the auth handshake.
	multiSub.startSubscription = func(ctx context.Context, _ *Client,
		_ chan<- *ReceivedMessages, _ keychain.KeyDescriptor,
		_ MessageFilter) (ReceiveSubscription, error) {

		<-ctx.Done()
		return nil, ctx.Err()
	}

	// Trigger a drop and let the handler enter the blocking replay.
	multiSub.onQueueDrop(&ReceivedMessages{Receiver: receiverKey})
	require.Eventually(t, func() bool {
		multiSub.dropMu.Lock()
		defer multiSub.dropMu.Unlock()
		return len(multiSub.pendingDrops) == 0
	}, 5*time.Second, 10*time.Millisecond, "drop picked up by handler")

	// Stop must return promptly even though the replay is blocked.
	stopped := make(chan error, 1)
	go func() {
		stopped <- multiSub.Stop()
	}()

	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Stop hung while a replay was in flight")
	}
}
