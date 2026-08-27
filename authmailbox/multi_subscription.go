package authmailbox

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/keychain"
)

const (
	// maxMsgQueueOverflow is the maximum number of received message
	// bundles allowed to accumulate in the shared message queue before
	// the oldest bundles are dropped. This is a memory-safety bound, not
	// a delivery guarantee: it protects the daemon against a mailbox
	// server that delivers messages faster than the consumer drains
	// them.
	maxMsgQueueOverflow = 1000
)

// subscribeParams holds the parameters a subscription was created with, so
// that it can be re-established later to trigger a server-side replay.
type subscribeParams struct {
	// receiverKey is the key of the account the subscription is for.
	receiverKey keychain.KeyDescriptor

	// filter is the message filter the subscription was created with.
	filter MessageFilter
}

// clientSubscriptions holds the subscriptions and cancel functions for a
// specific mailbox client.
type clientSubscriptions struct {
	// client is the mailbox client that this subscription belongs to.
	client *Client

	// subscriptions holds the active subscriptions for this client, keyed
	// by the serialized public key of the receiver.
	subscriptions map[asset.SerializedKey]ReceiveSubscription

	// cancels holds the cancel functions for each subscription, also keyed
	// by the serialized public key of the receiver.
	cancels map[asset.SerializedKey]context.CancelFunc

	// params holds the subscribe parameters for each subscription, keyed
	// by the serialized public key of the receiver.
	params map[asset.SerializedKey]subscribeParams
}

// MultiSubscription is a subscription manager that can handle multiple mailbox
// clients, allowing subscriptions to different accounts across different
// mailbox servers. It manages subscriptions and message queues for each client
// and provides a unified interface for receiving messages.
type MultiSubscription struct {
	// baseClientConfig holds the basic configuration for the mailbox
	// clients. All fields except the ServerAddress are used to create
	// new mailbox clients when needed.
	baseClientConfig ClientConfig

	// clients holds the active mailbox clients, keyed by their server URL.
	clients map[url.URL]*clientSubscriptions

	// msgQueue is the concurrent queue that holds received messages from
	// all subscriptions across all clients. This allows for a unified
	// message channel that can be used to receive messages from any
	// subscribed account, regardless of which mailbox server it belongs to.
	msgQueue *fn.ConcurrentQueue[*ReceivedMessages]

	// pendingDrops holds the serialized receiver keys whose message
	// bundles were dropped from the shared message queue and still need a
	// replay resubscription. The set makes drop coalescing lossless: a
	// drop is never forgotten just because another receiver's drop is
	// being handled.
	pendingDrops dropSet

	// dropMu guards pendingDrops.
	dropMu sync.Mutex

	// dropWake wakes the drop handler when pendingDrops is non-empty. It
	// is only a wake-up signal; the set above carries the actual state.
	dropWake chan struct{}

	// startSubscription creates a new receive subscription for a client.
	// It is a field so that tests can stub it out.
	startSubscription func(ctx context.Context, client *Client,
		msgChan chan<- *ReceivedMessages,
		receiverKey keychain.KeyDescriptor,
		filter MessageFilter) (ReceiveSubscription, error)

	// replayCtx is the parent context for replay resubscriptions. It is
	// canceled by Stop before waiting for the drop handler, so an
	// in-flight replay can never block shutdown.
	replayCtx context.Context

	// replayCancel cancels replayCtx.
	replayCancel context.CancelFunc

	// quit signals the drop handler goroutine to stop.
	quit chan struct{}

	// wg waits for the drop handler goroutine to exit.
	wg sync.WaitGroup

	sync.RWMutex
}

// NewMultiSubscription creates a new MultiSubscription instance.
func NewMultiSubscription(baseClientConfig ClientConfig) *MultiSubscription {
	queue := fn.NewConcurrentQueue[*ReceivedMessages](
		fn.DefaultQueueSize, fn.WithMaxOverflow(maxMsgQueueOverflow),
	)

	replayCtx, replayCancel := context.WithCancel(context.Background())

	m := &MultiSubscription{
		baseClientConfig: baseClientConfig,
		clients:          make(map[url.URL]*clientSubscriptions),
		msgQueue:         queue,
		pendingDrops:     make(dropSet),
		dropWake:         make(chan struct{}, 1),
		replayCtx:        replayCtx,
		replayCancel:     replayCancel,
		quit:             make(chan struct{}),
	}
	m.startSubscription = func(ctx context.Context, client *Client,
		msgChan chan<- *ReceivedMessages,
		receiverKey keychain.KeyDescriptor,
		filter MessageFilter) (ReceiveSubscription, error) {

		return client.StartAccountSubscription(
			ctx, msgChan, receiverKey, filter,
		)
	}

	// A dropped message bundle means the consumer fell behind and messages
	// were lost from the queue. Re-establish the affected subscription so
	// the mailbox server replays the messages from its durable store.
	queue.SetOnOverflowDrop(m.onQueueDrop)

	queue.Start()

	m.wg.Add(1)
	go m.dropHandler()

	return m
}

// Subscribe adds a new subscription for the specified client URL and receiver
// key. It starts a new mailbox client if one does not already exist for the
// given URL. The subscription will receive messages that match the provided
// filter and will send them to the shared message queue.
func (m *MultiSubscription) Subscribe(ctx context.Context, serverURL url.URL,
	receiverKey keychain.KeyDescriptor, filter MessageFilter) error {

	// We hold the mutex for access to common resources.
	m.Lock()
	cfgCopy := m.baseClientConfig
	client, ok := m.clients[serverURL]

	// If this is the first time we're seeing a server URL, we first create
	// a network connection to the mailbox server.
	if !ok {
		cfgCopy.ServerAddress = serverURL.Host

		mboxClient := NewClient(&cfgCopy)
		client = &clientSubscriptions{
			client: mboxClient,
			subscriptions: make(
				map[asset.SerializedKey]ReceiveSubscription,
			),
			cancels: make(
				map[asset.SerializedKey]context.CancelFunc,
			),
			params: make(
				map[asset.SerializedKey]subscribeParams,
			),
		}
		m.clients[serverURL] = client

		err := mboxClient.Start()
		if err != nil {
			m.Unlock()
			return fmt.Errorf("unable to create mailbox client: %w",
				err)
		}
	}

	// We release the lock here again, because StartAccountSubscription
	// might block for a while, and we don't want to hold the lock
	// unnecessarily long.
	m.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	subscription, err := client.client.StartAccountSubscription(
		ctx, m.msgQueue.ChanIn(), receiverKey, filter,
	)
	if err != nil {
		cancel()
		return fmt.Errorf("unable to start mailbox subscription: %w",
			err)
	}

	// We hold the lock again to safely add the subscription and cancel
	// function to the client's maps.
	m.Lock()
	key := asset.ToSerialized(receiverKey.PubKey)
	client.subscriptions[key] = subscription
	client.cancels[key] = cancel
	client.params[key] = subscribeParams{
		receiverKey: receiverKey,
		filter:      filter,
	}
	m.Unlock()

	return nil
}

// onQueueDrop is invoked by the shared message queue when a received message
// bundle is dropped because the overflow cap was reached. It records the
// affected receiver and wakes the drop handler so the subscription can be
// re-established for a replay.
func (m *MultiSubscription) onQueueDrop(msg *ReceivedMessages) {
	if msg == nil || msg.Receiver.PubKey == nil {
		return
	}

	key := asset.ToSerialized(msg.Receiver.PubKey)

	// The pending set makes the coalescing lossless: even if the handler
	// is busy with another receiver, this drop is remembered.
	m.dropMu.Lock()
	m.pendingDrops[key] = struct{}{}
	m.dropMu.Unlock()

	// Never block the queue's goroutine; the wake-up is only a hint, the
	// pending set carries the actual state.
	select {
	case m.dropWake <- struct{}{}:
	default:
	}
}

// dropHandler processes queue drop signals and triggers a replay of the
// affected subscriptions.
func (m *MultiSubscription) dropHandler() {
	defer m.wg.Done()

	for {
		select {
		case <-m.dropWake:
		case <-m.quit:
			return
		}

		// Wait until the queue has drained before replaying. Replaying
		// into a still-saturated queue would just drop the replayed
		// messages again and feed a reconnect loop.
		if !m.waitForDrain() {
			return
		}

		for key := range m.takePendingDrops() {
			if m.replayCtx.Err() != nil {
				return
			}

			m.replaySubscription(key)
		}
	}
}

// waitForDrain blocks until the shared message queue's overflow list is
// empty, the quit signal fires, or the replay context is canceled. It returns
// false in the two latter cases.
func (m *MultiSubscription) waitForDrain() bool {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		if m.msgQueue.OverflowLen() == 0 {
			return true
		}

		select {
		case <-ticker.C:
		case <-m.quit:
			return false
		case <-m.replayCtx.Done():
			return false
		}
	}
}

// dropSet is the set of receiver keys waiting for a replay resubscription.
type dropSet map[asset.SerializedKey]struct{}

// takePendingDrops atomically collects and clears the set of receiver keys
// waiting for a replay.
func (m *MultiSubscription) takePendingDrops() dropSet {
	m.dropMu.Lock()
	defer m.dropMu.Unlock()

	keys := m.pendingDrops
	m.pendingDrops = make(dropSet)

	return keys
}

// requeueDrop puts a receiver key back into the pending set, so a failed
// replay is retried after the next drain cycle.
func (m *MultiSubscription) requeueDrop(key asset.SerializedKey) {
	m.dropMu.Lock()
	m.pendingDrops[key] = struct{}{}
	m.dropMu.Unlock()

	select {
	case m.dropWake <- struct{}{}:
	default:
	}
}

// replaySubscription re-establishes the subscription for the given receiver
// key, causing the mailbox server to replay all messages matching the
// subscription's filter from its durable store. This recovers messages that
// were dropped from the shared message queue under overflow.
func (m *MultiSubscription) replaySubscription(key asset.SerializedKey) {
	// Lookup phase: find the client serving this receiver key and tear
	// down the current subscription. The server keeps undelivered
	// messages in its durable store, so the brief gap before the new
	// subscription is up does not lose anything.
	m.Lock()

	var client *clientSubscriptions
	for _, c := range m.clients {
		if _, ok := c.params[key]; ok {
			client = c
			break
		}
	}
	if client == nil {
		m.Unlock()
		log.Warnf("Dropped mailbox messages for unknown receiver "+
			"%s, cannot replay", key)
		return
	}

	params := client.params[key]

	if cancel, ok := client.cancels[key]; ok {
		cancel()
	}
	if sub, ok := client.subscriptions[key]; ok {
		if err := sub.Stop(); err != nil {
			log.Errorf("Error stopping subscription for replay: %v",
				err)
		}

		delete(client.subscriptions, key)
		delete(client.cancels, key)
	}
	m.Unlock()

	log.Infof("Mailbox message queue overflowed, re-establishing "+
		"subscription for receiver %s to replay dropped messages", key)

	// Network phase: no lock held, and the context is tied to the
	// MultiSubscription lifetime so a stuck server can never block
	// shutdown.
	ctx, cancel := context.WithCancel(m.replayCtx)
	subscription, err := m.startSubscription(
		ctx, client.client, m.msgQueue.ChanIn(), params.receiverKey,
		params.filter,
	)
	if err != nil {
		cancel()

		log.Errorf("Unable to re-establish subscription for "+
			"receiver %s after queue overflow: %v", key, err)

		// The old subscription is gone and the messages are still
		// waiting on the server, so retry after the next drain cycle.
		m.requeueDrop(key)

		return
	}

	// Swap-in phase.
	m.Lock()
	client.subscriptions[key] = subscription
	client.cancels[key] = cancel
	m.Unlock()
}

// MessageChan returns a channel that can be used to receive messages from all
// subscriptions across all mailbox clients. This channel will receive
// ReceivedMessages, which contain the messages and their associated
// metadata, such as the sender and receiver keys.
func (m *MultiSubscription) MessageChan() <-chan *ReceivedMessages {
	return m.msgQueue.ChanOut()
}

// RemoveMessages requests the mailbox server at the given URL to delete one or
// more messages belonging to the given receiver. If no client exists for the
// given URL, an error is returned.
func (m *MultiSubscription) RemoveMessages(ctx context.Context,
	serverURL url.URL, receiverKey keychain.KeyDescriptor,
	messageIDs []uint64) (uint64, error) {

	m.RLock()
	client, ok := m.clients[serverURL]
	m.RUnlock()

	if !ok {
		return 0, fmt.Errorf("no client for server %s", serverURL.Host)
	}

	return client.client.RemoveMessages(ctx, receiverKey, messageIDs)
}

// Stop stops all active subscriptions and mailbox clients. It cancels all
// active subscription contexts and waits for all clients to stop gracefully.
func (m *MultiSubscription) Stop() error {
	defer m.msgQueue.Stop()

	log.Info("Stopping all mailbox clients and subscriptions...")

	close(m.quit)

	// Cancel the replay context before waiting for the drop handler, so
	// an in-flight replay resubscription (which may be retrying a
	// network call) is interrupted and shutdown never hangs on it.
	m.replayCancel()
	m.wg.Wait()

	m.RLock()
	defer m.RUnlock()

	var lastErr error
	for _, client := range m.clients {
		for _, cancel := range client.cancels {
			cancel()
		}

		for _, sub := range client.subscriptions {
			err := sub.Stop()
			if err != nil {
				log.Errorf("Error stopping subscription: %v",
					err)
				lastErr = err
			}
		}

		if err := client.client.Stop(); err != nil {
			log.Errorf("Error stopping client: %v", err)
			lastErr = err
		}
	}

	return lastErr
}
