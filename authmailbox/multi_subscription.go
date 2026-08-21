package authmailbox

import (
	"context"
	"fmt"
	"net/url"
	"sync"

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

	// dropSignals carries the serialized receiver keys of message bundles
	// that were dropped from the shared message queue because the overflow
	// cap was reached.
	dropSignals chan asset.SerializedKey

	// pendingReplays tracks the receiver keys for which a replay
	// resubscription is currently in flight, so that a burst of drops
	// only triggers one replay per subscription.
	pendingReplays map[asset.SerializedKey]bool

	// startSubscription creates a new receive subscription for a client.
	// It is a field so that tests can stub it out.
	startSubscription func(ctx context.Context, client *Client,
		msgChan chan<- *ReceivedMessages,
		receiverKey keychain.KeyDescriptor,
		filter MessageFilter) (ReceiveSubscription, error)

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

	m := &MultiSubscription{
		baseClientConfig: baseClientConfig,
		clients:          make(map[url.URL]*clientSubscriptions),
		msgQueue:         queue,
		dropSignals:      make(chan asset.SerializedKey, 1),
		pendingReplays:   make(map[asset.SerializedKey]bool),
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
// bundle is dropped because the overflow cap was reached. It signals the drop
// handler so the affected subscription can be re-established for a replay.
func (m *MultiSubscription) onQueueDrop(msg *ReceivedMessages) {
	if msg == nil || msg.Receiver.PubKey == nil {
		return
	}

	key := asset.ToSerialized(msg.Receiver.PubKey)

	// Never block the queue's goroutine; if a signal is already pending,
	// the replay it triggers will cover this drop as well.
	select {
	case m.dropSignals <- key:
	default:
	}
}

// dropHandler processes queue drop signals and triggers a replay of the
// affected subscription.
func (m *MultiSubscription) dropHandler() {
	defer m.wg.Done()

	for {
		select {
		case key := <-m.dropSignals:
			m.replaySubscription(key)

		case <-m.quit:
			return
		}
	}
}

// replaySubscription re-establishes the subscription for the given receiver
// key, causing the mailbox server to replay all messages matching the
// subscription's filter from its durable store. This recovers messages that
// were dropped from the shared message queue under overflow.
func (m *MultiSubscription) replaySubscription(key asset.SerializedKey) {
	m.Lock()
	defer m.Unlock()

	// Only one replay per subscription at a time. Drops that happen while
	// a replay is in flight are covered by that replay, since the replay
	// re-fetches everything matching the original filter.
	if m.pendingReplays[key] {
		return
	}

	// Find the client that serves this receiver key.
	var (
		client *clientSubscriptions
		found  bool
	)
	for _, c := range m.clients {
		if _, ok := c.params[key]; ok {
			client = c
			found = true
			break
		}
	}
	if !found {
		log.Warnf("Dropped mailbox messages for unknown receiver "+
			"%s, cannot replay", key)
		return
	}

	m.pendingReplays[key] = true
	defer delete(m.pendingReplays, key)

	params := client.params[key]

	log.Infof("Mailbox message queue overflowed, re-establishing "+
		"subscription for receiver %s to replay dropped messages", key)

	// Cancel the current subscription, then start a fresh one with the
	// same filter. The server replays all messages matching the filter,
	// including the dropped ones.
	if cancel, ok := client.cancels[key]; ok {
		cancel()
	}
	if sub, ok := client.subscriptions[key]; ok {
		if err := sub.Stop(); err != nil {
			log.Errorf("Error stopping subscription for replay: %v",
				err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	subscription, err := m.startSubscription(
		ctx, client.client, m.msgQueue.ChanIn(), params.receiverKey,
		params.filter,
	)
	if err != nil {
		cancel()
		log.Errorf("Unable to re-establish subscription for "+
			"receiver %s after queue overflow: %v", key, err)
		return
	}

	client.subscriptions[key] = subscription
	client.cancels[key] = cancel
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
