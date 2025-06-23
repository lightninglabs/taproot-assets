package authmailbox

import (
	"context"
	"fmt"
	"net/url"

	"github.com/lightninglabs/taproot-assets/asset"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
)

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
	msgQueue *lfn.ConcurrentQueue[*ReceivedMessages]
}

// NewMultiSubscription creates a new MultiSubscription instance.
func NewMultiSubscription(baseClientConfig ClientConfig) *MultiSubscription {
	queue := lfn.NewConcurrentQueue[*ReceivedMessages](lfn.DefaultQueueSize)
	queue.Start()

	return &MultiSubscription{
		baseClientConfig: baseClientConfig,
		clients:          make(map[url.URL]*clientSubscriptions),
		msgQueue:         queue,
	}
}

// Subscribe adds a new subscription for the specified client URL and receiver
// key. It starts a new mailbox client if one does not already exist for the
// given URL. The subscription will receive messages that match the provided
// filter and will send them to the shared message queue.
func (m *MultiSubscription) Subscribe(serverURL url.URL,
	receiverKey keychain.KeyDescriptor, filter MessageFilter) error {

	// If this is the first time we're seeing a server URL, we first create
	// a network connection to the mailbox server.
	client, ok := m.clients[serverURL]
	if !ok {
		cfgCopy := m.baseClientConfig
		cfgCopy.ServerAddress = serverURL.Host

		mboxClient := NewClient(&cfgCopy)

		err := mboxClient.Start()
		if err != nil {
			return fmt.Errorf("unable to create mailbox client: %w",
				err)
		}

		client = &clientSubscriptions{
			client: mboxClient,
			subscriptions: make(
				map[asset.SerializedKey]ReceiveSubscription,
			),
			cancels: make(
				map[asset.SerializedKey]context.CancelFunc,
			),
		}
		m.clients[serverURL] = client
	}

	ctx, cancel := context.WithCancel(context.Background())

	subscription, err := client.client.StartAccountSubscription(
		ctx, m.msgQueue.ChanIn(), receiverKey, filter,
	)
	if err != nil {
		cancel()
		return fmt.Errorf("unable to start mailbox subscription: %w",
			err)
	}

	key := asset.ToSerialized(receiverKey.PubKey)
	client.subscriptions[key] = subscription
	client.cancels[key] = cancel

	return nil
}

// MessageChan returns a channel that can be used to receive messages from all
// subscriptions across all mailbox clients. This channel will receive
// ReceivedMessages, which contain the messages and their associated
// metadata, such as the sender and receiver keys.
func (m *MultiSubscription) MessageChan() <-chan *ReceivedMessages {
	return m.msgQueue.ChanOut()
}

// Stop stops all active subscriptions and mailbox clients. It cancels all
// active subscription contexts and waits for all clients to stop gracefully.
func (m *MultiSubscription) Stop() error {
	defer m.msgQueue.Stop()

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
