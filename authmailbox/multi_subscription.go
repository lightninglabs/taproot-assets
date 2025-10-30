package authmailbox

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
)

const (
	// DefaultTimeout is the default timeout we use for RPC and database
	// operations.
	DefaultTimeout = 30 * time.Second
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

// clientRegistry is a thread-safe registry for managing mailbox clients.
// It encapsulates the clients map and provides a safe API for accessing
// and modifying client subscriptions.
type clientRegistry struct {
	sync.RWMutex

	// clients holds the active mailbox clients, keyed by their server URL.
	clients map[url.URL]*clientSubscriptions
}

// newClientRegistry creates a new client registry instance.
func newClientRegistry() *clientRegistry {
	return &clientRegistry{
		clients: make(map[url.URL]*clientSubscriptions),
	}
}

// Get retrieves an existing client or creates a new one if it doesn't
// exist. It returns the client and a boolean indicating whether the client
// was newly created.
func (r *clientRegistry) Get(serverURL url.URL,
	cfgCopy ClientConfig) (*clientSubscriptions, bool, error) {

	r.Lock()
	defer r.Unlock()

	client, ok := r.clients[serverURL]
	if ok {
		return client, false, nil
	}

	// Create a new client connection.
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
	}
	r.clients[serverURL] = client

	return client, true, nil
}

// RemoveClient removes a client from the registry.
func (r *clientRegistry) RemoveClient(serverURL url.URL) {
	r.Lock()
	defer r.Unlock()

	delete(r.clients, serverURL)
}

// AddSubscription adds a subscription and its cancel function to a client. If
// the client does not exist, an error is returned.
func (r *clientRegistry) AddSubscription(serverURL url.URL,
	key asset.SerializedKey, subscription ReceiveSubscription,
	cancel context.CancelFunc) error {

	r.Lock()
	defer r.Unlock()

	client, ok := r.clients[serverURL]
	if !ok {
		return fmt.Errorf("no client found for %s", serverURL.String())
	}

	client.subscriptions[key] = subscription
	client.cancels[key] = cancel

	return nil
}

// ForEach executes a function for each client in the registry. The function
// receives a copy of the client subscriptions to avoid holding the lock
// during potentially long operations.
func (r *clientRegistry) ForEach(fn func(*clientSubscriptions)) {
	r.RLock()
	defer r.RUnlock()

	for _, client := range r.clients {
		fn(client)
	}
}

// MultiSubscription is a subscription manager that can handle multiple mailbox
// clients, allowing subscriptions to different accounts across different
// mailbox servers. It manages subscriptions and message queues for each client
// and provides a unified interface for receiving messages.
type MultiSubscription struct {
	// cfg holds the configuration for the MultiSubscription instance.
	cfg MultiSubscriptionConfig

	// registry manages the active mailbox clients in a thread-safe manner.
	registry *clientRegistry

	// msgQueue is the concurrent queue that holds received messages from
	// all subscriptions across all clients. This allows for a unified
	// message channel that can be used to receive messages from any
	// subscribed account, regardless of which mailbox server it belongs to.
	msgQueue *lfn.ConcurrentQueue[*ReceivedMessages]

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// MultiSubscriptionConfig holds the configuration parameters for creating a
// MultiSubscription instance.
type MultiSubscriptionConfig struct {
	// baseClientConfig holds the basic configuration for the mailbox
	// clients. All fields except the ServerAddress are used to create
	// new mailbox clients when needed.
	BaseClientConfig ClientConfig

	// FallbackMboxURLs are fallback proof courier AuthMailbox services.
	FallbackMboxURLs []url.URL
}

// NewMultiSubscription creates a new MultiSubscription instance.
func NewMultiSubscription(cfg MultiSubscriptionConfig) *MultiSubscription {
	queue := lfn.NewConcurrentQueue[*ReceivedMessages](lfn.DefaultQueueSize)
	queue.Start()

	return &MultiSubscription{
		cfg:      cfg,
		registry: newClientRegistry(),
		msgQueue: queue,
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Subscribe adds a subscription for the given client URL and receiver key.
// It launches a goroutine to asynchronously establish any fallback
// subscriptions.
func (m *MultiSubscription) Subscribe(ctx context.Context,
	primaryServerURL url.URL, receiverKey keychain.KeyDescriptor,
	filter MessageFilter) error {

	// Attempt to subscribe to all fallback mailbox servers in parallel and
	// in a non-blocking manner.
	m.Goroutine(func() error {
		errMap, err := fn.ParSliceErrCollect(
			ctx, m.cfg.FallbackMboxURLs,
			func(ctx context.Context, serverURL url.URL) error {
				return m.establishSubscription(
					ctx, serverURL, receiverKey, filter,
				)
			},
		)
		if err != nil {
			return fmt.Errorf("parallel subscription attempt "+
				"failed: %w", err)
		}

		for idx, subErr := range errMap {
			serverURL := m.cfg.FallbackMboxURLs[idx]

			log.ErrorS(ctx, "Subscription to fallback server "+
				"failed", subErr, "server_addr",
				serverURL.String())
		}

		return nil
	}, func(err error) {
		log.ErrorS(ctx, "Fallback server subscription goroutine "+
			"exited with error", err)
	})

	// Subscribe to the primary mailbox server in a blocking manner. This
	// ensures that we have at least one active subscription before
	// returning.
	err := m.establishSubscription(
		ctx, primaryServerURL, receiverKey, filter,
	)
	if err != nil {
		return fmt.Errorf("primary server subscription failed: %w", err)
	}

	return nil
}

// establishSubscription synchronously subscribes to a server.
// It creates a mailbox client for the URL if none exists.
// The subscription routes messages matching the filter to the shared queue.
func (m *MultiSubscription) establishSubscription(ctx context.Context,
	serverURL url.URL, receiverKey keychain.KeyDescriptor,
	filter MessageFilter) error {

	// Get or create a client for the given server URL. This call is
	// thread-safe and will handle locking internally.
	cfgCopy := m.cfg.BaseClientConfig
	client, isNewClient, err := m.registry.Get(serverURL, cfgCopy)
	if err != nil {
		return err
	}

	// Start the mailbox client if it's not already started. This is safe to
	// do without holding any locks since the client itself manages its own
	// state.
	if isNewClient {
		log.Debugf("Starting new mailbox client for %s",
			serverURL.String())

		err = client.client.Start()
		if err != nil {
			// Remove the client from the map if we failed to start
			// it.
			m.registry.RemoveClient(serverURL)
			return fmt.Errorf("unable to start mailbox client: %w",
				err)
		}
	}

	// Start the subscription. We don't hold any locks during this call
	// since StartAccountSubscription might block for a while.
	ctx, cancel := context.WithCancel(ctx)
	subscription, err := client.client.StartAccountSubscription(
		ctx, m.msgQueue.ChanIn(), receiverKey, filter,
	)
	if err != nil {
		cancel()
		return fmt.Errorf("unable to start mailbox subscription: %w",
			err)
	}

	// Add the subscription and cancel function to the client's maps.
	// This is thread-safe and handled internally by the registry.
	key := asset.ToSerialized(receiverKey.PubKey)
	err = m.registry.AddSubscription(serverURL, key, subscription, cancel)
	if err != nil {
		cancel()
		return fmt.Errorf("unable to add subscription to registry: %w",
			err)
	}

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

	log.Info("Stopping all mailbox clients and subscriptions...")

	var lastErr error

	// Iterate through all clients in a thread-safe manner and stop them.
	m.registry.ForEach(func(client *clientSubscriptions) {
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
	})

	return lastErr
}
