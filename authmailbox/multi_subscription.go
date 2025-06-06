package authmailbox

import (
	"context"
	"fmt"
	"net/url"

	"github.com/lightninglabs/taproot-assets/asset"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
)

type clientSubscriptions struct {
	client        *Client
	subscriptions map[asset.SerializedKey]ReceiveSubscription
	cancels       map[asset.SerializedKey]context.CancelFunc
}

type MultiSubscription struct {
	baseClientConfig ClientConfig

	clients map[url.URL]*clientSubscriptions

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

func (m *MultiSubscription) Subscribe(clientURL url.URL,
	receiverKey keychain.KeyDescriptor, filter MessageFilter) error {

	client, ok := m.clients[clientURL]
	if !ok {
		cfgCopy := m.baseClientConfig
		cfgCopy.ServerAddress = clientURL.Host

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
		m.clients[clientURL] = client
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

func (m *MultiSubscription) MessageChan() <-chan *ReceivedMessages {
	return m.msgQueue.ChanOut()
}

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
