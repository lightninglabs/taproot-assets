package rfq

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

const (
	// DefaultTimeout is the default timeout used for context operations.
	DefaultTimeout = 30 * time.Second

	// CacheCleanupInterval is the interval at which local runtime caches
	// are cleaned up.
	CacheCleanupInterval = 30 * time.Second
)

// ManagerCfg is a struct that holds the configuration parameters for the RFQ
// manager.
type ManagerCfg struct {
	// PeerMessenger is the peer messenger. This component provides the RFQ
	// manager with the ability to send and receive raw peer messages.
	PeerMessenger PeerMessenger

	// HtlcInterceptor is the HTLC interceptor. This component is used to
	// intercept and accept/reject HTLCs.
	HtlcInterceptor HtlcInterceptor

	// PriceOracle is the price oracle that the RFQ manager will use to
	// determine whether a quote is accepted or rejected.
	PriceOracle PriceOracle

	// ErrChan is the main error channel which will be used to report back
	// critical errors to the main server.
	ErrChan chan<- error
}

// Manager is a struct that manages the request for quote (RFQ) system.
type Manager struct {
	startOnce sync.Once
	stopOnce  sync.Once

	// cfg holds the configuration parameters for the RFQ manager.
	cfg ManagerCfg

	// orderHandler is the RFQ order handler. This subsystem monitors HTLCs
	// (Hash Time Locked Contracts), determining acceptance or rejection
	// based on compliance with the terms of any associated quote.
	orderHandler *OrderHandler

	// streamHandler is the RFQ stream handler. This subsystem handles
	// incoming and outgoing peer RFQ stream messages.
	streamHandler *StreamHandler

	// negotiator is the RFQ quote negotiator. This subsystem determines
	// whether a quote is accepted or rejected.
	negotiator *Negotiator

	// incomingMessages is a channel which is populated with incoming
	// messages.
	incomingMessages chan rfqmsg.IncomingMsg

	// outgoingMessages is a channel which is populated with outgoing
	// messages. These are messages which are destined to be sent to peers.
	outgoingMessages chan rfqmsg.OutgoingMsg

	// acceptHtlcEvents is a channel which is populated with accept HTLCs
	// events.
	acceptHtlcEvents chan *AcceptHtlcEvent

	// peerAcceptedQuotes is a map of serialised short channel IDs (SCIDs)
	// to associated accepted quotes. These quotes have been accepted by
	// peer nodes and are therefore available for use in buying assets.
	peerAcceptedQuotes lnutils.SyncMap[SerialisedScid, rfqmsg.BuyAccept]

	// subscribers is a map of components that want to be notified on new
	// events, keyed by their subscription ID.
	subscribers lnutils.SyncMap[uint64, *fn.EventReceiver[fn.Event]]

	// subsystemErrChan is the error channel populated by subsystems.
	subsystemErrChan chan error

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewManager creates a new RFQ manager.
func NewManager(cfg ManagerCfg) (*Manager, error) {
	return &Manager{
		cfg: cfg,

		incomingMessages: make(chan rfqmsg.IncomingMsg),
		outgoingMessages: make(chan rfqmsg.OutgoingMsg),

		acceptHtlcEvents: make(chan *AcceptHtlcEvent),
		peerAcceptedQuotes: lnutils.SyncMap[
			SerialisedScid, rfqmsg.BuyAccept]{},

		subscribers: lnutils.SyncMap[
			uint64, *fn.EventReceiver[fn.Event]]{},

		subsystemErrChan: make(chan error, 10),

		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}, nil
}

// startSubsystems starts the RFQ subsystems.
func (m *Manager) startSubsystems(ctx context.Context) error {
	var err error

	// Initialise and start the order handler.
	m.orderHandler, err = NewOrderHandler(OrderHandlerCfg{
		CleanupInterval:  CacheCleanupInterval,
		HtlcInterceptor:  m.cfg.HtlcInterceptor,
		AcceptHtlcEvents: m.acceptHtlcEvents,
	})
	if err != nil {
		return fmt.Errorf("error initializing RFQ order handler: %w",
			err)
	}

	if err := m.orderHandler.Start(); err != nil {
		return fmt.Errorf("unable to start RFQ order handler: %w", err)
	}

	// Initialise and start the peer message stream handler.
	m.streamHandler, err = NewStreamHandler(
		ctx, StreamHandlerCfg{
			PeerMessenger:    m.cfg.PeerMessenger,
			IncomingMessages: m.incomingMessages,
		},
	)
	if err != nil {
		return fmt.Errorf("error initializing RFQ subsystem service: "+
			"peer message stream handler: %w", err)
	}

	if err := m.streamHandler.Start(); err != nil {
		return fmt.Errorf("unable to start RFQ subsystem service: "+
			"peer message stream handler: %w", err)
	}

	// Initialise and start the quote negotiator.
	m.negotiator, err = NewNegotiator(
		NegotiatorCfg{
			PriceOracle:      m.cfg.PriceOracle,
			OutgoingMessages: m.outgoingMessages,
			ErrChan:          m.subsystemErrChan,
		},
	)
	if err != nil {
		return fmt.Errorf("error initializing RFQ negotiator: %w",
			err)
	}

	if err := m.negotiator.Start(); err != nil {
		return fmt.Errorf("unable to start RFQ negotiator: %w", err)
	}

	return err
}

// Start attempts to start a new RFQ manager.
func (m *Manager) Start() error {
	var startErr error
	m.startOnce.Do(func() {
		ctx, cancel := m.WithCtxQuitNoTimeout()

		log.Info("Initializing RFQ subsystems")
		err := m.startSubsystems(ctx)
		if err != nil {
			startErr = err
			return
		}

		// Start the manager's main event loop in a separate goroutine.
		m.Wg.Add(1)
		go func() {
			defer func() {
				m.Wg.Done()

				// Attempt to stop all subsystems if the main
				// event loop exits.
				err = m.stopSubsystems()
				if err != nil {
					log.Errorf("Error stopping RFQ "+
						"subsystems: %v", err)
				}

				// The context can now be cancelled as all
				// dependant components have been stopped.
				cancel()
			}()

			log.Info("Starting RFQ manager main event loop")
			m.mainEventLoop()
		}()
	})
	return startErr
}

// Stop attempts to stop the RFQ manager.
func (m *Manager) Stop() error {
	var stopErr error

	m.stopOnce.Do(func() {
		log.Info("Stopping RFQ system")
		stopErr = m.stopSubsystems()

		// Stop the main event loop.
		close(m.Quit)
	})

	return stopErr
}

// stopSubsystems stops the RFQ subsystems.
func (m *Manager) stopSubsystems() error {
	// Stop the RFQ order handler.
	err := m.orderHandler.Stop()
	if err != nil {
		return fmt.Errorf("error stopping RFQ order handler: %w", err)
	}

	// Stop the RFQ stream handler.
	err = m.streamHandler.Stop()
	if err != nil {
		return fmt.Errorf("error stopping RFQ stream handler: %w", err)
	}

	// Stop the RFQ quote negotiator.
	err = m.negotiator.Stop()
	if err != nil {
		return fmt.Errorf("error stopping RFQ quote negotiator: %w",
			err)
	}

	return nil
}

// handleIncomingMessage handles an incoming message. These are messages that
// have been received from a peer.
func (m *Manager) handleIncomingMessage(incomingMsg rfqmsg.IncomingMsg) error {
	// Perform type specific handling of the incoming message.
	switch msg := incomingMsg.(type) {
	case *rfqmsg.BuyRequest:
		err := m.negotiator.HandleIncomingBuyRequest(*msg)
		if err != nil {
			return fmt.Errorf("error handling incoming buy "+
				"request: %w", err)
		}

	case *rfqmsg.BuyAccept:
		// TODO(ffranr): The stream handler should ensure that the
		//  accept message corresponds to a request.
		//
		// The quote request has been accepted. Store accepted quote
		// so that it can be used to send a payment by our lightning
		// node.
		scid := SerialisedScid(msg.ShortChannelId())
		m.peerAcceptedQuotes.Store(scid, *msg)

		// Notify subscribers of the incoming quote accept.
		event := NewIncomingAcceptQuoteEvent(msg)
		m.publishSubscriberEvent(event)

	case *rfqmsg.Reject:
		// The quote request has been rejected. Notify subscribers of
		// the rejection.
		event := NewIncomingRejectQuoteEvent(msg)
		m.publishSubscriberEvent(event)

	default:
		return fmt.Errorf("unhandled incoming message type: %T", msg)
	}

	return nil
}

// handleOutgoingMessage handles an outgoing message. Outgoing messages are
// messages that will be sent to a peer.
func (m *Manager) handleOutgoingMessage(outgoingMsg rfqmsg.OutgoingMsg) error {
	// Perform type specific handling of the outgoing message.
	msg, ok := outgoingMsg.(*rfqmsg.BuyAccept)
	if ok {
		// Before sending an accept message to a peer, inform the HTLC
		// order handler that we've accepted the quote request.
		m.orderHandler.RegisterAssetSalePolicy(*msg)
	}

	// Send the outgoing message to the peer.
	err := m.streamHandler.HandleOutgoingMessage(outgoingMsg)
	if err != nil {
		return fmt.Errorf("error sending outgoing message to stream "+
			"handler: %w", err)
	}

	return nil
}

// mainEventLoop is the main event loop of the RFQ manager.
func (m *Manager) mainEventLoop() {
	for {
		select {
		// Handle incoming message.
		case incomingMsg := <-m.incomingMessages:
			log.Debugf("Manager handling incoming message: %s",
				incomingMsg)

			err := m.handleIncomingMessage(incomingMsg)
			if err != nil {
				m.cfg.ErrChan <- fmt.Errorf("failed to "+
					"handle incoming message: %w", err)
			}

		// Handle outgoing message.
		case outgoingMsg := <-m.outgoingMessages:
			log.Debugf("Manager handling outgoing message: %s",
				outgoingMsg)

			err := m.handleOutgoingMessage(outgoingMsg)
			if err != nil {
				m.cfg.ErrChan <- fmt.Errorf("failed to "+
					"handle outgoing message: %w", err)
			}

		case acceptHtlcEvent := <-m.acceptHtlcEvents:
			// Handle a HTLC accept event. Notify any subscribers.
			m.publishSubscriberEvent(acceptHtlcEvent)

		// Handle subsystem errors.
		case err := <-m.subsystemErrChan:
			// Report the subsystem error to the main server.
			m.cfg.ErrChan <- fmt.Errorf("encountered RFQ "+
				"subsystem error: %w", err)

		case <-m.Quit:
			log.Debug("Manager main event loop has received the " +
				"shutdown signal")
			return
		}
	}
}

// UpsertAssetSellOffer upserts an asset sell offer for management by the RFQ
// system. If the offer already exists for the given asset, it will be updated.
func (m *Manager) UpsertAssetSellOffer(offer SellOffer) error {
	// Store the asset sell offer in the negotiator.
	err := m.negotiator.UpsertAssetSellOffer(offer)
	if err != nil {
		return fmt.Errorf("error registering asset sell offer: %w", err)
	}

	return nil
}

// RemoveAssetSellOffer removes an asset sell offer from the RFQ manager.
func (m *Manager) RemoveAssetSellOffer(assetID *asset.ID,
	assetGroupKey *btcec.PublicKey) error {

	// Remove the asset sell offer from the negotiator.
	err := m.negotiator.RemoveAssetSellOffer(assetID, assetGroupKey)
	if err != nil {
		return fmt.Errorf("error removing asset sell offer: %w", err)
	}

	return nil
}

// BuyOrder is a struct that represents a buy order.
type BuyOrder struct {
	// AssetID is the ID of the asset that the buyer is interested in.
	AssetID *asset.ID

	// AssetGroupKey is the public key of the asset group that the buyer is
	// interested in.
	AssetGroupKey *btcec.PublicKey

	// MinAssetAmount is the minimum amount of the asset that the buyer is
	// willing to accept.
	MinAssetAmount uint64

	// MaxBid is the maximum bid price that the buyer is willing to pay.
	MaxBid lnwire.MilliSatoshi

	// Expiry is the unix timestamp at which the buy order expires.
	Expiry uint64

	// Peer is the peer that the buy order is intended for. This field is
	// optional.
	Peer *route.Vertex
}

// UpsertAssetBuyOrder upserts an asset buy order for management.
func (m *Manager) UpsertAssetBuyOrder(order BuyOrder) error {
	// For now, a peer must be specified.
	//
	// TODO(ffranr): Add support for peerless buy orders. The negotiator
	//  should be able to determine the optimal peer.
	if order.Peer == nil {
		return fmt.Errorf("buy order peer must be specified")
	}

	// Request a quote from a peer via the negotiator.
	err := m.negotiator.HandleOutgoingBuyOrder(order)
	if err != nil {
		return fmt.Errorf("error registering asset buy order: %w", err)
	}

	return nil
}

// QueryAcceptedQuotes returns a map of accepted quotes that have been
// registered with the RFQ manager.
func (m *Manager) QueryAcceptedQuotes() map[SerialisedScid]rfqmsg.BuyAccept {
	// Returning the map directly is not thread safe. We will therefore
	// create a copy.
	quotesCopy := make(map[SerialisedScid]rfqmsg.BuyAccept)

	m.peerAcceptedQuotes.ForEach(
		func(scid SerialisedScid, accept rfqmsg.BuyAccept) error {
			if time.Now().Unix() > int64(accept.Expiry) {
				m.peerAcceptedQuotes.Delete(scid)
				return nil
			}

			quotesCopy[scid] = accept
			return nil
		},
	)

	return quotesCopy
}

// RegisterSubscriber adds a new subscriber to the set of subscribers that will
// be notified of any new events that are broadcast.
//
// TODO(ffranr): Add support for delivering existing events to new subscribers.
func (m *Manager) RegisterSubscriber(
	receiver *fn.EventReceiver[fn.Event],
	deliverExisting bool, deliverFrom uint64) error {

	m.subscribers.Store(receiver.ID(), receiver)
	return nil
}

// RemoveSubscriber removes a subscriber from the set of subscribers that will
// be notified of any new events that are broadcast.
func (m *Manager) RemoveSubscriber(
	subscriber *fn.EventReceiver[fn.Event]) error {

	_, ok := m.subscribers.Load(subscriber.ID())
	if !ok {
		return fmt.Errorf("subscriber with ID %d not found",
			subscriber.ID())
	}

	subscriber.Stop()
	m.subscribers.Delete(subscriber.ID())

	return nil
}

// publishSubscriberEvent publishes an event to all subscribers.
func (m *Manager) publishSubscriberEvent(event fn.Event) {
	// Iterate over the subscribers and deliver the event to each one.
	m.subscribers.Range(
		func(id uint64, sub *fn.EventReceiver[fn.Event]) bool {
			sub.NewItemCreated.ChanIn() <- event
			return true
		},
	)
}

// IncomingAcceptQuoteEvent is an event that is broadcast when the RFQ manager
// receives an accept quote message from a peer.
type IncomingAcceptQuoteEvent struct {
	// timestamp is the event creation UTC timestamp.
	timestamp time.Time

	// BuyAccept is the accepted quote.
	rfqmsg.BuyAccept
}

// NewIncomingAcceptQuoteEvent creates a new IncomingAcceptQuoteEvent.
func NewIncomingAcceptQuoteEvent(
	accept *rfqmsg.BuyAccept) *IncomingAcceptQuoteEvent {

	return &IncomingAcceptQuoteEvent{
		timestamp: time.Now().UTC(),
		BuyAccept: *accept,
	}
}

// Timestamp returns the event creation UTC timestamp.
func (q *IncomingAcceptQuoteEvent) Timestamp() time.Time {
	return q.timestamp.UTC()
}

// Ensure that the IncomingAcceptQuoteEvent struct implements the Event
// interface.
var _ fn.Event = (*IncomingAcceptQuoteEvent)(nil)

// IncomingRejectQuoteEvent is an event that is broadcast when the RFQ manager
// receives a reject quote message from a peer.
type IncomingRejectQuoteEvent struct {
	// timestamp is the event creation UTC timestamp.
	timestamp time.Time

	// Reject is the rejected quote.
	rfqmsg.Reject
}

// NewIncomingRejectQuoteEvent creates a new IncomingRejectQuoteEvent.
func NewIncomingRejectQuoteEvent(
	reject *rfqmsg.Reject) *IncomingRejectQuoteEvent {

	return &IncomingRejectQuoteEvent{
		timestamp: time.Now().UTC(),
		Reject:    *reject,
	}
}

// Timestamp returns the event creation UTC timestamp.
func (q *IncomingRejectQuoteEvent) Timestamp() time.Time {
	return q.timestamp.UTC()
}

// Ensure that the IncomingRejectQuoteEvent struct implements the Event
// interface.
var _ fn.Event = (*IncomingRejectQuoteEvent)(nil)

// AcceptHtlcEvent is an event that is sent to the accept HTLCs channel when
// an HTLC is accepted.
type AcceptHtlcEvent struct {
	// Timestamp is the unix timestamp at which the HTLC was accepted.
	timestamp uint64

	// Htlc is the intercepted HTLC.
	Htlc lndclient.InterceptedHtlc

	// ChannelRemit is the channel remit that the HTLC complies with.
	ChannelRemit ChannelRemit
}

// NewAcceptHtlcEvent creates a new AcceptedHtlcEvent.
func NewAcceptHtlcEvent(htlc lndclient.InterceptedHtlc,
	channelRemit ChannelRemit) *AcceptHtlcEvent {

	return &AcceptHtlcEvent{
		timestamp:    uint64(time.Now().UTC().Unix()),
		Htlc:         htlc,
		ChannelRemit: channelRemit,
	}
}

// Timestamp returns the event creation UTC timestamp.
func (q *AcceptHtlcEvent) Timestamp() time.Time {
	return time.Unix(int64(q.timestamp), 0).UTC()
}

// Ensure that the AcceptedHtlcEvent struct implements the Event interface.
var _ fn.Event = (*AcceptHtlcEvent)(nil)
