package rfq

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

const (
	// DefaultTimeout is the default timeout used for context operations.
	DefaultTimeout = 30 * time.Second

	// DefaultInvoiceExpiry is the default expiry time for asset invoices.
	// The current value corresponds to 5 minutes.
	DefaultInvoiceExpiry = time.Second * 300

	// CacheCleanupInterval is the interval at which local runtime caches
	// are cleaned up.
	CacheCleanupInterval = 30 * time.Second
)

// ChannelLister is an interface that provides a list of channels that are
// available for routing.
type ChannelLister interface {
	// ListChannels returns a list of channels that are available for
	// routing.
	ListChannels(ctx context.Context) ([]lndclient.ChannelInfo, error)
}

// ScidAliasManager is an interface that can add short channel ID (SCID) aliases
// to the local SCID alias store.
type ScidAliasManager interface {
	// AddLocalAlias adds a database mapping from the passed alias to the
	// passed base SCID.
	AddLocalAlias(ctx context.Context, alias,
		baseScid lnwire.ShortChannelID) error

	// DeleteLocalAlias removes a mapping from the database and the
	// Manager's maps.
	DeleteLocalAlias(ctx context.Context, alias,
		baseScid lnwire.ShortChannelID) error
}

type (
	// BuyAcceptMap is a map of buy accepts, keyed by the serialised SCID.
	BuyAcceptMap map[SerialisedScid]rfqmsg.BuyAccept

	// SellAcceptMap is a map of sell accepts, keyed by the serialised SCID.
	SellAcceptMap map[SerialisedScid]rfqmsg.SellAccept
)

// GroupLookup is an interface that helps us look up a group of an asset based
// on the asset ID.
type GroupLookup interface {
	// QueryAssetGroup fetches the group information of an asset, if it
	// belongs in a group.
	QueryAssetGroup(context.Context, asset.ID) (*asset.AssetGroup, error)
}

// ManagerCfg is a struct that holds the configuration parameters for the RFQ
// manager.
type ManagerCfg struct {
	// PeerMessenger is the peer messenger. This component provides the RFQ
	// manager with the ability to send and receive raw peer messages.
	PeerMessenger PeerMessenger

	// HtlcInterceptor is the HTLC interceptor. This component is used to
	// intercept and accept/reject HTLCs.
	HtlcInterceptor HtlcInterceptor

	// HtlcSubscriber is a subscriber that is used to retrieve live HTLC
	// event updates.
	HtlcSubscriber HtlcSubscriber

	// PriceOracle is the price oracle that the RFQ manager will use to
	// determine whether a quote is accepted or rejected.
	PriceOracle PriceOracle

	// ChannelLister is the channel lister that the RFQ manager will use to
	// determine the available channels for routing.
	ChannelLister ChannelLister

	// GroupLookup is an interface that helps us querry asset groups by
	// asset IDs.
	GroupLookup GroupLookup

	// AliasManager is the SCID alias manager. This component is injected
	// into the manager once lnd and tapd are hooked together.
	AliasManager ScidAliasManager

	// AcceptPriceDeviationPpm is the price deviation in
	// parts per million that is accepted by the RFQ negotiator.
	//
	// Example: 50,000 ppm => price deviation is set to 5% .
	AcceptPriceDeviationPpm uint64

	// SkipAcceptQuotePriceCheck is a flag that, when set, will cause the
	// RFQ negotiator to skip price validation on incoming quote accept
	// messages (this means that the price oracle will not be queried).
	SkipAcceptQuotePriceCheck bool

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

	// peerAcceptedBuyQuotes holds buy quotes for assets that our node has
	// requested and that have been accepted by peer nodes. These quotes are
	// exclusively used by our node for the acquisition of assets, as they
	// represent agreed-upon terms for purchase transactions with our peers.
	peerAcceptedBuyQuotes lnutils.SyncMap[SerialisedScid, rfqmsg.BuyAccept]

	// peerAcceptedSellQuotes holds sell quotes for assets that our node has
	// requested and that have been accepted by peer nodes. These quotes are
	// exclusively used by our node for the sale of assets, as they
	// represent agreed-upon terms for sale transactions with our peers.
	peerAcceptedSellQuotes lnutils.SyncMap[
		SerialisedScid, rfqmsg.SellAccept,
	]

	// localAcceptedBuyQuotes holds buy quotes for assets that our node has
	// accepted and that have been requested by peer nodes. These quotes are
	// exclusively used by our node for the acquisition of assets, as they
	// represent agreed-upon terms for purchase transactions with our peers.
	localAcceptedBuyQuotes lnutils.SyncMap[SerialisedScid, rfqmsg.BuyAccept]

	// localAcceptedSellQuotes holds sell quotes for assets that our node
	// has accepted and that have been requested by peer nodes. These quotes
	// are exclusively used by our node for the sale of assets, as they
	// represent agreed-upon terms for sale transactions with our peers.
	localAcceptedSellQuotes lnutils.SyncMap[
		SerialisedScid, rfqmsg.SellAccept,
	]

	// groupKeyLookupCache is a map that helps us quickly perform an
	// in-memory look up of the group an asset belongs to. Since this
	// information is static and generated during minting, it is not
	// possible for an asset to change groups.
	groupKeyLookupCache lnutils.SyncMap[asset.ID, *btcec.PublicKey]

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
		peerAcceptedBuyQuotes: lnutils.SyncMap[
			SerialisedScid, rfqmsg.BuyAccept]{},
		peerAcceptedSellQuotes: lnutils.SyncMap[
			SerialisedScid, rfqmsg.SellAccept]{},

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
		HtlcSubscriber:   m.cfg.HtlcSubscriber,
		AcceptHtlcEvents: m.acceptHtlcEvents,
		SpecifierChecker: m.AssetMatchesSpecifier,
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
		// nolint: lll
		NegotiatorCfg{
			PriceOracle:               m.cfg.PriceOracle,
			OutgoingMessages:          m.outgoingMessages,
			AcceptPriceDeviationPpm:   m.cfg.AcceptPriceDeviationPpm,
			SkipAcceptQuotePriceCheck: m.cfg.SkipAcceptQuotePriceCheck,
			ErrChan:                   m.subsystemErrChan,
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

// handleError logs an error and sends it to the main server error channel if
// it is a critical error.
func (m *Manager) handleError(err error) {
	log.Errorf("Error in RFQ manager: %v", err)

	// If the error is a critical error, send it to the main server error
	// channel, which will cause the daemon to shut down.
	if fn.ErrorAs[*fn.CriticalError](err) {
		m.cfg.ErrChan <- err
	}
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

		finaliseCallback := func(msg rfqmsg.BuyAccept,
			invalidQuoteEvent fn.Option[InvalidQuoteRespEvent]) {

			// If the quote is invalid, notify subscribers of the
			// invalid quote event and return.
			invalidQuoteEvent.WhenSome(
				func(event InvalidQuoteRespEvent) {
					m.publishSubscriberEvent(&event)
				},
			)

			if invalidQuoteEvent.IsSome() {
				return
			}

			// The quote request has been accepted. Store accepted
			// quote so that it can be used to send a payment by our
			// lightning node.
			scid := msg.ShortChannelId()
			m.peerAcceptedBuyQuotes.Store(scid, msg)

			// Since we're going to buy assets from our peer, we
			// need to make sure we can identify the incoming asset
			// payment by the SCID alias through which it comes in
			// and compare it to the one in the invoice.
			err := m.addScidAlias(
				uint64(msg.ShortChannelId()),
				msg.Request.AssetSpecifier, msg.Peer,
			)
			if err != nil {
				m.handleError(
					fmt.Errorf("error adding local alias: "+
						"%w", err),
				)
				return
			}

			// Notify subscribers of the incoming peer accepted
			// asset buy quote.
			event := NewPeerAcceptedBuyQuoteEvent(&msg)
			m.publishSubscriberEvent(event)
		}

		m.negotiator.HandleIncomingBuyAccept(*msg, finaliseCallback)

	case *rfqmsg.SellRequest:
		err := m.negotiator.HandleIncomingSellRequest(*msg)
		if err != nil {
			return fmt.Errorf("error handling incoming sell "+
				"request: %w", err)
		}

	case *rfqmsg.SellAccept:
		// TODO(ffranr): The stream handler should ensure that the
		//  accept message corresponds to a request.

		finaliseCallback := func(msg rfqmsg.SellAccept,
			invalidQuoteEvent fn.Option[InvalidQuoteRespEvent]) {

			// If the quote is invalid, notify subscribers of the
			// invalid quote event and return.
			invalidQuoteEvent.WhenSome(
				func(event InvalidQuoteRespEvent) {
					m.publishSubscriberEvent(&event)
				},
			)

			if invalidQuoteEvent.IsSome() {
				return
			}

			// The quote request has been accepted. Store accepted
			// quote so that it can be used to send a payment by our
			// lightning node.
			scid := msg.ShortChannelId()
			m.peerAcceptedSellQuotes.Store(scid, msg)

			// Notify subscribers of the incoming peer accepted
			// asset sell quote.
			event := NewPeerAcceptedSellQuoteEvent(&msg)
			m.publishSubscriberEvent(event)
		}

		m.negotiator.HandleIncomingSellAccept(*msg, finaliseCallback)

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
	switch msg := outgoingMsg.(type) {
	case *rfqmsg.BuyAccept:
		// A peer sent us an asset buy quote request in an attempt to
		// buy an asset from us. Having accepted the request, but before
		// we inform our peer of our decision, we inform the order
		// handler that we are willing to sell the asset subject to a
		// sale policy.
		m.orderHandler.RegisterAssetSalePolicy(*msg)

		// We want to store that we accepted the buy quote, in case we
		// need to look it up for a direct peer payment.
		m.localAcceptedBuyQuotes.Store(msg.ShortChannelId(), *msg)

		// Since our peer is going to buy assets from us, we need to
		// make sure we can identify the forwarded asset payment by the
		// outgoing SCID alias within the onion packet.
		err := m.addScidAlias(
			uint64(msg.ShortChannelId()),
			msg.Request.AssetSpecifier, msg.Peer,
		)
		if err != nil {
			return fmt.Errorf("error adding local alias: %w", err)
		}

	case *rfqmsg.SellAccept:
		// A peer sent us an asset sell quote request in an attempt to
		// sell an asset to us. Having accepted the request, but before
		// we inform our peer of our decision, we inform the order
		// handler that we are willing to buy the asset subject to a
		// purchase policy.
		m.orderHandler.RegisterAssetPurchasePolicy(*msg)

		// We want to store that we accepted the sell quote, in case we
		// need to look it up for a direct peer payment.
		m.localAcceptedSellQuotes.Store(msg.ShortChannelId(), *msg)
	}

	// Send the outgoing message to the peer.
	err := m.streamHandler.HandleOutgoingMessage(outgoingMsg)
	if err != nil {
		return fmt.Errorf("error sending outgoing message to stream "+
			"handler: %w", err)
	}

	return nil
}

// addScidAlias adds a SCID alias to the alias manager.
func (m *Manager) addScidAlias(scidAlias uint64, assetSpecifier asset.Specifier,
	peer route.Vertex) error {

	// Retrieve all local channels.
	ctxb := context.Background()
	localChans, err := m.cfg.ChannelLister.ListChannels(ctxb)
	if err != nil {
		// Not being able to call lnd to add the alias is a critical
		// error, which warrants shutting down, as something is wrong.
		return fn.NewCriticalError(
			fmt.Errorf("add alias: error listing local channels: "+
				"%w", err),
		)
	}

	// Filter for channels with the given peer.
	peerChannels := lfn.Filter(
		localChans, func(c lndclient.ChannelInfo) bool {
			return c.PubKeyBytes == peer
		},
	)

	var baseSCID uint64
	for _, localChan := range peerChannels {
		if len(localChan.CustomChannelData) == 0 {
			continue
		}

		var assetData rfqmsg.JsonAssetChannel
		err = json.Unmarshal(localChan.CustomChannelData, &assetData)
		if err != nil {
			log.Warnf("Unable to unmarshal channel asset data: %v",
				err)
			continue
		}

		match, err := m.ChannelCompatible(
			ctxb, assetData, assetSpecifier,
		)
		if err != nil {
			return err
		}

		// TODO(george): Instead of returning the first result,
		// try to pick the best channel for what we're trying to
		// do (receive/send). Binding a baseSCID means we're
		// also binding the asset liquidity on that channel.
		if match {
			baseSCID = localChan.ChannelID
			break
		}
	}

	// As a fallback, if the base SCID is not found and there's only one
	// channel with the target peer, assume that the base SCID corresponds
	// to that channel.
	if baseSCID == 0 && len(peerChannels) == 1 {
		baseSCID = peerChannels[0].ChannelID
	}

	// At this point, if the base SCID is still not found, we return an
	// error. We can't map the SCID alias to a base SCID.
	if baseSCID == 0 {
		return fmt.Errorf("add alias: base SCID not found for %s",
			&assetSpecifier)
	}

	log.Debugf("Adding SCID alias %d for base SCID %d", scidAlias, baseSCID)

	err = m.cfg.AliasManager.AddLocalAlias(
		ctxb, lnwire.NewShortChanIDFromInt(scidAlias),
		lnwire.NewShortChanIDFromInt(baseSCID),
	)
	if err != nil {
		// Not being able to call lnd to add the alias is a critical
		// error, which warrants shutting down, as something is wrong.
		return fn.NewCriticalError(
			fmt.Errorf("add alias: error adding SCID alias to "+
				"lnd alias manager: %w", err),
		)
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
				m.handleError(
					fmt.Errorf("failed to handle "+
						"incoming message: %w", err),
				)
			}

		// Handle outgoing message.
		case outgoingMsg := <-m.outgoingMessages:
			log.Debugf("Manager handling outgoing message: %s",
				outgoingMsg)

			err := m.handleOutgoingMessage(outgoingMsg)
			if err != nil {
				m.handleError(
					fmt.Errorf("failed to handle outgoing "+
						"message: %w", err),
				)
			}

		case acceptHtlcEvent := <-m.acceptHtlcEvents:
			// Handle a HTLC accept event. Notify any subscribers.
			m.publishSubscriberEvent(acceptHtlcEvent)

		// Handle subsystem errors.
		case err := <-m.subsystemErrChan:
			// Report the subsystem error to the main server, in
			// case the root cause is a critical error.
			m.handleError(
				fmt.Errorf("encountered RFQ subsystem error "+
					"in main event loop: %w", err),
			)

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

// UpsertAssetBuyOffer upserts an asset buy offer for management by the RFQ
// system. If the offer already exists for the given asset, it will be updated.
func (m *Manager) UpsertAssetBuyOffer(offer BuyOffer) error {
	// Store the asset buy offer in the negotiator.
	err := m.negotiator.UpsertAssetBuyOffer(offer)
	if err != nil {
		return fmt.Errorf("error registering asset buy offer: %w", err)
	}

	return nil
}

// BuyOrder instructs the RFQ (Request For Quote) system to request a quote from
// one or more peers for the acquisition of an asset.
//
// The normal use of a buy order is as follows:
//  1. Alice, operating a wallet node, wants to receive a Tap asset as payment
//     by issuing a Lightning invoice.
//  2. Alice has an asset channel established with Bob's edge node.
//  3. Before issuing the invoice, Alice needs to agree on an exchange rate with
//     Bob, who will facilitate the asset transfer.
//  4. To obtain the best exchange rate, Alice creates a buy order specifying
//     the desired asset.
//  5. Alice's RFQ subsystem processes the buy order and sends buy requests to
//     relevant peers to find the best rate. In this example, Bob is the only
//     available peer.
//  6. Once Bob provides a satisfactory quote, Alice accepts it.
//  7. Alice issues the Lightning invoice, which Charlie will pay.
//  8. Instead of paying Alice directly, Charlie pays Bob.
//  9. Bob then forwards the agreed amount of the Tap asset to Alice over their
//     asset channel.
type BuyOrder struct {
	// AssetSpecifier is the asset that the buyer is interested in.
	AssetSpecifier asset.Specifier

	// AssetMaxAmt is the maximum amount of the asset that the provider must
	// be willing to offer.
	AssetMaxAmt uint64

	// Expiry is the time at which the order expires.
	Expiry time.Time

	// Peer is the peer that the buy order is intended for. This field is
	// optional.
	//
	// TODO(ffranr): Currently, this field must be specified. In the future,
	//  the negotiator should be able to determine the optimal peer.
	Peer fn.Option[route.Vertex]
}

// UpsertAssetBuyOrder upserts an asset buy order for management.
func (m *Manager) UpsertAssetBuyOrder(order BuyOrder) error {
	// For now, a peer must be specified.
	//
	// TODO(ffranr): Add support for peerless buy orders. The negotiator
	//  should be able to determine the optimal peer.
	if order.Peer.IsNone() {
		return fmt.Errorf("buy order peer must be specified")
	}

	// Request a quote from a peer via the negotiator.
	err := m.negotiator.HandleOutgoingBuyOrder(order)
	if err != nil {
		return fmt.Errorf("error registering asset buy order: %w", err)
	}

	return nil
}

// SellOrder instructs the RFQ (Request For Quote) system to request a quote
// from one or more peers for the disposition of an asset.
//
// Normal usage of a sell order:
//  1. Alice creates a Lightning invoice for Bob to pay.
//  2. Bob wants to pay the invoice using a Tap asset. To do so, Bob pays an
//     edge node with a Tap asset, and the edge node forwards the payment to the
//     network to settle Alice's invoice. Bob submits a SellOrder to his local
//     RFQ service.
//  3. The RFQ service converts the SellOrder into one or more SellRequests.
//     These requests are sent to Charlie (the edge node), who shares a relevant
//     Tap asset channel with Bob and can forward payments to settle Alice's
//     invoice.
//  4. Charlie responds with a quote that satisfies Bob.
//  5. Bob transfers the appropriate Tap asset amount to Charlie via their
//     shared Tap asset channel, and Charlie forwards the corresponding amount
//     to Alice to settle the Lightning invoice.
type SellOrder struct {
	// AssetSpecifier is the asset that the seller is interested in.
	AssetSpecifier asset.Specifier

	// PaymentMaxAmt is the maximum msat amount that the responding peer
	// must agree to pay.
	PaymentMaxAmt lnwire.MilliSatoshi

	// Expiry is the time at which the order expires.
	Expiry time.Time

	// Peer is the peer that the buy order is intended for. This field is
	// optional.
	Peer fn.Option[route.Vertex]
}

// UpsertAssetSellOrder upserts an asset sell order for management.
func (m *Manager) UpsertAssetSellOrder(order SellOrder) error {
	// For now, a peer must be specified.
	//
	// TODO(ffranr): Add support for peerless sell orders. The negotiator
	//  should be able to determine the optimal peer.
	if order.Peer.IsNone() {
		return fmt.Errorf("sell order peer must be specified")
	}

	// Pass the asset sell order to the negotiator which will generate sell
	// request messages to send to peers.
	m.negotiator.HandleOutgoingSellOrder(order)

	return nil
}

// PeerAcceptedBuyQuotes returns buy quotes that were requested by our node and
// have been accepted by our peers. These quotes are exclusively available to
// our node for the acquisition of assets.
func (m *Manager) PeerAcceptedBuyQuotes() BuyAcceptMap {
	// Returning the map directly is not thread safe. We will therefore
	// create a copy.
	buyQuotesCopy := make(map[SerialisedScid]rfqmsg.BuyAccept)
	m.peerAcceptedBuyQuotes.ForEach(
		func(scid SerialisedScid, accept rfqmsg.BuyAccept) error {
			if time.Now().After(accept.AssetRate.Expiry) {
				m.peerAcceptedBuyQuotes.Delete(scid)
				return nil
			}

			buyQuotesCopy[scid] = accept
			return nil
		},
	)

	return buyQuotesCopy
}

// PeerAcceptedSellQuotes returns sell quotes that were requested by our node
// and have been accepted by our peers. These quotes are exclusively available
// to our node for the sale of assets.
func (m *Manager) PeerAcceptedSellQuotes() SellAcceptMap {
	// Returning the map directly is not thread safe. We will therefore
	// create a copy.
	sellQuotesCopy := make(map[SerialisedScid]rfqmsg.SellAccept)
	m.peerAcceptedSellQuotes.ForEach(
		func(scid SerialisedScid, accept rfqmsg.SellAccept) error {
			if time.Now().After(accept.AssetRate.Expiry) {
				m.peerAcceptedSellQuotes.Delete(scid)
				return nil
			}

			sellQuotesCopy[scid] = accept
			return nil
		},
	)

	return sellQuotesCopy
}

// LocalAcceptedBuyQuotes returns buy quotes that were accepted by our node and
// have been requested by our peers. These quotes are exclusively available to
// our node for the acquisition of assets.
func (m *Manager) LocalAcceptedBuyQuotes() BuyAcceptMap {
	// Returning the map directly is not thread safe. We will therefore
	// create a copy.
	buyQuotesCopy := make(map[SerialisedScid]rfqmsg.BuyAccept)
	m.localAcceptedBuyQuotes.ForEach(
		func(scid SerialisedScid, accept rfqmsg.BuyAccept) error {
			if time.Now().After(accept.AssetRate.Expiry) {
				m.localAcceptedBuyQuotes.Delete(scid)
				return nil
			}

			buyQuotesCopy[scid] = accept
			return nil
		},
	)

	return buyQuotesCopy
}

// LocalAcceptedSellQuotes returns sell quotes that were accepted by our node
// and have been requested by our peers. These quotes are exclusively available
// to our node for the sale of assets.
func (m *Manager) LocalAcceptedSellQuotes() SellAcceptMap {
	// Returning the map directly is not thread safe. We will therefore
	// create a copy.
	sellQuotesCopy := make(map[SerialisedScid]rfqmsg.SellAccept)
	m.localAcceptedSellQuotes.ForEach(
		func(scid SerialisedScid, accept rfqmsg.SellAccept) error {
			if time.Now().After(accept.AssetRate.Expiry) {
				m.localAcceptedSellQuotes.Delete(scid)
				return nil
			}

			sellQuotesCopy[scid] = accept
			return nil
		},
	)

	return sellQuotesCopy
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

// getAssetGroupKey retrieves the group key of an asset based on its ID.
func (m *Manager) getAssetGroupKey(ctx context.Context,
	id asset.ID) (fn.Option[btcec.PublicKey], error) {

	// First, see if we have already queried our DB for this ID.
	v, ok := m.groupKeyLookupCache.Load(id)
	if ok {
		return fn.Some(*v), nil
	}

	// Perform the DB query.
	group, err := m.cfg.GroupLookup.QueryAssetGroup(ctx, id)
	if err != nil {
		if errors.Is(err, address.ErrAssetGroupUnknown) {
			return fn.None[btcec.PublicKey](), nil
		}

		return fn.None[btcec.PublicKey](), err
	}

	// If the asset does not belong to a group, return early with no error
	// or response.
	if group == nil || group.GroupKey == nil {
		return fn.None[btcec.PublicKey](), nil
	}

	// Store the result for future calls.
	m.groupKeyLookupCache.Store(id, &group.GroupPubKey)

	return fn.Some(group.GroupPubKey), nil
}

// AssetMatchesSpecifier checks if the provided asset satisfies the provided
// specifier. If the specifier includes a group key, we will check if the asset
// belongs to that group.
func (m *Manager) AssetMatchesSpecifier(ctx context.Context,
	specifier asset.Specifier, id asset.ID) (bool, error) {

	switch {
	case specifier.HasGroupPubKey():
		specifierGK := specifier.UnwrapGroupKeyToPtr()

		// Let's directly check if the ID is equal to the X coordinate
		// of the group key. This is used by the sender to indicate that
		// any asset that belongs to this group may be used.
		groupKeyX := schnorr.SerializePubKey(specifierGK)
		if asset.ID(groupKeyX) == id {
			return true, nil
		}

		// Now let's make an actual query to find this assetID's group,
		// if it exists.
		group, err := m.getAssetGroupKey(ctx, id)
		if err != nil {
			return false, err
		}

		if group.IsNone() {
			return false, nil
		}

		return group.UnwrapToPtr().IsEqual(specifierGK), nil

	case specifier.HasId():
		specifierID := specifier.UnwrapIdToPtr()

		return *specifierID == id, nil

	default:
		return false, fmt.Errorf("specifier is empty")
	}
}

// GetPriceDeviationPpm returns the configured price deviation in ppm that is
// used in rfq negotiations.
func (m *Manager) GetPriceDeviationPpm() uint64 {
	return m.cfg.AcceptPriceDeviationPpm
}

// ChannelCompatible checks a channel's assets against an asset specifier. If
// the specifier is an asset ID, then all assets must be of that specific ID,
// if the specifier is a group key, then all assets in the channel must belong
// to that group.
func (m *Manager) ChannelCompatible(ctx context.Context,
	jsonChannel rfqmsg.JsonAssetChannel, specifier asset.Specifier) (bool,
	error) {

	fundingAssets := jsonChannel.FundingAssets
	for _, chanAsset := range fundingAssets {
		gen := chanAsset.AssetGenesis
		assetIDBytes, err := hex.DecodeString(gen.AssetID)
		if err != nil {
			return false, fmt.Errorf("error decoding asset ID: %w",
				err)
		}

		var assetID asset.ID
		copy(assetID[:], assetIDBytes)

		match, err := m.AssetMatchesSpecifier(ctx, specifier, assetID)
		if err != nil {
			return false, err
		}

		if !match {
			return false, err
		}
	}

	return true, nil
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

// EstimateAssetUnits is a helper function that queries our price oracle to find
// out how many units of an asset are needed to evaluate to the provided amount
// in milli satoshi.
func EstimateAssetUnits(ctx context.Context, oracle PriceOracle,
	specifier asset.Specifier,
	amtMsat lnwire.MilliSatoshi) (uint64, error) {

	oracleRes, err := oracle.QueryBidPrice(
		ctx, specifier, fn.None[uint64](), fn.Some(amtMsat),
		fn.None[rfqmsg.AssetRate](),
	)
	if err != nil {
		return 0, err
	}

	if oracleRes.Err != nil {
		return 0, fmt.Errorf("cannot query oracle: %v",
			oracleRes.Err.Error())
	}

	assetUnits := rfqmath.MilliSatoshiToUnits(
		amtMsat, oracleRes.AssetRate.Rate,
	)

	return assetUnits.ScaleTo(0).ToUint64(), nil
}

// PeerAcceptedBuyQuoteEvent is an event that is broadcast when the RFQ manager
// receives an accept quote message from a peer. This is a quote which was
// requested by our node and has been accepted by a peer.
type PeerAcceptedBuyQuoteEvent struct {
	// timestamp is the event creation UTC timestamp.
	timestamp time.Time

	// BuyAccept is the accepted asset buy quote.
	rfqmsg.BuyAccept
}

// NewPeerAcceptedBuyQuoteEvent creates a new PeerAcceptedBuyQuoteEvent.
func NewPeerAcceptedBuyQuoteEvent(
	buyAccept *rfqmsg.BuyAccept) *PeerAcceptedBuyQuoteEvent {

	return &PeerAcceptedBuyQuoteEvent{
		timestamp: time.Now().UTC(),
		BuyAccept: *buyAccept,
	}
}

// Timestamp returns the event creation UTC timestamp.
func (q *PeerAcceptedBuyQuoteEvent) Timestamp() time.Time {
	return q.timestamp.UTC()
}

// MatchesOrder checks if the sell quote matches the provided order.
func (q *PeerAcceptedBuyQuoteEvent) MatchesOrder(order BuyOrder) bool {
	if q.Request.AssetSpecifier != order.AssetSpecifier {
		return false
	}

	// If the order has no peer, we accept equality just based on the
	// specifier.
	if order.Peer.IsNone() {
		return true
	}

	// If a peer is specified, ensure it matches the event's peer.
	return fn.MapOptionZ(order.Peer, func(vertex route.Vertex) bool {
		return q.Peer == vertex
	})
}

// Ensure that the PeerAcceptedBuyQuoteEvent struct implements the Event
// interface.
var _ fn.Event = (*PeerAcceptedBuyQuoteEvent)(nil)

// QuoteRespStatus is an enumeration of possible quote response statuses.
type QuoteRespStatus uint8

const (
	// InvalidAssetRatesQuoteRespStatus indicates that the asset rates in
	// the quote response is invalid.
	InvalidAssetRatesQuoteRespStatus QuoteRespStatus = 0

	// InvalidExpiryQuoteRespStatus indicates that the expiry in the quote
	// response is invalid.
	InvalidExpiryQuoteRespStatus QuoteRespStatus = 1

	// PriceOracleQueryErrQuoteRespStatus indicates that an error occurred
	// when querying the price oracle whilst evaluating the quote response.
	PriceOracleQueryErrQuoteRespStatus QuoteRespStatus = 2
)

// InvalidQuoteRespEvent is an event that is broadcast when the RFQ manager
// receives an unacceptable quote response message from a peer.
type InvalidQuoteRespEvent struct {
	// timestamp is the event creation UTC timestamp.
	timestamp time.Time

	// QuoteResponse is the quote response received from the peer which was
	// deemed invalid.
	QuoteResponse rfqmsg.QuoteResponse

	// Status is the status of the quote response.
	Status QuoteRespStatus
}

// NewInvalidQuoteRespEvent creates a new InvalidBuyRespEvent.
func NewInvalidQuoteRespEvent(quoteResponse rfqmsg.QuoteResponse,
	status QuoteRespStatus) *InvalidQuoteRespEvent {

	return &InvalidQuoteRespEvent{
		timestamp:     time.Now().UTC(),
		QuoteResponse: quoteResponse,
		Status:        status,
	}
}

// Timestamp returns the event creation UTC timestamp.
func (q *InvalidQuoteRespEvent) Timestamp() time.Time {
	return q.timestamp.UTC()
}

// Ensure that the InvalidQuoteRespEvent struct implements the Event
// interface.
var _ fn.Event = (*InvalidQuoteRespEvent)(nil)

// PeerAcceptedSellQuoteEvent is an event that is broadcast when the RFQ manager
// receives an asset sell request accept quote message from a peer. This is a
// quote which was requested by our node and has been accepted by a peer.
type PeerAcceptedSellQuoteEvent struct {
	// timestamp is the event creation UTC timestamp.
	timestamp time.Time

	// SellAccept is the accepted asset sell quote.
	rfqmsg.SellAccept
}

// NewPeerAcceptedSellQuoteEvent creates a new PeerAcceptedSellQuoteEvent.
func NewPeerAcceptedSellQuoteEvent(
	sellAccept *rfqmsg.SellAccept) *PeerAcceptedSellQuoteEvent {

	return &PeerAcceptedSellQuoteEvent{
		timestamp:  time.Now().UTC(),
		SellAccept: *sellAccept,
	}
}

// Timestamp returns the event creation UTC timestamp.
func (q *PeerAcceptedSellQuoteEvent) Timestamp() time.Time {
	return q.timestamp.UTC()
}

// MatchesOrder checks if the sell quote matches the provided order.
func (q *PeerAcceptedSellQuoteEvent) MatchesOrder(order SellOrder) bool {
	if q.Request.AssetSpecifier != order.AssetSpecifier {
		return false
	}

	// If the order has no peer, we accept equality just based on the
	// specifier.
	if order.Peer.IsNone() {
		return true
	}

	// If a peer is specified, ensure it matches the event's peer.
	return fn.MapOptionZ(order.Peer, func(vertex route.Vertex) bool {
		return q.Peer == vertex
	})
}

// Ensure that the PeerAcceptedSellQuoteEvent struct implements the Event
// interface.
var _ fn.Event = (*PeerAcceptedSellQuoteEvent)(nil)

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

	// Policy is the policy with which the HTLC is compliant.
	Policy Policy
}

// NewAcceptHtlcEvent creates a new AcceptedHtlcEvent.
func NewAcceptHtlcEvent(htlc lndclient.InterceptedHtlc,
	policy Policy) *AcceptHtlcEvent {

	return &AcceptHtlcEvent{
		timestamp: uint64(time.Now().UTC().Unix()),
		Htlc:      htlc,
		Policy:    policy,
	}
}

// Timestamp returns the event creation UTC timestamp.
func (q *AcceptHtlcEvent) Timestamp() time.Time {
	return time.Unix(int64(q.timestamp), 0).UTC()
}

// Ensure that the AcceptedHtlcEvent struct implements the Event interface.
var _ fn.Event = (*AcceptHtlcEvent)(nil)
