package rfq

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

const (
	// minAssetRatesExpiryLifetime is the minimum asset rates expiry
	// lifetime in seconds.
	minAssetRatesExpiryLifetime = 10

	// DefaultAcceptPriceDeviationPpm is the default price deviation in
	// parts per million that is accepted by the RFQ negotiator.
	//
	// NOTE: This value is set to 5% (50,000 ppm).
	DefaultAcceptPriceDeviationPpm = 50_000

	// DefaultPortfolioPilotTimeout is the default timeout imposed when
	// calling into the portfolio pilot.
	DefaultPortfolioPilotTimeout = 20 * time.Second
)

// NegotiatorCfg holds the configuration for the negotiator.
type NegotiatorCfg struct {
	// PriceOracle is the price oracle that the negotiator will use to
	// determine whether a quote is accepted or rejected.
	PriceOracle PriceOracle

	// PortfolioPilot makes financial decisions when evaluating quotes.
	PortfolioPilot PortfolioPilot

	// OutgoingMessages is a channel which is populated with outgoing peer
	// messages. These are messages which are destined to be sent to peers.
	OutgoingMessages chan<- rfqmsg.OutgoingMsg

	// AcceptPriceDeviationPpm specifies the maximum allowable price
	// deviation in parts per million (PPM). This parameter defines the
	// threshold for the price returned by the price oracle service,
	// indicating how much it can deviate from a peer's quote accept price
	// for the node to consider using the accepted quote.
	AcceptPriceDeviationPpm uint64

	// SkipQuoteAcceptVerify is a flag that, if set, will skip the
	// verification process when validating an incoming quote accept
	// message. This is useful for testing purposes.
	SkipQuoteAcceptVerify bool

	// SendPriceHint is a flag that, if set, will send a price hint to the
	// peer when requesting a quote.
	SendPriceHint bool

	// SendPeerId is a flag that, if set, will send the peer ID (public
	// key of the peer) to the price oracle when requesting a price rate.
	SendPeerId bool

	// ErrChan is a channel that is populated with errors by this subsystem.
	ErrChan chan<- error
}

// Negotiator is a struct that handles the negotiation of quotes. It is a RFQ
// subsystem. It determines whether a quote request is accepted or rejected.
type Negotiator struct {
	startOnce sync.Once
	stopOnce  sync.Once

	// cfg holds the configuration parameters for the negotiator.
	cfg NegotiatorCfg

	// assetSellOffers is a map (keyed on asset ID) that holds asset sell
	// offers.
	assetSellOffers lnutils.SyncMap[asset.ID, SellOffer]

	// assetGroupSellOffers is a map (keyed on asset group key) that holds
	// asset sell offers.
	assetGroupSellOffers lnutils.SyncMap[asset.SerializedKey, SellOffer]

	// assetBuyOffers is a map (keyed on asset ID) that holds asset buy
	// offers.
	assetBuyOffers lnutils.SyncMap[asset.ID, BuyOffer]

	// assetGroupBuyOffers is a map (keyed on asset group key) that holds
	// asset buy offers.
	assetGroupBuyOffers lnutils.SyncMap[asset.SerializedKey, BuyOffer]

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewNegotiator creates a new quote negotiator.
func NewNegotiator(cfg NegotiatorCfg) (*Negotiator, error) {
	// If the portfolio pilot is not specified, then we will use the
	// internal portfolio pilot.
	if cfg.PortfolioPilot == nil {
		// nolint: lll
		cfgPortfolioPilot := InternalPortfolioPilotConfig{
			PriceOracle:                 cfg.PriceOracle,
			ForwardPeerIDToOracle:       cfg.SendPeerId,
			AcceptPriceDeviationPpm:     cfg.AcceptPriceDeviationPpm,
			MinAssetRatesExpiryLifetime: minAssetRatesExpiryLifetime,
		}
		portfolioPilot, err := NewInternalPortfolioPilot(
			cfgPortfolioPilot,
		)
		if err != nil {
			return nil, fmt.Errorf("create internal portfolio "+
				"pilot: %w", err)
		}

		cfg.PortfolioPilot = &portfolioPilot
	}

	return &Negotiator{
		cfg: cfg,

		assetSellOffers: lnutils.SyncMap[asset.ID, SellOffer]{},
		assetGroupSellOffers: lnutils.SyncMap[
			asset.SerializedKey, SellOffer]{},

		assetBuyOffers: lnutils.SyncMap[asset.ID, BuyOffer]{},
		assetGroupBuyOffers: lnutils.SyncMap[
			asset.SerializedKey, BuyOffer]{},

		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}, nil
}

// getAssetRateHint queries the portfolio pilot for an asset rate hint based on
// the provided order. Returns None if portfolio pilot is not configured, price
// hints are disabled, or the query fails.
func (n *Negotiator) getAssetRateHint(order Order,
	assetAmount fn.Option[uint64],
	paymentAmt fn.Option[lnwire.MilliSatoshi]) fn.Option[rfqmsg.AssetRate] {

	if !n.cfg.SendPriceHint {
		return fn.None[rfqmsg.AssetRate]()
	}

	assetSpec := order.GetAssetSpecifier()
	if !assetSpec.IsSome() {
		return fn.None[rfqmsg.AssetRate]()
	}

	// Determine the direction based on the order type.
	direction := AssetTransferDirectionFromOrder(order)

	// Determine the appropriate hint intent based on the order type.
	var intent PriceQueryIntent
	switch order.(type) {
	case *SellOrder:
		intent = IntentPayInvoiceHint
	case *BuyOrder:
		intent = IntentRecvPaymentHint
	default:
		// This shouldn't happen since AssetTransferDirectionFromOrder
		// would have already caught unsupported order types.
		log.Warnf("Unknown order type for asset rate hint: %T", order)
		return fn.None[rfqmsg.AssetRate]()
	}

	var peerID fn.Option[route.Vertex]
	if n.cfg.SendPeerId {
		peerID = order.GetPeer()
	}

	// Query the portfolio pilot for a rate.
	ctx, cancel := n.WithCtxQuitNoTimeout()
	defer cancel()

	var oracleMetadata fn.Option[string]
	if order.GetPriceOracleMetadata() != "" {
		oracleMetadata = fn.Some(order.GetPriceOracleMetadata())
	}

	query := AssetRateQuery{
		AssetSpecifier: assetSpec,
		Direction:      direction,
		Intent:         intent,
		AssetAmount:    assetAmount,
		PaymentAmount:  paymentAmt,
		PeerID:         peerID,
		OracleMetadata: oracleMetadata,
		Expiry:         fn.Some(order.GetExpiry()),
	}

	assetRate, err := n.cfg.PortfolioPilot.QueryAssetRates(ctx, query)
	if err != nil {
		// If we fail to query the portfolio pilot for a rate, we
		// will log a warning and continue without a rate since this
		// is not a critical failure.
		log.Warnf("Failed to query rate from portfolio pilot "+
			"for outgoing request: (direction=%s, err=%v)",
			direction.String(), err)
		return fn.None[rfqmsg.AssetRate]()
	}

	return fn.Some(assetRate)
}

// HandleOutgoingBuyOrder handles an outgoing buy order by constructing buy
// requests and passing them to the outgoing messages channel. These requests
// are sent to peers.
func (n *Negotiator) HandleOutgoingBuyOrder(
	buyOrder BuyOrder) (rfqmsg.ID, error) {

	// Whenever this method returns an error we want to notify both the RFQ
	// manager main loop and also the caller. This wrapper delivers the
	// error to the manager (possibly triggering a daemon shutdown if
	// critical) then returns the error.
	finalise := func(err error) (rfqmsg.ID, error) {
		n.cfg.ErrChan <- err
		return rfqmsg.ID{}, err
	}

	// Unwrap the peer from the buy order. For now, we can assume
	// that the peer is always specified.
	peer, err := buyOrder.Peer.UnwrapOrErr(
		fmt.Errorf("buy order peer must be specified"),
	)
	if err != nil {
		return finalise(err)
	}

	// We calculate a proposed buy rate for our peer's consideration.
	assetRateHint := n.getAssetRateHint(
		&buyOrder, fn.Some(buyOrder.AssetMaxAmt),
		fn.None[lnwire.MilliSatoshi](),
	)

	// Construct a new buy request to send to the peer.
	request, err := rfqmsg.NewBuyRequest(
		peer, buyOrder.AssetSpecifier, buyOrder.AssetMaxAmt,
		assetRateHint, buyOrder.PriceOracleMetadata,
	)
	if err != nil {
		err := fmt.Errorf("unable to create buy request "+
			"message: %w", err)
		return finalise(err)
	}

	// Send the response message to the outgoing messages channel.
	var msg rfqmsg.OutgoingMsg = request
	sendSuccess := fn.SendOrQuit(
		n.cfg.OutgoingMessages, msg, n.Quit,
	)
	if !sendSuccess {
		err := fmt.Errorf("negotiator failed to add quote " +
			"request message to the outgoing messages " +
			"channel")

		return finalise(err)
	}

	return request.ID, nil
}

// HandleIncomingQuoteRequest handles an incoming asset buy or sell quote
// request. It runs as a goroutine to avoid blocking the caller. The function
// queries the portfolio pilot to determine whether to accept or reject the
// quote. Based on the pilot's decision, it sends either an accept message with
// an asset rate or a reject message to outgoing messages channel.
func (n *Negotiator) HandleIncomingQuoteRequest(
	request rfqmsg.Request) error {

	// Define a thread safe helper function for adding outgoing message to
	// the outgoing messages channel.
	sendOutgoingMsg := func(msg rfqmsg.OutgoingMsg) {
		sendSuccess := fn.SendOrQuit(
			n.cfg.OutgoingMessages, msg, n.Quit,
		)
		if !sendSuccess {
			err := fmt.Errorf("negotiator failed to add message "+
				"to the outgoing messages channel (msg=%v)",
				msg)
			n.cfg.ErrChan <- err
		}
	}

	// Query the portfolio pilot synchronously using a separate goroutine.
	// The portfolio pilot might be an external service, responses could be
	// delayed.
	n.Goroutine(func() error {
		ctx, cancel := n.WithCtxQuitCustomTimeout(
			DefaultPortfolioPilotTimeout,
		)
		defer cancel()

		resp, err := n.cfg.PortfolioPilot.ResolveRequest(ctx, request)
		if err != nil {
			// Construct an appropriate RejectErr based on
			// the oracle's response, and send it to the
			// peer.
			msg := rfqmsg.NewReject(
				request.MsgPeer(), request.MsgID(),
				customRejectErr(err),
			)
			sendOutgoingMsg(msg)

			return fmt.Errorf("resolve quote request: %w", err)
		}

		if resp.IsReject() {
			resp.WhenReject(func(reason rfqmsg.RejectErr) {
				msg := rfqmsg.NewReject(
					request.MsgPeer(), request.MsgID(),
					reason,
				)
				sendOutgoingMsg(msg)
			})
			return nil
		}

		var acceptErr error
		resp.WhenAccept(func(assetRate rfqmsg.AssetRate) {
			msg, err := rfqmsg.NewQuoteAcceptFromRequest(
				request, assetRate,
			)
			if err != nil {
				acceptErr = fmt.Errorf("create quote accept "+
					"message from request: %w",
					err)
				return
			}

			sendOutgoingMsg(msg)
		})
		if acceptErr != nil {
			return acceptErr
		}

		return nil
	}, func(err error) {
		n.cfg.ErrChan <- err
	})

	return nil
}

// customRejectErr creates a RejectErr with an opaque rejection code and a
// custom message based on an error response from a price oracle.
func customRejectErr(err error) rfqmsg.RejectErr {
	var oracleError *OracleError

	// Check if the error chain contains an OracleError, and return an
	// opaque rejection error if not.
	if !errors.As(err, &oracleError) {
		return rfqmsg.ErrUnknownReject
	}

	switch oracleError.Code {
	// The price oracle has indicated that it doesn't support the asset,
	// so return a rejection error indicating that.
	case UnsupportedAssetOracleErrorCode:
		return rfqmsg.NewRejectErr(oracleError.Msg)

	// The error code is either unspecified or unknown, so return an
	// opaque rejection error.
	default:
		return rfqmsg.ErrUnknownReject
	}
}

// HandleOutgoingSellOrder handles an outgoing sell order by constructing sell
// requests and passing them to the outgoing messages channel. These requests
// are sent to peers.
func (n *Negotiator) HandleOutgoingSellOrder(
	order SellOrder) (rfqmsg.ID, error) {

	// Whenever this method returns an error we want to notify both the RFQ
	// manager main loop and also the caller. This wrapper delivers the
	// error to the manager (possibly triggering a daemon shutdown if
	// critical) then returns the error.
	finalise := func(err error) (rfqmsg.ID, error) {
		n.cfg.ErrChan <- err
		return rfqmsg.ID{}, err
	}

	// Unwrap the peer from the order. For now, we can assume that
	// the peer is always specified.
	peer, err := order.Peer.UnwrapOrErr(
		fmt.Errorf("buy order peer must be specified"),
	)
	if err != nil {
		return finalise(err)
	}

	// We calculate a proposed sell rate for our peer's consideration.
	assetRateHint := n.getAssetRateHint(
		&order, fn.None[uint64](), fn.Some(order.PaymentMaxAmt),
	)

	request, err := rfqmsg.NewSellRequest(
		peer, order.AssetSpecifier, order.PaymentMaxAmt, assetRateHint,
		order.PriceOracleMetadata,
	)

	if err != nil {
		err := fmt.Errorf("unable to create sell request message: %w",
			err)
		return finalise(err)
	}

	// Send the response message to the outgoing messages channel.
	var msg rfqmsg.OutgoingMsg = request
	sendSuccess := fn.SendOrQuit(n.cfg.OutgoingMessages, msg, n.Quit)
	if !sendSuccess {
		err := fmt.Errorf("negotiator failed to add sell request " +
			"message to the outgoing messages channel")
		return finalise(err)
	}

	return request.ID, err
}

// HandleIncomingBuyAccept handles an incoming buy accept message. This method
// is called when a peer accepts a quote request from this node. The method
// delegates validation to the portfolio pilot. Once validation is complete,
// the finalise callback function is called.
func (n *Negotiator) HandleIncomingBuyAccept(msg rfqmsg.BuyAccept,
	finalise func(rfqmsg.BuyAccept, fn.Option[InvalidQuoteRespEvent])) {

	if n.cfg.SkipQuoteAcceptVerify {
		finalise(msg, fn.None[InvalidQuoteRespEvent]())
		return
	}

	// Verify the accepted quote asynchronously in a separate goroutine.
	// This avoids blocking, as the portfolio pilot may be an external
	// service.
	n.Goroutine(func() error {
		ctx, cancel := n.WithCtxQuitCustomTimeout(
			DefaultPortfolioPilotTimeout,
		)
		defer cancel()

		// Use the portfolio pilot to verify the accept quote.
		status, err := n.cfg.PortfolioPilot.VerifyAcceptQuote(
			ctx, &msg,
		)
		if err != nil {
			invalidQuoteRespEvent := NewInvalidQuoteRespEvent(
				&msg, PortfolioPilotErrQuoteRespStatus,
			)
			finalise(
				msg, fn.Some[InvalidQuoteRespEvent](
					*invalidQuoteRespEvent,
				),
			)

			return fmt.Errorf("portfolio pilot verify accept "+
				"quote: %w", err)
		}

		if status == ValidAcceptQuoteRespStatus {
			finalise(msg, fn.None[InvalidQuoteRespEvent]())
			return nil
		}

		invalidQuoteRespEvent := NewInvalidQuoteRespEvent(&msg, status)
		event := fn.Some[InvalidQuoteRespEvent](
			*invalidQuoteRespEvent,
		)
		finalise(msg, event)

		return nil
	}, func(err error) {
		log.Errorf("Error verifying buy accept quote: %v", err)
		n.cfg.ErrChan <- err
	})
}

// HandleIncomingSellAccept handles an incoming sell accept message. This method
// is called when a peer accepts a quote request from this node. The method
// delegates validation to the portfolio pilot. Once validation is complete,
// the finalise callback function is called.
func (n *Negotiator) HandleIncomingSellAccept(msg rfqmsg.SellAccept,
	finalise func(rfqmsg.SellAccept, fn.Option[InvalidQuoteRespEvent])) {

	if n.cfg.SkipQuoteAcceptVerify {
		finalise(msg, fn.None[InvalidQuoteRespEvent]())
		return
	}

	// Verify the accepted quote asynchronously in a separate goroutine.
	// This avoids blocking, as the portfolio pilot may be an external
	// service.
	n.Goroutine(func() error {
		ctx, cancel := n.WithCtxQuitCustomTimeout(
			DefaultPortfolioPilotTimeout,
		)
		defer cancel()

		// Use the portfolio pilot to verify the accept quote.
		status, err := n.cfg.PortfolioPilot.VerifyAcceptQuote(
			ctx, &msg,
		)
		if err != nil {
			invalidQuoteRespEvent := NewInvalidQuoteRespEvent(
				&msg, PortfolioPilotErrQuoteRespStatus,
			)
			event := fn.Some[InvalidQuoteRespEvent](
				*invalidQuoteRespEvent,
			)
			finalise(msg, event)

			return fmt.Errorf("portfolio pilot verify accept "+
				"quote: %w", err)
		}

		if status == ValidAcceptQuoteRespStatus {
			finalise(msg, fn.None[InvalidQuoteRespEvent]())
			return nil
		}

		invalidQuoteRespEvent := NewInvalidQuoteRespEvent(&msg, status)
		event := fn.Some[InvalidQuoteRespEvent](*invalidQuoteRespEvent)
		finalise(msg, event)

		return nil
	}, func(err error) {
		log.Errorf("Error verifying sell accept quote: %v", err)
		n.cfg.ErrChan <- err
	})
}

// SellOffer is a struct that represents an asset sell offer. This
// data structure describes the maximum amount of an asset that is available
// for sale.
//
// A sell offer is passive (unlike a buy order), meaning that it does not
// actively lead to a buy request from a peer. Instead, it is used by the node
// to selectively accept or reject incoming quote requests early before price
// considerations.
type SellOffer struct {
	// AssetID represents the identifier of the subject asset.
	AssetID *asset.ID

	// AssetGroupKey is the public group key of the subject asset.
	AssetGroupKey *btcec.PublicKey

	// MaxUnits is the maximum amount of the asset under offer.
	MaxUnits uint64
}

// Validate validates the asset sell offer.
func (a *SellOffer) Validate() error {
	if a.AssetID == nil && a.AssetGroupKey == nil {
		return fmt.Errorf("asset ID is nil and asset group key is nil")
	}

	if a.AssetID != nil && a.AssetGroupKey != nil {
		return fmt.Errorf("asset ID and asset group key are both set")
	}

	if a.MaxUnits == 0 {
		return fmt.Errorf("max asset amount is zero")
	}

	return nil
}

// UpsertAssetSellOffer upserts an asset sell offer. If the offer already exists
// for the given asset, it will be updated.
func (n *Negotiator) UpsertAssetSellOffer(offer SellOffer) error {
	// Validate the offer.
	err := offer.Validate()
	if err != nil {
		return fmt.Errorf("invalid asset sell offer: %w", err)
	}

	// Store the offer in the appropriate map.
	//
	// If the asset group key is not nil, then we will use it as the key for
	// the offer. Otherwise, we will use the asset ID as the key.
	switch {
	case offer.AssetGroupKey != nil:
		// We will serialize the public key to a fixed size byte array
		// before using it as a map key. This is because functionally
		// identical public keys can have different internal
		// representations. These differences would cause the map to
		// treat them as different keys.
		keyFixedBytes := asset.ToSerialized(offer.AssetGroupKey)
		n.assetGroupSellOffers.Store(keyFixedBytes, offer)

	case offer.AssetID != nil:
		n.assetSellOffers.Store(*offer.AssetID, offer)
	}

	return nil
}

// RemoveAssetSellOffer removes an asset sell offer from the negotiator.
func (n *Negotiator) RemoveAssetSellOffer(assetID *asset.ID,
	assetGroupKey *btcec.PublicKey) error {

	// Remove the offer from the appropriate map.
	//
	// If the asset group key is not nil, then we will use it as the key for
	// the offer. Otherwise, we will use the asset ID as the key.
	switch {
	case assetGroupKey != nil:
		keyFixedBytes := asset.ToSerialized(assetGroupKey)
		n.assetGroupSellOffers.Delete(keyFixedBytes)

	case assetID != nil:
		n.assetSellOffers.Delete(*assetID)

	default:
		return fmt.Errorf("asset ID and asset group key are both nil")
	}

	return nil
}

// BuyOffer is a struct that represents an asset buy offer. This data structure
// describes the maximum amount of an asset that this node is willing to
// purchase.
//
// A buy offer is passive (unlike a buy order), meaning that it does not
// actively lead to a buy request being sent to a peer. Instead, it is used by
// the node to selectively accept or reject incoming asset sell quote requests
// before price is considered.
type BuyOffer struct {
	// AssetID represents the identifier of the subject asset.
	AssetID *asset.ID

	// AssetGroupKey is the public group key of the subject asset.
	AssetGroupKey *btcec.PublicKey

	// MaxUnits is the maximum amount of the asset which this node is
	// willing to purchase.
	MaxUnits uint64
}

// Validate validates the asset buy offer.
func (a *BuyOffer) Validate() error {
	if a.AssetID == nil && a.AssetGroupKey == nil {
		return fmt.Errorf("asset ID is nil and asset group key is nil")
	}

	if a.AssetID != nil && a.AssetGroupKey != nil {
		return fmt.Errorf("asset ID and asset group key are both set")
	}

	if a.MaxUnits == 0 {
		return fmt.Errorf("max asset amount is zero")
	}

	return nil
}

// UpsertAssetBuyOffer upserts an asset buy offer. If the offer already exists
// for the given asset, it will be updated.
func (n *Negotiator) UpsertAssetBuyOffer(offer BuyOffer) error {
	// Validate the offer.
	err := offer.Validate()
	if err != nil {
		return fmt.Errorf("invalid asset buy offer: %w", err)
	}

	// Store the offer in the appropriate map.
	//
	// If the asset group key is not nil, then we will use it as the key for
	// the offer. Otherwise, we will use the asset ID as the key.
	switch {
	case offer.AssetGroupKey != nil:
		// We will serialize the public key to a fixed size byte array
		// before using it as a map key. This is because functionally
		// identical public keys can have different internal
		// representations. These differences would cause the map to
		// treat them as different keys.
		keyFixedBytes := asset.ToSerialized(offer.AssetGroupKey)
		n.assetGroupBuyOffers.Store(keyFixedBytes, offer)

	case offer.AssetID != nil:
		n.assetBuyOffers.Store(*offer.AssetID, offer)
	}

	return nil
}

// Start starts the service.
func (n *Negotiator) Start() error {
	var startErr error
	n.startOnce.Do(func() {
		log.Info("Starting subsystem: negotiator")
	})
	return startErr
}

// Stop stops the handler.
func (n *Negotiator) Stop() error {
	n.stopOnce.Do(func() {
		log.Info("Stopping subsystem: quote negotiator")

		// Stop any active context.
		close(n.Quit)
	})
	return nil
}
