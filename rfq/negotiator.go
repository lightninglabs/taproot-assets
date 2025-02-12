package rfq

import (
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
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
)

// NegotiatorCfg holds the configuration for the negotiator.
type NegotiatorCfg struct {
	// PriceOracle is the price oracle that the negotiator will use to
	// determine whether a quote is accepted or rejected.
	PriceOracle PriceOracle

	// OutgoingMessages is a channel which is populated with outgoing peer
	// messages. These are messages which are destined to be sent to peers.
	OutgoingMessages chan<- rfqmsg.OutgoingMsg

	// AcceptPriceDeviationPpm specifies the maximum allowable price
	// deviation in parts per million (PPM). This parameter defines the
	// threshold for the price returned by the price oracle service,
	// indicating how much it can deviate from a peer's quote accept price
	// for the node to consider using the accepted quote.
	AcceptPriceDeviationPpm uint64

	// SkipAcceptQuotePriceCheck is a flag that, if set, will skip the
	// price check when validating an incoming quote accept message. This is
	// useful for testing purposes.
	SkipAcceptQuotePriceCheck bool

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

// queryBidFromPriceOracle queries the price oracle for a bid price. It returns
// an appropriate outgoing response message which should be sent to the peer.
func (n *Negotiator) queryBidFromPriceOracle(assetSpecifier asset.Specifier,
	assetMaxAmt fn.Option[uint64],
	paymentMaxAmt fn.Option[lnwire.MilliSatoshi],
	assetRateHint fn.Option[rfqmsg.AssetRate]) (*rfqmsg.AssetRate, error) {

	// TODO(ffranr): Optionally accept a peer's proposed ask price as an
	//  arg to this func and pass it to the price oracle. The price oracle
	//  service might be intelligent enough to use the peer's proposed ask
	//  price as a factor when computing the bid price. This argument must
	//  be optional because at some call sites we are initiating a request
	//  and do not have a peer's proposed ask price.

	ctx, cancel := n.WithCtxQuitNoTimeout()
	defer cancel()

	log.Debugf("Querying price oracle for bid price (asset_specifier=%s, "+
		"asset_max_amt=%s, payment_max_amt=%s, asset_rate_hint=%s)",
		assetSpecifier.String(), assetMaxAmt.String(),
		paymentMaxAmt.String(), assetRateHint.String())

	oracleResponse, err := n.cfg.PriceOracle.QueryBidPrice(
		ctx, assetSpecifier, assetMaxAmt, paymentMaxAmt, assetRateHint,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query price oracle for "+
			"bid: %w", err)
	}

	// Now we will check for an error in the response from the price oracle.
	// If present, we will convert it to a string and return it as an error.
	if oracleResponse.Err != nil {
		return nil, fmt.Errorf("failed to query price oracle for "+
			"bid price: %s", oracleResponse.Err)
	}

	// By this point, the price oracle did not return an error or a bid
	// price. We will therefore return an error.
	if oracleResponse.AssetRate.Rate.ToUint64() == 0 {
		return nil, fmt.Errorf("price oracle did not specify a " +
			"bid price")
	}

	// TODO(ffranr): Check that the bid price is reasonable.
	// TODO(ffranr): Ensure that the expiry time is valid and sufficient.

	return &oracleResponse.AssetRate, nil
}

// HandleOutgoingBuyOrder handles an outgoing buy order by constructing buy
// requests and passing them to the outgoing messages channel. These requests
// are sent to peers.
func (n *Negotiator) HandleOutgoingBuyOrder(buyOrder BuyOrder) error {
	// Query the price oracle for a reasonable bid price. We perform this
	// query and response handling in a separate goroutine in case it is a
	// remote service and takes a long time to respond.
	n.Wg.Add(1)
	go func() {
		defer n.Wg.Done()

		// Unwrap the peer from the buy order. For now, we can assume
		// that the peer is always specified.
		peer, err := buyOrder.Peer.UnwrapOrErr(
			fmt.Errorf("buy order peer must be specified"),
		)
		if err != nil {
			n.cfg.ErrChan <- err
		}

		// We calculate a proposed bid price for our peer's
		// consideration. If a price oracle is not specified we will
		// skip this step.
		var assetRateHint fn.Option[rfqmsg.AssetRate]

		if n.cfg.PriceOracle != nil &&
			buyOrder.AssetSpecifier.IsSome() {

			// Query the price oracle for a bid price.
			//
			// TODO(ffranr): Pass the BuyOrder expiry to the price
			//  oracle at this point.
			assetRate, err := n.queryBidFromPriceOracle(
				buyOrder.AssetSpecifier,
				fn.Some(buyOrder.AssetMaxAmt),
				fn.None[lnwire.MilliSatoshi](),
				fn.None[rfqmsg.AssetRate](),
			)
			if err != nil {
				// If we fail to query the price oracle for a
				// bid price, we will log a warning and continue
				// without a bid price.
				log.Warnf("failed to query bid price from "+
					"price oracle for outgoing buy "+
					"request: %v", err)
			}

			assetRateHint = fn.MaybeSome[rfqmsg.AssetRate](
				assetRate,
			)
		}

		// Construct a new buy request to send to the peer.
		request, err := rfqmsg.NewBuyRequest(
			peer, buyOrder.AssetSpecifier,
			buyOrder.AssetMaxAmt, assetRateHint,
		)
		if err != nil {
			err := fmt.Errorf("unable to create buy request "+
				"message: %w", err)
			n.cfg.ErrChan <- err
			return
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
			n.cfg.ErrChan <- err
			return
		}
	}()

	return nil
}

// queryAskFromPriceOracle queries the price oracle for an asking price. It
// returns an appropriate outgoing response message which should be sent to the
// peer.
func (n *Negotiator) queryAskFromPriceOracle(assetSpecifier asset.Specifier,
	assetMaxAmt fn.Option[uint64],
	paymentMaxAmt fn.Option[lnwire.MilliSatoshi],
	assetRateHint fn.Option[rfqmsg.AssetRate]) (*rfqmsg.AssetRate, error) {

	// Query the price oracle for an asking price.
	ctx, cancel := n.WithCtxQuitNoTimeout()
	defer cancel()

	log.Debugf("Querying price oracle for ask price (asset_specifier=%s, "+
		"asset_max_amt=%s, payment_max_amt=%s, asset_rate_hint=%s)",
		assetSpecifier.String(), assetMaxAmt.String(),
		paymentMaxAmt.String(), assetRateHint.String())

	oracleResponse, err := n.cfg.PriceOracle.QueryAskPrice(
		ctx, assetSpecifier, assetMaxAmt, paymentMaxAmt,
		assetRateHint,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query price oracle for "+
			"ask price: %w", err)
	}

	// Now we will check for an error in the response from the price oracle.
	// If present, we will convert it to a string and return it as an error.
	if oracleResponse.Err != nil {
		return nil, fmt.Errorf("failed to query price oracle for "+
			"ask price: %s", oracleResponse.Err)
	}

	// By this point, the price oracle did not return an error or an asking
	// price. We will therefore return an error.
	if oracleResponse.AssetRate.Rate.Coefficient.ToUint64() == 0 {
		return nil, fmt.Errorf("price oracle did not specify an " +
			"asset to BTC rate")
	}

	// TODO(ffranr): Check that the asking price is reasonable.
	// TODO(ffranr): Ensure that the expiry time is valid and sufficient.

	return &oracleResponse.AssetRate, nil
}

// HandleIncomingBuyRequest handles an incoming asset buy quote request.
func (n *Negotiator) HandleIncomingBuyRequest(
	request rfqmsg.BuyRequest) error {

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

	// Reject the quote request if a price oracle is unavailable.
	if n.cfg.PriceOracle == nil {
		msg := rfqmsg.NewReject(
			request.Peer, request.ID,
			rfqmsg.ErrPriceOracleUnavailable,
		)
		go sendOutgoingMsg(msg)
		return nil
	}

	// Ensure that we have a suitable sell offer for the asset that is being
	// requested. Here we can handle the case where this node does not wish
	// to sell a particular asset.
	offerAvailable := n.HasAssetSellOffer(
		request.AssetSpecifier, request.AssetMaxAmt,
	)
	if !offerAvailable {
		log.Infof("Would reject buy request: no suitable buy offer, " +
			"but ignoring for now")

		// TODO(ffranr): Re-enable pre-price oracle rejection (i.e.
		//  reject on missing offer)

		// If we do not have a suitable sell offer, then we will reject
		// the quote request with an error.
		// reject := rfqmsg.NewReject(
		//	request.Peer, request.ID,
		//	rfqmsg.ErrNoSuitableSellOffer,
		// )
		// go sendOutgoingMsg(reject)
		//
		// return nil
	}

	// Query the price oracle asynchronously using a separate goroutine.
	// The price oracle might be an external service, responses could be
	// delayed.
	n.Wg.Add(1)
	go func() {
		defer n.Wg.Done()

		// Query the price oracle for an asking price.
		assetRate, err := n.queryAskFromPriceOracle(
			request.AssetSpecifier,
			fn.Some(request.AssetMaxAmt),
			fn.None[lnwire.MilliSatoshi](),
			request.AssetRateHint,
		)
		if err != nil {
			// Send a reject message to the peer.
			msg := rfqmsg.NewReject(
				request.Peer, request.ID,
				rfqmsg.ErrUnknownReject,
			)
			sendOutgoingMsg(msg)

			// Add an error to the error channel and return.
			err = fmt.Errorf("failed to query ask price from "+
				"oracle: %w", err)
			n.cfg.ErrChan <- err
			return
		}

		// Construct and send a buy accept message.
		msg := rfqmsg.NewBuyAcceptFromRequest(request, *assetRate)
		sendOutgoingMsg(msg)
	}()

	return nil
}

// HandleIncomingSellRequest handles an incoming asset sell quote request.
// This is a request by our peer to sell an asset to us.
func (n *Negotiator) HandleIncomingSellRequest(
	request rfqmsg.SellRequest) error {

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

	// Reject the quote request if a price oracle is unavailable.
	if n.cfg.PriceOracle == nil {
		msg := rfqmsg.NewReject(
			request.Peer, request.ID,
			rfqmsg.ErrPriceOracleUnavailable,
		)
		go sendOutgoingMsg(msg)
		return nil
	}

	// The sell request is attempting to sell some amount of an asset to our
	// node. Here we ensure that we have a suitable buy offer for the asset.
	// A buy offer is the criteria that this node uses to determine whether
	// it is willing to buy a particular asset (before price is considered).
	// At this point we can handle the case where this node does not wish
	// to buy some amount of a particular asset regardless of its price.
	//
	// TODO(ffranr): Reformulate once BuyOffer fields have been revised.
	offerAvailable := n.HasAssetBuyOffer(
		request.AssetSpecifier, uint64(request.PaymentMaxAmt),
	)
	if !offerAvailable {
		log.Infof("Would reject sell request: no suitable buy offer, " +
			"but ignoring for now")

		// TODO(ffranr): Re-enable pre-price oracle rejection (i.e.
		//  reject on missing offer)

		// If we do not have a suitable buy offer, then we will reject
		// the asset sell quote request with an error.
		// reject := rfqmsg.NewReject(
		//	request.Peer, request.ID,
		//	rfqmsg.ErrNoSuitableBuyOffer,
		// )
		// go sendOutgoingMsg(reject)
		//
		// return nil
	}

	// Query the price oracle asynchronously using a separate goroutine.
	// The price oracle might be an external service, responses could be
	// delayed.
	n.Wg.Add(1)
	go func() {
		defer n.Wg.Done()

		// Query the price oracle for a bid price. This is the price we
		// are willing to pay for the asset that our peer is trying to
		// sell to us.
		assetRate, err := n.queryBidFromPriceOracle(
			request.AssetSpecifier, fn.None[uint64](),
			fn.Some(request.PaymentMaxAmt), request.AssetRateHint,
		)
		if err != nil {
			// Send a reject message to the peer.
			msg := rfqmsg.NewReject(
				request.Peer, request.ID,
				rfqmsg.ErrUnknownReject,
			)
			sendOutgoingMsg(msg)

			// Add an error to the error channel and return.
			err = fmt.Errorf("failed to query bid price from "+
				"oracle: %w", err)
			n.cfg.ErrChan <- err
			return
		}

		// Construct and send a sell accept message.
		msg := rfqmsg.NewSellAcceptFromRequest(request, *assetRate)
		sendOutgoingMsg(msg)
	}()

	return nil
}

// HandleOutgoingSellOrder handles an outgoing sell order by constructing sell
// requests and passing them to the outgoing messages channel. These requests
// are sent to peers.
func (n *Negotiator) HandleOutgoingSellOrder(order SellOrder) {
	// Query the price oracle for a reasonable ask price. We perform this
	// query and response handling in a separate goroutine in case it is a
	// remote service and takes a long time to respond.
	n.Wg.Add(1)
	go func() {
		defer n.Wg.Done()

		// Unwrap the peer from the order. For now, we can assume that
		// the peer is always specified.
		peer, err := order.Peer.UnwrapOrErr(
			fmt.Errorf("buy order peer must be specified"),
		)
		if err != nil {
			n.cfg.ErrChan <- err
		}

		// We calculate a proposed ask price for our peer's
		// consideration. If a price oracle is not specified we will
		// skip this step.
		var assetRateHint fn.Option[rfqmsg.AssetRate]

		if n.cfg.PriceOracle != nil && order.AssetSpecifier.IsSome() {
			// Query the price oracle for an asking price.
			//
			// TODO(ffranr): Pass the SellOrder expiry to the
			//  price oracle at this point.
			assetRate, err := n.queryAskFromPriceOracle(
				order.AssetSpecifier, fn.None[uint64](),
				fn.Some(order.PaymentMaxAmt),
				fn.None[rfqmsg.AssetRate](),
			)
			if err != nil {
				err := fmt.Errorf("negotiator failed to "+
					"handle price oracle response: %w", err)
				n.cfg.ErrChan <- err
				return
			}

			assetRateHint = fn.MaybeSome(assetRate)
		}

		request, err := rfqmsg.NewSellRequest(
			peer, order.AssetSpecifier, order.PaymentMaxAmt,
			assetRateHint,
		)
		if err != nil {
			err := fmt.Errorf("unable to create sell request "+
				"message: %w", err)
			n.cfg.ErrChan <- err
			return
		}

		// Send the response message to the outgoing messages channel.
		var msg rfqmsg.OutgoingMsg = request
		sendSuccess := fn.SendOrQuit(
			n.cfg.OutgoingMessages, msg, n.Quit,
		)
		if !sendSuccess {
			err := fmt.Errorf("negotiator failed to add sell " +
				"request message to the outgoing messages " +
				"channel")
			n.cfg.ErrChan <- err
			return
		}
	}()
}

// expiryWithinBounds checks if a quote expiry unix timestamp (in seconds) is
// within acceptable bounds. This check ensures that the expiry timestamp is far
// enough in the future for the quote to be useful.
func expiryWithinBounds(expiry time.Time, minExpiryLifetime uint64) bool {
	diff := expiry.Unix() - time.Now().Unix()
	return diff >= int64(minExpiryLifetime)
}

// HandleIncomingBuyAccept handles an incoming buy accept message. This method
// is called when a peer accepts a quote request from this node. The method
// checks the price and expiry time of the quote accept message. Once validation
// is complete, the finalise callback function is called.
func (n *Negotiator) HandleIncomingBuyAccept(msg rfqmsg.BuyAccept,
	finalise func(rfqmsg.BuyAccept, fn.Option[InvalidQuoteRespEvent])) {

	// Ensure that the quote expiry time is within acceptable bounds.
	//
	// TODO(ffranr): Sanity check the buy accept quote expiry
	//  timestamp given the expiry timestamp in our outgoing buy request.
	//  The expiry timestamp in the outgoing request relates to the lifetime
	//  of the lightning invoice.
	if !expiryWithinBounds(
		msg.AssetRate.Expiry, minAssetRatesExpiryLifetime,
	) {
		// The expiry time is not within the acceptable bounds.
		log.Debugf("Buy accept quote expiry time is not within "+
			"acceptable bounds (asset_rate=%s)",
			msg.AssetRate.String())

		// Construct an invalid quote response event so that we can
		// inform the peer that the quote response has not validated
		// successfully.
		invalidQuoteRespEvent := NewInvalidQuoteRespEvent(
			&msg, InvalidExpiryQuoteRespStatus,
		)
		finalise(
			msg, fn.Some[InvalidQuoteRespEvent](
				*invalidQuoteRespEvent,
			),
		)

		return
	}

	if n.cfg.SkipAcceptQuotePriceCheck {
		// Skip the price check.
		finalise(msg, fn.None[InvalidQuoteRespEvent]())
		return
	}

	// Reject the quote response if a price oracle is unavailable.
	if n.cfg.PriceOracle == nil {
		invalidQuoteRespEvent := NewInvalidQuoteRespEvent(
			&msg, PriceOracleQueryErrQuoteRespStatus,
		)
		finalise(msg, fn.Some[InvalidQuoteRespEvent](
			*invalidQuoteRespEvent,
		))
		return
	}

	// Query the price oracle asynchronously using a separate goroutine.
	n.Wg.Add(1)
	go func() {
		defer n.Wg.Done()

		// The buy accept message includes an ask price, which
		// represents the amount the peer is willing to accept for the
		// asset we are purchasing.
		//
		// To validate this ask, we will query our price oracle for a
		// bid price and compare it with the peer's asking price. If the
		// two prices fall within an acceptable tolerance, we will
		// approve the quote.
		//
		// When querying the price oracle, we will provide the peer's
		// ask price as a hint. The oracle may factor this into its
		// calculations to generate a more relevant bid price.
		assetRate, err := n.queryBidFromPriceOracle(
			msg.Request.AssetSpecifier,
			fn.Some(msg.Request.AssetMaxAmt),
			fn.None[lnwire.MilliSatoshi](), fn.Some(msg.AssetRate),
		)
		if err != nil {
			// The price oracle returned an error. We will return
			// without calling the quote accept callback.
			err = fmt.Errorf("negotiator failed to query price "+
				"oracle when handling incoming buy accept "+
				"message: %w", err)
			log.Errorf("Error calling price oracle: %v", err)
			n.cfg.ErrChan <- err

			// Construct an invalid quote response event so that we
			// can inform the peer that the quote response has not
			// validated successfully.
			invalidQuoteRespEvent := NewInvalidQuoteRespEvent(
				&msg, PriceOracleQueryErrQuoteRespStatus,
			)
			finalise(
				msg, fn.Some[InvalidQuoteRespEvent](
					*invalidQuoteRespEvent,
				),
			)

			return
		}

		// The price returned by the oracle may not always align with
		// our specific interests, depending on the oracle's pricing
		// methodology. In other words, it may provide a general market
		// price rather than one optimized for our needs.
		//
		// To account for this, we allow some tolerance in price
		// deviation, ensuring that we can accept a reasonable range of
		// prices while maintaining flexibility.
		tolerance := rfqmath.NewBigIntFromUint64(
			n.cfg.AcceptPriceDeviationPpm,
		)
		acceptablePrice, err := msg.AssetRate.Rate.WithinTolerance(
			assetRate.Rate, tolerance,
		)
		if err != nil {
			// The tolerance check failed. We will return without
			// calling the quote accept callback.
			err = fmt.Errorf("failed to check tolerance: %w", err)
			log.Errorf("Error checking tolerance: %v", err)

			// Construct an invalid quote response event so that we
			// can inform the peer that the quote response has not
			// validated successfully.
			invalidQuoteRespEvent := NewInvalidQuoteRespEvent(
				&msg, InvalidAssetRatesQuoteRespStatus,
			)
			finalise(
				msg, fn.Some[InvalidQuoteRespEvent](
					*invalidQuoteRespEvent,
				),
			)

			return
		}

		if !acceptablePrice {
			// The price is not within the acceptable tolerance.
			// We will return without calling the quote accept
			// callback.
			log.Debugf("Buy accept price is not within "+
				"acceptable bounds (peer_asset_rate=%s, "+
				"oracle_asset_rate=%s)", msg.AssetRate.String(),
				assetRate.String())

			// Construct an invalid quote response event so that we
			// can inform the peer that the quote response has not
			// validated successfully.
			invalidQuoteRespEvent := NewInvalidQuoteRespEvent(
				&msg, InvalidAssetRatesQuoteRespStatus,
			)
			finalise(
				msg, fn.Some[InvalidQuoteRespEvent](
					*invalidQuoteRespEvent,
				),
			)

			return
		}

		finalise(msg, fn.None[InvalidQuoteRespEvent]())
	}()
}

// HandleIncomingSellAccept handles an incoming sell accept message. This method
// is called when a peer accepts a quote request from this node. The method
// checks the price and expiry time of the quote accept message. Once validation
// is complete, the finalise callback function is called.
func (n *Negotiator) HandleIncomingSellAccept(msg rfqmsg.SellAccept,
	finalise func(rfqmsg.SellAccept, fn.Option[InvalidQuoteRespEvent])) {

	// Ensure that the quote expiry time is within acceptable bounds.
	//
	// TODO(ffranr): Sanity check the quote expiry timestamp given
	//  the expiry timestamp provided by the price oracle.
	if !expiryWithinBounds(
		msg.AssetRate.Expiry, minAssetRatesExpiryLifetime,
	) {
		// The expiry time is not within the acceptable bounds.
		log.Debugf("Sell accept quote expiry time is not within "+
			"acceptable bounds (asset_rate=%s)",
			msg.AssetRate.String())

		// Construct an invalid quote response event so that we can
		// inform the peer that the quote response has not validated
		// successfully.
		invalidQuoteRespEvent := NewInvalidQuoteRespEvent(
			&msg, InvalidExpiryQuoteRespStatus,
		)
		finalise(
			msg, fn.Some[InvalidQuoteRespEvent](
				*invalidQuoteRespEvent,
			),
		)

		return
	}

	if n.cfg.SkipAcceptQuotePriceCheck {
		// Skip the price check.
		finalise(msg, fn.None[InvalidQuoteRespEvent]())
		return
	}

	// Reject the quote response if a price oracle is unavailable.
	if n.cfg.PriceOracle == nil {
		invalidQuoteRespEvent := NewInvalidQuoteRespEvent(
			&msg, PriceOracleQueryErrQuoteRespStatus,
		)
		finalise(msg, fn.Some[InvalidQuoteRespEvent](
			*invalidQuoteRespEvent,
		))
		return
	}

	// Query the price oracle asynchronously using a separate goroutine.
	n.ContextGuard.Goroutine(func() error {
		// The sell accept message includes a bid price, which
		// represents the amount the peer is willing to pay for the
		// asset we are selling.
		//
		// To validate this bid, we will query our price oracle for an
		// ask price and compare it with the peer's bid. If the two
		// prices fall within an acceptable tolerance, we will accept
		// the quote.
		//
		// When querying the price oracle, we will provide the peer's
		// bid as a hint. The oracle may incorporate this bid into its
		// calculations to determine a more accurate ask price.
		assetRate, err := n.queryAskFromPriceOracle(
			msg.Request.AssetSpecifier, fn.None[uint64](),
			fn.Some(msg.Request.PaymentMaxAmt),
			fn.Some(msg.AssetRate),
		)
		if err != nil {
			// The price oracle returned an error.
			//
			// Construct an invalid quote response event so that we
			// can inform the peer that the quote response has not
			// validated successfully.
			invalidQuoteRespEvent := NewInvalidQuoteRespEvent(
				&msg, PriceOracleQueryErrQuoteRespStatus,
			)
			finalise(
				msg, fn.Some[InvalidQuoteRespEvent](
					*invalidQuoteRespEvent,
				),
			)

			return fmt.Errorf("negotiator failed to query price "+
				"oracle when handling incoming sell accept "+
				"message: %w", err)
		}

		// The price returned by the oracle may not always align with
		// our specific interests, depending on the oracle's pricing
		// methodology. In other words, it may provide a general market
		// price rather than one optimized for our needs.
		//
		// To account for this, we allow some tolerance in price
		// deviation, ensuring that we can accept a reasonable range of
		// prices while maintaining flexibility.
		tolerance := rfqmath.NewBigIntFromUint64(
			n.cfg.AcceptPriceDeviationPpm,
		)
		acceptablePrice, err := msg.AssetRate.Rate.WithinTolerance(
			assetRate.Rate, tolerance,
		)
		if err != nil {
			// The tolerance check failed.
			//
			// Construct an invalid quote response event so that we
			// can inform the peer that the quote response has not
			// validated successfully.
			invalidQuoteRespEvent := NewInvalidQuoteRespEvent(
				&msg, InvalidAssetRatesQuoteRespStatus,
			)
			finalise(
				msg, fn.Some[InvalidQuoteRespEvent](
					*invalidQuoteRespEvent,
				),
			)

			return fmt.Errorf("failed to check tolerance: %w", err)
		}

		if !acceptablePrice {
			// The price is not within the acceptable bounds.
			// We will return without calling the quote accept
			// callback.
			log.Debugf("Sell accept quote price is not within "+
				"acceptable bounds (asset_rate=%v, "+
				"oracle_asset_rate=%v)", msg.AssetRate,
				assetRate)

			// Construct an invalid quote response event so that we
			// can inform the peer that the quote response has not
			// validated successfully.
			invalidQuoteRespEvent := NewInvalidQuoteRespEvent(
				&msg, InvalidAssetRatesQuoteRespStatus,
			)
			finalise(
				msg, fn.Some[InvalidQuoteRespEvent](
					*invalidQuoteRespEvent,
				),
			)

			return nil
		}

		finalise(msg, fn.None[InvalidQuoteRespEvent]())
		return nil
	}, func(err error) {
		log.Errorf("Error checking incoming sell accept asset rate: %v",
			err)

		n.cfg.ErrChan <- err
	})
}

// SellOffer is a struct that represents an asset sell offer. This
// data structure describes the maximum amount of an asset that is available
// for sale.
//
// A sell offer is passive (unlike a buy order), meaning that it does not
// actively lead to a bid request from a peer. Instead, it is used by the node
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

// HasAssetSellOffer returns true if the negotiator has an asset sell offer
// which matches the given asset ID/group and asset amount.
//
// TODO(ffranr): This method should return errors which can be used to
// differentiate between a missing offer and an invalid offer.
func (n *Negotiator) HasAssetSellOffer(assetSpecifier asset.Specifier,
	assetAmt uint64) bool {

	// If the asset group key is not nil, then we will use it as the key for
	// the offer. Otherwise, we will use the asset ID as the key.
	var sellOffer *SellOffer

	assetSpecifier.WhenGroupPubKey(func(assetGroupKey btcec.PublicKey) {
		keyFixedBytes := asset.ToSerialized(&assetGroupKey)
		offer, ok := n.assetGroupSellOffers.Load(keyFixedBytes)
		if !ok {
			// Corresponding offer not found.
			return
		}

		sellOffer = &offer
	})

	assetSpecifier.WhenId(func(assetID asset.ID) {
		offer, ok := n.assetSellOffers.Load(assetID)
		if !ok {
			// Corresponding offer not found.
			return
		}

		sellOffer = &offer
	})

	// We should never have a nil sell offer at this point. Check added here
	// for robustness.
	if sellOffer == nil {
		return false
	}

	// If the asset amount is greater than the maximum asset amount under
	// offer, then we will return false (we do not have a suitable offer).
	if assetAmt > sellOffer.MaxUnits {
		log.Warnf("asset amount is greater than sell offer max units "+
			"(asset_amt=%d, sell_offer_max_units=%d)", assetAmt,
			sellOffer.MaxUnits)
		return false
	}

	return true
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

// HasAssetBuyOffer returns true if the negotiator has an asset buy offer which
// matches the given asset ID/group and asset amount.
//
// TODO(ffranr): This method should return errors which can be used to
// differentiate between a missing offer and an invalid offer.
func (n *Negotiator) HasAssetBuyOffer(assetSpecifier asset.Specifier,
	assetAmt uint64) bool {

	// If the asset group key is not nil, then we will use it as the lookup
	// key to retrieve an offer. Otherwise, we will use the asset ID as the
	// lookup key.
	var buyOffer *BuyOffer

	assetSpecifier.WhenGroupPubKey(func(assetGroupKey btcec.PublicKey) {
		keyFixedBytes := asset.ToSerialized(&assetGroupKey)
		offer, ok := n.assetGroupBuyOffers.Load(keyFixedBytes)
		if !ok {
			// Corresponding offer not found.
			return
		}

		buyOffer = &offer
	})

	assetSpecifier.WhenId(func(assetID asset.ID) {
		offer, ok := n.assetBuyOffers.Load(assetID)
		if !ok {
			// Corresponding offer not found.
			return
		}

		buyOffer = &offer
	})

	// We should never have a nil buy offer at this point. Check added here
	// for robustness.
	if buyOffer == nil {
		return false
	}

	// If the asset amount is greater than the maximum asset amount under
	// offer, then we will return false (we do not have a suitable offer).
	if assetAmt > buyOffer.MaxUnits {
		// At this point, the sell request is asking us to buy more of
		// the asset than we are willing to purchase.
		log.Warnf("asset amount is greater than buy offer max units "+
			"(asset_amt=%d, buy_offer_max_units=%d)", assetAmt,
			buyOffer.MaxUnits)
		return false
	}

	return true
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
