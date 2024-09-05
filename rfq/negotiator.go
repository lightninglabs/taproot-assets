package rfq

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnutils"
)

const (
	// minRateTickExpiryLifetime is the minimum rate tick expiry lifetime in
	// seconds.
	minRateTickExpiryLifetime = 60

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

// queryBuyPriceFromOracle queries the price oracle for a buy price. It returns
// an appropriate price quote that can be included in an outgoing message.
func (n *Negotiator) queryBuyPriceFromOracle(inAssetId *asset.ID,
	inAssetGroupKey *btcec.PublicKey, inAssetMaxAmount uint64,
	suggestedPrice *rfqmsg.PriceQuote) (*rfqmsg.PriceQuote, error) {

	ctx, cancel := n.WithCtxQuitNoTimeout()
	defer cancel()

	oracleResponse, err := n.cfg.PriceOracle.QueryBuyPrice(
		ctx, inAssetId, inAssetGroupKey, inAssetMaxAmount,
		suggestedPrice,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query price oracle for buy "+
			"price: %w", err)
	}

	// Now we will check for an error in the response from the price oracle.
	// If present, we will convert it to a string and return it as an error.
	if oracleResponse.Err != nil {
		return nil, fmt.Errorf("failed to query price oracle for buy "+
			"price: %s", oracleResponse.Err)
	}

	// By this point, the price oracle did not return an error or a buy
	// price. We will therefore return an error.
	if oracleResponse.Price == nil {
		return nil, fmt.Errorf("price oracle did not specify a buy " +
			"price")
	}

	// We expect the price's expiry to be in the future.
	if oracleResponse.Price.Expiry.IsZero() ||
		oracleResponse.Price.Expiry.Before(time.Now()) {

		return nil, fmt.Errorf("price oracle did not specify a valid "+
			"expiry time: %v", oracleResponse.Price.Expiry)
	}

	// TODO(ffranr): Check that the bid price is reasonable.

	return oracleResponse.Price, nil
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

		// We calculate a proposed bid price for our peer's
		// consideration. If a price oracle is not specified we will
		// skip this step.
		var suggestedBuyPrice *rfqmsg.PriceQuote
		if n.cfg.PriceOracle != nil {
			// Query the price oracle for a bid price.
			var err error
			suggestedBuyPrice, err = n.queryBuyPriceFromOracle(
				buyOrder.AssetID, buyOrder.AssetGroupKey,
				buyOrder.MinAssetAmount, nil,
			)
			if err != nil {
				// If we fail to query the price oracle for a
				// bid price, we will log a warning and continue
				// without a bid price.
				log.Warnf("failed to query bid price from "+
					"price oracle for outgoing buy "+
					"request: %v", err)
			}
		}

		request, err := rfqmsg.NewBuyRequest(
			*buyOrder.Peer, time.Unix(int64(buyOrder.Expiry), 0),
			buyOrder.AssetID,
			buyOrder.AssetGroupKey, buyOrder.MinAssetAmount,
			suggestedBuyPrice,
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

// querySellPriceFromOracle queries the price oracle for a sell price. It
// returns an appropriate price quote that can be included in an outgoing
// message.
func (n *Negotiator) querySellPriceFromOracle(outAssetId *asset.ID,
	outAssetGroupKey *btcec.PublicKey, inAssetMaxAmount uint64,
	suggestedPrice *rfqmsg.PriceQuote) (*rfqmsg.PriceQuote, error) {

	// Query the price oracle for an asking price.
	ctx, cancel := n.WithCtxQuitNoTimeout()
	defer cancel()

	oracleResponse, err := n.cfg.PriceOracle.QuerySellPrice(
		ctx, outAssetId, outAssetGroupKey, inAssetMaxAmount,
		suggestedPrice,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query price oracle for sell "+
			"price: %w", err)
	}

	// Now we will check for an error in the response from the price oracle.
	// If present, we will convert it to a string and return it as an error.
	if oracleResponse.Err != nil {
		return nil, fmt.Errorf("failed to query price oracle for sell "+
			"price: %s", oracleResponse.Err)
	}

	// By this point, the price oracle did not return an error or a sell
	// price. We will therefore return an error.
	if oracleResponse.Price == nil {
		return nil, fmt.Errorf("price oracle did not specify a sell " +
			"price")
	}

	// We expect the price's expiry to be in the future.
	if oracleResponse.Price.Expiry.IsZero() ||
		oracleResponse.Price.Expiry.Before(time.Now()) {

		return nil, fmt.Errorf("price oracle did not specify a valid "+
			"expiry time: %v", oracleResponse.Price.Expiry)
	}

	// TODO(ffranr): Check that the asking price is reasonable.

	return oracleResponse.Price, nil
}

// HandleIncomingBuyRequest handles an incoming asset buy quote request.
func (n *Negotiator) HandleIncomingBuyRequest(request rfqmsg.BuyRequest) error {
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
		request.AssetID, request.AssetGroupKey, request.InAssetMaxAmount,
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
		buyPrice, err := n.queryBuyPriceFromOracle(
			request.AssetID, request.AssetGroupKey,
			request.InAssetMaxAmount, request.SuggestedPrice,
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
		msg := rfqmsg.NewBuyAcceptFromRequest(request, *buyPrice)
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
	offerAvailable := n.HasAssetBuyOffer(
		request.AssetID, request.AssetGroupKey,
		request.InAssetMaxAmount,
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

		// TODO(guggero): Set this to the suggested price from the
		// request, once the wire messages are refactored.
		var suggestedPrice *rfqmsg.PriceQuote

		// Query the price oracle for a bid price. This is the price we
		// are willing to pay for the asset that our peer is trying to
		// sell to us.
		sellPrice, err := n.querySellPriceFromOracle(
			request.AssetID, request.AssetGroupKey,
			request.InAssetMaxAmount, suggestedPrice,
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

		// Construct and send a sell accept message.
		msg := rfqmsg.NewSellAcceptFromRequest(request, *sellPrice)
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

		// We calculate a proposed ask price for our peer's
		// consideration. If a price oracle is not specified we will
		// skip this step.
		var suggestedSellPrice *rfqmsg.PriceQuote
		if n.cfg.PriceOracle != nil {
			// Query the price oracle for an asking price.
			var err error
			suggestedSellPrice, err = n.querySellPriceFromOracle(
				order.AssetID, order.AssetGroupKey,
				order.MaxAssetAmount, nil,
			)
			if err != nil {
				err := fmt.Errorf("negotiator failed to "+
					"handle price oracle response: %w", err)
				n.cfg.ErrChan <- err
				return
			}
		}

		request, err := rfqmsg.NewSellRequest(
			*order.Peer, time.Unix(int64(order.Expiry), 0),
			order.AssetID, order.AssetGroupKey,
			order.MaxAssetAmount, suggestedSellPrice,
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

// expiryWithinBounds checks if a quote expiry is within acceptable bounds. This
// check ensures that the expiry timestamp is far enough in the future for the
// quote to be useful.
func expiryWithinBounds(expiry time.Time, minExpiryLifetime uint64) bool {
	diff := expiry.Unix() - time.Now().Unix()
	return diff >= int64(minExpiryLifetime)
}

// priceWithinBounds returns true if the difference between the first price and
// the second price is within the given tolerance (in parts per million (PPM)).
func pricesWithinBounds(firstPriceQuote, secondPriceQuote *rfqmsg.PriceQuote,
	tolerancePpm uint64) bool {

	// TODO(guggero): This is obviously wrong and we'll want to fix this
	// after refactoring the wire messages. For now, we'll just want for
	// things to compile in this commit.
	firstPrice := firstPriceQuote.InAssetPrice.Value.ToUint64()
	secondPrice := secondPriceQuote.InAssetPrice.Value.ToUint64()

	// Handle the case where both prices are zero.
	if firstPrice == 0 && secondPrice == 0 {
		return true
	}

	// Handle cases where either price is zero.
	if firstPrice == 0 || secondPrice == 0 {
		return false
	}

	firstP := float64(firstPrice)
	secondP := float64(secondPrice)

	// Calculate the absolute difference between both prices.
	delta := math.Abs(firstP - secondP)

	// Normalize the delta by dividing by the greater of the two prices.
	normalisedDelta := delta / math.Max(firstP, secondP)

	// Convert the fraction to parts per million (PPM).
	deltaPpm := 1_000_000 * normalisedDelta

	// Compare the difference to the tolerance.
	return deltaPpm <= float64(tolerancePpm)
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
	//  timestamp given the expiry timestamp provided by the price
	//  oracle.
	if !expiryWithinBounds(msg.Price.Expiry, minRateTickExpiryLifetime) {
		// The expiry time is not within the acceptable bounds.
		log.Debugf("Buy accept quote expiry time is not within "+
			"acceptable bounds (expiry=%v)", msg.Price.Expiry)

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

		// The buy accept message contains a buy price. This price
		// is the price that the peer is willing to accept in order to
		// sell the asset that we are buying.
		//
		// We will sanity check that price by querying our price oracle
		// for a buy price. We will then compare the ask price returned
		// by the price oracle with the buy price provided by the peer.
		oraclePrice, err := n.queryBuyPriceFromOracle(
			msg.Request.AssetID, msg.Request.AssetGroupKey,
			msg.Request.InAssetMaxAmount, nil,
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

		// Ensure that the peer provided price is reasonable given the
		// price provided by the price oracle service.
		acceptablePrice := pricesWithinBounds(
			&msg.Price, oraclePrice, n.cfg.AcceptPriceDeviationPpm,
		)
		if !acceptablePrice {
			// The price is not within the acceptable tolerance.
			// We will return without calling the quote accept
			// callback.
			log.Debugf("Buy accept price is not within "+
				"acceptable bounds (peer_price=%v, "+
				"oracle_price=%v)", msg.Price, oraclePrice)

			// Construct an invalid quote response event so that we
			// can inform the peer that the quote response has not
			// validated successfully.
			invalidQuoteRespEvent := NewInvalidQuoteRespEvent(
				&msg, InvalidRateTickQuoteRespStatus,
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
	if !expiryWithinBounds(msg.Price.Expiry, minRateTickExpiryLifetime) {
		// The expiry time is not within the acceptable bounds.
		log.Debugf("Sell accept quote expiry time is not within "+
			"acceptable bounds (expiry=%v)", msg.Price.Expiry)

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

		// The sell accept message contains a sell price. This price
		// is the price that the peer is willing to pay in order to buy
		// the asset that we are selling.
		//
		// We will sanity check that price by querying our price oracle
		// for a sell price. We will then compare the bid price returned
		// by the price oracle with the sell price provided by the peer.
		oraclePrice, err := n.querySellPriceFromOracle(
			msg.Request.AssetID, msg.Request.AssetGroupKey,
			msg.Request.InAssetMaxAmount, nil,
		)
		if err != nil {
			// The price oracle returned an error. We will return
			// without calling the quote accept callback.
			err = fmt.Errorf("negotiator failed to query price "+
				"oracle when handling incoming sell accept "+
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

		// Ensure that the peer provided price is reasonable given the
		// price provided by the price oracle service.
		acceptablePrice := pricesWithinBounds(
			&msg.Price, oraclePrice, n.cfg.AcceptPriceDeviationPpm,
		)
		if !acceptablePrice {
			// The price is not within the acceptable bounds.
			// We will return without calling the quote accept
			// callback.
			log.Debugf("Sell accept quote price is not within "+
				"acceptable bounds (peer_price=%v, "+
				"oracle_price=%v)", msg.Price, oraclePrice)

			// Construct an invalid quote response event so that we
			// can inform the peer that the quote response has not
			// validated successfully.
			invalidQuoteRespEvent := NewInvalidQuoteRespEvent(
				&msg, InvalidRateTickQuoteRespStatus,
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
func (n *Negotiator) HasAssetSellOffer(assetID *asset.ID,
	assetGroupKey *btcec.PublicKey, assetAmt uint64) bool {

	// If the asset group key is not nil, then we will use it as the key for
	// the offer. Otherwise, we will use the asset ID as the key.
	var sellOffer *SellOffer
	switch {
	case assetGroupKey != nil:
		keyFixedBytes := asset.ToSerialized(assetGroupKey)
		offer, ok := n.assetGroupSellOffers.Load(keyFixedBytes)
		if !ok {
			// Corresponding offer not found.
			return false
		}

		sellOffer = &offer

	case assetID != nil:
		offer, ok := n.assetSellOffers.Load(*assetID)
		if !ok {
			// Corresponding offer not found.
			return false
		}

		sellOffer = &offer
	}

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
func (n *Negotiator) HasAssetBuyOffer(assetID *asset.ID,
	assetGroupKey *btcec.PublicKey, assetAmt uint64) bool {

	// If the asset group key is not nil, then we will use it as the lookup
	// key to retrieve an offer. Otherwise, we will use the asset ID as the
	// lookup key.
	var buyOffer *BuyOffer
	switch {
	case assetGroupKey != nil:
		keyFixedBytes := asset.ToSerialized(assetGroupKey)
		offer, ok := n.assetGroupBuyOffers.Load(keyFixedBytes)
		if !ok {
			// Corresponding offer not found.
			return false
		}

		buyOffer = &offer

	case assetID != nil:
		offer, ok := n.assetBuyOffers.Load(*assetID)
		if !ok {
			// Corresponding offer not found.
			return false
		}

		buyOffer = &offer
	}

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
