package rfq

import (
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

// NegotiatorCfg holds the configuration for the negotiator.
type NegotiatorCfg struct {
	// PriceOracle is the price oracle that the negotiator will use to
	// determine whether a quote is accepted or rejected.
	PriceOracle PriceOracle

	// OutgoingMessages is a channel which is populated with outgoing peer
	// messages. These are messages which are destined to be sent to peers.
	OutgoingMessages chan<- rfqmsg.OutgoingMsg

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
	assetGroupSellOffers lnutils.SyncMap[btcec.PublicKey, SellOffer]

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewNegotiator creates a new quote negotiator.
func NewNegotiator(cfg NegotiatorCfg) (*Negotiator, error) {
	// If the price oracle is nil, then we will return an error.
	if cfg.PriceOracle == nil {
		return nil, fmt.Errorf("price oracle is nil")
	}

	return &Negotiator{
		cfg: cfg,

		assetSellOffers: lnutils.SyncMap[asset.ID, SellOffer]{},
		assetGroupSellOffers: lnutils.SyncMap[
			btcec.PublicKey, SellOffer]{},

		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}, nil
}

// queryBidFromPriceOracle queries the price oracle for a bid price. It returns
// an appropriate outgoing response message which should be sent to the peer.
func (n *Negotiator) queryBidFromPriceOracle(peer route.Vertex,
	assetId *asset.ID, assetGroupKey *btcec.PublicKey,
	assetAmount uint64) (lnwire.MilliSatoshi, uint64, error) {

	ctx, cancel := n.WithCtxQuitNoTimeout()
	defer cancel()

	oracleResponse, err := n.cfg.PriceOracle.QueryBidPrice(
		ctx, assetId, assetGroupKey, assetAmount,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to query price oracle for "+
			"bid: %w", err)
	}

	// Now we will check for an error in the response from the price oracle.
	// If present, we will convert it to a string and return it as an error.
	if oracleResponse.Err != nil {
		return 0, 0, fmt.Errorf("failed to query price oracle for "+
			"bid price: %s", oracleResponse.Err)
	}

	// By this point, the price oracle did not return an error or a bid
	// price. We will therefore return an error.
	if oracleResponse.BidPrice == nil {
		return 0, 0, fmt.Errorf("price oracle did not specify a bid " +
			"price")
	}

	// TODO(ffranr): Check that the bid price is reasonable.
	// TODO(ffranr): Ensure that the expiry time is valid and sufficient.

	return *oracleResponse.BidPrice, oracleResponse.Expiry, nil
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

		// Query the price oracle for a bid price.
		bidPrice, _, err := n.queryBidFromPriceOracle(
			*buyOrder.Peer, buyOrder.AssetID,
			buyOrder.AssetGroupKey, buyOrder.MinAssetAmount,
		)
		if err != nil {
			err := fmt.Errorf("negotiator failed to handle price "+
				"oracle response: %w", err)
			n.cfg.ErrChan <- err
			return
		}

		request, err := rfqmsg.NewBuyRequest(
			*buyOrder.Peer, buyOrder.AssetID,
			buyOrder.AssetGroupKey, buyOrder.MinAssetAmount,
			bidPrice,
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
func (n *Negotiator) queryAskFromPriceOracle(peer *route.Vertex,
	assetId *asset.ID, assetGroupKey *btcec.PublicKey, assetAmount uint64,
	bid *lnwire.MilliSatoshi) (lnwire.MilliSatoshi, uint64, error) {

	// Query the price oracle for an asking price.
	ctx, cancel := n.WithCtxQuitNoTimeout()
	defer cancel()

	oracleResponse, err := n.cfg.PriceOracle.QueryAskPrice(
		ctx, assetId, assetGroupKey, assetAmount, bid,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to query price oracle for "+
			"ask price: %w", err)
	}

	// Now we will check for an error in the response from the price oracle.
	// If present, we will convert it to a string and return it as an error.
	if oracleResponse.Err != nil {
		return 0, 0, fmt.Errorf("failed to query price oracle for "+
			"ask price: %s", oracleResponse.Err)
	}

	// By this point, the price oracle did not return an error or an asking
	// price. We will therefore return an error.
	if oracleResponse.AskPrice == nil {
		return 0, 0, fmt.Errorf("price oracle did not specify an " +
			"asking price")
	}

	// TODO(ffranr): Check that the asking price is reasonable.
	// TODO(ffranr): Ensure that the expiry time is valid and sufficient.

	// If the asking price is not nil, then we can proceed to compute a
	// final asking price.
	//
	// If the bid price (bid price suggested in the buy request) is greater
	// than the asking price, then we will use the bid price as the final
	// asking price. Otherwise, we will use the asking price provided by the
	// price oracle as the final asking price.
	var finalAskPrice lnwire.MilliSatoshi

	if bid != nil && *bid > *oracleResponse.AskPrice {
		finalAskPrice = *bid
	} else {
		finalAskPrice = *oracleResponse.AskPrice
	}

	return finalAskPrice, oracleResponse.Expiry, nil
}

// HandleIncomingBuyRequest handles an incoming asset buy quote request.
func (n *Negotiator) HandleIncomingBuyRequest(
	request rfqmsg.BuyRequest) error {

	// Ensure that we have a suitable sell offer for the asset that is being
	// requested. Here we can handle the case where this node does not wish
	// to sell a particular asset.
	offerAvailable := n.HasAssetSellOffer(
		request.AssetID, request.AssetGroupKey, request.AssetAmount,
	)
	if !offerAvailable {
		// If we do not have a suitable sell offer, then we will reject
		// the quote request with an error.
		reject := rfqmsg.NewReject(
			request, rfqmsg.ErrNoSuitableSellOffer,
		)
		var msg rfqmsg.OutgoingMsg = reject

		sendSuccess := fn.SendOrQuit(
			n.cfg.OutgoingMessages, msg, n.Quit,
		)
		if !sendSuccess {
			return fmt.Errorf("negotiator failed to send reject " +
				"message")
		}

		return nil
	}

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

	// Query the price oracle asynchronously using a separate goroutine.
	// The price oracle might be an external service, responses could be
	// delayed.
	n.Wg.Add(1)
	go func() {
		defer n.Wg.Done()

		// Query the price oracle for an asking price.
		askPrice, askExpiry, err := n.queryAskFromPriceOracle(
			nil, request.AssetID, request.AssetGroupKey,
			request.AssetAmount, &request.BidPrice,
		)
		if err != nil {
			// Send a reject message to the peer.
			msg := rfqmsg.NewReject(
				request, rfqmsg.ErrUnknownReject,
			)
			sendOutgoingMsg(msg)

			// Add an error to the error channel and return.
			err = fmt.Errorf("failed to query ask price from "+
				"oracle: %w", err)
			n.cfg.ErrChan <- err
			return
		}

		// Construct and send a buy accept message.
		msg := rfqmsg.NewBuyAcceptFromRequest(
			request, askPrice, askExpiry,
		)
		sendOutgoingMsg(msg)
	}()

	return nil
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
		n.assetGroupSellOffers.Store(*offer.AssetGroupKey, offer)

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
		n.assetGroupSellOffers.Delete(*assetGroupKey)

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
		offer, ok := n.assetGroupSellOffers.Load(*assetGroupKey)
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
