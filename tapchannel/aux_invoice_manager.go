package tapchannel

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/invoices"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

// InvoiceHtlcModifier is an interface that abstracts the invoice HTLC
// modification functionality required by the auxiliary invoice manager.
type InvoiceHtlcModifier interface {
	// HtlcModifier is a bidirectional streaming RPC that allows a client to
	// intercept and modify the HTLCs that attempt to settle the given
	// invoice. The server will send HTLCs of invoices to the client and the
	// client can modify some aspects of the HTLC in order to pass the
	// invoice acceptance tests.
	HtlcModifier(ctx context.Context,
		handler lndclient.InvoiceHtlcModifyHandler) error
}

// RfqManager is an interface that abstracts the functionalities of the rfq
// manager that are needed by AuxInvoiceManager.
type RfqManager interface {
	// PeerAcceptedBuyQuotes returns buy quotes that were requested by our
	// node and have been accepted by our peers. These quotes are
	// exclusively available to our node for the acquisition of assets.
	PeerAcceptedBuyQuotes() rfq.BuyAcceptMap

	// LocalAcceptedSellQuotes returns sell quotes that were accepted by our
	// node and have been requested by our peers. These quotes are
	// exclusively available to our node for the sale of assets.
	LocalAcceptedSellQuotes() rfq.SellAcceptMap

	// AssetMatchesSpecifier checks if the provided asset satisfies the
	// provided specifier. If the specifier includes a group key, we will
	// check if the asset belongs to that group.
	AssetMatchesSpecifier(ctx context.Context, specifier asset.Specifier,
		id asset.ID) (bool, error)
}

// A compile time assertion to ensure that the rfq.Manager meets the expected
// tapchannel.RfqManager interface.
var _ RfqManager = (*rfq.Manager)(nil)

// RfqLookup is an interface that abstracts away the process of performing
// a lookup to the current set of existing RFQs.
type RfqLookup interface {
	// RfqPeerFromScid retrieves the peer associated with the RFQ id that
	// is mapped to the provided scid, if it exists.
	RfqPeerFromScid(scid uint64) (route.Vertex, error)
}

// InvoiceManagerConfig defines the configuration for the auxiliary invoice
// manager.
type InvoiceManagerConfig struct {
	// ChainParams are the chain parameters of the chain we're operating on.
	ChainParams *address.ChainParams

	// InvoiceHtlcModifier is the HTLC modifier that will be used to
	// intercept and modify the HTLCs that attempt to settle a given
	// invoice.
	InvoiceHtlcModifier InvoiceHtlcModifier

	// RfqManager is the RFQ manager that will be used to retrieve the
	// accepted quotes for determining the incoming value of invoice related
	// HTLCs.
	RfqManager RfqManager

	// LndClient is the lnd client that will be used to interact with the
	// lnd node.
	LightningClient lndclient.LightningClient
}

// AuxInvoiceManager is a Taproot Asset auxiliary invoice manager that can be
// used to make invoices to receive Taproot Assets.
type AuxInvoiceManager struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *InvoiceManagerConfig

	// channelFundingCache is a cache used to store the channel funding
	// information for the channels that are used to receive assets. The map
	// is keyed by the main channel ID, and the value is the asset channel
	// funding information.
	channelFundingCache lnutils.SyncMap[uint64, rfqmsg.JsonAssetChannel]

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewAuxInvoiceManager creates a new Taproot Asset auxiliary invoice manager
// based on the passed config.
func NewAuxInvoiceManager(cfg *InvoiceManagerConfig) *AuxInvoiceManager {
	return &AuxInvoiceManager{
		cfg: cfg,
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start attempts to start a new aux invoice manager.
func (s *AuxInvoiceManager) Start() error {
	var startErr error
	s.startOnce.Do(func() {
		log.Info("Starting aux invoice manager")

		// Start the interception in its own goroutine.
		s.Wg.Add(1)
		go func() {
			defer s.Wg.Done()

			ctx, cancel := s.WithCtxQuitNoTimeout()
			defer cancel()

			err := s.cfg.InvoiceHtlcModifier.HtlcModifier(
				ctx, s.handleInvoiceAccept,
			)
			if err != nil {
				log.Errorf("Error setting up invoice "+
					"acceptor: %v", err)
				return
			}
		}()
	})
	return startErr
}

// handleInvoiceAccept is the handler that will be called for each invoice that
// is accepted. It will intercept the HTLCs that attempt to settle the invoice
// and modify them if necessary.
func (s *AuxInvoiceManager) handleInvoiceAccept(ctx context.Context,
	req lndclient.InvoiceHtlcModifyRequest) (
	*lndclient.InvoiceHtlcModifyResponse, error) {

	// By default, we'll return the same amount that was requested.
	resp := &lndclient.InvoiceHtlcModifyResponse{
		CircuitKey: req.CircuitKey,
		AmtPaid:    req.ExitHtlcAmt,
	}

	if req.Invoice == nil {
		return nil, fmt.Errorf("cannot handle empty invoice")
	}

	jsonBytes, err := taprpc.ProtoJSONMarshalOpts.Marshal(req.Invoice)
	if err != nil {
		return nil, fmt.Errorf("unable to decode response: %w", err)
	}

	iLog := log.WithPrefix(
		fmt.Sprintf("Invoice(hash=%x, amt=%v): ",
			req.Invoice.RHash, req.Invoice.Value),
	)

	iLog.Debugf("received invoice: %s", jsonBytes)
	iLog.Debugf("received wire custom records: %v",
		limitSpewer.Sdump(req.WireCustomRecords))

	// Check if any strict forwarding rules need to be applied. Strict
	// forwarding means that we want assets for asset invoices and sats for
	// BTC invoices, and no mixing of the two.
	switch {
	// No asset custom records on the HTLC, check that we're not expecting
	// assets.
	case !rfqmsg.HasAssetHTLCCustomRecords(req.WireCustomRecords):
		// If there's no asset wire custom records but the invoice is an
		// asset invoice, do not settle the invoice. Since we are asking
		// for assets in the invoice, we may not let this HTLC go
		// through as it is not carrying assets. This could lead to
		// undesired behavior where the asset invoice may be settled by
		// accepting sats instead of assets.
		//
		// TODO(george): Strict-forwarding could be configurable?
		if isAssetInvoice(req.Invoice, s) {
			iLog.Debugf("has no asset custom records, but " +
				"invoice requires assets, canceling HTLCs")

			resp.CancelSet = true
		} else {
			iLog.Tracef("has no asset custom records, ignoring")
		}

		return resp, nil

	// We have custom records, but the invoice is not an asset invoice.
	case !isAssetInvoice(req.Invoice, s) && !req.Invoice.IsKeysend:
		// If we do have custom records, but the invoice does not
		// correspond to an asset invoice, we do not settle the invoice.
		// Since we requested btc we should be receiving btc.
		resp.CancelSet = true

		iLog.Debugf("has asset custom records, but invoice does not " +
			"require assets, canceling HTLCs")

		return resp, nil

	default:
		// No strict forwarding rule violation, continue below.
	}

	htlc, err := rfqmsg.HtlcFromCustomRecords(req.WireCustomRecords)
	if err != nil {
		return nil, fmt.Errorf("unable to decode htlc: %w", err)
	}

	iLog.Debugf("received htlc: %v", limitSpewer.Sdump(htlc))

	// If we don't have an RFQ ID, then this is likely a keysend payment,
	// and we don't modify the amount (since the invoice amount will match
	// the HTLC amount).
	if htlc.RfqID.ValOpt().IsNone() {
		return resp, nil
	}

	// We now run some validation checks on the asset HTLC.
	err = s.validateAssetHTLC(ctx, htlc, resp.CircuitKey)
	if err != nil {
		iLog.Errorf("failed to validate asset HTLC: %v", err)

		resp.CancelSet = true

		return resp, nil
	}

	// Convert the total asset amount to milli-satoshis using the price from
	// the accepted quote.
	rfqID := htlc.RfqID.ValOpt().UnsafeFromSome()
	assetRate, err := s.priceFromQuote(rfqID)
	if err != nil {
		return nil, fmt.Errorf("unable to get price from quote with "+
			"ID %x / SCID %d: %w", rfqID[:], rfqID.Scid(), err)
	}

	htlcAssetAmount := htlc.Amounts.Val.Sum()
	totalAssetAmt := rfqmath.NewBigIntFixedPoint(htlcAssetAmount, 0)
	resp.AmtPaid = rfqmath.UnitsToMilliSatoshi(totalAssetAmt, *assetRate)

	// If all previously accepted HTLC amounts plus the intercepted HTLC
	// amount together add up to just about the asset invoice amount, then
	// we can settle the HTLCs to address the rounding error.
	var acceptedHtlcSum lnwire.MilliSatoshi
	for _, invoiceHtlc := range req.Invoice.Htlcs {
		acceptedHtlcSum += lnwire.MilliSatoshi(invoiceHtlc.AmtMsat)
	}

	// We assume that each shard can have a rounding error of up to 1 asset
	// unit. So we allow the final amount to be off by up to 1 asset unit
	// per accepted HTLC (plus the one we're currently processing).
	allowedMarginAssetUnits := uint64(len(req.Invoice.Htlcs) + 1)
	marginAssetUnits := rfqmath.NewBigIntFixedPoint(
		allowedMarginAssetUnits, 0,
	)
	allowedMarginMSat := rfqmath.UnitsToMilliSatoshi(
		marginAssetUnits, *assetRate,
	)

	// If the sum of the accepted HTLCs plus the current HTLC amount plus
	// the error margin is greater than the invoice amount, we'll accept it.
	totalInbound := acceptedHtlcSum + resp.AmtPaid
	totalInboundWithMargin := totalInbound + allowedMarginMSat + 1
	invoiceValue := lnwire.MilliSatoshi(req.Invoice.ValueMsat)

	iLog.Debugf("accepted HTLC sum: %v, current HTLC amount: %v, allowed "+
		"margin: %v (total %v), invoice value %v", acceptedHtlcSum,
		resp.AmtPaid, allowedMarginMSat, totalInboundWithMargin,
		invoiceValue)

	// If we're within the error margin, we'll increase the current HTLCs
	// amount to cover the error rate and make the total sum match the
	// invoice amount exactly.
	if totalInboundWithMargin >= invoiceValue {
		resp.AmtPaid = invoiceValue - acceptedHtlcSum
	}

	return resp, nil
}

// identifierAndPeerFromQuote retrieves the quote by looking up the rfq
// manager's maps of accepted quotes based on the passed rfq ID. If there's a
// match, the asset specifier and peer are returned.
func (s *AuxInvoiceManager) identifierAndPeerFromQuote(
	rfqID rfqmsg.ID) (asset.Specifier, route.Vertex, error) {

	acceptedBuyQuotes := s.cfg.RfqManager.PeerAcceptedBuyQuotes()
	acceptedSellQuotes := s.cfg.RfqManager.LocalAcceptedSellQuotes()

	buyQuote, isBuy := acceptedBuyQuotes[rfqID.Scid()]
	sellQuote, isSell := acceptedSellQuotes[rfqID.Scid()]

	var (
		specifier asset.Specifier
		peer      route.Vertex
	)

	switch {
	case isBuy:
		specifier = buyQuote.Request.AssetSpecifier
		peer = buyQuote.Peer

	case isSell:
		specifier = sellQuote.Request.AssetSpecifier
		peer = sellQuote.Peer
	}

	err := specifier.AssertNotEmpty()
	if err != nil {
		return specifier, peer, fmt.Errorf("rfqID does not match any "+
			"accepted buy or sell quote: %v", err)
	}

	return specifier, peer, nil
}

// priceFromQuote retrieves the price from the accepted quote for the given RFQ
// ID. We allow the quote to either be a buy or a sell quote, since we don't
// know if this is a direct peer payment or a payment that is routed through the
// multiple hops. If it's a direct peer payment, then the quote will be a sell
// quote, since that's what the peer created to find out how many units to send
// for an invoice denominated in BTC.
func (s *AuxInvoiceManager) priceFromQuote(rfqID rfqmsg.ID) (
	*rfqmath.BigIntFixedPoint, error) {

	acceptedBuyQuotes := s.cfg.RfqManager.PeerAcceptedBuyQuotes()
	acceptedSellQuotes := s.cfg.RfqManager.LocalAcceptedSellQuotes()

	log.Tracef("Currently available quotes: buy %v, sell %v",
		limitSpewer.Sdump(acceptedBuyQuotes),
		limitSpewer.Sdump(acceptedSellQuotes))

	buyQuote, isBuy := acceptedBuyQuotes[rfqID.Scid()]
	sellQuote, isSell := acceptedSellQuotes[rfqID.Scid()]

	switch {
	// This is a normal invoice payment with multiple hops, so we expect to
	// find a buy quote.
	case isBuy:
		log.Debugf("Found buy quote for ID %x / SCID %d: %#v", rfqID[:],
			rfqID.Scid(), buyQuote)

		return &buyQuote.AssetRate.Rate, nil

	// This is a direct peer payment, so we expect to find a sell quote.
	case isSell:
		log.Debugf("Found sell quote for ID %x / SCID %d: %#v",
			rfqID[:], rfqID.Scid(), sellQuote)

		return &sellQuote.AssetRate.Rate, nil

	default:
		return nil, fmt.Errorf("no accepted quote found for RFQ SCID "+
			"%d", rfqID.Scid())
	}
}

// RfqPeerFromScid attempts to match the provided scid with a negotiated quote,
// then it returns the RFQ peer's node id.
func (s *AuxInvoiceManager) RfqPeerFromScid(scid uint64) (route.Vertex, error) {
	acceptedBuyQuotes := s.cfg.RfqManager.PeerAcceptedBuyQuotes()

	buyQuote, isBuy := acceptedBuyQuotes[rfqmsg.SerialisedScid(scid)]

	if !isBuy {
		return route.Vertex{}, fmt.Errorf("no peer found for RFQ "+
			"SCID %d", scid)
	}

	return buyQuote.Peer, nil
}

// isAssetInvoice checks whether the provided invoice is an asset invoice. This
// method checks whether the routing hints of the invoice match those created
// when generating an asset invoice, and if that's the case we then check that
// the scid matches an existing quote.
func isAssetInvoice(invoice *lnrpc.Invoice, rfqLookup RfqLookup) bool {
	hints := invoice.RouteHints

	for _, hint := range hints {
		for _, h := range hint.HopHints {
			scid := h.ChanId
			nodeId := h.NodeId

			// Check if for this hop hint we can retrieve a valid
			// rfq quote.
			peer, err := rfqLookup.RfqPeerFromScid(scid)
			if err != nil {
				log.Debugf("invoice hop hint scid %v does not "+
					"correspond to a valid RFQ quote", scid)

				continue
			}

			// If we also have a nodeId match, we're safe to assume
			// this is an asset invoice.
			if peer.String() == nodeId {
				return true
			}
		}
	}

	return false
}

// validateAssetHTLC runs a couple of checks on the provided asset HTLC.
func (s *AuxInvoiceManager) validateAssetHTLC(ctx context.Context,
	htlc *rfqmsg.Htlc, circuitKey invoices.CircuitKey) error {

	rfqID := htlc.RfqID.ValOpt().UnsafeFromSome()

	// Retrieve the asset identifier from the RFQ quote.
	identifier, peer, err := s.identifierAndPeerFromQuote(rfqID)
	if err != nil {
		return fmt.Errorf("could not extract assetID from "+
			"quote: %v", err)
	}

	// Check for each of the asset balances of the HTLC that the identifier
	// matches that of the RFQ quote.
	assetIDs := fn.NewSet[asset.ID]()
	for _, v := range htlc.Balances() {
		match, err := s.cfg.RfqManager.AssetMatchesSpecifier(
			ctx, identifier, v.AssetID.Val,
		)
		if err != nil {
			return err
		}

		if !match {
			return fmt.Errorf("asset ID %s does not match %s",
				v.AssetID.Val.String(), identifier.String())
		}

		assetIDs.Add(v.AssetID.Val)
	}

	assetData, err := s.fetchChannelAssetData(ctx, circuitKey.ChanID, peer)
	if err != nil {
		return fmt.Errorf("unable to fetch channel asset data: %w", err)
	}

	if !assetData.HasAllAssetIDs(assetIDs) {
		return fmt.Errorf("channel %d does not have all asset IDs "+
			"required for HTLC settlement",
			circuitKey.ChanID)
	}

	return nil
}

// fetchChannelAssetData retrieves the asset channel data for the provided
// channel ID. If the cache doesn't contain the data, it is queried from the
// backing lnd node.
func (s *AuxInvoiceManager) fetchChannelAssetData(ctx context.Context,
	chanID lnwire.ShortChannelID,
	peer route.Vertex) (*rfqmsg.JsonAssetChannel, error) {

	// Do we have the information cached? Great, no lookup necessary. We
	// don't need to worry about cache invalidation because the funding
	// information remains constant for the lifetime of the channel.
	cachedAssetData, ok := s.channelFundingCache.Load(chanID.ToUint64())
	if ok {
		return &cachedAssetData, nil
	}

	// We also need to validate that the HTLC is actually the correct asset
	// and arrived through the correct asset channel.
	channels, err := s.cfg.LightningClient.ListChannels(
		ctx, true, false, lndclient.WithPeer(peer[:]),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to list channels: %w", err)
	}

	var inboundChannel *lndclient.ChannelInfo
	for _, channel := range channels {
		if channel.ChannelID == chanID.ToUint64() {
			inboundChannel = &channel
			break
		}
	}

	if inboundChannel == nil {
		return nil, fmt.Errorf("unable to find channel with short "+
			"channel ID %d", chanID.ToUint64())
	}

	if len(inboundChannel.CustomChannelData) == 0 {
		return nil, fmt.Errorf("channel %d does not have custom "+
			"channel data, can't accept asset HTLC over non-asset "+
			"channel", inboundChannel.ChannelID)
	}

	var assetData rfqmsg.JsonAssetChannel
	err = json.Unmarshal(inboundChannel.CustomChannelData, &assetData)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal channel asset "+
			"data: %w", err)
	}

	// We cache the asset data for the channel so we don't have to look it
	// up again.
	s.channelFundingCache.Store(chanID.ToUint64(), assetData)

	return &assetData, nil
}

// Stop signals for an aux invoice manager to gracefully exit.
func (s *AuxInvoiceManager) Stop() error {
	var stopErr error
	s.stopOnce.Do(func() {
		log.Info("Stopping aux invoice manager")

		close(s.Quit)
		s.Wg.Wait()
	})

	return stopErr
}
