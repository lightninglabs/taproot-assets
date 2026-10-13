package tapchannel

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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
	"github.com/lightningnetwork/lnd/lnwallet"
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

	// LookUpScid resolves the peer associated with a given SCID for
	// peer-accepted buy quotes, checking active quotes, an LRU cache,
	// and the database.
	LookUpScid(scid uint64) (route.Vertex, error)
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

// htlcModifierRetryDelay is the delay between attempts to re-establish the
// invoice HTLC modifier stream after it ends.
var htlcModifierRetryDelay = time.Second

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

			// Any error returned by the HTLC modifier tears the
			// stream down in lnd. A single error must not
			// permanently disable the asset invoice gate, so we
			// re-establish the stream until we're shutting down.
			for {
				err := s.cfg.InvoiceHtlcModifier.HtlcModifier(
					ctx, s.handleInvoiceAccept,
				)

				if err != nil && ctx.Err() == nil {
					log.Warnf("Error setting up invoice "+
						"acceptor: %v", err)
				}

				// Even a clean stream exit must be retried
				// unless the manager is shutting down.

				select {
				case <-ctx.Done():
					return
				case <-time.After(htlcModifierRetryDelay):
				}
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
		if IsAssetInvoice(req.Invoice, s) {
			iLog.Debugf("has no asset custom records, but " +
				"invoice requires assets, canceling HTLCs")

			resp.CancelSet = true
		} else {
			noopTLV := uint64(lnwallet.NoOpHtlcTLVEntry.TypeVal())
			_, isNoop := req.WireCustomRecords[noopTLV]

			// If the HTLC does not carry assets and the invoice is
			// also not expecting assets then we do not want to
			// modify anything as assets are not involved. If for
			// any reason the noop flag is set (which is meant for
			// asset HTLCs) we want to log a warning and cancel the
			// HTLCs. Letting this HTLC through at this point means
			// that we would be accounting a certain sats amount
			// in favor of our invoice, without ever receiving that
			// amount.
			if isNoop {
				resp.CancelSet = true
				iLog.Warnf("sats HTLC without assets " +
					"attempted a noop-add, cancelling set")
			} else {
				iLog.Tracef("has no asset custom records, " +
					"ignoring")
			}
		}

		return resp, nil

	// We have custom records, but the invoice is not an asset invoice.
	case !IsAssetInvoice(req.Invoice, s) && !req.Invoice.IsKeysend:
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
		// The custom records are supplied by the payer, so a malformed
		// record is a peer-input-driven failure. Cancel the set instead
		// of returning an error, which would tear the HTLC modifier
		// stream down in lnd.
		iLog.Errorf("unable to decode htlc, canceling HTLCs: %v", err)

		resp.CancelSet = true

		return resp, nil
	}

	iLog.Debugf("received htlc: %v", limitSpewer.Sdump(htlc))

	// If we don't have an RFQ ID, then this must be a keysend payment. For
	// regular invoices, accepting the HTLC would allow asset custom records
	// without any asset balances to bypass strict forwarding.
	if htlc.RfqID.ValOpt().IsNone() {
		if !req.Invoice.IsKeysend {
			iLog.Debugf("asset HTLC has no RFQ ID, canceling HTLCs")
			resp.CancelSet = true
		}

		return resp, nil
	}

	// Take one quote snapshot for both identity validation and valuation.
	// The RFQ maps can change while the HTLC is being checked, including
	// replacement of a quote under the same RFQ ID.
	rfqID := htlc.RfqID.ValOpt().UnsafeFromSome()
	quote, err := s.settlementQuote(rfqID)
	if err != nil {
		iLog.Debugf("unable to get settlement quote, "+
			"canceling HTLCs: %v", err)
		resp.CancelSet = true
		return resp, nil
	}

	// For asset invoices, the assets actually paid must match the quotes
	// the invoice's route hints point to. Otherwise, on a node with
	// accepted quotes for multiple assets, a payer could settle an invoice
	// created for one asset with units of a different asset. The check is
	// on the HTLC's own balance records, not on the asset description of
	// the quote the payer chose to reference: a quote can claim both a
	// specific asset and a group while a different group member is paid,
	// and quotes are re-negotiated frequently anyway, so the SCID the
	// payer's quote carries is not stable. Keysend payments have no route
	// hints, so they are exempt.
	if !req.Invoice.IsKeysend {
		err := s.assetsMatchInvoiceHints(
			ctx, req.Invoice, htlc, resp.CircuitKey, quote.peer,
		)
		if err != nil {
			iLog.Debugf("asset HTLC does not match the invoice's "+
				"hinted quotes, canceling HTLCs: %v", err)

			resp.CancelSet = true

			return resp, nil
		}
	}

	// We now run some validation checks on the asset HTLC.
	err = s.validateAssetHTLC(ctx, htlc, resp.CircuitKey, quote)
	if err != nil {
		iLog.Errorf("failed to validate asset HTLC: %v", err)

		resp.CancelSet = true

		return resp, nil
	}

	// Convert the total asset amount to milli-satoshis using the price from
	// the accepted quote.
	assetRate := quote.rate

	htlcAssetAmount := htlc.Amounts.Val.Sum()
	totalAssetAmt := rfqmath.NewBigIntFixedPoint(htlcAssetAmount, 0)
	resp.AmtPaid, err = rfqmath.UnitsToMilliSatoshi(
		totalAssetAmt, assetRate,
	)
	if err != nil {
		// The asset amounts are supplied by the payer, so this is a
		// peer-input-driven failure. Cancel the set instead of
		// returning an error, which would tear the HTLC modifier
		// stream down in lnd.
		iLog.Errorf("unable to convert HTLC asset amount to mSat, "+
			"canceling HTLCs: %v", err)

		resp.CancelSet = true

		return resp, nil
	}

	// If all previously accepted HTLC amounts plus the intercepted HTLC
	// amount together add up to just about the asset invoice amount, then
	// we can settle the HTLCs to address the rounding error.
	var acceptedHtlcSum lnwire.MilliSatoshi
	for _, invoiceHtlc := range req.Invoice.Htlcs {
		acceptedHtlcSum += lnwire.MilliSatoshi(invoiceHtlc.AmtMsat)
	}

	// We assume that each shard can have a rounding error of up to 1 asset
	// unit. So we allow the final amount to be off by up to 1 asset unit
	// per accepted HTLC (plus the one we're currently processing). The
	// plus one here is because the invoice only has previously accepted
	// HTLCs committed to it, but we're processing the current HTLC which
	// is not yet in that list.
	allowedMarginAssetUnits := uint64(len(req.Invoice.Htlcs) + 1)

	// Convert the allowed margin asset units to milli-satoshis.
	marginAssetUnits := rfqmath.NewBigIntFixedPoint(
		allowedMarginAssetUnits, 0,
	)
	allowedMarginMSat, err := rfqmath.UnitsToMilliSatoshi(
		marginAssetUnits, assetRate,
	)
	if err != nil {
		iLog.Errorf("unable to convert margin asset units to mSat, "+
			"canceling HTLCs: %v", err)

		resp.CancelSet = true

		return resp, nil
	}

	// Every HTLC makes a roundtrip from msats to units and then back to
	// msats right here. Above we account for the asset units that may have
	// been lost by our peer when converting their incoming HTLC amount to
	// asset units, now we need to account for our loss for converting each
	// HTLC to msats.
	allowedMarginMSat += lnwire.MilliSatoshi(len(req.Invoice.Htlcs) + 1)

	// If the sum of the accepted HTLCs plus the current HTLC amount plus
	// the error margin is greater than the invoice amount, we'll accept it.
	totalInbound := acceptedHtlcSum + resp.AmtPaid
	totalInboundWithMargin := totalInbound + allowedMarginMSat
	invoiceValue := lnwire.MilliSatoshi(req.Invoice.ValueMsat)

	iLog.Debugf("accepted HTLC sum: %v, current HTLC amount: %v, allowed "+
		"margin: %v (total %v), invoice value %v", acceptedHtlcSum,
		resp.AmtPaid, allowedMarginMSat, totalInboundWithMargin,
		invoiceValue)

	// If we're within the error margin, we'll increase the current HTLCs
	// amount to cover the error rate and make the total sum match the
	// invoice amount exactly.
	//
	// Note: The total calculated margin should match what is implemented in
	// our TestUnitConversionToleranceRapid test. That test serves as a
	// sanity check for our tolerance model, which should allow all
	// combinations of shards and asset rates to be captured by the total
	// calculated tolerance.
	if totalInboundWithMargin >= invoiceValue {
		resp.AmtPaid = invoiceValue - acceptedHtlcSum
	}

	return resp, nil
}

// invoiceSettlementQuote keeps the pricing identity and rate together so
// a concurrent RFQ replacement cannot change the price after validation.
type invoiceSettlementQuote struct {
	specifier asset.Specifier
	peer      route.Vertex
	rate      rfqmath.BigIntFixedPoint
}

// settlementQuote selects a single accepted quote for the whole HTLC. Buy
// quotes cover routed payments; sell quotes cover direct peer payments.
func (s *AuxInvoiceManager) settlementQuote(
	rfqID rfqmsg.ID) (invoiceSettlementQuote, error) {

	buyQuotes := s.cfg.RfqManager.PeerAcceptedBuyQuotes()
	if quote, ok := buyQuotes[rfqID.Scid()]; ok {
		return invoiceSettlementQuote{
			specifier: quote.Request.AssetSpecifier,
			peer:      quote.Peer,
			rate:      quote.AssetRate.Rate,
		}, nil
	}
	sellQuotes := s.cfg.RfqManager.LocalAcceptedSellQuotes()
	if quote, ok := sellQuotes[rfqID.Scid()]; ok {
		return invoiceSettlementQuote{
			specifier: quote.Request.AssetSpecifier,
			peer:      quote.Peer,
			rate:      quote.AssetRate.Rate,
		}, nil
	}
	return invoiceSettlementQuote{}, fmt.Errorf(
		"no accepted quote found for RFQ SCID %d", rfqID.Scid(),
	)
}

// RfqPeerFromScid attempts to match the provided scid with a negotiated quote,
// then it returns the RFQ peer's node id. It delegates to the RFQ manager's
// LookUpScid which checks active quotes, an LRU cache, and the database.
func (s *AuxInvoiceManager) RfqPeerFromScid(scid uint64) (route.Vertex, error) {
	return s.cfg.RfqManager.LookUpScid(scid)
}

// IsAssetInvoice checks whether the provided invoice is an asset invoice. This
// method checks whether the routing hints of the invoice match those created
// when generating an asset invoice, and if that's the case we then check that
// the scid matches an existing quote.
func IsAssetInvoice(invoice *lnrpc.Invoice, rfqLookup RfqLookup) bool {
	return len(assetInvoiceHintScids(invoice, rfqLookup)) > 0
}

// assetInvoiceHintScids returns the set of SCIDs that appear in the invoice's
// route hints and can be mapped to one of our accepted RFQ quotes with a
// matching node ID. These are the SCIDs that identify an invoice as an asset
// invoice. The payer may use another quote with a compatible asset identity.
func assetInvoiceHintScids(invoice *lnrpc.Invoice,
	rfqLookup RfqLookup) map[uint64]struct{} {

	scids := make(map[uint64]struct{})

	for _, hint := range invoice.RouteHints {
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

			// If we also have a nodeId match, this hop hint
			// corresponds to one of our accepted quotes.
			if peer.String() == nodeId {
				scids[scid] = struct{}{}
			}
		}
	}

	return scids
}

// assetsMatchInvoiceHints returns an error if any asset balance the HTLC
// actually pays does not match the asset of at least one of the quotes the
// invoice's route hints point to. This binds an asset invoice to its
// invoiced asset through the paid balances themselves, without pinning the
// payer to the exact quote instance, which is re-negotiated frequently.
func (s *AuxInvoiceManager) assetsMatchInvoiceHints(ctx context.Context,
	invoice *lnrpc.Invoice, htlc *rfqmsg.Htlc,
	circuitKey invoices.CircuitKey, peer route.Vertex) error {

	channel, err := s.fetchChannelAssetData(ctx, circuitKey.ChanID, peer)
	if err != nil {
		return err
	}

	hintSpecifiers := s.assetInvoiceHintSpecifiers(invoice)
	if len(hintSpecifiers) == 0 {
		return fmt.Errorf("invoice has no route hints that map to " +
			"accepted quotes")
	}

	for _, balance := range htlc.Balances() {
		paidAsset := balance.AssetID.Val

		matched := false
		for _, hintSpecifier := range hintSpecifiers {
			match, err := s.paidAssetMatchesSpecifier(
				ctx, hintSpecifier, paidAsset, channel,
			)
			if err != nil {
				return fmt.Errorf("unable to check paid asset "+
					"%x against invoice hint: %w",
					paidAsset[:], err)
			}

			if match {
				matched = true
				break
			}
		}

		if !matched {
			return fmt.Errorf("paid asset %x does not match "+
				"any of the invoice's hinted quotes",
				paidAsset[:])
		}
	}

	return nil
}

// assetInvoiceHintSpecifiers returns the asset specifiers of the quotes the
// invoice's route hints point to.
func (s *AuxInvoiceManager) assetInvoiceHintSpecifiers(
	invoice *lnrpc.Invoice) []asset.Specifier {

	hintScids := assetInvoiceHintScids(invoice, s)

	buyQuotes := s.cfg.RfqManager.PeerAcceptedBuyQuotes()
	specifiers := make([]asset.Specifier, 0, len(hintScids))
	for scid := range hintScids {
		// Invoice hints originate from our buy requests, never a peer's
		// sell request that happens to reuse the same short ID.
		quote, ok := buyQuotes[rfqmsg.SerialisedScid(scid)]
		if ok {
			specifiers = append(
				specifiers, quote.Request.AssetSpecifier,
			)
		}
	}

	return specifiers
}

// GetBuyQuoteFromRouteHints is a helper method that extracts a buy quote from
// the route hints of an invoice, given that the quote is accepted and has a
// matching specifier. If no matching quote is found, it returns an error.
func (s *AuxInvoiceManager) GetBuyQuoteFromRouteHints(invoice *lnrpc.Invoice,
	specifier asset.Specifier) (*rfqmsg.BuyAccept, error) {

	buyQuotes := s.cfg.RfqManager.PeerAcceptedBuyQuotes()
	for _, hint := range invoice.RouteHints {
		for _, h := range hint.HopHints {
			scid := rfqmsg.SerialisedScid(h.ChanId)
			buyQuote, ok := buyQuotes[scid]
			if !ok {
				continue
			}

			quoteSpecifier := buyQuote.Request.AssetSpecifier
			areEqual, err := quoteSpecifier.Equal(&specifier, false)
			if err != nil {
				return nil, fmt.Errorf("error comparing "+
					"specifiers: %w", err)
			}

			if areEqual {
				return &buyQuote, nil
			}
		}
	}

	return nil, fmt.Errorf("no buy quote found for specifier %s",
		specifier.String())
}

// GetAllBuyQuotesFromRouteHints extracts all buy quotes from the route hints
// of an invoice that are accepted and have a matching specifier. Returns an
// error if no matching quotes are found.
func (s *AuxInvoiceManager) GetAllBuyQuotesFromRouteHints(
	invoice *lnrpc.Invoice,
	specifier asset.Specifier) ([]rfqmsg.BuyAccept, error) {

	var result []rfqmsg.BuyAccept
	seen := make(map[rfqmsg.SerialisedScid]struct{})

	buyQuotes := s.cfg.RfqManager.PeerAcceptedBuyQuotes()
	for _, hint := range invoice.RouteHints {
		for _, h := range hint.HopHints {
			scid := rfqmsg.SerialisedScid(h.ChanId)

			// Skip if we've already processed this SCID.
			if _, ok := seen[scid]; ok {
				continue
			}
			seen[scid] = struct{}{}

			buyQuote, ok := buyQuotes[scid]
			if !ok {
				continue
			}

			quoteSpecifier := buyQuote.Request.AssetSpecifier
			areEqual, err := quoteSpecifier.Equal(&specifier, false)
			if err != nil {
				return nil, fmt.Errorf("error comparing "+
					"specifiers: %w", err)
			}

			if areEqual {
				result = append(result, buyQuote)
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no buy quotes found for specifier %s",
			specifier.String())
	}

	return result, nil
}

// validateAssetHTLC runs a couple of checks on the provided asset HTLC.
func (s *AuxInvoiceManager) validateAssetHTLC(ctx context.Context,
	htlc *rfqmsg.Htlc, circuitKey invoices.CircuitKey,
	quote invoiceSettlementQuote) error {

	balances := htlc.Balances()
	hasPositiveBalance := false
	for _, balance := range balances {
		if balance.Amount.Val > 0 {
			hasPositiveBalance = true
			break
		}
	}
	if !hasPositiveBalance {
		return fmt.Errorf("asset HTLC has no positive asset balance")
	}

	assetData, err := s.fetchChannelAssetData(
		ctx, circuitKey.ChanID, quote.peer,
	)
	if err != nil {
		return fmt.Errorf("unable to fetch channel asset data: %w", err)
	}

	for _, balance := range balances {
		match, err := s.paidAssetMatchesSpecifier(
			ctx, quote.specifier, balance.AssetID.Val, assetData,
		)
		if err != nil {
			return err
		}
		if !match {
			return fmt.Errorf("paid asset does not match quote %s",
				quote.specifier.String())
		}
	}

	return nil
}

// paidAssetMatchesSpecifier binds both invoice and pricing identities to the
// channel's funding assets. An ID takes precedence over a group, as it does
// when the oracle prices a quote. A group wire marker is not an asset ID: all
// funding IDs must satisfy the specifier, since any of them may materialize.
func (s *AuxInvoiceManager) paidAssetMatchesSpecifier(ctx context.Context,
	specifier asset.Specifier, paid asset.ID,
	channel *rfqmsg.JsonAssetChannel) (bool, error) {

	ids := []asset.ID{paid}
	if channel.GroupKey != "" {
		keyBytes, err := hex.DecodeString(channel.GroupKey)
		if err != nil {
			return false, err
		}
		key, err := btcec.ParsePubKey(keyBytes)
		if err != nil {
			return false, err
		}
		if bytes.Equal(schnorr.SerializePubKey(key), paid[:]) {
			ids = nil
			for _, funding := range channel.FundingAssets {
				raw, err := hex.DecodeString(
					funding.AssetGenesis.AssetID,
				)
				if err != nil {
					return false, err
				}
				if len(raw) != len(paid) {
					return false, fmt.Errorf(
						"invalid funding asset ID",
					)
				}
				var id asset.ID
				copy(id[:], raw)
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return false, nil
	}
	for _, id := range ids {
		// Check actual IDs directly, without the group-marker
		// shortcut in HasAllAssetIDs.
		funded := false
		for _, funding := range channel.FundingAssets {
			if funding.AssetGenesis.AssetID == id.String() {
				funded = true
				break
			}
		}
		if !funded {
			return false, nil
		}
		if specifier.HasId() {
			if *specifier.UnwrapIdToPtr() != id {
				return false, nil
			}
			continue
		}
		match, err := s.cfg.RfqManager.AssetMatchesSpecifier(
			ctx, specifier, id,
		)
		if err != nil || !match {
			return match, err
		}
	}
	return true, nil
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
