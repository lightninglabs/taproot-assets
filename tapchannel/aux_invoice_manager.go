package tapchannel

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/lnrpc"
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
}

// AuxInvoiceManager is a Taproot Asset auxiliary invoice manager that can be
// used to make invoices to receive Taproot Assets.
type AuxInvoiceManager struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *InvoiceManagerConfig

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
func (s *AuxInvoiceManager) handleInvoiceAccept(_ context.Context,
	req lndclient.InvoiceHtlcModifyRequest) (
	*lndclient.InvoiceHtlcModifyResponse, error) {

	// By default, we'll return the same amount that was requested.
	resp := &lndclient.InvoiceHtlcModifyResponse{
		CircuitKey: req.CircuitKey,
		AmtPaid:    req.ExitHtlcAmt,
	}

	jsonBytes, err := taprpc.ProtoJSONMarshalOpts.Marshal(req.Invoice)
	if err != nil {
		return nil, fmt.Errorf("unable to decode response: %w", err)
	}

	log.Debugf("Received invoice: %s", jsonBytes)
	log.Debugf("Received wire custom records: %v",
		limitSpewer.Sdump(req.WireCustomRecords))

	// No custom record on the HTLC, so we have nothing to do.
	if len(req.WireCustomRecords) == 0 {
		// If there's no wire custom records and the invoice is an asset
		// invoice do not settle the invoice.
		//
		// TODO(george): Strict-forwarding could be configurable?
		if s.isAssetInvoice(req.Invoice) {
			resp.AmtPaid = 1
		}

		return resp, nil
	}

	htlcBlob, err := req.WireCustomRecords.Serialize()
	if err != nil {
		return nil, fmt.Errorf("error serializing custom records: %w",
			err)
	}

	htlc, err := rfqmsg.DecodeHtlc(htlcBlob)
	if err != nil {
		return nil, fmt.Errorf("unable to decode htlc: %w", err)
	}

	log.Debugf("Received htlc: %v", limitSpewer.Sdump(htlc))

	// If we don't have an RFQ ID, then this is likely a keysend payment,
	// and we don't modify the amount (since the invoice amount will match
	// the HTLC amount).
	if htlc.RfqID.ValOpt().IsNone() {
		return resp, nil
	}

	rfqID := htlc.RfqID.ValOpt().UnsafeFromSome()
	mSatPerAssetUnit, err := s.priceFromQuote(rfqID)
	if err != nil {
		return nil, fmt.Errorf("unable to get price from quote with "+
			"ID %x / SCID %d: %w", rfqID[:], rfqID.Scid(), err)
	}

	htlcAssetAmount := lnwire.MilliSatoshi(htlc.Amounts.Val.Sum())
	resp.AmtPaid = htlcAssetAmount * mSatPerAssetUnit

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
	allowedMarginAssetUnits := lnwire.MilliSatoshi(
		len(req.Invoice.Htlcs) + 1,
	)
	allowedMarginMSat := allowedMarginAssetUnits * mSatPerAssetUnit

	// If the sum of the accepted HTLCs plus the current HTLC amount plus
	// the error margin is greater than the invoice amount, we'll accept it.
	totalInbound := acceptedHtlcSum + resp.AmtPaid
	totalInboundWithMargin := totalInbound + allowedMarginMSat
	invoiceValue := lnwire.MilliSatoshi(req.Invoice.ValueMsat)

	log.Debugf("Accepted HTLC sum: %v, current HTLC amount: %v, allowed "+
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

// priceFromQuote retrieves the price from the accepted quote for the given RFQ
// ID. We allow the quote to either be a buy or a sell quote, since we don't
// know if this is a direct peer payment or a payment that is routed through the
// multiple hops. If it's a direct peer payment, then the quote will be a sell
// quote, since that's what the peer created to find out how many units to send
// for an invoice denominated in BTC.
func (s *AuxInvoiceManager) priceFromQuote(rfqID rfqmsg.ID) (
	lnwire.MilliSatoshi, error) {

	acceptedBuyQuotes := s.cfg.RfqManager.PeerAcceptedBuyQuotes()
	acceptedSellQuotes := s.cfg.RfqManager.LocalAcceptedSellQuotes()

	log.Tracef("Currently available quotes: buy %v, sell %v",
		spew.Sdump(acceptedBuyQuotes), spew.Sdump(acceptedSellQuotes))

	buyQuote, isBuy := acceptedBuyQuotes[rfqID.Scid()]
	sellQuote, isSell := acceptedSellQuotes[rfqID.Scid()]

	switch {
	case isBuy:
		log.Debugf("Found buy quote for ID %x / SCID %d: %#v",
			rfqID[:], rfqID.Scid(), buyQuote)

		return buyQuote.AskPrice, nil

	case isSell:
		log.Debugf("Found sell quote for ID %x / SCID %d: %#v",
			rfqID[:], rfqID.Scid(), sellQuote)

		return sellQuote.BidPrice, nil

	default:
		return 0, fmt.Errorf("no accepted quote found for RFQ SCID "+
			"%d", rfqID.Scid())
	}
}

// rfqPeerFromScid attempts to match the provided scid with a negotiated quote,
// then it returns the RFQ peer's node id.
func (s *AuxInvoiceManager) rfqPeerFromScid(scid uint64) (route.Vertex, error) {
	acceptedBuyQuotes := s.cfg.RfqManager.PeerAcceptedBuyQuotes()
	acceptedSellQuotes := s.cfg.RfqManager.LocalAcceptedSellQuotes()

	buyQuote, isBuy := acceptedBuyQuotes[rfqmsg.SerialisedScid(scid)]
	sellQuote, isSell := acceptedSellQuotes[rfqmsg.SerialisedScid(scid)]

	switch {
	case isBuy:
		return buyQuote.Peer, nil

	case isSell:
		return sellQuote.Peer, nil

	default:
		return route.Vertex{},
			fmt.Errorf("no peer found for RFQ SCID %d", scid)
	}
}

// isAssetInvoice checks whether the provided invoice is an asset invoice. This
// method checks whether the routing hints of the invoice match those created
// when generating an asset invoice, and if that's the case we then check that
// the scid matches an existing quote.
func (s *AuxInvoiceManager) isAssetInvoice(invoice *lnrpc.Invoice) bool {
	hints := invoice.RouteHints

	if len(hints) != 1 {
		return false
	}

	hint := hints[0]
	if len(hint.HopHints) != 1 {
		return false
	}

	hop := hint.HopHints[0]
	scid := hop.ChanId
	peer, err := s.rfqPeerFromScid(scid)
	if err != nil {
		log.Debugf("scid %v does not correspond to a valid RFQ quote",
			scid)

		return false
	}

	// We also want the RFQ peer and the node ID of the hop hint to match.
	nodeId := hop.NodeId
	return strings.Compare(peer.String(), nodeId) == 0
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
