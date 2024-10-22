package tapchannel

import (
	"context"
	"fmt"
	"sync"

	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/lnwire"
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
	RfqManager *rfq.Manager
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
	*rfqmath.BigIntFixedPoint, error) {

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

		return &buyQuote.AssetRate, nil

	case isSell:
		log.Debugf("Found sell quote for ID %x / SCID %d: %#v",
			rfqID[:], rfqID.Scid(), sellQuote)

		return &sellQuote.AssetRate, nil

	default:
		return nil, fmt.Errorf("no accepted quote found for RFQ SCID "+
			"%d", rfqID.Scid())
	}
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
