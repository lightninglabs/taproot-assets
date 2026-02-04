package rfq

import (
	"context"
	"fmt"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

// AssetTransferDirection represents the direction of an asset transfer
// from our perspective for pricing and rate queries.
type AssetTransferDirection uint8

const (
	// AssetTransferUndefined is the zero value and indicates an unspecified
	// direction.
	AssetTransferUndefined = 0

	// AssetTransferBuy indicates we want to buy the asset (receive asset
	// from edge node peer, peer gets paid sats from the Lightning network).
	AssetTransferBuy = 1

	// AssetTransferSell indicates we want to sell the asset (send asset
	// to edge node peer, peer forwards Lightning payment for us).
	AssetTransferSell = 2
)

// String returns a human-readable representation of the AssetTransferDirection.
func (d AssetTransferDirection) String() string {
	switch d {
	case AssetTransferUndefined:
		return "undefined"
	case AssetTransferBuy:
		return "buy"
	case AssetTransferSell:
		return "sell"
	default:
		return "unknown"
	}
}

// AssetTransferDirectionFromOrder determines the AssetTransferDirection from
// the order type.
func AssetTransferDirectionFromOrder(order Order) AssetTransferDirection {
	switch order.(type) {
	case *BuyOrder:
		return AssetTransferBuy
	case *SellOrder:
		return AssetTransferSell
	default:
		return AssetTransferUndefined
	}
}

// AssetRateQuery bundles parameters for querying asset rates for pricing
// and rate discovery purposes.
type AssetRateQuery struct {
	// AssetSpecifier identifies the asset being queried.
	AssetSpecifier asset.Specifier

	// Direction specifies whether we want to buy or sell the asset.
	Direction AssetTransferDirection

	// Intent specifies the purpose of the query (e.g., paying an invoice,
	// receiving payment, etc.). This determines the context for pricing.
	Intent PriceQueryIntent

	// AssetAmount is an optional constraint on the asset amount.
	AssetAmount fn.Option[uint64]

	// PaymentAmount is an optional constraint on the payment amount.
	PaymentAmount fn.Option[lnwire.MilliSatoshi]

	// PeerID is an optional peer identifier for peer-specific pricing.
	PeerID fn.Option[route.Vertex]

	// RateHint is an optional rate hint to guide pricing.
	RateHint fn.Option[rfqmsg.AssetRate]

	// OracleMetadata is optional metadata to pass to the price oracle.
	OracleMetadata fn.Option[string]

	// Expiry is an optional expiry time for the rate query.
	Expiry fn.Option[time.Time]
}

// ResolveResp captures the portfolio pilot's resolution decision for an RFQ. It
// carries either an accepted asset rate quote or a structured rejection reason.
type ResolveResp struct {
	// outcome holds either the accepted asset rate (left) or the rejection
	// error (right).
	outcome fn.Either[rfqmsg.AssetRate, rfqmsg.RejectErr]
}

// NewAcceptResolveResp builds an acceptance response with the provided asset
// rate quote.
func NewAcceptResolveResp(assetRate rfqmsg.AssetRate) ResolveResp {
	return ResolveResp{
		outcome: fn.NewLeft[rfqmsg.AssetRate, rfqmsg.RejectErr](
			assetRate,
		),
	}
}

// NewRejectResolveResp builds a rejection response that explains why a quote
// cannot be provided.
func NewRejectResolveResp(rejectErr rfqmsg.RejectErr) ResolveResp {
	return ResolveResp{
		outcome: fn.NewRight[rfqmsg.AssetRate, rfqmsg.RejectErr](
			rejectErr,
		),
	}
}

// IsAccept reports whether the response contains an accepted asset rate.
func (r *ResolveResp) IsAccept() bool {
	return r.outcome.IsLeft()
}

// IsReject reports whether the response contains a rejection error.
func (r *ResolveResp) IsReject() bool {
	return r.outcome.IsRight()
}

// WhenAccept executes the callback with the asset rate when the response is an
// acceptance and does nothing otherwise.
func (r *ResolveResp) WhenAccept(pred func(rate rfqmsg.AssetRate)) {
	r.outcome.WhenLeft(pred)
}

// WhenReject executes the callback with the rejection error when the response
// is a rejection and does nothing otherwise.
func (r *ResolveResp) WhenReject(pred func(err rfqmsg.RejectErr)) {
	r.outcome.WhenRight(pred)
}

// PortfolioPilot evaluates RFQs and returns either an accepted asset rate quote
// or a rejection reason.
type PortfolioPilot interface {
	// ResolveRequest resolves a quote request by returning either an
	// acceptable asset rate or a quote rejection error. Errors are reserved
	// for unexpected failures while evaluating the request.
	ResolveRequest(context.Context, rfqmsg.Request) (ResolveResp,
		error)

	// VerifyAcceptQuote verifies that an accepted quote from a peer meets
	// acceptable conditions.
	VerifyAcceptQuote(context.Context, rfqmsg.Accept) (QuoteRespStatus,
		error)

	// QueryAssetRates returns current asset rate information for a given
	// asset and direction. Can be used for rate discovery, outgoing RFQ
	// request construction, or general pricing information.
	QueryAssetRates(context.Context, AssetRateQuery) (rfqmsg.AssetRate,
		error)

	// Close releases any resources held by the portfolio pilot.
	Close() error
}

// InternalPortfolioPilotConfig holds settings for the built-in pilot that uses
// a price oracle for pricing decisions.
type InternalPortfolioPilotConfig struct {
	// PriceOracle supplies pricing data. If nil, the pilot rejects requests
	// as the oracle is considered unavailable.
	PriceOracle PriceOracle

	// ForwardPeerIDToOracle controls whether the requesting peer ID is sent
	// to the oracle for peer-specific pricing. Disabling this avoids
	// sharing caller identity with the oracle.
	ForwardPeerIDToOracle bool

	// AcceptPriceDeviationPpm specifies the maximum allowable price
	// deviation in parts per million (PPM) when verifying accepted quotes.
	// This defines the tolerance threshold for comparing peer quotes
	// against oracle prices.
	AcceptPriceDeviationPpm uint64

	// MinAssetRatesExpiryLifetime specifies the minimum lifetime in
	// seconds for an asset rate expiry to be considered valid.
	MinAssetRatesExpiryLifetime uint64
}

// Validate checks the config for validity.
func (c *InternalPortfolioPilotConfig) Validate() error {
	if c.MinAssetRatesExpiryLifetime == 0 {
		return fmt.Errorf("MinAssetRatesExpiryLifetime must be > 0")
	}

	return nil
}

// InternalPortfolioPilot is the built-in RFQ decision logic that delegates
// pricing to an external price oracle.
type InternalPortfolioPilot struct {
	// cfg holds settings and supporting components for the portfolio pilot.
	cfg InternalPortfolioPilotConfig
}

// NewInternalPortfolioPilot constructs a new pilot using the provided config.
func NewInternalPortfolioPilot(
	cfg InternalPortfolioPilotConfig) (InternalPortfolioPilot, error) {

	var zero InternalPortfolioPilot

	err := cfg.Validate()
	if err != nil {
		return zero, fmt.Errorf("validate internal portfolio pilot "+
			"config: %w", err)
	}

	return InternalPortfolioPilot{
		cfg: cfg,
	}, nil
}

// ResolveRequest resolves a quote request by querying the configured price
// oracle. It accepts with a quote when a valid rate is returned, rejects when
// no oracle is configured, and errors on unexpected oracle failures or missing
// rates.
func (p *InternalPortfolioPilot) ResolveRequest(ctx context.Context,
	request rfqmsg.Request) (ResolveResp, error) {

	var zero ResolveResp

	if p.cfg.PriceOracle == nil {
		return NewRejectResolveResp(
			rfqmsg.ErrPriceOracleUnavailable,
		), nil
	}

	peerID := fn.None[route.Vertex]()
	if p.cfg.ForwardPeerIDToOracle {
		peerID = fn.Some(request.MsgPeer())
	}

	var resp *OracleResponse

	switch req := request.(type) {
	case *rfqmsg.BuyRequest:
		var err error
		resp, err = p.cfg.PriceOracle.QuerySellPrice(
			ctx, req.AssetSpecifier, fn.Some(req.AssetMaxAmt),
			fn.None[lnwire.MilliSatoshi](), req.AssetRateHint,
			peerID, req.PriceOracleMetadata, IntentRecvPayment,
		)
		if err != nil {
			return zero, fmt.Errorf("query sell price: %w", err)
		}

	case *rfqmsg.SellRequest:
		var err error
		resp, err = p.cfg.PriceOracle.QueryBuyPrice(
			ctx, req.AssetSpecifier, fn.None[uint64](),
			fn.Some(req.PaymentMaxAmt), req.AssetRateHint,
			peerID, req.PriceOracleMetadata, IntentPayInvoice,
		)
		if err != nil {
			return zero, fmt.Errorf("query buy price: %w", err)
		}

	default:
		return zero, fmt.Errorf("unsupported request type %T", req)
	}

	//nolint:nilerr
	if resp.Err != nil {
		return zero, fmt.Errorf("price oracle returned error: %w",
			resp.Err)
	}

	return NewAcceptResolveResp(resp.AssetRate), nil
}

// VerifyAcceptQuote verifies that an accepted quote from a peer meets
// acceptable conditions. It validates the quote expiry and checks that the
// peer's proposed rate falls within acceptable tolerance of the oracle price.
func (p *InternalPortfolioPilot) VerifyAcceptQuote(ctx context.Context,
	accept rfqmsg.Accept) (QuoteRespStatus, error) {

	// Extract counter rate from the accept quote message. The counter rate
	// is the rate that the peer is offering.
	counterRate := accept.AcceptedRate()

	// Ensure that the quote expiry time is within acceptable bounds.
	if !p.expiryWithinBounds(counterRate.Expiry) {
		return InvalidExpiryQuoteRespStatus, nil
	}

	if p.cfg.PriceOracle == nil {
		return PriceOracleQueryErrQuoteRespStatus, nil
	}

	// Build peer ID option based on config.
	peerID := fn.None[route.Vertex]()
	if p.cfg.ForwardPeerIDToOracle {
		peerID = fn.Some(accept.MsgPeer())
	}

	// Query the oracle based on the request type. For a buy request (peer
	// selling to us), we query our buy price. For a sell request (peer
	// buying from us), we query our sell price.
	var resp *OracleResponse
	var err error

	req := accept.OriginalRequest()
	switch r := req.(type) {
	case *rfqmsg.BuyRequest:
		resp, err = p.cfg.PriceOracle.QueryBuyPrice(
			ctx, r.AssetSpecifier, fn.Some(r.AssetMaxAmt),
			fn.None[lnwire.MilliSatoshi](), fn.Some(counterRate),
			peerID, r.PriceOracleMetadata, IntentRecvPaymentQualify,
		)
		if err != nil {
			return PriceOracleQueryErrQuoteRespStatus, fmt.Errorf(
				"query buy price from oracle: %w", err,
			)
		}

	case *rfqmsg.SellRequest:
		resp, err = p.cfg.PriceOracle.QuerySellPrice(
			ctx, r.AssetSpecifier, fn.None[uint64](),
			fn.Some(r.PaymentMaxAmt), fn.Some(counterRate),
			peerID, r.PriceOracleMetadata, IntentPayInvoiceQualify,
		)
		if err != nil {
			return PriceOracleQueryErrQuoteRespStatus, fmt.Errorf(
				"query sell price from oracle: %w", err,
			)
		}

	default:
		return PortfolioPilotErrQuoteRespStatus, fmt.Errorf(
			"unknown request type: %T", req,
		)
	}

	//nolint:nilerr
	if resp.Err != nil {
		return PriceOracleQueryErrQuoteRespStatus,
			fmt.Errorf("price oracle returned error: %w", resp.Err)
	}

	// Check if the peer's price is within acceptable tolerance of the
	// oracle's price.
	tolerance := rfqmath.NewBigIntFromUint64(p.cfg.AcceptPriceDeviationPpm)
	acceptablePrice, err := counterRate.Rate.WithinTolerance(
		resp.AssetRate.Rate, tolerance,
	)
	if err != nil {
		return PortfolioPilotErrQuoteRespStatus, fmt.Errorf(
			"tolerance check failed: %w", err,
		)
	}

	if !acceptablePrice {
		return InvalidAssetRatesQuoteRespStatus, nil
	}

	return ValidAcceptQuoteRespStatus, nil
}

// expiryWithinBounds checks if a quote expiry unix timestamp (in seconds) is
// within acceptable bounds. This check ensures that the expiry timestamp is far
// enough in the future for the quote to be useful.
func (p *InternalPortfolioPilot) expiryWithinBounds(expiry time.Time) bool {
	diff := expiry.Unix() - time.Now().Unix()
	return diff >= int64(p.cfg.MinAssetRatesExpiryLifetime)
}

// QueryAssetRates returns current asset rate information by querying the
// configured price oracle based on the transfer direction and query parameters.
func (p *InternalPortfolioPilot) QueryAssetRates(ctx context.Context,
	query AssetRateQuery) (rfqmsg.AssetRate, error) {

	var zero rfqmsg.AssetRate

	if p.cfg.PriceOracle == nil {
		return zero, fmt.Errorf("no price oracle found")
	}

	// Build peer ID option based on config.
	peerID := fn.None[route.Vertex]()
	if p.cfg.ForwardPeerIDToOracle && query.PeerID.IsSome() {
		peerID = query.PeerID
	}

	// Extract metadata string from option.
	metadata := query.OracleMetadata.UnwrapOr("")

	var (
		resp *OracleResponse
		err  error
	)

	// Query the oracle based on the transfer direction using the caller's
	// specified intent to provide the appropriate context.
	switch query.Direction {
	case AssetTransferBuy:
		resp, err = p.cfg.PriceOracle.QueryBuyPrice(
			ctx, query.AssetSpecifier, query.AssetAmount,
			query.PaymentAmount, query.RateHint,
			peerID, metadata, query.Intent,
		)
		if err != nil {
			return zero, fmt.Errorf("query buy price for buy: %w",
				err)
		}

	case AssetTransferSell:
		resp, err = p.cfg.PriceOracle.QuerySellPrice(
			ctx, query.AssetSpecifier, query.AssetAmount,
			query.PaymentAmount, query.RateHint,
			peerID, metadata, query.Intent,
		)
		if err != nil {
			return zero, fmt.Errorf("query sell price for sell: %w",
				err)
		}

	default:
		return zero, fmt.Errorf("unsupported transfer direction: %d",
			query.Direction)
	}

	//nolint:nilerr
	if resp.Err != nil {
		return zero, fmt.Errorf("price oracle returned error: %w",
			resp.Err)
	}

	return resp.AssetRate, nil
}

// Close releases resources held by the internal portfolio pilot. The internal
// pilot is in-memory only, so this is a no-op.
func (p *InternalPortfolioPilot) Close() error {
	return nil
}
