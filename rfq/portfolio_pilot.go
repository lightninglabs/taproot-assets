package rfq

import (
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

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
	// ResolveBuyRequest resolves a buy request by returning either an
	// acceptable asset rate or a quote rejection error. Errors are reserved
	// for unexpected failures while evaluating the request.
	ResolveBuyRequest(context.Context, rfqmsg.BuyRequest) (ResolveResp,
		error)
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
}

// InternalPortfolioPilot is the built-in RFQ decision logic that delegates
// pricing to an external price oracle.
type InternalPortfolioPilot struct {
	// cfg holds settings and supporting components for the portfolio pilot.
	cfg InternalPortfolioPilotConfig
}

// NewInternalPortfolioPilot constructs a new pilot using the provided config.
func NewInternalPortfolioPilot(
	cfg InternalPortfolioPilotConfig) *InternalPortfolioPilot {

	return &InternalPortfolioPilot{
		cfg: cfg,
	}
}

// ResolveBuyRequest resolves a buy request by querying the configured price
// oracle. It accepts with a quote when a valid rate is returned, rejects when
// no oracle is configured, and errors on unexpected oracle failures or missing
// rates.
func (p *InternalPortfolioPilot) ResolveBuyRequest(ctx context.Context,
	request rfqmsg.BuyRequest) (ResolveResp, error) {

	var zero ResolveResp

	peerID := fn.None[route.Vertex]()
	if p.cfg.ForwardPeerIDToOracle {
		peerID = fn.Some(request.Peer)
	}

	if p.cfg.PriceOracle == nil {
		return NewRejectResolveResp(
			rfqmsg.ErrPriceOracleUnavailable,
		), nil
	}

	resp, err := p.cfg.PriceOracle.QuerySellPrice(
		ctx, request.AssetSpecifier, fn.Some(request.AssetMaxAmt),
		fn.None[lnwire.MilliSatoshi](), request.AssetRateHint, peerID,
		request.PriceOracleMetadata, IntentRecvPayment,
	)
	if err != nil {
		return zero, fmt.Errorf("query sell price: %w", err)
	}

	if resp.Err != nil {
		return zero, fmt.Errorf("price oracle returned error: %w",
			resp.Err)
	}

	if resp.AssetRate.Rate.Coefficient.ToUint64() == 0 {
		return zero, fmt.Errorf("price oracle did not specify an " +
			"asset rate")
	}

	return NewAcceptResolveResp(resp.AssetRate), nil
}
