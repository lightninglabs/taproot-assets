// This file contains the pricing pilot, which implements the three
// PortfolioPilot calls. The ideas it illustrates:
//
//   - Quotes come from our own reference price, never from the
//     requester. A request's rate hint is chosen by the peer, so it is
//     ignored.
//   - Quotes carry a spread in our favour: fewer asset units per BTC
//     when a peer buys the asset from us, more when a peer sells it.
//   - The requester's limit-order constraints are checked before
//     quoting, and our own request's constraints before accepting a
//     peer's quote, with the same rfq helpers tapd's built-in pilot
//     uses.
//   - A peer's quote is accepted only if it is close to our reference
//     rate and has enough time left. With an external pilot, tapd runs
//     no such check itself.
//   - Policy outcomes are rejects and statuses, not errors. An error
//     means the pilot failed to evaluate the call.

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	pilotrpc "github.com/lightninglabs/taproot-assets/taprpc/portfoliopilotrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// minQuoteLifetime is the minimum remaining lifetime of a peer's quote,
// matching tapd's internal pilot.
const minQuoteLifetime = 10 * time.Second

// pilot quotes the reference rate moved by a spread and checks peer
// quotes against the reference rate.
type pilot struct {
	pilotrpc.UnimplementedPortfolioPilotServer

	cfg  config
	feed *priceFeed

	// degraded reports whether trading is degraded, which doubles the
	// spread. Nil means never.
	degraded func() bool
}

// assetSupported returns true if the specifier names the configured
// asset. tapd sends the raw byte forms of the specifier.
func (p *pilot) assetSupported(spec *pilotrpc.AssetSpecifier) bool {
	if len(p.cfg.assetID) > 0 {
		return bytes.Equal(spec.GetAssetId(), p.cfg.assetID)
	}

	return bytes.Equal(spec.GetGroupKey(), p.cfg.groupKey)
}

// rfqSpecifier returns the configured asset as an rfqrpc specifier.
func (p *pilot) rfqSpecifier() *rfqrpc.AssetSpecifier {
	if len(p.cfg.assetID) > 0 {
		return &rfqrpc.AssetSpecifier{
			Id: &rfqrpc.AssetSpecifier_AssetId{
				AssetId: p.cfg.assetID,
			},
		}
	}

	return &rfqrpc.AssetSpecifier{
		Id: &rfqrpc.AssetSpecifier_GroupKey{GroupKey: p.cfg.groupKey},
	}
}

// assetBalance returns the local balance of the configured asset in an
// asset channel. A channel can hold several asset IDs, so only tranches
// of the configured asset ID count. A grouped channel holds members of
// its group only, so all of it counts if the group matches.
func (p *pilot) assetBalance(c *rfqmsg.JsonAssetChannel) uint64 {
	if len(p.cfg.groupKey) > 0 {
		if c.GroupKey != hex.EncodeToString(p.cfg.groupKey) {
			return 0
		}

		return c.LocalBalance
	}

	var balance uint64
	for _, t := range c.LocalAssets {
		if t.AssetID == hex.EncodeToString(p.cfg.assetID) {
			balance += t.Amount
		}
	}

	return balance
}

// referenceRate returns the current reference rate.
func (p *pilot) referenceRate() (rfqmath.BigIntFixedPoint, error) {
	btcUSD, err := p.feed.price()
	if err != nil {
		return rfqmath.BigIntFixedPoint{}, err
	}

	return referenceRate(btcUSD, p.cfg.decimalDisplay)
}

// assetRate returns an RPC asset rate expiring after the quote
// lifetime.
func (p *pilot) assetRate(
	rate rfqmath.BigIntFixedPoint) *pilotrpc.AssetRate {

	return &pilotrpc.AssetRate{
		Rate: rpcutils.MarshalPortfolioFixedPoint(rate),
		ExpiryTimestamp: uint64(
			time.Now().Add(p.cfg.quoteLifetime).Unix(),
		),
	}
}

// reject returns a ResolveRequest rejection.
func reject(r rfqmsg.RejectErr) *pilotrpc.ResolveRequestResponse {
	log.Printf("ResolveRequest: reject: %v", r)

	return &pilotrpc.ResolveRequestResponse{
		Result: &pilotrpc.ResolveRequestResponse_Reject{
			Reject: rfq.MarshalPortfolioRejectErr(r),
		},
	}
}

// ResolveRequest quotes the reference rate moved by the spread, capped
// by the fill cap, if the quote meets the requester's constraints.
func (p *pilot) ResolveRequest(_ context.Context,
	req *pilotrpc.ResolveRequestRequest) (
	*pilotrpc.ResolveRequestResponse, error) {

	var (
		rfqID    []byte
		spec     *pilotrpc.AssetSpecifier
		cons     rfqmsg.RequestConstraints
		fillCap  uint64
		spreadUp bool
		err      error
	)

	// A buy request asks us to sell the asset, so the spread lowers
	// the rate. A sell request asks us to buy it, so the spread raises
	// it. Rate hints are ignored.
	switch r := req.GetRequest().(type) {
	case *pilotrpc.ResolveRequestRequest_BuyRequest:
		rfqID = r.BuyRequest.GetRfqId()
		spec = r.BuyRequest.GetAssetSpecifier()
		fillCap = p.cfg.fillCapAsset
		cons, err = rpcutils.UnmarshalPortfolioBuyConstraints(
			r.BuyRequest,
		)

	case *pilotrpc.ResolveRequestRequest_SellRequest:
		rfqID = r.SellRequest.GetRfqId()
		spec = r.SellRequest.GetAssetSpecifier()
		fillCap = p.cfg.fillCapMsat
		spreadUp = true
		cons, err = rpcutils.UnmarshalPortfolioSellConstraints(
			r.SellRequest,
		)

	default:
		return nil, fmt.Errorf("unknown request type %T", r)
	}
	if err != nil {
		return nil, err
	}

	if !p.assetSupported(spec) {
		return reject(rfqmsg.NewRejectErr("unsupported asset")), nil
	}

	ref, err := p.referenceRate()
	//nolint:nilerr
	if err != nil {
		return reject(rfqmsg.ErrPriceOracleUnavailable), nil
	}

	spread := p.cfg.spreadPpm
	if p.degraded != nil && p.degraded() {
		spread *= 2
	}
	rate := applySpread(ref, spread, spreadUp)

	fill := fn.None[uint64]()
	if fillCap > 0 && fillCap < cons.MaxAmount {
		fill = fn.Some(fillCap)
	}

	s := rfq.CheckConstraints(cons, rate, fill)
	if s != rfq.ValidAcceptQuoteRespStatus {
		return reject(rfq.RejectForStatus(s)), nil
	}

	// The RFQ ID ties the quote to the swaps tapd later settles
	// against it.
	log.Printf("ResolveRequest: accept: rfq_id=%x rate=%v fill=%v",
		rfqID, rate, fill)

	return &pilotrpc.ResolveRequestResponse{
		Result: &pilotrpc.ResolveRequestResponse_Accept{
			Accept: p.assetRate(rate),
		},
		AcceptedMaxAmount: fill.UnwrapOr(0),
	}, nil
}

// verify checks a peer's quote: its remaining lifetime, its deviation
// from the reference rate, and the constraints of our request.
func (p *pilot) verify(
	accept *pilotrpc.AcceptedQuote) (rfq.QuoteRespStatus, error) {

	rate, err := rpcutils.UnmarshalPortfolioAssetRate(
		accept.GetAcceptedRate(),
	)
	//nolint:nilerr
	if err != nil {
		return rfq.InvalidAssetRatesQuoteRespStatus, nil
	}

	if time.Until(rate.Expiry) < minQuoteLifetime {
		return rfq.InvalidExpiryQuoteRespStatus, nil
	}

	var (
		spec *pilotrpc.AssetSpecifier
		cons rfqmsg.RequestConstraints
	)
	switch r := accept.GetRequest().(type) {
	case *pilotrpc.AcceptedQuote_BuyRequest:
		spec = r.BuyRequest.GetAssetSpecifier()
		cons, err = rpcutils.UnmarshalPortfolioBuyConstraints(
			r.BuyRequest,
		)

	case *pilotrpc.AcceptedQuote_SellRequest:
		spec = r.SellRequest.GetAssetSpecifier()
		cons, err = rpcutils.UnmarshalPortfolioSellConstraints(
			r.SellRequest,
		)

	default:
		return 0, fmt.Errorf("unknown request type %T", r)
	}
	if err != nil {
		return 0, err
	}

	if !p.assetSupported(spec) {
		return rfq.PriceOracleQueryErrQuoteRespStatus, nil
	}

	ref, err := p.referenceRate()
	//nolint:nilerr
	if err != nil {
		return rfq.PriceOracleQueryErrQuoteRespStatus, nil
	}

	ok, err := rate.Rate.WithinTolerance(
		ref, rfqmath.NewBigIntFromUint64(p.cfg.maxDeviationPpm),
	)
	//nolint:nilerr
	if err != nil || !ok {
		return rfq.InvalidAssetRatesQuoteRespStatus, nil
	}

	fill := fn.None[uint64]()
	if accept.GetAcceptedMaxAmount() > 0 {
		fill = fn.Some(accept.GetAcceptedMaxAmount())
	}

	return rfq.CheckConstraints(cons, rate.Rate, fill), nil
}

// VerifyAcceptQuote verifies a peer's quote for one of our requests.
func (p *pilot) VerifyAcceptQuote(_ context.Context,
	req *pilotrpc.VerifyAcceptQuoteRequest) (
	*pilotrpc.VerifyAcceptQuoteResponse, error) {

	s, err := p.verify(req.GetAccept())
	if err != nil {
		return nil, err
	}

	log.Printf("VerifyAcceptQuote: %v", s)

	rpcStatus, err := rfq.MarshalPortfolioQuoteRespStatus(s)
	if err != nil {
		return nil, err
	}

	return &pilotrpc.VerifyAcceptQuoteResponse{Status: rpcStatus}, nil
}

// QueryAssetRates returns the reference rate. Rate hints are ignored.
func (p *pilot) QueryAssetRates(_ context.Context,
	req *pilotrpc.QueryAssetRatesRequest) (
	*pilotrpc.QueryAssetRatesResponse, error) {

	if !p.assetSupported(req.GetAssetSpecifier()) {
		return nil, status.Error(codes.NotFound, "unsupported asset")
	}

	ref, err := p.referenceRate()
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}

	return &pilotrpc.QueryAssetRatesResponse{
		AssetRate: p.assetRate(ref),
	}, nil
}
