// This file contains the circuit breaker. It wraps the pricing pilot in
// another implementation of the same service, so it sees every call and
// every answer, and runs trading at one of three levels: normal,
// degraded or halted. The ideas it illustrates:
//
//   - Soft signals degrade trading, and the degradation clears by
//     itself. Hard signals halt trading until an operator intervenes.
//   - The halt is a file. It survives restarts, records the reason,
//     and lets an operator halt trading by creating it.
//   - A halt stops new quotes only. tapd honors quotes already given
//     until they expire, so exposure counts every unexpired quote.
//   - Repeated peer quotes far from our price mean either a peer
//     probing us or our own price being wrong. Either warrants a halt.
//
// Exposure is held in memory, so a restart forgets quotes that are
// still valid and allows another full limit of quotes. A production
// pilot would persist its quotes, or rebuild them from tapd, before
// quoting again.

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math"
	"os"
	"sync"
	"time"

	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	pilotrpc "github.com/lightninglabs/taproot-assets/taprpc/portfoliopilotrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// haltFile is the name of the halt file in the data directory.
	haltFile = "basic-portfolio-pilot.halt"

	// badQuoteWindow is the window over which out-of-tolerance peer
	// quotes are counted.
	badQuoteWindow = 10 * time.Minute
)

// breaker wraps a pilot and sets the trading level:
//
//   - Normal: requests pass to the pilot.
//   - Degraded: set by the monitor, and cleared when its conditions
//     clear. The pilot doubles its spread, and requests on a blocked
//     side are rejected.
//   - Halted: while the halt file exists. All requests are rejected.
//
// The breaker creates the halt file, recording the reason, when a quote
// would take the exposure of its unexpired quotes above maxExposure,
// after maxBadQuotes peer quotes outside tolerance within
// badQuoteWindow, and when trip is called by the price feed or the
// monitor. Trading resumes when an operator removes the file. Keeping
// the halt in a file makes it survive restarts and lets an operator
// halt by creating the file.
//
// A halt stops new quotes only. tapd honors quotes already given until
// they expire, which is why exposure counts every unexpired quote.
type breaker struct {
	pilotrpc.UnimplementedPortfolioPilotServer

	inner pilotrpc.PortfolioPilotServer

	// haltPath is the path of the halt file.
	haltPath string

	// maxExposure is the limit, in asset units, on the sum of the
	// maximum amounts of unexpired quotes.
	maxExposure uint64

	// maxBadQuotes is the number of peer quotes outside tolerance
	// within badQuoteWindow that trips the breaker. Zero disables the
	// check.
	maxBadQuotes int

	// mu guards the fields below.
	mu sync.Mutex

	// quotes are the accepted quotes counted towards exposure, held in
	// memory only.
	quotes []issuedQuote

	// badQuotes are the times of recent peer quotes outside tolerance.
	badQuotes []time.Time

	// degradedReason is non-empty while trading is degraded.
	degradedReason string

	// blockBuy and blockSell reject buy and sell requests while
	// trading is degraded.
	blockBuy, blockSell bool
}

// issuedQuote is a quote counted towards the outstanding exposure.
type issuedQuote struct {
	units  uint64
	expiry time.Time
}

// halted returns true unless the halt file is known not to exist, so a
// file that cannot be checked counts as present.
func (b *breaker) halted() bool {
	_, err := os.Stat(b.haltPath)
	return !errors.Is(err, fs.ErrNotExist)
}

// trip creates the halt file, recording the reason. The process exits
// if the file cannot be written.
func (b *breaker) trip(reason string) {
	log.Printf("Breaker tripped: %s", reason)

	line := fmt.Sprintf("%s %s\n", time.Now().UTC().Format(time.RFC3339),
		reason)
	if err := os.WriteFile(b.haltPath, []byte(line), 0600); err != nil {
		log.Fatalf("Unable to write halt file: %v", err)
	}
}

// setDegraded degrades trading for the given reason, blocking the given
// sides, or returns it to normal if the reason is empty.
func (b *breaker) setDegraded(reason string, blockBuy, blockSell bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if reason != b.degradedReason {
		if reason == "" {
			log.Printf("Trading normal")
		} else {
			log.Printf("Trading degraded: %s", reason)
		}
	}

	b.degradedReason = reason
	b.blockBuy, b.blockSell = blockBuy, blockSell
}

// degraded returns true while trading is degraded.
func (b *breaker) degraded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.degradedReason != ""
}

// blocked returns true if the request is on a side blocked while
// degraded.
func (b *breaker) blocked(req *pilotrpc.ResolveRequestRequest) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if req.GetBuyRequest() != nil {
		return b.blockBuy
	}

	return b.blockSell
}

var (
	// halt is the rejection sent while halted.
	halt = rfqmsg.NewRejectErr("trading halted")

	// floor is the rejection sent for a blocked side.
	floor = rfqmsg.NewRejectErr("inventory floor reached")
)

// ResolveRequest passes the request to the inner pilot unless trading
// is halted or its side is blocked, and counts accepted quotes towards
// the exposure limit.
func (b *breaker) ResolveRequest(ctx context.Context,
	req *pilotrpc.ResolveRequestRequest) (
	*pilotrpc.ResolveRequestResponse, error) {

	if b.halted() {
		return reject(halt), nil
	}

	if b.blocked(req) {
		return reject(floor), nil
	}

	resp, err := b.inner.ResolveRequest(ctx, req)
	if err != nil || resp.GetAccept() == nil {
		return resp, err
	}

	units, err := quoteUnits(req, resp)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Drop expired quotes and sum the rest.
	now := time.Now()
	var exposure uint64
	live := b.quotes[:0]
	for _, q := range b.quotes {
		if q.expiry.After(now) {
			live = append(live, q)
			exposure += q.units
		}
	}
	b.quotes = live

	// Exposure never exceeds maxExposure, so the subtraction cannot
	// wrap.
	if units > b.maxExposure-exposure {
		b.trip(fmt.Sprintf("quote for %d units would take exposure "+
			"from %d above %d", units, exposure, b.maxExposure))

		return reject(halt), nil
	}

	expiry := resp.GetAccept().GetExpiryTimestamp()
	b.quotes = append(b.quotes, issuedQuote{
		units:  units,
		expiry: time.Unix(int64(expiry), 0),
	})

	return resp, nil
}

// quoteUnits returns the most asset units an accepted quote can move. A
// zero fill cap means the request maximum. Sell request amounts are in
// msat, so they are converted at the quoted rate.
func quoteUnits(req *pilotrpc.ResolveRequestRequest,
	resp *pilotrpc.ResolveRequestResponse) (uint64, error) {

	maxAmt := resp.GetAcceptedMaxAmount()

	switch r := req.GetRequest().(type) {
	case *pilotrpc.ResolveRequestRequest_BuyRequest:
		if maxAmt == 0 {
			maxAmt = r.BuyRequest.GetAssetMaxAmount()
		}

		return maxAmt, nil

	case *pilotrpc.ResolveRequestRequest_SellRequest:
		if maxAmt == 0 {
			maxAmt = r.SellRequest.GetPaymentMaxAmount()
		}

		rate, err := rpcutils.UnmarshalPortfolioFixedPoint(
			resp.GetAccept().GetRate(),
		)
		if err != nil {
			return 0, err
		}

		units, ok := rfqmath.MilliSatoshiToUnits(
			lnwire.MilliSatoshi(maxAmt), *rate,
		).ScaleTo(0).ToUint64Checked()
		if !ok {
			return math.MaxUint64, nil
		}

		return units, nil

	default:
		return 0, fmt.Errorf("unknown request type %T", r)
	}
}

// VerifyAcceptQuote passes the quote to the inner pilot while trading
// is not halted, and counts quotes outside tolerance.
func (b *breaker) VerifyAcceptQuote(ctx context.Context,
	req *pilotrpc.VerifyAcceptQuoteRequest) (
	*pilotrpc.VerifyAcceptQuoteResponse, error) {

	if b.halted() {
		return &pilotrpc.VerifyAcceptQuoteResponse{
			Status: pilotrpc.QuoteRespStatus_PORTFOLIO_PILOT_ERR,
		}, nil
	}

	resp, err := b.inner.VerifyAcceptQuote(ctx, req)
	if err != nil || b.maxBadQuotes == 0 || resp.GetStatus() !=
		pilotrpc.QuoteRespStatus_INVALID_ASSET_RATES {

		return resp, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	recent := b.badQuotes[:0]
	for _, t := range b.badQuotes {
		if now.Sub(t) < badQuoteWindow {
			recent = append(recent, t)
		}
	}
	b.badQuotes = append(recent, now)

	if len(b.badQuotes) >= b.maxBadQuotes {
		b.trip(fmt.Sprintf("%d peer quotes outside tolerance within "+
			"%v", len(b.badQuotes), badQuoteWindow))
		b.badQuotes = nil
	}

	return resp, nil
}

// QueryAssetRates passes the query to the inner pilot while trading is
// not halted.
func (b *breaker) QueryAssetRates(ctx context.Context,
	req *pilotrpc.QueryAssetRatesRequest) (
	*pilotrpc.QueryAssetRatesResponse, error) {

	if b.halted() {
		return nil, status.Error(codes.Unavailable, "trading halted")
	}

	return b.inner.QueryAssetRates(ctx, req)
}
