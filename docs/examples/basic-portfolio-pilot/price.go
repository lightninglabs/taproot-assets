// This file contains the reference price: BTC/USD, polled from
// CoinGecko or fixed by flag, from which every rate is derived. The
// ideas it illustrates:
//
//   - A missing or stale price stops trading. There is no fallback
//     rate, since a wrong rate is worse than none.
//   - Rates are asset units per BTC. The asset's decimal display sets
//     the size of a unit, and getting it wrong misprices by a power of
//     ten.
//   - A large move between consecutive fetches is an anomaly in its
//     own right, and halts trading through the breaker.
//   - Prices are exact decimals, never floats.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/lightninglabs/taproot-assets/rfqmath"
)

const (
	// priceRefresh is the interval between live price fetches.
	priceRefresh = 30 * time.Second

	// maxPriceAge is the age after which the live price is stale.
	maxPriceAge = 2 * time.Minute

	// coingeckoURL is the CoinGecko simple-price endpoint.
	coingeckoURL = "https://api.coingecko.com/api/v3" +
		"/simple/price?ids=bitcoin&vs_currencies=usd"
)

// errNoPrice is returned when the reference price is missing or stale.
var errNoPrice = errors.New("reference price unavailable")

// priceFeed holds the BTC/USD reference price. A static price never
// goes stale.
type priceFeed struct {
	// maxJumpPpm is the largest move between consecutive fetched
	// prices that does not call onJump. Zero disables the check.
	maxJumpPpm uint64

	// onJump is called with a description of a larger move.
	onJump func(reason string)

	mu      sync.RWMutex
	btcUSD  *big.Rat
	fetched time.Time
	static  bool
}

// price returns the reference price, or errNoPrice.
func (f *priceFeed) price() (*big.Rat, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.btcUSD == nil ||
		(!f.static && time.Since(f.fetched) > maxPriceAge) {

		return nil, errNoPrice
	}

	return f.btcUSD, nil
}

// update stores a fetched price, calling onJump if it moved more than
// maxJumpPpm from the previous one.
func (f *priceFeed) update(btcUSD *big.Rat) {
	f.mu.Lock()
	prev := f.btcUSD
	f.btcUSD, f.fetched = btcUSD, time.Now()
	f.mu.Unlock()

	if prev == nil || f.maxJumpPpm == 0 {
		return
	}

	// The move exceeds the bound if |new - prev| * 1e6 exceeds
	// maxJumpPpm * prev.
	move := new(big.Rat).Sub(btcUSD, prev)
	move.Abs(move).Mul(move, big.NewRat(1_000_000, 1))
	bound := new(big.Rat).Mul(prev, new(big.Rat).SetUint64(f.maxJumpPpm))
	if move.Cmp(bound) > 0 {
		f.onJump(fmt.Sprintf("BTC/USD moved from %s to %s",
			prev.FloatString(2), btcUSD.FloatString(2)))
	}
}

// poll fetches the live price until the context is cancelled. A failed
// fetch leaves the previous price in place.
func (f *priceFeed) poll(ctx context.Context) {
	ticker := time.NewTicker(priceRefresh)
	defer ticker.Stop()

	for {
		btcUSD, err := fetchBTCPrice(ctx)
		if err != nil {
			log.Printf("Price fetch failed: %v", err)
		} else {
			f.update(btcUSD)
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// fetchBTCPrice fetches the BTC/USD price from CoinGecko.
func fetchBTCPrice(ctx context.Context) (*big.Rat, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, coingeckoURL, nil,
	)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var result struct {
		Bitcoin struct {
			USD json.Number `json:"usd"`
		} `json:"bitcoin"`
	}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(&result); err != nil {
		return nil, err
	}

	return parsePrice(result.Bitcoin.USD.String())
}

// parsePrice parses a positive decimal price.
func parsePrice(s string) (*big.Rat, error) {
	price, ok := new(big.Rat).SetString(s)
	if !ok || price.Sign() <= 0 {
		return nil, fmt.Errorf("invalid price %q", s)
	}

	return price, nil
}

// referenceRate converts a BTC/USD price into asset units per BTC for
// the given decimal display, rounded down.
func referenceRate(btcUSD *big.Rat,
	decimalDisplay int) (rfqmath.BigIntFixedPoint, error) {

	unit := new(big.Int).Exp(
		big.NewInt(10), big.NewInt(int64(decimalDisplay)), nil,
	)
	units := new(big.Rat).Mul(btcUSD, new(big.Rat).SetInt(unit))
	coefficient := new(big.Int).Quo(units.Num(), units.Denom())
	if coefficient.Sign() <= 0 {
		return rfqmath.BigIntFixedPoint{}, errNoPrice
	}

	return rfqmath.BigIntFixedPoint{
		Coefficient: rfqmath.NewBigInt(coefficient),
	}, nil
}

// applySpread moves a rate by spreadPpm, up or down, rounding down.
func applySpread(rate rfqmath.BigIntFixedPoint, spreadPpm uint64,
	up bool) rfqmath.BigIntFixedPoint {

	factor := 1_000_000 - spreadPpm
	if up {
		factor = 1_000_000 + spreadPpm
	}

	rate.Coefficient = rate.Coefficient.
		Mul(rfqmath.NewBigIntFromUint64(factor)).
		Div(rfqmath.NewBigIntFromUint64(1_000_000))

	return rate
}
