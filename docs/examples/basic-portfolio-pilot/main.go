// WARNING: This is a demonstration example only and is NOT
// suitable for production use. Using this code in production
// will almost certainly result in loss of funds. It is
// intended solely to illustrate the PortfolioPilot RPC
// interface.
//
// This example demonstrates a basic RPC portfolio pilot server
// that implements ResolveRequest, VerifyAcceptQuote, and
// QueryAssetRates. The server returns asset rates fetched
// live from CoinGecko (or a static rate if configured),
// supports configurable fill caps, and enforces rate bound,
// min fill, and fill constraint checks on accepted quotes.
//
// Flags:
//
//	-listen             Listen address (default
//	                    "localhost:8096").
//	-rate               Rate coefficient in units/BTC.
//	                    0 (default) fetches live from
//	                    CoinGecko.
//	-fillcap-asset-units  Fill cap for buy orders (asset
//	                    units). 0 = no cap.
//	-fillcap-msat       Fill cap for sell orders (msat).
//	                    0 = no cap.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	"github.com/lightninglabs/taproot-assets/taprpc/portfoliopilotrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

const (
	// defaultListenAddress is the default listening address.
	defaultListenAddress = "localhost:8096"

	// defaultRateCoefficient is the default rate coefficient
	// in units per BTC. This is an arbitrary demo value.
	defaultRateCoefficient = 42_000_160_000
)

// pilotConfig holds the runtime configuration parsed from flags.
type pilotConfig struct {
	listenAddr      string
	rateCoefficient uint64
	fillCapAsset    uint64
	fillCapMsat     uint64
}

// parseFlags parses command-line flags into a pilotConfig.
func parseFlags() pilotConfig {
	cfg := pilotConfig{}

	flag.StringVar(
		&cfg.listenAddr, "listen",
		defaultListenAddress, "listen address (host:port)",
	)
	flag.Uint64Var(
		&cfg.rateCoefficient, "rate", 0,
		"rate coefficient in asset units per BTC "+
			"(0 = fetch live from CoinGecko)",
	)
	flag.Uint64Var(
		&cfg.fillCapAsset, "fillcap-asset-units", 0,
		"fill cap for buy orders (asset units); "+
			"0 = no cap",
	)
	flag.Uint64Var(
		&cfg.fillCapMsat, "fillcap-msat", 0,
		"fill cap for sell orders (msat); 0 = no cap",
	)

	flag.Parse()

	return cfg
}

// coingeckoURL is the CoinGecko simple-price endpoint.
const coingeckoURL = "https://api.coingecko.com/api/v3" +
	"/simple/price?ids=bitcoin&vs_currencies=usd"

// fetchBTCPrice fetches the current BTC/USD price from
// CoinGecko and returns the rate coefficient (price * 100,
// since 1 USDX = 1 cent).
func fetchBTCPrice() (uint64, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(coingeckoURL)
	if err != nil {
		return 0, fmt.Errorf("coingecko request: %w",
			err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf(
			"coingecko status: %d", resp.StatusCode,
		)
	}

	var result struct {
		Bitcoin struct {
			USD float64 `json:"usd"`
		} `json:"bitcoin"`
	}
	if err := json.NewDecoder(resp.Body).Decode(
		&result,
	); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}

	if result.Bitcoin.USD <= 0 {
		return 0, fmt.Errorf("invalid price: %f",
			result.Bitcoin.USD)
	}

	// Price in dollars → coefficient in cents.
	coefficient := uint64(result.Bitcoin.USD * 100)

	return coefficient, nil
}

// rateCache caches the live BTC/USD rate coefficient,
// refreshing from CoinGecko when the TTL expires.
type rateCache struct {
	mu        sync.Mutex
	rate      uint64
	fetchedAt time.Time
	ttl       time.Duration
	fallback  uint64
}

// newRateCache creates a rate cache. If fallback is 0 the
// default demo coefficient is used.
func newRateCache(
	ttl time.Duration, fallback uint64) *rateCache {

	if fallback == 0 {
		fallback = defaultRateCoefficient
	}

	return &rateCache{
		ttl:      ttl,
		fallback: fallback,
	}
}

// getRate returns a fresh rate coefficient (cents/BTC).
func (c *rateCache) getRate() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.fetchedAt.IsZero() &&
		time.Since(c.fetchedAt) < c.ttl {

		return c.rate
	}

	price, err := fetchBTCPrice()
	if err != nil {
		log.Printf("CoinGecko fetch error: %v", err)

		if c.rate != 0 {
			log.Printf("Using stale rate: %d",
				c.rate)
			return c.rate
		}

		log.Printf("Using fallback rate: %d",
			c.fallback)
		return c.fallback
	}

	c.rate = price
	c.fetchedAt = time.Now()
	log.Printf("Fetched live rate: %d (≈$%d/BTC)",
		price, price/100)

	return c.rate
}

// setupLogger sets up the logger to write logs to both stdout and a file.
func setupLogger() {
	// Create a log file.
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	file, err := os.OpenFile(
		"basic-portfolio-pilot-example.log", flags, 0644,
	)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	// Create a multi-writer to write to both stdout and the file.
	multiWriter := io.MultiWriter(os.Stdout, file)

	// Set the output and format of the standard logger.
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags)
}

// makeAssetRate builds an asset rate from the given coefficient.
func makeAssetRate(
	coefficient uint64) (rfqmsg.AssetRate, error) {

	rate := rfqmath.NewBigIntFixedPoint(coefficient, 0)
	expiry := time.Now().Add(5 * time.Minute).UTC()

	return rfqmsg.NewAssetRate(rate, expiry), nil
}

// makeRpcAssetRate returns the asset rate in RPC form.
func makeRpcAssetRate(
	coefficient uint64) (*portfoliopilotrpc.AssetRate, error) {

	assetRate, err := makeAssetRate(coefficient)
	if err != nil {
		return nil, fmt.Errorf("create asset rate: %w", err)
	}

	rpcRate, err := rpcutils.MarshalPortfolioAssetRate(assetRate)
	if err != nil {
		return nil, fmt.Errorf("marshal asset rate: %w", err)
	}

	return rpcRate, nil
}

// RpcPortfolioPilotServer is a basic example RPC portfolio pilot
// server.
type RpcPortfolioPilotServer struct {
	portfoliopilotrpc.UnimplementedPortfolioPilotServer

	cfg   pilotConfig
	cache *rateCache
}

// ResolveRequest resolves an incoming quote request by returning
// either a provided rate hint or the configured rate. When a
// fill cap is configured it is returned as AcceptedMaxAmount.
func (p *RpcPortfolioPilotServer) ResolveRequest(_ context.Context,
	req *portfoliopilotrpc.ResolveRequestRequest) (
	*portfoliopilotrpc.ResolveRequestResponse, error) {

	if req == nil {
		return nil, fmt.Errorf("resolve request is nil")
	}

	var (
		hint    *portfoliopilotrpc.AssetRate
		fillCap uint64
	)
	switch r := req.GetRequest().(type) {
	case *portfoliopilotrpc.ResolveRequestRequest_BuyRequest:
		br := r.BuyRequest
		hint = br.GetAssetRateHint()
		fillCap = p.cfg.fillCapAsset
		log.Printf("ResolveRequest buy: max=%d min=%d "+
			"rate_limit=%v", br.GetAssetMaxAmount(),
			br.GetAssetMinAmount(),
			br.GetAssetRateLimit())
	case *portfoliopilotrpc.ResolveRequestRequest_SellRequest:
		sr := r.SellRequest
		hint = sr.GetAssetRateHint()
		fillCap = p.cfg.fillCapMsat
		log.Printf("ResolveRequest sell: max=%d min=%d "+
			"rate_limit=%v", sr.GetPaymentMaxAmount(),
			sr.GetPaymentMinAmount(),
			sr.GetAssetRateLimit())
	default:
		return nil, fmt.Errorf("unknown request type: %T", r)
	}

	if hint == nil {
		coeff := p.cfg.rateCoefficient
		if p.cache != nil {
			coeff = p.cache.getRate()
		}

		var err error
		hint, err = makeRpcAssetRate(coeff)
		if err != nil {
			return nil, fmt.Errorf("make asset rate: %w",
				err)
		}
	}

	log.Printf("ResolveRequest accepting (fillcap=%d)",
		fillCap)

	return &portfoliopilotrpc.ResolveRequestResponse{
		Result: &portfoliopilotrpc.
			ResolveRequestResponse_Accept{
			Accept: hint,
		},
		AcceptedMaxAmount: fillCap,
	}, nil
}

// amountIsTransportable returns true when amt converts to a
// non-zero result at the given rate. For buy (rateBoundCmp < 0)
// the amount is asset units converting to msat; for sell
// (rateBoundCmp > 0) the amount is msat converting to asset
// units.
func amountIsTransportable(amt uint64,
	rate rfqmath.BigIntFixedPoint, rateBoundCmp int) bool {

	if rateBoundCmp < 0 {
		// Buy: asset units → msat.
		units := rfqmath.FixedPoint[rfqmath.BigInt]{
			Coefficient: rfqmath.NewBigIntFromUint64(
				amt,
			),
			Scale: 0,
		}
		return rfqmath.UnitsToMilliSatoshi(units, rate) != 0
	}

	// Sell: msat → asset units.
	units := rfqmath.MilliSatoshiToUnits(
		lnwire.MilliSatoshi(amt), rate,
	)
	zero := rfqmath.NewBigIntFromUint64(0)

	return !units.Coefficient.Equals(zero)
}

// VerifyAcceptQuote verifies an accepted quote from a peer by
// checking rate bound, min fill, and fill constraints. Returns
// the appropriate QuoteRespStatus.
func (p *RpcPortfolioPilotServer) VerifyAcceptQuote(
	_ context.Context,
	req *portfoliopilotrpc.VerifyAcceptQuoteRequest) (
	*portfoliopilotrpc.VerifyAcceptQuoteResponse, error) {

	if req == nil || req.Accept == nil {
		return nil, fmt.Errorf("accept quote is nil")
	}

	accept := req.Accept
	log.Printf("VerifyAcceptQuote peer=%x", accept.PeerId)

	// Parse accepted rate.
	rpcRate := accept.GetAcceptedRate()
	if rpcRate == nil || rpcRate.GetRate() == nil {
		log.Printf("VerifyAcceptQuote: invalid rate")
		return &portfoliopilotrpc.VerifyAcceptQuoteResponse{
			Status: portfoliopilotrpc.
				QuoteRespStatus_INVALID_ASSET_RATES,
		}, nil
	}
	acceptedRate, err := rpcutils.UnmarshalPortfolioFixedPoint(
		rpcRate.GetRate(),
	)
	if err != nil {
		log.Printf("VerifyAcceptQuote: unmarshal rate: %v",
			err)
		return &portfoliopilotrpc.VerifyAcceptQuoteResponse{
			Status: portfoliopilotrpc.
				QuoteRespStatus_INVALID_ASSET_RATES,
		}, nil
	}

	// Extract constraints based on request type.
	var (
		minAmount    uint64
		maxAmount    uint64
		rateLimit    *portfoliopilotrpc.FixedPoint
		rateBoundCmp int
		isFOK        bool
	)
	switch r := accept.GetRequest().(type) {
	case *portfoliopilotrpc.AcceptedQuote_BuyRequest:
		br := r.BuyRequest
		minAmount = br.GetAssetMinAmount()
		maxAmount = br.GetAssetMaxAmount()
		rateLimit = br.GetAssetRateLimit()
		rateBoundCmp = -1 // floor
		isFOK = br.GetExecutionPolicy() ==
			portfoliopilotrpc.ExecutionPolicy_EXECUTION_POLICY_FOK
	case *portfoliopilotrpc.AcceptedQuote_SellRequest:
		sr := r.SellRequest
		minAmount = sr.GetPaymentMinAmount()
		maxAmount = sr.GetPaymentMaxAmount()
		rateLimit = sr.GetAssetRateLimit()
		rateBoundCmp = 1 // ceiling
		isFOK = sr.GetExecutionPolicy() ==
			portfoliopilotrpc.ExecutionPolicy_EXECUTION_POLICY_FOK
	default:
		return nil, fmt.Errorf(
			"unknown request type: %T", r,
		)
	}

	// Check expiry.
	if rpcRate.GetExpiryTimestamp() > 0 {
		expiry := time.Unix(
			int64(rpcRate.GetExpiryTimestamp()), 0,
		)
		if time.Now().After(expiry) {
			log.Printf("VerifyAcceptQuote: expired "+
				"at %v", expiry)
			return &portfoliopilotrpc.
				VerifyAcceptQuoteResponse{
				Status: portfoliopilotrpc.
					QuoteRespStatus_INVALID_EXPIRY,
			}, nil
		}
	}

	// Check rate bound: buy requires accepted >= limit,
	// sell requires accepted <= limit.
	if rateLimit != nil {
		limit, err := rpcutils.UnmarshalPortfolioFixedPoint(
			rateLimit,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"unmarshal rate limit: %w", err,
			)
		}
		if acceptedRate.Cmp(*limit) == rateBoundCmp {
			log.Printf("VerifyAcceptQuote: rate bound "+
				"miss (accepted=%v limit=%v cmp=%d)",
				acceptedRate, *limit, rateBoundCmp)
			return &portfoliopilotrpc.
				VerifyAcceptQuoteResponse{
				Status: portfoliopilotrpc.
					QuoteRespStatus_RATE_BOUND_MISS,
			}, nil
		}
	}

	// FOK: full max amount must be transportable.
	if isFOK && !amountIsTransportable(
		maxAmount, *acceptedRate, rateBoundCmp,
	) {

		log.Printf("VerifyAcceptQuote: FOK not viable "+
			"(max=%d)", maxAmount)
		return &portfoliopilotrpc.VerifyAcceptQuoteResponse{
			Status: portfoliopilotrpc.
				QuoteRespStatus_FOK_NOT_VIABLE,
		}, nil
	}

	// Fill must not exceed the request max.
	fillAmt := accept.GetAcceptedMaxAmount()
	if fillAmt > 0 && fillAmt > maxAmount {
		log.Printf("VerifyAcceptQuote: fill %d > max %d",
			fillAmt, maxAmount)
		return &portfoliopilotrpc.VerifyAcceptQuoteResponse{
			Status: portfoliopilotrpc.
				QuoteRespStatus_FILL_EXCEEDS_MAX,
		}, nil
	}

	// FOK + fill cap: if cap < max, reject.
	if isFOK && fillAmt > 0 && fillAmt < maxAmount {
		log.Printf("VerifyAcceptQuote: FOK fill cap "+
			"%d < max %d", fillAmt, maxAmount)
		return &portfoliopilotrpc.VerifyAcceptQuoteResponse{
			Status: portfoliopilotrpc.
				QuoteRespStatus_FOK_NOT_VIABLE,
		}, nil
	}

	// Check min fill is transportable at the accepted rate.
	if minAmount > 0 && !amountIsTransportable(
		minAmount, *acceptedRate, rateBoundCmp,
	) {

		log.Printf("VerifyAcceptQuote: min fill not met "+
			"(min=%d)", minAmount)
		return &portfoliopilotrpc.VerifyAcceptQuoteResponse{
			Status: portfoliopilotrpc.
				QuoteRespStatus_MIN_FILL_NOT_MET,
		}, nil
	}

	// Check fill constraints: if a fill cap was negotiated,
	// it must satisfy the minimum.
	if fillAmt > 0 && minAmount > 0 && fillAmt < minAmount {
		log.Printf("VerifyAcceptQuote: fill %d < min %d",
			fillAmt, minAmount)
		return &portfoliopilotrpc.VerifyAcceptQuoteResponse{
			Status: portfoliopilotrpc.
				QuoteRespStatus_MIN_FILL_NOT_MET,
		}, nil
	}

	log.Printf("VerifyAcceptQuote: valid")
	return &portfoliopilotrpc.VerifyAcceptQuoteResponse{
		Status: portfoliopilotrpc.
			QuoteRespStatus_VALID_ACCEPT_QUOTE,
	}, nil
}

// QueryAssetRates returns the configured asset rate, or the
// provided hint if one is given.
func (p *RpcPortfolioPilotServer) QueryAssetRates(
	_ context.Context,
	req *portfoliopilotrpc.QueryAssetRatesRequest) (
	*portfoliopilotrpc.QueryAssetRatesResponse, error) {

	if req == nil {
		return nil, fmt.Errorf("query request is nil")
	}

	if req.AssetRateHint != nil {
		log.Print("QueryAssetRates using provided hint")
		return &portfoliopilotrpc.QueryAssetRatesResponse{
			AssetRate: req.AssetRateHint,
		}, nil
	}

	coeff := p.cfg.rateCoefficient
	if p.cache != nil {
		coeff = p.cache.getRate()
	}

	rpcRate, err := makeRpcAssetRate(coeff)
	if err != nil {
		return nil, fmt.Errorf("make asset rate: %w", err)
	}

	log.Print("QueryAssetRates returning configured rate")
	return &portfoliopilotrpc.QueryAssetRatesResponse{
		AssetRate: rpcRate,
	}, nil
}

// startService starts the given RPC server and blocks until the
// server is shut down.
func startService(grpcServer *grpc.Server, cfg pilotConfig) error {
	serviceAddr := fmt.Sprintf(
		"portfoliopilotrpc://%s", cfg.listenAddr,
	)

	var cache *rateCache
	if cfg.rateCoefficient == 0 {
		cache = newRateCache(
			30*time.Second, 0,
		)
		log.Printf("Starting portfolio pilot at "+
			"%s (rate=live, fillcap_asset=%d, "+
			"fillcap_msat=%d)",
			serviceAddr, cfg.fillCapAsset,
			cfg.fillCapMsat)
	} else {
		log.Printf("Starting portfolio pilot at "+
			"%s (rate=%d, fillcap_asset=%d, "+
			"fillcap_msat=%d)",
			serviceAddr, cfg.rateCoefficient,
			cfg.fillCapAsset, cfg.fillCapMsat)
	}

	server := &RpcPortfolioPilotServer{
		cfg:   cfg,
		cache: cache,
	}
	portfoliopilotrpc.RegisterPortfolioPilotServer(
		grpcServer, server,
	)

	grpcListener, err := net.Listen("tcp", cfg.listenAddr)
	if err != nil {
		return fmt.Errorf(
			"RPC server unable to listen on %s: %w",
			cfg.listenAddr, err,
		)
	}
	if err := grpcServer.Serve(grpcListener); err != nil {
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return fmt.Errorf("RPC server failed: %w", err)
	}

	return nil
}

// generateSelfSignedCert creates a self-signed TLS certificate and private
// key.
func generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate ECDSA key: %w",
			err)
	}

	keyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"basic-portfolio-pilot"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour), // Valid for 1 day

		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader, &template, &template, &privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w",
			err)
	}

	privateKeyBits, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal ECDSA key: %w",
			err)
	}

	certPEM := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: certDER},
	)
	keyPEM := pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBits},
	)

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load key pair: %w", err)
	}

	return tlsCert, nil
}

// main runs the example RPC portfolio pilot server.
func main() {
	cfg := parseFlags()
	setupLogger()

	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate TLS cert: %v", err)
	}

	serverKeepalive := keepalive.ServerParameters{
		Time:              time.Minute,
		Timeout:           20 * time.Second,
		MaxConnectionIdle: 24 * time.Hour,
	}
	clientKeepalive := keepalive.EnforcementPolicy{
		PermitWithoutStream: true,
		MinTime:             5 * time.Second,
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	backendService := grpc.NewServer(
		grpc.Creds(creds),
		grpc.KeepaliveParams(serverKeepalive),
		grpc.KeepaliveEnforcementPolicy(clientKeepalive),
	)

	errChan := make(chan error, 1)
	go func() {
		errChan <- startService(backendService, cfg)
	}()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signalChan)

	select {
	case err = <-errChan:
		if err != nil {
			log.Fatalf("Start service error: %v", err)
		}

	case sig := <-signalChan:
		log.Printf("Shutting down on signal: %v", sig)
		backendService.GracefulStop()
		if err = <-errChan; err != nil {
			log.Printf("Shutdown error: %v", err)
		}
	}
}
