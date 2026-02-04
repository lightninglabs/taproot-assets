package itest

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	pilotrpc "github.com/lightninglabs/taproot-assets/taprpc/portfoliopilotrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// portfolioPilotHarness is a basic integration test RPC portfolio pilot server
// harness.
type portfolioPilotHarness struct {
	pilotrpc.UnimplementedPortfolioPilotServer

	// listenAddr is the host:port the harness listens on.
	listenAddr string

	// grpcListener is the network listener for the gRPC server.
	grpcListener net.Listener

	// grpcServer is the gRPC server instance.
	grpcServer *grpc.Server

	// mu guards the call counts and last request fields.
	mu sync.Mutex

	// resolveCalls is the number of ResolveRequest calls seen.
	resolveCalls int

	// verifyCalls is the number of VerifyAcceptQuote calls seen.
	verifyCalls int

	// queryCalls is the number of QueryAssetRates calls seen.
	queryCalls int

	// lastResolve is the last ResolveRequest seen by the server.
	lastResolve *pilotrpc.ResolveRequestRequest

	// lastVerify is the last VerifyAcceptQuote request seen by the server.
	lastVerify *pilotrpc.VerifyAcceptQuoteRequest

	// lastQuery is the last QueryAssetRates request seen by the server.
	lastQuery *pilotrpc.QueryAssetRatesRequest

	// verifyStatus is the quote verification status returned by the server.
	verifyStatus pilotrpc.QuoteRespStatus
}

// newPortfolioPilotHarness returns a new portfolio pilot harness instance that
// is set to listen on the provided address.
func newPortfolioPilotHarness(listenAddr string) *portfolioPilotHarness {
	return &portfolioPilotHarness{
		listenAddr:   listenAddr,
		verifyStatus: pilotrpc.QuoteRespStatus_VALID_ACCEPT_QUOTE,
	}
}

// start runs the portfolio pilot harness.
func (p *portfolioPilotHarness) start(t *testing.T) {
	// Generate a self-signed certificate. This allows us to use TLS for
	// the gRPC server.
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate TLS certificate: %v", err)
	}

	transportCredentials := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	p.grpcServer = grpc.NewServer(grpc.Creds(transportCredentials))

	serviceAddr := fmt.Sprintf("portfoliopilotrpc://%s", p.listenAddr)
	log.Infof("Starting RPC portfolio pilot service at address: %s\n",
		serviceAddr)

	pilotrpc.RegisterPortfolioPilotServer(p.grpcServer, p)

	go func() {
		var err error
		p.grpcListener, err = net.Listen("tcp", p.listenAddr)
		if err != nil {
			log.Errorf("Error portfolio pilot listening: %v", err)
			return
		}
		if err := p.grpcServer.Serve(p.grpcListener); err != nil {
			log.Errorf("Error portfolio pilot serving: %v", err)
		}
	}()
}

// stop terminates the portfolio pilot harness.
func (p *portfolioPilotHarness) stop() {
	if p.grpcServer != nil {
		p.grpcServer.Stop()
	}
	if p.grpcListener != nil {
		_ = p.grpcListener.Close()
	}
}

// callCounts returns the number of calls received per RPC method.
func (p *portfolioPilotHarness) callCounts() (resolve, verify, query int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.resolveCalls, p.verifyCalls, p.queryCalls
}

// defaultAssetRate returns a default asset rate in RPC form.
func (p *portfolioPilotHarness) defaultAssetRate() (*pilotrpc.AssetRate,
	error) {

	rate := rfqmath.NewBigIntFixedPoint(42_000_160_000, 0)
	expiry := time.Now().Add(5 * time.Minute).UTC()
	assetRate := rfqmsg.NewAssetRate(rate, expiry)

	rpcRate, err := rpcutils.MarshalPortfolioAssetRate(assetRate)
	if err != nil {
		return nil, fmt.Errorf("marshal asset rate: %w", err)
	}

	return rpcRate, nil
}

// ResolveRequest resolves a quote request by returning a fixed asset rate.
func (p *portfolioPilotHarness) ResolveRequest(_ context.Context,
	req *pilotrpc.ResolveRequestRequest) (
	*pilotrpc.ResolveRequestResponse, error) {

	p.mu.Lock()
	p.resolveCalls++
	p.lastResolve = req
	p.mu.Unlock()

	if req == nil {
		return nil, fmt.Errorf("resolve request is nil")
	}

	var hint *pilotrpc.AssetRate
	switch r := req.GetRequest().(type) {
	case *pilotrpc.ResolveRequestRequest_BuyRequest:
		hint = r.BuyRequest.GetAssetRateHint()
	case *pilotrpc.ResolveRequestRequest_SellRequest:
		hint = r.SellRequest.GetAssetRateHint()
	default:
		return nil, fmt.Errorf("unknown request type: %T", r)
	}

	if hint == nil {
		var err error
		hint, err = p.defaultAssetRate()
		if err != nil {
			return nil, fmt.Errorf("default asset rate: %w", err)
		}
	}

	return &pilotrpc.ResolveRequestResponse{
		Result: &pilotrpc.ResolveRequestResponse_Accept{
			Accept: hint,
		},
	}, nil
}

// VerifyAcceptQuote verifies an accepted quote and returns a fixed status.
func (p *portfolioPilotHarness) VerifyAcceptQuote(_ context.Context,
	req *pilotrpc.VerifyAcceptQuoteRequest) (
	*pilotrpc.VerifyAcceptQuoteResponse, error) {

	p.mu.Lock()
	p.verifyCalls++
	p.lastVerify = req
	status := p.verifyStatus
	p.mu.Unlock()

	if req == nil || req.Accept == nil {
		return nil, fmt.Errorf("accept quote is nil")
	}

	return &pilotrpc.VerifyAcceptQuoteResponse{
		Status: status,
	}, nil
}

// QueryAssetRates returns a default asset rate or the provided hint.
func (p *portfolioPilotHarness) QueryAssetRates(_ context.Context,
	req *pilotrpc.QueryAssetRatesRequest) (
	*pilotrpc.QueryAssetRatesResponse, error) {

	p.mu.Lock()
	p.queryCalls++
	p.lastQuery = req
	p.mu.Unlock()

	if req == nil {
		return nil, fmt.Errorf("query request is nil")
	}

	if req.AssetRateHint != nil {
		return &pilotrpc.QueryAssetRatesResponse{
			AssetRate: req.AssetRateHint,
		}, nil
	}

	rpcRate, err := p.defaultAssetRate()
	if err != nil {
		return nil, fmt.Errorf("default asset rate: %w", err)
	}

	return &pilotrpc.QueryAssetRatesResponse{
		AssetRate: rpcRate,
	}, nil
}
