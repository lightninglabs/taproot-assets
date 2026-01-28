// This example demonstrates a basic RPC portfolio pilot server that implements
// ResolveRequest, VerifyAcceptQuote, and QueryAssetRates. The server listens on
// localhost:8096 and returns fixed asset rates for demonstration purposes.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	"github.com/lightninglabs/taproot-assets/taprpc/portfoliopilotrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

const (
	// serviceListenAddress is the listening address of the service.
	serviceListenAddress = "localhost:8096"

	// defaultRateCoefficient is the default rate coefficient used for the
	// fixed asset rate. This is an arbitrary demo value, not a live price.
	defaultRateCoefficient = 42_000_160_000
)

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

// defaultAssetRate returns a fixed asset rate with a short expiry window.
func defaultAssetRate() (rfqmsg.AssetRate, error) {
	rate := rfqmath.NewBigIntFixedPoint(defaultRateCoefficient, 0)
	expiry := time.Now().Add(5 * time.Minute).UTC()

	return rfqmsg.NewAssetRate(rate, expiry), nil
}

// defaultRpcAssetRate returns the fixed asset rate in RPC form.
func defaultRpcAssetRate() (*portfoliopilotrpc.AssetRate, error) {
	assetRate, err := defaultAssetRate()
	if err != nil {
		return nil, fmt.Errorf("create default asset rate: %w", err)
	}

	rpcRate, err := rpcutils.MarshalPortfolioAssetRate(assetRate)
	if err != nil {
		return nil, fmt.Errorf("marshal default asset rate: %w", err)
	}

	return rpcRate, nil
}

// RpcPortfolioPilotServer is a basic example RPC portfolio pilot server.
type RpcPortfolioPilotServer struct {
	// UnimplementedPortfolioPilotServer enables forward compatibility.
	portfoliopilotrpc.UnimplementedPortfolioPilotServer
}

// ResolveRequest resolves an incoming quote request by returning either a
// provided rate hint or a fixed default rate. This example always accepts
// requests; real implementations should apply business-specific rules.
func (p *RpcPortfolioPilotServer) ResolveRequest(_ context.Context,
	req *portfoliopilotrpc.ResolveRequestRequest) (
	*portfoliopilotrpc.ResolveRequestResponse, error) {

	if req == nil {
		return nil, fmt.Errorf("resolve request is nil")
	}

	// If a rate hint was provided, accept it as-is.
	var hint *portfoliopilotrpc.AssetRate
	switch r := req.GetRequest().(type) {
	case *portfoliopilotrpc.ResolveRequestRequest_BuyRequest:
		hint = r.BuyRequest.GetAssetRateHint()
	case *portfoliopilotrpc.ResolveRequestRequest_SellRequest:
		hint = r.SellRequest.GetAssetRateHint()
	default:
		return nil, fmt.Errorf("unknown request type: %T", r)
	}

	if hint != nil {
		log.Print("ResolveRequest using provided rate hint")
		acceptResult :=
			&portfoliopilotrpc.ResolveRequestResponse_Accept{
				Accept: hint,
			}
		return &portfoliopilotrpc.ResolveRequestResponse{
			Result: acceptResult,
		}, nil
	}

	rpcRate, err := defaultRpcAssetRate()
	if err != nil {
		return nil, fmt.Errorf("default rpc asset rate: %w", err)
	}

	log.Print("ResolveRequest returning default rate")
	acceptResult := &portfoliopilotrpc.ResolveRequestResponse_Accept{
		Accept: rpcRate,
	}
	return &portfoliopilotrpc.ResolveRequestResponse{
		Result: acceptResult,
	}, nil
}

// VerifyAcceptQuote verifies an accepted quote from a peer and returns the
// validation status. This example logs the peer ID and always returns
// VALID_ACCEPT_QUOTE.
func (p *RpcPortfolioPilotServer) VerifyAcceptQuote(_ context.Context,
	req *portfoliopilotrpc.VerifyAcceptQuoteRequest) (
	*portfoliopilotrpc.VerifyAcceptQuoteResponse, error) {

	if req == nil || req.Accept == nil {
		return nil, fmt.Errorf("accept quote is nil")
	}

	log.Printf("VerifyAcceptQuote peer=%x", req.Accept.PeerId)

	return &portfoliopilotrpc.VerifyAcceptQuoteResponse{
		Status: portfoliopilotrpc.QuoteRespStatus_VALID_ACCEPT_QUOTE,
	}, nil
}

// QueryAssetRates returns an asset rate for the given query. It prefers a rate
// hint if provided, otherwise it returns the fixed default rate.
func (p *RpcPortfolioPilotServer) QueryAssetRates(_ context.Context,
	req *portfoliopilotrpc.QueryAssetRatesRequest) (
	*portfoliopilotrpc.QueryAssetRatesResponse, error) {

	if req == nil {
		return nil, fmt.Errorf("query request is nil")
	}

	if req.AssetRateHint != nil {
		log.Print("QueryAssetRates using provided rate hint")
		return &portfoliopilotrpc.QueryAssetRatesResponse{
			AssetRate: req.AssetRateHint,
		}, nil
	}

	rpcRate, err := defaultRpcAssetRate()
	if err != nil {
		return nil, fmt.Errorf("default rpc asset rate: %w", err)
	}

	log.Print("QueryAssetRates returning default rate")
	return &portfoliopilotrpc.QueryAssetRatesResponse{
		AssetRate: rpcRate,
	}, nil
}

// startService starts the given RPC server and blocks until the server is
// shut down.
func startService(grpcServer *grpc.Server) error {
	serviceAddr := fmt.Sprintf("portfoliopilotrpc://%s",
		serviceListenAddress)
	log.Printf("Starting RPC portfolio pilot service at address: %s",
		serviceAddr)

	server := RpcPortfolioPilotServer{}
	portfoliopilotrpc.RegisterPortfolioPilotServer(grpcServer, &server)
	grpcListener, err := net.Listen("tcp", serviceListenAddress)
	if err != nil {
		return fmt.Errorf("RPC server unable to listen on %s: %w",
			serviceListenAddress, err)
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
	setupLogger()

	// Generate a self-signed certificate. This allows us to use TLS for the
	// gRPC server.
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate TLS certificate: %v", err)
	}

	// Configure server-side keepalive parameters. These settings ensure the
	// server actively probes client connection health and allows long-lived
	// idle connections.
	serverKeepalive := keepalive.ServerParameters{
		// Ping clients after 1 minute of inactivity.
		Time: time.Minute,

		// Wait 20 seconds for ping response.
		Timeout: 20 * time.Second,

		// Allow connections to stay idle for 24 hours. The active
		// pinging mechanism (via Time parameter) handles health
		// checking, so we don't need aggressive idle timeouts.
		MaxConnectionIdle: time.Hour * 24,
	}

	// Configure client keepalive enforcement policy. This tells the server
	// how to handle client keepalive pings.
	clientKeepalive := keepalive.EnforcementPolicy{
		// Allow client to ping even when there are no active RPCs.
		// This is critical for long-lived connections with infrequent
		// requests.
		PermitWithoutStream: true,

		// Prevent abusive clients from pinging too frequently (DoS
		// protection).
		MinTime: 5 * time.Second,
	}

	// Create the gRPC server with TLS and keepalive configuration.
	transportCredentials := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	backendService := grpc.NewServer(
		grpc.Creds(transportCredentials),
		grpc.KeepaliveParams(serverKeepalive),
		grpc.KeepaliveEnforcementPolicy(clientKeepalive),
	)

	errChan := make(chan error, 1)
	go func() {
		errChan <- startService(backendService)
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
		log.Printf("Shutting down service on signal: %v", sig)
		backendService.GracefulStop()
		if err = <-errChan; err != nil {
			log.Printf("Service shutdown error: %v", err)
		}
	}
}
