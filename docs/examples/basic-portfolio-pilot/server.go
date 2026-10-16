// This file contains the gRPC server and its transport security. The
// pilot sets every price the node trades at, so tapd must know it is
// talking to the pilot, and the pilot that it is talking to tapd. The
// ideas it illustrates:
//
//   - The TLS certificate is written to disk, so tapd can verify it
//     through experimental.rfq.tls.certpath rather than skip
//     verification.
//   - Every call must carry the macaroon tapd sends from
//     experimental.rfq.portfoliopilotmacaroonpath. The pilot compares
//     it byte for byte; a production pilot would verify its signature
//     and caveats.
//   - tapd's client sends keepalive pings while idle, which the server
//     must permit.

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	pilotrpc "github.com/lightninglabs/taproot-assets/taprpc/portfoliopilotrpc"
	"github.com/lightningnetwork/lnd/cert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gopkg.in/macaroon.v2"
)

// certFile, keyFile and macaroonFile are the names of the files written
// to the data directory.
const (
	certFile     = "basic-portfolio-pilot.cert"
	keyFile      = "basic-portfolio-pilot.key"
	macaroonFile = "basic-portfolio-pilot.macaroon"
)

// loadTLS loads the TLS certificate and key from the data directory,
// generating them first if either is missing.
func loadTLS(cfg config) (credentials.TransportCredentials, error) {
	certPath := filepath.Join(cfg.dataDir, certFile)
	keyPath := filepath.Join(cfg.dataDir, keyFile)

	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		var domains []string
		if cfg.extraDomain != "" {
			domains = []string{cfg.extraDomain}
		}

		certBytes, keyBytes, err := cert.GenCertPair(
			"basic-portfolio-pilot", nil, domains, false,
			14*30*24*time.Hour,
		)
		if err != nil {
			return nil, err
		}

		err = cert.WriteCertPair(certPath, keyPath, certBytes, keyBytes)
		if err != nil {
			return nil, err
		}
		log.Printf("Wrote %s", certPath)
	}

	tlsCert, _, err := cert.LoadCert(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return credentials.NewTLS(cert.TLSConfFromCert(tlsCert)), nil
}

// loadMacaroon returns the hex encoding of the macaroon in the data
// directory, generating it first if it is missing.
func loadMacaroon(cfg config) (string, error) {
	path := filepath.Join(cfg.dataDir, macaroonFile)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		rootKey := make([]byte, 32)
		if _, err := rand.Read(rootKey); err != nil {
			return "", err
		}

		mac, err := macaroon.New(
			rootKey, []byte("pilot"), "basic-portfolio-pilot",
			macaroon.LatestVersion,
		)
		if err != nil {
			return "", err
		}

		macBytes, err := mac.MarshalBinary()
		if err != nil {
			return "", err
		}

		if err := os.WriteFile(path, macBytes, 0600); err != nil {
			return "", err
		}
		log.Printf("Wrote %s", path)
	}

	macBytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(macBytes), nil
}

// requireMacaroon returns an interceptor that rejects calls without
// the expected hex-encoded macaroon.
func requireMacaroon(expected string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error) {

		md, _ := metadata.FromIncomingContext(ctx)
		got := md.Get("macaroon")
		if len(got) != 1 || subtle.ConstantTimeCompare(
			[]byte(got[0]), []byte(expected),
		) != 1 {

			return nil, status.Error(
				codes.Unauthenticated, "invalid macaroon",
			)
		}

		return handler(ctx, req)
	}
}

// newServer builds the gRPC server for the given pilot.
func newServer(cfg config,
	svc pilotrpc.PortfolioPilotServer) (*grpc.Server, error) {

	creds, err := loadTLS(cfg)
	if err != nil {
		return nil, fmt.Errorf("TLS setup: %w", err)
	}

	mac, err := loadMacaroon(cfg)
	if err != nil {
		return nil, fmt.Errorf("macaroon setup: %w", err)
	}

	// tapd's client sends keepalive pings every 30 seconds, also
	// without active calls.
	server := grpc.NewServer(
		grpc.Creds(creds), grpc.UnaryInterceptor(requireMacaroon(mac)),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	pilotrpc.RegisterPortfolioPilotServer(server, svc)

	return server, nil
}
