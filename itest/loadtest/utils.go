package loadtest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

var (
	// maxMsgRecvSize is the largest message our client will receive. We
	// set this to 200MiB atm.
	maxMsgRecvSize = grpc.MaxCallRecvMsgSize(lnrpc.MaxGrpcMsgSize)
)

type rpcClient struct {
	taprpc.TaprootAssetsClient
	universerpc.UniverseClient
	mintrpc.MintClient
	assetwalletrpc.AssetWalletClient
}

func getTapClient(t *testing.T, ctx context.Context,
	cfg *TapConfig) (*rpcClient, func()) {

	creds := credentials.NewTLS(&tls.Config{})
	if cfg.TLSPath != "" {
		// Load the certificate file now, if specified.
		tlsCert, err := os.ReadFile(cfg.TLSPath)
		require.NoError(t, err)

		cp := x509.NewCertPool()
		ok := cp.AppendCertsFromPEM(tlsCert)
		require.True(t, ok)

		creds = credentials.NewClientTLSFromCert(cp, "")
	}

	// Create a dial options array.
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(maxMsgRecvSize),
	}

	if cfg.MacPath != "" {
		var macBytes []byte
		macBytes, err := os.ReadFile(cfg.MacPath)
		require.NoError(t, err)

		mac := &macaroon.Macaroon{}
		err = mac.UnmarshalBinary(macBytes)
		require.NoError(t, err)

		macCred, err := macaroons.NewMacaroonCredential(mac)
		require.NoError(t, err)

		opts = append(opts, grpc.WithPerRPCCredentials(macCred))
	}

	svrAddr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	conn, err := grpc.Dial(svrAddr, opts...)
	require.NoError(t, err)

	assetsClient := taprpc.NewTaprootAssetsClient(conn)
	universeClient := universerpc.NewUniverseClient(conn)
	mintMintClient := mintrpc.NewMintClient(conn)
	assetWalletClient := assetwalletrpc.NewAssetWalletClient(conn)

	client := &rpcClient{
		TaprootAssetsClient: assetsClient,
		UniverseClient:      universeClient,
		MintClient:          mintMintClient,
		AssetWalletClient:   assetWalletClient,
	}

	cleanUp := func() {
		conn.Close()
	}

	return client, cleanUp
}

func getBitcoinConn(t *testing.T, cfg *BitcoinConfig) *rpcclient.Client {
	var (
		rpcCert []byte
		err     error
	)

	disableTLS := cfg.TLSPath == ""

	// In case we use TLS and a certificate argument is provided, we need to
	// read that file and provide it to the RPC connection as byte slice.
	if !disableTLS {
		rpcCert, err = os.ReadFile(cfg.TLSPath)
		require.NoError(t, err)
	}

	// Connect to the backend with the certs we just loaded.
	connCfg := &rpcclient.ConnConfig{
		Host:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		User:         cfg.User,
		Pass:         cfg.Password,
		HTTPPostMode: true,
		DisableTLS:   disableTLS,
		Certificates: rpcCert,
	}

	client, err := rpcclient.New(connCfg, nil)
	require.NoError(t, err)

	return client
}
