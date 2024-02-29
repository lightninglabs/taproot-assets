package loadtest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

var (
	// defaultTimeout is a timeout that will be used for various wait
	// scenarios where no custom timeout value is defined.
	defaultTimeout = time.Second * 10
)

type rpcClient struct {
	cfg *TapConfig
	taprpc.TaprootAssetsClient
	assetwalletrpc.AssetWalletClient
	tapdevrpc.TapDevClient
	mintrpc.MintClient
	rfqrpc.RfqClient
	universerpc.UniverseClient
}

// assetIDWithBalance returns the asset ID of an asset that has at least the
// given balance. If no such asset is found, nil is returned.
func (r *rpcClient) assetIDWithBalance(t *testing.T, ctx context.Context,
	minBalance uint64, assetType taprpc.AssetType) *taprpc.Asset {

	balances, err := r.ListBalances(ctx, &taprpc.ListBalancesRequest{
		GroupBy: &taprpc.ListBalancesRequest_AssetId{
			AssetId: true,
		},
	})
	require.NoError(t, err)

	for assetIDHex, balance := range balances.AssetBalances {
		if balance.Balance >= minBalance &&
			balance.AssetGenesis.AssetType == assetType {

			assetIDBytes, err := hex.DecodeString(assetIDHex)
			require.NoError(t, err)

			assets, err := r.ListAssets(
				ctx, &taprpc.ListAssetRequest{},
			)
			require.NoError(t, err)

			for _, asset := range assets.Assets {
				if bytes.Equal(
					asset.AssetGenesis.AssetId,
					assetIDBytes,
				) {

					return asset
				}
			}
		}
	}

	return nil
}

// listTransfersSince returns all transfers that have been made since the last
// transfer in the given list. If the list is empty, all transfers are returned.
func (r *rpcClient) listTransfersSince(t *testing.T, ctx context.Context,
	existingTransfers []*taprpc.AssetTransfer) []*taprpc.AssetTransfer {

	resp, err := r.ListTransfers(ctx, &taprpc.ListTransfersRequest{})
	require.NoError(t, err)

	if len(existingTransfers) == 0 {
		return resp.Transfers
	}

	newIndex := len(existingTransfers)
	return resp.Transfers[newIndex:]
}

func initClients(t *testing.T, ctx context.Context,
	cfg *Config) (*rpcClient, *rpcClient, *rpcclient.Client) {

	// Create tapd clients.
	alice := getTapClient(t, ctx, cfg.Alice.Tapd)

	_, err := alice.GetInfo(ctx, &taprpc.GetInfoRequest{})
	require.NoError(t, err)

	bob := getTapClient(t, ctx, cfg.Bob.Tapd)

	_, err = bob.GetInfo(ctx, &taprpc.GetInfoRequest{})
	require.NoError(t, err)

	// Create bitcoin client.
	bitcoinClient := getBitcoinConn(t, cfg.Bitcoin)

	// Test bitcoin client connection by mining a block.
	itest.MineBlocks(t, bitcoinClient, 1, 0)

	// If we fail from this point onward, we might have created a
	// transaction that isn't mined yet. To make sure we can run the test
	// again, we'll make sure to clean up the mempool by mining a block.
	t.Cleanup(func() {
		itest.MineBlocks(t, bitcoinClient, 1, 0)
	})

	return alice, bob, bitcoinClient
}

func getTapClient(t *testing.T, ctx context.Context,
	cfg *TapConfig) *rpcClient {

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
		grpc.WithDefaultCallOptions(tap.MaxMsgReceiveSize),
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
	conn, err := grpc.DialContext(ctx, svrAddr, opts...)
	require.NoError(t, err)

	assetsClient := taprpc.NewTaprootAssetsClient(conn)
	assetWalletClient := assetwalletrpc.NewAssetWalletClient(conn)
	devClient := tapdevrpc.NewTapDevClient(conn)
	mintMintClient := mintrpc.NewMintClient(conn)
	rfqClient := rfqrpc.NewRfqClient(conn)
	universeClient := universerpc.NewUniverseClient(conn)

	client := &rpcClient{
		cfg:                 cfg,
		TaprootAssetsClient: assetsClient,
		AssetWalletClient:   assetWalletClient,
		TapDevClient:        devClient,
		MintClient:          mintMintClient,
		RfqClient:           rfqClient,
		UniverseClient:      universeClient,
	}

	t.Cleanup(func() {
		err := conn.Close()
		require.NoError(t, err)
	})

	return client
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
