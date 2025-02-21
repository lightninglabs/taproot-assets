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
	"github.com/lightninglabs/taproot-assets/cmd/commands"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/lntest/rpc"
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
	lnd *rpc.HarnessRPC

	// RpcClientsBundle is a bundle of all the gRPC clients that are
	// available to the test harness.
	commands.RpcClientsBundle
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

// initAlice is similar to initClients, but only returns the Alice client.
func initAlice(t *testing.T, ctx context.Context, cfg *Config) *rpcClient {
	alice := getTapClient(t, ctx, cfg.Alice.Tapd, cfg.Alice.Lnd)

	_, err := alice.GetInfo(ctx, &taprpc.GetInfoRequest{})
	require.NoError(t, err)

	return alice
}

func initClients(t *testing.T, ctx context.Context,
	cfg *Config) (*rpcClient, *rpcClient, *rpcclient.Client) {

	// Create tapd clients.
	alice := getTapClient(t, ctx, cfg.Alice.Tapd, cfg.Alice.Lnd)

	_, err := alice.GetInfo(ctx, &taprpc.GetInfoRequest{})
	require.NoError(t, err)

	bob := getTapClient(t, ctx, cfg.Bob.Tapd, cfg.Bob.Lnd)

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
	cfg *TapConfig, lndCfg *LndConfig) *rpcClient {

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

	lnd := getLndClient(t, ctx, lndCfg)

	assetsClient := taprpc.NewTaprootAssetsClient(conn)
	assetWalletClient := assetwalletrpc.NewAssetWalletClient(conn)
	devClient := tapdevrpc.NewTapDevClient(conn)
	mintMintClient := mintrpc.NewMintClient(conn)
	rfqClient := rfqrpc.NewRfqClient(conn)
	universeClient := universerpc.NewUniverseClient(conn)

	client := &rpcClient{
		cfg: cfg,
		lnd: lnd,
		RpcClientsBundle: &struct {
			taprpc.TaprootAssetsClient
			assetwalletrpc.AssetWalletClient
			mintrpc.MintClient
			rfqrpc.RfqClient
			tchrpc.TaprootAssetChannelsClient
			universerpc.UniverseClient
			tapdevrpc.TapDevClient
		}{
			TaprootAssetsClient: assetsClient,
			AssetWalletClient:   assetWalletClient,
			TapDevClient:        devClient,
			MintClient:          mintMintClient,
			RfqClient:           rfqClient,
			UniverseClient:      universeClient,
		},
	}

	t.Cleanup(func() {
		err := conn.Close()
		require.NoError(t, err)
	})

	return client
}

func getLndClient(t *testing.T, ctx context.Context,
	cfg *LndConfig) *rpc.HarnessRPC {

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

	client := rpc.NewHarnessRPC(ctx, t, conn, cfg.Name)

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

// stringToAssetType converts a string of an asset type to its respective taprpc
// type enum value.
func stringToAssetType(t string) taprpc.AssetType {
	switch t {
	case "collectible":
		return taprpc.AssetType_COLLECTIBLE

	default:
		return taprpc.AssetType_NORMAL
	}
}

// noopBaseUni is a dummy implementation of the universe.DiffEngine and
// universe.LocalRegistrar interfaces. This is meant to be used by the simple
// syncer used in the sync loadtest. As we don't care about persistence and we
// always want to do a full sync, we always return an empty root node to trigger
// a sync.
type noopBaseUni struct{}

// RootNode returns the root node of the base universe corresponding to the
// passed ID.
func (n noopBaseUni) RootNode(ctx context.Context,
	id universe.Identifier) (universe.Root, error) {

	return universe.Root{
		Node: mssmt.EmptyLeafNode,
	}, nil
}

// RootNodes returns the set of root nodes for all known base universes assets.
func (n noopBaseUni) RootNodes(ctx context.Context,
	q universe.RootNodesQuery) ([]universe.Root, error) {

	return nil, nil
}

// MultiverseRoot returns the root node of the multiverse for the specified
// proof type. If the given list of universe IDs is non-empty, then the root
// will be calculated just for those universes.
func (n *noopBaseUni) MultiverseRoot(ctx context.Context,
	proofType universe.ProofType,
	filterByIDs []universe.Identifier) (fn.Option[universe.MultiverseRoot],
	error) {

	return fn.None[universe.MultiverseRoot](), nil
}

// UpsertProofLeaf attempts to upsert a proof for an asset issuance or transfer
// event. This method will return an error if the passed proof is invalid. If
// the leaf is already known, then no action is taken and the existing
// commitment proof returned.
func (n noopBaseUni) UpsertProofLeaf(ctx context.Context,
	id universe.Identifier, key universe.LeafKey,
	leaf *universe.Leaf) (*universe.Proof, error) {

	return nil, nil
}

// UpsertProofLeafBatch inserts a batch of proof leaves within the target
// universe tree. We assume the proofs within the batch have already been
// checked that they don't yet exist in the local database.
func (n noopBaseUni) UpsertProofLeafBatch(ctx context.Context,
	items []*universe.Item) error {

	return nil
}

// Close closes the noopBaseUni, stopping all goroutines and freeing all
// resources.
func (n noopBaseUni) Close() error {
	return nil
}

// FetchProofLeaf attempts to fetch a proof leaf for the target leaf key
// and given a universe identifier (assetID/groupKey).
func (n noopBaseUni) FetchProofLeaf(ctx context.Context, id universe.Identifier,
	key universe.LeafKey) ([]*universe.Proof, error) {

	return nil, nil
}

// UniverseLeafKeys returns the set of leaf keys known for the specified
// universe identifier.
func (n noopBaseUni) UniverseLeafKeys(ctx context.Context,
	q universe.UniverseLeafKeysQuery) ([]universe.LeafKey, error) {

	return nil, nil
}
