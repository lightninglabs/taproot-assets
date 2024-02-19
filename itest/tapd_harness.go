package itest

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapcfg"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

var (
	// dbbackend is a command line flag for specifying the database backend
	// to use when starting a tap daemon.
	dbbackend = flag.String("dbbackend", "sqlite", "Set the database "+
		"backend to use when starting a tap daemon.")

	// postgresTimeout is a command line flag for specifying the amount of
	// time to allow the postgres fixture to run in total. Needs to be
	// increased for long-running tests.
	postgresTimeout = flag.Duration("postgrestimeout",
		tapdb.DefaultPostgresFixtureLifetime, "The amount of time to "+
			"allow the postgres fixture to run in total. Needs "+
			"to be increased for long-running tests.")

	// defaultHashmailBackoffConfig is the default backoff config we'll use
	// for sending proofs with the hashmail courier.
	defaultHashmailBackoffConfig = proof.BackoffCfg{
		BackoffResetWait: time.Second,
		NumTries:         5,
		InitialBackoff:   300 * time.Millisecond,
		MaxBackoff:       600 * time.Millisecond,
	}

	// defaultUniverseRpcBackoffConfig is the default backoff config we'll
	// use for sending proofs with the universe RPC courier.
	defaultUniverseRpcBackoffConfig = proof.BackoffCfg{
		SkipInitDelay:    true,
		BackoffResetWait: time.Second,
		NumTries:         5,
		InitialBackoff:   300 * time.Millisecond,
		MaxBackoff:       600 * time.Millisecond,
	}

	// defaultProofRetrievalDelay is the default delay we'll use for the
	// custodian to wait from observing a transaction on-chan to retrieving
	// the proof from the courier.
	defaultProofRetrievalDelay = 200 * time.Millisecond
)

const (
	// defaultProofTransferReceiverAckTimeout is the default itest specific
	// timeout we'll use for waiting for a receiver to acknowledge a proof
	// transfer.
	defaultProofTransferReceiverAckTimeout = 5 * time.Second
)

// tapdHarness is a test harness that holds everything that is needed to
// start an instance of the tapd server.
type tapdHarness struct {
	cfg       *tapdConfig
	server    *tap.Server
	clientCfg *tapcfg.Config

	ht *harnessTest
	wg sync.WaitGroup

	taprpc.TaprootAssetsClient
	assetwalletrpc.AssetWalletClient
	mintrpc.MintClient
	rfqrpc.RfqClient
	universerpc.UniverseClient
	tapdevrpc.TapDevClient
}

// tapdConfig holds all configuration items that are required to start a tapd
// server.
type tapdConfig struct {
	LndNode   *node.HarnessNode
	NetParams *chaincfg.Params
	BaseDir   string
}

type harnessOpts struct {
	proofSendBackoffCfg          *proof.BackoffCfg
	proofReceiverAckTimeout      *time.Duration
	proofCourier                 proof.CourierHarness
	custodianProofRetrievalDelay *time.Duration
	addrAssetSyncerDisable       bool

	// fedSyncTickerInterval is the interval at which the federation envoy
	// sync ticker will fire.
	fedSyncTickerInterval *time.Duration

	// sqliteDatabaseFilePath is the path to the SQLite database file to
	// use.
	sqliteDatabaseFilePath *string
}

type harnessOption func(*harnessOpts)

func defaultHarnessOpts() *harnessOpts {
	return &harnessOpts{}
}

// newTapdHarness creates a new tapd server harness with the given
// configuration.
func newTapdHarness(t *testing.T, ht *harnessTest, cfg tapdConfig,
	harnessOpts ...harnessOption) (*tapdHarness, error) {

	opts := defaultHarnessOpts()
	for _, harnessOpt := range harnessOpts {
		harnessOpt(opts)
	}

	if cfg.BaseDir == "" {
		var err error
		cfg.BaseDir, err = os.MkdirTemp("", "itest-tapd")
		if err != nil {
			return nil, err
		}
	}

	if cfg.LndNode == nil || cfg.LndNode.Cfg == nil {
		return nil, fmt.Errorf("lnd node configuration cannot be nil")
	}
	lndMacPath := filepath.Join(
		cfg.LndNode.Cfg.DataDir, "chain", "bitcoin", cfg.NetParams.Name,
		"admin.macaroon",
	)

	tapCfg := tapcfg.DefaultConfig()
	tapCfg.LogDir = "."
	tapCfg.MaxLogFiles = 99
	tapCfg.MaxLogFileSize = 999

	tapCfg.ChainConf.Network = cfg.NetParams.Name
	tapCfg.TapdDir = cfg.BaseDir
	tapCfg.DebugLevel = *logLevel

	// Enable universe proof courier RPC endpoints. These endpoints are
	// also used within some tests for transferring proofs.
	tapCfg.RpcConf.AllowPublicUniProofCourier = true

	// Decide which DB backend to use.
	switch *dbbackend {
	case tapcfg.DatabaseBackendSqlite:
		// We use the default settings, nothing to change for SQLite.

	case tapcfg.DatabaseBackendPostgres:
		fixture := tapdb.NewTestPgFixture(
			t, *postgresTimeout, !*noDelete,
		)
		t.Cleanup(func() {
			if !*noDelete {
				fixture.TearDown(t)
			}
		})
		tapCfg.DatabaseBackend = tapcfg.DatabaseBackendPostgres
		tapCfg.Postgres = fixture.GetConfig()
	}

	tapCfg.RpcConf.RawRPCListeners = []string{
		fmt.Sprintf("127.0.0.1:%d", nextAvailablePort()),
	}
	tapCfg.RpcConf.RawRESTListeners = []string{
		fmt.Sprintf("127.0.0.1:%d", nextAvailablePort()),
	}

	tapCfg.Lnd = &tapcfg.LndConfig{
		Host:         cfg.LndNode.Cfg.RPCAddr(),
		MacaroonPath: lndMacPath,
		TLSPath:      cfg.LndNode.Cfg.TLSCertPath,
	}

	// Ensure valid proof from tapd nodes will be accepted, and proofs will
	// be queryable by other tapd nodes. This applies to federation syncing
	// as well as RPC insert and query.
	tapCfg.Universe.PublicAccess = true

	// Set the SQLite database file path if it was specified.
	if opts.sqliteDatabaseFilePath != nil {
		tapCfg.Sqlite.DatabaseFileName = *opts.sqliteDatabaseFilePath
	}

	// Pass through the address asset syncer disable flag. If the option
	// was not set, this will be false, which is the default.
	tapCfg.AddrBook.DisableSyncer = opts.addrAssetSyncerDisable

	cfgLogger := tapCfg.LogWriter.GenSubLogger("CONF", nil)
	finalCfg, err := tapcfg.ValidateConfig(tapCfg, cfgLogger)
	if err != nil {
		return nil, err
	}

	// Populate proof courier specific config fields.
	//
	// Use passed in backoff config or default config.
	hashmailBackoffCfg := defaultHashmailBackoffConfig
	universeRpcBackoffCfg := defaultUniverseRpcBackoffConfig
	if opts.proofSendBackoffCfg != nil {
		hashmailBackoffCfg = *opts.proofSendBackoffCfg
		universeRpcBackoffCfg = *opts.proofSendBackoffCfg
	}

	// Used passed in proof receiver ack timeout or default.
	receiverAckTimeout := defaultProofTransferReceiverAckTimeout
	if opts.proofReceiverAckTimeout != nil {
		receiverAckTimeout = *opts.proofReceiverAckTimeout
	}

	finalCfg.HashMailCourier = &proof.HashMailCourierCfg{
		ReceiverAckTimeout: receiverAckTimeout,
		BackoffCfg:         &hashmailBackoffCfg,
	}
	finalCfg.UniverseRpcCourier = &proof.UniverseRpcCourierCfg{
		BackoffCfg: &universeRpcBackoffCfg,
	}

	switch typedProofCourier := (opts.proofCourier).(type) {
	case *ApertureHarness:
		finalCfg.DefaultProofCourierAddr = fmt.Sprintf(
			"%s://%s", proof.HashmailCourierType,
			typedProofCourier.ListenAddr,
		)

	case *universeServerHarness:
		finalCfg.DefaultProofCourierAddr = fmt.Sprintf(
			"%s://%s", proof.UniverseRpcCourierType,
			typedProofCourier.ListenAddr,
		)

	default:
		finalCfg.DefaultProofCourierAddr = ""
	}

	ht.t.Logf("Using proof courier address: %v",
		finalCfg.DefaultProofCourierAddr)

	// Set the custodian proof retrieval delay if it was specified.
	finalCfg.CustodianProofRetrievalDelay = defaultProofRetrievalDelay
	if opts.custodianProofRetrievalDelay != nil {
		finalCfg.CustodianProofRetrievalDelay = *opts.custodianProofRetrievalDelay
	}

	if opts.fedSyncTickerInterval != nil {
		finalCfg.Universe.SyncInterval = *opts.fedSyncTickerInterval
	}

	return &tapdHarness{
		cfg:       &cfg,
		clientCfg: finalCfg,
		ht:        ht,
	}, nil
}

// rpcHost returns the RPC host for the tapd server.
func (hs *tapdHarness) rpcHost() string {
	return hs.clientCfg.RpcConf.RawRPCListeners[0]
}

// start spins up the tapd server listening for gRPC connections.
func (hs *tapdHarness) start(expectErrExit bool) error {
	cfgLogger := hs.ht.logWriter.GenSubLogger("CONF", func() {})

	var (
		err         error
		mainErrChan = make(chan error, 10)
	)
	hs.server, err = tapcfg.CreateServerFromConfig(
		hs.clientCfg, cfgLogger, hs.ht.interceptor, mainErrChan,
	)
	if err != nil {
		return fmt.Errorf("could not create tapd server: %w", err)
	}

	hs.wg.Add(1)
	go func() {
		err := hs.server.RunUntilShutdown(mainErrChan)
		if err != nil && !expectErrExit {
			hs.ht.Fatalf("Error running server: %v", err)
		}
	}()

	// Let's wait until the RPC server is actually listening before we
	// connect our client to it.
	listenerAddr := hs.clientCfg.RpcConf.RawRPCListeners[0]
	err = wait.NoError(func() error {
		_, err := net.Dial("tcp", listenerAddr)
		return err
	}, defaultTimeout)
	if err != nil {
		return fmt.Errorf("error waiting for server to start: %w", err)
	}

	// Create our client to interact with the tapd RPC server directly.
	rpcConn, err := dialServer(
		listenerAddr, hs.clientCfg.RpcConf.TLSCertPath,
		hs.clientCfg.RpcConf.MacaroonPath,
	)
	if err != nil {
		return fmt.Errorf("could not connect to %v: %w",
			listenerAddr, err)
	}
	hs.TaprootAssetsClient = taprpc.NewTaprootAssetsClient(rpcConn)
	hs.AssetWalletClient = assetwalletrpc.NewAssetWalletClient(rpcConn)
	hs.MintClient = mintrpc.NewMintClient(rpcConn)
	hs.RfqClient = rfqrpc.NewRfqClient(rpcConn)
	hs.UniverseClient = universerpc.NewUniverseClient(rpcConn)
	hs.TapDevClient = tapdevrpc.NewTapDevClient(rpcConn)

	return nil
}

// stop shuts down the tapd server and deletes its temporary data directory.
func (hs *tapdHarness) stop(deleteData bool) error {
	// Don't return the error immediately if stopping goes wrong, always
	// remove the temp directory.
	err := hs.server.Stop()
	if deleteData {
		_ = os.RemoveAll(hs.cfg.BaseDir)
	}

	return err
}

// assetIDWithBalance returns the asset ID of an asset that has at least the
// given balance. If no such asset is found, nil is returned.
func (hs *tapdHarness) assetIDWithBalance(t *testing.T, ctx context.Context,
	minBalance uint64, assetType taprpc.AssetType) *taprpc.Asset {

	balances, err := hs.ListBalances(ctx, &taprpc.ListBalancesRequest{
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

			assets, err := hs.ListAssets(
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
func (hs *tapdHarness) listTransfersSince(t *testing.T, ctx context.Context,
	existingTransfers []*taprpc.AssetTransfer) []*taprpc.AssetTransfer {

	resp, err := hs.ListTransfers(ctx, &taprpc.ListTransfersRequest{})
	require.NoError(t, err)

	if len(existingTransfers) == 0 {
		return resp.Transfers
	}

	newIndex := len(existingTransfers)
	return resp.Transfers[newIndex:]
}

// dialServer creates a gRPC client connection to the given host using a default
// timeout context.
func dialServer(rpcHost, tlsCertPath, macaroonPath string) (*grpc.ClientConn,
	error) {

	defaultOpts, err := defaultDialOptions(tlsCertPath, macaroonPath)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return grpc.DialContext(ctx, rpcHost, defaultOpts...)
}

// defaultDialOptions returns the default RPC dial options.
func defaultDialOptions(serverCertPath, macaroonPath string) ([]grpc.DialOption,
	error) {

	baseOpts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           backoff.DefaultConfig,
			MinConnectTimeout: 10 * time.Second,
		}),
		grpc.WithDefaultCallOptions(tap.MaxMsgReceiveSize),
	}

	if serverCertPath != "" {
		err := wait.Predicate(func() bool {
			return lnrpc.FileExists(serverCertPath)
		}, defaultTimeout)
		if err != nil {
			return nil, err
		}

		creds, err := credentials.NewClientTLSFromFile(
			serverCertPath, "",
		)
		if err != nil {
			return nil, err
		}
		baseOpts = append(baseOpts, grpc.WithTransportCredentials(creds))
	} else {
		baseOpts = append(baseOpts, grpc.WithInsecure())
	}

	if macaroonPath != "" {
		macaroonOptions, err := readMacaroon(macaroonPath)
		if err != nil {
			return nil, fmt.Errorf("unable to load macaroon %s: %w",
				macaroonPath, err)
		}
		baseOpts = append(baseOpts, macaroonOptions)
	}

	return baseOpts, nil
}

// readMacaroon tries to read the macaroon file at the specified path and create
// gRPC dial options from it.
func readMacaroon(macaroonPath string) (grpc.DialOption, error) {
	// Load the specified macaroon file.
	macBytes, err := os.ReadFile(macaroonPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read macaroon path : %w", err)
	}

	mac := &macaroon.Macaroon{}
	if err = mac.UnmarshalBinary(macBytes); err != nil {
		return nil, fmt.Errorf("unable to decode macaroon: %w", err)
	}

	// Now we append the macaroon credentials to the dial options.
	cred, err := macaroons.NewMacaroonCredential(mac)
	if err != nil {
		return nil, fmt.Errorf("error creating mac cred: %w", err)
	}
	return grpc.WithPerRPCCredentials(cred), nil
}
