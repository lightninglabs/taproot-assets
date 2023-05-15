package itest

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightninglabs/taro"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tapcfg"
	"github.com/lightninglabs/taro/tarodb"
	"github.com/lightninglabs/taro/tarorpc"
	"github.com/lightninglabs/taro/tarorpc/assetwalletrpc"
	"github.com/lightninglabs/taro/tarorpc/mintrpc"
	"github.com/lightninglabs/taro/tarorpc/universerpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

var (
	// dbbackend is a command line flag for specifying the database backend
	// to use when starting a taro daemon.
	dbbackend = flag.String("dbbackend", "sqlite", "Set the database "+
		"backend to use when starting a taro daemon.")
)

const (
	// defaultProofTransferReceiverAckTimeout is the default itest specific
	// timeout we'll use for waiting for a receiver to acknowledge a proof
	// transfer.
	defaultProofTransferReceiverAckTimeout = 5 * time.Second
)

// tarodHarness is a test harness that holds everything that is needed to
// start an instance of the tarod server.
type tarodHarness struct {
	cfg       *tarodConfig
	server    *taro.Server
	clientCfg *tapcfg.Config

	ht *harnessTest
	wg sync.WaitGroup

	tarorpc.TaroClient
	assetwalletrpc.AssetWalletClient
	mintrpc.MintClient
	universerpc.UniverseClient
}

// tarodConfig holds all configuration items that are required to start a tarod
// server.
type tarodConfig struct {
	LndNode   *node.HarnessNode
	NetParams *chaincfg.Params
	BaseDir   string
}

// newTarodHarness creates a new tarod server harness with the given
// configuration.
func newTarodHarness(ht *harnessTest, cfg tarodConfig,
	enableHashMail bool, proofSendBackoffCfg *proof.BackoffCfg,
	proofReceiverAckTimeout *time.Duration) (*tarodHarness, error) {

	if cfg.BaseDir == "" {
		var err error
		cfg.BaseDir, err = os.MkdirTemp("", "itest-tarod")
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

	tarodCfg := tapcfg.DefaultConfig()
	tarodCfg.LogDir = "."
	tarodCfg.MaxLogFiles = 99
	tarodCfg.MaxLogFileSize = 999

	tarodCfg.ChainConf.Network = cfg.NetParams.Name
	tarodCfg.TaroDir = cfg.BaseDir
	tarodCfg.DebugLevel = *logLevel

	// Decide which DB backend to use.
	switch *dbbackend {
	case tapcfg.DatabaseBackendSqlite:
		// We use the default settings, nothing to change for SQLite.

	case tapcfg.DatabaseBackendPostgres:
		fixture := tarodb.NewTestPgFixture(
			ht.t, tarodb.DefaultPostgresFixtureLifetime,
		)
		ht.t.Cleanup(func() {
			fixture.TearDown(ht.t)
		})
		tarodCfg.DatabaseBackend = tapcfg.DatabaseBackendPostgres
		tarodCfg.Postgres = fixture.GetConfig()
	}

	tarodCfg.RpcConf.RawRPCListeners = []string{
		fmt.Sprintf("127.0.0.1:%d", nextAvailablePort()),
	}
	tarodCfg.RpcConf.RawRESTListeners = []string{
		fmt.Sprintf("127.0.0.1:%d", nextAvailablePort()),
	}

	tarodCfg.Lnd = &tapcfg.LndConfig{
		Host:         cfg.LndNode.Cfg.RPCAddr(),
		MacaroonPath: lndMacPath,
		TLSPath:      cfg.LndNode.Cfg.TLSCertPath,
	}

	cfgLogger := tarodCfg.LogWriter.GenSubLogger("CONF", nil)
	finalCfg, err := tapcfg.ValidateConfig(tarodCfg, cfgLogger)
	if err != nil {
		return nil, err
	}

	// Conditionally use the local hashmail service.
	finalCfg.HashMailCourier = nil
	if enableHashMail {
		// Use passed in backoff config or default config.
		backoffCfg := &proof.BackoffCfg{
			BackoffResetWait: 20 * time.Second,
			NumTries:         3,
			InitialBackoff:   2 * time.Second,
			MaxBackoff:       2 * time.Second,
		}
		if proofSendBackoffCfg != nil {
			backoffCfg = proofSendBackoffCfg
		}

		// Used passed in proof receiver ack timeout or default.
		receiverAckTimeout := defaultProofTransferReceiverAckTimeout
		if proofReceiverAckTimeout != nil {
			receiverAckTimeout = *proofReceiverAckTimeout
		}

		finalCfg.HashMailCourier = &proof.HashMailCourierCfg{
			Addr:               ht.apertureHarness.ListenAddr,
			TlsCertPath:        ht.apertureHarness.TlsCertPath,
			ReceiverAckTimeout: receiverAckTimeout,
			BackoffCfg:         backoffCfg,
		}
	}

	return &tarodHarness{
		cfg:       &cfg,
		clientCfg: finalCfg,
		ht:        ht,
	}, nil
}

// rpcHost returns the RPC host for the tarod server.
func (hs *tarodHarness) rpcHost() string {
	return hs.clientCfg.RpcConf.RawRPCListeners[0]
}

// start spins up the tarod server listening for gRPC connections.
func (hs *tarodHarness) start(expectErrExit bool) error {
	cfgLogger := hs.ht.logWriter.GenSubLogger("CONF", func() {})

	var (
		err         error
		mainErrChan = make(chan error, 10)
	)
	hs.server, err = tapcfg.CreateServerFromConfig(
		hs.clientCfg, cfgLogger, hs.ht.interceptor, mainErrChan,
	)
	if err != nil {
		return fmt.Errorf("could not create tarod server: %v", err)
	}

	hs.wg.Add(1)
	go func() {
		err := hs.server.RunUntilShutdown(mainErrChan)
		if err != nil && !expectErrExit {
			hs.ht.Fatalf("Error running server: %v", err)
		}
	}()

	time.Sleep(1 * time.Second)

	// Create our client to interact with the tarod RPC server directly.
	listenerAddr := hs.clientCfg.RpcConf.RawRPCListeners[0]
	rpcConn, err := dialServer(
		listenerAddr, hs.clientCfg.RpcConf.TLSCertPath,
		hs.clientCfg.RpcConf.MacaroonPath,
	)
	if err != nil {
		return fmt.Errorf("could not connect to %v: %v",
			listenerAddr, err)
	}
	hs.TaroClient = tarorpc.NewTaroClient(rpcConn)
	hs.AssetWalletClient = assetwalletrpc.NewAssetWalletClient(rpcConn)
	hs.MintClient = mintrpc.NewMintClient(rpcConn)
	hs.UniverseClient = universerpc.NewUniverseClient(rpcConn)

	return nil
}

// stop shuts down the tarod server and deletes its temporary data directory.
func (hs *tarodHarness) stop(deleteData bool) error {
	// Don't return the error immediately if stopping goes wrong, always
	// remove the temp directory.
	err := hs.server.Stop()
	if deleteData {
		_ = os.RemoveAll(hs.cfg.BaseDir)
	}

	return err
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
			return nil, fmt.Errorf("unable to load macaroon %s: %v",
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
		return nil, fmt.Errorf("unable to read macaroon path : %v", err)
	}

	mac := &macaroon.Macaroon{}
	if err = mac.UnmarshalBinary(macBytes); err != nil {
		return nil, fmt.Errorf("unable to decode macaroon: %v", err)
	}

	// Now we append the macaroon credentials to the dial options.
	cred, err := macaroons.NewMacaroonCredential(mac)
	if err != nil {
		return nil, fmt.Errorf("error creating mac cred: %v", err)
	}
	return grpc.WithPerRPCCredentials(cred), nil
}
