package itest

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightninglabs/taro"
	"github.com/lightninglabs/taro/tarocfg"
	"github.com/lightninglabs/taro/tarorpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

// tarodHarness is a test harness that holds everything that is needed to
// start an instance of the tarod server.
type tarodHarness struct {
	cfg       *tarodConfig
	server    *taro.Server
	clientCfg *tarocfg.Config

	ht *harnessTest
	wg sync.WaitGroup

	tarorpc.TaroClient
}

// tarodConfig holds all configuration items that are required to start a tarod
// server.
type tarodConfig struct {
	UniverseServer string
	BackendCfg     lntest.BackendConfig
	ServerTLSPath  string
	LndNode        *lntest.HarnessNode
	NetParams      *chaincfg.Params
	BaseDir        string
}

// newTarodHarness creates a new tarod server harness with the given
// configuration.
func newTarodHarness(ht *harnessTest, cfg tarodConfig) (*tarodHarness, error) {
	if cfg.BaseDir == "" {
		var err error
		cfg.BaseDir, err = ioutil.TempDir("", "itest-tarod")
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

	tarodCfg := tarocfg.DefaultConfig()
	tarodCfg.LogDir = "."
	tarodCfg.MaxLogFiles = 99
	tarodCfg.MaxLogFileSize = 999

	tarodCfg.ChainConf.Network = cfg.NetParams.Name
	tarodCfg.TaroDir = cfg.BaseDir
	tarodCfg.DebugLevel = "debug"

	tarodCfg.RpcConf.RawRPCListeners = []string{
		fmt.Sprintf("127.0.0.1:%d", nextAvailablePort()),
	}
	tarodCfg.RpcConf.RawRESTListeners = []string{
		fmt.Sprintf("127.0.0.1:%d", nextAvailablePort()),
	}

	tarodCfg.Lnd = &tarocfg.LndConfig{
		Host:         cfg.LndNode.Cfg.RPCAddr(),
		MacaroonPath: lndMacPath,
		TLSPath:      cfg.LndNode.Cfg.TLSCertPath,
	}

	finalCfg, _, err := tarocfg.ValidateConfig(tarodCfg, ht.interceptor)
	if err != nil {
		return nil, err
	}

	return &tarodHarness{
		cfg:       &cfg,
		clientCfg: finalCfg,
		ht:        ht,
	}, nil
}

// start spins up the tarod server listening for gRPC connections.
func (hs *tarodHarness) start() error {
	cfgLogger := hs.ht.logWriter.GenSubLogger("CONF", func() {})

	var (
		err         error
		mainErrChan = make(chan error, 10)
	)
	hs.server, err = tarocfg.CreateServerFromConfig(
		hs.clientCfg, cfgLogger, hs.ht.interceptor, mainErrChan,
	)
	if err != nil {
		return fmt.Errorf("could not create tarod server: %v", err)
	}

	hs.wg.Add(1)
	go func() {
		err := hs.server.RunUntilShutdown(mainErrChan)
		if err != nil {
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
	macBytes, err := ioutil.ReadFile(macaroonPath)
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
