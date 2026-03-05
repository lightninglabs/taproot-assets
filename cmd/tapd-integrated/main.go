// Package main implements a minimal integrated daemon that runs lnd and tapd
// in the same process. It wires tapd's aux channel implementations into lnd
// via the integration.BuildAuxComponents function, enabling Taproot Asset
// channel support without requiring lightning-terminal.
//
// The binary accepts command-line flags under --lnd.* and
// --taproot-assets.* namespaces and is intended primarily for integration
// testing.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/btcsuite/btclog/v2"
	"github.com/jessevdk/go-flags"
	"github.com/lightninglabs/lndclient"
	taprootassets "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/integration"
	"github.com/lightninglabs/taproot-assets/tapcfg"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/signal"
	"google.golang.org/grpc"
)

// config is the combined configuration for the integrated daemon, embedding
// both lnd and tapd configs under their respective namespaces. Command line
// args arrive as --lnd.<option> and --taproot-assets.<option>.
type config struct {
	Lnd *lnd.Config `group:"lnd" namespace:"lnd"`

	//nolint:lll
	TaprootAssets *tapcfg.Config `group:"taproot-assets" namespace:"taproot-assets"`

	// ReadyFile is an optional file path that will be created once both
	// lnd and tapd are fully initialized and ready to accept RPCs. This
	// is used by test harnesses to avoid calling tapd RPCs during the
	// startup window before RPCServer.Start() has been called (which
	// would cause a nil pointer panic).
	//nolint:lll
	ReadyFile string `long:"ready-file" description:"Create this file when fully ready"`
}

// defaultConfig returns the default combined configuration.
func defaultConfig() *config {
	lndCfg := lnd.DefaultConfig()
	tapdCfg := tapcfg.DefaultConfig()

	return &config{
		Lnd:           &lndCfg,
		TaprootAssets: &tapdCfg,
	}
}

// integratedRegistrar wraps an existing lnd.GrpcRegistrar and additionally
// registers tapd's gRPC services on lnd's gRPC server. This puts both lnd
// and tapd services on a single port.
type integratedRegistrar struct {
	lnd.GrpcRegistrar
	tapServer *taprootassets.Server
}

// RegisterGrpcSubserver registers both the original lnd subserver services
// and tapd's gRPC services on the given gRPC server.
//
// NOTE: This is part of the lnd.GrpcRegistrar interface.
func (r *integratedRegistrar) RegisterGrpcSubserver(s *grpc.Server) error {
	if err := r.GrpcRegistrar.RegisterGrpcSubserver(s); err != nil {
		return err
	}

	r.tapServer.RegisterGrpcService(s)

	return nil
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	// Hook interceptor for os signals.
	interceptor, err := signal.Intercept()
	if err != nil {
		return fmt.Errorf("error setting up signal interceptor: %w",
			err)
	}

	// Parse the combined config from command line flags. We create two
	// parsers: one representing the "config file" (unused, but required
	// by lnd.ValidateConfig) and one for actual flag parsing.
	cfg := defaultConfig()
	fileParser := flags.NewParser(cfg, flags.Default)
	flagParser := flags.NewParser(cfg, flags.Default)

	if _, err := flagParser.Parse(); err != nil {
		return err
	}

	// Validate the lnd configuration. ValidateConfig handles the "lnd."
	// namespace prefix when looking up options (see config.go:986-992).
	// This also sets up lnd's logging subsystem.
	cfg.Lnd, err = lnd.ValidateConfig(
		*cfg.Lnd, interceptor, fileParser, flagParser,
	)
	if err != nil {
		return fmt.Errorf("error validating lnd config: %w", err)
	}

	// Create a logger for tapd operations. After lnd.ValidateConfig, the
	// log rotator is set up. We create a simple stdout-based logger for
	// tapd configuration logging.
	tapdLog := btclog.NewSLogger(btclog.NewDefaultHandler(os.Stdout))

	// Validate the tapd configuration.
	cfg.TaprootAssets, err = tapcfg.ValidateConfig(
		*cfg.TaprootAssets, tapdLog,
	)
	if err != nil {
		return fmt.Errorf("error validating tapd config: %w", err)
	}

	// Determine chain parameters from lnd's active net.
	chainParams := address.ParamsForChain(
		cfg.Lnd.ActiveNetParams.Name,
	)

	// Step 1: Create a tapd Server shell. This implements all aux channel
	// interfaces but has no lnd connection yet. The shell will be filled
	// in later via ConfigureSubServer after lnd starts.
	tapServer := taprootassets.NewServer(&chainParams)

	// Step 2: Wrap the shell in AuxComponents. These fn.Option[T] values
	// point to the shell. Once ConfigureSubServer fills it in, the same
	// pointer provides real behavior.
	ctx := context.Background()
	auxComponents, cleanup, err := integration.BuildAuxComponents(
		ctx, tapServer,
	)
	if err != nil {
		return fmt.Errorf("error building aux components: %w", err)
	}
	defer cleanup()

	// Step 3: Get the default ImplementationCfg from lnd's config, then
	// overlay our aux components and custom GrpcRegistrar that also
	// registers tapd's services.
	implCfg := cfg.Lnd.ImplementationConfig(interceptor)
	implCfg.GrpcRegistrar = &integratedRegistrar{
		GrpcRegistrar: implCfg.GrpcRegistrar,
		tapServer:     tapServer,
	}
	implCfg.AuxComponents = *auxComponents

	// Step 4: Set up listeners. We eagerly bind each RPC address so the
	// port is available immediately. lnd closes the Ready channel before
	// calling grpcServer.Serve(), so with a deferred (on-demand) listener
	// there would be a race where lndclient tries to connect before the
	// port is actually bound.
	rpcListeners := make(
		[]*lnd.ListenerWithSignal, 0,
		len(cfg.Lnd.RPCListeners)+1,
	)
	var readyChan chan struct{}
	for i, addr := range cfg.Lnd.RPCListeners {
		lis, err := net.Listen(addr.Network(), addr.String())
		if err != nil {
			return fmt.Errorf("error listening on %s: %w",
				addr, err)
		}

		ready := make(chan struct{})
		rpcListeners = append(rpcListeners, &lnd.ListenerWithSignal{
			Listener: lis,
			Ready:    ready,
		})
		if i == 0 {
			readyChan = ready
		}
	}

	lisCfg := lnd.ListenerCfg{
		RPCListeners: rpcListeners,
	}

	// Step 5: Start lnd in a goroutine. During startup, lnd will call
	// our RegisterGrpcSubserver, registering both lnd and tapd services.
	var wg sync.WaitGroup
	lndErrChan := make(chan error, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()

		err := lnd.Main(
			cfg.Lnd, lisCfg, implCfg, interceptor,
		)
		if err != nil {
			lndErrChan <- err
		}
	}()

	// Step 6: Wait for lnd to be ready.
	select {
	case <-readyChan:
	case err := <-lndErrChan:
		return fmt.Errorf("lnd failed to start: %w", err)
	case <-interceptor.ShutdownChannel():
		wg.Wait()

		return nil
	}

	// Step 7: Create full lnd client services via the external RPC
	// address. The lndclient will wait for chain sync and wallet unlock.
	lndAddr := cfg.Lnd.RPCListeners[0].String()

	// Derive the macaroon directory from the lnd config. When
	// --no-macaroons is set, we provide a dummy macaroon hex string so
	// lndclient doesn't try to load macaroon files from disk (which
	// don't exist). lnd won't validate the macaroon anyway.
	activeNet := cfg.Lnd.ActiveNetParams.Name
	svcsCfg := &lndclient.LndServicesConfig{
		LndAddress:            lndAddr,
		Network:               lndclient.Network(activeNet),
		Insecure:              true,
		BlockUntilChainSynced: true,
		BlockUntilUnlocked:    true,
		CallerCtx:             ctx,
	}
	if cfg.Lnd.NoMacaroons {
		// Use a dummy macaroon that lndclient can deserialize.
		// lnd won't validate it with --no-macaroons.
		svcsCfg.CustomMacaroonHex = "0201047465737402067" +
			"788991234560000062052d26ed139ea5af83e675" +
			"500c4ccb2471f62191b745bab820f129e5588a255d2"
	} else {
		macDir := filepath.Join(
			cfg.Lnd.DataDir, "chain", "bitcoin",
			cfg.Lnd.ActiveNetParams.Name,
		)
		svcsCfg.MacaroonDir = macDir
	}

	lndServices, err := lndclient.NewLndServices(svcsCfg)
	if err != nil {
		return fmt.Errorf("error creating lnd services: %w", err)
	}
	defer lndServices.Close()

	// Step 8: Configure the tapd server shell with lnd's services. This
	// fills in the empty shell with all the stores, chain bridge, wallet
	// integration, etc.
	tapErrChan := make(chan error, 1)
	err = tapcfg.ConfigureSubServer(
		tapServer, cfg.TaprootAssets, tapdLog,
		&lndServices.LndServices, true, tapErrChan,
	)
	if err != nil {
		return fmt.Errorf("error configuring tapd: %w", err)
	}

	// Step 9: Initialize tapd's RPC services. The gRPC services were
	// already registered on lnd's server during RegisterGrpcSubserver,
	// and now that the server is configured, RPCs will function.
	err = tapServer.StartAsSubserver(lndServices)
	if err != nil {
		return fmt.Errorf("error starting tapd subserver: %w", err)
	}

	tapdLog.Infof("Integrated tapd+lnd daemon fully active!")

	// Signal readiness via file if requested. Test harnesses use this
	// to avoid calling tapd RPCs before RPCServer.Start() is called.
	if cfg.ReadyFile != "" {
		if err := os.WriteFile(
			cfg.ReadyFile, []byte("ready\n"), 0644,
		); err != nil {
			return fmt.Errorf("error writing ready file: %w", err)
		}
	}

	// Block until shutdown.
	select {
	case err := <-lndErrChan:
		return fmt.Errorf("lnd error: %w", err)
	case err := <-tapErrChan:
		return fmt.Errorf("tapd error: %w", err)
	case <-interceptor.ShutdownChannel():
	}

	wg.Wait()

	return nil
}
