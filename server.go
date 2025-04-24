package taprootassets

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/monitoring"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/rpcperms"
	"github.com/lightninglabs/taproot-assets/tapchannel"
	cmsg "github.com/lightninglabs/taproot-assets/tapchannelmsg"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/channeldb"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/funding"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwallet"
	lnwl "github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chancloser"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/lightningnetwork/lnd/msgmux"
	"github.com/lightningnetwork/lnd/sweep"
	"github.com/lightningnetwork/lnd/tlv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/proto"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

// Server is the main daemon construct for the Taproot Asset server. It handles
// spinning up the RPC sever, the database, and any other components that the
// Taproot Asset server needs to function.
type Server struct {
	started  int32
	shutdown int32

	// ready is a channel that is closed once the server is ready to do its
	// work.
	ready chan bool

	chainParams *address.ChainParams

	cfg *Config

	*rpcServer
	macaroonService *lndclient.MacaroonService

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewServer creates a new server given the passed config.
func NewServer(chainParams *address.ChainParams, cfg *Config) *Server {
	return &Server{
		chainParams: chainParams,
		cfg:         cfg,
		ready:       make(chan bool),
		quit:        make(chan struct{}, 1),
	}
}

// UpdateConfig updates the server's configuration. This MUST be called before
// the server is started.
func (s *Server) UpdateConfig(cfg *Config) {
	s.cfg = cfg
}

// initialize creates and initializes an instance of the macaroon service and
// rpc server based on the server configuration. This method ensures that
// everything is cleaned up in case there is an error while initializing any of
// the components.
//
// NOTE: the rpc server is not registered with any grpc server in this function.
func (s *Server) initialize(interceptorChain *rpcperms.InterceptorChain) error {
	var ready bool

	// If by the time this function exits we haven't yet given the ready
	// signal, we detect it here and signal that the daemon should quit.
	defer func() {
		if !ready {
			close(s.quit)
		}
	}()

	// Show version at startup.
	srvrLog.Infof("Version: %s, build=%s, logging=%s, "+
		"debuglevel=%s, active_network=%v", Version(), build.Deployment,
		build.LoggingType, s.cfg.DebugLevel, s.cfg.ChainParams.Name)

	// Depending on how far we got in initializing the server, we might need
	// to clean up certain services that were already started. Keep track of
	// them with this map of service name to shutdown function.
	shutdownFuncs := make(map[string]func() error)
	defer func() {
		for serviceName, shutdownFn := range shutdownFuncs {
			if err := shutdownFn(); err != nil {
				srvrLog.Errorf("Error shutting down %s "+
					"service: %v", serviceName, err)
			}
		}
	}()

	// If we're using macaroons, then go ahead and instantiate the main
	// macaroon service.
	if !s.cfg.RPCConfig.NoMacaroons {
		var err error
		s.macaroonService, err = lndclient.NewMacaroonService(
			&lndclient.MacaroonServiceConfig{
				RootKeyStore:     s.cfg.DatabaseConfig.RootKeyStore,
				MacaroonLocation: tapdMacaroonLocation,
				MacaroonPath:     s.cfg.MacaroonPath,
				Checkers: []macaroons.Checker{
					macaroons.IPLockChecker,
				},
				RequiredPerms: taprpc.RequiredPermissions,
			},
		)
		if err != nil {
			return fmt.Errorf("unable to create macaroon "+
				"service: %w", err)
		}
		rpcsLog.Infof("Validating RPC requests based on macaroon "+
			"at: %v", s.cfg.MacaroonPath)

		if err := s.macaroonService.Start(); err != nil {
			return err
		}

		shutdownFuncs["macaroonService"] = s.macaroonService.Stop

		if interceptorChain != nil {
			// Register the macaroon service with the main
			// interceptor chain.
			interceptorChain.AddMacaroonService(
				s.macaroonService.Service,
			)

			// Register all our known permission with the macaroon
			// service.
			for method, ops := range taprpc.RequiredPermissions {
				err := interceptorChain.AddPermission(
					method, ops,
				)
				if err != nil {
					return err
				}
			}
		}
	}

	// Initialize, and register our implementation of the gRPC interface
	// exported by the rpcServer.
	var err error
	s.rpcServer, err = newRPCServer(
		s.cfg.SignalInterceptor, interceptorChain, s.cfg,
	)
	if err != nil {
		return fmt.Errorf("unable to create rpc server: %w", err)
	}

	// First, we'll start the main batched asset minter.
	if err := s.cfg.AssetMinter.Start(); err != nil {
		return fmt.Errorf("unable to start asset minter: %w", err)
	}

	// Next, we'll start the asset custodian.
	if err := s.cfg.AssetCustodian.Start(); err != nil {
		return fmt.Errorf("unable to start asset custodian: %w", err)
	}

	if err := s.cfg.ReOrgWatcher.Start(); err != nil {
		return fmt.Errorf("unable to start re-org watcher: %w", err)
	}

	if err := s.cfg.ChainPorter.Start(); err != nil {
		return fmt.Errorf("unable to start chain porter: %w", err)
	}

	if err := s.cfg.UniverseFederation.Start(); err != nil {
		return fmt.Errorf("unable to start universe "+
			"federation: %w", err)
	}

	// Start the request for quote (RFQ) manager.
	if err := s.cfg.RfqManager.Start(); err != nil {
		return fmt.Errorf("unable to start RFQ manager: %w", err)
	}

	// Start the auxiliary components.
	if err := s.cfg.AuxLeafSigner.Start(); err != nil {
		return fmt.Errorf("unable to start aux leaf signer: %w", err)
	}
	if err := s.cfg.AuxFundingController.Start(); err != nil {
		return fmt.Errorf("unable to start aux funding controller: %w",
			err)
	}
	if err := s.cfg.AuxTrafficShaper.Start(); err != nil {
		return fmt.Errorf("unable to start aux traffic shaper %w", err)
	}
	if err := s.cfg.AuxInvoiceManager.Start(); err != nil {
		return fmt.Errorf("unable to start aux invoice mgr: %w", err)
	}
	if err := s.cfg.AuxSweeper.Start(); err != nil {
		return fmt.Errorf("unable to start aux sweeper mgr: %w", err)
	}

	// If the server is configured to sync all assets by default, we'll set
	// the universe federation to allow public access.
	if s.cfg.UniFedSyncAllAssets {
		err := s.cfg.UniverseFederation.SetConfigSyncAllAssets()
		if err != nil {
			return fmt.Errorf("unable to set public access "+
				"for universe federation: %w", err)
		}
	}

	// Now we have created all dependencies necessary to populate and
	// start the RPC server.
	if err := s.rpcServer.Start(); err != nil {
		return fmt.Errorf("unable to start RPC server: %w", err)
	}

	// This does have no effect if starting the rpc server is the last step
	// in this function, but its better to have it here in case we add more
	// steps in the future.
	//
	// NOTE: if this is not the last step in the function, feel free to
	// delete this comment.
	shutdownFuncs["rpcServer"] = s.rpcServer.Stop

	shutdownFuncs = nil

	close(s.ready)
	ready = true

	return nil
}

// RunUntilShutdown runs the main Taproot Asset server loop until a signal is
// received to shut down the process.
func (s *Server) RunUntilShutdown(mainErrChan <-chan error) error {
	if atomic.AddInt32(&s.started, 1) != 1 {
		return nil
	}

	defer func() {
		srvrLog.Info("Shutdown complete\n")
		err := s.cfg.LogWriter.Close()
		if err != nil {
			srvrLog.Errorf("Could not close log rotator: %v", err)
		}
	}()

	mkErr := func(format string, args ...interface{}) error {
		logFormat := strings.ReplaceAll(format, "%w", "%v")
		srvrLog.Errorf("Shutting down because error in main "+
			"method: "+logFormat, args...)
		return fmt.Errorf(format, args...)
	}

	// If we have chosen to start with a dedicated listener for the rpc
	// server, we set it directly.
	grpcListeners := append(
		[]*lnd.ListenerWithSignal{}, s.cfg.LisCfg.RPCListeners...,
	)
	if len(grpcListeners) == 0 {
		// Otherwise we create listeners from the RPCListeners defined
		// in the config.
		for _, grpcEndpoint := range s.cfg.RPCListeners {
			// Start a gRPC server listening for HTTP/2
			// connections.
			lis, err := lncfg.ListenOnAddress(grpcEndpoint)
			if err != nil {
				return mkErr("unable to listen on %s: %v",
					grpcEndpoint, err)
			}
			defer func() {
				_ = lis.Close()
			}()

			grpcListeners = append(
				grpcListeners, &lnd.ListenerWithSignal{
					Listener: lis,
					Ready:    make(chan struct{}),
				},
			)
		}
	}

	serverOpts := s.cfg.GrpcServerOpts

	// Get RPC endpoints which don't require macaroons.
	macaroonWhitelist := taprpc.MacaroonWhitelist(
		s.cfg.UniversePublicAccess.IsReadAccessGranted(),
		s.cfg.UniversePublicAccess.IsWriteAccessGranted(),
		s.cfg.RPCConfig.AllowPublicUniProofCourier,
		s.cfg.RPCConfig.AllowPublicStats,
	)

	// Create a new RPC interceptor that we'll add to the GRPC server. This
	// will be used to log the API calls invoked on the GRPC server.
	interceptorChain := rpcperms.NewInterceptorChain(
		rpcsLog, s.cfg.RPCConfig.NoMacaroons, nil, macaroonWhitelist,
	)
	if err := interceptorChain.Start(); err != nil {
		return mkErr("error starting interceptor chain: %v", err)
	}
	defer func() {
		err := interceptorChain.Stop()
		if err != nil {
			rpcsLog.Warnf("error stopping RPC interceptor "+
				"chain: %v", err)
		}
	}()

	err := s.initialize(interceptorChain)
	if err != nil {
		return mkErr("unable to initialize RPC server: %v", err)
	}

	rpcServerOpts := interceptorChain.CreateServerOpts(
		&rpcperms.InterceptorsOpts{
			Prometheus: &s.cfg.Prometheus,
		},
	)
	serverOpts = append(serverOpts, rpcServerOpts...)
	serverOpts = append(serverOpts, ServerMaxMsgReceiveSize)

	keepAliveParams := keepalive.ServerParameters{
		MaxConnectionIdle: time.Minute * 2,
	}

	serverOpts = append(serverOpts, grpc.KeepaliveParams(keepAliveParams))

	grpcServer := grpc.NewServer(serverOpts...)
	defer grpcServer.Stop()

	err = s.rpcServer.RegisterWithGrpcServer(grpcServer)
	if err != nil {
		return mkErr("error registering gRPC server: %v", err)
	}

	// All the necessary components have been registered, so we can
	// actually start listening for requests.
	err = startGrpcListen(s.cfg, grpcServer, grpcListeners)
	if err != nil {
		return mkErr("error starting gRPC listener: %v", err)
	}

	// Now start the REST proxy for our gRPC server above. We'll ensure we
	// direct tapd to connect to its loopback address rather than a
	// wildcard to prevent certificate issues when accessing the proxy
	// externally.
	stopProxy, err := startRestProxy(s.cfg, s.rpcServer)
	if err != nil {
		return mkErr("error starting REST proxy: %v", err)
	}
	defer stopProxy()

	// TODO(roasbeef): make macaroons service, needs the lnd APIs present
	// an abstracted

	defer func() {
		_ = s.rpcServer.Stop()
	}()

	// We transition the RPC state to Active, as the RPC server is up.
	interceptorChain.SetRPCActive()

	// We transition the server state to Active, as the server is up.
	interceptorChain.SetServerActive()

	// If Prometheus monitoring is enabled, start the Prometheus exporter.
	if s.cfg.Prometheus.Active {
		// Set the gRPC server instance in the Prometheus exporter
		// configuration.
		s.cfg.Prometheus.RPCServer = grpcServer

		// Provide Prometheus collectors with access to Universe stats.
		s.cfg.Prometheus.UniverseStats = s.cfg.UniverseStats

		// Provide Prometheus collectors with access to the asset store.
		s.cfg.Prometheus.AssetStore = s.cfg.AssetStore

		// Provide Prometheus collectors with access to the asset
		// minter.
		s.cfg.Prometheus.AssetMinter = s.cfg.AssetMinter

		promExporter, err := monitoring.NewPrometheusExporter(
			&s.cfg.Prometheus,
		)
		if err != nil {
			return mkErr("Unable to get prometheus exporter: %v",
				err)
		}

		if err := promExporter.Start(); err != nil {
			return mkErr("Unable to start prometheus exporter: %v",
				err)
		}

		srvrLog.Infof("Prometheus exporter server listening on %v",
			s.cfg.Prometheus.ListenAddr)
	}

	srvrLog.Infof("Taproot Asset Daemon fully active!")

	// Wait for shutdown signal from either a graceful server stop or from
	// the interrupt handler.
	select {
	case <-s.cfg.SignalInterceptor.ShutdownChannel():
		srvrLog.Infof("Received SIGINT (Ctrl+C). Shutting down...")

	case err := <-mainErrChan:
		if err == nil {
			srvrLog.Debug("Main err chan closed")
			return nil
		}

		// We'll report the error to the main daemon, but only if this
		// isn't a context cancel.
		if fn.IsCanceled(err) {
			srvrLog.Debugf("Got context canceled error: %v", err)
			return nil
		}

		return mkErr("received critical error from subsystem: %w", err)

	case <-s.quit:
	}
	return nil
}

// StartAsSubserver is an alternative to Start where the RPC server does not
// create its own gRPC server but registers to an existing one. The same goes
// for REST (if enabled), instead of creating an own mux and HTTP server, we
// register to an existing one.
func (s *Server) StartAsSubserver(lndGrpc *lndclient.GrpcLndServices) error {
	if err := s.initialize(nil); err != nil {
		return fmt.Errorf("unable to initialize RPC server: %w", err)
	}

	return nil
}

// ValidateMacaroon extracts the macaroon from the context's gRPC metadata,
// checks its signature, makes sure all specified permissions for the called
// method are contained within and finally ensures all caveat conditions are
// met. A non-nil error is returned if any of the checks fail. This method is
// needed to enable tapd running as an external subserver in the same process
// as lnd but still validate its own macaroons.
func (s *Server) ValidateMacaroon(ctx context.Context,
	requiredPermissions []bakery.Op, fullMethod string) error {

	if s.macaroonService == nil {
		return fmt.Errorf("macaroon service has not been initialised")
	}

	// Delegate the call to tapd's own macaroon validator service.
	return s.macaroonService.ValidateMacaroon(
		ctx, requiredPermissions, fullMethod,
	)
}

// startGrpcListen starts the GRPC server on the passed listeners.
func startGrpcListen(cfg *Config, grpcServer *grpc.Server,
	listeners []*lnd.ListenerWithSignal) error {

	// Use a WaitGroup so we can be sure the instructions on how to input the
	// password is the last thing to be printed to the console.
	var wg sync.WaitGroup

	for _, lis := range listeners {
		wg.Add(1)
		go func(lis *lnd.ListenerWithSignal) {
			rpcsLog.Infof("RPC server listening on %s", lis.Addr())

			// Close the ready chan to indicate we are listening.
			close(lis.Ready)

			wg.Done()
			_ = grpcServer.Serve(lis)
		}(lis)
	}

	// Wait for gRPC servers to be up running.
	wg.Wait()

	return nil
}

// startRestProxy starts the given REST proxy on the listeners found in the
// config.
func startRestProxy(cfg *Config, rpcServer *rpcServer) (func(), error) {
	// We use the first RPC listener as the destination for our REST proxy.
	// If the listener is set to listen on all interfaces, we replace it
	// with localhost, as we cannot dial it directly.
	restProxyDest := cfg.RPCListeners[0].String()
	switch {
	case strings.Contains(restProxyDest, "0.0.0.0"):
		restProxyDest = strings.Replace(
			restProxyDest, "0.0.0.0", "127.0.0.1", 1,
		)

	case strings.Contains(restProxyDest, "[::]"):
		restProxyDest = strings.Replace(
			restProxyDest, "[::]", "[::1]", 1,
		)
	}

	var shutdownFuncs []func()
	shutdown := func() {
		for _, shutdownFn := range shutdownFuncs {
			shutdownFn()
		}
	}

	// Start a REST proxy for our gRPC server.
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	shutdownFuncs = append(shutdownFuncs, cancel)

	// We'll set up a proxy that will forward REST calls to the GRPC
	// server.
	//
	// The default JSON marshaler of the REST proxy only sets OrigName to
	// true, which instructs it to use the same field names as specified in
	// the proto file and not switch to camel case. What we also want is
	// that the marshaler prints all values, even if they are falsey.
	customMarshalerOption := proxy.WithMarshalerOption(
		proxy.MIMEWildcard, &proxy.JSONPb{
			MarshalOptions:   *taprpc.RESTJsonMarshalOpts,
			UnmarshalOptions: *taprpc.RESTJsonUnmarshalOpts,
		},
	)
	mux := proxy.NewServeMux(
		customMarshalerOption,

		// Don't allow falling back to other HTTP methods, we want exact
		// matches only. The actual method to be used can be overwritten
		// by setting X-HTTP-Method-Override so there should be no
		// reason for not specifying the correct method in the first
		// place.
		proxy.WithDisablePathLengthFallback(),
	)

	// Register our services with the REST proxy.
	err := lnrpc.RegisterStateHandlerFromEndpoint(
		ctx, mux, restProxyDest, cfg.RestDialOpts,
	)
	if err != nil {
		return nil, err
	}

	err = rpcServer.RegisterWithRestProxy(
		ctx, mux, cfg.RestDialOpts, restProxyDest,
	)
	if err != nil {
		return nil, err
	}

	// Wrap the default grpc-gateway handler with the WebSocket handler.
	restHandler := lnrpc.NewWebSocketProxy(
		mux, rpcsLog, cfg.WSPingInterval, cfg.WSPongWait,
		nil,
	)

	// Use a WaitGroup so we can be sure the instructions on how to input the
	// password is the last thing to be printed to the console.
	var wg sync.WaitGroup

	// Now spin up a network listener for each requested port and start a
	// goroutine that serves REST with the created mux there.
	for _, restEndpoint := range cfg.RESTListeners {
		lis, err := cfg.RestListenFunc(restEndpoint)
		if err != nil {
			rpcsLog.Errorf("gRPC proxy unable to listen on %s",
				restEndpoint)
			return nil, err
		}

		shutdownFuncs = append(shutdownFuncs, func() {
			err := lis.Close()
			if err != nil {
				rpcsLog.Errorf("Error closing listener: %v",
					err)
			}
		})

		wg.Add(1)
		go func() {
			rpcsLog.Infof("gRPC proxy started at %s", lis.Addr())

			// Create our proxy chain now. A request will pass
			// through the following chain:
			// req ---> CORS handler --> WS proxy --->
			//   REST proxy --> gRPC endpoint
			corsHandler := allowCORS(restHandler, cfg.RestCORS)

			wg.Done()
			err := http.Serve(lis, corsHandler) //nolint:gosec
			if err != nil && !lnrpc.IsClosedConnError(err) {
				rpcsLog.Error(err)
			}
		}()
	}

	// Wait for REST servers to be up running.
	wg.Wait()

	return shutdown, nil
}

// Stop signals that the main tapd server should attempt a graceful shutdown.
func (s *Server) Stop() error {
	if atomic.AddInt32(&s.shutdown, 1) != 1 {
		return nil
	}

	srvrLog.Infof("Stopping Main Server")

	if err := s.rpcServer.Stop(); err != nil {
		return err
	}
	if err := s.cfg.AssetMinter.Stop(); err != nil {
		return err
	}
	if err := s.cfg.AssetCustodian.Stop(); err != nil {
		return err
	}

	if err := s.cfg.ReOrgWatcher.Stop(); err != nil {
		return err
	}

	if err := s.cfg.ChainPorter.Stop(); err != nil {
		return err
	}

	if err := s.cfg.UniverseFederation.Start(); err != nil {
		return err
	}

	if err := s.cfg.RfqManager.Stop(); err != nil {
		return err
	}

	if err := s.cfg.AuxLeafSigner.Stop(); err != nil {
		return err
	}
	if err := s.cfg.AuxFundingController.Stop(); err != nil {
		return err
	}
	if err := s.cfg.AuxTrafficShaper.Stop(); err != nil {
		return err
	}
	if err := s.cfg.AuxInvoiceManager.Stop(); err != nil {
		return err
	}
	if err := s.cfg.AuxSweeper.Stop(); err != nil {
		return err
	}

	if s.macaroonService != nil {
		err := s.macaroonService.Stop()
		if err != nil {
			return err
		}
	}

	close(s.quit)

	s.wg.Wait()

	return nil
}

// A compile-time check to ensure that Server fully implements the
// lnwallet.AuxLeafStore, lnd.AuxDataParser, lnwallet.AuxSigner,
// msgmux.Endpoint, funding.AuxFundingController, htlcswitch.AuxTrafficShaper
// and chancloser.AuxChanCloser interfaces.
var _ lnwl.AuxLeafStore = (*Server)(nil)
var _ lnd.AuxDataParser = (*Server)(nil)
var _ lnwl.AuxSigner = (*Server)(nil)
var _ msgmux.Endpoint = (*Server)(nil)
var _ funding.AuxFundingController = (*Server)(nil)
var _ htlcswitch.AuxTrafficShaper = (*Server)(nil)
var _ chancloser.AuxChanCloser = (*Server)(nil)
var _ lnwl.AuxContractResolver = (*Server)(nil)
var _ sweep.AuxSweeper = (*Server)(nil)

// waitForReady blocks until the server is ready to serve requests. If the
// server is shutting down before we ever become ready, an error is returned.
func (s *Server) waitForReady() error {
	// We just need to wait for the server to be ready (but not block
	// shutdown in case of a startup error). If we shut down after passing
	// this part of the code, the called component will handle the quit
	// signal.

	// In order to give priority to the quit signal, we wrap the blocking
	// select so that we give a chance to the quit signal to be read first.
	// This is needed as there is currently no wait to un-set the ready
	// signal, so we would have a race between the 2 channels.
	select {
	case <-s.quit:
		return fmt.Errorf("tapd is shutting down")

	default:
		// We now wait for either signal to be provided.
		select {
		case <-s.ready:
			return nil
		case <-s.quit:
			return fmt.Errorf("tapd is shutting down")
		}
	}
}

// FetchLeavesFromView attempts to fetch the auxiliary leaves that correspond to
// the passed aux blob, and pending fully evaluated HTLC view.
//
// NOTE: This method is part of the lnwallet.AuxLeafStore interface.
func (s *Server) FetchLeavesFromView(
	in lnwl.CommitDiffAuxInput) lfn.Result[lnwl.CommitDiffAuxResult] {

	srvrLog.Debugf("FetchLeavesFromView called, whoseCommit=%v, "+
		"ourBalance=%v, theirBalance=%v, numOurUpdates=%d, "+
		"numTheirUpdates=%d", in.WhoseCommit, in.OurBalance,
		in.TheirBalance, len(in.UnfilteredView.Updates.Local),
		len(in.UnfilteredView.Updates.Remote))

	// The aux leaf creator is fully stateless, and we don't need to wait
	// for the server to be started before being able to use it.
	return tapchannel.FetchLeavesFromView(s.chainParams, in)
}

// FetchLeavesFromCommit attempts to fetch the auxiliary leaves that
// correspond to the passed aux blob, and an existing channel
// commitment.
//
// NOTE: This method is part of the lnwallet.AuxLeafStore interface.
// nolint:lll
func (s *Server) FetchLeavesFromCommit(chanState lnwl.AuxChanState,
	com channeldb.ChannelCommitment, keys lnwl.CommitmentKeyRing,
	whoseCommit lntypes.ChannelParty) lfn.Result[lnwl.CommitDiffAuxResult] {

	srvrLog.Debugf("FetchLeavesFromCommit called, ourBalance=%v, "+
		"theirBalance=%v, numHtlcs=%d", com.LocalBalance,
		com.RemoteBalance, len(com.Htlcs))

	// The aux leaf creator is fully stateless, and we don't need to wait
	// for the server to be started before being able to use it.
	return tapchannel.FetchLeavesFromCommit(
		s.chainParams, chanState, com, keys, whoseCommit,
	)
}

// FetchLeavesFromRevocation attempts to fetch the auxiliary leaves
// from a channel revocation that stores balance + blob information.
//
// NOTE: This method is part of the lnwallet.AuxLeafStore interface.
func (s *Server) FetchLeavesFromRevocation(
	r *channeldb.RevocationLog) lfn.Result[lnwl.CommitDiffAuxResult] {

	srvrLog.Debugf("FetchLeavesFromRevocation called, ourBalance=%v, "+
		"teirBalance=%v, numHtlcs=%d", r.OurBalance, r.TheirBalance,
		len(r.HTLCEntries))

	// The aux leaf creator is fully stateless, and we don't need to wait
	// for the server to be started before being able to use it.
	return tapchannel.FetchLeavesFromRevocation(r)
}

// ApplyHtlcView serves as the state transition function for the custom
// channel's blob. Given the old blob, and an HTLC view, then a new
// blob should be returned that reflects the pending updates.
//
// NOTE: This method is part of the lnwallet.AuxLeafStore interface.
func (s *Server) ApplyHtlcView(
	in lnwl.CommitDiffAuxInput) lfn.Result[lfn.Option[tlv.Blob]] {

	srvrLog.Debugf("ApplyHtlcView called, whoseCommit=%v, "+
		"ourBalance=%v, theirBalance=%v, numOurUpdates=%d, "+
		"numTheirUpdates=%d", in.WhoseCommit, in.OurBalance,
		in.TheirBalance, len(in.UnfilteredView.Updates.Local),
		len(in.UnfilteredView.Updates.Remote))

	// The aux leaf creator is fully stateless, and we don't need to wait
	// for the server to be started before being able to use it.
	return tapchannel.ApplyHtlcView(s.chainParams, in)
}

// InlineParseCustomData replaces any custom data binary blob in the given RPC
// message with its corresponding JSON formatted data. This transforms the
// binary (likely TLV encoded) data to a human-readable JSON representation
// (still as byte slice).
//
// NOTE: This method is part of the lnd.AuxDataParser interface.
func (s *Server) InlineParseCustomData(msg proto.Message) error {
	srvrLog.Tracef("InlineParseCustomData called with %T", msg)

	// We don't need to wait for the server to be ready here, as the
	// following function is fully stateless.
	return cmsg.ParseCustomChannelData(msg)
}

// Name returns the name of this endpoint. This MUST be unique across all
// registered endpoints.
//
// NOTE: This method is part of the msgmux.MsgEndpoint interface.
func (s *Server) Name() msgmux.EndpointName {
	return tapchannel.MsgEndpointName
}

// CanHandle returns true if the target message can be routed to this endpoint.
//
// NOTE: This method is part of the msgmux.MsgEndpoint interface.
func (s *Server) CanHandle(msg msgmux.PeerMsg) bool {
	err := s.waitForReady()
	if err != nil {
		srvrLog.Debugf("Can't handle PeerMsg, server not ready %v",
			err)
		return false
	}
	return s.cfg.AuxFundingController.CanHandle(msg)
}

// SendMessage handles the target message, and returns true if the message was
// able to be processed.
//
// NOTE: This method is part of the msgmux.MsgEndpoint interface.
func (s *Server) SendMessage(ctx context.Context, msg msgmux.PeerMsg) bool {
	err := s.waitForReady()
	if err != nil {
		srvrLog.Debugf("Failed to send PeerMsg, server not ready %v",
			err)
		return false
	}
	return s.cfg.AuxFundingController.SendMessage(ctx, msg)
}

// SubmitSecondLevelSigBatch takes a batch of aux sign jobs and processes them
// asynchronously.
//
// NOTE: This method is part of the lnwallet.AuxSigner interface.
func (s *Server) SubmitSecondLevelSigBatch(chanState lnwl.AuxChanState,
	commitTx *wire.MsgTx, sigJob []lnwl.AuxSigJob) error {

	srvrLog.Debugf("SubmitSecondLevelSigBatch called, numSigs=%d",
		len(sigJob))

	if err := s.waitForReady(); err != nil {
		return err
	}

	return s.cfg.AuxLeafSigner.SubmitSecondLevelSigBatch(
		chanState, commitTx, sigJob,
	)
}

// PackSigs takes a series of aux signatures and packs them into a single blob
// that can be sent alongside the CommitSig messages.
//
// NOTE: This method is part of the lnwallet.AuxSigner interface.
func (s *Server) PackSigs(
	blob []lfn.Option[tlv.Blob]) lfn.Result[lfn.Option[tlv.Blob]] {

	srvrLog.Debugf("PackSigs called")

	// We don't need to wait for the server to be ready here, as the
	// PackSigs method is fully stateless.
	return tapchannel.PackSigs(blob)
}

// UnpackSigs takes a packed blob of signatures and returns the original
// signatures for each HTLC, keyed by HTLC index.
//
// NOTE: This method is part of the lnwallet.AuxSigner interface.
func (s *Server) UnpackSigs(
	blob lfn.Option[tlv.Blob]) lfn.Result[[]lfn.Option[tlv.Blob]] {

	srvrLog.Debugf("UnpackSigs called")

	// We don't need to wait for the server to be ready here, as the
	// UnpackSigs method is fully stateless.
	return tapchannel.UnpackSigs(blob)
}

// VerifySecondLevelSigs attempts to synchronously verify a batch of aux sig
// jobs.
//
// NOTE: This method is part of the lnwallet.AuxSigner interface.
func (s *Server) VerifySecondLevelSigs(chanState lnwl.AuxChanState,
	commitTx *wire.MsgTx, verifyJob []lnwl.AuxVerifyJob) error {

	srvrLog.Debugf("VerifySecondLevelSigs called")

	// We don't need to wait for the server to be ready here, as the
	// VerifySecondLevelSigs method is fully stateless.
	return tapchannel.VerifySecondLevelSigs(
		s.chainParams, chanState, commitTx, verifyJob,
	)
}

// DescFromPendingChanID takes a pending channel ID, that may already be
// known due to prior custom channel messages, and maybe returns an aux
// funding desc which can be used to modify how a channel is funded.
//
// NOTE: This method is part of the funding.AuxFundingController interface.
func (s *Server) DescFromPendingChanID(pid funding.PendingChanID,
	chanState lnwl.AuxChanState,
	keyRing lntypes.Dual[lnwl.CommitmentKeyRing],
	initiator bool) funding.AuxFundingDescResult {

	srvrLog.Debugf("DescFromPendingChanID called")

	if err := s.waitForReady(); err != nil {
		return lfn.Err[lfn.Option[lnwl.AuxFundingDesc]](err)
	}

	return s.cfg.AuxFundingController.DescFromPendingChanID(
		pid, chanState, keyRing, initiator,
	)
}

// DeriveTapscriptRoot takes a pending channel ID and maybe returns a
// tapscript root that should be used when creating any MuSig2 sessions
// for a channel.
//
// NOTE: This method is part of the funding.AuxFundingController interface.
func (s *Server) DeriveTapscriptRoot(
	pid funding.PendingChanID) funding.AuxTapscriptResult {

	srvrLog.Debugf("DeriveTapscriptRoot called")

	if err := s.waitForReady(); err != nil {
		return lfn.Err[lfn.Option[chainhash.Hash]](err)
	}

	return s.cfg.AuxFundingController.DeriveTapscriptRoot(pid)
}

// ChannelReady is called when a channel has been fully opened and is ready to
// be used. This can be used to perform any final setup or cleanup.
//
// NOTE: This method is part of the funding.AuxFundingController interface.
func (s *Server) ChannelReady(openChan lnwl.AuxChanState) error {
	srvrLog.Debugf("ChannelReady called")

	if err := s.waitForReady(); err != nil {
		return err
	}

	return s.cfg.AuxFundingController.ChannelReady(openChan)
}

// ChannelFinalized is called once we receive the commit sig from a remote
// party and find it to be valid.
//
// NOTE: This method is part of the funding.AuxFundingController interface.
func (s *Server) ChannelFinalized(pid funding.PendingChanID) error {
	srvrLog.Debugf("ChannelFinalized called")

	if err := s.waitForReady(); err != nil {
		return err
	}

	return s.cfg.AuxFundingController.ChannelFinalized(pid)
}

// ShouldHandleTraffic is called in order to check if the channel identified by
// the provided channel ID is handled by the traffic shaper implementation. If
// it is handled by the traffic shaper, then the normal bandwidth calculation
// can be skipped and the bandwidth returned by PaymentBandwidth should be used
// instead.
//
// NOTE: This method is part of the routing.TlvTrafficShaper interface.
func (s *Server) ShouldHandleTraffic(cid lnwire.ShortChannelID,
	fundingBlob, htlcBlob lfn.Option[tlv.Blob]) (bool, error) {

	srvrLog.Debugf("HandleTraffic called, cid=%v, fundingBlob=%v, "+
		"htlcBlob=%v", cid, lnutils.SpewLogClosure(fundingBlob),
		lnutils.SpewLogClosure(htlcBlob))

	if err := s.waitForReady(); err != nil {
		return false, err
	}

	return s.cfg.AuxTrafficShaper.ShouldHandleTraffic(
		cid, fundingBlob, htlcBlob,
	)
}

// PaymentBandwidth returns the available bandwidth for a custom channel decided
// by the given channel aux blob and HTLC blob. A return value of 0 means there
// is no bandwidth available. To find out if a channel is a custom channel that
// should be handled by the traffic shaper, the HandleTraffic method should be
// called first.
//
// NOTE: This method is part of the routing.TlvTrafficShaper interface.
func (s *Server) PaymentBandwidth(fundingBlob, htlcBlob,
	commitmentBlob lfn.Option[tlv.Blob], linkBandwidth,
	htlcAmt lnwire.MilliSatoshi,
	htlcView lnwallet.AuxHtlcView) (lnwire.MilliSatoshi, error) {

	srvrLog.Debugf("PaymentBandwidth called, fundingBlob=%v, htlcBlob=%v, "+
		"commitmentBlob=%v", lnutils.SpewLogClosure(fundingBlob),
		lnutils.SpewLogClosure(htlcBlob),
		lnutils.SpewLogClosure(commitmentBlob))

	if err := s.waitForReady(); err != nil {
		return 0, err
	}

	return s.cfg.AuxTrafficShaper.PaymentBandwidth(
		fundingBlob, htlcBlob, commitmentBlob, linkBandwidth, htlcAmt,
		htlcView,
	)
}

// ProduceHtlcExtraData is a function that, based on the previous custom record
// blob of an HTLC, may produce a different blob or modify the amount of bitcoin
// this HTLC should carry.
//
// NOTE: This method is part of the routing.TlvTrafficShaper interface.
func (s *Server) ProduceHtlcExtraData(totalAmount lnwire.MilliSatoshi,
	htlcCustomRecords lnwire.CustomRecords) (lnwire.MilliSatoshi,
	lnwire.CustomRecords, error) {

	srvrLog.Debugf("ProduceHtlcExtraData called, totalAmount=%d, "+
		"htlcBlob=%v", totalAmount,
		lnutils.SpewLogClosure(htlcCustomRecords))

	if err := s.waitForReady(); err != nil {
		return 0, nil, err
	}

	return s.cfg.AuxTrafficShaper.ProduceHtlcExtraData(
		totalAmount, htlcCustomRecords,
	)
}

// IsCustomHTLC returns true if the HTLC carries the set of relevant custom
// records to put it under the purview of the traffic shaper, meaning that it's
// from a custom channel.
//
// NOTE: This method is part of the routing.TlvTrafficShaper interface.
func (s *Server) IsCustomHTLC(htlcRecords lnwire.CustomRecords) bool {
	// We don't need to wait for server ready here since this operation can
	// be done completely stateless.
	return rfqmsg.HasAssetHTLCCustomRecords(htlcRecords)
}

// AuxCloseOutputs returns the set of close outputs to use for this co-op close
// attempt. We'll add some extra outputs to the co-op close transaction, and
// also give the caller a custom sorting routine.
//
// NOTE: This method is part of the chancloser.AuxChanCloser interface.
func (s *Server) AuxCloseOutputs(
	desc chancloser.AuxCloseDesc) (lfn.Option[chancloser.AuxCloseOutputs],
	error) {

	srvrLog.Tracef("AuxCloseOutputs called, desc=%v",
		lnutils.SpewLogClosure(desc))

	if err := s.waitForReady(); err != nil {
		return lfn.None[chancloser.AuxCloseOutputs](), err
	}

	return s.cfg.AuxChanCloser.AuxCloseOutputs(desc)
}

// ShutdownBlob returns the set of custom records that should be included in
// the shutdown message.
//
// NOTE: This method is part of the chancloser.AuxChanCloser interface.
func (s *Server) ShutdownBlob(
	req chancloser.AuxShutdownReq) (lfn.Option[lnwire.CustomRecords],
	error) {

	srvrLog.Tracef("ShutdownBlob called, req=%v",
		lnutils.SpewLogClosure(req))

	if err := s.waitForReady(); err != nil {
		return lfn.None[lnwire.CustomRecords](), err
	}

	return s.cfg.AuxChanCloser.ShutdownBlob(req)
}

// FinalizeClose is called once the co-op close transaction has been agreed
// upon. We'll finalize the exclusion proofs, then send things off to the
// custodian or porter to finish sending/receiving the proofs.
//
// NOTE: This method is part of the chancloser.AuxChanCloser interface.
func (s *Server) FinalizeClose(desc chancloser.AuxCloseDesc,
	closeTx *wire.MsgTx) error {

	srvrLog.Tracef("FinalizeClose called, desc=%v, closeTx=%v",
		lnutils.SpewLogClosure(desc), lnutils.SpewLogClosure(closeTx))

	if err := s.waitForReady(); err != nil {
		return err
	}

	return s.cfg.AuxChanCloser.FinalizeClose(desc, closeTx)
}

// ResolveContract attempts to obtain a resolution blob for the specified
// contract.
//
// NOTE: This method is part of the lnwallet.AuxContractResolver interface.
func (s *Server) ResolveContract(req lnwl.ResolutionReq) lfn.Result[tlv.Blob] {
	srvrLog.Tracef("ResolveContract called, req=%v",
		lnutils.SpewLogClosure(req))

	if err := s.waitForReady(); err != nil {
		return lfn.Err[tlv.Blob](err)
	}

	return s.cfg.AuxSweeper.ResolveContract(req)
}

// DeriveSweepAddr takes a set of inputs, and the change address we'd use to
// sweep them, and maybe results in an extra sweep output that we should add to
// the sweeping transaction.
//
// NOTE: This method is part of the sweep.AuxSweeper interface.
func (s *Server) DeriveSweepAddr(inputs []input.Input,
	change lnwl.AddrWithKey) lfn.Result[sweep.SweepOutput] {

	srvrLog.Tracef("DeriveSweepAddr called, inputs=%v, change=%v",
		lnutils.SpewLogClosure(inputs), lnutils.SpewLogClosure(change))

	if err := s.waitForReady(); err != nil {
		return lfn.Err[sweep.SweepOutput](err)
	}

	return s.cfg.AuxSweeper.DeriveSweepAddr(inputs, change)
}

// ExtraBudgetForInputs takes a set of inputs and maybe returns an extra budget
// that should be added to the sweep transaction.
//
// NOTE: This method is part of the sweep.AuxSweeper interface.
func (s *Server) ExtraBudgetForInputs(
	inputs []input.Input) lfn.Result[btcutil.Amount] {

	srvrLog.Tracef("ExtraBudgetForInputs called, inputs=%v",
		lnutils.SpewLogClosure(inputs))

	if err := s.waitForReady(); err != nil {
		return lfn.Err[btcutil.Amount](err)
	}

	return s.cfg.AuxSweeper.ExtraBudgetForInputs(inputs)
}

// NotifyBroadcast is used to notify external callers of the broadcast of a
// sweep transaction, generated by the passed BumpRequest.
//
// NOTE: This method is part of the sweep.AuxSweeper interface.
func (s *Server) NotifyBroadcast(req *sweep.BumpRequest,
	tx *wire.MsgTx, fee btcutil.Amount,
	outpointToTxIndex map[wire.OutPoint]int) error {

	srvrLog.Tracef("NotifyBroadcast called, req=%v, tx=%v, fee=%v, "+
		"out_index=%v", lnutils.SpewLogClosure(req),
		lnutils.SpewLogClosure(tx), fee,
		lnutils.SpewLogClosure(outpointToTxIndex))

	if err := s.waitForReady(); err != nil {
		return err
	}

	return s.cfg.AuxSweeper.NotifyBroadcast(req, tx, fee, outpointToTxIndex)
}
