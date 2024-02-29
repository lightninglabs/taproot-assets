package taprootassets

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/monitoring"
	"github.com/lightninglabs/taproot-assets/perms"
	"github.com/lightninglabs/taproot-assets/rpcperms"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

// Server is the main daemon construct for the Taproot Asset server. It handles
// spinning up the RPC sever, the database, and any other components that the
// Taproot Asset server needs to function.
type Server struct {
	started  int32
	shutdown int32

	cfg *Config

	*rpcServer
	macaroonService *lndclient.MacaroonService

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewServer creates a new server given the passed config.
func NewServer(cfg *Config) *Server {
	return &Server{
		cfg:  cfg,
		quit: make(chan struct{}, 1),
	}
}

// initialize creates and initializes an instance of the macaroon service and
// rpc server based on the server configuration. This method ensures that
// everything is cleaned up in case there is an error while initializing any of
// the components.
//
// NOTE: the rpc server is not registered with any grpc server in this function.
func (s *Server) initialize(interceptorChain *rpcperms.InterceptorChain) error {
	// Show version at startup.
	srvrLog.Infof("Version: %s, build=%s, logging=%s, "+
		"debuglevel=%s", Version(), build.Deployment,
		build.LoggingType, s.cfg.DebugLevel)

	srvrLog.Infof("Active network: %v", s.cfg.ChainParams.Name)

	// Depending on how far we got in initializing the server, we might need
	// to clean up certain services that were already started. Keep track of
	// them with this map of service name to shutdown function.
	shutdownFuncs := make(map[string]func() error)
	defer func() {
		for serviceName, shutdownFn := range shutdownFuncs {
			if err := shutdownFn(); err != nil {
				srvrLog.Errorf("Error shutting down %s "+
					"service: %w", serviceName, err)
			}
		}
	}()

	// If we're usign macaroons, then go ahead and instantiate the main
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
				RequiredPerms: perms.RequiredPermissions,
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
			for method, ops := range perms.RequiredPermissions {
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

	if s.cfg.UniversePublicAccess {
		err := s.cfg.UniverseFederation.SetAllowPublicAccess()
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
			defer lis.Close()

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
	macaroonWhitelist := perms.MacaroonWhitelist(
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
