package taro

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	proxy "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taro/build"
	"github.com/lightninglabs/taro/rpcperms"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

// Server is the main daemon construct for the Taro server. It handles spinning
// up the RPC sever, the database, and any other components that the taro
// server needs to function.
type Server struct {
	started  int32
	shutdown int32

	cfg *Config

	rpcServer *rpcServer

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewServer creates a new server given the passed config.
func NewServer(cfg *Config) (*Server, error) {
	return &Server{
		cfg:  cfg,
		quit: make(chan struct{}, 1),
	}, nil
}

// RunUntilShutdown runs the main Taro server loop until a signal is received
// to shutdown the process.
func (s *Server) RunUntilShutdown() error {
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
		srvrLog.Errorf("Shutting down because error in main "+
			"method: "+format, args...)
		return fmt.Errorf(format, args...)
	}

	// Show version at startup.
	srvrLog.Infof("Version: %s commit=%s, build=%s, logging=%s, "+
		"debuglevel=%s", build.Version(), build.Commit,
		build.Deployment, build.LoggingType, s.cfg.DebugLevel)

	srvrLog.Infof("Active network: %v", s.cfg.ChainParams.Name)

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

	// Create a new RPC interceptor that we'll add to the GRPC server. This
	// will be used to log the API calls invoked on the GRPC server.
	interceptorChain := rpcperms.NewInterceptorChain(
		rpcsLog, s.cfg.RPCConfig.NoMacaroons, nil,
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

	// If we're usign macaroons, then go ahead and instntiate the main
	// macaroon service.
	if !s.cfg.RPCConfig.NoMacaroons {
		macaroonService, err := lndclient.NewMacaroonService(
			&lndclient.MacaroonServiceConfig{
				RootKeyStore:     s.cfg.DatabaseConfig.RootKeyStore,
				MacaroonLocation: taroMacaroonLocation,
				MacaroonPath:     s.cfg.MacaroonPath,
				Checkers: []macaroons.Checker{
					macaroons.IPLockChecker,
				},
				RequiredPerms: RequiredPermissions,
			},
		)
		if err != nil {
			return fmt.Errorf("unable to create macaroon "+
				"service: %v", err)
		}
		rpcsLog.Infof("Validating RPC requests based on macaroon "+
			"at: %v", s.cfg.MacaroonPath)

		if err := macaroonService.Start(); err != nil {
			return err
		}

		// Register the macaroon service with the main interceptor
		// chain.
		interceptorChain.AddMacaroonService(macaroonService.Service)
	}

	rpcServerOpts := interceptorChain.CreateServerOpts()
	serverOpts = append(serverOpts, rpcServerOpts...)
	serverOpts = append(
		serverOpts, grpc.MaxRecvMsgSize(lnrpc.MaxGrpcMsgSize),
	)

	grpcServer := grpc.NewServer(serverOpts...)
	defer grpcServer.Stop()

	// Initialize, and register our implementation of the gRPC interface
	// exported by the rpcServer.
	rpcServer, err := newRPCServer(
		s.cfg.SignalInterceptor, interceptorChain, s.cfg,
	)
	if err != nil {
		return mkErr("unable to create rpc server: %v", err)
	}
	err = rpcServer.RegisterWithGrpcServer(grpcServer)
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
	// direct tarod to connect to its loopback address rather than a
	// wildcard to prevent certificate issues when accessing the proxy
	// externally.
	stopProxy, err := startRestProxy(s.cfg, rpcServer)
	if err != nil {
		return mkErr("error starting REST proxy: %v", err)
	}
	defer stopProxy()

	// TODO(roasbeef): make macaroons service, needs the lnd APIs present
	// an abstracted

	// First, we'll start the main batched asset minter.
	if err := s.cfg.AssetMinter.Start(); err != nil {
		return mkErr("unable to start asset minter: %v", err)
	}

	// Now we have created all dependencies necessary to populate and
	// start the RPC server.
	if err := rpcServer.Start(); err != nil {
		return mkErr("unable to start RPC server: %v", err)
	}
	defer func() {
		_ = rpcServer.Stop()
	}()

	// We transition the RPC state to Active, as the RPC server is up.
	interceptorChain.SetRPCActive()

	// We transition the server state to Active, as the server is up.
	interceptorChain.SetServerActive()

	srvrLog.Infof("Taro Daemon fully active!")

	// Wait for shutdown signal from either a graceful server stop or from
	// the interrupt handler.
	select {
	case <-s.cfg.SignalInterceptor.ShutdownChannel():
	case <-s.quit:
	}
	return nil
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
			MarshalOptions: protojson.MarshalOptions{
				UseProtoNames:   true,
				EmitUnpopulated: true,
			},
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
			err := http.Serve(lis, corsHandler)
			if err != nil && !lnrpc.IsClosedConnError(err) {
				rpcsLog.Error(err)
			}
		}()
	}

	// Wait for REST servers to be up running.
	wg.Wait()

	return shutdown, nil
}

// Stop signals that the main taro server should attempt a graceful shutdown.
func (s *Server) Stop() error {
	if atomic.AddInt32(&s.shutdown, 1) != 1 {
		return nil
	}

	srvrLog.Infof("Stopping Main Server")

	// TODO(roasbeef): stop all other sub-systems

	if err := s.rpcServer.Stop(); err != nil {
		return err
	}
	if err := s.cfg.AssetMinter.Start(); err != nil {
		return err
	}

	close(s.quit)

	s.wg.Wait()

	return nil
}
