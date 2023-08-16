package rpcperms

import (
	"context"
	"fmt"
	"sync"

	"github.com/btcsuite/btclog"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/lightninglabs/taproot-assets/monitoring"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

// rpcState is an enum that we use to keep track of the current RPC service
// state. This will transition as we go from startup to unlocking the wallet,
// and finally fully active.
type rpcState uint8

const (
	// waitingToStart indicates that we're at the beginning of the startup
	// process. In a cluster environment this may mean that we're waiting to
	// become the leader in which case RPC calls will be disabled until
	// this instance has been elected as leader.
	waitingToStart rpcState = iota

	// rpcActive means that the RPC server is ready to accept calls.
	rpcActive

	// serverActive means that the tapd server is ready to accept calls.
	serverActive
)

var (
	// ErrWaitingToStart is returned if LND is still waiting to start,
	// possibly blocked until elected as the leader.
	ErrWaitingToStart = fmt.Errorf("waiting to start, RPC services not " +
		"available")

	// ErrRPCStarting is returned if the wallet has been unlocked but the
	// RPC server is not yet ready to accept calls.
	ErrRPCStarting = fmt.Errorf("the RPC server is in the process of " +
		"starting up, but not yet ready to accept calls")
)

// InterceptorChain is a struct that can be added to the running GRPC server,
// intercepting API calls. This is useful for logging, enforcing permissions,
// supporting middleware etc. The following diagram shows the order of each
// interceptor in the chain and when exactly requests/responses are intercepted
// and forwarded to external middleware for approval/modification. Middleware in
// general can only intercept gRPC requests/responses that are sent by the
// client with a macaroon that contains a custom caveat that is supported by one
// of the registered middlewares.
//
//	    |
//	    | gRPC request from client
//	    |
//	+---v--------------------------------+
//	|   InterceptorChain                 |
//	+-+----------------------------------+
//	  | Log Interceptor                  |
//	  +----------------------------------+
//	  | RPC State Interceptor            |
//	  +----------------------------------+
//	  | Macaroon Interceptor             |
//	  +----------------------------------+
//	  | Prometheus Interceptor           |
//	  +-+--------------------------------+
//	    | validated gRPC request from client
//	+---v--------------------------------+
//	|   main gRPC server                 |
//	+---+--------------------------------+
//	    |
//	    | original gRPC request to client
//	    |
//	    v
type InterceptorChain struct {
	stopped sync.Once

	// state is the current RPC state of our RPC server.
	state rpcState

	// noMacaroons should be set true if we don't want to check macaroons.
	noMacaroons bool

	// svc is the macaroon service used to enforce permissions in case
	// macaroons are used.
	svc *macaroons.Service

	// permissionMap is the permissions to enforce if macaroons are used.
	permissionMap map[string][]bakery.Op

	// rpcsLog is the logger used to log calls to the RPCs intercepted.
	rpcsLog btclog.Logger

	// macaroonWhitelist defines methods that we don't require macaroons to
	// access. We also allow these methods to be called even if not all
	// mandatory middlewares are registered yet. If the wallet is locked
	// then a middleware cannot register itself, creating an impossible
	// situation. Also, a middleware might want to check the state of tapd
	// by calling the State service before it registers itself. So we also
	// need to exclude those calls from the mandatory middleware check.
	macaroonWhitelist map[string]struct{}

	quit chan struct{}
	sync.RWMutex
}

// NewInterceptorChain creates a new InterceptorChain.
func NewInterceptorChain(log btclog.Logger, noMacaroons bool,
	mandatoryMiddleware []string,
	macaroonWhitelist map[string]struct{}) *InterceptorChain {

	return &InterceptorChain{
		state:             waitingToStart,
		noMacaroons:       noMacaroons,
		permissionMap:     make(map[string][]bakery.Op),
		rpcsLog:           log,
		quit:              make(chan struct{}),
		macaroonWhitelist: macaroonWhitelist,
	}
}

// Start starts the InterceptorChain, which is needed to start the state
// subscription server it powers.
func (r *InterceptorChain) Start() error {
	return nil
}

// Stop stops the InterceptorChain and its internal state subscription server.
func (r *InterceptorChain) Stop() error {
	var err error
	r.stopped.Do(func() {
		close(r.quit)
	})

	return err
}

// SetRPCActive moves the RPC state from walletUnlocked to rpcActive.
func (r *InterceptorChain) SetRPCActive() {
	r.Lock()
	defer r.Unlock()

	r.state = rpcActive
}

// SetServerActive moves the RPC state from walletUnlocked to rpcActive.
func (r *InterceptorChain) SetServerActive() {
	r.Lock()
	defer r.Unlock()

	r.state = serverActive
}

// AddMacaroonService adds a macaroon service to the interceptor. After this is
// done every RPC call made will have to pass a valid macaroon to be accepted.
func (r *InterceptorChain) AddMacaroonService(svc *macaroons.Service) {
	r.Lock()
	defer r.Unlock()

	r.svc = svc
}

// MacaroonService returns the currently registered macaroon service. This might
// be nil if none was registered (yet).
func (r *InterceptorChain) MacaroonService() *macaroons.Service {
	r.RLock()
	defer r.RUnlock()

	return r.svc
}

// AddPermission adds a new macaroon rule for the given method.
func (r *InterceptorChain) AddPermission(method string, ops []bakery.Op) error {
	r.Lock()
	defer r.Unlock()

	if _, ok := r.permissionMap[method]; ok {
		return fmt.Errorf("detected duplicate macaroon constraints "+
			"for path: %v", method)
	}

	r.permissionMap[method] = ops
	return nil
}

// Permissions returns the current set of macaroon permissions.
func (r *InterceptorChain) Permissions() map[string][]bakery.Op {
	r.RLock()
	defer r.RUnlock()

	// Make a copy under the read lock to avoid races.
	c := make(map[string][]bakery.Op)
	for k, v := range r.permissionMap {
		s := make([]bakery.Op, len(v))
		copy(s, v)
		c[k] = s
	}

	return c
}

// InterceptorsOpts holds the options that need to be set in some server
// interceptors.
type InterceptorsOpts struct {
	Prometheus *monitoring.PrometheusConfig
}

// CreateServerOpts creates the GRPC server options that can be added to a GRPC
// server in order to add this InterceptorChain.
func (r *InterceptorChain) CreateServerOpts(
	opts *InterceptorsOpts) []grpc.ServerOption {

	var unaryInterceptors []grpc.UnaryServerInterceptor
	var strmInterceptors []grpc.StreamServerInterceptor

	// The first interceptors we'll add to the chain is our logging
	// interceptors, so we can automatically log all errors that happen
	// during RPC calls.
	unaryInterceptors = append(
		unaryInterceptors, errorLogUnaryServerInterceptor(r.rpcsLog),
	)
	strmInterceptors = append(
		strmInterceptors, errorLogStreamServerInterceptor(r.rpcsLog),
	)

	// Next we'll add our RPC state check interceptors, that will check
	// whether the attempted call is allowed in the current state.
	unaryInterceptors = append(
		unaryInterceptors, r.rpcStateUnaryServerInterceptor(),
	)
	strmInterceptors = append(
		strmInterceptors, r.rpcStateStreamServerInterceptor(),
	)

	// We'll add the macaroon interceptors. If macaroons aren't disabled,
	// then these interceptors will enforce macaroon authentication.
	unaryInterceptors = append(
		unaryInterceptors, r.MacaroonUnaryServerInterceptor(),
	)
	strmInterceptors = append(
		strmInterceptors, r.MacaroonStreamServerInterceptor(),
	)

	// Get interceptors for Prometheus to gather gRPC performance metrics.
	// If monitoring is disabled, GetPromInterceptors() will return empty
	// slices.
	promUnary, promStrm := monitoring.GetPromInterceptors(opts.Prometheus)

	// Concatenate the slices of unary and stream interceptors respectively.
	unaryInterceptors = append(unaryInterceptors, promUnary...)
	strmInterceptors = append(strmInterceptors, promStrm...)

	// Create server options from the interceptors we just set up.
	chainedUnary := grpc_middleware.WithUnaryServerChain(
		unaryInterceptors...,
	)
	chainedStream := grpc_middleware.WithStreamServerChain(
		strmInterceptors...,
	)
	serverOpts := []grpc.ServerOption{chainedUnary, chainedStream}

	return serverOpts
}

// errorLogUnaryServerInterceptor is a simple UnaryServerInterceptor that will
// automatically log any errors that occur when serving a client's unary
// request.
func errorLogUnaryServerInterceptor(logger btclog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {

		resp, err := handler(ctx, req)
		if err != nil {
			// TODO(roasbeef): also log request details?
			logger.Errorf("[%v]: %v", info.FullMethod, err)
		}

		return resp, err
	}
}

// errorLogStreamServerInterceptor is a simple StreamServerInterceptor that
// will log any errors that occur while processing a client or server streaming
// RPC.
func errorLogStreamServerInterceptor(logger btclog.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {

		err := handler(srv, ss)
		if err != nil {
			logger.Errorf("[%v]: %v", info.FullMethod, err)
		}

		return err
	}
}

// checkMacaroon validates that the context contains the macaroon needed to
// invoke the given RPC method.
func (r *InterceptorChain) checkMacaroon(ctx context.Context,
	fullMethod string) error {

	// If noMacaroons is set, we'll always allow the call.
	if r.noMacaroons {
		return nil
	}

	// Check whether the method is whitelisted, if so we'll allow it
	// regardless of macaroons.
	_, ok := r.macaroonWhitelist[fullMethod]
	if ok {
		return nil
	}

	r.RLock()
	svc := r.svc
	r.RUnlock()

	// If the macaroon service is not yet active, we cannot allow
	// the call.
	if svc == nil {
		return fmt.Errorf("unable to determine macaroon permissions")
	}

	r.RLock()
	uriPermissions, ok := r.permissionMap[fullMethod]
	r.RUnlock()
	if !ok {
		return fmt.Errorf("%s: unknown permissions required for method",
			fullMethod)
	}

	// Find out if there is an external validator registered for
	// this method. Fall back to the internal one if there isn't.
	validator, ok := svc.ExternalValidators[fullMethod]
	if !ok {
		validator = svc
	}

	// Now that we know what validator to use, let it do its work.
	return validator.ValidateMacaroon(ctx, uriPermissions, fullMethod)
}

// MacaroonUnaryServerInterceptor is a GRPC interceptor that checks whether the
// request is authorized by the included macaroons.
func (r *InterceptorChain) MacaroonUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {

		// Check macaroons.
		if err := r.checkMacaroon(ctx, info.FullMethod); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// MacaroonStreamServerInterceptor is a GRPC interceptor that checks whether
// the request is authorized by the included macaroons.
func (r *InterceptorChain) MacaroonStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {

		// Check macaroons.
		err := r.checkMacaroon(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}

		return handler(srv, ss)
	}
}

// checkRPCState checks whether a call to the given server is allowed in the
// current RPC state.
func (r *InterceptorChain) checkRPCState(srv interface{}) error {
	// The StateService is being accessed, we allow the call regardless of
	// the current state.
	_, ok := srv.(lnrpc.StateServer)
	if ok {
		return nil
	}

	r.RLock()
	state := r.state
	r.RUnlock()

	switch state {
	// Do not accept any RPC calls (unless to the state service) until LND
	// has not started.
	case waitingToStart:
		return ErrWaitingToStart

	// If the RPC server or tapd server is active, we allow all calls.
	case rpcActive, serverActive:

	default:
		return fmt.Errorf("unknown RPC state: %v", state)
	}

	return nil
}

// rpcStateUnaryServerInterceptor is a GRPC interceptor that checks whether
// calls to the given gGRPC server is allowed in the current rpc state.
func (r *InterceptorChain) rpcStateUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {

		if err := r.checkRPCState(info.Server); err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// rpcStateStreamServerInterceptor is a GRPC interceptor that checks whether
// calls to the given gGRPC server is allowed in the current rpc state.
func (r *InterceptorChain) rpcStateStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {

		if err := r.checkRPCState(srv); err != nil {
			return err
		}

		return handler(srv, ss)
	}
}
