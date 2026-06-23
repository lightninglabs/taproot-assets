package rpcserver

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// captureRegistrar is a grpc.ServiceRegistrar that records the last
// ServiceDesc it was asked to register, so a test can reach in and invoke the
// (possibly wrapped) method handlers directly.
type captureRegistrar struct {
	desc *grpc.ServiceDesc
	impl interface{}
}

// RegisterService records the descriptor and implementation.
//
// NOTE: This is part of the grpc.ServiceRegistrar interface.
func (c *captureRegistrar) RegisterService(desc *grpc.ServiceDesc,
	impl interface{}) {

	c.desc = desc
	c.impl = impl
}

// markReady flips the server's ready flag, mimicking what Start does once all
// dependencies are wired up.
func markReady(r *RPCServer) {
	atomic.StoreInt32(&r.ready, 1)
}

// requireUnavailable asserts that the passed error is a gRPC Unavailable
// status error.
func requireUnavailable(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	require.Equal(t, codes.Unavailable, status.Code(err))
}

// TestCheckReady asserts that checkReady gates calls on the ready flag,
// returning an Unavailable status error until the server is marked ready.
func TestCheckReady(t *testing.T) {
	t.Parallel()

	r := NewRPCServer()

	// A freshly constructed server has not started, so the gate is closed.
	requireUnavailable(t, r.checkReady())

	// Once we flip the ready flag, the gate opens and the check is a noop.
	markReady(r)
	require.NoError(t, r.checkReady())
}

// TestReadyGatedRegistrarGatesHandlers asserts that every unary handler
// registered through the readyGatedRegistrar is wrapped with the readiness
// gate: before the server is ready the underlying handler is never reached and
// the call fails with Unavailable, and after it is ready the call dispatches
// through to the real handler.
func TestReadyGatedRegistrarGatesHandlers(t *testing.T) {
	t.Parallel()

	r := NewRPCServer()

	// The underlying handler records whether it ran and returns a sentinel
	// value so we can tell a real dispatch apart from a gated rejection.
	var handlerCalls int32
	const sentinel = "dispatched"
	innerHandler := func(_ interface{}, _ context.Context,
		_ func(interface{}) error,
		_ grpc.UnaryServerInterceptor) (interface{}, error) {

		atomic.AddInt32(&handlerCalls, 1)
		return sentinel, nil
	}

	// Register a one-method service through the gated registrar.
	capture := &captureRegistrar{}
	gated := newReadyGatedRegistrar(capture, r)
	desc := &grpc.ServiceDesc{
		ServiceName: "test.Service",
		HandlerType: (*interface{})(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Method",
				Handler:    innerHandler,
			},
		},
	}
	gated.RegisterService(desc, r)

	require.NotNil(t, capture.desc)
	require.Len(t, capture.desc.Methods, 1)

	invoke := func() (interface{}, error) {
		return capture.desc.Methods[0].Handler(
			r, context.Background(), nil, nil,
		)
	}

	// Before the server is ready, the gate rejects the call and the
	// underlying handler is never reached.
	resp, err := invoke()
	requireUnavailable(t, err)
	require.Nil(t, resp)
	require.Equal(t, int32(0), atomic.LoadInt32(&handlerCalls))

	// After the server is ready, the call dispatches through to the real
	// handler.
	markReady(r)
	resp, err = invoke()
	require.NoError(t, err)
	require.Equal(t, sentinel, resp)
	require.Equal(t, int32(1), atomic.LoadInt32(&handlerCalls))
}

// TestReadyGatedRegistrarDoesNotMutateDesc asserts that the gated registrar
// wraps handlers on a copy of the ServiceDesc, leaving the caller's
// (package-level, process-shared) descriptor untouched.
func TestReadyGatedRegistrarDoesNotMutateDesc(t *testing.T) {
	t.Parallel()

	r := NewRPCServer()

	var origCalled bool
	origHandler := func(_ interface{}, _ context.Context,
		_ func(interface{}) error,
		_ grpc.UnaryServerInterceptor) (interface{}, error) {

		origCalled = true
		return nil, nil
	}

	desc := &grpc.ServiceDesc{
		ServiceName: "test.Service",
		Methods: []grpc.MethodDesc{
			{MethodName: "Method", Handler: origHandler},
		},
	}

	capture := &captureRegistrar{}
	newReadyGatedRegistrar(capture, r).RegisterService(desc, r)

	// The original descriptor must still point at the original handler, and
	// the registrar must have handed the underlying server a different,
	// wrapped descriptor.
	require.NotSame(t, desc, capture.desc)
	_, err := desc.Methods[0].Handler(r, context.Background(), nil, nil)
	require.NoError(t, err)
	require.True(t, origCalled)
}

// TestReadinessGateConcurrent exercises the gate from many goroutines while the
// ready flag is flipped, asserting (under -race) that publishing readiness via
// the atomic store is free of data races and that a gated handler never reaches
// the underlying handler before the flag is set.
func TestReadinessGateConcurrent(t *testing.T) {
	t.Parallel()

	r := NewRPCServer()

	// The underlying handler dereferences the rate limiter, exactly like
	// the real Universe handlers do. This is the original crash site: if
	// the gate ever dispatches before the limiter is wired up, this
	// panics on a nil pointer (and, lacking the atomic barrier, the race
	// detector flags the read against the limiter write in the main
	// goroutine).
	innerHandler := func(_ interface{}, _ context.Context,
		_ func(interface{}) error,
		_ grpc.UnaryServerInterceptor) (interface{}, error) {

		_ = r.proofQueryRateLimiter.Limit()
		return nil, nil
	}

	capture := &captureRegistrar{}
	desc := &grpc.ServiceDesc{
		ServiceName: "test.Service",
		Methods: []grpc.MethodDesc{
			{MethodName: "Method", Handler: innerHandler},
		},
	}
	newReadyGatedRegistrar(capture, r).RegisterService(desc, r)
	handler := capture.desc.Methods[0].Handler

	// Track how the calls resolved so we can assert on the main goroutine,
	// since testify's FailNow is not safe to call from a spawned goroutine.
	var dispatched, gated int32

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Either the gate rejects us (server not ready yet) or
			// we dispatch after ready; both are valid, but we must
			// never panic or trip the race detector.
			_, err := handler(r, context.Background(), nil, nil)
			switch {
			case err == nil:
				atomic.AddInt32(&dispatched, 1)
			case status.Code(err) == codes.Unavailable:
				atomic.AddInt32(&gated, 1)
			default:
				atomic.AddInt32(&gated, -1000)
			}
		}()
	}

	// Concurrently mark the server ready, just as Start would. The rate
	// limiter must be initialized before the flag is set so that any
	// handler observing ready also observes a non-nil limiter.
	r.proofQueryRateLimiter = rate.NewLimiter(rate.Inf, 1)
	markReady(r)

	wg.Wait()

	// Every call must have resolved to either a clean dispatch or an
	// Unavailable rejection; no call may have produced any other error.
	require.Equal(t, int32(50), dispatched+gated)
	require.GreaterOrEqual(t, gated, int32(0))
}
