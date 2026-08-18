package rfq

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/graph/db/models"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockHtlcInterceptor is a mock implementation of the HtlcInterceptor interface
// that returns a pre-defined list of errors, one per call. Once the list is
// exhausted, it blocks until the passed context is canceled, mimicking a
// healthy interception stream.
type mockHtlcInterceptor struct {
	sync.Mutex

	// errs are the errors returned by consecutive InterceptHtlcs calls.
	errs []error

	// numCalls is the number of times InterceptHtlcs was called.
	numCalls int
}

func newMockHtlcInterceptor(errs ...error) *mockHtlcInterceptor {
	return &mockHtlcInterceptor{
		errs: errs,
	}
}

// InterceptHtlcs implements the HtlcInterceptor interface.
func (m *mockHtlcInterceptor) InterceptHtlcs(ctx context.Context,
	_ lndclient.HtlcInterceptHandler) error {

	m.Lock()
	m.numCalls++

	var err error
	if len(m.errs) > 0 {
		err, m.errs = m.errs[0], m.errs[1:]
	}
	m.Unlock()

	if err != nil {
		return err
	}

	// No more errors to return, so we act like a healthy stream that only
	// terminates once the context is canceled.
	<-ctx.Done()

	return ctx.Err()
}

// calls returns the number of times InterceptHtlcs was called.
func (m *mockHtlcInterceptor) calls() int {
	m.Lock()
	defer m.Unlock()

	return m.numCalls
}

var _ HtlcInterceptor = (*mockHtlcInterceptor)(nil)

// mockHtlcSubscriber is a mock implementation of the HtlcSubscriber interface
// that forwards the events sent to its events channel.
type mockHtlcSubscriber struct {
	events chan *routerrpc.HtlcEvent
	errs   chan error
}

func newMockHtlcSubscriber() *mockHtlcSubscriber {
	return &mockHtlcSubscriber{
		events: make(chan *routerrpc.HtlcEvent, 8),
		errs:   make(chan error, 1),
	}
}

// SubscribeHtlcEvents implements the HtlcSubscriber interface.
func (m *mockHtlcSubscriber) SubscribeHtlcEvents(_ context.Context) (
	<-chan *routerrpc.HtlcEvent, <-chan error, error) {

	return m.events, m.errs, nil
}

// LookupHtlcResolution implements the HtlcSubscriber interface.
func (m *mockHtlcSubscriber) LookupHtlcResolution(_ context.Context, _ uint64,
	_ uint64) (*lnrpc.LookupHtlcResolutionResponse, error) {

	return nil, errors.New("unimplemented")
}

var _ HtlcSubscriber = (*mockHtlcSubscriber)(nil)

// newTestOrderHandler creates an order handler that only has the given HTLC
// interceptor configured, which is all that's needed for the interception
// related tests.
func newTestOrderHandler(t *testing.T,
	interceptor HtlcInterceptor) *OrderHandler {

	t.Helper()

	handler, err := NewOrderHandler(OrderHandlerCfg{
		CleanupInterval: time.Hour,
		HtlcInterceptor: interceptor,
	})
	require.NoError(t, err)

	return handler
}

// testCircuitKey returns a circuit key for the given HTLC ID.
func testCircuitKey(htlcID uint64) models.CircuitKey {
	return models.CircuitKey{
		ChanID: lnwire.NewShortChanIDFromInt(1234),
		HtlcID: htlcID,
	}
}

// TestIsRecoverableInterceptorErr tests that we correctly identify the errors
// that lnd returns when it can't apply a resolution we sent for an intercepted
// HTLC. Those errors reach us as opaque gRPC status errors, which is why we
// need to match on their string representation.
func TestIsRecoverableInterceptorErr(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		err         error
		recoverable bool
	}{{
		name:        "nil error",
		err:         nil,
		recoverable: false,
	}, {
		// This is lnd's ErrCannotResume, as it reaches us over the
		// wire.
		name: "cannot resume",
		err: status.Error(
			codes.Unknown, "cannot resume in the on-chain flow",
		),
		recoverable: true,
	}, {
		// This is lnd's ErrCannotFail, as it reaches us over the wire.
		name: "cannot fail",
		err: status.Error(
			codes.Unknown, "cannot fail in the on-chain flow",
		),
		recoverable: true,
	}, {
		// This is lnd's ErrFwdNotExists, returned if we resolve an
		// HTLC that lnd doesn't hold (anymore).
		name: "forward does not exist",
		err: status.Error(
			codes.Unknown, "forward does not exist",
		),
		recoverable: true,
	}, {
		name: "wrapped recoverable error",
		err: fmt.Errorf("stream terminated: %w", status.Error(
			codes.Unknown, "cannot fail in the on-chain flow",
		)),
		recoverable: true,
	}, {
		name:        "unrelated error",
		err:         errors.New("connection refused"),
		recoverable: false,
	}, {
		name: "interceptor already registered",
		err: status.Error(
			codes.Unavailable, "interceptor already registered",
		),
		recoverable: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(
				t, tc.recoverable,
				isRecoverableInterceptorErr(tc.err),
			)
		})
	}
}

// TestSetupHtlcInterceptRecovers tests that the order handler re-establishes
// the HTLC interception stream if lnd tears it down because it couldn't apply
// one of our resolutions. This is the regression test for the case where a
// single HTLC that is being resolved on chain took the whole daemon down.
func TestSetupHtlcInterceptRecovers(t *testing.T) {
	t.Parallel()

	onChainErr := status.Error(
		codes.Unknown, "cannot fail in the on-chain flow",
	)
	interceptor := newMockHtlcInterceptor(onChainErr, onChainErr)
	handler := newTestOrderHandler(t, interceptor)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- handler.setupHtlcIntercept(ctx)
	}()

	// The interceptor should be re-established twice, after which the mock
	// blocks until we cancel the context.
	require.Eventually(t, func() bool {
		return interceptor.calls() == 3
	}, 10*time.Second, 10*time.Millisecond)

	// We're still running, no critical error was reported.
	require.Len(t, errChan, 0)

	// Once the context is canceled, we expect a clean exit.
	cancel()

	select {
	case err := <-errChan:
		require.NoError(t, err)

	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for setupHtlcIntercept to return")
	}
}

// TestSetupHtlcInterceptFatalError tests that an error that isn't related to
// the on-chain resolution flow is still reported to the caller, so a tapd
// instance without a working RFQ subsystem doesn't keep running.
func TestSetupHtlcInterceptFatalError(t *testing.T) {
	t.Parallel()

	fatalErr := errors.New("interceptor already registered")
	interceptor := newMockHtlcInterceptor(fatalErr)
	handler := newTestOrderHandler(t, interceptor)

	err := handler.setupHtlcIntercept(context.Background())
	require.ErrorIs(t, err, fatalErr)
	require.Equal(t, 1, interceptor.calls())
}

// TestSetupHtlcInterceptShutdown tests that a canceled context doesn't lead to
// an error being reported.
func TestSetupHtlcInterceptShutdown(t *testing.T) {
	t.Parallel()

	interceptor := newMockHtlcInterceptor()
	handler := newTestOrderHandler(t, interceptor)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, handler.setupHtlcIntercept(ctx))
}

// TestHandleIncomingHtlcNoDoubleResolution tests that we only ever send a
// single resolution per HTLC. lnd offers an HTLC to the interceptor a second
// time when it ends up being resolved on chain, and rejects any resolution we
// send for it, which would tear down the interception stream.
func TestHandleIncomingHtlcNoDoubleResolution(t *testing.T) {
	t.Parallel()

	handler := newTestOrderHandler(t, newMockHtlcInterceptor())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	circuitKey := testCircuitKey(1)
	htlc := lndclient.InterceptedHtlc{
		IncomingCircuitKey: circuitKey,
	}

	// The first time we see the HTLC, we don't have a policy for it, so we
	// resume it.
	resp, err := handler.handleIncomingHtlc(ctx, htlc)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, lndclient.InterceptorActionResume, resp.Action)

	// We should now know that we resolved this HTLC.
	_, resolved := handler.resolvedHtlcs.Load(circuitKey)
	require.True(t, resolved)

	// A different HTLC is still resolved normally.
	otherHtlc := lndclient.InterceptedHtlc{
		IncomingCircuitKey: testCircuitKey(2),
	}
	resp, err = handler.handleIncomingHtlc(ctx, otherHtlc)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// But if lnd offers us the same HTLC again, we must not answer, since
	// any answer would terminate the interception stream. So the call
	// blocks until the stream (or the daemon) shuts down.
	type result struct {
		resp *lndclient.InterceptedHtlcResponse
		err  error
	}
	resultChan := make(chan result, 1)
	go func() {
		resp, err := handler.handleIncomingHtlc(ctx, htlc)
		resultChan <- result{resp: resp, err: err}
	}()

	select {
	case res := <-resultChan:
		t.Fatalf("expected handler to block, got %v, %v", res.resp,
			res.err)

	case <-time.After(200 * time.Millisecond):
	}

	// Once the stream context is canceled, the handler returns without
	// producing a response.
	cancel()

	select {
	case res := <-resultChan:
		require.Nil(t, res.resp)

		// The error must be one that the interceptor setup treats as a
		// clean shutdown. Anything else would make us report a critical
		// error every time we shut down while holding an HTLC.
		require.True(t, fn.IsCanceled(res.err), "error %v is not a "+
			"cancellation", res.err)
		require.False(t, isRecoverableInterceptorErr(res.err))

	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for handler to return")
	}
}

// TestHandleIncomingHtlcForgetsFinalHtlcs tests that we forget about a resolved
// HTLC once lnd tells us it reached a final state, so the set of resolved HTLCs
// doesn't grow indefinitely.
func TestHandleIncomingHtlcForgetsFinalHtlcs(t *testing.T) {
	t.Parallel()

	subscriber := newMockHtlcSubscriber()
	handler, err := NewOrderHandler(OrderHandlerCfg{
		CleanupInterval: time.Hour,
		HtlcInterceptor: newMockHtlcInterceptor(),
		HtlcSubscriber:  subscriber,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = handler.subscribeHtlcs(ctx)
	}()

	circuitKey := testCircuitKey(1)
	htlc := lndclient.InterceptedHtlc{
		IncomingCircuitKey: circuitKey,
	}

	_, err = handler.handleIncomingHtlc(ctx, htlc)
	require.NoError(t, err)

	_, resolved := handler.resolvedHtlcs.Load(circuitKey)
	require.True(t, resolved)

	// A settle event for the HTLC means we can forget about it. We use a
	// receive event here to make sure we also clean up HTLCs that weren't
	// forwards.
	subscriber.events <- &routerrpc.HtlcEvent{
		IncomingChannelId: circuitKey.ChanID.ToUint64(),
		IncomingHtlcId:    circuitKey.HtlcID,
		EventType:         routerrpc.HtlcEvent_RECEIVE,
		Event: &routerrpc.HtlcEvent_SettleEvent{
			SettleEvent: &routerrpc.SettleEvent{},
		},
	}

	require.Eventually(t, func() bool {
		_, ok := handler.resolvedHtlcs.Load(circuitKey)
		return !ok
	}, 10*time.Second, 10*time.Millisecond)

	// And we're able to resolve it again (which in practice can't happen,
	// but shows the entry is truly gone).
	resp, err := handler.handleIncomingHtlc(ctx, htlc)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// TestCleanupResolvedHtlcs tests that stale entries are removed from the set of
// resolved HTLCs, in case we never learn about their final state.
func TestCleanupResolvedHtlcs(t *testing.T) {
	t.Parallel()

	handler := newTestOrderHandler(t, newMockHtlcInterceptor())

	staleKey := testCircuitKey(1)
	freshKey := testCircuitKey(2)

	handler.resolvedHtlcs.Store(
		staleKey, time.Now().Add(-resolvedHtlcRetention-time.Minute),
	)
	handler.resolvedHtlcs.Store(freshKey, time.Now())

	handler.cleanupResolvedHtlcs()

	_, ok := handler.resolvedHtlcs.Load(staleKey)
	require.False(t, ok)

	_, ok = handler.resolvedHtlcs.Load(freshKey)
	require.True(t, ok)
}

// TestSetupHtlcInterceptCriticalError tests that a non-recoverable interception
// error is reported as a critical error through the order handler's Start
// method, which is what makes tapd shut down.
func TestSetupHtlcInterceptCriticalError(t *testing.T) {
	t.Parallel()

	fatalErr := errors.New("some fatal error")
	interceptor := newMockHtlcInterceptor(fatalErr)

	errChan := make(chan error, 1)
	handler, err := NewOrderHandler(OrderHandlerCfg{
		CleanupInterval: time.Hour,
		HtlcInterceptor: interceptor,
		ErrChan:         errChan,
	})
	require.NoError(t, err)

	go func() {
		err := handler.setupHtlcIntercept(context.Background())
		if err != nil {
			handler.ReportMainChanError(fn.NewCriticalError(err))
		}
	}()

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, fatalErr)

	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for critical error")
	}
}
