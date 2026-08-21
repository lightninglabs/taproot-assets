package rfq

import (
	"context"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/graph/db/models"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestSubscribeHtlcsFinalEvent tests that a final HTLC event is acted on even
// though lnd doesn't set an event type on it. That event is the only signal we
// get for an HTLC that was resolved on chain, so dropping it would leave the
// policy accounting for that HTLC inflated until the quote expires.
func TestSubscribeHtlcsFinalEvent(t *testing.T) {
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

	// Track an HTLC against a policy, the way an accepted forward would.
	circuitKey := testCircuitKey(1)
	policy := &AssetSalePolicy{
		htlcToAmt: make(map[models.CircuitKey]lnwire.MilliSatoshi),
	}
	policy.TrackAcceptedHtlc(circuitKey, 1000)
	handler.htlcToPolicy.Store(circuitKey, policy)

	// lnd reports the HTLC as resolved on chain. Note that it does not set
	// an event type on final HTLC events, which is exactly the case we need
	// to handle.
	subscriber.events <- &routerrpc.HtlcEvent{
		IncomingChannelId: circuitKey.ChanID.ToUint64(),
		IncomingHtlcId:    circuitKey.HtlcID,
		Event: &routerrpc.HtlcEvent_FinalHtlcEvent{
			FinalHtlcEvent: &routerrpc.FinalHtlcEvent{
				Settled: true,
			},
		},
	}

	// The HTLC must no longer be tracked against the policy, and its amount
	// must have been released again.
	require.Eventually(t, func() bool {
		_, tracked := handler.htlcToPolicy.Load(circuitKey)
		if tracked {
			return false
		}

		policy.stateMutex.Lock()
		defer policy.stateMutex.Unlock()

		return policy.CurrentAmountMsat == 0
	}, 10*time.Second, 10*time.Millisecond)
}
