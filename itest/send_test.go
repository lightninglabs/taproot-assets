package itest

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/lightninglabs/taro/tarofreighter"
	"github.com/lightninglabs/taro/tarorpc"
	"github.com/stretchr/testify/require"
)

// testBasicSend tests that we can properly send assets back and forth between
// nodes.
func testBasicSend(t *harnessTest) {
	var (
		ctxb = context.Background()
		wg   sync.WaitGroup
	)

	const (
		numUnits = 10
		numSends = 2
	)

	// Subscribe to receive assent send events from primary taro node.
	eventNtfns, err := t.tarod.SubscribeSendAssetEventNtfns(
		ctxb, &tarorpc.SubscribeSendAssetEventNtfnsRequest{},
	)
	require.NoError(t.t, err)

	// Test to ensure that we execute the transaction broadcast state.
	// This test is executed in a goroutine to ensure that we can receive
	// the event notification from the taro node as the rest of the test
	// proceeds.
	wg.Add(1)
	go func() {
		defer wg.Done()

		targetEventSelector := func(event *tarorpc.SendAssetEvent) bool {
			switch eventTyped := event.Event.(type) {
			case *tarorpc.SendAssetEvent_ExecuteSendStateEvent:
				ev := eventTyped.ExecuteSendStateEvent

				// Log send state execution.
				timestamp := time.UnixMicro(
					ev.Timestamp,
				)
				t.Logf("Executing send state (%v): %v",
					timestamp.Format(time.RFC3339Nano),
					ev.SendState,
				)

				return ev.SendState ==
					tarofreighter.SendStateBroadcast.String()
			}

			return false
		}

		ctx, cancel := context.WithTimeout(ctxb, 10*time.Second)
		defer cancel()
		assertRecvNtfsEvent(
			t, ctx, eventNtfns, targetEventSelector, numSends,
		)
	}()

	// First, we'll make a normal assets with enough units to allow us to
	// send it around a few times.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*tarorpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis
	genBootstrap := genInfo.GenesisBootstrapInfo

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.BackendCfg, t.lndHarness.Bob,
		t.universeServer, func(params *tarodHarnessParams) {
			params.enableHashMail = true
		},
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	// Next, we'll attempt to complete two transfers with distinct
	// addresses from our main node to Bob.
	currentUnits := simpleAssets[0].Amount

	for i := 0; i < numSends; i++ {
		bobAddr, err := secondTarod.NewAddr(
			ctxb, &tarorpc.NewAddrRequest{
				GenesisBootstrapInfo: genBootstrap,
				Amt:                  numUnits,
			},
		)
		require.NoError(t.t, err)

		// Deduct what we sent from the expected current number of
		// units.
		currentUnits -= numUnits

		assertAddrCreated(t.t, secondTarod, rpcAssets[0], bobAddr)

		sendResp := sendAssetsToAddr(t, t.tarod, bobAddr)

		confirmAndAssertOutboundTransfer(
			t, t.tarod, sendResp, genInfo.AssetId, currentUnits,
			i, i+1,
		)
		_ = sendProof(
			t, t.tarod, secondTarod, bobAddr.ScriptKey, genInfo,
		)
		assertReceiveComplete(t, secondTarod, i+1)
	}

	// Close event stream.
	err = eventNtfns.CloseSend()
	require.NoError(t.t, err)

	wg.Wait()
}

// testReattemptFailedAssetSend tests that a failed attempt at sending an asset
// proof will be reattempted by the taro node.
func testReattemptFailedAssetSend(t *harnessTest) {
	var (
		ctxb = context.Background()
		wg   sync.WaitGroup
	)

	// Make a new node which will send the asset to the primary taro node.
	// We expect this node to fail because our send call will time out
	// whilst the porter continues to attempt to send the asset.
	sendTarod := setupTarodHarness(
		t.t, t, t.lndHarness.BackendCfg, t.lndHarness.Bob,
		t.universeServer, func(params *tarodHarnessParams) {
			params.enableHashMail = true
			params.expectErrExit = true
		},
	)

	// Subscribe to receive asset send events from primary taro node.
	eventNtfns, err := sendTarod.SubscribeSendAssetEventNtfns(
		ctxb, &tarorpc.SubscribeSendAssetEventNtfnsRequest{},
	)
	require.NoError(t.t, err)

	// Test to ensure that we receive the expected number of backoff wait
	// event notifications.
	// This test is executed in a goroutine to ensure that we can receive
	// the event notification(s) from the taro node as the rest of the test
	// proceeds.
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Define a target event selector to match the backoff wait
		// event. This function selects for a specific event type.
		targetEventSelector := func(event *tarorpc.SendAssetEvent) bool {
			switch eventTyped := event.Event.(type) {
			case *tarorpc.SendAssetEvent_ReceiverProofBackoffWaitEvent:
				ev := eventTyped.ReceiverProofBackoffWaitEvent
				t.Logf("Found event ntfs: %v", ev)
				return true
			}

			return false
		}

		// Default number of proof delivery attempts in tests is 3,
		// therefore expect at least 2 backoff wait events
		// (not waiting on first attempt).
		expectedEventCount := 2

		ctx, cancel := context.WithTimeout(ctxb, 10*time.Second)
		defer cancel()

		assertRecvNtfsEvent(
			t, ctx, eventNtfns, targetEventSelector,
			expectedEventCount,
		)
	}()

	// Mint an asset for sending.
	rpcAssets := mintAssetsConfirmBatch(
		t, sendTarod, []*tarorpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis
	genBootstrap := genInfo.GenesisBootstrapInfo

	// Create a new address for the receiver node.
	recvAddr, err := t.tarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			GenesisBootstrapInfo: genBootstrap,
			Amt:                  10,
		},
	)
	require.NoError(t.t, err)
	assertAddrCreated(t.t, t.tarod, rpcAssets[0], recvAddr)

	// Stop aperture to simulate a failure.
	require.NoError(t.t, t.apertureHarness.Service.Stop())

	// Send asset and then mine to confirm the associated on-chain tx.
	sendAssetsToAddr(t, sendTarod, recvAddr)
	_ = mineBlocks(t, t.lndHarness, 1, 1)

	wg.Wait()
}

// assertRecvNtfsEvent asserts that the given event notification was received.
// This function will block until the event is received or the event stream is
// closed.
func assertRecvNtfsEvent(t *harnessTest, ctx context.Context,
	eventNtfns tarorpc.Taro_SubscribeSendAssetEventNtfnsClient,
	targetEventSelector func(*tarorpc.SendAssetEvent) bool,
	expectedCount int,
) {

	countFound := 0
	for {
		// Ensure that the context has not been cancelled.
		require.NoError(t.t, ctx.Err())

		if countFound == expectedCount {
			break
		}

		event, err := eventNtfns.Recv()

		// Break if we get an EOF, which means the stream was
		// closed.
		//
		// Use string comparison here because the RPC protocol
		// does not transport wrapped error structures.
		if err != nil &&
			strings.Contains(err.Error(), io.EOF.Error()) {

			break
		}

		// If err is not EOF, then we expect it to be nil.
		require.NoError(t.t, err)

		// Check for target state.
		if targetEventSelector(event) {
			countFound++
		}
	}

	require.Equal(t.t, countFound, expectedCount)
}
