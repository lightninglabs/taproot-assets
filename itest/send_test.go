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

		assertRecvSendSateExecEvent(
			t, eventNtfns, tarofreighter.SendStateBroadcast,
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
		t.universeServer, false,
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	// Next, we'll attempt to complete two transfers with distinct
	// addresses from our main node to Bob.
	const (
		numUnits = 10
		numSends = 2
	)
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
		_ = sendProof(t, t.tarod, secondTarod, bobAddr, genInfo)
		assertReceiveComplete(t, secondTarod, i+1)
	}

	// Close event stream.
	err = eventNtfns.CloseSend()
	require.NoError(t.t, err)

	wg.Wait()
}

// assertRecvSendSateExecEvent asserts that the given send state execution event
// notification was received. This function will block until the event is
// received or the event stream is closed.
func assertRecvSendSateExecEvent(
	t *harnessTest,
	eventNtfns tarorpc.Taro_SubscribeSendAssetEventNtfnsClient,
	targetSendState tarofreighter.SendState,
) {

	targetSendStateStr := targetSendState.String()
	foundTargetState := false
	for {
		if foundTargetState {
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

		// Check for the transaction broadcast state.
		switch eventTyped := event.Event.(type) {
		case *tarorpc.SendAssetEvent_ExecuteSendStateEvent:
			executeSendStateEvent := eventTyped.ExecuteSendStateEvent

			// Log send state execution.
			timestamp := time.UnixMicro(
				executeSendStateEvent.Timestamp,
			)
			t.Logf("Executing send state (%v): %v",
				timestamp.Format(time.RFC3339Nano),
				executeSendStateEvent.SendState,
			)

			if executeSendStateEvent.SendState == targetSendStateStr {
				foundTargetState = true
			}
		}
	}

	require.True(t.t, foundTargetState)
}
