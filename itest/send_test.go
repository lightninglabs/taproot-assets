package itest

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/lightninglabs/taro/tarofreighter"
	"github.com/lightninglabs/taro/tarorpc"
	"github.com/lightninglabs/taro/tarorpc/mintrpc"
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

		broadcastState := tarofreighter.SendStateBroadcast.String()
		targetEventSelector := func(event *tarorpc.SendAssetEvent) bool {
			switch eventTyped := event.Event.(type) {
			case *tarorpc.SendAssetEvent_ExecuteSendStateEvent:
				ev := eventTyped.ExecuteSendStateEvent

				// Log send state execution.
				timestamp := time.UnixMicro(ev.Timestamp)
				t.Logf("Executing send state (%v): %v",
					timestamp.Format(time.RFC3339Nano),
					ev.SendState)

				return ev.SendState == broadcastState
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
		t, t.tarod, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets. The existing tarod
	// node will be used to synchronize universe state.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tarodHarnessParams) {
			params.enableHashMail = true
			params.startupSyncNode = t.tarod
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	// Next, we'll attempt to complete two transfers with distinct
	// addresses from our main node to Bob.
	currentUnits := simpleAssets[0].Asset.Amount

	for i := 0; i < numSends; i++ {
		bobAddr, err := secondTarod.NewAddr(
			ctxb, &tarorpc.NewAddrRequest{
				AssetId: genInfo.AssetId,
				Amt:     numUnits,
			},
		)
		require.NoError(t.t, err)

		// Deduct what we sent from the expected current number of
		// units.
		currentUnits -= numUnits

		assertAddrCreated(t.t, secondTarod, rpcAssets[0], bobAddr)

		sendResp := sendAssetsToAddr(t, t.tarod, bobAddr)

		confirmAndAssertOutboundTransfer(
			t, t.tarod, sendResp, genInfo.AssetId,
			[]uint64{currentUnits, numUnits}, i, i+1,
		)
		_ = sendProof(
			t, t.tarod, secondTarod, bobAddr.ScriptKey, genInfo,
		)
		assertNonInteractiveRecvComplete(t, secondTarod, i+1)
	}

	// Close event stream.
	err = eventNtfns.CloseSend()
	require.NoError(t.t, err)

	wg.Wait()
}

// testBasicSendPassiveAsset tests that we can properly send assets which were
// passive assets during a previous send.
func testBasicSendPassiveAsset(t *harnessTest) {
	ctxb := context.Background()

	// Mint two different assets.
	assets := []*mintrpc.MintAssetRequest{
		{
			Asset: &mintrpc.MintAsset{
				AssetType: tarorpc.AssetType_NORMAL,
				Name:      "first-itestbuxx",
				AssetMeta: &tarorpc.AssetMeta{
					Data: []byte("itest-metadata"),
				},
				Amount: 1500,
			},
		},
		{
			Asset: &mintrpc.MintAsset{
				AssetType: tarorpc.AssetType_NORMAL,
				Name:      "second-itestbuxx",
				AssetMeta: &tarorpc.AssetMeta{
					Data: []byte("itest-metadata"),
				},
				Amount: 2000,
			},
		},
	}
	rpcAssets := mintAssetsConfirmBatch(t, t.tarod, assets)
	firstAsset := rpcAssets[0]

	// Set up a new node that will serve as the receiving node.
	recvTarod := setupTarodHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tarodHarnessParams) {
			params.enableHashMail = true
			params.startupSyncNode = t.tarod
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, recvTarod.stop(true))
	}()

	// Next, we'll attempt to transfer some amount of assets[0] to the
	// receiving node.
	numUnitsSend := uint64(1200)

	// Get a new address (which accepts the first asset) from the
	// receiving node.
	genInfo := firstAsset.AssetGenesis
	recvAddr, err := recvTarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     numUnitsSend,
		},
	)
	require.NoError(t.t, err)
	assertAddrCreated(t.t, recvTarod, firstAsset, recvAddr)

	// Send the assets to the receiving node.
	sendResp := sendAssetsToAddr(t, t.tarod, recvAddr)

	// Assert that the outbound transfer was confirmed.
	expectedAmtAfterSend := assets[0].Asset.Amount - numUnitsSend
	confirmAndAssertOutboundTransfer(
		t, t.tarod, sendResp, genInfo.AssetId,
		[]uint64{expectedAmtAfterSend, numUnitsSend}, 0, 1,
	)
	_ = sendProof(t, t.tarod, recvTarod, recvAddr.ScriptKey, genInfo)
	assertNonInteractiveRecvComplete(t, recvTarod, 1)

	// Assert that the sending node returns the correct asset list via RPC.
	assertListAssets(
		t, ctxb, t.tarod, []MatchRpcAsset{
			func(asset *tarorpc.Asset) bool {
				return asset.Amount == 300 &&
					asset.AssetGenesis.Name == "first-itestbuxx"
			},
			func(asset *tarorpc.Asset) bool {
				return asset.Amount == 2000 &&
					asset.AssetGenesis.Name == "second-itestbuxx"
			},
		},
	)

	t.Logf("First send complete, now attempting to send passive asset")

	// Inspect the state of the second asset on the sending node.
	secondAsset := rpcAssets[1]
	genInfo = secondAsset.AssetGenesis

	// Send previously passive asset (the "second" asset).
	recvAddr, err = recvTarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     numUnitsSend,
		},
	)
	require.NoError(t.t, err)
	assertAddrCreated(t.t, recvTarod, secondAsset, recvAddr)

	// Send the assets to the receiving node.
	sendResp = sendAssetsToAddr(t, t.tarod, recvAddr)

	// Assert that the outbound transfer was confirmed.
	expectedAmtAfterSend = assets[1].Asset.Amount - numUnitsSend
	confirmAndAssertOutboundTransfer(
		t, t.tarod, sendResp, genInfo.AssetId,
		[]uint64{expectedAmtAfterSend, numUnitsSend}, 1, 2,
	)
	_ = sendProof(t, t.tarod, recvTarod, recvAddr.ScriptKey, genInfo)
	assertNonInteractiveRecvComplete(t, recvTarod, 2)
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
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tarodHarnessParams) {
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
		t, sendTarod, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// Synchronize the Universe state of the second node, with the main
	// node.
	t.syncUniverseState(sendTarod, t.tarod, len(rpcAssets))

	// Create a new address for the receiver node.
	recvAddr, err := t.tarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     10,
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
	expectedCount int) {

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

	require.Equal(t.t, expectedCount, countFound)
}

// testMultiInputSendNonInteractiveSingleID tests that we can properly
// non-interactively send a single asset from multiple inputs.
//
// This test works as follows:
// 1. The primary node mints a single asset.
// 2. A secondary node is set up.
// 3. Perform two different send events from the minting node to the secondary
// node.
// 4. Performs a single multi input send from the secondary node back to the
// minting node. (The two inputs used in this send were set up via the
// minting node's send events.)
func testMultiInputSendNonInteractiveSingleID(t *harnessTest) {
	ctxb := context.Background()

	// Mint a single asset.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)
	rpcAsset := rpcAssets[0]

	// Set up a node that will serve as the final multi input send origin
	// node. Sync the new node with the primary node.
	bobTarod := setupTarodHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tarodHarnessParams) {
			params.startupSyncNode = t.tarod
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, bobTarod.stop(true))
	}()

	// First of two send events from minting node to secondary node.
	genInfo := rpcAsset.AssetGenesis
	addr, err := bobTarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     1000,
		},
	)
	require.NoError(t.t, err)
	assertAddrCreated(t.t, bobTarod, rpcAsset, addr)

	// Send the assets to the secondary node.
	sendResp := sendAssetsToAddr(t, t.tarod, addr)

	confirmAndAssertOutboundTransfer(
		t, t.tarod, sendResp, genInfo.AssetId, []uint64{4000, 1000},
		0, 1,
	)

	_ = sendProof(t, t.tarod, bobTarod, addr.ScriptKey, genInfo)
	assertNonInteractiveRecvComplete(t, bobTarod, 1)

	// Second of two send events from minting node to the secondary node.
	addr, err = bobTarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     4000,
		},
	)
	require.NoError(t.t, err)
	assertAddrCreated(t.t, bobTarod, rpcAsset, addr)

	// Send the assets to the secondary node.
	sendResp = sendAssetsToAddr(t, t.tarod, addr)

	confirmAndAssertOutboundTransfer(
		t, t.tarod, sendResp, genInfo.AssetId, []uint64{0, 4000}, 1, 2,
	)

	_ = sendProof(t, t.tarod, bobTarod, addr.ScriptKey, genInfo)
	assertNonInteractiveRecvComplete(t, bobTarod, 2)

	t.Logf("Two separate send events complete, now attempting to send " +
		"back the full amount in a single multi input send event")

	// Send back full amount from secondary node to the minting node.
	addr, err = t.tarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     5000,
		},
	)
	require.NoError(t.t, err)
	assertAddrCreated(t.t, t.tarod, rpcAsset, addr)

	// Send the assets to the minting node.
	sendResp = sendAssetsToAddr(t, bobTarod, addr)

	confirmAndAssertOutboundTransfer(
		t, bobTarod, sendResp, genInfo.AssetId, []uint64{0, 5000}, 0, 1,
	)

	_ = sendProof(t, bobTarod, t.tarod, addr.ScriptKey, genInfo)
	assertNonInteractiveRecvComplete(t, t.tarod, 1)
}
