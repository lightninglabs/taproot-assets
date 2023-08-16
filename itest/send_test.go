package itest

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// testBasicSend tests that we can properly send assets back and forth between
// nodes.
func testBasicSendUnidirectional(t *harnessTest) {
	var (
		ctxb = context.Background()
		wg   sync.WaitGroup
	)

	const (
		numUnits = 10
		numSends = 2
	)

	// Subscribe to receive assent send events from primary tapd node.
	eventNtfns, err := t.tapd.SubscribeSendAssetEventNtfns(
		ctxb, &taprpc.SubscribeSendAssetEventNtfnsRequest{},
	)
	require.NoError(t.t, err)

	// Test to ensure that we execute the transaction broadcast state.
	// This test is executed in a goroutine to ensure that we can receive
	// the event notification from the tapd node as the rest of the test
	// proceeds.
	wg.Add(1)
	go func() {
		defer wg.Done()

		broadcastState := tapfreighter.SendStateBroadcast.String()
		targetEventSelector := func(event *taprpc.SendAssetEvent) bool {
			switch eventTyped := event.Event.(type) {
			case *taprpc.SendAssetEvent_ExecuteSendStateEvent:
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

		timeout := 2 * defaultProofTransferReceiverAckTimeout
		ctx, cancel := context.WithTimeout(ctxb, timeout)
		defer cancel()
		assertRecvNtfsEvent(
			t, ctx, eventNtfns, targetEventSelector, numSends,
		)
	}()

	// First, we'll make a normal assets with enough units to allow us to
	// send it around a few times.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tapd, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets. The existing tapd
	// node will be used to synchronize universe state.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.startupSyncNode = t.tapd
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	// Next, we'll attempt to complete two transfers with distinct
	// addresses from our main node to Bob.
	currentUnits := simpleAssets[0].Asset.Amount

	// Issue a single address which will be reused for each send.
	bobAddr, err := secondTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     numUnits,
		},
	)
	require.NoError(t.t, err)

	for i := 0; i < numSends; i++ {
		// Deduct what we sent from the expected current number of
		// units.
		currentUnits -= numUnits

		assertAddrCreated(t.t, secondTapd, rpcAssets[0], bobAddr)

		sendResp := sendAssetsToAddr(t, t.tapd, bobAddr)

		confirmAndAssertOutboundTransfer(
			t, t.tapd, sendResp, genInfo.AssetId,
			[]uint64{currentUnits, numUnits}, i, i+1,
		)
		_ = sendProof(
			t, t.tapd, secondTapd, bobAddr.ScriptKey, genInfo,
		)
		AssertNonInteractiveRecvComplete(t.t, secondTapd, i+1)
	}

	// Close event stream.
	err = eventNtfns.CloseSend()
	require.NoError(t.t, err)

	wg.Wait()
}

// testResumePendingPackageSend tests that we can properly resume a pending
// package send after a restart.
func testResumePendingPackageSend(t *harnessTest) {
	ctxb := context.Background()

	sendTapd := t.tapd

	// Setup a receiver node.
	recvLnd := t.lndHarness.Bob
	recvTapd := setupTapdHarness(
		t.t, t, recvLnd, t.universeServer,
		func(params *tapdHarnessParams) {
			// We expect the receiver node to exit with an error
			// since it will fail to receive the asset at the first
			// attempt. We will confirm that the receiver node does
			// eventually receive the asset correctly via an RPC
			// call.
			params.expectErrExit = true
		},
	)

	// Mint (and mine) an asset for sending.
	rpcAssets := mintAssetsConfirmBatch(
		t, sendTapd, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// Synchronize the Universe state of the sending node, with the
	// receiving node.
	t.syncUniverseState(sendTapd, recvTapd, len(rpcAssets))

	// The receiver node generates a new address.
	recvAddr, err := recvTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     10,
		},
	)
	require.NoError(t.t, err)
	assertAddrCreated(t.t, recvTapd, rpcAssets[0], recvAddr)

	// We will now start two asset send events in sequence. We will stop and
	// restart the sending node during each send. During one sending event
	// we will mine whilst the sending node is stopped. During the other
	// sending event we will only mine once the sending node has restarted.
	for i := 0; i < 2; i++ {
		mineWhileNodeDown := i == 0

		// Start the asset send procedure.
		t.t.Logf("Commencing asset send procedure")
		sendAssetsToAddr(t, sendTapd, recvAddr)

		// Stop the sending node before mining the asset transfer's
		// anchoring transaction. This will ensure that the send
		// procedure does not complete. The sending node will be stalled
		// waiting for the broadcast transaction to confirm.
		t.t.Logf("Stopping sending tapd node")
		err = sendTapd.stop(false)
		require.NoError(t.t, err)

		if mineWhileNodeDown {
			// Mine the anchoring transaction to ensure that the
			// asset transfer is broadcast.
			t.lndHarness.MineBlocks(6)
		}

		// Re-commence the asset send procedure by restarting the
		// sending node. The asset package should be picked up as a
		// pending package.
		t.t.Logf("Re-starting sending tapd node so as to complete " +
			"transfer")
		err = sendTapd.start(false)
		require.NoError(t.t, err)

		if !mineWhileNodeDown {
			// Complete the transfer by mining the anchoring
			// transaction and sending the proof to the receiver
			// node.
			t.lndHarness.MineBlocks(6)
		}

		_ = sendProof(
			t, sendTapd, recvTapd, recvAddr.ScriptKey, genInfo,
		)

		// Confirm with the receiver node that the asset was fully
		// received.
		AssertNonInteractiveRecvComplete(t.t, recvTapd, i+1)
	}
}

// testBasicSendPassiveAsset tests that we can properly send assets which were
// passive assets during a previous send.
func testBasicSendPassiveAsset(t *harnessTest) {
	ctxb := context.Background()

	// Mint two different assets.
	assets := []*mintrpc.MintAssetRequest{
		{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_NORMAL,
				Name:      "first-itestbuxx",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("itest-metadata"),
				},
				Amount: 1500,
			},
		},
		{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_NORMAL,
				Name:      "second-itestbuxx",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("itest-metadata"),
				},
				Amount: 2000,
			},
		},
	}
	rpcAssets := mintAssetsConfirmBatch(t, t.tapd, assets)
	firstAsset := rpcAssets[0]

	// Set up a new node that will serve as the receiving node.
	recvTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.startupSyncNode = t.tapd
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, recvTapd.stop(!*noDelete))
	}()

	// Next, we'll attempt to transfer some amount of assets[0] to the
	// receiving node.
	numUnitsSend := uint64(1200)

	// Get a new address (which accepts the first asset) from the
	// receiving node.
	genInfo := firstAsset.AssetGenesis
	recvAddr, err := recvTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     numUnitsSend,
		},
	)
	require.NoError(t.t, err)
	assertAddrCreated(t.t, recvTapd, firstAsset, recvAddr)

	// Send the assets to the receiving node.
	sendResp := sendAssetsToAddr(t, t.tapd, recvAddr)

	// Assert that the outbound transfer was confirmed.
	expectedAmtAfterSend := assets[0].Asset.Amount - numUnitsSend
	confirmAndAssertOutboundTransfer(
		t, t.tapd, sendResp, genInfo.AssetId,
		[]uint64{expectedAmtAfterSend, numUnitsSend}, 0, 1,
	)
	_ = sendProof(t, t.tapd, recvTapd, recvAddr.ScriptKey, genInfo)
	AssertNonInteractiveRecvComplete(t.t, recvTapd, 1)

	// Assert that the sending node returns the correct asset list via RPC.
	assertListAssets(
		t.t, ctxb, t.tapd, []MatchRpcAsset{
			func(asset *taprpc.Asset) bool {
				return asset.Amount == 300 &&
					asset.AssetGenesis.Name == "first-itestbuxx"
			},
			func(asset *taprpc.Asset) bool {
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
	recvAddr, err = recvTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     numUnitsSend,
		},
	)
	require.NoError(t.t, err)
	assertAddrCreated(t.t, recvTapd, secondAsset, recvAddr)

	// Send the assets to the receiving node.
	sendResp = sendAssetsToAddr(t, t.tapd, recvAddr)

	// Assert that the outbound transfer was confirmed.
	expectedAmtAfterSend = assets[1].Asset.Amount - numUnitsSend
	confirmAndAssertOutboundTransfer(
		t, t.tapd, sendResp, genInfo.AssetId,
		[]uint64{expectedAmtAfterSend, numUnitsSend}, 1, 2,
	)
	_ = sendProof(t, t.tapd, recvTapd, recvAddr.ScriptKey, genInfo)
	AssertNonInteractiveRecvComplete(t.t, recvTapd, 2)
}

// testReattemptFailedAssetSend tests that a failed attempt at sending an asset
// proof will be reattempted by the tapd node.
func testReattemptFailedAssetSend(t *harnessTest) {
	var (
		ctxb = context.Background()
		wg   sync.WaitGroup
	)

	// Make a new node which will send the asset to the primary tapd node.
	// We expect this node to fail because our send call will time out
	// whilst the porter continues to attempt to send the asset.
	sendTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.expectErrExit = true
		},
	)

	// Subscribe to receive asset send events from primary tapd node.
	eventNtfns, err := sendTapd.SubscribeSendAssetEventNtfns(
		ctxb, &taprpc.SubscribeSendAssetEventNtfnsRequest{},
	)
	require.NoError(t.t, err)

	// Test to ensure that we receive the expected number of backoff wait
	// event notifications.
	// This test is executed in a goroutine to ensure that we can receive
	// the event notification(s) from the tapd node as the rest of the test
	// proceeds.
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Define a target event selector to match the backoff wait
		// event. This function selects for a specific event type.
		targetEventSelector := func(event *taprpc.SendAssetEvent) bool {
			switch eventTyped := event.Event.(type) {
			case *taprpc.SendAssetEvent_ReceiverProofBackoffWaitEvent:
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

		// Context timeout scales with expected number of events.
		timeout := time.Duration(expectedEventCount) *
			defaultProofTransferReceiverAckTimeout
		// Add overhead buffer to context timeout.
		timeout += 5 * time.Second
		ctx, cancel := context.WithTimeout(ctxb, timeout)
		defer cancel()

		assertRecvNtfsEvent(
			t, ctx, eventNtfns, targetEventSelector,
			expectedEventCount,
		)
	}()

	// Mint an asset for sending.
	rpcAssets := mintAssetsConfirmBatch(
		t, sendTapd, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// Synchronize the Universe state of the second node, with the main
	// node.
	t.syncUniverseState(sendTapd, t.tapd, len(rpcAssets))

	// Create a new address for the receiver node.
	recvAddr, err := t.tapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     10,
		},
	)
	require.NoError(t.t, err)
	assertAddrCreated(t.t, t.tapd, rpcAssets[0], recvAddr)

	// Simulate a failed attempt at sending the asset proof by stopping
	// the receiver node.
	require.NoError(t.t, t.tapd.stop(false))

	// Send asset and then mine to confirm the associated on-chain tx.
	sendAssetsToAddr(t, sendTapd, recvAddr)
	_ = mineBlocks(t, t.lndHarness, 1, 1)

	wg.Wait()
}

// testOfflineReceiverEventuallyReceives tests that a receiver node will
// eventually receive an asset even if it is offline whilst the sender node
// makes multiple attempts to send the asset.
func testOfflineReceiverEventuallyReceives(t *harnessTest) {
	var (
		ctxb = context.Background()
		wg   sync.WaitGroup
	)

	// Make a new node which will send the asset to the primary tapd node.
	// We start a new node for sending so that we can customize the proof
	// send backoff configuration.
	sendTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.expectErrExit = true
			params.proofSendBackoffCfg = &proof.BackoffCfg{
				BackoffResetWait: 1 * time.Microsecond,
				NumTries:         200,
				InitialBackoff:   1 * time.Microsecond,
				MaxBackoff:       1 * time.Microsecond,
			}
			proofReceiverAckTimeout := 1 * time.Microsecond
			params.proofReceiverAckTimeout = &proofReceiverAckTimeout
		},
	)

	recvTapd := t.tapd

	// Subscribe to receive asset send events from primary tapd node.
	eventNtfns, err := sendTapd.SubscribeSendAssetEventNtfns(
		ctxb, &taprpc.SubscribeSendAssetEventNtfnsRequest{},
	)
	require.NoError(t.t, err)

	// Test to ensure that we receive the expected number of backoff wait
	// event notifications.
	// This test is executed in a goroutine to ensure that we can receive
	// the event notification(s) from the tapd node as the rest of the test
	// proceeds.
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Define a target event selector to match the backoff wait
		// event. This function selects for a specific event type.
		targetEventSelector := func(event *taprpc.SendAssetEvent) bool {
			switch eventTyped := event.Event.(type) {
			case *taprpc.SendAssetEvent_ReceiverProofBackoffWaitEvent:
				ev := eventTyped.ReceiverProofBackoffWaitEvent
				t.Logf("Found event ntfs: %v", ev)
				return true
			}

			return false
		}

		// Lower bound number of proof delivery attempts.
		expectedEventCount := 20

		// Events must be received before a timeout.
		timeout := 5 * time.Second
		ctx, cancel := context.WithTimeout(ctxb, timeout)
		defer cancel()

		assertRecvNtfsEvent(
			t, ctx, eventNtfns, targetEventSelector,
			expectedEventCount,
		)
	}()

	// Mint an asset for sending.
	rpcAssets := mintAssetsConfirmBatch(
		t, sendTapd, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// Synchronize the Universe state of the second node, with the main
	// node.
	t.syncUniverseState(sendTapd, recvTapd, len(rpcAssets))

	// Create a new address for the receiver node.
	recvAddr, err := recvTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     10,
		},
	)
	require.NoError(t.t, err)
	assertAddrCreated(t.t, recvTapd, rpcAssets[0], recvAddr)

	// Stop receiving tapd node to simulate offline receiver.
	t.Logf("Stopping receiving taproot assets node")
	require.NoError(t.t, recvTapd.stop(false))

	// Send asset and then mine to confirm the associated on-chain tx.
	sendAssetsToAddr(t, sendTapd, recvAddr)
	_ = mineBlocks(t, t.lndHarness, 1, 1)

	// Pause before restarting receiving tapd node so that sender node has
	// an opportunity to attempt to send the proof multiple times.
	time.Sleep(1 * time.Second)

	// Restart receiving tapd node.
	t.Logf("Re-starting receiving taproot assets node")
	require.NoError(t.t, recvTapd.start(false))

	// Confirm that the receiver eventually receives the asset. Pause to
	// give the receiver time to recognise the full send event.
	t.Logf("Attempting to confirm asset received")
	AssertNonInteractiveRecvComplete(t.t, recvTapd, 1)

	wg.Wait()
}

// assertRecvNtfsEvent asserts that the given event notification was received.
// This function will block until the event is received or the event stream is
// closed.
func assertRecvNtfsEvent(t *harnessTest, ctx context.Context,
	eventNtfns taprpc.TaprootAssets_SubscribeSendAssetEventNtfnsClient,
	targetEventSelector func(*taprpc.SendAssetEvent) bool,
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
		t, t.tapd, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)
	rpcAsset := rpcAssets[0]

	// Set up a node that will serve as the final multi input send origin
	// node. Sync the new node with the primary node.
	bobTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.startupSyncNode = t.tapd
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	// First of two send events from minting node to secondary node.
	genInfo := rpcAsset.AssetGenesis
	addr, err := bobTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     1000,
		},
	)
	require.NoError(t.t, err)
	assertAddrCreated(t.t, bobTapd, rpcAsset, addr)

	// Send the assets to the secondary node.
	sendResp := sendAssetsToAddr(t, t.tapd, addr)

	confirmAndAssertOutboundTransfer(
		t, t.tapd, sendResp, genInfo.AssetId, []uint64{4000, 1000},
		0, 1,
	)

	_ = sendProof(t, t.tapd, bobTapd, addr.ScriptKey, genInfo)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)

	// Second of two send events from minting node to the secondary node.
	addr, err = bobTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     4000,
		},
	)
	require.NoError(t.t, err)
	assertAddrCreated(t.t, bobTapd, rpcAsset, addr)

	// Send the assets to the secondary node.
	sendResp = sendAssetsToAddr(t, t.tapd, addr)

	confirmAndAssertOutboundTransfer(
		t, t.tapd, sendResp, genInfo.AssetId, []uint64{0, 4000}, 1, 2,
	)

	_ = sendProof(t, t.tapd, bobTapd, addr.ScriptKey, genInfo)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 2)

	t.Logf("Two separate send events complete, now attempting to send " +
		"back the full amount in a single multi input send event")

	// Send back full amount from secondary node to the minting node.
	addr, err = t.tapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     5000,
		},
	)
	require.NoError(t.t, err)
	assertAddrCreated(t.t, t.tapd, rpcAsset, addr)

	// Send the assets to the minting node.
	sendResp = sendAssetsToAddr(t, bobTapd, addr)

	confirmAndAssertOutboundTransfer(
		t, bobTapd, sendResp, genInfo.AssetId, []uint64{0, 5000}, 0, 1,
	)

	_ = sendProof(t, bobTapd, t.tapd, addr.ScriptKey, genInfo)
	AssertNonInteractiveRecvComplete(t.t, t.tapd, 1)
}

// testSendMultipleCoins tests that we can send multiple transfers at the same
// time if we have multiple managed UTXOs/asset coins available.
func testSendMultipleCoins(t *harnessTest) {
	ctxb := context.Background()

	// First, we'll make a normal assets with enough units to allow us to
	// send it to different UTXOs
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tapd, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets. The existing tapd
	// node will be used to synchronize universe state.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.startupSyncNode = t.tapd
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	// Next, we split the asset into 5 different UTXOs, each with 1k units.
	const (
		numParts     = 5
		unitsPerPart = 1000
	)
	addrs := make([]*taprpc.Addr, numParts)
	for i := 0; i < numParts; i++ {
		newAddr, err := t.tapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     unitsPerPart,
		})
		require.NoError(t.t, err)

		assertAddrCreated(t.t, t.tapd, rpcAssets[0], newAddr)
		addrs[i] = newAddr
	}

	// We created 5 addresses in our first node now, so we can initiate the
	// transfer to send the coins back to our wallet in 5 pieces now.
	sendResp := sendAssetsToAddr(t, t.tapd, addrs...)
	confirmAndAssetOutboundTransferWithOutputs(
		t, t.tapd, sendResp, genInfo.AssetId, []uint64{
			0, unitsPerPart, unitsPerPart, unitsPerPart,
			unitsPerPart, unitsPerPart,
		}, 0, 1, numParts+1,
	)
	AssertNonInteractiveRecvComplete(t.t, t.tapd, 5)

	// Next, we'll attempt to complete 5 parallel transfers with distinct
	// addresses from our main node to Bob.
	bobAddrs := make([]*taprpc.Addr, numParts)
	for i := 0; i < numParts; i++ {
		var err error
		bobAddrs[i], err = secondTapd.NewAddr(
			ctxb, &taprpc.NewAddrRequest{
				AssetId: genInfo.AssetId,
				Amt:     unitsPerPart,
			},
		)
		require.NoError(t.t, err)

		sendResp := sendAssetsToAddr(t, t.tapd, bobAddrs[i])
		assertAssetOutboundTransferWithOutputs(
			t, t.tapd, sendResp, genInfo.AssetId,
			[]uint64{0, unitsPerPart}, i+1, i+2, 2, false,
		)
	}

	// Before we mine the next block, we'll make sure that we get a proper
	// error message when trying to send more assets (there are currently no
	// asset UTXOs available).
	bobAddr, err := secondTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     1,
	})
	require.NoError(t.t, err)

	_, err = t.tapd.SendAsset(ctxb, &taprpc.SendAssetRequest{
		TapAddrs: []string{bobAddr.Encoded},
	})
	require.ErrorContains(
		t.t, err, "failed to find coin(s) that satisfy given "+
			"constraints",
	)

	// Now we confirm the 5 transfers and make sure they complete as
	// expected.
	_ = mineBlocks(t, t.lndHarness, 1, 5)
	for _, addr := range bobAddrs {
		_ = sendProof(t, t.tapd, secondTapd, addr.ScriptKey, genInfo)
	}
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 5)
}
