package itest

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

var (
	transferTypeSend    = tapdevrpc.ProofTransferType_PROOF_TRANSFER_TYPE_SEND
	transferTypeReceive = tapdevrpc.ProofTransferType_PROOF_TRANSFER_TYPE_RECEIVE
	timeoutMargin       = 5 * time.Second
)

// testBasicSendUnidirectional tests that we can properly send assets back and
// forth between nodes.
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
	events := SubscribeSendEvents(t.t, t.tapd)

	// Test to ensure that we execute the transaction broadcast state.
	// This test is executed in a goroutine to ensure that we can receive
	// the event notification from the tapd node as the rest of the test
	// proceeds.
	wg.Add(1)
	go func() {
		defer wg.Done()

		broadcastState := tapfreighter.SendStateBroadcast.String()
		targetEventSelector := func(
			event *tapdevrpc.SendAssetEvent) bool {

			return AssertSendEventExecuteSendState(
				t, event, broadcastState,
			)
		}

		timeout := 2 * defaultProofTransferReceiverAckTimeout

		// Allow for some margin for the operations that aren't pure
		// waiting on the receiver ACK.
		timeout += timeoutMargin

		assertAssetNtfsEvent(
			t, events, timeout, targetEventSelector, numSends,
		)
	}()

	// First, we'll make a normal assets with enough units to allow us to
	// send it around a few times.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets. The existing tapd
	// node will be used to synchronize universe state.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	// Next, we'll attempt to complete two transfers with distinct
	// addresses from our main node to Bob.
	currentUnits := issuableAssets[0].Asset.Amount

	// Issue a single address which will be reused for each send.
	bobAddr, err := secondTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:      genInfo.AssetId,
		Amt:          numUnits,
		AssetVersion: rpcAssets[0].Version,
	})
	require.NoError(t.t, err)

	for i := 0; i < numSends; i++ {
		t.t.Logf("Performing send procedure: %d", i)

		// Deduct what we sent from the expected current number of
		// units.
		currentUnits -= numUnits

		AssertAddrCreated(t.t, secondTapd, rpcAssets[0], bobAddr)

		sendResp, sendEvents := sendAssetsToAddr(t, t.tapd, bobAddr)

		ConfirmAndAssertOutboundTransfer(
			t.t, t.lndHarness.Miner().Client, t.tapd, sendResp,
			genInfo.AssetId,
			[]uint64{currentUnits, numUnits}, i, i+1,
		)
		AssertNonInteractiveRecvComplete(t.t, secondTapd, i+1)
		AssertSendEventsComplete(t.t, bobAddr.ScriptKey, sendEvents)
	}

	// Close event stream.
	err = events.CloseSend()
	require.NoError(t.t, err)

	wg.Wait()
}

// testRestartReceiver tests that the receiver node's asset balance after a
// single asset transfer does not change if the receiver node restarts.
// Before the addition of this test, after restarting the receiver node
// the asset balance would be erroneously incremented. This is because the
// receiver node was not storing asset transfer in its database with the
// appropriate field uniqueness constraints.
func testRestartReceiverCheckBalance(t *harnessTest) {
	var (
		ctxb = context.Background()
		wg   sync.WaitGroup
	)

	const (
		// Number of units to send.
		numUnits = 10
	)

	// Subscribe to receive assent send events from primary tapd node.
	events := SubscribeSendEvents(t.t, t.tapd)

	// Test to ensure that we execute the transaction broadcast state.
	// This test is executed in a goroutine to ensure that we can receive
	// the event notification from the tapd node as the rest of the test
	// proceeds.
	wg.Add(1)
	go func() {
		defer wg.Done()

		broadcastState := tapfreighter.SendStateBroadcast.String()
		targetEventSelector := func(
			event *tapdevrpc.SendAssetEvent) bool {

			return AssertSendEventExecuteSendState(
				t, event, broadcastState,
			)
		}

		timeout := 2 * defaultProofTransferReceiverAckTimeout

		// Allow for some margin for the operations that aren't pure
		// waiting on the receiver ACK.
		timeout += timeoutMargin

		assertAssetNtfsEvent(
			t, events, timeout, targetEventSelector, 1,
		)
	}()

	// First, we'll make a normal assets with enough units to allow us to
	// send it around a few times.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets. The existing tapd
	// node will be used to synchronize universe state.
	//
	// We will stipulate that the receiver node's custodian service should
	// not delay commencing the proof retrieval procedure once a suitable
	// on-chain asset transfer is detected. This will ensure that on restart
	// the receiver node will attempt to immediately retrieve the asset
	// proof even if the proof and asset are present.
	custodianProofRetrievalDelay := 0 * time.Second

	recvTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.custodianProofRetrievalDelay = &custodianProofRetrievalDelay
		},
	)
	defer func() {
		require.NoError(t.t, recvTapd.stop(!*noDelete))
	}()

	// Next, we'll attempt to complete two transfers with distinct
	// addresses from our main node to Bob.
	currentUnits := issuableAssets[0].Asset.Amount

	// Issue a single address which will be reused for each send.
	bobAddr, err := recvTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:      genInfo.AssetId,
		Amt:          numUnits,
		AssetVersion: rpcAssets[0].Version,
	})
	require.NoError(t.t, err)

	t.t.Logf("Performing send procedure")

	// Deduct what we sent from the expected current number of
	// units.
	currentUnits -= numUnits

	AssertAddrCreated(t.t, recvTapd, rpcAssets[0], bobAddr)

	sendResp, sendEvents := sendAssetsToAddr(t, t.tapd, bobAddr)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp,
		genInfo.AssetId,
		[]uint64{currentUnits, numUnits}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, recvTapd, 1)
	AssertSendEventsComplete(t.t, bobAddr.ScriptKey, sendEvents)

	// Close event stream.
	err = events.CloseSend()
	require.NoError(t.t, err)

	wg.Wait()

	assertRecvBalance := func() {
		// Get asset balance by group from the receiver node.
		respGroup, err := recvTapd.ListBalances(
			ctxb, &taprpc.ListBalancesRequest{
				GroupBy: &taprpc.ListBalancesRequest_GroupKey{
					GroupKey: true,
				},
			},
		)
		require.NoError(t.t, err)

		// We expect to see a single asset group balance. The receiver
		// node received one asset only.
		require.Len(t.t, respGroup.AssetGroupBalances, 1)

		var assetGroupBalance *taprpc.AssetGroupBalance

		for _, value := range respGroup.AssetGroupBalances {
			assetGroupBalance = value
			break
		}

		require.Equal(t.t, int(10), int(assetGroupBalance.Balance))

		// Get asset balance by asset ID from the receiver node.
		respAsset, err := recvTapd.ListBalances(
			ctxb, &taprpc.ListBalancesRequest{
				GroupBy: &taprpc.ListBalancesRequest_AssetId{
					AssetId: true,
				},
			},
		)
		require.NoError(t.t, err)

		// We expect to see a single asset group balance. The receiver
		// node received one asset only.
		require.Len(t.t, respAsset.AssetBalances, 1)

		var assetBalance *taprpc.AssetBalance

		for _, value := range respAsset.AssetBalances {
			assetBalance = value
			break
		}

		require.Equal(t.t, assetBalance.Balance, uint64(10))
	}

	// Initial balance check.
	assertRecvBalance()

	// Restart the receiver node and then check the balance again.
	require.NoError(t.t, recvTapd.stop(false))
	require.NoError(t.t, recvTapd.start(false))

	assertRecvBalance()

	// Restart the receiver node, mine some blocks, and then check the
	// balance again.
	require.NoError(t.t, recvTapd.stop(false))
	t.lndHarness.MineBlocks(7)
	require.NoError(t.t, recvTapd.start(false))

	assertRecvBalance()
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
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, sendTapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// Synchronize the Universe state of the sending node, with the
	// receiving node.
	t.syncUniverseState(sendTapd, recvTapd, len(rpcAssets))

	// The receiver node generates a new address.
	recvAddr, err := recvTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     10,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, recvTapd, rpcAssets[0], recvAddr)

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
			t.lndHarness.MineBlocksAndAssertNumTxes(6, 1)
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
			t.lndHarness.MineBlocksAndAssertNumTxes(6, 1)
		}

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
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd, assets,
	)
	firstAsset := rpcAssets[0]
	genInfo := firstAsset.AssetGenesis
	secondAsset := rpcAssets[1]
	genInfo2 := secondAsset.AssetGenesis

	testVectors := &proof.TestVectors{}
	addProofTestVectorFromFile(
		t.t, "valid regtest genesis proof with meta reveal", t.tapd,
		testVectors, rpcAssets[0].AssetGenesis, rpcAssets[0].ScriptKey,
		0, "",
	)

	// Set up a new node that will serve as the receiving node.
	recvTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, recvTapd.stop(!*noDelete))
	}()

	// Next, we'll attempt to transfer some amount of assets[0] to the
	// receiving node.
	numUnitsSend := uint64(1200)

	// Get a new address (which accepts the first asset) from the
	// receiving node.
	recvAddr, err := recvTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     numUnitsSend,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, recvTapd, firstAsset, recvAddr)

	// Send the assets to the receiving node.
	sendResp, sendEvents := sendAssetsToAddr(t, t.tapd, recvAddr)

	addProofTestVectorFromProof(
		t.t, "valid regtest proof for split root", testVectors,
		sendResp.Transfer.Outputs[0].NewProofBlob,
		proof.RegtestProofName,
	)
	addProofTestVectorFromProof(
		t.t, "valid regtest split proof", testVectors,
		sendResp.Transfer.Outputs[1].NewProofBlob, "",
	)

	// Assert that the outbound transfer was confirmed.
	expectedAmtAfterSend := assets[0].Asset.Amount - numUnitsSend
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp,
		genInfo.AssetId,
		[]uint64{expectedAmtAfterSend, numUnitsSend}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, recvTapd, 1)
	AssertSendEventsComplete(t.t, recvAddr.ScriptKey, sendEvents)

	// Assert that the sending node returns the correct asset list via RPC.
	AssertListAssets(
		t.t, ctxb, t.tapd, []MatchRpcAsset{
			func(asset *taprpc.Asset) bool {
				return asset.Amount == 300 &&
					asset.AssetGenesis.Name == "first-itestbuxx"
			},
			func(asset *taprpc.Asset) bool {
				return asset.Amount == 2000 &&
					asset.AssetGenesis.Name == "second-itestbuxx"
			},
		})

	t.Logf("First send complete, now attempting to send passive asset")

	// Send previously passive asset (the "second" asset).
	recvAddr, err = recvTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: genInfo2.AssetId,
		Amt:     numUnitsSend,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, recvTapd, secondAsset, recvAddr)

	// Send the assets to the receiving node.
	sendResp, sendEvents = sendAssetsToAddr(t, t.tapd, recvAddr)

	// Assert that the outbound transfer was confirmed.
	expectedAmtAfterSend = assets[1].Asset.Amount - numUnitsSend

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp,
		genInfo2.AssetId,
		[]uint64{expectedAmtAfterSend, numUnitsSend}, 1, 2,
	)
	AssertNonInteractiveRecvComplete(t.t, recvTapd, 2)
	AssertSendEventsComplete(t.t, recvAddr.ScriptKey, sendEvents)

	// And now send part of the first asset back again, so we get a bit of a
	// longer proof chain in the file.
	newAddr, err := t.tapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     numUnitsSend / 2,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, t.tapd, firstAsset, newAddr)

	// Send the assets back to the first node.
	sendResp, sendEvents = sendAssetsToAddr(t, recvTapd, newAddr)

	// Assert that the outbound transfer was confirmed.
	expectedAmtAfterSend = numUnitsSend - numUnitsSend/2
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, recvTapd, sendResp,
		genInfo.AssetId,
		[]uint64{expectedAmtAfterSend, numUnitsSend / 2}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, t.tapd, 1)
	AssertSendEventsComplete(t.t, newAddr.ScriptKey, sendEvents)

	// We also want to generate an ownership proof of the asset we received
	// back.
	proveResp, err := t.tapd.ProveAssetOwnership(
		ctxb, &wrpc.ProveAssetOwnershipRequest{
			AssetId:   genInfo.AssetId,
			ScriptKey: newAddr.ScriptKey,
		},
	)
	require.NoError(t.t, err)
	addProofTestVectorFromProof(
		t.t, "valid regtest ownership proof", testVectors,
		proveResp.ProofWithWitness, proof.RegtestOwnershipProofName,
	)

	addProofTestVectorFromFile(
		t.t, "valid regtest proof file index 0", t.tapd, testVectors,
		genInfo, newAddr.ScriptKey, 0, proof.RegtestProofFileName,
	)
	addProofTestVectorFromFile(
		t.t, "valid regtest proof file index 1", t.tapd, testVectors,
		genInfo, newAddr.ScriptKey, 1, "",
	)
	addProofTestVectorFromFile(
		t.t, "valid regtest proof file index 2", t.tapd, testVectors,
		genInfo, newAddr.ScriptKey, 2, "",
	)

	test.WriteTestVectors(t.t, proof.RegtestTestVectorName, testVectors)
}

// testReattemptFailedSendHashmailCourier tests that a failed attempt at
// sending an asset proof will be reattempted by the tapd node. This test
// targets the hashmail courier. The proof courier is specified in the test
// list entry.
func testReattemptFailedSendHashmailCourier(t *harnessTest) {
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
	events := SubscribeSendEvents(t.t, sendTapd)

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
		targetEventSelector := func(
			event *tapdevrpc.SendAssetEvent) bool {

			return AssertSendEventProofTransferBackoffWaitTypeSend(
				t, event,
			)
		}

		// Expected number of events is one less than the number of
		// tries because the first attempt does not count as a backoff
		// event.
		nodeBackoffCfg := t.tapd.clientCfg.HashMailCourier.BackoffCfg
		expectedEventCount := nodeBackoffCfg.NumTries - 1

		// Context timeout scales with expected number of events.
		timeout := time.Duration(expectedEventCount) *
			defaultProofTransferReceiverAckTimeout

		// Allow for some margin for the operations that aren't pure
		// waiting on the receiver ACK.
		timeout += timeoutMargin

		assertAssetNtfsEvent(
			t, events, timeout, targetEventSelector,
			expectedEventCount,
		)
	}()

	// Mint an asset for sending.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, sendTapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// Synchronize the Universe state of the second node, with the main
	// node.
	t.syncUniverseState(sendTapd, t.tapd, len(rpcAssets))

	// Create a new address for the receiver node.
	recvAddr, err := t.tapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     10,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, t.tapd, rpcAssets[0], recvAddr)

	// Simulate a failed attempt at sending the asset proof by stopping
	// the receiver node.
	require.NoError(t.t, t.tapd.stop(false))

	// Send asset and then mine to confirm the associated on-chain tx.
	sendAssetsToAddr(t, sendTapd, recvAddr)
	_ = MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	wg.Wait()
}

// testReattemptProofTransferOnTapdRestart tests that a failed attempt at
// transferring a transfer output proof to a proof courier will be reattempted
// by the sending tapd node upon restart. This test targets the universe
// courier.
func testReattemptProofTransferOnTapdRestart(t *harnessTest) {
	var (
		ctxb = context.Background()
		wg   sync.WaitGroup
	)

	// For this test we will use the universe server as the proof courier.
	proofCourier := t.universeServer

	// Make a new tapd node which will send an asset to a receiving tapd
	// node.
	sendTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.expectErrExit = true
			params.proofCourier = proofCourier
		},
	)
	defer func() {
		// Any node that has been started within an itest should be
		// explicitly stopped within the same itest.
		require.NoError(t.t, sendTapd.stop(!*noDelete))
	}()

	// Use the primary tapd node as the receiver node.
	recvTapd := t.tapd

	// Use the sending node to mint an asset for sending.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, sendTapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// After minting an asset with the sending node, we need to synchronize
	// the Universe state to ensure the receiving node is updated and aware
	// of the asset.
	t.syncUniverseState(sendTapd, recvTapd, len(rpcAssets))

	// Create a new address for the receiver node. We will use the universe
	// server as the proof courier.
	proofCourierAddr := fmt.Sprintf(
		"%s://%s", proof.UniverseRpcCourierType,
		proofCourier.service.rpcHost(),
	)
	t.Logf("Proof courier address: %s", proofCourierAddr)

	recvAddr, err := recvTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:          genInfo.AssetId,
		Amt:              10,
		ProofCourierAddr: proofCourierAddr,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, recvTapd, rpcAssets[0], recvAddr)

	// Soon we will be attempting to send an asset to the receiver node. We
	// want the attempt to fail until we restart the sending node.
	// Therefore, we will take the proof courier service offline.
	t.Log("Stopping proof courier service")
	require.NoError(t.t, proofCourier.Stop())

	// Now that the proof courier service is offline, the sending node's
	// attempt to transfer the asset proof should fail.
	//
	// We will soon start the asset transfer process. However, before we
	// start, we subscribe to the send events from the sending tapd node so
	// that we can be sure that a transfer has been attempted.
	events := SubscribeSendEvents(t.t, sendTapd)

	wg.Add(1)
	go func() {
		defer wg.Done()

		// Define a target event selector to match the backoff wait
		// event. This function selects for a specific event type.
		targetEventSelector := func(
			event *tapdevrpc.SendAssetEvent) bool {

			return AssertSendEventProofTransferBackoffWaitTypeSend(
				t, event,
			)
		}

		// Expected number of events is one less than the number of
		// tries because the first attempt does not count as a backoff
		// event.
		nodeBackoffCfg :=
			sendTapd.clientCfg.UniverseRpcCourier.BackoffCfg
		expectedEventCount := nodeBackoffCfg.NumTries - 1

		// Context timeout scales with expected number of events.
		timeout := time.Duration(expectedEventCount) *
			defaultProofTransferReceiverAckTimeout

		// Allow for some margin for the operations that aren't pure
		// waiting on the receiver ACK.
		timeout += timeoutMargin

		assertAssetNtfsEvent(
			t, events, timeout, targetEventSelector,
			expectedEventCount,
		)
	}()

	// Start asset transfer and then mine to confirm the associated on-chain
	// tx. The on-chain tx should be mined successfully, but we expect the
	// asset proof transfer to be unsuccessful.
	sendResp, _ := sendAssetsToAddr(t, sendTapd, recvAddr)
	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	// Wait to ensure that the asset transfer attempt has been made.
	wg.Wait()

	// Stop the sending tapd node. This downtime will give us the
	// opportunity to restart the proof courier service.
	t.Log("Stopping sending tapd node")
	require.NoError(t.t, sendTapd.stop(false))

	// Restart the proof courier service.
	t.Log("Starting proof courier service")
	require.NoError(t.t, proofCourier.Start(nil))
	t.Logf("Proof courier address: %s", proofCourier.service.rpcHost())

	// Ensure that the proof courier address has not changed on restart.
	// The port is currently selected opportunistically.
	// If the proof courier address has changed the tap address will be
	// stale.
	newProofCourierAddr := fmt.Sprintf(
		"%s://%s", proof.UniverseRpcCourierType,
		proofCourier.service.rpcHost(),
	)
	require.Equal(t.t, proofCourierAddr, newProofCourierAddr)

	// Identify receiver's asset transfer output.
	require.Len(t.t, sendResp.Transfer.Outputs, 2)
	recvOutput := sendResp.Transfer.Outputs[0]

	// If the script key of the output is local to the sending node, then
	// the receiver's output is the second output.
	if recvOutput.ScriptKeyIsLocal {
		recvOutput = sendResp.Transfer.Outputs[1]
	}

	// Formulate a universe key to query the proof courier for the asset
	// transfer proof.
	uniKey := unirpc.UniverseKey{
		Id: &unirpc.ID{
			Id: &unirpc.ID_AssetId{
				AssetId: genInfo.AssetId,
			},
			ProofType: unirpc.ProofType_PROOF_TYPE_TRANSFER,
		},
		LeafKey: &unirpc.AssetKey{
			Outpoint: &unirpc.AssetKey_OpStr{
				OpStr: recvOutput.Anchor.Outpoint,
			},
			ScriptKey: &unirpc.AssetKey_ScriptKeyBytes{
				ScriptKeyBytes: recvOutput.ScriptKey,
			},
		},
	}

	// Ensure that the transfer proof has not reached the proof courier yet.
	resp, err := proofCourier.service.QueryProof(ctxb, &uniKey)
	require.Nil(t.t, resp)
	require.ErrorContains(t.t, err, "no universe proof found")

	// Restart the sending tapd node. The node should reattempt to transfer
	// the asset proof to the proof courier.
	t.Log("Restarting sending tapd node")
	require.NoError(t.t, sendTapd.start(false))

	require.Eventually(t.t, func() bool {
		resp, err = proofCourier.service.QueryProof(ctxb, &uniKey)
		return err == nil && resp != nil
	}, defaultWaitTimeout, 200*time.Millisecond)

	// TODO(ffranr): Modify the receiver node proof retrieval backoff
	//  schedule such that we can assert that the transfer fully completes
	//  in a timely and predictable manner.
	//  AssertNonInteractiveRecvComplete(t.t, recvTapd, 1)
}

// testReattemptFailedSendUniCourier tests that a failed attempt at
// sending an asset proof will be reattempted by the tapd node. This test
// targets the universe proof courier.
func testReattemptFailedSendUniCourier(t *harnessTest) {
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

	// Use the primary tapd node as the receiver node.
	recvTapd := t.tapd

	// Use the sending node to mint an asset for sending.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, sendTapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// After minting an asset with the sending node, we need to synchronize
	// the Universe state to ensure the receiving node is updated and aware
	// of the asset.
	t.syncUniverseState(sendTapd, recvTapd, len(rpcAssets))

	// Create a new address for the receiver node.
	recvAddr, err := recvTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     10,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, recvTapd, rpcAssets[0], recvAddr)

	// No we will ensure that the expected number of backoff wait event
	// notifications are emitted from the sending node.
	//
	// We identify backoff wait events in a goroutine to ensure that we can
	// capture event notifications from the send node while the main
	// test continues.
	//
	// Subscribe to proof transfer send events from the sending tapd node.
	events := SubscribeSendEvents(t.t, sendTapd)

	wg.Add(1)
	go func() {
		defer wg.Done()

		// Define a target event selector to match the backoff wait
		// event. This function selects for a specific event type.
		targetEventSelector := func(
			event *tapdevrpc.SendAssetEvent) bool {

			return AssertSendEventProofTransferBackoffWaitTypeSend(
				t, event,
			)
		}

		// Expected number of events is one less than the number of
		// tries because the first attempt does not count as a backoff
		// event.
		nodeBackoffCfg := sendTapd.clientCfg.HashMailCourier.BackoffCfg
		expectedEventCount := nodeBackoffCfg.NumTries - 1

		// Context timeout scales with expected number of events.
		timeout := time.Duration(expectedEventCount) *
			defaultProofTransferReceiverAckTimeout

		// Allow for some margin for the operations that aren't pure
		// waiting on the receiver ACK.
		timeout += timeoutMargin

		assertAssetNtfsEvent(
			t, events, timeout, targetEventSelector,
			expectedEventCount,
		)
	}()

	// Simulate a failed attempt at sending the asset proof by stopping
	// the proof courier service.
	require.NoError(t.t, t.proofCourier.Stop())

	// Send asset and then mine to confirm the associated on-chain tx.
	sendAssetsToAddr(t, sendTapd, recvAddr)
	_ = MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	wg.Wait()
}

// testSpendChangeOutputWhenProofTransferFail tests that a tapd node is able
// to spend a change output even if the proof transfer for the previous
// transaction fails.
func testSpendChangeOutputWhenProofTransferFail(t *harnessTest) {
	var (
		ctxb = context.Background()
		wg   sync.WaitGroup
	)

	// For this test we will use the universe server as the proof courier.
	proofCourier := t.universeServer

	// Make a new tapd node which will send an asset to a receiving tapd
	// node.
	sendTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.expectErrExit = true
			params.proofCourier = proofCourier
		},
	)
	defer func() {
		// Any node that has been started within an itest should be
		// explicitly stopped within the same itest.
		require.NoError(t.t, sendTapd.stop(!*noDelete))
	}()

	// Use the primary tapd node as the receiver node.
	recvTapd := t.tapd

	// Use the sending node to mint an asset for sending.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, sendTapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// After minting an asset with the sending node, we need to synchronize
	// the Universe state to ensure the receiving node is updated and aware
	// of the asset.
	t.syncUniverseState(sendTapd, recvTapd, len(rpcAssets))

	// Create a new address for the receiver node. We will use the universe
	// server as the proof courier.
	proofCourierAddr := fmt.Sprintf(
		"%s://%s", proof.UniverseRpcCourierType,
		proofCourier.service.rpcHost(),
	)
	t.Logf("Proof courier address: %s", proofCourierAddr)

	recvAddr, err := recvTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:          genInfo.AssetId,
		Amt:              10,
		ProofCourierAddr: proofCourierAddr,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, recvTapd, rpcAssets[0], recvAddr)

	// Soon we will be attempting to send an asset to the receiver node. We
	// want any associated proof delivery attempt to fail. Therefore, we
	// will take the proof courier service offline.
	t.Log("Stopping proof courier service")
	require.NoError(t.t, proofCourier.Stop())

	// Now that the proof courier service is offline, the sending node's
	// attempt to transfer the asset proof should fail.
	//
	// We will soon start the asset transfer process. However, before we
	// start, we subscribe to the send events from the sending tapd node so
	// that we can be sure that a proof delivery has been attempted
	// unsuccessfully. We assert that at least a single proof delivery
	// attempt has been made by identifying a backoff wait event.
	events := SubscribeSendEvents(t.t, sendTapd)

	wg.Add(1)
	go func() {
		defer wg.Done()

		// Define a target event selector to match the backoff wait
		// event. This function selects for a specific event type.
		targetEventSelector := func(
			event *tapdevrpc.SendAssetEvent) bool {

			return AssertSendEventProofTransferBackoffWaitTypeSend(
				t, event,
			)
		}

		// Set the context timeout for detecting a single proof delivery
		// attempt to something reasonable.
		timeout := 2 * defaultProofTransferReceiverAckTimeout

		assertAssetNtfsEvent(
			t, events, timeout, targetEventSelector, 1,
		)
	}()

	// Start asset transfer and then mine to confirm the associated on-chain
	// tx. The on-chain tx should be mined successfully, but we expect the
	// asset proof transfer to be unsuccessful.
	sendAssetsToAddr(t, sendTapd, recvAddr)
	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	// There may be a delay between mining the anchoring transaction and
	// recognizing its on-chain confirmation. To handle this potential
	// delay, we use require.Eventually to ensure the transfer details are
	// correctly listed after confirmation.
	require.Eventually(t.t, func() bool {
		// Ensure that the transaction took place as expected.
		listTransfersResp, err := sendTapd.ListTransfers(
			ctxb, &taprpc.ListTransfersRequest{},
		)
		require.NoError(t.t, err)

		require.Len(t.t, listTransfersResp.Transfers, 1)

		firstTransfer := listTransfersResp.Transfers[0]
		require.NotEqual(t.t, firstTransfer.AnchorTxHeightHint, 0)
		require.NotEmpty(t.t, firstTransfer.AnchorTxBlockHash)

		// Assert proof transfer status for each transfer output.
		require.Len(t.t, firstTransfer.Outputs, 2)

		// First output should have a proof delivery status of not
		// applicable. This indicates that a proof will not be delivered
		// for this output.
		firstOutput := firstTransfer.Outputs[0]
		require.Equal(
			t.t, taprpc.ProofDeliveryStatusNotApplicable,
			firstOutput.ProofDeliveryStatus,
		)

		// The second output should have a proof delivery status of
		// pending. This indicates that the proof deliver has not yet
		// completed successfully.
		secondOutput := firstTransfer.Outputs[1]
		require.Equal(
			t.t, taprpc.ProofDeliveryStatusPending,
			secondOutput.ProofDeliveryStatus,
		)

		return true
	}, defaultWaitTimeout, 200*time.Millisecond)

	// Wait to ensure that the asset transfer proof deliver attempt has been
	// made.
	wg.Wait()

	// Attempt to send the change output to the receiver node. This
	// operation should select the change output from the previous
	// transaction and transmit it to the receiver node, despite the fact
	// that proof delivery for the previous transaction remains incomplete
	// (due to the proof courier being shut down). We will generate a new
	// address for this new transaction.
	recvAddr, err = recvTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:          genInfo.AssetId,
		Amt:              42,
		ProofCourierAddr: proofCourierAddr,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, recvTapd, rpcAssets[0], recvAddr)

	sendAssetsToAddr(t, sendTapd, recvAddr)
	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	// There may be a delay between mining the anchoring transaction and
	// recognizing its on-chain confirmation. To handle this potential
	// delay, we use require.Eventually to ensure the transfer details are
	// correctly listed after confirmation.
	require.Eventually(t.t, func() bool {
		// Ensure that the transaction took place as expected.
		listTransfersResp, err := sendTapd.ListTransfers(
			ctxb, &taprpc.ListTransfersRequest{},
		)
		require.NoError(t.t, err)

		require.Len(t.t, listTransfersResp.Transfers, 2)

		// Inspect the first transfer.
		firstTransfer := listTransfersResp.Transfers[0]
		require.NotEqual(t.t, firstTransfer.AnchorTxHeightHint, 0)
		require.NotEmpty(t.t, firstTransfer.AnchorTxBlockHash)

		// Assert proof transfer status for each transfer output.
		require.Len(t.t, firstTransfer.Outputs, 2)

		// First output should have a proof delivery status of not
		// applicable. This indicates that a proof will not be delivered
		// for this output.
		firstOutput := firstTransfer.Outputs[0]
		require.Equal(
			t.t, taprpc.ProofDeliveryStatusNotApplicable,
			firstOutput.ProofDeliveryStatus,
		)

		// The second output should have a proof delivery status of
		// pending. This indicates that the proof deliver has not yet
		// completed successfully.
		secondOutput := firstTransfer.Outputs[1]
		require.Equal(
			t.t, taprpc.ProofDeliveryStatusPending,
			secondOutput.ProofDeliveryStatus,
		)

		// Inspect the second transfer.
		secondTransfer := listTransfersResp.Transfers[1]
		require.NotEqual(t.t, secondTransfer.AnchorTxHeightHint, 0)
		require.NotEmpty(t.t, secondTransfer.AnchorTxBlockHash)

		// Assert proof transfer status for each transfer output.
		require.Len(t.t, secondTransfer.Outputs, 2)

		// First output should have a proof delivery status of not
		// applicable. This indicates that a proof will not be delivered
		// for this output.
		firstOutput = secondTransfer.Outputs[0]
		require.Equal(
			t.t, taprpc.ProofDeliveryStatusNotApplicable,
			firstOutput.ProofDeliveryStatus,
		)

		// The second output should have a proof delivery status of
		// pending. This indicates that the proof deliver has not yet
		// completed successfully.
		secondOutput = secondTransfer.Outputs[1]
		require.Equal(
			t.t, taprpc.ProofDeliveryStatusPending,
			secondOutput.ProofDeliveryStatus,
		)

		return true
	}, defaultWaitTimeout, 200*time.Millisecond)

	// Restart the proof courier service.
	t.Log("Starting proof courier service")
	require.NoError(t.t, proofCourier.Start(nil))

	// TODO(ffranr): Assert proof transfer complete after proof courier
	//  restart.
}

// testReattemptFailedReceiveUniCourier ensures that a failed attempt to receive
// an asset proof is retried by the receiving Tapd node.  This test focuses on
// the universe proof courier.
func testReattemptFailedReceiveUniCourier(t *harnessTest) {
	ctxb := context.Background()

	// This tapd node will send the asset to the receiving tapd node.
	// It will also transfer proof the related transfer proofs to the
	// proof courier.
	sendTapd := t.tapd

	// Initialise a receiver tapd node. This node will attempt to retrieve
	// the transfer proofs from the proof courier.
	receiveTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.expectErrExit = true
			params.proofSendBackoffCfg = &proof.BackoffCfg{
				BackoffResetWait: 1 * time.Second,
				NumTries:         200,
				InitialBackoff:   1 * time.Second,
				MaxBackoff:       1 * time.Second,
			}
		},
	)

	// Mint an asset for sending using the sending tapd node.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, sendTapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// Synchronize the Universe state of the second node, with the receiver
	// node.
	t.syncUniverseState(sendTapd, receiveTapd, len(rpcAssets))

	// Create a new address for the receiver node.
	recvAddr, err := receiveTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     10,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, receiveTapd, rpcAssets[0], recvAddr)

	// Stop receiving tapd node to simulate an offline receiver.
	t.Logf("Stopping the receiving tapd node")
	require.NoError(t.t, receiveTapd.stop(false))

	// Send asset and then mine to confirm the associated on-chain tx.
	sendAssetsToAddr(t, sendTapd, recvAddr)
	_ = MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	// At this point, the proof courier service is running. We will
	// therefore pause to allow the sender to transfer the proof to the
	// proof courier service.
	time.Sleep(2 * time.Second)

	// Next, we're going to simulate a failed attempt at proof retrieval by
	// the receiver node. The receiver node will fail to retrieve the proof
	// from the proof courier. We simulate this failure by stopping the
	// proof courier service and then restarting the receiver tapd node.
	t.Logf("Stopping the proof courier service")
	require.NoError(t.t, t.proofCourier.Stop())

	// Restart receiving tapd node.
	t.Logf("Re-starting receiving tapd node")
	require.NoError(t.t, receiveTapd.start(false))
	// Defer stopping the receiving tapd node to ensure that it is stopped
	// cleanly at the end of the test.
	defer func() {
		err := receiveTapd.stop(false)
		fmt.Println("Error stopping receiver tapd node: ", err)
	}()

	// Subscribe to receive asset receive events from receiving tapd node.
	// We'll use these events to ensure that the receiver node is making
	// multiple attempts to retrieve the asset proof.
	events := SubscribeReceiveEvents(t.t, receiveTapd)

	// Test to ensure that we receive the minimum expected number of backoff
	// wait event notifications.
	t.Logf("Waiting for the receiving tapd node to complete backoff " +
		"proof retrieval attempts")

	// Define a target event selector to match the backoff wait event. This
	// function selects for a specific event type.
	targetEventSelector := func(event *tapdevrpc.ReceiveAssetEvent) bool {
		ev := event.GetProofTransferBackoffWaitEvent()
		if ev == nil {
			return false
		}

		// We are attempting to identify receive transfer types.
		// Skip the event if it is not a receiving transfer
		// type.
		if ev.TransferType != transferTypeReceive {
			return false
		}

		t.Logf("Found event ntfs: %v", ev)
		return true
	}

	// Expected minimum number of events to receive.
	expectedEventCount := 3

	// Context timeout scales with expected number of events.
	timeout := time.Duration(expectedEventCount) *
		defaultProofTransferReceiverAckTimeout

	// Allow for some margin for the operations that aren't pure
	// waiting on the receiver ACK.
	timeout += timeoutMargin

	// Assert that the receiver tapd node has accomplished our minimum
	// expected number of backoff procedure receive attempts.
	assertAssetNtfsEvent(
		t, events, timeout, targetEventSelector, expectedEventCount,
	)

	t.Logf("Finished waiting for the receiving tapd node to complete " +
		"backoff procedure")

	// Restart the proof courier so that the receiver node can receive the
	// asset proof. The receiver tapd node should continue to make
	// attempts to retrieve the asset proof. Once the proof courier is
	// restarted, the receiver node should receive the transfer proof(s).
	t.Logf("Restarting proof courier service")
	require.NoError(t.t, t.proofCourier.Start(nil))

	// Confirm that the receiver tapd node eventually receives the transfer
	// proof(s).
	t.Logf("Attempting to confirm asset received by receiver node")
	AssertNonInteractiveRecvComplete(t.t, receiveTapd, 1)

	// Confirm that the sender tapd node eventually receives the asset
	// transfer and publishes an asset recv complete event.
	t.Logf("Check for asset recv complete event from receiver tapd node")
	assertAssetCompleteEvent(
		t, 5*time.Second, recvAddr.Encoded, events,
	)
}

// testOfflineReceiverEventuallyReceives tests that a receiver node will
// eventually receive an asset even if it is offline whilst the sender node
// makes multiple attempts to send the asset. This test explicitly listens for
// backoff wait events to ensure that the sender node is making multiple
// attempts to send the asset.
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
	events := SubscribeSendEvents(t.t, sendTapd)

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
		targetEventSelector := func(
			event *tapdevrpc.SendAssetEvent) bool {

			// We're listening for events on the sender node. We
			// therefore expect to receive deliver transfer type
			// backoff wait events for sending transfers.
			return AssertSendEventProofTransferBackoffWaitTypeSend(
				t, event,
			)
		}

		// Lower bound number of proof delivery attempts.
		expectedEventCount := 20

		// Events must be received before a timeout.
		timeout := 5 * time.Second

		assertAssetNtfsEvent(
			t, events, timeout, targetEventSelector,
			expectedEventCount,
		)
	}()

	// Mint an asset for sending.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, sendTapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// Synchronize the Universe state of the second node, with the main
	// node.
	t.syncUniverseState(sendTapd, recvTapd, len(rpcAssets))

	// Create a new address for the receiver node.
	recvAddr, err := recvTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     10,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, recvTapd, rpcAssets[0], recvAddr)

	// Stop receiving tapd node to simulate offline receiver.
	t.Logf("Stopping receiving taproot assets node")
	require.NoError(t.t, recvTapd.stop(false))

	// Send asset and then mine to confirm the associated on-chain tx.
	sendAssetsToAddr(t, sendTapd, recvAddr)
	_ = MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	// Pause before restarting receiving tapd node so that sender node has
	// an opportunity to attempt to send the proof multiple times.
	time.Sleep(1 * time.Second)

	// Restart receiving tapd node.
	t.Logf("Re-starting receiving taproot assets node")
	require.NoError(t.t, recvTapd.start(false))

	// Confirm that the receiver eventually receives the asset.
	t.Logf("Attempting to confirm asset received")
	AssertNonInteractiveRecvComplete(t.t, recvTapd, 1)

	wg.Wait()
}

// assetRpcEvent is a generic type that catches all asset events.
type assetRpcEvent interface {
	*tapdevrpc.SendAssetEvent | *tapdevrpc.ReceiveAssetEvent
}

// assertAssetNtfsEvent asserts that the given asset event notification was
// received. This function will block until the event is received or the event
// stream is closed.
func assertAssetNtfsEvent[T assetRpcEvent](t *harnessTest,
	stream *EventSubscription[T], timeout time.Duration,
	targetEventSelector func(T) bool, expectedCount int) {

	success := make(chan struct{})
	timeoutChan := time.After(timeout)

	// To make sure we don't forever hang on receiving on the stream, we'll
	// cancel it after the timeout.
	go func() {
		select {
		case <-timeoutChan:
			stream.Cancel()

		case <-success:

		case <-stream.Context().Done():
		}
	}()

	countFound := 0
	for {
		// Ensure that the context has not been cancelled.
		select {
		case <-stream.Context().Done():
			require.NoError(t.t, stream.Context().Err())

			break
		default:
		}

		if countFound == expectedCount {
			close(success)

			break
		}

		event, err := stream.Recv()
		if err != nil {
			close(success)

			require.NoError(t.t, err)

			break
		}

		// Check for target state.
		if targetEventSelector(event) {
			countFound++
		}
	}

	require.Equal(t.t, expectedCount, countFound, "unexpected number of "+
		"asset event notifications (expected=%d, actual=%d)",
		expectedCount, countFound)
}

// assertAssetNtfsEvent asserts that the given asset complete event notification
// was received. This function will block until the event is received or the
// event stream is closed.
func assertAssetCompleteEvent(t *harnessTest,
	timeout time.Duration, encodedAddr string,
	stream *EventSubscription[*tapdevrpc.ReceiveAssetEvent]) {

	eventSelector := func(event *tapdevrpc.ReceiveAssetEvent) bool {
		switch eventTyped := event.Event.(type) {
		case *tapdevrpc.ReceiveAssetEvent_AssetReceiveCompleteEvent:
			ev := eventTyped.AssetReceiveCompleteEvent
			return encodedAddr == ev.Address.Encoded
		default:
			return false
		}
	}

	assertAssetNtfsEvent(t, stream, timeout, eventSelector, 1)
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
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)
	rpcAsset := rpcAssets[0]

	// Set up a node that will serve as the final multi input send origin
	// node. Sync the new node with the primary node.
	bobTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
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
	AssertAddrCreated(t.t, bobTapd, rpcAsset, addr)

	// Send the assets to the secondary node.
	sendResp, sendEvents := sendAssetsToAddr(t, t.tapd, addr)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp,
		genInfo.AssetId, []uint64{4000, 1000}, 0, 1,
	)

	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)
	AssertSendEventsComplete(t.t, addr.ScriptKey, sendEvents)

	// Second of two send events from minting node to the secondary node.
	addr, err = bobTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     4000,
		},
	)
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, bobTapd, rpcAsset, addr)

	// Send the assets to the secondary node.
	sendResp, sendEvents = sendAssetsToAddr(t, t.tapd, addr)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp,
		genInfo.AssetId, []uint64{0, 4000}, 1, 2,
	)

	AssertNonInteractiveRecvComplete(t.t, bobTapd, 2)
	AssertSendEventsComplete(t.t, addr.ScriptKey, sendEvents)

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
	AssertAddrCreated(t.t, t.tapd, rpcAsset, addr)

	// Send the assets to the minting node.
	sendResp, sendEvents = sendAssetsToAddr(t, bobTapd, addr)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, bobTapd, sendResp,
		genInfo.AssetId, []uint64{0, 5000}, 0, 1,
	)

	AssertNonInteractiveRecvComplete(t.t, t.tapd, 1)
	AssertSendEventsComplete(t.t, addr.ScriptKey, sendEvents)
}

// testSendMultipleCoins tests that we can send multiple transfers at the same
// time if we have multiple managed UTXOs/asset coins available.
func testSendMultipleCoins(t *harnessTest) {
	ctxb := context.Background()

	// First, we'll make a normal assets with enough units to allow us to
	// send it to different UTXOs
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets. The existing tapd
	// node will be used to synchronize universe state.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
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

		AssertAddrCreated(t.t, t.tapd, rpcAssets[0], newAddr)
		addrs[i] = newAddr
	}

	// We created 5 addresses in our first node now, so we can initiate the
	// transfer to send the coins back to our wallet in 5 pieces now.
	sendResp, sendEvents := sendAssetsToAddr(t, t.tapd, addrs...)
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp,
		genInfo.AssetId, []uint64{
			0, unitsPerPart, unitsPerPart, unitsPerPart,
			unitsPerPart, unitsPerPart,
		}, 0, 1, numParts+1,
	)
	AssertNonInteractiveRecvComplete(t.t, t.tapd, 5)
	AssertSendEventsComplete(t.t, addrs[0].ScriptKey, sendEvents)

	// Next, we'll attempt to complete 5 parallel transfers with distinct
	// addresses from our main node to Bob.
	bobAddrs := make([]*taprpc.Addr, numParts)
	addrSendEvents := make(
		[]*EventSubscription[*taprpc.SendEvent], numParts,
	)
	for i := 0; i < numParts; i++ {
		var err error
		bobAddrs[i], err = secondTapd.NewAddr(
			ctxb, &taprpc.NewAddrRequest{
				AssetId: genInfo.AssetId,
				Amt:     unitsPerPart,
			},
		)
		require.NoError(t.t, err)

		sendResp, addrSendEvents[i] = sendAssetsToAddr(
			t, t.tapd, bobAddrs[i],
		)
		AssertAssetOutboundTransferWithOutputs(
			t.t, t.lndHarness.Miner().Client, t.tapd,
			sendResp.Transfer, genInfo.AssetId,
			[]uint64{0, unitsPerPart}, i+1, i+2,
			2, false,
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
	_ = MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 5)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 5)
	for idx, events := range addrSendEvents {
		AssertSendEventsComplete(t.t, bobAddrs[idx].ScriptKey, events)
	}
}

// testSendNoCourierUniverseImport tests that we can send assets to a node that
// has no courier, and then manually transfer the proof to the receiving using
// the universe proof import RPC method.
func testSendNoCourierUniverseImport(t *harnessTest) {
	ctxb := context.Background()

	// First, we'll make a normal assets with enough units.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	firstAsset := rpcAssets[0]
	genInfo := firstAsset.AssetGenesis

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets. We turn off the proof
	// courier by supplying a dummy implementation.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.proofCourier = &proof.MockProofCourier{}
		},
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	// Next, we'll attempt to transfer some amount of assets[0] to the
	// receiving node.
	numUnitsSend := uint64(1200)

	// Get a new address (which accepts the first asset) from the
	// receiving node.
	receiveAddr, err := secondTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     numUnitsSend,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, secondTapd, firstAsset, receiveAddr)

	// Send the assets to the receiving node.
	sendResp, sendEvents := sendAssetsToAddr(t, t.tapd, receiveAddr)

	// Assert that the outbound transfer was confirmed.
	expectedAmtAfterSend := firstAsset.Amount - numUnitsSend
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp,
		genInfo.AssetId,
		[]uint64{expectedAmtAfterSend, numUnitsSend}, 0, 1,
	)

	// Since we disabled proof couriers, we need to manually transfer the
	// proof from the sender to the receiver now. We use the universe RPC
	// InsertProof method to do this.
	sendProofUniRPC(t, t.tapd, secondTapd, receiveAddr.ScriptKey, genInfo)

	// And now, the transfer should be completed on the receiver side too.
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 1)
	AssertSendEventsComplete(t.t, receiveAddr.ScriptKey, sendEvents)
}

// addProofTestVectorFromFile adds a proof test vector by extracting it from the
// proof file found at the given asset ID and script key.
func addProofTestVectorFromFile(t *testing.T, testName string,
	tapd *tapdHarness, vectors *proof.TestVectors,
	genInfo *taprpc.GenesisInfo, scriptKey []byte, fileIndex int,
	binaryFileName string) {

	ctxb := context.Background()

	var proofResp *taprpc.ProofFile
	waitErr := wait.NoError(func() error {
		resp, err := tapd.ExportProof(ctxb, &taprpc.ExportProofRequest{
			AssetId:   genInfo.AssetId,
			ScriptKey: scriptKey,
		})
		if err != nil {
			return err
		}

		proofResp = resp
		return nil
	}, defaultWaitTimeout)
	require.NoError(t, waitErr)

	if binaryFileName != "" {
		test.WriteTestFileHex(t, binaryFileName, proofResp.RawProofFile)
	}

	var f proof.File
	err := f.Decode(bytes.NewReader(proofResp.RawProofFile))
	require.NoError(t, err)

	if f.NumProofs() <= fileIndex {
		t.Fatalf("Not enough proofs in file")
	}

	p, err := f.ProofAt(uint32(fileIndex))
	require.NoError(t, err)

	rawProof, err := f.RawProofAt(uint32(fileIndex))
	require.NoError(t, err)

	vectors.ValidTestCases = append(
		vectors.ValidTestCases, &proof.ValidTestCase{
			Proof:    proof.NewTestFromProof(t, p),
			Expected: hex.EncodeToString(rawProof),
			Comment:  testName,
		},
	)
}

// addProofTestVectorFromProof adds the given proof blob to the proof test
// vector.
func addProofTestVectorFromProof(t *testing.T, testName string,
	vectors *proof.TestVectors, blob proof.Blob, binaryFileName string) {

	var p proof.Proof
	err := p.Decode(bytes.NewReader(blob))
	require.NoError(t, err)

	vectors.ValidTestCases = append(
		vectors.ValidTestCases, &proof.ValidTestCase{
			Proof:    proof.NewTestFromProof(t, &p),
			Expected: hex.EncodeToString(blob),
			Comment:  testName,
		},
	)

	if binaryFileName != "" {
		test.WriteTestFileHex(t, binaryFileName, blob)
	}
}
