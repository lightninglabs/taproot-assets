package itest

import (
	"bytes"
	"context"

	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testAddresses tests the various RPC calls related to addresses.
func testAddresses(t *harnessTest) {
	// First, mint a few assets, so we have some to create addresses for.
	// We mint all of them in individual batches to avoid needing to sign
	// for multiple internal asset transfers when only sending one of them
	// to an external address.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tapd, []*mintrpc.MintAssetRequest{
			simpleAssets[0], issuableAssets[0],
		},
	)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We'll make a second node now that'll be the receiver of all the
	// assets made above.
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

	var addresses []*taprpc.Addr
	for idx, a := range rpcAssets {
		// In order to force a split, we don't try to send the full
		// asset.
		addr, err := secondTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
			AssetId: a.AssetGenesis.AssetId,
			Amt:     a.Amount - 1,
		})
		require.NoError(t.t, err)
		addresses = append(addresses, addr)

		assertAddrCreated(t.t, secondTapd, a, addr)

		sendResp := sendAssetsToAddr(t, t.tapd, addr)
		sendRespJSON, err := formatProtoJSON(sendResp)
		require.NoError(t.t, err)

		t.Logf("Got response from sending assets: %v", sendRespJSON)

		// Make sure that eventually we see a single event for the
		// address.
		AssertAddrEvent(t.t, secondTapd, addr, 1, statusDetected)

		// Mine a block to make sure the events are marked as confirmed.
		mineBlocks(t, t.lndHarness, 1, 1)

		// Eventually the event should be marked as confirmed.
		AssertAddrEvent(t.t, secondTapd, addr, 1, statusConfirmed)

		// To complete the transfer, we'll export the proof from the
		// sender and import it into the receiver for each asset set.
		sendProof(
			t, t.tapd, secondTapd, addr.ScriptKey, a.AssetGenesis,
		)

		// Make sure we have imported and finalized all proofs.
		AssertNonInteractiveRecvComplete(t.t, secondTapd, idx+1)

		// Make sure the asset meta is also fetched correctly.
		assetResp, err := secondTapd.FetchAssetMeta(
			ctxt, &taprpc.FetchAssetMetaRequest{
				Asset: &taprpc.FetchAssetMetaRequest_AssetId{
					AssetId: a.AssetGenesis.AssetId,
				},
			},
		)
		require.NoError(t.t, err)
		require.Equal(t.t, a.AssetGenesis.MetaHash, assetResp.MetaHash)
	}

	// Now sanity check that we can actually list the transfer.
	err := wait.NoError(func() error {
		resp, err := t.tapd.ListTransfers(
			ctxt, &taprpc.ListTransfersRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, resp.Transfers, len(rpcAssets))
		require.Len(t.t, resp.Transfers[0].Outputs, 2)
		firstOut := resp.Transfers[0].Outputs[0]
		require.EqualValues(t.t, 1, firstOut.Amount)
		firstIn := resp.Transfers[0].Inputs[0]
		require.Equal(
			t.t, rpcAssets[0].AssetGenesis.AssetId, firstIn.AssetId,
		)

		return nil
	}, defaultTimeout/2)
	require.NoError(t.t, err)

	// We should now also be able to generate ownership proofs for the
	// received assets.
	for idx := range addresses {
		receiverAddr := addresses[idx]

		// Generate the ownership proof on the receiver node.
		proveResp, err := secondTapd.ProveAssetOwnership(
			ctxt, &wrpc.ProveAssetOwnershipRequest{
				AssetId:   receiverAddr.AssetId,
				ScriptKey: receiverAddr.ScriptKey,
			},
		)
		require.NoError(t.t, err)

		// Verify the ownership proof on the sender node.
		t.Logf("Got ownership proof: %x", proveResp.ProofWithWitness)
		verifyResp, err := t.tapd.VerifyAssetOwnership(
			ctxt, &wrpc.VerifyAssetOwnershipRequest{
				ProofWithWitness: proveResp.ProofWithWitness,
			},
		)
		require.NoError(t.t, err)
		require.True(t.t, verifyResp.ValidProof)
	}
}

// testMultiAddress tests that we can send assets to multiple addresses at the
// same time.
func testMultiAddress(t *harnessTest) {
	// First, mint an asset, so we have one to create addresses for.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tapd, []*mintrpc.MintAssetRequest{
			simpleAssets[0], issuableAssets[0],
		},
	)
	mintedAsset := rpcAssets[0]
	mintedGroupAsset := rpcAssets[1]
	genInfo := mintedAsset.AssetGenesis
	groupGenInfo := mintedGroupAsset.AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We'll make a second node now that'll be the receiver of all the
	// assets made above.
	alice := t.tapd
	bob := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.startupSyncNode = alice
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	runMultiSendTest(ctxt, t, alice, bob, genInfo, mintedAsset, 0, 1)
	runMultiSendTest(
		ctxt, t, alice, bob, groupGenInfo, mintedGroupAsset, 1, 2,
	)
}

// runMultiSendTest runs a test that sends assets to multiple addresses at the
// same time.
func runMultiSendTest(ctxt context.Context, t *harnessTest, alice,
	bob *tapdHarness, genInfo *taprpc.GenesisInfo,
	mintedAsset *taprpc.Asset, runIdx, numRuns int) {

	// In order to force a split, we don't try to send the full asset.
	const sendAmt = 100
	var bobAddresses []*taprpc.Addr
	bobAddr1, err := bob.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     sendAmt,
	})
	require.NoError(t.t, err)
	bobAddresses = append(bobAddresses, bobAddr1)
	assertAddrCreated(t.t, bob, mintedAsset, bobAddr1)

	bobAddr2, err := bob.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     sendAmt,
	})
	require.NoError(t.t, err)
	bobAddresses = append(bobAddresses, bobAddr2)
	assertAddrCreated(t.t, bob, mintedAsset, bobAddr2)

	// To test that Alice can also receive to multiple addresses in a single
	// transaction as well, we also add two addresses for her.
	aliceAddr1, err := alice.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     sendAmt,
	})
	require.NoError(t.t, err)
	assertAddrCreated(t.t, alice, mintedAsset, aliceAddr1)

	aliceAddr2, err := alice.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     sendAmt,
	})
	require.NoError(t.t, err)
	assertAddrCreated(t.t, alice, mintedAsset, aliceAddr2)

	sendResp := sendAssetsToAddr(
		t, alice, bobAddr1, bobAddr2, aliceAddr1, aliceAddr2,
	)
	sendRespJSON, err := formatProtoJSON(sendResp)
	require.NoError(t.t, err)
	t.Logf("Got response from sending assets: %v", sendRespJSON)

	// Make sure that eventually we see a single event for the address.
	AssertAddrEvent(t.t, bob, bobAddr1, 1, statusDetected)
	AssertAddrEvent(t.t, bob, bobAddr2, 1, statusDetected)
	AssertAddrEvent(t.t, alice, aliceAddr1, 1, statusDetected)
	AssertAddrEvent(t.t, alice, aliceAddr2, 1, statusDetected)

	// Mine a block to make sure the events are marked as confirmed.
	_ = mineBlocks(t, t.lndHarness, 1, 1)[0]

	// Eventually the events should be marked as confirmed.
	assertAddrEventByStatus(t.t, bob, statusConfirmed, 2)

	// For local addresses, we should already have the proof in the DB at
	// this point, so the status should go to completed directly.
	assertAddrEventByStatus(t.t, alice, statusCompleted, numRuns*2)

	// To complete the transfer, we'll export the proof from the sender and
	// import it into the receiver for each asset set. This should not be
	// necessary for the sends to Alice, as she is both the sender and
	// receiver and should detect the local proof once it's written to disk.
	for i := range bobAddresses {
		sendProof(t, alice, bob, bobAddresses[i].ScriptKey, genInfo)
	}

	// Make sure we have imported and finalized all proofs.
	AssertNonInteractiveRecvComplete(t.t, bob, numRuns*2)
	AssertNonInteractiveRecvComplete(t.t, alice, numRuns*2)

	// Now sanity check that we can actually list the transfer.
	const (
		numOutputs = 5
		numAddrs   = 4
	)
	changeAmt := mintedAsset.Amount - (sendAmt * numAddrs)
	err = wait.NoError(func() error {
		resp, err := alice.ListTransfers(
			ctxt, &taprpc.ListTransfersRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, resp.Transfers, numRuns)

		transfer := resp.Transfers[runIdx]
		require.Len(t.t, transfer.Outputs, numOutputs)
		firstOut := transfer.Outputs[0]
		require.EqualValues(t.t, changeAmt, firstOut.Amount)
		firstIn := transfer.Inputs[0]
		require.Equal(t.t, genInfo.AssetId, firstIn.AssetId)

		return nil
	}, defaultTimeout/2)
	require.NoError(t.t, err)
}

func sendProof(t *harnessTest, src, dst *tapdHarness, scriptKey []byte,
	genInfo *taprpc.GenesisInfo) *tapdevrpc.ImportProofResponse {

	ctxb := context.Background()

	var proofResp *taprpc.ProofFile
	waitErr := wait.NoError(func() error {
		resp, err := src.ExportProof(ctxb, &taprpc.ExportProofRequest{
			AssetId:   genInfo.AssetId,
			ScriptKey: scriptKey,
		})
		if err != nil {
			return err
		}

		proofResp = resp
		return nil
	}, defaultWaitTimeout)
	require.NoError(t.t, waitErr)

	t.Logf("Importing proof %x", proofResp.RawProofFile)

	importResp, err := dst.ImportProof(ctxb, &tapdevrpc.ImportProofRequest{
		ProofFile:    proofResp.RawProofFile,
		GenesisPoint: genInfo.GenesisPoint,
	})
	require.NoError(t.t, err)

	return importResp
}

// sendAssetsToAddr spends the given input asset and sends the amount specified
// in the address to the Taproot output derived from the address.
func sendAssetsToAddr(t *harnessTest, sender *tapdHarness,
	receiverAddrs ...*taprpc.Addr) *taprpc.SendAssetResponse {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	encodedAddrs := make([]string, len(receiverAddrs))
	for i, addr := range receiverAddrs {
		encodedAddrs[i] = addr.Encoded
	}

	resp, err := sender.SendAsset(ctxt, &taprpc.SendAssetRequest{
		TapAddrs: encodedAddrs,
	})
	require.NoError(t.t, err)

	return resp
}

// fundAddressSendPacket asks the wallet to fund a new virtual packet with the
// given address as the single receiver.
func fundAddressSendPacket(t *harnessTest, tapd *tapdHarness,
	rpcAddr *taprpc.Addr) *wrpc.FundVirtualPsbtResponse {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	resp, err := tapd.FundVirtualPsbt(ctxt, &wrpc.FundVirtualPsbtRequest{
		Template: &wrpc.FundVirtualPsbtRequest_Raw{
			Raw: &wrpc.TxTemplate{
				Recipients: map[string]uint64{
					rpcAddr.Encoded: 1,
				},
			},
		},
	})
	require.NoError(t.t, err)

	return resp
}

// fundPacket asks the wallet to fund the given virtual packet.
func fundPacket(t *harnessTest, tapd *tapdHarness,
	vPkg *tappsbt.VPacket) *wrpc.FundVirtualPsbtResponse {

	var buf bytes.Buffer
	err := vPkg.Serialize(&buf)
	require.NoError(t.t, err)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	resp, err := tapd.FundVirtualPsbt(ctxt, &wrpc.FundVirtualPsbtRequest{
		Template: &wrpc.FundVirtualPsbtRequest_Psbt{
			Psbt: buf.Bytes(),
		},
	})
	require.NoError(t.t, err)

	return resp
}
