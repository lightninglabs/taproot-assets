package itest

import (
	"bytes"
	"context"
	"fmt"

	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightninglabs/taro/tarorpc"
	wrpc "github.com/lightninglabs/taro/tarorpc/assetwalletrpc"
	"github.com/lightninglabs/taro/tarorpc/mintrpc"
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
		t, t.tarod, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We'll make a second node now that'll be the receiver of all the
	// assets made above.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tarodHarnessParams) {
			params.startupSyncNode = t.tarod
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	var addresses []*tarorpc.Addr
	for _, a := range rpcAssets {
		// In order to force a split, we don't try to send the full
		// asset.
		addr, err := secondTarod.NewAddr(ctxt, &tarorpc.NewAddrRequest{
			AssetId: a.AssetGenesis.AssetId,
			Amt:     a.Amount - 1,
		})
		require.NoError(t.t, err)
		addresses = append(addresses, addr)

		assertAddrCreated(t.t, secondTarod, a, addr)

		sendResp := sendAssetsToAddr(t, t.tarod, addr)
		sendRespJSON, err := formatProtoJSON(sendResp)
		require.NoError(t.t, err)

		t.Logf("Got response from sending assets: %v", sendRespJSON)

		// Make sure that eventually we see a single event for the
		// address.
		assertAddrEvent(t.t, secondTarod, addr)
	}

	// Mine a block to make sure the events are marked as confirmed.
	_ = mineBlocks(t, t.lndHarness, 1, len(rpcAssets))[0]

	// Eventually the events should be marked as confirmed.
	err := wait.NoError(func() error {
		resp, err := secondTarod.AddrReceives(
			ctxt, &tarorpc.AddrReceivesRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, resp.Events, len(rpcAssets))

		for _, event := range resp.Events {
			if event.Status != statusConfirmed {
				return fmt.Errorf("got status %v, wanted %v",
					resp.Events[0].Status, statusConfirmed)
			}
		}

		return nil
	}, defaultWaitTimeout/2)
	require.NoError(t.t, err)

	// To complete the transfer, we'll export the proof from the sender and
	// import it into the receiver for each asset set.
	for i, rpcAsset := range rpcAssets {
		receiverAddr := addresses[i]

		assetGen := rpcAsset.AssetGenesis

		sendProof(
			t, t.tarod, secondTarod, receiverAddr.ScriptKey,
			assetGen,
		)
	}

	// Make sure we have imported and finalized all proofs.
	assertNonInteractiveRecvComplete(t, secondTarod, len(rpcAssets))

	// Now sanity check that we can actually list the transfer.
	err = wait.NoError(func() error {
		resp, err := t.tarod.ListTransfers(
			ctxt, &tarorpc.ListTransfersRequest{},
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
}

// testMultiAddress tests that we can send assets to multiple addresses at the
// same time.
func testMultiAddress(t *harnessTest) {
	// First, mint an asset, so we have one to create addresses for.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)
	mintedAsset := rpcAssets[0]
	genInfo := mintedAsset.AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We'll make a second node now that'll be the receiver of all the
	// assets made above.
	alice := t.tarod
	bob := setupTarodHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tarodHarnessParams) {
			params.startupSyncNode = alice
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, bob.stop(true))
	}()

	// In order to force a split, we don't try to send the full asset.
	const sendAmt = 100
	var bobAddresses []*tarorpc.Addr
	bobAddr1, err := bob.NewAddr(ctxt, &tarorpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     sendAmt,
	})
	require.NoError(t.t, err)
	bobAddresses = append(bobAddresses, bobAddr1)
	assertAddrCreated(t.t, bob, mintedAsset, bobAddr1)

	bobAddr2, err := bob.NewAddr(ctxt, &tarorpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     sendAmt,
	})
	require.NoError(t.t, err)
	bobAddresses = append(bobAddresses, bobAddr2)
	assertAddrCreated(t.t, bob, mintedAsset, bobAddr2)

	// To test that Alice can also receive to multiple addresses in a single
	// transaction as well, we also add two addresses for her.
	aliceAddr1, err := alice.NewAddr(ctxt, &tarorpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     sendAmt,
	})
	require.NoError(t.t, err)
	assertAddrCreated(t.t, alice, mintedAsset, aliceAddr1)

	aliceAddr2, err := alice.NewAddr(ctxt, &tarorpc.NewAddrRequest{
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
	assertAddrEvent(t.t, bob, bobAddr1)
	assertAddrEvent(t.t, bob, bobAddr2)
	assertAddrEvent(t.t, alice, aliceAddr1)
	assertAddrEvent(t.t, alice, aliceAddr2)

	// Mine a block to make sure the events are marked as confirmed.
	_ = mineBlocks(t, t.lndHarness, 1, 1)[0]

	// Eventually the events should be marked as confirmed.
	assertAddrReceives(t.t, bob, 2, statusConfirmed)

	// For local addresses, we should already have the proof in the DB at
	// this point, so the status should go to completed directly.
	assertAddrReceives(t.t, alice, 2, statusCompleted)

	// To complete the transfer, we'll export the proof from the sender and
	// import it into the receiver for each asset set. This should not be
	// necessary for the sends to Alice, as she is both the sender and
	// receiver and should detect the local proof once it's written to disk.
	for i := range bobAddresses {
		sendProof(t, alice, bob, bobAddresses[i].ScriptKey, genInfo)
	}

	// Make sure we have imported and finalized all proofs.
	assertNonInteractiveRecvComplete(t, bob, 2)
	assertNonInteractiveRecvComplete(t, alice, 2)

	// Now sanity check that we can actually list the transfer.
	const (
		numOutputs = 5
		numAddrs   = 4
	)
	changeAmt := mintedAsset.Amount - (sendAmt * numAddrs)
	err = wait.NoError(func() error {
		resp, err := alice.ListTransfers(
			ctxt, &tarorpc.ListTransfersRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, resp.Transfers, len(rpcAssets))
		require.Len(t.t, resp.Transfers[0].Outputs, numOutputs)
		firstOut := resp.Transfers[0].Outputs[0]
		require.EqualValues(t.t, changeAmt, firstOut.Amount)
		firstIn := resp.Transfers[0].Inputs[0]
		require.Equal(
			t.t, rpcAssets[0].AssetGenesis.AssetId, firstIn.AssetId,
		)

		return nil
	}, defaultTimeout/2)
	require.NoError(t.t, err)
}

func sendProof(t *harnessTest, src, dst *tarodHarness, scriptKey []byte,
	genInfo *tarorpc.GenesisInfo) *tarorpc.ImportProofResponse {

	ctxb := context.Background()

	var proofResp *tarorpc.ProofFile
	waitErr := wait.NoError(func() error {
		resp, err := src.ExportProof(ctxb, &tarorpc.ExportProofRequest{
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

	t.Logf("Importing proof %x", proofResp.RawProof)

	importResp, err := dst.ImportProof(ctxb, &tarorpc.ImportProofRequest{
		ProofFile:    proofResp.RawProof,
		GenesisPoint: genInfo.GenesisPoint,
	})
	require.NoError(t.t, err)

	return importResp
}

// sendAssetsToAddr spends the given input asset and sends the amount specified
// in the address to the Taproot output derived from the address.
func sendAssetsToAddr(t *harnessTest, sender *tarodHarness,
	receiverAddrs ...*tarorpc.Addr) *tarorpc.SendAssetResponse {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	encodedAddrs := make([]string, len(receiverAddrs))
	for i, addr := range receiverAddrs {
		encodedAddrs[i] = addr.Encoded
	}

	resp, err := sender.SendAsset(ctxt, &tarorpc.SendAssetRequest{
		TaroAddrs: encodedAddrs,
	})
	require.NoError(t.t, err)

	return resp
}

// fundAddressSendPacket asks the wallet to fund a new virtual packet with the
// given address as the single receiver.
func fundAddressSendPacket(t *harnessTest, tarod *tarodHarness,
	rpcAddr *tarorpc.Addr) *wrpc.FundVirtualPsbtResponse {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	resp, err := tarod.FundVirtualPsbt(ctxt, &wrpc.FundVirtualPsbtRequest{
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
func fundPacket(t *harnessTest, tarod *tarodHarness,
	vPkg *taropsbt.VPacket) *wrpc.FundVirtualPsbtResponse {

	var buf bytes.Buffer
	err := vPkg.Serialize(&buf)
	require.NoError(t.t, err)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	resp, err := tarod.FundVirtualPsbt(ctxt, &wrpc.FundVirtualPsbtRequest{
		Template: &wrpc.FundVirtualPsbtRequest_Psbt{
			Psbt: buf.Bytes(),
		},
	})
	require.NoError(t.t, err)

	return resp
}
