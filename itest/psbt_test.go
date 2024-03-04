package itest

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/davecgh/go-spew/spew"
	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/tapdevrpc"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

var (
	feeRateSatPerKVByte chainfee.SatPerKVByte = 2000
)

// testPsbtScriptHashLockSend tests that we can properly send assets with a hash
// lock back and forth between nodes with the use of PSBTs.
func testPsbtScriptHashLockSend(t *harnessTest) {
	// First, we'll make a normal asset with enough units to allow us to
	// send it around a few times.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	mintedAsset := rpcAssets[0]
	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	var (
		alice    = t.tapd
		bob      = secondTapd
		numUnits = uint64(10)
	)

	// We need to derive two keys, one for the new script key and one for
	// the internal key.
	bobScriptKey, bobInternalKey := deriveKeys(t.t, bob)

	// Now we create a script tree consisting of two simple scripts.
	preImage := []byte("hash locks are cool")
	leaf1 := test.ScriptHashLock(t.t, preImage)
	leaf2 := test.ScriptSchnorrSig(t.t, bobScriptKey.PubKey)
	leaf2Hash := leaf2.TapHash()
	tapscript := input.TapscriptPartialReveal(
		bobScriptKey.PubKey, leaf1, leaf2Hash[:],
	)
	rootHash := tapscript.ControlBlock.RootHash(leaf1.Script)

	sendToTapscriptAddr(
		ctxt, t, alice, bob, numUnits, genInfo, mintedAsset,
		bobScriptKey, bobInternalKey, tapscript, rootHash,
	)

	// Now try to send back those assets using the PSBT flow.
	aliceAddr, err := alice.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     numUnits / 2,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, alice, rpcAssets[0], aliceAddr)

	fundResp := fundAddressSendPacket(t, bob, aliceAddr)
	t.Logf("Funded PSBT: %v",
		base64.StdEncoding.EncodeToString(fundResp.FundedPsbt))

	fundedPacket, err := tappsbt.NewFromRawBytes(
		bytes.NewReader(fundResp.FundedPsbt), false,
	)
	require.NoError(t.t, err)

	// We don't need to sign anything as we're going to spend with a
	// pre-image to the script lock.
	controlBlockBytes, err := tapscript.ControlBlock.ToBytes()
	require.NoError(t.t, err)
	senderOut := fundedPacket.Outputs[0].Asset
	senderOut.PrevWitnesses[0].TxWitness = [][]byte{
		preImage, leaf1.Script, controlBlockBytes,
	}

	for idx := range fundedPacket.Outputs {
		out := fundedPacket.Outputs[idx]
		splitAsset := out.Asset

		if out.Type.IsSplitRoot() {
			splitAsset = out.SplitAsset
		}

		splitCommitment := splitAsset.PrevWitnesses[0].SplitCommitment
		splitCommitment.RootAsset = *senderOut.Copy()
	}

	var b bytes.Buffer
	err = fundedPacket.Serialize(&b)
	require.NoError(t.t, err)

	// Now we'll attempt to complete the transfer.
	sendResp, err := bob.AnchorVirtualPsbts(
		ctxb, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{b.Bytes()},
		},
	)
	require.NoError(t.t, err)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, bob, sendResp,
		genInfo.AssetId, []uint64{numUnits / 2, numUnits / 2}, 0, 1,
	)

	AssertNonInteractiveRecvComplete(t.t, alice, 1)
	AssertAddrEvent(t.t, alice, aliceAddr, 1, statusCompleted)

	aliceAssets, err := alice.ListAssets(ctxb, &taprpc.ListAssetRequest{
		WithWitness: true,
	})
	require.NoError(t.t, err)

	assetsJSON, err := formatProtoJSON(aliceAssets)
	require.NoError(t.t, err)
	t.Logf("Got alice assets: %s", assetsJSON)
}

// testPsbtScriptCheckSigSend tests that we can properly send assets with a sig
// script back and forth between nodes with the use of PSBTs.
func testPsbtScriptCheckSigSend(t *harnessTest) {
	// First, we'll make a normal asset with enough units to allow us to
	// send it around a few times.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)

	mintedAsset := rpcAssets[0]
	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	var (
		alice    = t.tapd
		bob      = secondTapd
		numUnits = uint64(10)
	)

	// We need to derive two keys, one for the new script key and one for
	// the internal key.
	bobScriptKey, bobInternalKey := deriveKeys(t.t, bob)

	// Now we create a script tree consisting of two simple scripts.
	preImage := []byte("hash locks are cool")
	leaf1 := test.ScriptHashLock(t.t, preImage)
	leaf2 := test.ScriptSchnorrSig(t.t, bobScriptKey.RawKey.PubKey)
	leaf1Hash := leaf1.TapHash()
	leaf2Hash := leaf2.TapHash()
	tapscript := input.TapscriptPartialReveal(
		bobScriptKey.RawKey.PubKey, leaf2, leaf1Hash[:],
	)
	rootHash := tapscript.ControlBlock.RootHash(leaf2.Script)

	sendToTapscriptAddr(
		ctxt, t, alice, bob, numUnits, genInfo, mintedAsset,
		bobScriptKey, bobInternalKey, tapscript, rootHash,
	)

	// Now try to send back those assets using the PSBT flow.
	aliceAddr, err := alice.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:      genInfo.AssetId,
		Amt:          numUnits / 2,
		AssetVersion: mintedAsset.Version,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, alice, rpcAssets[0], aliceAddr)

	fundResp := fundAddressSendPacket(t, bob, aliceAddr)
	t.Logf("Funded PSBT: %v",
		base64.StdEncoding.EncodeToString(fundResp.FundedPsbt))

	fundedPacket, err := tappsbt.NewFromRawBytes(
		bytes.NewReader(fundResp.FundedPsbt), false,
	)
	require.NoError(t.t, err)

	// We can now ask the wallet to sign the script path, since we only need
	// a signature.
	controlBlockBytes, err := tapscript.ControlBlock.ToBytes()
	require.NoError(t.t, err)
	fundedPacket.Inputs[0].TaprootMerkleRoot = rootHash[:]
	fundedPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: controlBlockBytes,
			Script:       leaf2.Script,
			LeafVersion:  leaf2.LeafVersion,
		},
	}
	fundedPacket.Inputs[0].TaprootBip32Derivation[0].LeafHashes = [][]byte{
		leaf2Hash[:],
	}
	var b bytes.Buffer
	err = fundedPacket.Serialize(&b)
	require.NoError(t.t, err)

	signedResp, err := bob.SignVirtualPsbt(
		ctxb, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: b.Bytes(),
		},
	)
	require.NoError(t.t, err)
	require.Contains(t.t, signedResp.SignedInputs, uint32(0))

	// Now we'll attempt to complete the transfer.
	sendResp, err := bob.AnchorVirtualPsbts(
		ctxb, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signedResp.SignedPsbt},
		},
	)
	require.NoError(t.t, err)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, bob, sendResp,
		genInfo.AssetId, []uint64{numUnits / 2, numUnits / 2}, 0, 1,
	)

	AssertNonInteractiveRecvComplete(t.t, alice, 1)
	AssertAddrEvent(t.t, alice, aliceAddr, 1, statusCompleted)

	aliceAssets, err := alice.ListAssets(ctxb, &taprpc.ListAssetRequest{
		WithWitness: true,
	})
	require.NoError(t.t, err)

	assetsJSON, err := formatProtoJSON(aliceAssets)
	require.NoError(t.t, err)
	t.Logf("Got alice assets: %s", assetsJSON)
}

// testPsbtNormalInteractiveFullValueSend tests that we can properly send normal
// assets back and forth, using the full amount, between nodes with the use of
// PSBTs.
func testPsbtNormalInteractiveFullValueSend(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send backand forth. We're also minting a passive asset that
	// should remain where it is.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			simpleAssets[0],
			// Our "passive" asset.
			{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "itestbuxx-passive",
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte("some metadata"),
					},
					Amount: 123,
				},
			},
		},
	)

	mintedAsset := rpcAssets[0]
	genInfo := mintedAsset.AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	runPsbtInteractiveFullValueSendTest(
		ctxt, t, t.tapd, secondTapd, genInfo, mintedAsset,
		rpcAssets[1],
	)
}

// testPsbtGroupedInteractiveFullValueSend tests that we can properly send
// grouped assets back and forth, using the full amount, between nodes with the
// use of PSBTs.
func testPsbtGroupedInteractiveFullValueSend(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send backand forth. We're also minting a passive asset that
	// should remain where it is.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			issuableAssets[0],
			// Our "passive" asset.
			{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "itestbuxx-passive",
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte("some metadata"),
					},
					Amount: 123,
				},
			},
		},
	)

	mintedAsset := rpcAssets[0]
	genInfo := mintedAsset.AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	runPsbtInteractiveFullValueSendTest(
		ctxt, t, t.tapd, secondTapd, genInfo, mintedAsset,
		rpcAssets[1],
	)
}

// runPsbtInteractiveFullValueSendTest runs a single test of sending an asset
// back and forth between two nodes using PSBTs and the full amount.
func runPsbtInteractiveFullValueSendTest(ctxt context.Context, t *harnessTest,
	alice, bob *tapdHarness, genInfo *taprpc.GenesisInfo,
	mintedAsset, passiveAsset *taprpc.Asset) {

	var (
		sender      = alice
		receiver    = bob
		id          [32]byte
		fullAmt     = mintedAsset.Amount
		chainParams = &address.RegressionNetTap
	)
	copy(id[:], genInfo.AssetId)

	const numSend = 4
	for i := 0; i < numSend; i++ {
		// Swap the sender and receiver nodes starting at the second
		// iteration.
		if i > 0 {
			sender, receiver = receiver, sender
		}

		// We need to derive two keys, one for the new script key and
		// one for the internal key.
		receiverScriptKey, receiverAnchorIntKeyDesc := deriveKeys(
			t.t, receiver,
		)

		vPkt := tappsbt.ForInteractiveSend(
			id, fullAmt, receiverScriptKey, 0,
			receiverAnchorIntKeyDesc, asset.V0,
			chainParams,
		)

		// Next, we'll attempt to complete a transfer with PSBTs from
		// our sender node to our receiver, using the full amount.
		fundResp := fundPacket(t, sender, vPkt)
		signResp, err := sender.SignVirtualPsbt(
			ctxt, &wrpc.SignVirtualPsbtRequest{
				FundedPsbt: fundResp.FundedPsbt,
			},
		)
		require.NoError(t.t, err)

		// Now we'll attempt to complete the transfer.
		sendResp, err := sender.AnchorVirtualPsbts(
			ctxt, &wrpc.AnchorVirtualPsbtsRequest{
				VirtualPsbts: [][]byte{signResp.SignedPsbt},
			},
		)
		require.NoError(t.t, err)

		numOutputs := 1
		amounts := []uint64{fullAmt}
		ConfirmAndAssertOutboundTransferWithOutputs(
			t.t, t.lndHarness.Miner.Client, sender,
			sendResp, genInfo.AssetId, amounts, i/2, (i/2)+1,
			numOutputs,
		)

		// This is an interactive transfer, so we do need to manually
		// send the proof from the sender to the receiver.
		_ = sendProof(
			t, sender, receiver, sendResp,
			receiverScriptKey.PubKey.SerializeCompressed(), genInfo,
		)

		senderAssets, err := sender.ListAssets(
			ctxt, &taprpc.ListAssetRequest{},
		)
		require.NoError(t.t, err)

		// Depending on what direction we currently have, the number of
		// expected assets is different, since the initial sender always
		// has the passive asset left.
		numSenderAssets := 1
		numReceiverAssets := 1
		if sender == bob {
			numSenderAssets = 0
			numReceiverAssets = 2
		}
		require.Len(t.t, senderAssets.Assets, numSenderAssets)

		receiverAssets, err := receiver.ListAssets(
			ctxt, &taprpc.ListAssetRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, receiverAssets.Assets, numReceiverAssets)
		receivedAssets := GroupAssetsByName(receiverAssets.Assets)
		AssertAssetState(
			t.t, receivedAssets, genInfo.Name, genInfo.MetaHash,
			AssetAmountCheck(fullAmt),
		)
	}

	// Finally, make sure we can still send out the passive asset.
	passiveGen := passiveAsset.AssetGenesis
	sendAssetAndAssert(
		ctxt, t, alice, bob, passiveAsset.Amount, 0,
		passiveGen, passiveAsset, 2, 3, 1,
	)
}

// testPsbtNormalInteractiveSplitSend tests that we can properly send normal
// assets back and forth, using the full amount, between nodes with the use of
// PSBTs.
func testPsbtNormalInteractiveSplitSend(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send backand forth. We're also minting a passive asset that
	// should remain where it is.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			simpleAssets[0],
			// Our "passive" asset.
			{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "itestbuxx-passive",
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte("some metadata"),
					},
					Amount: 123,
				},
			},
		},
	)

	mintedAsset := rpcAssets[0]
	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	runPsbtInteractiveSplitSendTest(
		ctxt, t, t.tapd, secondTapd, genInfo, mintedAsset,
		rpcAssets[1],
	)
}

// testPsbtGroupedInteractiveSplitSend tests that we can properly send grouped
// assets back and forth, using the full amount, between nodes with the use of
// PSBTs.
func testPsbtGroupedInteractiveSplitSend(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send backand forth. We're also minting a passive asset that
	// should remain where it is.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			issuableAssets[0],
			// Our "passive" asset.
			{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "itestbuxx-passive",
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte("some metadata"),
					},
					Amount: 123,
				},
			},
		},
	)

	mintedAsset := rpcAssets[0]
	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	runPsbtInteractiveSplitSendTest(
		ctxt, t, t.tapd, secondTapd, genInfo, mintedAsset,
		rpcAssets[1],
	)
}

// runPsbtInteractiveSplitSendTest runs a single test of sending an asset
// back and forth between two nodes using PSBTs and a split amount.
func runPsbtInteractiveSplitSendTest(ctxt context.Context, t *harnessTest,
	alice, bob *tapdHarness, genInfo *taprpc.GenesisInfo,
	mintedAsset, passiveAsset *taprpc.Asset) {

	var (
		sender      = alice
		receiver    = bob
		senderSum   = mintedAsset.Amount
		receiverSum = uint64(0)
		id          [32]byte
		chainParams = &address.RegressionNetTap
	)
	copy(id[:], genInfo.AssetId)

	// We are going to send 4200 units at the beginning, then always half
	// the amount of the previous transfer, doing a total of 4 transfers.
	const (
		numSend        = 4
		initialSendAmt = 4800
	)
	var (
		sendAmt   = uint64(initialSendAmt)
		changeAmt = senderSum - sendAmt
	)
	for i := 0; i < numSend; i++ {
		// Swap the sender and receiver nodes starting at the second
		// iteration.
		if i > 0 {
			sendAmt /= 2
			changeAmt = sendAmt
			sender, receiver = receiver, sender
			senderSum, receiverSum = receiverSum, senderSum
		}
		if i == 3 {
			changeAmt = (initialSendAmt / 2) - sendAmt
		}

		// We need to derive two keys, one for the new script key and
		// one for the internal key.
		receiverScriptKey, receiverAnchorIntKeyDesc := deriveKeys(
			t.t, receiver,
		)

		vPkt := tappsbt.ForInteractiveSend(
			id, sendAmt, receiverScriptKey, 0,
			receiverAnchorIntKeyDesc, asset.V0, chainParams,
		)

		// Next, we'll attempt to complete a transfer with PSBTs from
		// our sender node to our receiver, using the partial amount.
		fundResp := fundPacket(t, sender, vPkt)
		signResp, err := sender.SignVirtualPsbt(
			ctxt, &wrpc.SignVirtualPsbtRequest{
				FundedPsbt: fundResp.FundedPsbt,
			},
		)
		require.NoError(t.t, err)

		// Now we'll attempt to complete the transfer.
		sendResp, err := sender.AnchorVirtualPsbts(
			ctxt, &wrpc.AnchorVirtualPsbtsRequest{
				VirtualPsbts: [][]byte{signResp.SignedPsbt},
			},
		)
		require.NoError(t.t, err)

		numOutputs := 2
		ConfirmAndAssertOutboundTransferWithOutputs(
			t.t, t.lndHarness.Miner.Client, sender,
			sendResp, genInfo.AssetId,
			[]uint64{sendAmt, changeAmt}, i/2, (i/2)+1,
			numOutputs,
		)

		// This is an interactive transfer, so we do need to manually
		// send the proof from the sender to the receiver.
		_ = sendProof(
			t, sender, receiver, sendResp,
			receiverScriptKey.PubKey.SerializeCompressed(), genInfo,
		)

		senderAssets, err := sender.ListAssets(
			ctxt, &taprpc.ListAssetRequest{},
		)
		require.NoError(t.t, err)

		// Depending on what direction we currently have, the number of
		// expected assets is different, since the initial sender always
		// has the passive asset left. We start with 5k units for the
		// active asset and 123 units for the passive assets.
		// 	i	alice			send	     bob
		//	--------------------------------------------------------
		// 	0	123, 200		4.8k ->	     4800
		// 	1	123, 200, 2400		<- 2.4k	     2400
		// 	2	123, 200, 1200		1.2k ->      2400, 1200
		// 	3	123, 200, 1250, 600	<- 600	     2400, 600
		aliceOutputs := 1 + ((i + 1) / 2) + 1
		bobOutputs := 1 + (i / 2)
		numSenderAssets, numReceiverAssets := aliceOutputs, bobOutputs
		if i%2 != 0 {
			numSenderAssets, numReceiverAssets = bobOutputs,
				aliceOutputs
		}
		require.Len(t.t, senderAssets.Assets, numSenderAssets)

		receiverAssets, err := receiver.ListAssets(
			ctxt, &taprpc.ListAssetRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, receiverAssets.Assets, numReceiverAssets)
	}

	// Finally, make sure we can still send out the passive asset.
	passiveGen := passiveAsset.AssetGenesis
	sendAssetAndAssert(
		ctxt, t, alice, bob, passiveAsset.Amount, 0,
		passiveGen, passiveAsset, 2, 3, 1,
	)
}

// testPsbtInteractiveTapscriptSibling tests that we can send assets to an
// anchor output that also commits to a tapscript sibling.
func testPsbtInteractiveTapscriptSibling(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send backand forth.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis
	chainParams := &address.RegressionNetTap

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	var (
		alice = t.tapd
		bob   = secondTapd
		id    [32]byte
	)
	copy(id[:], genInfo.AssetId)

	// We need to derive two keys, one for the new script key and one for
	// the internal key.
	receiverScriptKey, receiverAnchorIntKeyDesc := deriveKeys(t.t, bob)

	var (
		sendAmt   = uint64(1000)
		changeAmt = rpcAssets[0].Amount - sendAmt
	)
	vPkt := tappsbt.ForInteractiveSend(
		id, sendAmt, receiverScriptKey, 0, receiverAnchorIntKeyDesc,
		asset.V0, chainParams,
	)

	// We now create a Tapscript sibling with a simple hash lock script.
	preImage := []byte("hash locks are cool")
	siblingLeaf := test.ScriptHashLock(t.t, preImage)

	siblingPreimage, err := commitment.NewPreimageFromLeaf(siblingLeaf)
	require.NoError(t.t, err)
	vPkt.Outputs[0].AnchorOutputTapscriptSibling = siblingPreimage

	// Next, we'll attempt to complete a transfer with PSBTs from alice to
	// bob, using the partial amount.
	fundResp := fundPacket(t, alice, vPkt)
	signResp, err := alice.SignVirtualPsbt(
		ctxt, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundResp.FundedPsbt,
		},
	)
	require.NoError(t.t, err)

	// Now we'll attempt to complete the transfer.
	sendResp, err := alice.AnchorVirtualPsbts(
		ctxt, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signResp.SignedPsbt},
		},
	)
	require.NoError(t.t, err)

	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner.Client, alice, sendResp,
		genInfo.AssetId, []uint64{sendAmt, changeAmt}, 0, 1, 2,
	)

	// This is an interactive transfer, so we do need to manually send the
	// proof from the sender to the receiver.
	_ = sendProof(
		t, alice, bob, sendResp,
		receiverScriptKey.PubKey.SerializeCompressed(), genInfo,
	)

	senderAssets, err := alice.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, senderAssets.Assets, 1)

	receiverAssets, err := bob.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, receiverAssets.Assets, 1)
	require.True(t.t, bytes.Contains(
		receiverAssets.Assets[0].ChainAnchor.TapscriptSibling,
		siblingLeaf.Script,
	))

	assetsJSON, err := formatProtoJSON(receiverAssets)
	require.NoError(t.t, err)
	t.Logf("Got bob assets: %s", assetsJSON)

	// And finally, make sure we can spend the asset again.
	sendAssetAndAssert(
		ctxt, t, bob, alice, sendAmt/2, sendAmt/2, genInfo,
		rpcAssets[0], 0, 1, 1,
	)
}

// testPsbtMultiSend tests that we can properly send assets to multiple
// addresses at the same time.
func testPsbtMultiSend(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send backand forth. We're also minting a passive asset that
	// should remain where it is.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			simpleAssets[0],
			// Our "passive" asset.
			{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "itestbuxx-passive",
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte("some metadata"),
					},
					Amount: 123,
				},
			},
		},
	)

	genInfo := rpcAssets[0].AssetGenesis
	chainParams := &address.RegressionNetTap

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	var (
		sender   = t.tapd
		receiver = secondTapd
		id       [32]byte
	)
	copy(id[:], genInfo.AssetId)

	// We need to derive two sets of keys, one for the new script key and
	// one for the internal key each.
	receiverScriptKey1, receiverAnchorIntKeyDesc1 := deriveKeys(
		t.t, receiver,
	)
	receiverScriptKey2, receiverAnchorIntKeyDesc2 := deriveKeys(
		t.t, receiver,
	)

	// We'll also do an internal split back to the sender itself. So we also
	// need two sets of keys for the sender.
	senderScriptKey1, senderAnchorIntKeyDesc1 := deriveKeys(t.t, sender)
	senderScriptKey2, _ := deriveKeys(t.t, sender)

	// We create the output at anchor index 0 for the first address.
	outputAmounts := []uint64{1200, 1300, 1400, 800, 300}
	vPkt := tappsbt.ForInteractiveSend(
		id, outputAmounts[0], receiverScriptKey1, 0,
		receiverAnchorIntKeyDesc1, asset.V0, chainParams,
	)

	// And now we'll create an output at anchor index 1 for the second
	// address and two at anchor index 2 for our internal split. This should
	// still leave 300 units as change which we expect to end up at anchor
	// index 3.
	tappsbt.AddOutput(
		vPkt, outputAmounts[1], receiverScriptKey2, 1,
		receiverAnchorIntKeyDesc2, asset.V0,
	)
	tappsbt.AddOutput(
		vPkt, outputAmounts[2], senderScriptKey1, 2,
		senderAnchorIntKeyDesc1, asset.V0,
	)
	tappsbt.AddOutput(
		vPkt, outputAmounts[3], senderScriptKey2, 2,
		senderAnchorIntKeyDesc1, asset.V0,
	)

	// Next, we'll attempt to complete a transfer with PSBTs from
	// our sender node to our receiver, using the partial amount.
	fundResp := fundPacket(t, sender, vPkt)
	signResp, err := sender.SignVirtualPsbt(
		ctxt, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundResp.FundedPsbt,
		},
	)
	require.NoError(t.t, err)

	// Now we'll attempt to complete the transfer.
	sendResp, err := sender.AnchorVirtualPsbts(
		ctxt, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signResp.SignedPsbt},
		},
	)
	require.NoError(t.t, err)

	// We end up with a transfer with 5 outputs: 2 for the two different
	// receiver addresses (with an anchor output each), 2 for the sender
	// addresses (sharing an anchor output) and 1 for the change. So there
	// are 4 BTC anchor outputs but 5 asset transfer outputs.
	numOutputs := 5
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner.Client, sender, sendResp,
		genInfo.AssetId, outputAmounts, 0, 1, numOutputs,
	)

	// This is an interactive transfer, so we do need to manually send the
	// proof from the sender to the receiver.
	_ = sendProof(
		t, sender, receiver, sendResp,
		receiverScriptKey1.PubKey.SerializeCompressed(), genInfo,
	)
	_ = sendProof(
		t, sender, receiver, sendResp,
		receiverScriptKey2.PubKey.SerializeCompressed(), genInfo,
	)

	senderAssets, err := sender.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, senderAssets.Assets, 4)

	receiverAssets, err := receiver.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, receiverAssets.Assets, 2)

	// Next, we make sure we can still send out the passive asset.
	passiveAsset := rpcAssets[1]
	passiveGen := rpcAssets[1].AssetGenesis
	sendAssetAndAssert(
		ctxt, t, t.tapd, secondTapd, passiveAsset.Amount, 0,
		passiveGen, passiveAsset, 1, 2, 1,
	)

	// And finally, we make sure that we can send out one of the asset UTXOs
	// that shared the anchor output and the other one is treated as a
	// passive asset.
	sendAssetAndAssert(
		ctxt, t, t.tapd, secondTapd, outputAmounts[2], 0,
		genInfo, rpcAssets[0], 2, 3, 2,
	)
}

// testMultiInputPsbtSingleAssetID tests to ensure that we can correctly
// construct and spend a multi-input partial value and full value PSBT where
// each input has the same asset ID.
//
// The test works as follows:
//  1. Mint an asset on the primary tapd node.
//  2. Send the asset to a secondary tapd node in three different send events.
//  3. Send a partial amount of the asset back to the primary tapd node in a
//     single multi-input PSBT send event.
//  4. Send the remaining amount of the asset back to the primary tapd node in
//     a single full value multi-input PSBT send event.
func testMultiInputPsbtSingleAssetID(t *harnessTest) {
	var (
		ctxb        = context.Background()
		primaryTapd = t.tapd
	)

	// Mint a single asset.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, primaryTapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)
	rpcAsset := rpcAssets[0]
	assetTotalAmtMinted := simpleAssets[0].Asset.Amount

	// The primary node asset total should be equal to the amount minted.
	// This variable will serve as a running total of the amount of the
	// asset on the primary node.
	primaryTapdAssetAmt := assetTotalAmtMinted

	// Set up a node that will serve as the final multi input PSBT sender
	// node.
	secondaryTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondaryTapd.stop(!*noDelete))
	}()

	// First of three send events from primary (minting) node to secondary
	// node.
	sendAmt := uint64(1000)
	changeAmt := primaryTapdAssetAmt - sendAmt

	genInfo := rpcAsset.AssetGenesis
	addr, err := secondaryTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     sendAmt,
		},
	)
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, secondaryTapd, rpcAsset, addr)

	// Send the assets to the secondary node.
	sendResp := sendAssetsToAddr(t, primaryTapd, addr)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, primaryTapd, sendResp,
		genInfo.AssetId, []uint64{changeAmt, sendAmt}, 0, 1,
	)

	AssertNonInteractiveRecvComplete(t.t, secondaryTapd, 1)

	primaryTapdAssetAmt -= sendAmt

	// Second of three send events from primary (minting) node to secondary
	// node.
	sendAmt = uint64(1000)
	changeAmt = primaryTapdAssetAmt - sendAmt

	genInfo = rpcAsset.AssetGenesis
	addr, err = secondaryTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     sendAmt,
		},
	)
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, secondaryTapd, rpcAsset, addr)

	// Send the assets to the secondary node.
	sendResp = sendAssetsToAddr(t, primaryTapd, addr)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, primaryTapd, sendResp,
		genInfo.AssetId, []uint64{changeAmt, sendAmt}, 1, 2,
	)

	AssertNonInteractiveRecvComplete(t.t, secondaryTapd, 2)

	primaryTapdAssetAmt -= sendAmt

	// Third of three send events from primary (minting) node to the
	// secondary node.
	sendAmt = uint64(3000)
	changeAmt = primaryTapdAssetAmt - sendAmt

	addr, err = secondaryTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     sendAmt,
		},
	)
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, secondaryTapd, rpcAsset, addr)

	// Send the assets to the secondary node.
	sendResp = sendAssetsToAddr(t, primaryTapd, addr)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, primaryTapd, sendResp,
		genInfo.AssetId, []uint64{changeAmt, sendAmt}, 2, 3,
	)

	AssertNonInteractiveRecvComplete(t.t, secondaryTapd, 3)

	primaryTapdAssetAmt -= sendAmt

	// At this point, all three send events have completed. The primary
	// node should have no assets and the secondary node should have three
	// assets.
	require.Equal(t.t, uint64(0), primaryTapdAssetAmt)

	t.Logf("Three separate send events complete. Now attempting to send " +
		"a partial amount in a single multi-input PSBT send event " +
		"back to the primary node from the secondary node.")

	// Ensure that the primary node has no assets before we begin.
	primaryNodeAssets, err := primaryTapd.ListAssets(
		ctxb, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Empty(t.t, primaryNodeAssets.Assets)

	// The secondary node should have three assets as a result of the
	// previous three send events.
	secondaryNodeAssets, err := secondaryTapd.ListAssets(
		ctxb, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, secondaryNodeAssets.Assets, 3)

	// We need to derive two keys for the receiver node, one for the new
	// script key and one for the internal key.
	primaryNodeScriptKey, primaryNodeAnchorIntKeyDesc := deriveKeys(
		t.t, primaryTapd,
	)

	var assetId asset.ID
	copy(assetId[:], genInfo.AssetId)

	chainParams := &address.RegressionNetTap
	sendAmt = uint64(3500)
	changeAmt = uint64(500)

	vPkt := tappsbt.ForInteractiveSend(
		assetId, sendAmt, primaryNodeScriptKey, 0,
		primaryNodeAnchorIntKeyDesc, asset.V0, chainParams,
	)

	// Next, we'll attempt to fund the PSBT.
	fundResp := fundPacket(t, secondaryTapd, vPkt)

	// Decode and inspect the funded vPSBT.
	fundedVPsbtCopy := make([]byte, len(fundResp.FundedPsbt))
	copy(fundedVPsbtCopy, fundResp.FundedPsbt)
	bytesReader := bytes.NewReader(fundedVPsbtCopy)

	vPkt, err = tappsbt.NewFromRawBytes(bytesReader, false)
	require.NoError(t.t, err)
	require.Equal(t.t, 2, len(vPkt.Inputs))

	// Sign the funded vPSBT.
	signResp, err := secondaryTapd.SignVirtualPsbt(
		ctxb, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundResp.FundedPsbt,
		},
	)
	require.NoError(t.t, err)

	// And finally anchor the PSBT in the BTC chain to complete the
	// transfer.
	sendResp, err = secondaryTapd.AnchorVirtualPsbts(
		ctxb, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signResp.SignedPsbt},
		},
	)
	require.NoError(t.t, err)

	var (
		currentTransferIdx = 0
		numTransfers       = 1
		numOutputs         = 2
	)
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner.Client, secondaryTapd,
		sendResp, genInfo.AssetId,
		[]uint64{sendAmt, changeAmt}, currentTransferIdx, numTransfers,
		numOutputs,
	)

	// This is an interactive transfer. Therefore, we will manually transfer
	// the proof from the sender to the receiver.
	_ = sendProof(
		t, secondaryTapd, primaryTapd, sendResp,
		primaryNodeScriptKey.PubKey.SerializeCompressed(), genInfo,
	)

	// Finally, we make sure that the primary node has the asset.
	primaryNodeAssets, err = primaryTapd.ListAssets(
		ctxb, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, primaryNodeAssets.Assets, 1)

	// Ensure that the asset is the one we expect.
	primaryNodeAsset := primaryNodeAssets.Assets[0]

	require.Equal(t.t, primaryNodeAsset.Amount, sendAmt)

	var foundAssetId asset.ID
	copy(foundAssetId[:], primaryNodeAsset.AssetGenesis.AssetId)
	require.Equal(t.t, assetId, foundAssetId)

	t.Logf("Partial amount multi-input PSBT send event complete. Now " +
		"attempting to send the remaining amount in a full value " +
		"multi-input PSBT send event back to the primary node from " +
		"the secondary node.")

	// Attempt a full value send of the rest of the asset back to the
	// primary node.
	sendAmt = uint64(1500)

	vPkt = tappsbt.ForInteractiveSend(
		assetId, sendAmt, primaryNodeScriptKey, 0,
		primaryNodeAnchorIntKeyDesc, asset.V0, chainParams,
	)

	// Next, we'll attempt to fund the PSBT.
	fundResp = fundPacket(t, secondaryTapd, vPkt)

	// Decode and inspect the funded vPSBT.
	fundedVPsbtCopy = make([]byte, len(fundResp.FundedPsbt))
	copy(fundedVPsbtCopy, fundResp.FundedPsbt)
	bytesReader = bytes.NewReader(fundedVPsbtCopy)

	vPkt, err = tappsbt.NewFromRawBytes(bytesReader, false)
	require.NoError(t.t, err)
	require.Equal(t.t, 2, len(vPkt.Inputs))

	// Sign the funded vPSBT.
	signResp, err = secondaryTapd.SignVirtualPsbt(
		ctxb, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundResp.FundedPsbt,
		},
	)
	require.NoError(t.t, err)

	// And finally anchor the PSBT in the BTC chain to complete the
	// transfer.
	sendResp, err = secondaryTapd.AnchorVirtualPsbts(
		ctxb, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signResp.SignedPsbt},
		},
	)
	require.NoError(t.t, err)

	currentTransferIdx = 1
	numTransfers = 2
	numOutputs = 1
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner.Client, secondaryTapd, sendResp,
		genInfo.AssetId, []uint64{sendAmt}, currentTransferIdx,
		numTransfers, numOutputs,
	)

	// This is an interactive transfer. Therefore, we will manually transfer
	// the proof from the sender to the receiver.
	_ = sendProof(
		t, secondaryTapd, primaryTapd, sendResp,
		primaryNodeScriptKey.PubKey.SerializeCompressed(), genInfo,
	)

	// Finally, we make sure that the primary node has the asset.
	primaryNodeAssets, err = primaryTapd.ListAssets(
		ctxb, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, primaryNodeAssets.Assets, 2)

	primaryTapdAssetAmt = 0
	for idx := range primaryNodeAssets.Assets {
		a := primaryNodeAssets.Assets[idx]

		// Ensure matching asset ID.
		copy(foundAssetId[:], a.AssetGenesis.AssetId)
		require.Equal(t.t, assetId, foundAssetId)

		require.True(t.t, a.Amount == 1500 || a.Amount == 3500)
		primaryTapdAssetAmt += a.Amount
	}
	require.Equal(t.t, primaryTapdAssetAmt, assetTotalAmtMinted)

	// Finally, we ensure that the secondary node has no assets.
	secondaryNodeAssets, err = secondaryTapd.ListAssets(
		ctxb, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, secondaryNodeAssets.Assets, 0)
}

// testPsbtSighashNone tests that the SIGHASH_NONE flag of vPSBTs is properly
// accounted for in the generated signatures,
func testPsbtSighashNone(t *harnessTest) {
	// First, we'll make a normal asset with enough units to allow us to
	// send it around a few times.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)

	mintedAsset := rpcAssets[0]
	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	var (
		alice    = t.tapd
		bob      = secondTapd
		numUnits = uint64(500)
	)

	// We need to derive two keys, one for the new script key and one for
	// the internal key.
	bobScriptKey, bobInternalKey := deriveKeys(t.t, bob)

	// Now we create a script tree consisting of two simple scripts.
	preImage := []byte("hash locks are cool")
	leaf1 := test.ScriptHashLock(t.t, preImage)
	leaf2 := test.ScriptSchnorrSig(t.t, bobScriptKey.RawKey.PubKey)
	leaf1Hash := leaf1.TapHash()
	leaf2Hash := leaf2.TapHash()
	tapScript := input.TapscriptPartialReveal(
		bobScriptKey.RawKey.PubKey, leaf2, leaf1Hash[:],
	)
	rootHash := tapScript.ControlBlock.RootHash(leaf2.Script)

	sendToTapscriptAddr(
		ctxt, t, alice, bob, numUnits, genInfo, mintedAsset,
		bobScriptKey, bobInternalKey, tapScript, rootHash,
	)

	// Now try to send back those assets using the PSBT flow.
	aliceAddr, err := alice.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:      genInfo.AssetId,
		Amt:          numUnits / 5,
		AssetVersion: mintedAsset.Version,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, alice, rpcAssets[0], aliceAddr)

	fundResp := fundAddressSendPacket(t, bob, aliceAddr)
	t.Logf("Funded PSBT: %v",
		base64.StdEncoding.EncodeToString(fundResp.FundedPsbt))

	fundedPacket, err := tappsbt.NewFromRawBytes(
		bytes.NewReader(fundResp.FundedPsbt), false,
	)
	require.NoError(t.t, err)

	// We can now ask the wallet to sign the script path, since we only need
	// a signature.
	controlBlockBytes, err := tapScript.ControlBlock.ToBytes()
	require.NoError(t.t, err)
	fundedPacket.Inputs[0].TaprootMerkleRoot = rootHash[:]
	fundedPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: controlBlockBytes,
			Script:       leaf2.Script,
			LeafVersion:  leaf2.LeafVersion,
		},
	}
	fundedPacket.Inputs[0].TaprootBip32Derivation[0].LeafHashes = [][]byte{
		leaf2Hash[:],
	}

	// Before signing, we set the sighash of the first input to SIGHASH_NONE
	// which allows us to alter the outputs of the PSBT after the signature
	// has been generated.
	fundedPacket.Inputs[0].SighashType = txscript.SigHashNone

	var b bytes.Buffer
	err = fundedPacket.Serialize(&b)
	require.NoError(t.t, err)

	signedResp, err := bob.SignVirtualPsbt(
		ctxb, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: b.Bytes(),
		},
	)
	require.NoError(t.t, err)
	require.Contains(t.t, signedResp.SignedInputs, uint32(0))

	// Now we deserialize the signed packet again in order to edit it
	// and then anchor it.
	signedPacket, err := tappsbt.NewFromRawBytes(
		bytes.NewReader(signedResp.SignedPsbt), false,
	)
	require.NoError(t.t, err)

	// Edit the already signed PSBT and change the output amounts. This
	// should be ok as we used SIGHASH_NONE for the input's signature.
	signedPacket.Outputs[0].Amount -= 1
	signedPacket.Outputs[1].Amount += 1

	// Keep a backup of the PrevWitnesses as our input is already signed.
	// When Bob re-creates the outputs for the vPSBT we will need to
	// re-attach the witnesses to the new vPkt as the inputs are already
	// signed.
	witnessBackup := signedPacket.Outputs[0].Asset.PrevWitnesses

	// Bob now creates the output assets.
	err = tapsend.PrepareOutputAssets(context.Background(), signedPacket)
	require.NoError(t.t, err)

	// We attach the backed-up Previous Witnesses to the newly created
	// outputs by Bob.
	signedPacket.Outputs[0].Asset.PrevWitnesses = witnessBackup
	signedPacket.Outputs[1].Asset.PrevWitnesses[0].SplitCommitment.RootAsset.
		PrevWitnesses = witnessBackup

	// Serialize the edited signed packet.
	var buffer bytes.Buffer
	err = signedPacket.Serialize(&buffer)
	require.NoError(t.t, err)
	signedBytes := buffer.Bytes()

	// Now we'll attempt to complete the transfer.
	sendResp, err := bob.AnchorVirtualPsbts(
		ctxb, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signedBytes},
		},
	)
	require.NoError(t.t, err)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, bob, sendResp,
		genInfo.AssetId,
		[]uint64{(4*numUnits)/5 - 1, (numUnits / 5) + 1}, 0, 1,
	)

	// This is an interactive/PSBT based transfer, so we do need to manually
	// send the proof from the sender to the receiver because the proof
	// courier address gets lost in the address->PSBT conversion.
	_ = sendProof(t, bob, alice, sendResp, aliceAddr.ScriptKey, genInfo)

	// If Bob was successful in his attempt to edit the outputs, Alice
	// should see an asset with an amount of 399.
	aliceAssets, err := alice.ListAssets(ctxb, &taprpc.ListAssetRequest{
		WithWitness: true,
	})
	require.NoError(t.t, err)

	found := false
	for _, asset := range aliceAssets.Assets {
		if asset.Amount == (numUnits/5)+1 {
			found = true
		}
	}

	require.True(t.t, found)
}

// testPsbtSighashNoneInvalid tests that the SIGHASH_NONE flag of vPSBTs is
// properly accounted for in the generated signatures. This case tests that the
// transfer is invalidated when the flag is not used.
func testPsbtSighashNoneInvalid(t *harnessTest) {
	// First, we'll make a normal asset with enough units to allow us to
	// send it around a few times.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)

	mintedAsset := rpcAssets[0]
	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	var (
		alice    = t.tapd
		bob      = secondTapd
		numUnits = uint64(500)
	)

	// We need to derive two keys, one for the new script key and one for
	// the internal key.
	bobScriptKey, bobInternalKey := deriveKeys(t.t, bob)

	// Now we create a script tree consisting of two simple scripts.
	preImage := []byte("hash locks are cool")
	leaf1 := test.ScriptHashLock(t.t, preImage)
	leaf2 := test.ScriptSchnorrSig(t.t, bobScriptKey.RawKey.PubKey)
	leaf1Hash := leaf1.TapHash()
	leaf2Hash := leaf2.TapHash()
	tapScript := input.TapscriptPartialReveal(
		bobScriptKey.RawKey.PubKey, leaf2, leaf1Hash[:],
	)
	rootHash := tapScript.ControlBlock.RootHash(leaf2.Script)

	sendToTapscriptAddr(
		ctxt, t, alice, bob, numUnits, genInfo, mintedAsset,
		bobScriptKey, bobInternalKey, tapScript, rootHash,
	)

	// Now try to send back those assets using the PSBT flow.
	aliceAddr, err := alice.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:      genInfo.AssetId,
		Amt:          numUnits / 5,
		AssetVersion: mintedAsset.Version,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, alice, rpcAssets[0], aliceAddr)

	fundResp := fundAddressSendPacket(t, bob, aliceAddr)
	t.Logf("Funded PSBT: %v",
		base64.StdEncoding.EncodeToString(fundResp.FundedPsbt))

	fundedPacket, err := tappsbt.NewFromRawBytes(
		bytes.NewReader(fundResp.FundedPsbt), false,
	)
	require.NoError(t.t, err)

	// We can now ask the wallet to sign the script path, since we only need
	// a signature.
	controlBlockBytes, err := tapScript.ControlBlock.ToBytes()
	require.NoError(t.t, err)
	fundedPacket.Inputs[0].TaprootMerkleRoot = rootHash[:]
	fundedPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: controlBlockBytes,
			Script:       leaf2.Script,
			LeafVersion:  leaf2.LeafVersion,
		},
	}
	fundedPacket.Inputs[0].TaprootBip32Derivation[0].LeafHashes = [][]byte{
		leaf2Hash[:],
	}

	// This is where we would normally set the sighash flag to SIGHASH_NONE,
	// but instead we skip that step to verify that the VM will invalidate
	// the transfer when any inputs or outputs are mutated.

	var b bytes.Buffer
	err = fundedPacket.Serialize(&b)
	require.NoError(t.t, err)

	signedResp, err := bob.SignVirtualPsbt(
		ctxb, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: b.Bytes(),
		},
	)
	require.NoError(t.t, err)
	require.Contains(t.t, signedResp.SignedInputs, uint32(0))

	// Now we deserialize the signed packet again in order to edit it
	// and then anchor it.
	signedPacket, err := tappsbt.NewFromRawBytes(
		bytes.NewReader(signedResp.SignedPsbt), false,
	)
	require.NoError(t.t, err)

	// Edit the already signed PSBT and change the output amounts. This
	// should be ok as we used SIGHASH_NONE for the input's signature.
	signedPacket.Outputs[0].Amount -= 1
	signedPacket.Outputs[1].Amount += 1

	// Keep a backup of the PrevWitnesses as our input is already signed.
	// When Bob re-creates the outputs for the vPSBT we will need to
	// re-attach the witnesses to the new vPkt as the inputs are already
	// signed.
	witnessBackup := signedPacket.Outputs[0].Asset.PrevWitnesses

	// Bob now creates the output assets.
	err = tapsend.PrepareOutputAssets(context.Background(), signedPacket)
	require.NoError(t.t, err)

	// We attach the backed-up Previous Witnesses to the newly created
	// outputs by Bob.
	signedPacket.Outputs[0].Asset.PrevWitnesses = witnessBackup
	signedPacket.Outputs[1].Asset.PrevWitnesses[0].SplitCommitment.RootAsset.
		PrevWitnesses = witnessBackup

	// Serialize the edited signed packet.
	var buffer bytes.Buffer
	err = signedPacket.Serialize(&buffer)
	require.NoError(t.t, err)
	signedBytes := buffer.Bytes()

	// Now we'll attempt to complete the transfer.
	sendResp, err := bob.AnchorVirtualPsbts(
		ctxb, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signedBytes},
		},
	)
	require.NoError(t.t, err)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, bob, sendResp,
		genInfo.AssetId,
		[]uint64{(4*numUnits)/5 - 1, (numUnits / 5) + 1}, 0, 1,
	)

	// Export Bob's faulty proof for this transfer.
	var proofResp *taprpc.ProofFile
	waitErr := wait.NoError(func() error {
		resp, err := bob.ExportProof(ctxb, &taprpc.ExportProofRequest{
			AssetId:   genInfo.AssetId,
			ScriptKey: aliceAddr.ScriptKey,
		})
		if err != nil {
			return err
		}

		proofResp = resp
		return nil
	}, defaultWaitTimeout)
	require.NoError(t.t, waitErr)

	// Alice now attempts to import the proof. This will also trigger a
	// transfer validation. This is where we expect the VM to invalidate
	// the proof.
	_, err = alice.ImportProof(ctxb, &tapdevrpc.ImportProofRequest{
		ProofFile:    proofResp.RawProofFile,
		GenesisPoint: genInfo.GenesisPoint,
	})
	require.ErrorContains(t.t, err, "unable to verify proof")
}

// testPsbtExternalCommit tests the ability to fully customize the BTC level of
// an asset transfer using a PSBT. This exercises the CommitVirtualPsbts and
// PublishAndLogTransfer RPCs. The test case moves some assets into an output
// that has a hash lock tapscript.
func testPsbtExternalCommit(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We mint some grouped assets to use in the test. These assets are
	// minted on the default tapd instance that is always created in the
	// integration test (connected to lnd "Alice").
	assets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			issuableAssets[0],
			// Our "passive" asset.
			{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "itestbuxx-passive",
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte("some metadata"),
					},
					Amount: 123,
				},
			},
		},
	)
	targetAsset := assets[0]

	var (
		targetAssetGenesis = targetAsset.AssetGenesis
		aliceTapd          = t.tapd
		aliceLnd           = t.lndHarness.Alice
		bobLnd             = t.lndHarness.Bob
	)

	// We create a second tapd node that will be used to simulate a second
	// party in the test. This tapd node is connected to lnd "Bob".
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	// And now we prepare the hash lock script for the BTC level.
	btcTapLeaf := test.ScriptHashLock(t.t, []byte("hash locks are cool"))

	// The actual internal key of the BTC level Taproot output will be the
	// provably un-spendable NUMS key.
	siblingPreimage, err := commitment.NewPreimageFromLeaf(btcTapLeaf)
	require.NoError(t.t, err)
	siblingPreimageBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(
		siblingPreimage,
	)
	require.NoError(t.t, err)

	// We now have everything we need to create the TAP address to receive
	// the multisig secured assets. The recipient of the assets is going to
	// be the Bob node, but the custody will be shared between Alice and Bob
	// on both levels.
	const assetsToSend = 1000
	bobAddr, err := bobTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:          targetAssetGenesis.AssetId,
		Amt:              assetsToSend,
		TapscriptSibling: siblingPreimageBytes,
	})
	require.NoError(t.t, err)

	// Now we can create our virtual transaction and ask Alice's tapd to
	// fund it.
	recipients := map[string]uint64{
		bobAddr.Encoded: bobAddr.Amount,
	}
	fundResp, err := aliceTapd.FundVirtualPsbt(
		ctxt, &wrpc.FundVirtualPsbtRequest{
			Template: &wrpc.FundVirtualPsbtRequest_Raw{
				Raw: &wrpc.TxTemplate{
					Recipients: recipients,
				},
			},
		},
	)
	require.NoError(t.t, err)

	// We expect a passive asset to be returned.
	require.Equal(t.t, 1, len(fundResp.PassiveAssetPsbts))

	// With the virtual transaction funded, we can simply sign it and the
	// passive assets.
	activeAsset, err := tappsbt.Decode(fundResp.FundedPsbt)
	require.NoError(t.t, err)

	activeAssets := []*tappsbt.VPacket{
		signVirtualPacket(t.t, aliceTapd, activeAsset),
	}

	passiveAssets := make(
		[]*tappsbt.VPacket, len(fundResp.PassiveAssetPsbts),
	)
	for idx := range fundResp.PassiveAssetPsbts {
		passiveAsset, err := tappsbt.Decode(
			fundResp.PassiveAssetPsbts[idx],
		)
		require.NoError(t.t, err)

		passiveAssets[idx] = signVirtualPacket(
			t.t, aliceTapd, passiveAsset,
		)
	}

	allPackets := append([]*tappsbt.VPacket{}, activeAssets...)
	allPackets = append(allPackets, passiveAssets...)
	btcPacket, err := tapsend.PrepareAnchoringTemplate(allPackets)
	require.NoError(t.t, err)

	var commitResp *wrpc.CommitVirtualPsbtsResponse
	btcPacket, activeAssets, passiveAssets, commitResp = commitVirtualPsbts(
		t.t, aliceTapd, btcPacket, activeAssets, passiveAssets, -1,
	)

	t.Logf("Committed transaction: %v", toJSON(t.t, commitResp))

	btcPacket = signPacket(t.t, aliceLnd, btcPacket)
	btcPacket = finalizePacket(t.t, aliceLnd, btcPacket)
	sendResp := logAndPublish(
		t.t, aliceTapd, btcPacket, activeAssets, passiveAssets,
		commitResp,
	)

	expectedAmounts := []uint64{
		targetAsset.Amount - assetsToSend, assetsToSend,
	}
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner.Client, aliceTapd,
		sendResp, targetAssetGenesis.AssetId, expectedAmounts,
		0, 1, len(expectedAmounts),
	)

	// And now the event should be completed on both sides.
	AssertAddrEvent(t.t, bobTapd, bobAddr, 1, statusCompleted)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)
	AssertBalanceByID(
		t.t, bobTapd, targetAssetGenesis.AssetId, assetsToSend,
	)
}

func signVirtualPacket(t *testing.T, tapd *tapdHarness,
	packet *tappsbt.VPacket) *tappsbt.VPacket {

	ctx := context.Background()
	ctxt, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	rawPacket, err := tappsbt.Encode(packet)
	require.NoError(t, err)

	signResp, err := tapd.SignVirtualPsbt(
		ctxt, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: rawPacket,
		},
	)
	require.NoError(t, err)

	require.NotEmpty(t, signResp.SignedInputs)

	parsedPacket, err := tappsbt.Decode(signResp.SignedPsbt)
	require.NoError(t, err)

	return parsedPacket
}

func deriveKeys(t *testing.T, tapd *tapdHarness) (asset.ScriptKey,
	keychain.KeyDescriptor) {

	ctx := context.Background()
	ctxt, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	scriptKeyDesc, err := tapd.NextScriptKey(
		ctxt, &wrpc.NextScriptKeyRequest{
			KeyFamily: uint32(asset.TaprootAssetsKeyFamily),
		},
	)
	require.NoError(t, err)
	scriptKey, err := tap.UnmarshalScriptKey(scriptKeyDesc.ScriptKey)
	require.NoError(t, err)

	internalKeyDesc, err := tapd.NextInternalKey(
		ctxt, &wrpc.NextInternalKeyRequest{
			KeyFamily: uint32(asset.TaprootAssetsKeyFamily),
		},
	)
	require.NoError(t, err)
	internalKeyLnd, err := tap.UnmarshalKeyDescriptor(
		internalKeyDesc.InternalKey,
	)
	require.NoError(t, err)

	return *scriptKey, internalKeyLnd
}

func sendToTapscriptAddr(ctx context.Context, t *harnessTest, alice,
	bob *tapdHarness, numUnits uint64, genInfo *taprpc.GenesisInfo,
	mintedAsset *taprpc.Asset, bobScriptKey asset.ScriptKey,
	bobInternalKey keychain.KeyDescriptor, tapscript *waddrmgr.Tapscript,
	rootHash []byte) {

	bobAssetScriptKey, err := tapscript.TaprootKey()
	require.NoError(t.t, err)

	t.Logf("Bob destination key %x (internal %x, root %x)",
		bobAssetScriptKey.SerializeCompressed(),
		bobScriptKey.PubKey.SerializeCompressed(), rootHash)

	// Next, we'll attempt to complete a transfer with PSBTs from our main
	// node to Bob.
	bobAddr, err := bob.NewAddr(ctx, &taprpc.NewAddrRequest{
		AssetId:      genInfo.AssetId,
		Amt:          numUnits,
		AssetVersion: mintedAsset.Version,
		ScriptKey: &taprpc.ScriptKey{
			PubKey:   schnorr.SerializePubKey(bobAssetScriptKey),
			KeyDesc:  lndKeyDescToTap(bobScriptKey.RawKey),
			TapTweak: rootHash,
		},
		InternalKey: lndKeyDescToTap(bobInternalKey),
	})

	require.NoError(t.t, err)
	AssertAddrCreated(t.t, bob, mintedAsset, bobAddr)

	// Send the asset to Bob using the script key with an actual script
	// tree.
	sendResp := sendAssetsToAddr(t, alice, bobAddr)

	changeUnits := mintedAsset.Amount - numUnits
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, alice, sendResp,
		genInfo.AssetId, []uint64{changeUnits, numUnits}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, bob, 1)
}

func sendAssetAndAssert(ctx context.Context, t *harnessTest, alice,
	bob *tapdHarness, numUnits, change uint64,
	genInfo *taprpc.GenesisInfo, mintedAsset *taprpc.Asset,
	outTransferIdx, numOutTransfers, numInTransfers int) {

	// And finally, we make sure that we can send out one of the asset UTXOs
	// that shared the anchor output and the other one is treated as a
	// passive asset.
	bobAddr, err := bob.NewAddr(ctx, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     numUnits,
	})
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, bob, mintedAsset, bobAddr)
	sendResp := sendAssetsToAddr(t, alice, bobAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, alice, sendResp,
		genInfo.AssetId, []uint64{change, numUnits}, outTransferIdx,
		numOutTransfers,
	)

	// There are now two receive events (since only non-interactive sends
	// appear in that RPC output).
	AssertNonInteractiveRecvComplete(t.t, bob, numInTransfers)
}

func commitVirtualPsbts(t *testing.T, funder *tapdHarness, packet *psbt.Packet,
	activePackets []*tappsbt.VPacket, passivePackets []*tappsbt.VPacket,
	changeOutputIndex int32) (*psbt.Packet, []*tappsbt.VPacket,
	[]*tappsbt.VPacket, *wrpc.CommitVirtualPsbtsResponse) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	t.Logf("Funding packet: %v\n", spew.Sdump(packet))

	var buf bytes.Buffer
	err := packet.Serialize(&buf)
	require.NoError(t, err)

	request := &wrpc.CommitVirtualPsbtsRequest{
		AnchorPsbt: buf.Bytes(),
		Fees: &wrpc.CommitVirtualPsbtsRequest_SatPerVbyte{
			SatPerVbyte: uint64(feeRateSatPerKVByte / 1000),
		},
	}

	type existingIndex = wrpc.CommitVirtualPsbtsRequest_ExistingOutputIndex
	if changeOutputIndex < 0 {
		request.AnchorChangeOutput = &wrpc.CommitVirtualPsbtsRequest_Add{
			Add: true,
		}
	} else {
		request.AnchorChangeOutput = &existingIndex{
			ExistingOutputIndex: changeOutputIndex,
		}
	}

	request.VirtualPsbts = make([][]byte, len(activePackets))
	for idx := range activePackets {
		request.VirtualPsbts[idx], err = tappsbt.Encode(
			activePackets[idx],
		)
		require.NoError(t, err)
	}
	request.PassiveAssetPsbts = make([][]byte, len(passivePackets))
	for idx := range passivePackets {
		request.PassiveAssetPsbts[idx], err = tappsbt.Encode(
			passivePackets[idx],
		)
		require.NoError(t, err)
	}

	// Now we can map the virtual packets to the PSBT.
	commitResponse, err := funder.CommitVirtualPsbts(ctxt, request)
	require.NoError(t, err)

	fundedPacket, err := psbt.NewFromRawBytes(
		bytes.NewReader(commitResponse.AnchorPsbt), false,
	)
	require.NoError(t, err)

	activePackets = make(
		[]*tappsbt.VPacket, len(commitResponse.VirtualPsbts),
	)
	for idx := range commitResponse.VirtualPsbts {
		activePackets[idx], err = tappsbt.Decode(
			commitResponse.VirtualPsbts[idx],
		)
		require.NoError(t, err)
	}

	passivePackets = make(
		[]*tappsbt.VPacket, len(commitResponse.PassiveAssetPsbts),
	)
	for idx := range commitResponse.PassiveAssetPsbts {
		passivePackets[idx], err = tappsbt.Decode(
			commitResponse.PassiveAssetPsbts[idx],
		)
		require.NoError(t, err)
	}

	return fundedPacket, activePackets, passivePackets, commitResponse
}

func signPacket(t *testing.T, lnd *node.HarnessNode,
	pkt *psbt.Packet) *psbt.Packet {

	var buf bytes.Buffer
	err := pkt.Serialize(&buf)
	require.NoError(t, err)

	signResp := lnd.RPC.SignPsbt(&walletrpc.SignPsbtRequest{
		FundedPsbt: buf.Bytes(),
	})

	signedPacket, err := psbt.NewFromRawBytes(
		bytes.NewReader(signResp.SignedPsbt), false,
	)
	require.NoError(t, err)

	return signedPacket
}

func finalizePacket(t *testing.T, lnd *node.HarnessNode,
	pkt *psbt.Packet) *psbt.Packet {

	var buf bytes.Buffer
	err := pkt.Serialize(&buf)
	require.NoError(t, err)

	finalizeResp := lnd.RPC.FinalizePsbt(&walletrpc.FinalizePsbtRequest{
		FundedPsbt: buf.Bytes(),
	})

	signedPacket, err := psbt.NewFromRawBytes(
		bytes.NewReader(finalizeResp.SignedPsbt), false,
	)
	require.NoError(t, err)

	return signedPacket
}

func logAndPublish(t *testing.T, tapd *tapdHarness, btcPkt *psbt.Packet,
	activeAssets []*tappsbt.VPacket, passiveAssets []*tappsbt.VPacket,
	commitResp *wrpc.CommitVirtualPsbtsResponse) *taprpc.SendAssetResponse {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	var buf bytes.Buffer
	err := btcPkt.Serialize(&buf)
	require.NoError(t, err)

	request := &wrpc.PublishAndLogRequest{
		AnchorPsbt:        buf.Bytes(),
		VirtualPsbts:      make([][]byte, len(activeAssets)),
		PassiveAssetPsbts: make([][]byte, len(passiveAssets)),
		ChangeOutputIndex: commitResp.ChangeOutputIndex,
		LndLockedUtxos:    commitResp.LndLockedUtxos,
	}

	for idx := range activeAssets {
		request.VirtualPsbts[idx], err = tappsbt.Encode(
			activeAssets[idx],
		)
		require.NoError(t, err)
	}
	for idx := range passiveAssets {
		request.PassiveAssetPsbts[idx], err = tappsbt.Encode(
			passiveAssets[idx],
		)
		require.NoError(t, err)
	}

	resp, err := tapd.PublishAndLogTransfer(ctxt, request)
	require.NoError(t, err)

	return resp
}
