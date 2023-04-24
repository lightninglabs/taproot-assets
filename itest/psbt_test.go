package itest

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/lightninglabs/taro"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightninglabs/taro/tarorpc"
	wrpc "github.com/lightninglabs/taro/tarorpc/assetwalletrpc"
	"github.com/lightninglabs/taro/tarorpc/mintrpc"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// testPsbtScriptHashLockSend tests that we can properly send assets with a hash
// lock back and forth between nodes with the use of PSBTs.
func testPsbtScriptHashLockSend(t *harnessTest) {
	// First, we'll make a normal asset with enough units to allow us to
	// send it around a few times.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
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

	var (
		alice = t.tarod
		bob   = secondTarod
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

	controlBlockBytes, err := tapscript.ControlBlock.ToBytes()
	require.NoError(t.t, err)

	bobAssetScriptKey, err := tapscript.TaprootKey()
	require.NoError(t.t, err)

	t.Logf("Bob destination key %x (internal %x, root %x)",
		bobAssetScriptKey.SerializeCompressed(),
		bobScriptKey.PubKey.SerializeCompressed(), rootHash[:])

	// Next, we'll attempt to complete a transfer with PSBTs from our main
	// node to Bob.
	const numUnits = 10
	bobAddr, err := bob.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     numUnits,
		ScriptKey: &tarorpc.ScriptKey{
			PubKey:   schnorr.SerializePubKey(bobAssetScriptKey),
			KeyDesc:  lndKeyDescToTaro(bobScriptKey.RawKey),
			TapTweak: rootHash[:],
		},
		InternalKey: lndKeyDescToTaro(bobInternalKey),
	})
	require.NoError(t.t, err)
	assertAddrCreated(t.t, bob, rpcAssets[0], bobAddr)

	// Send the asset to Bob using the script key with an actual script
	// tree.
	sendResp := sendAssetsToAddr(t, alice, bobAddr)

	changeUnits := rpcAssets[0].Amount - numUnits
	confirmAndAssertOutboundTransfer(
		t, alice, sendResp, genInfo.AssetId,
		[]uint64{changeUnits, numUnits}, 0, 1,
	)
	_ = sendProof(t, alice, bob, bobAddr.ScriptKey, genInfo)
	assertNonInteractiveRecvComplete(t, bob, 1)

	// Now try to send back those assets using the PSBT flow.
	aliceAddr, err := alice.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     numUnits / 2,
	})
	require.NoError(t.t, err)
	assertAddrCreated(t.t, alice, rpcAssets[0], aliceAddr)

	fundResp := fundAddressSendPacket(t, bob, aliceAddr)
	t.Logf("Funded PSBT: %v",
		base64.StdEncoding.EncodeToString(fundResp.FundedPsbt))

	fundedPacket, err := taropsbt.NewFromRawBytes(
		bytes.NewReader(fundResp.FundedPsbt), false,
	)
	require.NoError(t.t, err)

	// We don't need to sign anything as we're going to spend with a
	// pre-image to the script lock.
	senderOut := fundedPacket.Outputs[0].Asset
	senderOut.PrevWitnesses[0].TxWitness = [][]byte{
		preImage, leaf1.Script, controlBlockBytes,
	}

	for idx := range fundedPacket.Outputs {
		out := fundedPacket.Outputs[idx]
		splitAsset := out.Asset

		if out.IsSplitRoot {
			splitAsset = out.SplitAsset
		}

		splitCommitment := splitAsset.PrevWitnesses[0].SplitCommitment
		splitCommitment.RootAsset = *senderOut.Copy()
	}

	var b bytes.Buffer
	err = fundedPacket.Serialize(&b)
	require.NoError(t.t, err)

	// Now we'll attempt to complete the transfer.
	sendResp, err = bob.AnchorVirtualPsbts(
		ctxb, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{b.Bytes()},
		},
	)
	require.NoError(t.t, err)

	confirmAndAssertOutboundTransfer(
		t, bob, sendResp, genInfo.AssetId,
		[]uint64{numUnits / 2, numUnits / 2}, 0, 1,
	)
	_ = sendProof(t, bob, alice, aliceAddr.ScriptKey, genInfo)
	assertNonInteractiveRecvComplete(t, alice, 1)

	aliceAssets, err := alice.ListAssets(ctxb, &tarorpc.ListAssetRequest{
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
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
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

	var (
		alice = t.tarod
		bob   = secondTarod
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

	controlBlockBytes, err := tapscript.ControlBlock.ToBytes()
	require.NoError(t.t, err)

	bobAssetScriptKey, err := tapscript.TaprootKey()
	require.NoError(t.t, err)

	t.Logf("Bob destination key %x (internal %x, root %x)",
		bobAssetScriptKey.SerializeCompressed(),
		bobScriptKey.PubKey.SerializeCompressed(), rootHash[:])

	// Next, we'll attempt to complete a transfer with PSBTs from our main
	// node to Bob.
	const numUnits = 10
	bobAddr, err := bob.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     numUnits,
		ScriptKey: &tarorpc.ScriptKey{
			PubKey:   schnorr.SerializePubKey(bobAssetScriptKey),
			KeyDesc:  lndKeyDescToTaro(bobScriptKey.RawKey),
			TapTweak: rootHash[:],
		},
		InternalKey: lndKeyDescToTaro(bobInternalKey),
	})
	require.NoError(t.t, err)
	assertAddrCreated(t.t, bob, rpcAssets[0], bobAddr)

	// Send the asset to Bob using the script key with an actual script
	// tree.
	sendResp := sendAssetsToAddr(t, alice, bobAddr)

	changeUnits := rpcAssets[0].Amount - numUnits
	confirmAndAssertOutboundTransfer(
		t, alice, sendResp, genInfo.AssetId,
		[]uint64{changeUnits, numUnits}, 0, 1,
	)
	_ = sendProof(t, alice, bob, bobAddr.ScriptKey, genInfo)
	assertNonInteractiveRecvComplete(t, bob, 1)

	// Now try to send back those assets using the PSBT flow.
	aliceAddr, err := alice.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     numUnits / 2,
	})
	require.NoError(t.t, err)
	assertAddrCreated(t.t, alice, rpcAssets[0], aliceAddr)

	fundResp := fundAddressSendPacket(t, bob, aliceAddr)
	t.Logf("Funded PSBT: %v",
		base64.StdEncoding.EncodeToString(fundResp.FundedPsbt))

	fundedPacket, err := taropsbt.NewFromRawBytes(
		bytes.NewReader(fundResp.FundedPsbt), false,
	)
	require.NoError(t.t, err)

	// We can now ask the wallet to sign the script path, since we only need
	// a signature.
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
	sendResp, err = bob.AnchorVirtualPsbts(
		ctxb, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signedResp.SignedPsbt},
		},
	)
	require.NoError(t.t, err)

	confirmAndAssertOutboundTransfer(
		t, bob, sendResp, genInfo.AssetId,
		[]uint64{numUnits / 2, numUnits / 2}, 0, 1,
	)
	_ = sendProof(t, bob, alice, aliceAddr.ScriptKey, genInfo)
	assertNonInteractiveRecvComplete(t, alice, 1)

	aliceAssets, err := alice.ListAssets(ctxb, &tarorpc.ListAssetRequest{
		WithWitness: true,
	})
	require.NoError(t.t, err)

	assetsJSON, err := formatProtoJSON(aliceAssets)
	require.NoError(t.t, err)
	t.Logf("Got alice assets: %s", assetsJSON)
}

// testPsbtInteractiveFullValueSend tests that we can properly send assets back
// and forth, using the full amount, between nodes with the use of PSBTs.
func testPsbtInteractiveFullValueSend(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send backand forth. We're also minting a passive asset that
	// should remain where it is.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*mintrpc.MintAssetRequest{
			simpleAssets[0],
			// Our "passive" asset.
			{
				Asset: &mintrpc.MintAsset{
					AssetType: tarorpc.AssetType_NORMAL,
					Name:      "itestbuxx-passive",
					AssetMeta: &tarorpc.AssetMeta{
						Data: []byte("some metadata"),
					},
					Amount: 123,
				},
			},
		},
	)

	genInfo := rpcAssets[0].AssetGenesis
	chainParams := &address.RegressionNetTaro

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
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

	var (
		sender   = t.tarod
		receiver = secondTarod
		id       [32]byte
		fullAmt  = rpcAssets[0].Amount
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

		vPkt := taropsbt.ForInteractiveSend(
			id, fullAmt, receiverScriptKey, 0,
			receiverAnchorIntKeyDesc, chainParams,
		)

		// Next, we'll attempt to complete a transfer with PSBTs from
		// our sender node to our receiver, using the full amount.
		fundResp := fundPacket(t, sender, vPkt)
		signResp, err := sender.SignVirtualPsbt(
			ctxb, &wrpc.SignVirtualPsbtRequest{
				FundedPsbt: fundResp.FundedPsbt,
			},
		)
		require.NoError(t.t, err)

		// Now we'll attempt to complete the transfer.
		sendResp, err := sender.AnchorVirtualPsbts(
			ctxb, &wrpc.AnchorVirtualPsbtsRequest{
				VirtualPsbts: [][]byte{signResp.SignedPsbt},
			},
		)
		require.NoError(t.t, err)

		numOutputs := 1
		amounts := []uint64{fullAmt}
		if i == 0 {
			// Account for the passive asset in the first transfer.
			numOutputs = 2
			amounts = []uint64{fullAmt, 0}
		}
		confirmAndAssetOutboundTransferWithOutputs(
			t, sender, sendResp, genInfo.AssetId, amounts,
			i/2, (i/2)+1, numOutputs,
		)
		_ = sendProof(
			t, sender, receiver,
			receiverScriptKey.PubKey.SerializeCompressed(), genInfo,
		)

		senderAssets, err := sender.ListAssets(
			ctxb, &tarorpc.ListAssetRequest{},
		)
		require.NoError(t.t, err)

		// Depending on what direction we currently have, the number of
		// expected assets is different, since the initial sender always
		// has the passive asset left.
		numSenderAssets := 1
		numReceiverAssets := 1
		if sender == secondTarod {
			numSenderAssets = 0
			numReceiverAssets = 2
		}
		require.Len(t.t, senderAssets.Assets, numSenderAssets)

		receiverAssets, err := receiver.ListAssets(
			ctxb, &tarorpc.ListAssetRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, receiverAssets.Assets, numReceiverAssets)
		assertAssetState(
			t, receiver, genInfo.Name, genInfo.MetaHash,
			assetAmountCheck(fullAmt),
		)
	}

	// Finally, make sure we can still send out the passive asset.
	passiveGen := rpcAssets[1].AssetGenesis
	bobAddr, err := secondTarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			AssetId: passiveGen.AssetId,
			Amt:     rpcAssets[1].Amount,
		},
	)
	require.NoError(t.t, err)

	assertAddrCreated(t.t, secondTarod, rpcAssets[1], bobAddr)
	sendResp := sendAssetsToAddr(t, t.tarod, bobAddr)
	confirmAndAssertOutboundTransfer(
		t, t.tarod, sendResp, passiveGen.AssetId,
		[]uint64{0, rpcAssets[1].Amount}, 2, 3,
	)
	_ = sendProof(
		t, t.tarod, secondTarod, bobAddr.ScriptKey, passiveGen,
	)

	// There's only one non-interactive receive event.
	assertNonInteractiveRecvComplete(t, secondTarod, 1)
}

// testPsbtInteractiveSplitSend tests that we can properly send assets back
// and forth, using the full amount, between nodes with the use of PSBTs.
func testPsbtInteractiveSplitSend(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send backand forth. We're also minting a passive asset that
	// should remain where it is.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*mintrpc.MintAssetRequest{
			simpleAssets[0],
			// Our "passive" asset.
			{
				Asset: &mintrpc.MintAsset{
					AssetType: tarorpc.AssetType_NORMAL,
					Name:      "itestbuxx-passive",
					AssetMeta: &tarorpc.AssetMeta{
						Data: []byte("some metadata"),
					},
					Amount: 123,
				},
			},
		},
	)

	genInfo := rpcAssets[0].AssetGenesis
	chainParams := &address.RegressionNetTaro

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
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

	var (
		sender      = t.tarod
		receiver    = secondTarod
		senderSum   = simpleAssets[0].Asset.Amount
		receiverSum = uint64(0)
		id          [32]byte
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
			sendAmt = sendAmt / 2
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

		vPkt := taropsbt.ForInteractiveSend(
			id, sendAmt, receiverScriptKey, 0,
			receiverAnchorIntKeyDesc, chainParams,
		)

		// Next, we'll attempt to complete a transfer with PSBTs from
		// our sender node to our receiver, using the partial amount.
		fundResp := fundPacket(t, sender, vPkt)
		signResp, err := sender.SignVirtualPsbt(
			ctxb, &wrpc.SignVirtualPsbtRequest{
				FundedPsbt: fundResp.FundedPsbt,
			},
		)
		require.NoError(t.t, err)

		// Now we'll attempt to complete the transfer.
		sendResp, err := sender.AnchorVirtualPsbts(
			ctxb, &wrpc.AnchorVirtualPsbtsRequest{
				VirtualPsbts: [][]byte{signResp.SignedPsbt},
			},
		)
		require.NoError(t.t, err)

		numOutputs := 2
		confirmAndAssetOutboundTransferWithOutputs(
			t, sender, sendResp, genInfo.AssetId,
			[]uint64{sendAmt, changeAmt}, i/2, (i/2)+1,
			numOutputs,
		)
		_ = sendProof(
			t, sender, receiver,
			receiverScriptKey.PubKey.SerializeCompressed(), genInfo,
		)

		senderAssets, err := sender.ListAssets(
			ctxb, &tarorpc.ListAssetRequest{},
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
			ctxb, &tarorpc.ListAssetRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, receiverAssets.Assets, numReceiverAssets)
	}

	// Finally, make sure we can still send out the passive asset.
	passiveGen := rpcAssets[1].AssetGenesis
	bobAddr, err := secondTarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			AssetId: passiveGen.AssetId,
			Amt:     rpcAssets[1].Amount,
		},
	)
	require.NoError(t.t, err)

	assertAddrCreated(t.t, secondTarod, rpcAssets[1], bobAddr)
	sendResp := sendAssetsToAddr(t, t.tarod, bobAddr)
	confirmAndAssertOutboundTransfer(
		t, t.tarod, sendResp, passiveGen.AssetId,
		[]uint64{0, rpcAssets[1].Amount}, 2, 3,
	)
	_ = sendProof(
		t, t.tarod, secondTarod, bobAddr.ScriptKey, passiveGen,
	)

	// There's only one non-interactive receive event.
	assertNonInteractiveRecvComplete(t, secondTarod, 1)
}

// testPsbtInteractiveTapscriptSibling tests that we can send assets to an
// anchor output that also commits to a tapscript sibling.
func testPsbtInteractiveTapscriptSibling(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send backand forth.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis
	chainParams := &address.RegressionNetTaro

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(p *tarodHarnessParams) {
			p.startupSyncNode = t.tarod
			p.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	var (
		alice = t.tarod
		bob   = secondTarod
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
	vPkt := taropsbt.ForInteractiveSend(
		id, sendAmt, receiverScriptKey, 0, receiverAnchorIntKeyDesc,
		chainParams,
	)

	// We now create a Tapscript sibling with a simple hash lock script.
	preImage := []byte("hash locks are cool")
	siblingLeaf := test.ScriptHashLock(t.t, preImage)

	preimage := commitment.NewPreimageFromLeaf(siblingLeaf)
	vPkt.Outputs[0].AnchorOutputTapscriptPreimage = preimage

	// Next, we'll attempt to complete a transfer with PSBTs from alice to
	// bob, using the partial amount.
	fundResp := fundPacket(t, alice, vPkt)
	signResp, err := alice.SignVirtualPsbt(
		ctxb, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundResp.FundedPsbt,
		},
	)
	require.NoError(t.t, err)

	// Now we'll attempt to complete the transfer.
	sendResp, err := alice.AnchorVirtualPsbts(
		ctxb, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signResp.SignedPsbt},
		},
	)
	require.NoError(t.t, err)

	confirmAndAssetOutboundTransferWithOutputs(
		t, alice, sendResp, genInfo.AssetId,
		[]uint64{sendAmt, changeAmt}, 0, 1, 2,
	)
	_ = sendProof(
		t, alice, bob,
		receiverScriptKey.PubKey.SerializeCompressed(), genInfo,
	)

	senderAssets, err := alice.ListAssets(
		ctxb, &tarorpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, senderAssets.Assets, 1)

	receiverAssets, err := bob.ListAssets(
		ctxb, &tarorpc.ListAssetRequest{},
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
	aliceAddr, err := alice.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     sendAmt / 2,
	})
	require.NoError(t.t, err)

	assertAddrCreated(t.t, alice, rpcAssets[0], aliceAddr)
	sendResp = sendAssetsToAddr(t, bob, aliceAddr)
	confirmAndAssertOutboundTransfer(
		t, bob, sendResp, genInfo.AssetId,
		[]uint64{sendAmt / 2, sendAmt / 2}, 0, 1,
	)
	_ = sendProof(t, bob, alice, aliceAddr.ScriptKey, genInfo)

	// There's only one receive event (since only non-interactive sends
	// appear in that RPC output).
	assertNonInteractiveRecvComplete(t, alice, 1)
}

// testPsbtMultiSend tests that we can properly send assets to multiple
// addresses at the same time.
func testPsbtMultiSend(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send backand forth. We're also minting a passive asset that
	// should remain where it is.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tarod, []*mintrpc.MintAssetRequest{
			simpleAssets[0],
			// Our "passive" asset.
			{
				Asset: &mintrpc.MintAsset{
					AssetType: tarorpc.AssetType_NORMAL,
					Name:      "itestbuxx-passive",
					AssetMeta: &tarorpc.AssetMeta{
						Data: []byte("some metadata"),
					},
					Amount: 123,
				},
			},
		},
	)

	genInfo := rpcAssets[0].AssetGenesis
	chainParams := &address.RegressionNetTaro

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
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

	var (
		sender   = t.tarod
		receiver = secondTarod
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
	vPkt := taropsbt.ForInteractiveSend(
		id, outputAmounts[0], receiverScriptKey1, 0,
		receiverAnchorIntKeyDesc1, chainParams,
	)

	// And now we'll create an output at anchor index 1 for the second
	// address and two at anchor index 2 for our internal split. This should
	// still leave 300 units as change which we expect to end up at anchor
	// index 3.
	taropsbt.AddOutput(
		vPkt, outputAmounts[1], receiverScriptKey2, 1,
		receiverAnchorIntKeyDesc2,
	)
	taropsbt.AddOutput(
		vPkt, outputAmounts[2], senderScriptKey1, 2,
		senderAnchorIntKeyDesc1,
	)
	taropsbt.AddOutput(
		vPkt, outputAmounts[3], senderScriptKey2, 2,
		senderAnchorIntKeyDesc1,
	)

	// Next, we'll attempt to complete a transfer with PSBTs from
	// our sender node to our receiver, using the partial amount.
	fundResp := fundPacket(t, sender, vPkt)
	signResp, err := sender.SignVirtualPsbt(
		ctxb, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundResp.FundedPsbt,
		},
	)
	require.NoError(t.t, err)

	// Now we'll attempt to complete the transfer.
	sendResp, err := sender.AnchorVirtualPsbts(
		ctxb, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signResp.SignedPsbt},
		},
	)
	require.NoError(t.t, err)

	// We end up with a transfer with 5 outputs: 2 for the two different
	// receiver addresses (with an anchor output each), 2 for the sender
	// addresses (sharing an anchor output) and 1 for the change. So there
	// are 4 BTC anchor outputs but 5 asset transfer outputs.
	numOutputs := 5
	confirmAndAssetOutboundTransferWithOutputs(
		t, sender, sendResp, genInfo.AssetId, outputAmounts, 0, 1,
		numOutputs,
	)
	_ = sendProof(
		t, sender, receiver,
		receiverScriptKey1.PubKey.SerializeCompressed(), genInfo,
	)
	_ = sendProof(
		t, sender, receiver,
		receiverScriptKey2.PubKey.SerializeCompressed(), genInfo,
	)

	senderAssets, err := sender.ListAssets(
		ctxb, &tarorpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, senderAssets.Assets, 4)

	receiverAssets, err := receiver.ListAssets(
		ctxb, &tarorpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, receiverAssets.Assets, 2)

	// Next, we make sure we can still send out the passive asset.
	passiveGen := rpcAssets[1].AssetGenesis
	bobAddr, err := secondTarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			AssetId: passiveGen.AssetId,
			Amt:     rpcAssets[1].Amount,
		},
	)
	require.NoError(t.t, err)

	assertAddrCreated(t.t, secondTarod, rpcAssets[1], bobAddr)
	sendResp = sendAssetsToAddr(t, t.tarod, bobAddr)
	confirmAndAssertOutboundTransfer(
		t, t.tarod, sendResp, passiveGen.AssetId,
		[]uint64{0, rpcAssets[1].Amount}, 1, 2,
	)
	_ = sendProof(
		t, t.tarod, secondTarod, bobAddr.ScriptKey, passiveGen,
	)

	// There's only one receive event (since only non-interactive sends
	// appear in that RPC output).
	assertNonInteractiveRecvComplete(t, secondTarod, 1)

	// And finally, we make sure that we can send out one of the asset UTXOs
	// that shared the anchor output and the other one is treated as a
	// passive asset.
	bobAddr, err = secondTarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     outputAmounts[2],
		},
	)
	require.NoError(t.t, err)

	assertAddrCreated(t.t, secondTarod, rpcAssets[0], bobAddr)
	sendResp = sendAssetsToAddr(t, t.tarod, bobAddr)
	confirmAndAssertOutboundTransfer(
		t, t.tarod, sendResp, genInfo.AssetId,
		[]uint64{0, outputAmounts[2]}, 2, 3,
	)
	_ = sendProof(
		t, t.tarod, secondTarod, bobAddr.ScriptKey, genInfo,
	)

	// There are now two receive events (since only non-interactive sends
	// appear in that RPC output).
	assertNonInteractiveRecvComplete(t, secondTarod, 2)
}

func deriveKeys(t *testing.T, tarod *tarodHarness) (asset.ScriptKey,
	keychain.KeyDescriptor) {

	ctx := context.Background()
	ctxt, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	scriptKeyDesc, err := tarod.NextScriptKey(
		ctxt, &wrpc.NextScriptKeyRequest{
			KeyFamily: uint32(asset.TaroKeyFamily),
		},
	)
	require.NoError(t, err)
	scriptKey, err := taro.UnmarshalScriptKey(scriptKeyDesc.ScriptKey)
	require.NoError(t, err)

	internalKeyDesc, err := tarod.NextInternalKey(
		ctxt, &wrpc.NextInternalKeyRequest{
			KeyFamily: uint32(asset.TaroKeyFamily),
		},
	)
	require.NoError(t, err)
	internalKeyLnd, err := taro.UnmarshalKeyDescriptor(
		internalKeyDesc.InternalKey,
	)
	require.NoError(t, err)

	return *scriptKey, internalKeyLnd
}
