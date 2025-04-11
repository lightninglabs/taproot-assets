package itest

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/stretchr/testify/require"
)

// testPsbtScriptHashLockSend tests that we can properly send assets with a hash
// lock back and forth between nodes with the use of PSBTs.
func testPsbtScriptHashLockSend(t *harnessTest) {
	// First, we'll make a normal asset with enough units to allow us to
	// send it around a few times.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	mintedAsset := rpcAssets[0]
	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
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
	bobScriptKey, bobInternalKey := DeriveKeys(t.t, bob)

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
		t.t, t.lndHarness.Miner().Client, bob, sendResp,
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
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)

	mintedAsset := rpcAssets[0]
	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
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
	bobScriptKey, bobInternalKey := DeriveKeys(t.t, bob)

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
		t.t, t.lndHarness.Miner().Client, bob, sendResp,
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
		t.t, t.lndHarness.Miner().Client, t.tapd,
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
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	runPsbtInteractiveFullValueSendTest(
		ctxt, t, t.tapd, secondTapd, genInfo, mintedAsset,
		rpcAssets[1],
	)
}

// testPsbtMultiVersionSend tests that funding a V1 vPkt succeeds, but funding
// a V0 vPkt fails.
func testPsbtMultiVersionSend(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// First, we'll mint two assets.
	firstRpcAsset := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			simpleAssets[0],
		},
	)

	secondRpcAsset := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			simpleAssets[1],
		},
	)

	firstAsset := firstRpcAsset[0]
	secondAsset := secondRpcAsset[0]

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	sender := t.tapd
	receiver := secondTapd
	chainParams := &address.RegressionNetTap

	// Derive script and internal keys for the receiver.
	receiverScriptKey1, receiverAnchorIntKeyDesc1 := DeriveKeys(
		t.t, receiver,
	)

	receiverScriptKey2, receiverAnchorIntKeyDesc2 := DeriveKeys(
		t.t, receiver,
	)

	// Construct a vPkt to receive each asset; the second vPkt will be V0.
	vPkt1 := tappsbt.ForInteractiveSend(
		fn.ToArray[[32]byte](firstAsset.AssetGenesis.AssetId),
		firstAsset.Amount, receiverScriptKey1, 0, 0, 0,
		receiverAnchorIntKeyDesc1, asset.V0, chainParams,
	)
	vPkt1.Version = tappsbt.V1

	vPkt2 := tappsbt.ForInteractiveSend(
		fn.ToArray[[32]byte](secondAsset.AssetGenesis.AssetId),
		secondAsset.Amount, receiverScriptKey2, 0, 0, 0,
		receiverAnchorIntKeyDesc2, asset.V0, chainParams,
	)
	vPkt2.Version = tappsbt.V0

	// Funding for the V1 packet should succeed.
	fundPkt1Resp := fundPacket(t, sender, vPkt1)
	_, err := tappsbt.Decode(fundPkt1Resp.FundedPsbt)
	require.NoError(t.t, err)

	// Funding for the V0 packet should fail, as it was minted into an
	// incompatible commitment version.
	_, err = maybeFundPacket(t, sender, vPkt2)
	require.ErrorContains(
		t.t, err, tapfreighter.ErrMatchingAssetsNotFound.Error(),
	)

	// Let's mint two assets anchored in downgraded commitments, to ensure
	// that we can receive such assets.
	firstManualAssetName := "honigbuxxx"
	firstReq := mintrpc.MintAsset{
		AssetVersion: 0,
		AssetType:    taprpc.AssetType_NORMAL,
		Name:         firstManualAssetName,
		AssetMeta: &taprpc.AssetMeta{
			Data: []byte("not metadata"),
		},
		Amount: 22,
	}
	secondManualAssetName := "honigbuxxx-collective"
	secondReq := mintrpc.MintAsset{
		AssetVersion: taprpc.AssetVersion_ASSET_VERSION_V1,
		AssetType:    taprpc.AssetType_COLLECTIBLE,
		Name:         secondManualAssetName,
		AssetMeta: &taprpc.AssetMeta{
			Data: []byte("not metadata"),
		},
		Amount: 1,
	}

	numAssets := 1
	AssertNumAssets(t.t, ctxb, sender, numAssets)
	firstAsset, _, _ = ManualMintSimpleAsset(
		t, lndBob, sender, commitment.TapCommitmentV0, &firstReq,
	)

	numAssets += 1
	AssertNumAssets(t.t, ctxb, sender, numAssets)
	secondAsset, _, _ = ManualMintSimpleAsset(
		t, lndBob, sender, commitment.TapCommitmentV1, &secondReq,
	)

	numAssets += 1
	AssertNumAssets(t.t, ctxb, sender, numAssets)

	// Build new vPkts to receive the assets; the first packet will be V0,
	// and cause a split of the first asset.
	firstAssetSplitAmt := firstAsset.Amount / 2
	manualPkt1 := tappsbt.ForInteractiveSend(
		fn.ToArray[[32]byte](firstAsset.AssetGenesis.AssetId),
		firstAssetSplitAmt, receiverScriptKey1, 0, 0, 0,
		receiverAnchorIntKeyDesc1, asset.V0, chainParams,
	)
	manualPkt1.Version = tappsbt.V0

	manualPkt2 := tappsbt.ForInteractiveSend(
		fn.ToArray[[32]byte](secondAsset.AssetGenesis.AssetId),
		secondAsset.Amount, receiverScriptKey2, 0, 0, 0,
		receiverAnchorIntKeyDesc2, asset.V0, chainParams,
	)
	manualPkt2.Version = tappsbt.V1

	vPkts := []*tappsbt.VPacket{manualPkt1, manualPkt2}
	signedPkts := [][]byte{}

	// Funding and signing both packets should succeed.
	for _, vPkt := range vPkts {
		fundResp := fundPacket(t, sender, vPkt)
		signResp, err := sender.SignVirtualPsbt(
			ctxt, &wrpc.SignVirtualPsbtRequest{
				FundedPsbt: fundResp.FundedPsbt,
			},
		)
		require.NoError(t.t, err)
		require.NotEmpty(t.t, signResp.SignedInputs)

		signedPkts = append(signedPkts, signResp.SignedPsbt)
	}

	// If we try to anchor the packets together, that should fail, as they
	// have mismatched versions.
	_, err = sender.AnchorVirtualPsbts(
		ctxt, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: signedPkts,
		},
	)
	require.ErrorContains(t.t, err, "mixed virtual packet versions")

	// Anchoring the packets and completing the transfers separately should
	// succeed.
	send1Resp, err := sender.AnchorVirtualPsbts(
		ctxt, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signedPkts[0]},
		},
	)
	require.NoError(t.t, err)

	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, sender, send1Resp,
		firstAsset.AssetGenesis.AssetId,
		[]uint64{firstAssetSplitAmt, firstAssetSplitAmt},
		0, 1, 2,
	)

	send2Resp, err := sender.AnchorVirtualPsbts(
		ctxt, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signedPkts[1]},
		},
	)
	require.NoError(t.t, err)

	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, sender, send2Resp,
		secondAsset.AssetGenesis.AssetId, []uint64{secondAsset.Amount},
		1, 2, 1,
	)

	// This is an interactive transfer, so we do need to manually send the
	// proofs from the sender to the receiver.
	sendProof(
		t, sender, receiver, send1Resp,
		receiverScriptKey1.PubKey.SerializeCompressed(),
		firstAsset.AssetGenesis,
	)
	sendProof(
		t, sender, receiver, send2Resp,
		receiverScriptKey2.PubKey.SerializeCompressed(),
		secondAsset.AssetGenesis,
	)
	AssertNumAssets(t.t, ctxb, receiver, 2)

	receiverAssets, err := receiver.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)

	t.Logf("Receiver assets: %v", toJSON(t.t, receiverAssets))
}

// testPsbtGroupedInteractiveFullValueSend tests that we can properly send
// grouped assets back and forth, using the full amount, between nodes with the
// use of PSBTs.
func testPsbtGroupedInteractiveFullValueSend(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send backand forth. We're also minting a passive asset that
	// should remain where it is.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
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
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
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
		receiverScriptKey, receiverAnchorIntKeyDesc := DeriveKeys(
			t.t, receiver,
		)
		receiverScriptKeyBytes := receiverScriptKey.PubKey.
			SerializeCompressed()

		vPkt := tappsbt.ForInteractiveSend(
			id, fullAmt, receiverScriptKey, 0, 0, 0,
			receiverAnchorIntKeyDesc, asset.V0, chainParams,
		)
		altLeaves := asset.RandAltLeaves(t.t, true)
		leafMap := map[string][]*asset.Asset{
			string(receiverScriptKeyBytes): altLeaves,
		}
		err := vPkt.Outputs[0].SetAltLeaves(altLeaves)
		require.NoError(t.t, err)

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

		activeAsset, err := tappsbt.Decode(fundResp.FundedPsbt)
		require.NoError(t.t, err)

		// We expect stxo alt leaves as well, so we'll create those to
		// use in an assertion comparison later.
		var stxoAltLeaves []*asset.Asset
		for _, output := range activeAsset.Outputs {
			if !output.Asset.IsTransferRoot() {
				continue
			}

			witnesses, err := output.PrevWitnesses()
			require.NoError(t.t, err)
			for _, wit := range witnesses {
				prevIdKey := asset.DeriveBurnKey(*wit.PrevID)
				scriptKey := asset.NewScriptKey(prevIdKey)
				altLeaf, err := asset.NewAltLeaf(
					scriptKey, asset.ScriptV0,
				)
				require.NoError(t.t, err)

				stxoAltLeaves = append(stxoAltLeaves, altLeaf)
			}
		}
		leafMap[string(receiverScriptKeyBytes)] = append(
			leafMap[string(receiverScriptKeyBytes)],
			stxoAltLeaves...,
		)

		numOutputs := 1
		amounts := []uint64{fullAmt}
		ConfirmAndAssertOutboundTransferWithOutputs(
			t.t, t.lndHarness.Miner().Client, sender,
			sendResp, genInfo.AssetId, amounts, i/2, (i/2)+1,
			numOutputs,
		)

		// This is an interactive transfer, so we do need to manually
		// send the proof from the sender to the receiver.
		sendProof(
			t, sender, receiver, sendResp, receiverScriptKeyBytes,
			genInfo,
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

		// Check that the altLeaves from the receiver's vPacket were set
		// by the sender correctly.
		for _, asset := range receiverAssets.Assets {
			AssertProofAltLeaves(t.t, receiver, asset, leafMap)
		}
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
		t.t, t.lndHarness.Miner().Client, t.tapd,
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
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
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
		t.t, t.lndHarness.Miner().Client, t.tapd,
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
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
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
		receiverScriptKey, receiverAnchorIntKeyDesc := DeriveKeys(
			t.t, receiver,
		)
		receiverScriptKeyBytes := receiverScriptKey.PubKey.
			SerializeCompressed()

		vPkt := tappsbt.ForInteractiveSend(
			id, sendAmt, receiverScriptKey, 0, 0, 0,
			receiverAnchorIntKeyDesc, asset.V0, chainParams,
		)
		altLeaves := asset.RandAltLeaves(t.t, true)
		leafMap := map[string][]*asset.Asset{
			string(receiverScriptKeyBytes): altLeaves,
		}
		err := vPkt.Outputs[0].SetAltLeaves(altLeaves)
		require.NoError(t.t, err)

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
			t.t, t.lndHarness.Miner().Client, sender,
			sendResp, genInfo.AssetId,
			[]uint64{changeAmt, sendAmt}, i/2, (i/2)+1,
			numOutputs,
		)

		// This is an interactive transfer, so we do need to manually
		// send the proof from the sender to the receiver.
		sendProof(
			t, sender, receiver, sendResp, receiverScriptKeyBytes,
			genInfo,
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

		// Check that the altLeaves from the receiver's vPacket were set
		// by the sender correctly.
		for _, asset := range receiverAssets.Assets {
			AssertProofAltLeaves(t.t, receiver, asset, leafMap)
		}
	}

	// Finally, make sure we can still send out the passive asset.
	passiveGen := passiveAsset.AssetGenesis
	sendAssetAndAssert(
		ctxt, t, alice, bob, passiveAsset.Amount, 0,
		passiveGen, passiveAsset, 2, 3, 1,
	)
}

// testPsbtInteractiveAltLeafAnchoring tests that the tapfreighter and PSBT flow
// RPC calls will reject a vPkt with invalid AltLeaves. It also tests that
// AltLeaves from multiple vOutputs are merged into one anchor output correctly.
func testPsbtInteractiveAltLeafAnchoring(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units. We're also
	// minting a passive asset that should remain where it is.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
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
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	var (
		sender      = t.tapd
		senderLnd   = t.tapd.cfg.LndNode
		receiver    = secondTapd
		id          = fn.ToArray[[32]byte](genInfo.AssetId)
		partialAmt  = mintedAsset.Amount / 4
		chainParams = &address.RegressionNetTap
	)

	// Now, let's create a vPkt for receiving the active asset. We'll use
	// two outputs with  different script keys and different altLeaves.
	receiverScriptKey1, receiverAnchorIntKeyDesc := DeriveKeys(
		t.t, receiver,
	)
	receiverScriptKey1Bytes := receiverScriptKey1.PubKey.
		SerializeCompressed()
	receiverScriptKey2, _ := DeriveKeys(t.t, receiver)
	receiverScriptKey2Bytes := receiverScriptKey2.PubKey.
		SerializeCompressed()

	vPkt := tappsbt.ForInteractiveSend(
		id, partialAmt, receiverScriptKey1, 0, 0, 0,
		receiverAnchorIntKeyDesc, asset.V0, chainParams,
	)
	tappsbt.AddOutput(
		vPkt, partialAmt*2, receiverScriptKey2, 0,
		receiverAnchorIntKeyDesc, asset.V0,
	)

	// Let's make multiple sets of altLeaves. Set 1 and 2 should be valid
	// if they were combined, but set 3 is a subset of set 1. If we submit
	// two vPkts with sets 1 and 3, they should be rejected.
	altLeaves1 := asset.RandAltLeaves(t.t, true)
	altLeaves2 := asset.RandAltLeaves(t.t, true)
	altLeaves3 := []*asset.Asset{altLeaves1[0].Copy()}

	require.NoError(t.t, vPkt.Outputs[0].SetAltLeaves(altLeaves1))
	require.NoError(t.t, vPkt.Outputs[1].SetAltLeaves(altLeaves3))

	// Packet funding with conflicting altLeaves should fail.
	_, err := maybeFundPacket(t, sender, vPkt)
	require.ErrorContains(t.t, err, asset.ErrDuplicateAltLeafKey.Error())

	// Let's unset the conflicting altLeaf, sign the vPkt, re-add the
	// conflicting altLeaf, and try to anchor the vPkt.
	vPkt.Outputs[1].AltLeaves = nil

	fundResp := fundPacket(t, sender, vPkt)

	// The funding added a change output at the first index. So all the
	// indexes will be shifted below. The output with index 1 becomes index
	// 2 (where we cleared the alt leaves).
	fundedvPkt, err := tappsbt.Decode(fundResp.FundedPsbt)
	require.NoError(t.t, err)
	require.Len(t.t, fundedvPkt.Outputs, 3)
	require.Nil(t.t, fundedvPkt.Outputs[0].AltLeaves)
	require.NotNil(t.t, fundedvPkt.Outputs[1].AltLeaves)
	require.Nil(t.t, fundedvPkt.Outputs[2].AltLeaves)

	signActiveResp, err := sender.SignVirtualPsbt(
		ctxt, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundResp.FundedPsbt,
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, fundResp.PassiveAssetPsbts, 1)

	signPassiveResp, err := sender.SignVirtualPsbt(
		ctxt, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundResp.PassiveAssetPsbts[0],
		},
	)
	require.NoError(t.t, err)

	passivevPkt, err := tappsbt.Decode(signPassiveResp.SignedPsbt)
	require.NoError(t.t, err)

	signedvPkt, err := tappsbt.Decode(signActiveResp.SignedPsbt)
	require.NoError(t.t, err)

	signedvPktCopy := signedvPkt.Copy()
	require.NoError(t.t, signedvPkt.Outputs[2].SetAltLeaves(altLeaves3))
	signedvPktBytes, err := tappsbt.Encode(signedvPkt)
	require.NoError(t.t, err)

	// Anchoring this vPkt should fail when creating the Tap commitments for
	// each anchor output.
	_, err = sender.AnchorVirtualPsbts(
		ctxt, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signedvPktBytes},
		},
	)
	require.ErrorContains(t.t, err, asset.ErrDuplicateAltLeafKey.Error())

	// Trying to anchor the vPkt via the PSBT flow should also fail, for the
	// same reason.
	allPackets := []*tappsbt.VPacket{signedvPkt, passivevPkt}
	btcPacket, err := tapsend.PrepareAnchoringTemplate(allPackets)
	require.NoError(t.t, err)

	var btcPacketBuf bytes.Buffer
	require.NoError(t.t, btcPacket.Serialize(&btcPacketBuf))

	commitReq := &wrpc.CommitVirtualPsbtsRequest{
		VirtualPsbts:      [][]byte{signedvPktBytes},
		PassiveAssetPsbts: [][]byte{signPassiveResp.SignedPsbt},
		AnchorPsbt:        btcPacketBuf.Bytes(),
		Fees: &wrpc.CommitVirtualPsbtsRequest_SatPerVbyte{
			SatPerVbyte: uint64(feeRateSatPerKVByte / 1000),
		},
		AnchorChangeOutput: &wrpc.CommitVirtualPsbtsRequest_Add{
			Add: true,
		},
	}
	_, err = sender.CommitVirtualPsbts(ctxt, commitReq)
	require.ErrorContains(t.t, err, asset.ErrDuplicateAltLeafKey.Error())

	// Now, let's set non-conflicting altLeaves for the second vOutput, and
	// complete the transfer via the PSBT flow. This should succeed.
	require.NoError(t.t, signedvPktCopy.Outputs[2].SetAltLeaves(altLeaves2))
	signedvPktBytes, err = tappsbt.Encode(signedvPktCopy)

	require.NoError(t.t, err)

	commitReq.VirtualPsbts = [][]byte{signedvPktBytes}
	commitResp, err := sender.CommitVirtualPsbts(ctxt, commitReq)
	require.NoError(t.t, err)

	commitPacket, err := psbt.NewFromRawBytes(
		bytes.NewReader(commitResp.AnchorPsbt), false,
	)
	require.NoError(t.t, err)
	require.Len(t.t, commitResp.VirtualPsbts, 1)
	require.Len(t.t, commitResp.PassiveAssetPsbts, 1)

	activePacket, err := tappsbt.Decode(commitResp.VirtualPsbts[0])
	require.NoError(t.t, err)

	passivePacket, err := tappsbt.Decode(commitResp.PassiveAssetPsbts[0])
	require.NoError(t.t, err)

	commitPacket = signPacket(t.t, senderLnd, commitPacket)
	commitPacket = FinalizePacket(t.t, senderLnd.RPC, commitPacket)
	publishResp := LogAndPublish(
		t.t, sender, commitPacket, []*tappsbt.VPacket{activePacket},
		[]*tappsbt.VPacket{passivePacket}, commitResp,
	)

	expectedAmounts := []uint64{
		partialAmt, partialAmt, partialAmt * 2,
	}
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, sender, publishResp,
		genInfo.AssetId, expectedAmounts, 0, 1, len(expectedAmounts),
	)

	// This is an interactive transfer, so we do need to manually send the
	// proofs from the sender to the receiver.
	sendProof(
		t, sender, receiver, publishResp, receiverScriptKey1Bytes,
		genInfo,
	)
	sendProof(
		t, sender, receiver, publishResp, receiverScriptKey2Bytes,
		genInfo,
	)

	// Now, both output proofs should contain altLeaf sets 1 and 2, since
	// our two vOutputs should be committed in the same anchor output.
	receiverAssets, err := receiver.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)

	allAltLeaves := append(altLeaves1, altLeaves2...)
	leafMap := map[string][]*asset.Asset{
		string(receiverScriptKey1Bytes): allAltLeaves,
		string(receiverScriptKey2Bytes): allAltLeaves,
	}

	for _, receiverAsset := range receiverAssets.Assets {
		AssertProofAltLeaves(t.t, receiver, receiverAsset, leafMap)
	}
}

// testPsbtInteractiveTapscriptSibling tests that we can send assets to an
// anchor output that also commits to a tapscript sibling.
func testPsbtInteractiveTapscriptSibling(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send backand forth.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)

	genInfo := rpcAssets[0].AssetGenesis
	chainParams := &address.RegressionNetTap

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
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
	receiverScriptKey, receiverAnchorIntKeyDesc := DeriveKeys(t.t, bob)

	var (
		sendAmt   = uint64(1000)
		changeAmt = rpcAssets[0].Amount - sendAmt
	)
	vPkt := tappsbt.ForInteractiveSend(
		id, sendAmt, receiverScriptKey, 0, 0, 0,
		receiverAnchorIntKeyDesc, asset.V0, chainParams,
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
		t.t, t.lndHarness.Miner().Client, alice, sendResp,
		genInfo.AssetId, []uint64{changeAmt, sendAmt}, 0, 1, 2,
	)

	// This is an interactive transfer, so we do need to manually send the
	// proof from the sender to the receiver.
	sendProof(
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
		t.t, t.lndHarness.Miner().Client, t.tapd,
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

	// With the asset created, we'll set up a new node that will act as the
	// receiver of the transfer.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
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
	receiverScriptKey1, receiverAnchorIntKeyDesc1 := DeriveKeys(
		t.t, receiver,
	)
	receiverScriptKey2, receiverAnchorIntKeyDesc2 := DeriveKeys(
		t.t, receiver,
	)

	// We'll also do an internal split back to the sender itself. So we also
	// need two sets of keys for the sender.
	senderScriptKey1, senderAnchorIntKeyDesc1 := DeriveKeys(t.t, sender)
	senderScriptKey2, _ := DeriveKeys(t.t, sender)

	// We create the output at anchor index 0 for the first address.
	outputAmounts := []uint64{300, 1200, 1300, 1400, 800}
	vPkt := tappsbt.ForInteractiveSend(
		id, outputAmounts[1], receiverScriptKey1, 0, 0, 0,
		receiverAnchorIntKeyDesc1, asset.V0, chainParams,
	)

	// And now we'll create an output at anchor index 1 for the second
	// address and two at anchor index 2 for our internal split. This should
	// still leave 300 units as change which we expect to end up at anchor
	// index 3.
	tappsbt.AddOutput(
		vPkt, outputAmounts[2], receiverScriptKey2, 1,
		receiverAnchorIntKeyDesc2, asset.V0,
	)
	tappsbt.AddOutput(
		vPkt, outputAmounts[3], senderScriptKey1, 2,
		senderAnchorIntKeyDesc1, asset.V0,
	)
	tappsbt.AddOutput(
		vPkt, outputAmounts[4], senderScriptKey2, 2,
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

	// Before we anchor the transaction, we'll subscribe for send events, so
	// we can track the state of the parcel.
	ctxc, streamCancel := context.WithCancel(ctxb)
	scriptKey1Bytes := receiverScriptKey1.PubKey.SerializeCompressed()
	stream, err := sender.SubscribeSendEvents(
		ctxc, &taprpc.SubscribeSendEventsRequest{
			FilterScriptKey: scriptKey1Bytes,
		},
	)
	require.NoError(t.t, err)
	sendEvents := &EventSubscription[*taprpc.SendEvent]{
		ClientEventStream: stream,
		Cancel:            streamCancel,
	}

	// Now we'll attempt to complete the transfer.
	sendResp, err := sender.AnchorVirtualPsbts(
		ctxt, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signResp.SignedPsbt},
		},
	)
	require.NoError(t.t, err)

	AssertSendEvents(
		t.t, scriptKey1Bytes, sendEvents,
		tapfreighter.SendStateAnchorSign,
		tapfreighter.SendStateBroadcast,
	)

	// We end up with a transfer with 5 outputs: 2 for the two different
	// receiver addresses (with an anchor output each), 2 for the sender
	// addresses (sharing an anchor output) and 1 for the change. So there
	// are 4 BTC anchor outputs but 5 asset transfer outputs.
	numOutputs := 5
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, sender, sendResp,
		genInfo.AssetId, outputAmounts, 0, 1, numOutputs,
	)

	AssertSendEvents(
		t.t, scriptKey1Bytes, sendEvents,
		tapfreighter.SendStateWaitTxConf,
		tapfreighter.SendStateComplete,
	)

	// This is an interactive transfer, so we do need to manually send the
	// proof from the sender to the receiver.
	sendProof(
		t, sender, receiver, sendResp, scriptKey1Bytes, genInfo,
	)
	sendProof(
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
		ctxt, t, t.tapd, secondTapd, outputAmounts[3], 0,
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
		t.t, t.lndHarness.Miner().Client, primaryTapd,
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
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondaryTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
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
	sendResp, sendEvents := sendAssetsToAddr(t, primaryTapd, addr)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, primaryTapd, sendResp,
		genInfo.AssetId, []uint64{changeAmt, sendAmt}, 0, 1,
	)

	AssertNonInteractiveRecvComplete(t.t, secondaryTapd, 1)
	AssertSendEventsComplete(t.t, addr.ScriptKey, sendEvents)

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
	sendResp, sendEvents = sendAssetsToAddr(t, primaryTapd, addr)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, primaryTapd, sendResp,
		genInfo.AssetId, []uint64{changeAmt, sendAmt}, 1, 2,
	)

	AssertNonInteractiveRecvComplete(t.t, secondaryTapd, 2)
	AssertSendEventsComplete(t.t, addr.ScriptKey, sendEvents)

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
	sendResp, sendEvents = sendAssetsToAddr(t, primaryTapd, addr)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, primaryTapd, sendResp,
		genInfo.AssetId, []uint64{changeAmt, sendAmt}, 2, 3,
	)

	AssertNonInteractiveRecvComplete(t.t, secondaryTapd, 3)
	AssertSendEventsComplete(t.t, addr.ScriptKey, sendEvents)

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
	primaryNodeScriptKey, primaryNodeAnchorIntKeyDesc := DeriveKeys(
		t.t, primaryTapd,
	)

	var assetId asset.ID
	copy(assetId[:], genInfo.AssetId)

	chainParams := &address.RegressionNetTap
	sendAmt = uint64(3500)
	changeAmt = uint64(500)

	vPkt := tappsbt.ForInteractiveSend(
		assetId, sendAmt, primaryNodeScriptKey, 0, 0, 0,
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
		t.t, t.lndHarness.Miner().Client, secondaryTapd,
		sendResp, genInfo.AssetId,
		[]uint64{changeAmt, sendAmt}, currentTransferIdx, numTransfers,
		numOutputs,
	)

	// This is an interactive transfer. Therefore, we will manually transfer
	// the proof from the sender to the receiver.
	sendProof(
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
		assetId, sendAmt, primaryNodeScriptKey, 0, 0, 0,
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
		t.t, t.lndHarness.Miner().Client, secondaryTapd, sendResp,
		genInfo.AssetId, []uint64{sendAmt}, currentTransferIdx,
		numTransfers, numOutputs,
	)

	// This is an interactive transfer. Therefore, we will manually transfer
	// the proof from the sender to the receiver.
	sendProof(
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
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)

	mintedAsset := rpcAssets[0]
	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
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
	bobScriptKey, bobInternalKey := DeriveKeys(t.t, bob)

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
		t.t, t.lndHarness.Miner().Client, bob, sendResp,
		genInfo.AssetId,
		[]uint64{(4*numUnits)/5 - 1, (numUnits / 5) + 1}, 0, 1,
	)

	// This is an interactive/PSBT based transfer, so we do need to manually
	// send the proof from the sender to the receiver because the proof
	// courier address gets lost in the address->PSBT conversion.
	sendProof(t, bob, alice, sendResp, aliceAddr.ScriptKey, genInfo)

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
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)

	mintedAsset := rpcAssets[0]
	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
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
	bobScriptKey, bobInternalKey := DeriveKeys(t.t, bob)

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

	ctxc, streamCancel := context.WithCancel(ctxb)
	stream, err := bob.SubscribeSendEvents(
		ctxc, &taprpc.SubscribeSendEventsRequest{},
	)
	require.NoError(t.t, err)
	sendEvents := &EventSubscription[*taprpc.SendEvent]{
		ClientEventStream: stream,
		Cancel:            streamCancel,
	}

	// Now we'll attempt to complete the transfer.
	sendResp, err := bob.AnchorVirtualPsbts(
		ctxb, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signedBytes},
		},
	)
	require.NoError(t.t, err)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, bob, sendResp,
		genInfo.AssetId,
		[]uint64{(4*numUnits)/5 - 1, (numUnits / 5) + 1}, 0, 1,
	)

	AssertSendEvents(
		t.t, aliceAddr.ScriptKey, sendEvents,
		tapfreighter.SendStateAnchorSign,
		tapfreighter.SendStateWaitTxConf,
	)

	msg, err := stream.Recv()
	require.NoError(t.t, err)
	require.Contains(
		t.t, msg.Error, "signature not empty on failed checksig",
	)
}

// testPsbtTrustlessSwap tests that the SIGHASH_NONE flag of vPSBTs can be used
// to execute a trustless swap between two parties. This is done by using
// different sighashes for the bitcoin psbt and taproot asset vpsbt. One is able
// to "claim" the assets only by bringing their own bitcoin to fulfill the
// outputs of the bitcoin transaction.
func testPsbtTrustlessSwap(t *harnessTest) {
	// First, we'll make a normal asset.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)

	mintedAsset := rpcAssets[0]
	genInfo := mintedAsset.AssetGenesis

	ctxb := context.Background()

	var (
		alice       = t.tapd
		numUnits    = mintedAsset.Amount
		chainParams = &address.RegressionNetTap
		assetID     asset.ID
	)
	copy(assetID[:], genInfo.AssetId)

	// Now Alice will derive the script and anchor internal keys that will
	// be used to bootstrap an interactive full send of her assets. This
	// generated script key is only used to create the template of the asset
	// transfer that will be later be changed by the receiver.
	aliceDummyScriptKey, aliceAnchorInternalKey := DeriveKeys(t.t, alice)
	vPkt := tappsbt.ForInteractiveSend(
		assetID, numUnits, aliceDummyScriptKey, 0, 0, 1,
		aliceAnchorInternalKey, asset.V0, chainParams,
	)

	// Now we fund the vPSBT, which creates 1 input and 1 output, which
	// correspond to Alice's anchor that carries the asset and the output to
	// which Alice is sending all of the assets.
	fundResp := fundPacket(t, alice, vPkt)

	var err error
	vPkt, err = tappsbt.Decode(fundResp.FundedPsbt)
	require.NoError(t.t, err)

	require.Len(t.t, vPkt.Inputs, 1)
	require.Len(t.t, vPkt.Outputs, 1)

	// On the vPSBT level, which describes the assets transfer, we do not
	// commit to any outputs.
	vPkt.Inputs[0].SighashType = txscript.SigHashNone

	// Let's do some sanity checks on the structure of the vPSBT, and
	// prepare its outputs before signing.
	require.Equal(t.t, vPkt.Outputs[0].Type, tappsbt.TypeSimple)
	require.NoError(t.t, tapsend.PrepareOutputAssets(ctxb, vPkt))
	require.Nil(t.t, vPkt.Outputs[0].Asset.SplitCommitmentRoot)
	require.Len(t.t, vPkt.Outputs[0].Asset.PrevWitnesses, 1)
	require.Nil(t.t, vPkt.Outputs[0].Asset.PrevWitnesses[0].SplitCommitment)

	fundedPsbtBytes, err := tappsbt.Encode(vPkt)
	require.NoError(t.t, err)

	// Alice signs the vPSBT.
	signedResp, err := alice.SignVirtualPsbt(
		ctxb, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundedPsbtBytes,
		},
	)
	require.NoError(t.t, err)
	require.Contains(t.t, signedResp.SignedInputs, uint32(0))

	// Deserialize the signed vPSBT.
	vPkt, err = tappsbt.Decode(signedResp.SignedPsbt)
	require.NoError(t.t, err)

	// Now we need to create the bitcoin PSBT where the previously created
	// vPSBT will be anchored to.
	btcPacket, err := tapsend.PrepareAnchoringTemplate([]*tappsbt.VPacket{
		vPkt,
	})
	require.NoError(t.t, err)

	// This bitcoin PSBT should have 1 input, which is the anchor of Alice's
	// assets, and 2 outputs that correspond to Alice's bitcoin change
	// (index 0) and the anchor that carries the assets (index 1).
	require.Len(t.t, btcPacket.Inputs, 1)
	require.Len(t.t, btcPacket.Outputs, 2)

	// Let's set an actual address for Alice's output.
	addrResp := t.tapd.cfg.LndNode.RPC.NewAddress(&lnrpc.NewAddressRequest{
		Type: lnrpc.AddressType_TAPROOT_PUBKEY,
	})

	aliceP2TR, err := btcutil.DecodeAddress(
		addrResp.Address, harnessNetParams,
	)
	require.NoError(t.t, err)

	alicePkScript, err := txscript.PayToAddrScript(aliceP2TR)
	require.NoError(t.t, err)

	// These are basically Alice's terms that she signs the assets over:
	// Send me 69420 satoshis to this address that belongs to me, and you
	// will get assets in return.
	btcPacket.UnsignedTx.TxOut[0].PkScript = alicePkScript
	btcPacket.UnsignedTx.TxOut[0].Value = 69420
	derivation, trDerivation := getAddressBip32Derivation(
		t.t, addrResp.Address, t.tapd.cfg.LndNode,
	)

	// Add the derivation info and internal key for alice's taproot address.
	btcPacket.Outputs[0].Bip32Derivation = []*psbt.Bip32Derivation{
		derivation,
	}
	btcPacket.Outputs[0].TaprootBip32Derivation =
		[]*psbt.TaprootBip32Derivation{trDerivation}
	btcPacket.Outputs[0].TaprootInternalKey = trDerivation.XOnlyPubKey

	var b bytes.Buffer
	err = btcPacket.Serialize(&b)
	require.NoError(t.t, err)

	// Now we need to commit the vPSBT and PSBT, creating all the related
	// proofs for this transfer to be valid.
	resp, err := alice.CommitVirtualPsbts(
		ctxb, &wrpc.CommitVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signedResp.SignedPsbt},
			AnchorPsbt:   b.Bytes(),
			AnchorChangeOutput: &wrpc.CommitVirtualPsbtsRequest_Add{
				Add: true,
			},
			Fees: &wrpc.CommitVirtualPsbtsRequest_TargetConf{
				TargetConf: 12,
			},
		},
	)
	require.NoError(t.t, err)

	// Now we retrieve the bitcoin PSBT from the response.
	btcPacket, err = psbt.NewFromRawBytes(
		bytes.NewReader(resp.AnchorPsbt), false,
	)
	require.NoError(t.t, err)

	// The first input is the anchor that carries Alice's assets. This input
	// will only commit to itself and Alice's output at same index (0),
	// which is Alice's btc reward for swapping the assets. With the
	// following sighash flag we commit to exactly that input and output,
	// but we also allow anyone to add their own inputs, which will allow
	// Bob later to add his btc input to pay Alice.
	btcPacket.Inputs[0].SighashType = txscript.SigHashSingle |
		txscript.SigHashAnyOneCanPay

	// We now strip the extra input that was only used to fund the bitcoin
	// psbt. This is meant to be filled later by the person redeeming this
	// swap offer.
	btcPacket.Inputs = append(
		btcPacket.Inputs[:1], btcPacket.Inputs[2:]...,
	)
	btcPacket.UnsignedTx.TxIn = append(
		btcPacket.UnsignedTx.TxIn[:1], btcPacket.UnsignedTx.TxIn[2:]...,
	)

	// Let's get rid of the change output that we no longer need.
	btcPacket.Outputs = btcPacket.Outputs[:2]
	btcPacket.UnsignedTx.TxOut = btcPacket.UnsignedTx.TxOut[:2]

	t.Logf("Alice BTC PSBT: %v", spew.Sdump(btcPacket))

	b.Reset()
	err = btcPacket.Serialize(&b)
	require.NoError(t.t, err)

	// Now alice signs the bitcoin psbt.
	signPsbtResp := t.tapd.cfg.LndNode.RPC.SignPsbt(
		&walletrpc.SignPsbtRequest{
			FundedPsbt: b.Bytes(),
		},
	)

	require.Len(t.t, signPsbtResp.SignedInputs, 1)
	require.Equal(t.t, uint32(0), signPsbtResp.SignedInputs[0])

	btcPacket, err = psbt.NewFromRawBytes(
		bytes.NewReader(signPsbtResp.SignedPsbt), false,
	)
	require.NoError(t.t, err)

	// Let's do some sanity checks.
	require.Len(t.t, btcPacket.Inputs, 1)
	require.Len(t.t, btcPacket.Outputs, 2)

	signedVpsbtBytes, err := tappsbt.Encode(vPkt)
	require.NoError(t.t, err)

	// Now let's spin up the receiver of this swap offer.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	var bob = secondTapd

	// Bob begins by decoding the vPSBT.
	bobVPsbt, err := tappsbt.Decode(signedVpsbtBytes)
	require.NoError(t.t, err)

	require.Len(t.t, bobVPsbt.Outputs, 1)

	// And then he replaces the asset output with one of his own.
	bobScriptKey, bobAnchorInternalKey := DeriveKeys(t.t, bob)

	bobVOut := bobVPsbt.Outputs[0]
	bobVOut.ScriptKey = bobScriptKey
	bobVOut.AnchorOutputBip32Derivation = nil
	bobVOut.AnchorOutputTaprootBip32Derivation = nil
	bobVOut.SetAnchorInternalKey(
		bobAnchorInternalKey, harnessNetParams.HDCoinType,
	)
	deliveryAddrStr := fmt.Sprintf(
		"%s://%s", proof.UniverseRpcCourierType,
		t.universeServer.ListenAddr,
	)
	deliveryAddr, err := url.Parse(deliveryAddrStr)
	require.NoError(t.t, err)
	bobVPsbt.Outputs[0].ProofDeliveryAddress = deliveryAddr

	// The key information on the btc level, including the derivation path,
	// needs to be updated to point to Bob's keys as well. Otherwise, he
	// wouldn't be able to take over custody of the anchor carrying the
	// assets.
	btcPacket.Outputs[1].TaprootInternalKey = schnorr.SerializePubKey(
		bobAnchorInternalKey.PubKey,
	)
	btcPacket.Outputs[1].Bip32Derivation =
		bobVOut.AnchorOutputBip32Derivation
	btcPacket.Outputs[1].TaprootBip32Derivation =
		bobVOut.AnchorOutputTaprootBip32Derivation

	// Before Bob tidies up the output commitments he keeps a backup of the
	// transfer witnesses. This is where Alice's SIGHASH_NONE signature
	// lies.
	witnessBackup := bobVPsbt.Outputs[0].Asset.PrevWitnesses

	// Bob tidies up the outputs.
	err = tapsend.PrepareOutputAssets(ctxb, bobVPsbt)
	require.NoError(t.t, err)

	require.Len(t.t, bobVPsbt.Outputs, 1)
	require.Equal(
		t.t, bobVPsbt.Outputs[0].ScriptKey,
		bobVPsbt.Outputs[0].Asset.ScriptKey,
	)

	// Bob restores Alice's signature for the asset input.
	bobVPsbt.Outputs[0].Asset.PrevWitnesses = witnessBackup

	bobVPsbtBytes, err := tappsbt.Encode(bobVPsbt)
	require.NoError(t.t, err)

	// Now let's serialize the edited vPSBT and commit it to our bitcoin
	// PSBT.
	b.Reset()
	err = btcPacket.Serialize(&b)
	require.NoError(t.t, err)

	// This call will also fund the PSBT, which means that the bitcoin that
	// Alice "requested" previously by bumping her output will now be
	// provided by Bob.
	resp, err = bob.CommitVirtualPsbts(
		ctxb, &wrpc.CommitVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{bobVPsbtBytes},
			AnchorPsbt:   b.Bytes(),
			AnchorChangeOutput: &wrpc.CommitVirtualPsbtsRequest_Add{
				Add: true,
			},
			Fees: &wrpc.CommitVirtualPsbtsRequest_TargetConf{
				TargetConf: 12,
			},
		},
	)
	require.NoError(t.t, err)

	bobVPsbt, err = tappsbt.Decode(resp.VirtualPsbts[0])
	require.NoError(t.t, err)

	// Since Bob brings in a new input to the bitcoin transaction, he needs
	// to sign it. We do not care about the sighash flag here, that can be
	// the default, as we will not edit the bitcoin transaction further.
	signResp := lndBob.RPC.SignPsbt(&walletrpc.SignPsbtRequest{
		FundedPsbt: resp.AnchorPsbt,
	})
	require.NoError(t.t, err)

	finalPsbt, err := psbt.NewFromRawBytes(
		bytes.NewReader(signResp.SignedPsbt), false,
	)
	require.NoError(t.t, err)

	// Bob must have brought his own input in order to pay Alice.
	require.Len(t.t, finalPsbt.Inputs, 2)

	// Bob's input should be at index 1, as index 0 is Alice's assets
	// anchor.
	bobInputIdx := uint32(1)

	// Bob should sign exactly 1 input.
	require.Len(t.t, signResp.SignedInputs, 1)

	// Bob should have signed the input at the expected index.
	require.Equal(t.t, bobInputIdx, signResp.SignedInputs[0])
	require.NoError(t.t, finalPsbt.SanityCheck())

	signedPkt := finalizePacket(t.t, lndBob, finalPsbt)
	require.True(t.t, signedPkt.IsComplete())

	logResp := logAndPublish(
		t.t, alice, signedPkt, []*tappsbt.VPacket{bobVPsbt}, nil, resp,
	)
	t.Logf("Logged transaction: %v", toJSON(t.t, logResp))

	// Mine a block to confirm the transfer.
	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	// We also need to push the proof for this transfer to the universe
	// server.
	bobScriptKeyBytes := bobScriptKey.PubKey.SerializeCompressed()
	bobOutputIndex := uint32(1)
	transferTXID := finalPsbt.UnsignedTx.TxHash()
	bobAssetOutpoint := fmt.Sprintf("%s:%d", transferTXID.String(),
		bobOutputIndex)
	transferProofUniRPC(
		t, t.universeServer.service, bob, bobScriptKeyBytes, genInfo,
		mintedAsset.AssetGroup, bobAssetOutpoint,
	)

	// In order for Bob to expect this incoming transfer, we need to
	// register it with the internal wallet of Bob.
	registerResp, err := bob.RegisterTransfer(
		ctxb, &taprpc.RegisterTransferRequest{
			AssetId:   assetID[:],
			GroupKey:  mintedAsset.AssetGroup.TweakedGroupKey,
			ScriptKey: bobScriptKeyBytes,
			Outpoint: &taprpc.OutPoint{
				Txid:        transferTXID[:],
				OutputIndex: bobOutputIndex,
			},
		},
	)
	require.NoError(t.t, err)
	require.Equal(
		t.t, bobScriptKeyBytes, registerResp.RegisteredAsset.ScriptKey,
	)

	bobAssets, err := bob.ListAssets(ctxb, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)

	// Verify that Bob now holds the asset.
	require.Len(t.t, bobAssets.Assets, 1)
	require.Equal(t.t, bobAssets.Assets[0].Amount, numUnits)

	require.Equal(t.t, bobScriptKeyBytes, bobAssets.Assets[0].ScriptKey)
}

// testPsbtSTXOExclusionProofs tests that we can properly send normal assets
// back and forth, using partial amounts, between nodes with the use of PSBTs,
// and that we see the expected STXO exclusion proofs.
func testPsbtSTXOExclusionProofs(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send backand forth. We're also minting a passive asset that
	// should remain where it is.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
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

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	mintedAsset := rpcAssets[0]
	genInfo := rpcAssets[0].AssetGenesis
	var assetId asset.ID
	copy(assetId[:], genInfo.AssetId)

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bob := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	alice := t.tapd

	// We need to derive two keys, one for the new script key and
	// one for the internal key.
	bobScriptKey, bobAnchorIntKeyDesc := DeriveKeys(t.t, bob)

	var id [32]byte
	copy(id[:], genInfo.AssetId)
	sendAmt := uint64(2400)

	vPkt := tappsbt.ForInteractiveSend(
		id, sendAmt, bobScriptKey, 0, 0, 0,
		bobAnchorIntKeyDesc, asset.V0, chainParams,
	)

	// Next, we'll attempt to complete a transfer with PSBTs from
	// alice to bob, using the partial amount.
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

	numOutputs := 2
	changeAmt := mintedAsset.Amount - sendAmt
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, alice, sendResp,
		genInfo.AssetId, []uint64{changeAmt, sendAmt}, 0, 1, numOutputs,
	)

	// We want the proof of the change asset since that is the root asset.
	aliceScriptKeyBytes := sendResp.Transfer.Outputs[0].ScriptKey
	proofResp := exportProof(
		t, alice, sendResp, aliceScriptKeyBytes, genInfo,
	)
	proofFile, err := proof.DecodeFile(proofResp.RawProofFile)
	require.NoError(t.t, err)
	require.Equal(t.t, proofFile.NumProofs(), 2)
	latestProof, err := proofFile.LastProof()
	require.NoError(t.t, err)

	// This proof should contain the STXO exclusion proofs
	stxoProofs := latestProof.ExclusionProofs[0].CommitmentProof.STXOProofs
	require.NotNil(t.t, stxoProofs)

	// We expect a single exclusion proof for the change output, which is
	// the input asset that we spent which should not be committed to in the
	// other anchor output.
	outpoint, err := wire.NewOutPointFromString(
		mintedAsset.ChainAnchor.AnchorOutpoint,
	)
	require.NoError(t.t, err)

	prevId := asset.PrevID{
		OutPoint:  *outpoint,
		ID:        id,
		ScriptKey: asset.SerializedKey(mintedAsset.ScriptKey),
	}

	prevIdKey := asset.DeriveBurnKey(prevId)
	expectedScriptKey := asset.NewScriptKey(prevIdKey)

	pubKey := expectedScriptKey.PubKey
	identifier := asset.ToSerialized(pubKey)

	require.Len(t.t, stxoProofs, 1)

	// If we derive the identifier from the script key we expect of the
	// minimal asset, it should yield a proof when used as a key for the
	// stxoProofs.
	require.NotNil(t.t, stxoProofs[identifier])

	// Create the minimal asset for which we expect to see the STXO
	// exclusion.
	minAsset, err := asset.NewAltLeaf(expectedScriptKey, asset.ScriptV0)
	require.NoError(t.t, err)

	// We need to copy the base exclusion proof for each STXO because we'll
	// modify it with the specific asset and taproot proofs.
	stxoProof := stxoProofs[identifier]
	stxoExclProof := proof.MakeSTXOProof(
		latestProof.ExclusionProofs[0], &stxoProof,
	)

	// Derive the possible taproot keys assuming the exclusion proof is
	// correct.
	derivedKeys, err := stxoExclProof.DeriveByAssetExclusion(
		minAsset.AssetCommitmentKey(),
		minAsset.TapCommitmentKey(),
	)
	require.NoError(t.t, err)

	// Extract the actual taproot key from the anchor tx.
	expectedTaprootKey, err := proof.ExtractTaprootKey(
		&latestProof.AnchorTx, stxoExclProof.OutputIndex,
	)
	require.NoError(t.t, err)
	expectedKey := schnorr.SerializePubKey(expectedTaprootKey)

	// Convert the derived (possible) keys into their schnorr serialized
	// counterparts.
	serializedKeys := make([][]byte, 0, len(derivedKeys))
	for derivedKey := range derivedKeys {
		serializedKeys = append(
			serializedKeys, derivedKey.SchnorrSerialized(),
		)
	}

	// The derived keys should contain the expected key.
	require.Contains(t.t, serializedKeys, expectedKey)

	// This is an interactive transfer, so we do need to manually
	// send the proof from the sender to the receiver.
	bobScriptKeyBytes := bobScriptKey.PubKey.SerializeCompressed()
	sendProof(t, alice, bob, sendResp, bobScriptKeyBytes, genInfo)
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
		t.t, t.lndHarness.Miner().Client, t.tapd,
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
		aliceLnd           = t.tapd.cfg.LndNode
		bobLnd             = t.lndHarness.NewNodeWithCoins("Bob", nil)
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
	btcPacket, activeAssets, passiveAssets, commitResp = CommitVirtualPsbts(
		t.t, aliceTapd, btcPacket, activeAssets, passiveAssets, -1,
	)

	t.Logf("Committed transaction: %v", toJSON(t.t, commitResp))

	btcPacket = signPacket(t.t, aliceLnd, btcPacket)
	btcPacket = FinalizePacket(t.t, aliceLnd.RPC, btcPacket)
	sendResp := LogAndPublish(
		t.t, aliceTapd, btcPacket, activeAssets, passiveAssets,
		commitResp,
	)

	expectedAmounts := []uint64{
		targetAsset.Amount - assetsToSend, assetsToSend,
	}
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, aliceTapd,
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

// testPsbtLockTimeSend tests that we can send minted assets into a ScriptKey
// encumbered with an absolute (CLTV) lock time.
func testPsbtLockTimeSend(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send. We're also minting a passive asset that should remain
	// where it is.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
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
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bob := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	var (
		alice       = t.tapd
		id          [32]byte
		fullAmt     = mintedAsset.Amount
		chainParams = &address.RegressionNetTap
	)
	copy(id[:], genInfo.AssetId)

	_, bestBlock := t.lndHarness.Miner().GetBestBlock()
	lockTimeBlocks := uint64(bestBlock + 6)

	// We need to derive two keys, one for the new script key and one for
	// the internal key.
	bobScriptKey, bobInternalKey := DeriveKeys(t.t, bob)

	// Bob creates a pkScript that will be used to lock the assets.
	tapLeaf := test.ScriptCltv(t.t, int64(lockTimeBlocks))
	tapscript := input.TapscriptFullTree(bobScriptKey.PubKey, tapLeaf)
	rootHash := tapscript.ControlBlock.RootHash(tapLeaf.Script)
	tweakedTaprootKeyBob, err := tapscript.TaprootKey()
	require.NoError(t.t, err)

	keyDescriptorBob := keychain.KeyDescriptor{
		PubKey: tweakedTaprootKeyBob,
	}

	bobAssetScriptKey := asset.ScriptKey{
		PubKey: tweakedTaprootKeyBob,
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: keyDescriptorBob,
			Tweak:  rootHash,
		},
	}

	// We need to let the wallet of Bob know that we're going to use a
	// script key with a custom root.
	_, err = bob.DeclareScriptKey(ctxt, &wrpc.DeclareScriptKeyRequest{
		ScriptKey: taprpc.MarshalScriptKey(bobAssetScriptKey),
	})
	require.NoError(t.t, err)

	fundRespLock := fundPacket(t, alice, tappsbt.ForInteractiveSend(
		id, fullAmt, bobAssetScriptKey, 0, 0, 0, bobInternalKey,
		asset.V0, chainParams,
	))

	// We now sign the vPSBT.
	signRespLock, err := alice.SignVirtualPsbt(
		ctxt, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundRespLock.FundedPsbt,
		},
	)
	require.NoError(t.t, err)

	// Now we'll attempt to complete the transfer.
	sendResp, err := alice.AnchorVirtualPsbts(
		ctxt, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signRespLock.SignedPsbt},
		},
	)
	require.NoError(t.t, err)

	var (
		amounts            = []uint64{fullAmt}
		currentTransferIdx = 0
		numTransfers       = 1
		numOutputs         = len(amounts)
	)
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, alice,
		sendResp, genInfo.AssetId, amounts, currentTransferIdx,
		numTransfers, numOutputs,
	)

	// This is an interactive transfer, so we do need to manually
	// send the proof from the sender to the receiver.
	sendProof(
		t, alice, bob, sendResp,
		bobAssetScriptKey.PubKey.SerializeCompressed(), genInfo,
	)

	assertNumAssetOutputs(t.t, alice, genInfo.AssetId, 0)
	assertNumAssetOutputs(t.t, bob, genInfo.AssetId, 1)

	// We mine just 4 blocks, two short of being enough for the relative
	// time lock.
	MineBlocks(t.t, t.lndHarness.Miner().Client, 4, 0)

	// Now if we spend Bob's asset, we should see a lock time in the anchor
	// transaction. For that, we need to derive two keys for Alice, one for
	// the new script key and one for the internal key.
	aliceScriptKey, aliceInternalKey := DeriveKeys(t.t, alice)
	fundRespSpend := fundPacket(t, bob, tappsbt.ForInteractiveSend(
		id, fullAmt, aliceScriptKey, lockTimeBlocks, 0, 0,
		aliceInternalKey, asset.V0, chainParams,
	))

	// We don't need to sign anything as our csv script is anyone can spend.
	fundedPsbtSpend, err := tappsbt.Decode(fundRespSpend.FundedPsbt)
	require.NoError(t.t, err)
	controlBlockBytes, err := tapscript.ControlBlock.ToBytes()
	require.NoError(t.t, err)
	senderOut := fundedPsbtSpend.Outputs[0].Asset
	senderOut.PrevWitnesses[0].TxWitness = [][]byte{
		tapLeaf.Script, controlBlockBytes,
	}

	// We now create our spending transaction manually, but expect it to
	// fail, because it is not yet final.
	vPackets := []*tappsbt.VPacket{fundedPsbtSpend}
	btcPacket, err := tapsend.PrepareAnchoringTemplate(vPackets)
	require.NoError(t.t, err)

	btcPacket, _, _, _ = CommitVirtualPsbts(
		t.t, bob, btcPacket, vPackets, nil, -1,
	)
	btcPacket = signPacket(t.t, bobLnd, btcPacket)
	btcPacket = FinalizePacket(t.t, bobLnd.RPC, btcPacket)
	spendTx, err := psbt.Extract(btcPacket)
	require.NoError(t.t, err)

	var spendTxBuf bytes.Buffer
	require.NoError(t.t, spendTx.Serialize(&spendTxBuf))
	_, err = bobLnd.RPC.WalletKit.PublishTransaction(
		ctxt, &walletrpc.Transaction{
			TxHex: spendTxBuf.Bytes(),
		},
	)
	require.ErrorContains(t.t, err, "non final")
	t.lndHarness.Miner().AssertNumTxsInMempool(0)

	// After mining a single block, the error should go away.
	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 0)

	// Now we'll attempt to complete the transfer normally, which should
	// succeed.
	signedPsbtBytes, err := tappsbt.Encode(fundedPsbtSpend)
	require.NoError(t.t, err)
	sendRespSpend, err := bob.AnchorVirtualPsbts(
		ctxt, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signedPsbtBytes},
		},
	)
	require.NoError(t.t, err)

	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, bob,
		sendRespSpend, genInfo.AssetId, amounts, currentTransferIdx,
		numTransfers, numOutputs,
	)

	// Make sure the transfer shows the lock time.
	resp, err := bob.ListTransfers(ctxb, &taprpc.ListTransfersRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, resp.Transfers, numTransfers)
	require.EqualValues(
		t.t, lockTimeBlocks, resp.Transfers[0].Outputs[0].LockTime,
	)
	require.EqualValues(
		t.t, 0, resp.Transfers[0].Outputs[0].RelativeLockTime,
	)

	// This is an interactive transfer, so we do need to manually
	// send the proof from the sender to the receiver.
	sendProof(
		t, bob, alice, sendRespSpend,
		aliceScriptKey.PubKey.SerializeCompressed(), genInfo,
	)

	spendOuts := assertNumAssetOutputs(t.t, alice, genInfo.AssetId, 1)
	assertNumAssetOutputs(t.t, bob, genInfo.AssetId, 0)

	// Does the asset also show the correct lock times?
	require.EqualValues(t.t, lockTimeBlocks, spendOuts[0].LockTime)
	require.EqualValues(t.t, 0, spendOuts[0].RelativeLockTime)
}

// testPsbtRelativeLockTimeSend tests that we can send minted assets into a
// ScriptKey encumbered with a relative (CSV) lock time.
func testPsbtRelativeLockTimeSend(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send. We're also minting a passive asset that should remain
	// where it is.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
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

	const lockTimeBlocks = 6

	mintedAsset := rpcAssets[0]
	genInfo := mintedAsset.AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bob := setupTapdHarness(t.t, t, lndBob, t.universeServer)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	var (
		alice       = t.tapd
		id          [32]byte
		fullAmt     = mintedAsset.Amount
		chainParams = &address.RegressionNetTap
	)
	copy(id[:], genInfo.AssetId)

	// We need to derive two keys, one for the new script key and one for
	// the internal key.
	bobScriptKey, bobInternalKey := DeriveKeys(t.t, bob)

	// Bob creates a pkScript that will be used to lock the assets.
	tapLeaf := test.ScriptCsv(t.t, lockTimeBlocks)
	tapscript := input.TapscriptFullTree(bobScriptKey.PubKey, tapLeaf)
	rootHash := tapscript.ControlBlock.RootHash(tapLeaf.Script)
	tweakedTaprootKeyBob, err := tapscript.TaprootKey()
	require.NoError(t.t, err)

	keyDescriptorBob := keychain.KeyDescriptor{
		PubKey: tweakedTaprootKeyBob,
	}

	bobAssetScriptKey := asset.ScriptKey{
		PubKey: tweakedTaprootKeyBob,
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: keyDescriptorBob,
			Tweak:  rootHash,
		},
	}

	// We need to let the wallet of Bob know that we're going to use a
	// script key with a custom root.
	_, err = bob.DeclareScriptKey(ctxt, &wrpc.DeclareScriptKeyRequest{
		ScriptKey: taprpc.MarshalScriptKey(bobAssetScriptKey),
	})
	require.NoError(t.t, err)

	fundRespLock := fundPacket(t, alice, tappsbt.ForInteractiveSend(
		id, fullAmt, bobAssetScriptKey, 0, 0, 0, bobInternalKey,
		asset.V0, chainParams,
	))

	// We now sign the vPSBT.
	signRespLock, err := alice.SignVirtualPsbt(
		ctxt, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundRespLock.FundedPsbt,
		},
	)
	require.NoError(t.t, err)

	// Now we'll attempt to complete the transfer.
	sendResp, err := alice.AnchorVirtualPsbts(
		ctxt, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signRespLock.SignedPsbt},
		},
	)
	require.NoError(t.t, err)

	var (
		amounts            = []uint64{fullAmt}
		currentTransferIdx = 0
		numTransfers       = 1
		numOutputs         = len(amounts)
	)
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, alice,
		sendResp, genInfo.AssetId, amounts, currentTransferIdx,
		numTransfers, numOutputs,
	)

	// This is an interactive transfer, so we do need to manually
	// send the proof from the sender to the receiver.
	sendProof(
		t, alice, bob, sendResp,
		bobAssetScriptKey.PubKey.SerializeCompressed(), genInfo,
	)

	assertNumAssetOutputs(t.t, alice, genInfo.AssetId, 0)
	assertNumAssetOutputs(t.t, bob, genInfo.AssetId, 1)

	// We mine just 4 blocks, two short of being enough for the relative
	// time lock.
	MineBlocks(t.t, t.lndHarness.Miner().Client, 4, 0)

	// Now if we spend Bob's asset, we should see a lock time in the anchor
	// transaction. For that, we need to derive two keys for Alice, one for
	// the new script key and one for the internal key.
	aliceScriptKey, aliceInternalKey := DeriveKeys(t.t, alice)
	fundRespSpend := fundPacket(t, bob, tappsbt.ForInteractiveSend(
		id, fullAmt, aliceScriptKey, 0, lockTimeBlocks, 0,
		aliceInternalKey, asset.V0, chainParams,
	))

	// We don't need to sign anything as our csv script is anyone can spend.
	fundedPsbtSpend, err := tappsbt.Decode(fundRespSpend.FundedPsbt)
	require.NoError(t.t, err)
	controlBlockBytes, err := tapscript.ControlBlock.ToBytes()
	require.NoError(t.t, err)
	senderOut := fundedPsbtSpend.Outputs[0].Asset
	senderOut.PrevWitnesses[0].TxWitness = [][]byte{
		tapLeaf.Script, controlBlockBytes,
	}

	// We now create our spending transaction manually, but expect it to
	// fail, because it is not yet final.
	vPackets := []*tappsbt.VPacket{fundedPsbtSpend}
	btcPacket, err := tapsend.PrepareAnchoringTemplate(vPackets)
	require.NoError(t.t, err)

	btcPacket, _, _, _ = CommitVirtualPsbts(
		t.t, bob, btcPacket, vPackets, nil, -1,
	)
	btcPacket = signPacket(t.t, lndBob, btcPacket)
	btcPacket = FinalizePacket(t.t, lndBob.RPC, btcPacket)
	spendTx, err := psbt.Extract(btcPacket)
	require.NoError(t.t, err)

	var spendTxBuf bytes.Buffer
	require.NoError(t.t, spendTx.Serialize(&spendTxBuf))
	_, err = lndBob.RPC.WalletKit.PublishTransaction(
		ctxt, &walletrpc.Transaction{
			TxHex: spendTxBuf.Bytes(),
		},
	)
	require.ErrorContains(t.t, err, "non BIP68 final")
	t.lndHarness.Miner().AssertNumTxsInMempool(0)

	// After mining a single block, the error should go away.
	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 0)

	// Now we'll attempt to complete the transfer normally, which should
	// succeed.
	signedPsbtBytes, err := tappsbt.Encode(fundedPsbtSpend)
	require.NoError(t.t, err)
	sendRespSpend, err := bob.AnchorVirtualPsbts(
		ctxt, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signedPsbtBytes},
		},
	)
	require.NoError(t.t, err)

	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, bob,
		sendRespSpend, genInfo.AssetId, amounts, currentTransferIdx,
		numTransfers, numOutputs,
	)

	// Make sure the transfer shows the lock time.
	resp, err := bob.ListTransfers(ctxb, &taprpc.ListTransfersRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, resp.Transfers, numTransfers)
	require.EqualValues(
		t.t, lockTimeBlocks,
		resp.Transfers[0].Outputs[0].RelativeLockTime,
	)
	require.EqualValues(t.t, 0, resp.Transfers[0].Outputs[0].LockTime)

	// This is an interactive transfer, so we do need to manually
	// send the proof from the sender to the receiver.
	sendProof(
		t, bob, alice, sendRespSpend,
		aliceScriptKey.PubKey.SerializeCompressed(), genInfo,
	)

	spendOuts := assertNumAssetOutputs(t.t, alice, genInfo.AssetId, 1)
	assertNumAssetOutputs(t.t, bob, genInfo.AssetId, 0)

	// Does the asset also show the correct lock times?
	require.EqualValues(t.t, 0, spendOuts[0].LockTime)
	require.EqualValues(t.t, lockTimeBlocks, spendOuts[0].RelativeLockTime)
}

// testPsbtRelativeLockTimeSendProofFail tests that we can send minted assets
// into a ScriptKey encumbered with a relative (CSV) lock time, and get an error
// in the proof validation (resulting in a bricked asset) if we manually
// overwrite the lock time in the anchor transaction.
func testPsbtRelativeLockTimeSendProofFail(t *harnessTest) {
	// First, we'll make a normal asset with a bunch of units that we are
	// going to send. We're also minting a passive asset that should remain
	// where it is.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
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

	const lockTimeBlocks = 6

	mintedAsset := rpcAssets[0]
	genInfo := mintedAsset.AssetGenesis

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bob := setupTapdHarness(t.t, t, lndBob, t.universeServer)
	defer func() {
		require.NoError(t.t, bob.stop(!*noDelete))
	}()

	var (
		alice       = t.tapd
		id          [32]byte
		fullAmt     = mintedAsset.Amount
		chainParams = &address.RegressionNetTap
	)
	copy(id[:], genInfo.AssetId)

	// We need to derive two keys, one for the new script key and one for
	// the internal key.
	bobScriptKey, bobInternalKey := DeriveKeys(t.t, bob)

	// Bob creates a pkScript that will be used to lock the assets.
	tapLeaf := test.ScriptCsv(t.t, lockTimeBlocks)
	tapscript := input.TapscriptFullTree(bobScriptKey.PubKey, tapLeaf)
	rootHash := tapscript.ControlBlock.RootHash(tapLeaf.Script)
	tweakedTaprootKeyBob, err := tapscript.TaprootKey()
	require.NoError(t.t, err)

	keyDescriptorBob := keychain.KeyDescriptor{
		PubKey: tweakedTaprootKeyBob,
	}

	bobAssetScriptKey := asset.ScriptKey{
		PubKey: tweakedTaprootKeyBob,
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: keyDescriptorBob,
			Tweak:  rootHash,
		},
	}

	// We need to let the wallet of Bob know that we're going to use a
	// script key with a custom root.
	_, err = bob.DeclareScriptKey(ctxt, &wrpc.DeclareScriptKeyRequest{
		ScriptKey: taprpc.MarshalScriptKey(bobAssetScriptKey),
	})
	require.NoError(t.t, err)

	fundRespLock := fundPacket(t, alice, tappsbt.ForInteractiveSend(
		id, fullAmt, bobAssetScriptKey, 0, 0, 0, bobInternalKey,
		asset.V0, chainParams,
	))

	// We now sign the vPSBT.
	signRespLock, err := alice.SignVirtualPsbt(
		ctxt, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundRespLock.FundedPsbt,
		},
	)
	require.NoError(t.t, err)

	// Now we'll attempt to complete the transfer.
	sendResp, err := alice.AnchorVirtualPsbts(
		ctxt, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signRespLock.SignedPsbt},
		},
	)
	require.NoError(t.t, err)

	var (
		amounts            = []uint64{fullAmt}
		currentTransferIdx = 0
		numTransfers       = 1
		numOutputs         = len(amounts)
	)
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, alice,
		sendResp, genInfo.AssetId, amounts, currentTransferIdx,
		numTransfers, numOutputs,
	)

	// This is an interactive transfer, so we do need to manually
	// send the proof from the sender to the receiver.
	sendProof(
		t, alice, bob, sendResp,
		bobAssetScriptKey.PubKey.SerializeCompressed(), genInfo,
	)

	assertNumAssetOutputs(t.t, alice, genInfo.AssetId, 0)
	assertNumAssetOutputs(t.t, bob, genInfo.AssetId, 1)

	// We mine just 4 blocks, two short of being enough for the relative
	// time lock.
	MineBlocks(t.t, t.lndHarness.Miner().Client, 4, 0)

	// Now if we spend Bob's asset, we should see a lock time in the anchor
	// transaction. For that, we need to derive two keys for Alice, one for
	// the new script key and one for the internal key.
	aliceScriptKey, aliceInternalKey := DeriveKeys(t.t, alice)
	fundRespSpend := fundPacket(t, bob, tappsbt.ForInteractiveSend(
		id, fullAmt, aliceScriptKey, 0, lockTimeBlocks, 0,
		aliceInternalKey, asset.V0, chainParams,
	))

	// We don't need to sign anything as our csv script is anyone can spend.
	fundedPsbtSpend, err := tappsbt.Decode(fundRespSpend.FundedPsbt)
	require.NoError(t.t, err)
	controlBlockBytes, err := tapscript.ControlBlock.ToBytes()
	require.NoError(t.t, err)
	senderOut := fundedPsbtSpend.Outputs[0].Asset
	senderOut.PrevWitnesses[0].TxWitness = [][]byte{
		tapLeaf.Script, controlBlockBytes,
	}

	// We now create our spending transaction manually, but expect it to
	// fail, because it is not yet final.
	vPackets := []*tappsbt.VPacket{fundedPsbtSpend}
	btcPacket, err := tapsend.PrepareAnchoringTemplate(vPackets)
	require.NoError(t.t, err)

	btcPacket, vPackets, _, commitResp := CommitVirtualPsbts(
		t.t, bob, btcPacket, vPackets, nil, -1,
	)
	btcPacketTimeLocked := signPacket(t.t, lndBob, btcPacket)
	btcPacketTimeLocked = FinalizePacket(
		t.t, lndBob.RPC, btcPacketTimeLocked,
	)
	spendTxTimeLocked, err := psbt.Extract(btcPacketTimeLocked)
	require.NoError(t.t, err)

	var spendTxBuf bytes.Buffer
	require.NoError(t.t, spendTxTimeLocked.Serialize(&spendTxBuf))
	_, err = lndBob.RPC.WalletKit.PublishTransaction(
		ctxt, &walletrpc.Transaction{
			TxHex: spendTxBuf.Bytes(),
		},
	)
	require.ErrorContains(t.t, err, "non BIP68 final")
	t.lndHarness.Miner().AssertNumTxsInMempool(0)

	// We now do something very stupid and dangerous (don't try this at
	// home) and manually overwrite the lock time in the anchor transaction.
	// This should result in us being able to broadcast the transaction, but
	// will effectively brick the asset in the process, because the
	// asset-level VM verification of the lock time will fail.
	for idx := range btcPacket.UnsignedTx.TxIn {
		btcPacket.UnsignedTx.TxIn[idx].Sequence = 0
	}

	btcPacket = signPacket(t.t, lndBob, btcPacket)
	btcPacket = FinalizePacket(t.t, lndBob.RPC, btcPacket)
	spendTxTimeLocked, err = psbt.Extract(btcPacket)
	require.NoError(t.t, err)

	spendTxBuf.Reset()
	require.NoError(t.t, spendTxTimeLocked.Serialize(&spendTxBuf))
	_, err = lndBob.RPC.WalletKit.PublishTransaction(
		ctxt, &walletrpc.Transaction{
			TxHex: spendTxBuf.Bytes(),
		},
	)
	require.NoError(t.t, err)
	t.lndHarness.Miner().AssertNumTxsInMempool(1)

	ctxc, streamCancel := context.WithCancel(ctxb)
	aliceScriptKeyBytes := aliceScriptKey.PubKey.SerializeCompressed()
	stream, err := bob.SubscribeSendEvents(
		ctxc, &taprpc.SubscribeSendEventsRequest{
			FilterScriptKey: aliceScriptKeyBytes,
		},
	)
	require.NoError(t.t, err)
	sendEvents := &EventSubscription[*taprpc.SendEvent]{
		ClientEventStream: stream,
		Cancel:            streamCancel,
	}

	LogAndPublish(t.t, bob, btcPacket, vPackets, nil, commitResp)

	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	AssertSendEvents(
		t.t, aliceScriptKeyBytes, sendEvents,
		tapfreighter.SendStateStorePreBroadcast,
		tapfreighter.SendStateWaitTxConf,
	)

	msg, err := stream.Recv()
	require.NoError(t.t, err)
	require.Contains(t.t, msg.Error, "un-finalized asset")
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
			PubKey: schnorr.SerializePubKey(bobAssetScriptKey),
			KeyDesc: taprpc.MarshalKeyDescriptor(
				bobScriptKey.RawKey,
			),
			TapTweak: rootHash,
		},
		InternalKey: taprpc.MarshalKeyDescriptor(bobInternalKey),
	})

	require.NoError(t.t, err)
	AssertAddrCreated(t.t, bob, mintedAsset, bobAddr)

	// Send the asset to Bob using the script key with an actual script
	// tree.
	sendResp, sendEvents := sendAssetsToAddr(t, alice, bobAddr)

	changeUnits := mintedAsset.Amount - numUnits
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, alice, sendResp,
		genInfo.AssetId, []uint64{changeUnits, numUnits}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, bob, 1)
	AssertSendEventsComplete(t.t, bobAddr.ScriptKey, sendEvents)
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
	sendResp, sendEvents := sendAssetsToAddr(t, alice, bobAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, alice, sendResp,
		genInfo.AssetId, []uint64{change, numUnits}, outTransferIdx,
		numOutTransfers,
	)

	// There are now two receive events (since only non-interactive sends
	// appear in that RPC output).
	AssertNonInteractiveRecvComplete(t.t, bob, numInTransfers)
	AssertSendEventsComplete(t.t, bobAddr.ScriptKey, sendEvents)
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

// getAddressBip32Derivation returns the PSBT BIP-0032 derivation info of an
// address.
func getAddressBip32Derivation(t testing.TB, addr string,
	node *node.HarnessNode) (*psbt.Bip32Derivation,
	*psbt.TaprootBip32Derivation) {

	// We can't query a single address directly, so we just query all wallet
	// addresses.
	addresses := node.RPC.ListAddresses(
		&walletrpc.ListAddressesRequest{},
	)

	var (
		path        []uint32
		pubKeyBytes []byte
		err         error
	)
	for _, account := range addresses.AccountWithAddresses {
		for _, address := range account.Addresses {
			if address.Address == addr {
				path, err = lntest.ParseDerivationPath(
					address.DerivationPath,
				)
				require.NoError(t, err)

				pubKeyBytes = address.PublicKey
			}
		}
	}

	if len(path) != 5 || len(pubKeyBytes) == 0 {
		t.Fatalf("Derivation path for address %s not found or invalid",
			addr)
	}

	// The actual derivation path in a PSBT needs to be using the hardened
	// uint32 notation for the first three elements.
	path[0] += hdkeychain.HardenedKeyStart
	path[1] += hdkeychain.HardenedKeyStart
	path[2] += hdkeychain.HardenedKeyStart

	return &psbt.Bip32Derivation{
			PubKey:    pubKeyBytes,
			Bip32Path: path,
		}, &psbt.TaprootBip32Derivation{
			XOnlyPubKey: pubKeyBytes[1:],
			Bip32Path:   path,
		}
}
