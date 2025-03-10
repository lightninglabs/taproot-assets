package itest

import (
	"bytes"
	"context"

	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/stretchr/testify/require"
)

var (
	dummyMetaData = &taprpc.AssetMeta{
		Data: []byte("some metadata"),
	}
	assetXTranche1Req = &mintrpc.MintAsset{
		AssetType:       taprpc.AssetType_NORMAL,
		Name:            "itest-asset-X-tranche-1",
		AssetMeta:       dummyMetaData,
		Amount:          300,
		NewGroupedAsset: true,
	}
	assetXTranche2Req = &mintrpc.MintAsset{
		AssetType:    taprpc.AssetType_NORMAL,
		Name:         "itest-asset-X-tranche-2",
		AssetMeta:    dummyMetaData,
		Amount:       300,
		GroupedAsset: true,
		GroupAnchor:  "itest-asset-X-tranche-1",
	}
	assetXTranche3Req = &mintrpc.MintAsset{
		AssetType: taprpc.AssetType_NORMAL,
		Name:      "itest-asset-X-tranche-3",
		AssetMeta: dummyMetaData,
		Amount:    300,
		// This is going to be in the second batch, the group key from
		// batch 1 will be added during the test.
		GroupedAsset: true,
	}

	assetYTranche1Req = &mintrpc.MintAsset{
		AssetType:       taprpc.AssetType_NORMAL,
		Name:            "itest-asset-Y-tranche-1",
		AssetMeta:       dummyMetaData,
		Amount:          400,
		NewGroupedAsset: true,
	}
	assetYTranche2Req = &mintrpc.MintAsset{
		AssetType:    taprpc.AssetType_NORMAL,
		Name:         "itest-asset-Y-tranche-2",
		AssetMeta:    dummyMetaData,
		Amount:       400,
		GroupedAsset: true,
		GroupAnchor:  "itest-asset-Y-tranche-1",
	}
	assetYTranche3Req = &mintrpc.MintAsset{
		AssetType: taprpc.AssetType_NORMAL,
		Name:      "itest-asset-Y-tranche-3",
		AssetMeta: dummyMetaData,
		Amount:    400,
		// This is going to be in the second batch, the group key from
		// batch 1 will be added during the test.
		GroupedAsset: true,
	}

	assetPReq = &mintrpc.MintAsset{
		AssetType: taprpc.AssetType_NORMAL,
		Name:      "itest-asset-P",
		AssetMeta: dummyMetaData,
		Amount:    5000,
	}
	assetQReq = &mintrpc.MintAsset{
		AssetType: taprpc.AssetType_NORMAL,
		Name:      "itest-asset-Q",
		AssetMeta: dummyMetaData,
		Amount:    5000,
	}
	chainParams = &address.RegressionNetTap
)

// testAnchorMultipleVirtualTransactions tests that we can spend assets from
// multiple anchor outputs in a single virtual transaction, resulting in an
// on-chain transaction with multiple asset inputs.
func testAnchorMultipleVirtualTransactions(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// In our first batch we create multiple units of the grouped asset X
	// and Y as well as a passive asset P.
	firstBatch := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			{
				Asset: assetXTranche1Req,
			},
			{
				Asset: assetXTranche2Req,
			},
			{
				Asset: assetYTranche1Req,
			},
			{
				Asset: assetYTranche2Req,
			},
			{
				Asset: assetPReq,
			},
		},
	)

	groupKeyX := firstBatch[0].AssetGroup.TweakedGroupKey
	assetXTranche3Req.GroupKey = groupKeyX

	groupKeyY := firstBatch[2].AssetGroup.TweakedGroupKey
	assetYTranche3Req.GroupKey = groupKeyY

	// In our second batch we create the third tranche of the grouped asset
	// X and Y as well as a passive asset Q.
	secondBatch := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			{
				Asset: assetXTranche3Req,
			},
			{
				Asset: assetYTranche3Req,
			},
			{
				Asset: assetQReq,
			},
		},
	)

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	var (
		aliceTapd = t.tapd
		aliceLnd  = aliceTapd.cfg.LndNode
		bobTapd   = secondTapd
	)

	// We now want to send all units of X to Bob. Since we can't yet select
	// coins by just group key, we just ask for all units of tranche 1 and
	// then promote some of the passive assets to active assets.
	scriptKey1, anchorInternalKeyDesc1 := DeriveKeys(t.t, bobTapd)
	var (
		assetXTranche1   = firstBatch[0]
		assetXTranche2   = firstBatch[1]
		assetYTranche1   = firstBatch[2]
		assetP           = firstBatch[4]
		assetXTranche3   = secondBatch[0]
		assetQ           = secondBatch[2]
		assetXTranche1ID asset.ID
		assetXTranche3ID asset.ID
	)
	copy(assetXTranche1ID[:], assetXTranche1.AssetGenesis.AssetId)
	copy(assetXTranche3ID[:], assetXTranche3.AssetGenesis.AssetId)

	vPktFirstBatch := tappsbt.ForInteractiveSend(
		assetXTranche1ID, assetXTranche1.Amount, scriptKey1, 0, 0, 0,
		anchorInternalKeyDesc1, asset.V0, chainParams,
	)
	fundRespFirstBatch := fundPacket(t, aliceTapd, vPktFirstBatch)

	// Now we collect all the active assets, which are all tranches of
	// asset X.
	activePackets := make([]*tappsbt.VPacket, 0, 3)
	tranche1, err := tappsbt.Decode(fundRespFirstBatch.FundedPsbt)
	require.NoError(t.t, err)
	activePackets = append(activePackets, tranche1)

	for _, packetBytes := range fundRespFirstBatch.PassiveAssetPsbts {
		passivePacket, err := tappsbt.Decode(packetBytes)
		require.NoError(t.t, err)

		passiveAssetID, err := passivePacket.AssetID()
		require.NoError(t.t, err)

		if bytes.Equal(
			passiveAssetID[:], assetXTranche2.AssetGenesis.AssetId,
		) {

			activePackets = append(activePackets, passivePacket)
		}
	}

	vPktSecondBatch := tappsbt.ForInteractiveSend(
		assetXTranche3ID, assetXTranche3.Amount, scriptKey1, 0, 0, 0,
		anchorInternalKeyDesc1, asset.V0, chainParams,
	)
	fundRespSecondBatch := fundPacket(t, aliceTapd, vPktSecondBatch)
	tranche3, err := tappsbt.Decode(fundRespSecondBatch.FundedPsbt)
	require.NoError(t.t, err)

	activePackets = append(activePackets, tranche3)

	// We now need to update the outputs of the passive packets to also go
	// to Bob. With this, we're promoting those passive assets to active
	// assets. Which means they should get an entry in the transfer output
	// table.
	scriptKeys := []asset.ScriptKey{scriptKey1}
	for idx, activePacket := range activePackets {
		if idx > 0 {
			scriptKey, _ := DeriveKeys(t.t, bobTapd)
			activePacket.Outputs[0].ScriptKey = scriptKey
			activePacket.Outputs[0].Asset.ScriptKey = scriptKey
			scriptKeys = append(scriptKeys, scriptKey)
		}

		activePacket.Outputs[0].AnchorOutputBip32Derivation = nil
		activePacket.Outputs[0].AnchorOutputTaprootBip32Derivation = nil
		activePacket.Outputs[0].SetAnchorInternalKey(
			anchorInternalKeyDesc1, chainParams.HDCoinType,
		)
		activePacket.Outputs[0].AnchorOutputIndex = 0
	}

	// Let's now sign all the active packets.
	signedPackets := make([][]byte, len(activePackets))
	for idx := range activePackets {
		signedPacket := signVirtualPacket(
			t.t, aliceTapd, activePackets[idx],
		)

		signedPackets[idx], err = tappsbt.Encode(signedPacket)
		require.NoError(t.t, err)
	}

	// Now we'll attempt to complete the transfer.
	sendResp, err := aliceTapd.AnchorVirtualPsbts(
		ctxt, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: signedPackets,
		},
	)
	require.NoError(t.t, err)

	// We'll attempt to list assets immediately after initiating the
	// transfer. The unconfirmed assets should not be listed yet, but the
	// unconfirmed transfer count should be 1.
	aliceAssets, err := aliceTapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Nil(t.t, aliceAssets.Assets)
	require.EqualValues(t.t, aliceAssets.UnconfirmedTransfers, 1)

	t.Logf("Send response: %v", toJSON(t.t, sendResp))

	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, aliceTapd, sendResp,
		assetXTranche1ID[:], []uint64{300, 300, 300}, 0, 1, 3,
	)

	// This is an interactive transfer, so we do need to manually send the
	// proofs from the sender to the receiver.
	sendProof(
		t, aliceTapd, bobTapd, sendResp,
		scriptKeys[0].PubKey.SerializeCompressed(),
		assetXTranche1.AssetGenesis,
	)
	sendProof(
		t, aliceTapd, bobTapd, sendResp,
		scriptKeys[1].PubKey.SerializeCompressed(),
		assetXTranche2.AssetGenesis,
	)
	sendProof(
		t, aliceTapd, bobTapd, sendResp,
		scriptKeys[2].PubKey.SerializeCompressed(),
		assetXTranche3.AssetGenesis,
	)

	aliceAssets, err = aliceTapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, aliceAssets.Assets, 5)

	t.Logf("Alice assets: %v", toJSON(t.t, aliceAssets))

	bobAssets, err := bobTapd.ListAssets(ctxt, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, bobAssets.Assets, 3)

	t.Logf("Bob assets: %v", toJSON(t.t, bobAssets))

	// Next, we make sure we can still send out the passive assets. Since
	// the sendAndAsset function does a non-interactive send to a TAP
	// address, and we're sending the full amount, this should leave a
	// tombstone in both those anchors. We'll then make sure that we can
	// still send out the assets that are in the same commitment as the
	// tombstones, using the CommitVirtualPsbts method.
	sendAssetAndAssert(
		ctxt, t, aliceTapd, bobTapd, assetP.Amount, 0,
		assetP.AssetGenesis, assetP, 1, 2, 1,
	)
	sendAssetAndAssert(
		ctxt, t, aliceTapd, bobTapd, assetQ.Amount, 0,
		assetQ.AssetGenesis, assetQ, 2, 3, 2,
	)

	// Fund a new packet for sending asset Y from tranche 1 to Bob.
	assetsToSend := uint64(100)
	bobAddr, err := bobTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: assetYTranche1.AssetGenesis.AssetId,
		Amt:     assetsToSend,
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

	// We expect two passive assets to be returned: Tranche 2 and tranche 3
	// of asset Y, since they were combined into a single output in the
	// previous transaction.
	require.Equal(t.t, 2, len(fundResp.PassiveAssetPsbts))

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

	btcPacket = signPacket(t.t, aliceLnd, btcPacket)
	btcPacket = FinalizePacket(t.t, aliceLnd.RPC, btcPacket)
	sendResp = LogAndPublish(
		t.t, aliceTapd, btcPacket, activeAssets, passiveAssets,
		commitResp,
	)

	expectedAmounts := []uint64{
		assetYTranche1.Amount - assetsToSend, assetsToSend,
	}
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, aliceTapd,
		sendResp, assetYTranche1.AssetGenesis.AssetId, expectedAmounts,
		3, 4, len(expectedAmounts),
	)

	// And now the event should be completed on both sides.
	AssertAddrEvent(t.t, bobTapd, bobAddr, 1, statusCompleted)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 3)
	AssertBalanceByID(
		t.t, bobTapd, assetYTranche1.AssetGenesis.AssetId, assetsToSend,
	)
}
