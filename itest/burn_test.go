package itest

import (
	"bytes"
	"context"
	"encoding/hex"

	taprootassets "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// testBurnAssets tests that we're able to mint assets and then burn assets
// again.
func testBurnAssets(t *harnessTest) {
	minerClient := t.lndHarness.Miner().Client
	rpcAssets := MintAssetsConfirmBatch(
		t.t, minerClient, t.tapd, []*mintrpc.MintAssetRequest{
			simpleAssets[0], simpleAssets[1], issuableAssets[0],
			issuableAssets[1],
		},
	)

	// We first fan out the assets we have to different outputs.
	var (
		chainParams           = &address.RegressionNetTap
		simpleAsset           = rpcAssets[0]
		simpleCollectible     = rpcAssets[1]
		simpleGroup           = rpcAssets[2]
		simpleGroupCollect    = rpcAssets[3]
		simpleAssetGen        = simpleAsset.AssetGenesis
		simpleCollectibleGen  = simpleCollectible.AssetGenesis
		simpleGroupGen        = simpleGroup.AssetGenesis
		simpleGroupCollectGen = simpleGroupCollect.AssetGenesis
		simpleAssetID         [32]byte
	)
	copy(simpleAssetID[:], simpleAssetGen.AssetId)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Preparation: We derive a couple of keys, so we can spread out our
	// assets over several outputs, which we are going to use for the first
	// couple of test cases.
	scriptKey1, anchorInternalKeyDesc1 := DeriveKeys(t.t, t.tapd)
	scriptKey2, anchorInternalKeyDesc2 := DeriveKeys(t.t, t.tapd)
	scriptKey3, anchorInternalKeyDesc3 := DeriveKeys(t.t, t.tapd)
	scriptKey4, _ := DeriveKeys(t.t, t.tapd)

	// We create the following outputs:
	// 	anchor index 0 (anchor internal key 1):
	//		- 1100 units to scriptKey1
	//		- 1200 units to scriptKey2
	// 	anchor index 1 (anchor internal key 2):
	// 		- 1600 units to scriptKey3
	// 	anchor index 2 (anchor internal key 3):
	// 		- 800 units to scriptKey4
	// 	anchor index 3 (automatic change output):
	// 		- 300 units to new script key
	outputAmounts := []uint64{300, 1100, 1200, 1600, 800}
	vPkt := tappsbt.ForInteractiveSend(
		simpleAssetID, outputAmounts[1], scriptKey1, 0, 0, 0,
		anchorInternalKeyDesc1, asset.V0, chainParams,
	)
	tappsbt.AddOutput(
		vPkt, outputAmounts[2], scriptKey2, 0, anchorInternalKeyDesc1,
		asset.V0,
	)
	tappsbt.AddOutput(
		vPkt, outputAmounts[3], scriptKey3, 1, anchorInternalKeyDesc2,
		asset.V0,
	)
	tappsbt.AddOutput(
		vPkt, outputAmounts[4], scriptKey4, 2, anchorInternalKeyDesc3,
		asset.V0,
	)

	// We end up with a transfer with 5 outputs: 2 grouped into the first
	// anchor output and then 3 each in their own output. So there are 4 BTC
	// anchor outputs but 5 asset transfer outputs which we are now going to
	// sign for and then finalize the transfer.
	numOutputs := 5
	fundResp := fundPacket(t, t.tapd, vPkt)
	signResp, err := t.tapd.SignVirtualPsbt(
		ctxt, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundResp.FundedPsbt,
		},
	)
	require.NoError(t.t, err)
	sendResp, err := t.tapd.AnchorVirtualPsbts(
		ctxt, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signResp.SignedPsbt},
		},
	)
	require.NoError(t.t, err)
	ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, minerClient, t.tapd, sendResp, simpleAssetGen.AssetId,
		outputAmounts, 0, 1, numOutputs,
	)

	// Let's make sure that we still have the original number of assets as
	// seen by our wallet balance.
	AssertBalanceByID(
		t.t, t.tapd, simpleAssetGen.AssetId, simpleAsset.Amount,
	)

	// Test case 1: We'll now try to the exact amount of the largest output,
	// which should still select exactly that one largest output, which is
	// located alone in an anchor output. When attempting to burn this, we
	// should get an error saying that we cannot completely burn all assets
	// in an output.
	_, err = t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: simpleAssetID[:],
		},
		AmountToBurn:     outputAmounts[3],
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.ErrorContains(
		t.t, err, tapfreighter.ErrFullBurnNotSupported.Error(),
	)

	// Test case 2: We'll now try to burn a small amount of assets, which
	// should select the largest output, which is located alone in an anchor
	// output.
	const (
		burnAmt  = 100
		burnNote = "blazeit"
	)

	burnResp, err := t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: simpleAssetID[:],
		},
		AmountToBurn:     burnAmt,
		Note:             burnNote,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	burnRespJSON, err := formatProtoJSON(burnResp)
	require.NoError(t.t, err)
	t.Logf("Got response from burning %d units: %v", burnAmt, burnRespJSON)

	AssertAssetOutboundTransferWithOutputs(
		t.t, minerClient, t.tapd, burnResp.BurnTransfer,
		simpleAssetGen.AssetId,
		[]uint64{outputAmounts[3] - burnAmt, burnAmt}, 1, 2, 2, true,
	)

	// We'll now assert that the burned asset has the correct state.
	burnedAsset := burnResp.BurnProof.Asset
	allAssets, err := t.tapd.ListAssets(ctxt, &taprpc.ListAssetRequest{
		IncludeSpent:  true,
		ScriptKeyType: allScriptKeysQuery,
	})
	require.NoError(t.t, err)
	AssertAssetStateByScriptKey(
		t.t, allAssets.Assets, burnedAsset.ScriptKey,
		AssetAmountCheck(burnedAsset.Amount),
		AssetTypeCheck(burnedAsset.AssetGenesis.AssetType),
		AssetScriptKeyIsLocalCheck(false),
		AssetScriptKeyIsBurnCheck(true),
	)
	AssertBalances(
		t.t, t.tapd, burnAmt, WithNumUtxos(1), WithNumAnchorUtxos(1),
		WithScriptKeyType(asset.ScriptKeyBurn),
	)

	// And now our asset balance should have been decreased by the burned
	// amount.
	AssertBalanceByID(
		t.t, t.tapd, simpleAssetGen.AssetId, simpleAsset.Amount-burnAmt,
	)

	burns := AssertNumBurns(t.t, t.tapd, 1, nil)
	burn := burns[0]
	require.Equal(t.t, uint64(burnAmt), burn.Amount)
	require.Equal(t.t, burnResp.BurnTransfer.AnchorTxHash, burn.AnchorTxid)
	require.Equal(t.t, burn.AssetId, simpleAssetID[:])
	require.Equal(t.t, burn.Note, burnNote)

	// The burned asset should be pruned from the tree when we next spend
	// the anchor output it was in (together with the change). So let's test
	// that we can successfully spend the change output.
	secondSendAmt := outputAmounts[3] - burnAmt
	fullSendAddr, stream := NewAddrWithEventStream(
		t.t, t.tapd, &taprpc.NewAddrRequest{
			AssetId: simpleAssetGen.AssetId,
			Amt:     secondSendAmt,
		},
	)
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, t.tapd, simpleAsset, fullSendAddr)
	sendResp, sendEvents := sendAssetsToAddr(t, t.tapd, fullSendAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, minerClient, t.tapd, sendResp, simpleAssetGen.AssetId,
		[]uint64{0, secondSendAmt}, 2, 3,
	)
	AssertNonInteractiveRecvComplete(t.t, t.tapd, 1)
	AssertReceiveEvents(t.t, fullSendAddr, stream)

	// Test case 3: Burn all assets of one asset ID (in this case a single
	// collectible from the original mint TX), while there are other,
	// passive assets in the anchor output.
	burnResp, err = t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: simpleCollectibleGen.AssetId,
		},
		AmountToBurn:     simpleCollectible.Amount,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	burnRespJSON, err = formatProtoJSON(burnResp)
	require.NoError(t.t, err)
	t.Logf("Got response from burning all units: %v", burnRespJSON)

	AssertAssetOutboundTransferWithOutputs(
		t.t, minerClient, t.tapd, burnResp.BurnTransfer,
		simpleCollectibleGen.AssetId, []uint64{1}, 3, 4, 1, true,
	)
	AssertSendEventsComplete(t.t, fullSendAddr.ScriptKey, sendEvents)

	AssertBalances(
		t.t, t.tapd, burnAmt+simpleCollectible.Amount,
		WithNumUtxos(2), WithNumAnchorUtxos(2),
		WithScriptKeyType(asset.ScriptKeyBurn),
	)

	// Test case 4: Burn assets from multiple inputs. This will select the
	// two largest inputs we have, the one over 1500 we sent above and the
	// 1200 from the initial fan out transfer.
	const changeAmt = 300
	multiBurnAmt := outputAmounts[2] + secondSendAmt - changeAmt
	burnResp, err = t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: simpleAssetGen.AssetId,
		},
		AmountToBurn:     multiBurnAmt,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	burnRespJSON, err = formatProtoJSON(burnResp)
	require.NoError(t.t, err)
	t.Logf("Got response from burning units from multiple inputs: %v",
		burnRespJSON)

	AssertAssetOutboundTransferWithOutputs(
		t.t, minerClient, t.tapd, burnResp.BurnTransfer,
		simpleAssetGen.AssetId,
		[]uint64{changeAmt, multiBurnAmt}, 4, 5, 2, true,
	)

	// Our final asset balance should be reduced by both successful burn
	// amounts of the simple asset.
	AssertBalanceByID(
		t.t, t.tapd, simpleAssetGen.AssetId,
		simpleAsset.Amount-burnAmt-multiBurnAmt,
	)

	AssertBalances(
		t.t, t.tapd, burnAmt+simpleCollectible.Amount+multiBurnAmt,
		WithNumUtxos(3), WithNumAnchorUtxos(3),
		WithScriptKeyType(asset.ScriptKeyBurn),
	)

	resp, err := t.tapd.ListAssets(ctxt, &taprpc.ListAssetRequest{
		IncludeSpent: true,
	})
	require.NoError(t.t, err)
	assets, err := formatProtoJSON(resp)
	require.NoError(t.t, err)
	t.Logf("All assets before last burn: %v", assets)

	// Test case 5: Burn some units of a grouped asset. We start by making
	// sure we still have the full balance before burning.
	AssertBalanceByID(
		t.t, t.tapd, simpleGroupGen.AssetId, simpleGroup.Amount,
	)
	burnResp, err = t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: simpleGroupGen.AssetId,
		},
		AmountToBurn:     burnAmt,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	burnRespJSON, err = formatProtoJSON(burnResp)
	require.NoError(t.t, err)
	t.Logf("Got response from burning units from grouped asset: %v",
		burnRespJSON)

	AssertAssetOutboundTransferWithOutputs(
		t.t, minerClient, t.tapd, burnResp.BurnTransfer,
		simpleGroupGen.AssetId,
		[]uint64{simpleGroup.Amount - burnAmt, burnAmt}, 5, 6, 2, true,
	)
	AssertBalanceByID(
		t.t, t.tapd, simpleGroupGen.AssetId, simpleGroup.Amount-burnAmt,
	)

	AssertBalances(
		t.t, t.tapd,
		burnAmt+simpleCollectible.Amount+multiBurnAmt+burnAmt,
		WithNumUtxos(4), WithNumAnchorUtxos(4),
		WithScriptKeyType(asset.ScriptKeyBurn),
	)

	burns = AssertNumBurns(t.t, t.tapd, 4, nil)
	var groupBurn *taprpc.AssetBurn
	for _, b := range burns {
		if bytes.Equal(b.AssetId, simpleGroupGen.AssetId) {
			groupBurn = b
		}
	}

	// Keep track of the txhash of the anchor transaction that completed
	// this transfer. This will be used later to query burns with a txhash
	// filter.
	groupBurnTxHash := burnResp.BurnTransfer.AnchorTxHash

	require.Equal(t.t, uint64(burnAmt), groupBurn.Amount)
	require.Equal(
		t.t, burnResp.BurnTransfer.AnchorTxHash, groupBurn.AnchorTxid,
	)

	require.Equal(t.t, groupBurn.AssetId, simpleGroupGen.AssetId[:])
	require.Equal(
		t.t, groupBurn.TweakedGroupKey,
		simpleGroup.AssetGroup.TweakedGroupKey,
	)

	require.Equal(t.t, groupBurn.Note, "")

	// Test case 6: Burn the single unit of a grouped collectible. We start
	// by making sure we still have the full balance before burning.
	AssertBalanceByID(
		t.t, t.tapd, simpleGroupCollectGen.AssetId,
		simpleGroupCollect.Amount,
	)
	burnResp, err = t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: simpleGroupCollectGen.AssetId,
		},
		AmountToBurn:     1,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	burnRespJSON, err = formatProtoJSON(burnResp)
	require.NoError(t.t, err)
	t.Logf("Got response from burning units from grouped asset: %v",
		burnRespJSON)

	AssertAssetOutboundTransferWithOutputs(
		t.t, minerClient, t.tapd, burnResp.BurnTransfer,
		simpleGroupCollectGen.AssetId, []uint64{1}, 6, 7, 1, true,
	)
	AssertBalanceByID(t.t, t.tapd, simpleGroupCollectGen.AssetId, 0)

	AssertBalances(
		t.t, t.tapd,
		burnAmt+simpleCollectible.Amount+multiBurnAmt+burnAmt+1,
		WithNumUtxos(5), WithNumAnchorUtxos(5),
		WithScriptKeyType(asset.ScriptKeyBurn),
	)

	// We now perform some queries to test the filters of the ListBurns
	// call.

	// Fetch the burns related to the simple asset id, which should have a
	// total of 2 burns (tc1 & tc4).
	AssertNumBurns(t.t, t.tapd, 2, &taprpc.ListBurnsRequest{
		AssetId: simpleAssetGen.AssetId,
	})

	// Fetch the burns related to the group key of the grouped asset in tc5.
	// There should be 1 burn.
	AssertNumBurns(t.t, t.tapd, 1, &taprpc.ListBurnsRequest{
		TweakedGroupKey: simpleGroup.AssetGroup.TweakedGroupKey,
	})

	// Fetch the burns associated with the txhash of the burn in tc5. There
	// should be 1 burn returned.
	AssertNumBurns(t.t, t.tapd, 1, &taprpc.ListBurnsRequest{
		AnchorTxid: groupBurnTxHash,
	})
}

// testBurnGroupedAssets tests that some amount of an asset from an asset group
// can be burnt successfully.
func testBurnGroupedAssets(t *harnessTest) {
	var (
		ctxb  = context.Background()
		miner = t.lndHarness.Miner().Client

		firstMintReq = issuableAssets[0]
		burnNote     = "blazeit"
	)

	// We start off without any asset groups.
	AssertNumGroups(t.t, t.tapd, 0)

	// Next, we mint a re-issuable asset, creating a new asset group.
	firstMintResponses := MintAssetsConfirmBatch(
		t.t, miner, t.tapd, []*mintrpc.MintAssetRequest{firstMintReq},
	)
	require.Len(t.t, firstMintResponses, 1)

	var (
		firstMintResp = firstMintResponses[0]
		assetGroupKey = firstMintResp.AssetGroup.TweakedGroupKey
	)

	// Ensure that an asset group was created.
	AssertNumGroups(t.t, t.tapd, 1)

	// Issue a further asset into the asset group.
	simpleAssetsCopy := CopyRequests(simpleAssets)
	secondMintReq := simpleAssetsCopy[0]
	secondMintReq.Asset.Amount = 1010
	secondMintReq.Asset.GroupKey = assetGroupKey
	secondMintReq.Asset.GroupedAsset = true

	secondMintResponses := MintAssetsConfirmBatch(
		t.t, miner, t.tapd,
		[]*mintrpc.MintAssetRequest{secondMintReq},
	)
	require.Len(t.t, secondMintResponses, 1)

	// Ensure that we haven't created a new group.
	AssertNumGroups(t.t, t.tapd, 1)

	secondMintResp := secondMintResponses[0]

	// Confirm that the minted asset group contains two assets.
	assetGroups, err := t.tapd.ListGroups(
		ctxb, &taprpc.ListGroupsRequest{},
	)
	require.NoError(t.t, err)

	encodedGroupKey := hex.EncodeToString(assetGroupKey)
	assetGroup := assetGroups.Groups[encodedGroupKey]
	require.Len(t.t, assetGroup.Assets, 2)

	// Burn some amount of the second asset.
	var (
		burnAssetID = secondMintResp.AssetGenesis.AssetId

		preBurnAmt  = secondMintResp.Amount
		burnAmt     = uint64(10)
		postBurnAmt = preBurnAmt - burnAmt
	)

	burnResp, err := t.tapd.BurnAsset(ctxb, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: burnAssetID,
		},
		AmountToBurn:     burnAmt,
		Note:             burnNote,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	burnRespJSON, err := formatProtoJSON(burnResp)
	require.NoError(t.t, err)
	t.Logf("Got response from burning %d units: %v", burnAmt, burnRespJSON)

	// Assert that the asset burn transfer occurred correctly.
	AssertAssetOutboundTransferWithOutputs(
		t.t, miner, t.tapd, burnResp.BurnTransfer,
		burnAssetID, []uint64{postBurnAmt, burnAmt}, 0, 1, 2, true,
	)

	// Ensure that the burnt asset has the correct state.
	burnedAsset := burnResp.BurnProof.Asset
	allAssets, err := t.tapd.ListAssets(ctxb, &taprpc.ListAssetRequest{
		IncludeSpent:  true,
		ScriptKeyType: allScriptKeysQuery,
	})
	require.NoError(t.t, err)
	AssertAssetStateByScriptKey(
		t.t, allAssets.Assets, burnedAsset.ScriptKey,
		AssetAmountCheck(burnedAsset.Amount),
		AssetTypeCheck(burnedAsset.AssetGenesis.AssetType),
		AssetScriptKeyIsLocalCheck(false),
		AssetScriptKeyIsBurnCheck(true),
	)

	// Our asset balance should have been decreased by the burned amount.
	AssertBalanceByID(t.t, t.tapd, burnAssetID, postBurnAmt)

	// Confirm that the minted asset group still contains two assets.
	assetGroups, err = t.tapd.ListGroups(ctxb, &taprpc.ListGroupsRequest{})
	require.NoError(t.t, err)

	encodedGroupKey = hex.EncodeToString(assetGroupKey)
	assetGroup = assetGroups.Groups[encodedGroupKey]
	require.Len(t.t, assetGroup.Assets, 2)

	burns, err := t.tapd.ListBurns(ctxb, &taprpc.ListBurnsRequest{
		TweakedGroupKey: assetGroupKey,
	})
	require.NoError(t.t, err)
	require.Len(t.t, burns.Burns, 1)

	burn := burns.Burns[0]

	require.Equal(t.t, burnAmt, burn.Amount)
	require.Equal(t.t, burnNote, burn.Note)
	require.Equal(t.t, assetGroupKey, burn.TweakedGroupKey)
}
