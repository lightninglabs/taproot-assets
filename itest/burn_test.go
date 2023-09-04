package itest

import (
	"context"

	taprootassets "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/address"
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
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tapd, []*mintrpc.MintAssetRequest{
			simpleAssets[0], simpleAssets[1], issuableAssets[1],
		},
	)

	// We first fan out the assets we have to different outputs.
	var (
		chainParams          = &address.RegressionNetTap
		simpleAsset          = rpcAssets[0]
		simpleCollectible    = rpcAssets[1]
		simpleAssetGen       = simpleAsset.AssetGenesis
		simpleCollectibleGen = simpleCollectible.AssetGenesis
		simpleAssetID        [32]byte
	)
	copy(simpleAssetID[:], simpleAssetGen.AssetId)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Preparation: We derive a couple of keys, so we can spread out our
	// assets over several outputs, which we are going to use for the first
	// couple of test cases.
	scriptKey1, anchorInternalKeyDesc1 := deriveKeys(t.t, t.tapd)
	scriptKey2, anchorInternalKeyDesc2 := deriveKeys(t.t, t.tapd)
	scriptKey3, anchorInternalKeyDesc3 := deriveKeys(t.t, t.tapd)
	scriptKey4, _ := deriveKeys(t.t, t.tapd)

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
	outputAmounts := []uint64{1100, 1200, 1600, 800, 300}
	vPkt := tappsbt.ForInteractiveSend(
		simpleAssetID, outputAmounts[0], scriptKey1, 0, anchorInternalKeyDesc1,
		chainParams,
	)
	tappsbt.AddOutput(
		vPkt, outputAmounts[1], scriptKey2, 0, anchorInternalKeyDesc1,
	)
	tappsbt.AddOutput(
		vPkt, outputAmounts[2], scriptKey3, 1, anchorInternalKeyDesc2,
	)
	tappsbt.AddOutput(
		vPkt, outputAmounts[3], scriptKey4, 2, anchorInternalKeyDesc3,
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
	confirmAndAssetOutboundTransferWithOutputs(
		t, t.tapd, sendResp, simpleAssetGen.AssetId, outputAmounts, 0, 1,
		numOutputs,
	)

	// Let's make sure that we still have the original number of assets as
	// seen by our wallet balance.
	AssertBalanceByID(t.t, t.tapd, simpleAssetGen.AssetId, simpleAsset.Amount)

	// Test case 1: We'll now try to the exact amount of the largest output,
	// which should still select exactly that one largest output, which is
	// located alone in an anchor output. When attempting to burn this, we
	// should get an error saying that we cannot completely burn all assets
	// in an output.
	_, err = t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: simpleAssetID[:],
		},
		AmountToBurn:     outputAmounts[2],
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.ErrorContains(
		t.t, err, tapfreighter.ErrFullBurnNotSupported.Error(),
	)

	// Test case 2: We'll now try to burn a small amount of assets, which
	// should select the largest output, which is located alone in an anchor
	// output.
	const burnAmt = 100
	burnResp, err := t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: simpleAssetID[:],
		},
		AmountToBurn:     burnAmt,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	burnRespJSON, err := formatProtoJSON(burnResp)
	require.NoError(t.t, err)
	t.Logf("Got response from burning %d units: %v", burnAmt, burnRespJSON)

	assertAssetOutboundTransferWithOutputs(
		t, t.tapd, burnResp.BurnTransfer, simpleAssetGen.AssetId,
		[]uint64{outputAmounts[2] - burnAmt, burnAmt}, 1, 2, 2, true,
	)

	// We'll now assert that the burned asset has the correct state.
	burnedAsset := burnResp.BurnProof.Asset
	allAssets, err := t.tapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{IncludeSpent: true},
	)
	require.NoError(t.t, err)
	AssertAssetStateByScriptKey(
		t.t, allAssets.Assets, burnedAsset.ScriptKey,
		assetAmountCheck(burnedAsset.Amount),
		assetTypeCheck(burnedAsset.AssetType),
		assetScriptKeyIsLocalCheck(false),
		assetScriptKeyIsBurnCheck(true),
	)

	// And now our asset balance should have been decreased by the burned
	// amount.
	AssertBalanceByID(
		t.t, t.tapd, simpleAssetGen.AssetId, simpleAsset.Amount-burnAmt,
	)

	// The burned asset should be pruned from the tree when we next spend
	// the anchor output it was in (together with the change). So let's test
	// that we can successfully spend the change output.
	secondSendAmt := outputAmounts[2] - burnAmt
	fullSendAddr, err := t.tapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId: simpleAssetGen.AssetId,
		Amt:     secondSendAmt,
	})
	require.NoError(t.t, err)

	assertAddrCreated(t.t, t.tapd, simpleAsset, fullSendAddr)
	sendResp = sendAssetsToAddr(t, t.tapd, fullSendAddr)
	confirmAndAssertOutboundTransfer(
		t, t.tapd, sendResp, simpleAssetGen.AssetId,
		[]uint64{0, secondSendAmt}, 2, 3,
	)
	AssertNonInteractiveRecvComplete(t.t, t.tapd, 1)

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

	assertAssetOutboundTransferWithOutputs(
		t, t.tapd, burnResp.BurnTransfer, simpleCollectibleGen.AssetId,
		[]uint64{1}, 3, 4, 1, true,
	)

	// Test case 4: Burn assets from multiple inputs. This will select the
	// two largest inputs we have, the one over 1500 we sent above and the
	// 1200 from the initial fan out transfer.
	const changeAmt = 300
	multiBurnAmt := outputAmounts[1] + secondSendAmt - changeAmt
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

	assertAssetOutboundTransferWithOutputs(
		t, t.tapd, burnResp.BurnTransfer, simpleAssetGen.AssetId,
		[]uint64{changeAmt, multiBurnAmt}, 4, 5, 2, true,
	)

	// Our final asset balance should be reduced by both successful burn
	// amounts of the simple asset.
	AssertBalanceByID(
		t.t, t.tapd, simpleAssetGen.AssetId,
		simpleAsset.Amount-burnAmt-multiBurnAmt,
	)
}
