package itest

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/btcsuite/btcd/wire"
	taprootassets "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
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

	// Test case 1: We'll now try to burn a small amount of assets, which
	// should select the largest output, which is located alone in an anchor
	// output.
	const (
		burnAmt  = 100
		burnNote = "blazeit"
	)

	burnResp, err := t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		AssetSpecifier: &taprpc.AssetSpecifier{
			Id: simpleAssetID[:],
		},
		AmountToBurn:     burnAmt,
		Note:             burnNote,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	AssertAssetOutboundTransferWithOutputs(
		t.t, minerClient, t.tapd, burnResp.BurnTransfer,
		[][]byte{simpleAssetGen.AssetId},
		[]uint64{outputAmounts[3] - burnAmt, burnAmt}, 1, 2, 2, true,
	)

	// We'll now assert that the burned asset has the correct state.
	burnedAsset := burnResp.BurnProofs[0].Asset
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

	// Test case 2: Burn all assets of one asset ID (in this case a single
	// collectible from the original mint TX), while there are other,
	// passive assets in the anchor output.
	burnResp, err = t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		AssetSpecifier: &taprpc.AssetSpecifier{
			Id: simpleCollectibleGen.AssetId,
		},
		AmountToBurn:     simpleCollectible.Amount,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	AssertAssetOutboundTransferWithOutputs(
		t.t, minerClient, t.tapd, burnResp.BurnTransfer,
		[][]byte{simpleCollectibleGen.AssetId}, []uint64{1}, 3, 4, 1,
		true,
	)
	AssertSendEventsComplete(t.t, fullSendAddr.ScriptKey, sendEvents)

	AssertBalances(
		t.t, t.tapd, burnAmt+simpleCollectible.Amount,
		WithNumUtxos(2), WithNumAnchorUtxos(2),
		WithScriptKeyType(asset.ScriptKeyBurn),
	)

	// Test case 3: Burn assets from multiple inputs. This will select the
	// two largest inputs we have, the one over 1500 we sent above and the
	// 1200 from the initial fan out transfer.
	const changeAmt = 300
	multiBurnAmt := outputAmounts[2] + secondSendAmt - changeAmt
	burnResp, err = t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		AssetSpecifier: &taprpc.AssetSpecifier{
			Id: simpleAssetGen.AssetId,
		},
		AmountToBurn:     multiBurnAmt,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	AssertAssetOutboundTransferWithOutputs(
		t.t, minerClient, t.tapd, burnResp.BurnTransfer,
		[][]byte{simpleAssetGen.AssetId},
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

	// Test case 4: Burn some units of a grouped asset. We start by making
	// sure we still have the full balance before burning.
	AssertBalanceByID(
		t.t, t.tapd, simpleGroupGen.AssetId, simpleGroup.Amount,
	)
	burnResp, err = t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		AssetSpecifier: &taprpc.AssetSpecifier{
			Id: simpleGroupGen.AssetId,
		},
		AmountToBurn:     burnAmt,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	AssertAssetOutboundTransferWithOutputs(
		t.t, minerClient, t.tapd, burnResp.BurnTransfer,
		[][]byte{simpleGroupGen.AssetId},
		[]uint64{simpleGroup.Amount - burnAmt, burnAmt}, 5, 6, 2, true,
	)
	AssertBalanceByID(
		t.t, t.tapd, simpleGroupGen.AssetId, simpleGroup.Amount-burnAmt,
	)

	// Depending on passive re-anchoring behavior, earlier burn outputs
	// might become spent when inputs are consolidated. We assert only
	// currently unspent burn outputs here.
	AssertBalances(
		t.t, t.tapd,
		burnAmt+multiBurnAmt+burnAmt,
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

	// Test case 5: Burn the single unit of a grouped collectible. We start
	// by making sure we still have the full balance before burning.
	AssertBalanceByID(
		t.t, t.tapd, simpleGroupCollectGen.AssetId,
		simpleGroupCollect.Amount,
	)
	burnResp, err = t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		AssetSpecifier: &taprpc.AssetSpecifier{
			Id: simpleGroupCollectGen.AssetId,
		},
		AmountToBurn:     1,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	AssertAssetOutboundTransferWithOutputs(
		t.t, minerClient, t.tapd, burnResp.BurnTransfer,
		[][]byte{simpleGroupCollectGen.AssetId}, []uint64{1}, 6, 7, 1,
		true,
	)
	AssertBalanceByID(t.t, t.tapd, simpleGroupCollectGen.AssetId, 0)

	AssertBalances(
		t.t, t.tapd,
		burnAmt+multiBurnAmt+burnAmt+1,
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
		burnAssetID1  = firstMintResp.AssetGenesis.AssetId
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

	totalAmt := firstMintResp.Amount + secondMintResp.Amount
	AssertBalanceByGroup(t.t, t.tapd, encodedGroupKey, totalAmt)

	// Test case 1: Burn by asset id.
	var (
		burnAssetID2 = secondMintResp.AssetGenesis.AssetId

		preBurnAmt  = secondMintResp.Amount
		burnAmt     = uint64(10)
		postBurnAmt = preBurnAmt - burnAmt
	)

	burnResp, err := t.tapd.BurnAsset(ctxb, &taprpc.BurnAssetRequest{
		AssetSpecifier: &taprpc.AssetSpecifier{
			Id: burnAssetID2,
		},
		AmountToBurn:     burnAmt,
		Note:             burnNote,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	// Assert that the asset burn transfer occurred correctly.
	AssertAssetOutboundTransferWithOutputs(
		t.t, miner, t.tapd, burnResp.BurnTransfer,
		[][]byte{burnAssetID2}, []uint64{postBurnAmt, burnAmt}, 0, 1, 2,
		true,
	)

	// Ensure that the burnt asset has the correct state.
	burnedAsset := burnResp.BurnProofs[0].Asset
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
	AssertBalanceByID(t.t, t.tapd, burnAssetID2, postBurnAmt)

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

	// Test case 2: Burn by group key to we select multiple inputs.
	// We burn the full amount.
	burnResp, err = t.tapd.BurnAsset(ctxb, &taprpc.BurnAssetRequest{
		AssetSpecifier: &taprpc.AssetSpecifier{
			GroupKey: assetGroupKey,
		},
		AmountToBurn:     totalAmt - burnAmt,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	// When burning by group key with multiple inputs,
	// the coin selection can vary. We verify that:
	// - There are 2 outputs total
	// - We burn all remaining balance.
	amounts := make([]uint64, len(burnResp.BurnTransfer.Outputs))
	for i, out := range burnResp.BurnTransfer.Outputs {
		amounts[i] = out.Amount
	}
	require.Len(t.t, amounts, 2)

	actualSum := uint64(0)
	for _, amt := range amounts {
		actualSum += amt
	}
	require.Equal(t.t, totalAmt-burnAmt, actualSum)

	AssertAssetOutboundTransferWithOutputs(
		t.t, miner, t.tapd, burnResp.BurnTransfer,
		[][]byte{burnAssetID1, burnAssetID2},
		amounts, 1, 2, 2, true,
	)
	AssertBalanceByGroup(t.t, t.tapd, encodedGroupKey, 0)
}

// testFullBurnUTXO tests that we can burn the full amount of an asset UTXO.
func testFullBurnUTXO(t *harnessTest) {
	minerClient := t.lndHarness.Miner().Client
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Test 1: Burn the full amount of a simple asset.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, minerClient, t.tapd, []*mintrpc.MintAssetRequest{
			simpleAssets[0],
		},
	)
	simpleAsset := rpcAssets[0]
	simpleAssetGen := simpleAsset.AssetGenesis
	var simpleAssetID [32]byte
	copy(simpleAssetID[:], simpleAssetGen.AssetId)

	AssertBalanceByID(
		t.t, t.tapd, simpleAssetGen.AssetId, simpleAsset.Amount,
	)

	// Perform a full burn of the asset.
	fullBurnAmt := simpleAsset.Amount
	burnResp, err := t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		AssetSpecifier: &taprpc.AssetSpecifier{
			Id: simpleAssetID[:],
		},
		AmountToBurn:     fullBurnAmt,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	AssertAssetOutboundTransferWithOutputs(
		t.t, minerClient, t.tapd, burnResp.BurnTransfer,
		[][]byte{simpleAssetGen.AssetId},
		[]uint64{fullBurnAmt}, 0, 1, 1, true,
	)
	AssertBalanceByID(t.t, t.tapd, simpleAssetGen.AssetId, 0)

	// Export and verify the burn proof for the simple asset.
	wop, err := wire.NewOutPointFromString(
		burnResp.BurnTransfer.Outputs[0].Anchor.Outpoint,
	)
	require.NoError(t.t, err)
	outpoint := &taprpc.OutPoint{Txid: wop.Hash[:], OutputIndex: wop.Index}

	proofResp := ExportProofFile(
		t.t, t.tapd,
		burnResp.BurnProofs[0].Asset.AssetGenesis.AssetId,
		burnResp.BurnProofs[0].Asset.ScriptKey,
		outpoint,
	)
	verifyResp, err := t.tapd.VerifyProof(ctxt, &taprpc.ProofFile{
		RawProofFile: proofResp.RawProofFile,
	})
	require.NoError(t.t, err)
	require.True(t.t, verifyResp.Valid)

	// Test 2: Burn the full amount of a collectible asset.
	rpcAssets = MintAssetsConfirmBatch(
		t.t, minerClient, t.tapd, []*mintrpc.MintAssetRequest{
			simpleAssets[1],
		},
	)
	collectibleAsset := rpcAssets[0]
	collectibleAssetGen := collectibleAsset.AssetGenesis
	var collectibleAssetID [32]byte
	copy(collectibleAssetID[:], collectibleAssetGen.AssetId)

	AssertBalanceByID(
		t.t, t.tapd, collectibleAssetGen.AssetId,
		collectibleAsset.Amount,
	)

	fullBurnAmt = collectibleAsset.Amount
	burnResp, err = t.tapd.BurnAsset(ctxt, &taprpc.BurnAssetRequest{
		AssetSpecifier: &taprpc.AssetSpecifier{
			Id: collectibleAssetID[:],
		},
		AmountToBurn:     fullBurnAmt,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	AssertAssetOutboundTransferWithOutputs(
		t.t, minerClient, t.tapd, burnResp.BurnTransfer,
		[][]byte{collectibleAssetID[:]},
		[]uint64{fullBurnAmt}, 1, 2, 1, true,
	)
	AssertBalanceByID(t.t, t.tapd, collectibleAssetID[:], 0)

	// Export and verify the burn proof for the collectible.
	wop, err = wire.NewOutPointFromString(
		burnResp.BurnTransfer.Outputs[0].Anchor.Outpoint,
	)
	require.NoError(t.t, err)
	outpoint = &taprpc.OutPoint{Txid: wop.Hash[:], OutputIndex: wop.Index}

	proofResp = ExportProofFile(
		t.t, t.tapd,
		burnResp.BurnProofs[0].Asset.AssetGenesis.AssetId,
		burnResp.BurnProofs[0].Asset.ScriptKey,
		outpoint,
	)
	verifyResp, err = t.tapd.VerifyProof(ctxt, &taprpc.ProofFile{
		RawProofFile: proofResp.RawProofFile,
	})
	require.NoError(t.t, err)
	require.True(t.t, verifyResp.Valid)

	// Verify that we have 2 burns.
	burns := AssertNumBurns(t.t, t.tapd, 2, nil)
	require.Equal(t.t, simpleAssetGen.AssetId, burns[0].AssetId)
	require.Equal(t.t, collectibleAssetGen.AssetId, burns[1].AssetId)
}
