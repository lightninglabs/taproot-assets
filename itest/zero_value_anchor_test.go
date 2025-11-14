package itest

import (
	"context"
	"time"

	taprootassets "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// testZeroValueAnchorSweep tests that zero-value anchor outputs
// are automatically swept when creating new on-chain transactions.
func testZeroValueAnchorSweep(t *harnessTest) {
	ctxb := context.Background()

	// First, mint some simple asset.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)
	genInfo := rpcAssets[0].AssetGenesis
	assetAmount := simpleAssets[0].Asset.Amount

	// Create a second tapd node.
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	bobAddr, err := secondTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:      genInfo.AssetId,
		Amt:          assetAmount,
		AssetVersion: rpcAssets[0].Version,
	})
	require.NoError(t.t, err)

	// Send ALL assets to Bob, which should create a tombstone.
	sendResp, _ := sendAssetsToAddr(t, t.tapd, bobAddr)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp,
		genInfo.AssetId,
		[]uint64{0, assetAmount}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 1)

	// Alice should have 1 tombstone UTXO from the full-value send.
	AssertBalances(
		t.t, t.tapd, 0, WithScriptKeyType(asset.ScriptKeyTombstone),
		WithNumUtxos(1), WithNumAnchorUtxos(1),
	)

	// Test 1: Send transaction sweeps tombstones.
	rpcAssets2 := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)
	genInfo2 := rpcAssets2[0].AssetGenesis

	// Send full amount of the new asset. This should sweep Alice's
	// first tombstone and create a new one.
	bobAddr2, err := secondTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:      genInfo2.AssetId,
		Amt:          assetAmount,
		AssetVersion: rpcAssets2[0].Version,
	})
	require.NoError(t.t, err)

	sendResp2, _ := sendAssetsToAddr(t, t.tapd, bobAddr2)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp2,
		genInfo2.AssetId,
		[]uint64{0, assetAmount}, 1, 2,
	)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 2)

	// Check Alice's tombstone balance. The first tombstone should have been
	// swept (spent on-chain as an input), and a new one created. We now
	// have 1 tombstone UTXO (the new one from the second send).
	AssertBalances(
		t.t, t.tapd, 0, WithScriptKeyType(asset.ScriptKeyTombstone),
		WithNumUtxos(1), WithNumAnchorUtxos(1),
	)

	// Get the new tombstone outpoint.
	utxosAfterSend, err := t.tapd.ListUtxos(ctxb, &taprpc.ListUtxosRequest{
		ScriptKeyType: &taprpc.ScriptKeyTypeQuery{
			Type: &taprpc.ScriptKeyTypeQuery_ExplicitType{
				ExplicitType: taprpc.
					ScriptKeyType_SCRIPT_KEY_TOMBSTONE,
			},
		},
	})
	require.NoError(t.t, err)
	require.Len(t.t, utxosAfterSend.ManagedUtxos, 1)

	// Test 2: Burning transaction sweeps tombstones.
	rpcAssets3 := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)
	genInfo3 := rpcAssets3[0].AssetGenesis

	// Full burn the asset to create a zero-value burn UTXO
	// and sweep the second tombstone.
	burnResp, err := t.tapd.BurnAsset(ctxb, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: genInfo3.AssetId,
		},
		AmountToBurn:     assetAmount,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	AssertAssetOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, t.tapd, burnResp.BurnTransfer,
		[][]byte{genInfo3.AssetId},
		[]uint64{assetAmount}, 2, 3, 1, true,
	)

	// Alice should have 0 tombstones remaining and 1 burn UTXO.
	AssertBalances(
		t.t, t.tapd, 0, WithScriptKeyType(asset.ScriptKeyTombstone),
		WithNumUtxos(0), WithNumAnchorUtxos(0),
	)
	AssertBalances(
		t.t, t.tapd, assetAmount,
		WithScriptKeyType(asset.ScriptKeyBurn),
		WithNumUtxos(1), WithNumAnchorUtxos(1),
	)

	// Get the burn UTXO outpoint for the next test.
	burnUtxos, err := t.tapd.ListUtxos(ctxb, &taprpc.ListUtxosRequest{
		ScriptKeyType: &taprpc.ScriptKeyTypeQuery{
			Type: &taprpc.ScriptKeyTypeQuery_ExplicitType{
				ExplicitType: taprpc.
					ScriptKeyType_SCRIPT_KEY_BURN,
			},
		},
	})
	require.NoError(t.t, err)
	require.Len(t.t, burnUtxos.ManagedUtxos, 1)

	// Test 3: Send transactions sweeps zero-value burns.
	rpcAssets4 := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)
	genInfo4 := rpcAssets4[0].AssetGenesis

	// Send partial amount. This should NOT create a tombstone output
	// and sweep the burn UTXO.
	partialAmount := assetAmount / 2
	bobAddr3, err := secondTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:      genInfo4.AssetId,
		Amt:          partialAmount,
		AssetVersion: rpcAssets4[0].Version,
	})
	require.NoError(t.t, err)

	sendResp3, _ := sendAssetsToAddr(t, t.tapd, bobAddr3)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp3,
		genInfo4.AssetId,
		[]uint64{partialAmount, partialAmount}, 3, 4,
	)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 3)

	// The burn UTXO should have been swept.
	AssertBalances(
		t.t, t.tapd, 0, WithScriptKeyType(asset.ScriptKeyBurn),
		WithNumUtxos(0), WithNumAnchorUtxos(0),
	)
}

// testZeroValueAnchorAccumulation tests that zero-value anchor outputs
// accumulate when sweeping is disabled, and are swept when the node
// is restarted with sweeping enabled.
func testZeroValueAnchorAccumulation(t *harnessTest) {
	ctxb := context.Background()

	// Start Alice's node WITHOUT sweeping enabled.
	// Note: t.tapd is already started without sweeping by default.

	// Create Bob's node with sweeping enabled for receives.
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	// First, mint some assets to create zero-value UTXOs with.
	rpcAssets1 := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)
	genInfo1 := rpcAssets1[0].AssetGenesis
	assetAmount := simpleAssets[0].Asset.Amount

	// Test 1: Create a tombstone by sending ALL assets to Bob.
	bobAddr1, err := bobTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:      genInfo1.AssetId,
		Amt:          assetAmount,
		AssetVersion: rpcAssets1[0].Version,
	})
	require.NoError(t.t, err)

	sendResp1, _ := sendAssetsToAddr(t, t.tapd, bobAddr1)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp1,
		genInfo1.AssetId,
		[]uint64{0, assetAmount}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)

	// Alice should have 1 tombstone UTXO.
	AssertBalances(
		t.t, t.tapd, 0, WithScriptKeyType(asset.ScriptKeyTombstone),
		WithNumUtxos(1), WithNumAnchorUtxos(1),
	)

	// Test 2: Create a burn UTXO by burning another asset fully.
	rpcAssets2 := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)
	genInfo2 := rpcAssets2[0].AssetGenesis

	// Full burn the asset to create a zero-value burn UTXO.
	burnResp, err := t.tapd.BurnAsset(ctxb, &taprpc.BurnAssetRequest{
		Asset: &taprpc.BurnAssetRequest_AssetId{
			AssetId: genInfo2.AssetId,
		},
		AmountToBurn:     assetAmount,
		ConfirmationText: taprootassets.AssetBurnConfirmationText,
	})
	require.NoError(t.t, err)

	AssertAssetOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, t.tapd, burnResp.BurnTransfer,
		[][]byte{genInfo2.AssetId},
		[]uint64{assetAmount}, 1, 2, 1, true,
	)

	// Alice should now have 1 tombstone and 1 burn UTXO.
	AssertBalances(
		t.t, t.tapd, 0, WithScriptKeyType(asset.ScriptKeyTombstone),
		WithNumUtxos(1), WithNumAnchorUtxos(1),
	)
	AssertBalances(
		t.t, t.tapd, assetAmount,
		WithScriptKeyType(asset.ScriptKeyBurn),
		WithNumUtxos(1), WithNumAnchorUtxos(1),
	)

	// Test 3: Create another tombstone with a different asset.
	rpcAssets3 := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)
	genInfo3 := rpcAssets3[0].AssetGenesis

	bobAddr2, err := bobTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:      genInfo3.AssetId,
		Amt:          assetAmount,
		AssetVersion: rpcAssets3[0].Version,
	})
	require.NoError(t.t, err)

	sendResp2, _ := sendAssetsToAddr(t, t.tapd, bobAddr2)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp2,
		genInfo3.AssetId, []uint64{0, assetAmount}, 2, 3,
	)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 2)

	// Alice should now have 2 tombstones and 1 burn UTXO.
	AssertBalances(
		t.t, t.tapd, 0, WithScriptKeyType(asset.ScriptKeyTombstone),
		WithNumUtxos(2), WithNumAnchorUtxos(2),
	)

	// Now restart Alice's node with sweeping enabled.
	require.NoError(t.t, t.tapd.stop(false))

	// Enable sweeping in the config.
	t.tapd.clientCfg.Wallet.SweepOrphanUtxos = true

	// Restart with the modified config.
	require.NoError(t.t, t.tapd.start(false))

	// Wait for the node to fully sync after restart.
	time.Sleep(2 * time.Second)

	// Verify that the zero-value UTXOs are still present after restart.
	//nolint:lll
	tombstoneUtxosAfterRestart, err := t.tapd.ListUtxos(ctxb, &taprpc.ListUtxosRequest{
		ScriptKeyType: &taprpc.ScriptKeyTypeQuery{
			Type: &taprpc.ScriptKeyTypeQuery_ExplicitType{
				ExplicitType: taprpc.
					ScriptKeyType_SCRIPT_KEY_TOMBSTONE,
			},
		},
	})
	require.NoError(t.t, err)
	require.Len(t.t, tombstoneUtxosAfterRestart.ManagedUtxos, 2)

	//nolint:lll
	burnUtxosAfterRestart, err := t.tapd.ListUtxos(ctxb, &taprpc.ListUtxosRequest{
		ScriptKeyType: &taprpc.ScriptKeyTypeQuery{
			Type: &taprpc.ScriptKeyTypeQuery_ExplicitType{
				ExplicitType: taprpc.
					ScriptKeyType_SCRIPT_KEY_BURN,
			},
		},
	})
	require.NoError(t.t, err)
	require.Len(t.t, burnUtxosAfterRestart.ManagedUtxos, 1)

	// Test 4: Mint and send a new asset. This should sweep all accumulated
	// zero-value UTXOs (2 tombstones + 1 burn).
	rpcAssets4 := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)
	genInfo4 := rpcAssets4[0].AssetGenesis

	// Send partial amount to create a normal transfer that should sweep
	// all zero-value UTXOs.
	partialAmount := assetAmount / 2
	bobAddr3, err := bobTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:      genInfo4.AssetId,
		Amt:          partialAmount,
		AssetVersion: rpcAssets4[0].Version,
	})
	require.NoError(t.t, err)

	sendResp3, _ := sendAssetsToAddr(t, t.tapd, bobAddr3)

	// This transfer should have swept all 3 zero-value UTXOs as inputs.
	// The expected number of inputs is:
	// 1 (new asset) + 3 (swept zero-value).
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp3,
		genInfo4.AssetId,
		[]uint64{partialAmount, partialAmount}, 3, 4,
	)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 3)

	// All zero-value UTXOs should have been swept.
	AssertBalances(
		t.t, t.tapd, 0, WithScriptKeyType(asset.ScriptKeyTombstone),
		WithNumUtxos(0), WithNumAnchorUtxos(0),
	)
	AssertBalances(
		t.t, t.tapd, 0, WithScriptKeyType(asset.ScriptKeyBurn),
		WithNumUtxos(0), WithNumAnchorUtxos(0),
	)
}
