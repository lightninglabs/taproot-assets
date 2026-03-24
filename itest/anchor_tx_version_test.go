package itest

import (
	"context"

	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/stretchr/testify/require"
)

// testAnchorTxVersionV3 verifies that minting and transfer flows honor an
// explicit request for v3 Bitcoin anchor transactions.
func testAnchorTxVersionV3(t *harnessTest) {
	if t.lndHarness.ChainBackendName() != "bitcoind" {
		t.t.Skip(
			"v3 anchor coverage requires the bitcoind chain " +
				"backend",
		)
	}

	ctx := context.Background()
	miner := t.lndHarness.Miner()

	rpcAssets := MintAssetsConfirmBatch(
		t.t, miner, t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
		WithMintAnchorTxVersion(
			taprpc.AnchorTxVersion_ANCHOR_TX_VERSION_V3,
		),
	)
	mintedAsset := rpcAssets[0]
	genInfo := mintedAsset.AssetGenesis

	AssertAssetAnchorTxVersion(
		t.t, miner, mintedAsset, tapsend.AnchorTxVersionV3,
	)

	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	const bobAmt = 1000
	bobAddr, err := bobTapd.NewAddr(ctx, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     bobAmt,
	})
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, bobTapd, mintedAsset, bobAddr)

	sendResp, sendEvents := sendAsset(
		t, t.tapd, withReceiverAddresses(bobAddr), withAnchorTxVersion(
			taprpc.AnchorTxVersion_ANCHOR_TX_VERSION_V3,
		),
	)
	ConfirmAndAssertOutboundTransfer(
		t.t, miner, t.tapd, sendResp, genInfo.AssetId,
		[]uint64{mintedAsset.Amount - bobAmt, bobAmt}, 0, 1,
	)
	AssertTransferAnchorTxVersion(
		t.t, miner, sendResp.Transfer, tapsend.AnchorTxVersionV3,
	)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)
	AssertSendEventsComplete(t.t, bobAddr.ScriptKey, sendEvents)

	const aliceAmt = 600
	aliceAddr, err := t.tapd.NewAddr(ctx, &taprpc.NewAddrRequest{
		AssetId: genInfo.AssetId,
		Amt:     aliceAmt,
	})
	require.NoError(t.t, err)

	fundResp := fundAddressSendPacket(t, bobTapd, aliceAddr)
	signResp, err := bobTapd.SignVirtualPsbt(
		ctx, &wrpc.SignVirtualPsbtRequest{
			FundedPsbt: fundResp.FundedPsbt,
		},
	)
	require.NoError(t.t, err)

	psbtSendResp, err := bobTapd.AnchorVirtualPsbts(
		ctx, &wrpc.AnchorVirtualPsbtsRequest{
			VirtualPsbts: [][]byte{signResp.SignedPsbt},
			AnchorTxVersion: taprpc.
				AnchorTxVersion_ANCHOR_TX_VERSION_V3,
		},
	)
	require.NoError(t.t, err)

	ConfirmAndAssertOutboundTransfer(
		t.t, miner, bobTapd, psbtSendResp, genInfo.AssetId,
		[]uint64{bobAmt - aliceAmt, aliceAmt}, 0, 1,
	)
	AssertTransferAnchorTxVersion(
		t.t, miner, psbtSendResp.Transfer, tapsend.AnchorTxVersionV3,
	)
	AssertNonInteractiveRecvComplete(t.t, t.tapd, 1)
}
