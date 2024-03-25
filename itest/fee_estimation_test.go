package itest

import (
	"context"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// testFeeEstimation tests that we're able to spend outputs of various script
// types, and that the fee estimator and TX size estimator used during asset
// transfers are accurate.
func testFeeEstimation(t *harnessTest) {
	var (
		// Make a ladder of UTXO values so use order is deterministic.
		anchorAmounts = []int64{10000, 9990, 9980, 9970}

		// The default feerate in the itests is 12.5 sat/vB, but we
		// define it here explicitly to use for assertions.
		defaultFeeRate   = chainfee.SatPerKWeight(3125)
		higherFeeRate    = defaultFeeRate * 2
		excessiveFeeRate = defaultFeeRate * 8
		lowFeeRate       = chainfee.SatPerKWeight(500)

		// We will mint assets using the largest NP2WKH output, and then
		// use all three output types for transfers.
		initialUTXOs = []*UTXORequest{
			{
				Type:   lnrpc.AddressType_NESTED_PUBKEY_HASH,
				Amount: anchorAmounts[0],
			},
			{
				Type:   lnrpc.AddressType_NESTED_PUBKEY_HASH,
				Amount: anchorAmounts[1],
			},
			{
				Type:   lnrpc.AddressType_WITNESS_PUBKEY_HASH,
				Amount: anchorAmounts[2],
			},
			{
				Type:   lnrpc.AddressType_TAPROOT_PUBKEY,
				Amount: anchorAmounts[3],
			},
		}
	)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Set the initial state of the wallet of the first node. The wallet
	// state will reset at the end of this test.
	SetNodeUTXOs(t, t.lndHarness.Alice, btcutil.Amount(1), initialUTXOs)
	defer ResetNodeWallet(t, t.lndHarness.Alice)

	// Mint some assets with a NP2WPKH input, which will give us an anchor
	// output to spend for a transfer.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd, simpleAssets,
	)

	// Check the final fee rate of the mint TX.
	rpcMintOutpoint := rpcAssets[0].ChainAnchor.AnchorOutpoint
	mintOutpoint, err := wire.NewOutPointFromString(rpcMintOutpoint)
	require.NoError(t.t, err)

	// We check the minting TX with a rounded fee rate as the minter does
	// not adjust the fee rate of the TX after it was funded by our backing
	// wallet.
	AssertFeeRate(
		t.t, t.lndHarness.Miner.Client, anchorAmounts[0],
		&mintOutpoint.Hash, defaultFeeRate, true,
	)

	// Split the normal asset to create a transfer with two anchor outputs.
	normalAssetId := rpcAssets[0].AssetGenesis.AssetId
	splitAmount := rpcAssets[0].Amount / 2
	addr, stream := NewAddrWithEventStream(
		t.t, t.tapd, &taprpc.NewAddrRequest{
			AssetId: normalAssetId,
			Amt:     splitAmount,
		},
	)

	AssertAddrCreated(t.t, t.tapd, rpcAssets[0], addr)
	sendResp, sendEvents := sendAssetsToAddr(t, t.tapd, addr)

	transferIdx := 0
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, t.tapd, sendResp, normalAssetId,
		[]uint64{splitAmount, splitAmount}, transferIdx, transferIdx+1,
	)
	transferIdx += 1
	AssertNonInteractiveRecvComplete(t.t, t.tapd, transferIdx)
	AssertSendEventsComplete(t.t, addr.ScriptKey, sendEvents)
	AssertReceiveEvents(t.t, addr, stream)

	sendInputAmt := anchorAmounts[1] + 1000
	AssertTransferFeeRate(
		t.t, t.lndHarness.Miner.Client, sendResp, sendInputAmt,
		defaultFeeRate, false,
	)

	// Double the fee rate to 25 sat/vB before performing another transfer.
	t.lndHarness.SetFeeEstimateWithConf(higherFeeRate, 6)

	secondSplitAmount := splitAmount / 2
	addr2, stream2 := NewAddrWithEventStream(
		t.t, t.tapd, &taprpc.NewAddrRequest{
			AssetId: normalAssetId,
			Amt:     secondSplitAmount,
		},
	)

	AssertAddrCreated(t.t, t.tapd, rpcAssets[0], addr2)
	sendResp, sendEvents = sendAssetsToAddr(t, t.tapd, addr2)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, t.tapd, sendResp, normalAssetId,
		[]uint64{secondSplitAmount, secondSplitAmount},
		transferIdx, transferIdx+1,
	)
	transferIdx += 1
	AssertNonInteractiveRecvComplete(t.t, t.tapd, transferIdx)
	AssertSendEventsComplete(t.t, addr2.ScriptKey, sendEvents)
	AssertReceiveEvents(t.t, addr2, stream2)

	sendInputAmt = anchorAmounts[2] + 1000
	AssertTransferFeeRate(
		t.t, t.lndHarness.Miner.Client, sendResp, sendInputAmt,
		higherFeeRate, false,
	)

	// If we quadruple the fee rate, the freighter should fail during input
	// selection.
	t.lndHarness.SetFeeEstimateWithConf(excessiveFeeRate, 6)

	thirdSplitAmount := splitAmount / 4
	addr3, stream3 := NewAddrWithEventStream(
		t.t, t.tapd, &taprpc.NewAddrRequest{
			AssetId: normalAssetId,
			Amt:     thirdSplitAmount,
		},
	)

	AssertAddrCreated(t.t, t.tapd, rpcAssets[0], addr3)
	_, err = t.tapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		TapAddrs: []string{addr3.Encoded},
	})
	require.ErrorContains(t.t, err, "insufficient funds available")

	// The transfer should also be rejected if the manually-specified
	// feerate fails the sanity check against the fee estimator's fee floor
	// of 253 sat/kw, or 1.012 sat/vB.
	_, err = t.tapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		TapAddrs: []string{addr3.Encoded},
		FeeRate:  uint32(chainfee.FeePerKwFloor) - 1,
	})
	require.ErrorContains(t.t, err, "manual fee rate below floor")
	// After failure at the high feerate, we should still be able to make a
	// transfer at a very low feerate.
	t.lndHarness.SetFeeEstimateWithConf(lowFeeRate, 6)
	sendResp, sendEvents = sendAssetsToAddr(t, t.tapd, addr3)

	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, t.tapd, sendResp, normalAssetId,
		[]uint64{thirdSplitAmount, thirdSplitAmount},
		transferIdx, transferIdx+1,
	)
	transferIdx += 1
	AssertNonInteractiveRecvComplete(t.t, t.tapd, transferIdx)
	AssertSendEventsComplete(t.t, addr3.ScriptKey, sendEvents)
	AssertReceiveEvents(t.t, addr3, stream3)

	sendInputAmt = anchorAmounts[3] + 1000
	AssertTransferFeeRate(
		t.t, t.lndHarness.Miner.Client, sendResp, sendInputAmt,
		lowFeeRate, false,
	)
}
