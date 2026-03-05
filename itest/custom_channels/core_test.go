//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightninglabs/taproot-assets/tapscript"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannels tests that we can create a network with custom channels
// and send asset payments over them.
//
// Topology:
//
//	Charlie --[assets]--> Dave --[sats]--> Erin --[assets]--> Fabia
//	                        |
//	                     [assets]
//	                        |
//	                        v
//	                      Yara
//
//nolint:lll
func testCustomChannels(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// We use Charlie as the proof courier. But in order for Charlie to also
	// use itself, we need to define its port upfront.
	charliePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, charliePort),
	))

	// The topology we are going for looks like the following:
	//
	// Charlie  --[assets]-->  Dave  --[sats]-->  Erin  --[assets]-->  Fabia
	//                          |
	//                          |
	//                       [assets]
	//                          |
	//                          v
	//                        Yara
	//
	// With [assets] being a custom channel and [sats] being a normal, BTC
	// only channel.
	// All 5 nodes need to be full integrated nodes running with tapd
	// included. We also need specific flags to be enabled, so we create 5
	// completely new nodes, ignoring the two default nodes that are created
	// by the harness.
	charlieLndArgs := slices.Clone(lndArgs)
	charlieLndArgs = append(charlieLndArgs, fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", charliePort,
	))
	charlie := net.NewNode("Charlie", charlieLndArgs, tapdArgs)
	dave := net.NewNode("Dave", lndArgs, tapdArgs)
	erin := net.NewNode("Erin", lndArgs, tapdArgs)
	fabia := net.NewNode("Fabia", lndArgs, tapdArgs)
	yara := net.NewNode("Yara", lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{charlie, dave, erin, fabia, yara}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Create the normal channel between Dave and Erin.
	t.Logf("Opening normal channel between Dave and Erin...")
	channelOp := openChannelAndAssert(
		t, net, dave, erin, lntest.OpenChannelParams{
			Amt:         5_000_000,
			SatPerVByte: 5,
		},
	)
	defer closeChannelAndAssert(t, net, dave, channelOp, false)

	// This is the only public channel, we need everyone to be aware of it.
	assertChannelKnown(t.t, charlie, channelOp)
	assertChannelKnown(t.t, fabia, channelOp)

	// Mint an asset on Charlie and sync all nodes to Charlie as the
	// universe.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{
			{
				Asset: ccItestAsset,
			},
		},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId
	fundingScriptTree := tapscript.NewChannelFundingScriptTree()
	fundingScriptKey := fundingScriptTree.TaprootKey
	fundingScriptTreeBytes := fundingScriptKey.SerializeCompressed()

	t.Logf("Minted %d lightning cents, syncing universes...", cents.Amount)
	syncUniverses(t.t, charlie, dave, erin, fabia, yara)
	t.Logf("Universes synced between all nodes, distributing assets...")

	const (
		daveFundingAmount = uint64(startAmount)
		erinFundingAmount = uint64(fundingAmount)
	)
	charlieFundingAmount := cents.Amount - 2*startAmount

	chanPointCD, chanPointDY, chanPointEF := createTestAssetNetwork(
		t, net, charlie, dave, erin, fabia, yara, charlie,
		cents, startAmount, charlieFundingAmount,
		daveFundingAmount, erinFundingAmount, DefaultPushSat,
	)

	// We'll be tracking the expected asset balances throughout the test, so
	// we can assert it after each action.
	charlieAssetBalance := charlieFundingAmount
	daveAssetBalance := uint64(startAmount)
	erinAssetBalance := uint64(startAmount)
	fabiaAssetBalance := uint64(0)
	yaraAssetBalance := uint64(0)

	// Before we start sending out payments, let's make sure each node can
	// see the other one in the graph and has all required features.
	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))
	require.NoError(t.t, net.AssertNodeKnown(dave, yara))
	require.NoError(t.t, net.AssertNodeKnown(yara, dave))
	require.NoError(t.t, net.AssertNodeKnown(erin, fabia))
	require.NoError(t.t, net.AssertNodeKnown(fabia, erin))
	require.NoError(t.t, net.AssertNodeKnown(charlie, erin))

	// Print initial channel balances.
	logBalance(t.t, nodes, assetID, "initial")

	// ------------
	// Test case 1: Send a direct keysend payment from Charlie to Dave,
	// sending the whole balance.
	// ------------
	keySendAmount := charlieFundingAmount
	sendAssetKeySendPayment(
		t.t, charlie, dave, charlieFundingAmount, assetID,
		fn.None[int64](),
	)
	logBalance(t.t, nodes, assetID, "after keysend")

	charlieAssetBalance -= keySendAmount
	daveAssetBalance += keySendAmount

	// We should be able to send 1000 assets back immediately, because
	// there is enough on-chain balance on Dave's side to be able to create
	// an HTLC. We use an invoice to execute another code path.
	const charlieInvoiceAmount = 1_000
	invoiceResp := createAssetInvoice(
		t.t, dave, charlie, charlieInvoiceAmount, assetID,
	)
	payInvoiceWithAssets(
		t.t, dave, charlie, invoiceResp.PaymentRequest, assetID,
		withSmallShards(),
	)
	logBalance(t.t, nodes, assetID, "after invoice back")

	// Make sure the invoice on the receiver side and the payment on the
	// sender side show the individual HTLCs that arrived for it and that
	// they show the correct asset amounts when decoded.
	assertInvoiceHtlcAssets(
		t.t, charlie, invoiceResp, assetID, nil, charlieInvoiceAmount,
	)
	assertPaymentHtlcAssets(
		t.t, dave, invoiceResp.RHash, assetID, nil,
		charlieInvoiceAmount,
	)

	charlieAssetBalance += charlieInvoiceAmount
	daveAssetBalance -= charlieInvoiceAmount

	// We should also be able to do a non-asset (BTC only) keysend payment
	// from Charlie to Dave. This'll also replenish the BTC balance of
	// Dave, making it possible to send another asset HTLC below, sending
	// all assets back to Charlie (so we have enough balance for further
	// tests).
	sendKeySendPayment(t.t, charlie, dave, 2000)
	logBalance(t.t, nodes, assetID, "after BTC only keysend")

	// Let's keysend the rest of the balance back to Charlie.
	sendAssetKeySendPayment(
		t.t, dave, charlie, charlieFundingAmount-charlieInvoiceAmount,
		assetID, fn.None[int64](),
	)
	logBalance(t.t, nodes, assetID, "after keysend back")

	charlieAssetBalance += charlieFundingAmount - charlieInvoiceAmount
	daveAssetBalance -= charlieFundingAmount - charlieInvoiceAmount

	// ------------
	// Test case 2: Pay a normal invoice from Dave by Charlie, making it
	// a direct channel invoice payment with no RFQ SCID present in the
	// invoice.
	// ------------
	createAndPayNormalInvoice(
		t.t, charlie, dave, dave, 20_000, assetID, withSmallShards(),
		withFailure(lnrpc.Payment_FAILED, failureIncorrectDetails),
	)
	logBalance(t.t, nodes, assetID, "after invoice")

	// We should also be able to do a multi-hop BTC only payment, paying an
	// invoice from Erin by Charlie.
	createAndPayNormalInvoiceWithBtc(t.t, charlie, erin, 2000)
	logBalance(t.t, nodes, assetID, "after BTC only invoice")

	// ------------
	// Test case 3: Pay an asset invoice from Dave by Charlie, making it
	// a direct channel invoice payment with an RFQ SCID present in the
	// invoice.
	// ------------
	const daveInvoiceAssetAmount = 2_000
	invoiceResp = createAssetInvoice(
		t.t, charlie, dave, daveInvoiceAssetAmount, assetID,
	)
	payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp.PaymentRequest, assetID,
		withSmallShards(),
	)
	logBalance(t.t, nodes, assetID, "after invoice")

	charlieAssetBalance -= daveInvoiceAssetAmount
	daveAssetBalance += daveInvoiceAssetAmount

	// ------------
	// Test case 3.5: Pay an asset invoice from Dave by Charlie with normal
	// satoshi payment flow. We expect that payment to fail, since it's a
	// direct channel payment and the invoice is for assets, not sats. So
	// without a conversion, it is rejected by the receiver.
	// ------------
	invoiceResp = createAssetInvoice(
		t.t, charlie, dave, daveInvoiceAssetAmount, assetID,
	)
	payInvoiceWithSatoshi(
		t.t, charlie, invoiceResp, withFailure(
			lnrpc.Payment_FAILED, failureIncorrectDetails,
		),
	)
	logBalance(t.t, nodes, assetID, "after asset invoice paid with sats")

	// We don't need to update the asset balances of Charlie and Dave here
	// as the invoice payment failed.

	// ------------
	// Test case 4: Pay a normal invoice from Erin by Charlie.
	// ------------
	paidAssetAmount := createAndPayNormalInvoice(
		t.t, charlie, dave, erin, 20_000, assetID, withSmallShards(),
	)
	logBalance(t.t, nodes, assetID, "after invoice")

	charlieAssetBalance -= paidAssetAmount
	daveAssetBalance += paidAssetAmount

	// ------------
	// Test case 5: Create an asset invoice on Fabia and pay it from
	// Charlie.
	// ------------

	// First send some sats from Erin to Fabia, for Fabia to have some
	// minimal sats liquidity on her end.
	sendKeySendPayment(t.t, erin, fabia, 5000)

	logBalance(t.t, nodes, assetID, "after erin->fabia sats keysend")

	const fabiaInvoiceAssetAmount1 = 1000
	invoiceResp = createAssetInvoice(
		t.t, erin, fabia, fabiaInvoiceAssetAmount1, assetID,
	)
	payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp.PaymentRequest, assetID,
		withSmallShards(),
	)
	logBalance(t.t, nodes, assetID, "after invoice")

	charlieAssetBalance -= fabiaInvoiceAssetAmount1
	daveAssetBalance += fabiaInvoiceAssetAmount1
	erinAssetBalance -= fabiaInvoiceAssetAmount1
	fabiaAssetBalance += fabiaInvoiceAssetAmount1

	// ------------
	// Test case 6: Create an asset invoice on Fabia and pay it with just
	// BTC from Dave, making sure it ends up being a multipart payment (we
	// set the maximum shard size to 80k sat and 15k asset units will be
	// more than a single shard).
	// ------------
	const fabiaInvoiceAssetAmount2 = 15_000
	invoiceResp = createAssetInvoice(
		t.t, erin, fabia, fabiaInvoiceAssetAmount2, assetID,
	)
	payInvoiceWithSatoshi(t.t, dave, invoiceResp)
	logBalance(t.t, nodes, assetID, "after invoice")

	erinAssetBalance -= fabiaInvoiceAssetAmount2
	fabiaAssetBalance += fabiaInvoiceAssetAmount2

	// ------------
	// Test case 7: Create an asset invoice on Fabia and pay it with assets
	// from Charlie, making sure it ends up being a multipart payment as
	// well, with the high amount of asset units to send and the hard coded
	// 80k sat max shard size.
	// ------------
	const fabiaInvoiceAssetAmount3 = 10_000
	invoiceResp = createAssetInvoice(
		t.t, erin, fabia, fabiaInvoiceAssetAmount3, assetID,
	)
	payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp.PaymentRequest, assetID,
		withSmallShards(),
	)
	logBalance(t.t, nodes, assetID, "after invoice")

	charlieAssetBalance -= fabiaInvoiceAssetAmount3
	daveAssetBalance += fabiaInvoiceAssetAmount3
	erinAssetBalance -= fabiaInvoiceAssetAmount3
	fabiaAssetBalance += fabiaInvoiceAssetAmount3

	// ------------
	// Test case 8: An invoice payment over two channels that are both asset
	// channels.
	// ------------
	logBalance(t.t, nodes, assetID, "before asset-to-asset")

	const yaraInvoiceAssetAmount1 = 1000
	invoiceResp = createAssetInvoice(
		t.t, dave, yara, yaraInvoiceAssetAmount1, assetID,
	)
	payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp.PaymentRequest, assetID,
		withSmallShards(),
	)
	logBalance(t.t, nodes, assetID, "after asset-to-asset")

	charlieAssetBalance -= yaraInvoiceAssetAmount1
	yaraAssetBalance += yaraInvoiceAssetAmount1

	// ------------
	// Test case 9: Now we'll close each of the channels, starting with the
	// Charlie -> Dave custom channel.
	// ------------
	t.Logf("Closing Charlie -> Dave channel")
	closeAssetChannelAndAssert(
		t, net, charlie, dave, chanPointCD, [][]byte{assetID}, nil,
		charlie, assertDefaultCoOpCloseBalance(true, true),
	)

	t.Logf("Closing Dave -> Yara channel")
	closeAssetChannelAndAssert(
		t, net, dave, yara, chanPointDY, [][]byte{assetID}, nil,
		charlie, assertDefaultCoOpCloseBalance(false, true),
	)

	t.Logf("Closing Erin -> Fabia channel")
	closeAssetChannelAndAssert(
		t, net, erin, fabia, chanPointEF, [][]byte{assetID}, nil,
		charlie, assertDefaultCoOpCloseBalance(true, true),
	)

	// We've been tracking the off-chain channel balances all this time, so
	// now that we have the assets on-chain again, we can assert them. Due
	// to rounding errors that happened when sending multiple shards with
	// MPP, we need to do some slight adjustments.
	charlieAssetBalance += 1
	erinAssetBalance += 3
	fabiaAssetBalance -= 3
	yaraAssetBalance -= 1
	assertBalance(
		t.t, charlie, charlieAssetBalance,
		itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, dave, daveAssetBalance, itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, erin, erinAssetBalance, itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, fabia, fabiaAssetBalance, itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, yara, yaraAssetBalance, itest.WithAssetID(assetID),
	)

	// ------------
	// Test case 10: We now open a new asset channel and close it again, to
	// make sure that a non-existent remote balance is handled correctly.
	t.Logf("Opening new asset channel between Charlie and Dave...")
	fundRespCD, err := asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded second channel between Charlie and Dave: %v",
		fundRespCD)

	mineBlocks(t, net, 6, 1)

	// Assert that the proofs for both channels has been uploaded to the
	// designated Universe server.
	assertUniverseProofExists(
		t.t, charlie, assetID, nil, fundingScriptTreeBytes,
		fmt.Sprintf("%v:%v", fundRespCD.Txid, fundRespCD.OutputIndex),
	)
	assertAssetChan(
		t.t, charlie, dave, fundingAmount, []*taprpc.Asset{cents},
	)

	// And let's just close the channel again.
	chanPointCD = &lnrpc.ChannelPoint{
		OutputIndex: uint32(fundRespCD.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: fundRespCD.Txid,
		},
	}

	t.Logf("Closing Charlie -> Dave channel")
	closeAssetChannelAndAssert(
		t, net, charlie, dave, chanPointCD, [][]byte{assetID}, nil,
		charlie, assertDefaultCoOpCloseBalance(false, false),
	)

	// Charlie should still have four asset pieces, two with the same size.
	assertBalance(
		t.t, charlie, charlieAssetBalance,
		itest.WithAssetID(assetID), itest.WithNumUtxos(2),
		itest.WithScriptKeyType(asset.ScriptKeyBip86),
	)

	// Dave should have two outputs, one from the initial channel with Yara
	// and one from the remaining amount of the channel with Charlie.
	assertBalance(
		t.t, dave, daveAssetBalance, itest.WithAssetID(assetID),
		itest.WithNumUtxos(2),
		itest.WithScriptKeyType(asset.ScriptKeyBip86),
	)

	// Fabia and Yara should all have a single output each, just what was
	// left over from the initial channel.
	assertBalance(
		t.t, fabia, fabiaAssetBalance, itest.WithAssetID(assetID),
		itest.WithNumUtxos(1),
		itest.WithScriptKeyType(asset.ScriptKeyBip86),
	)
	assertBalance(
		t.t, yara, yaraAssetBalance, itest.WithAssetID(assetID),
		itest.WithNumUtxos(1),
		itest.WithScriptKeyType(asset.ScriptKeyBip86),
	)

	// Erin didn't use all of his assets when opening the channel, so he
	// should have two outputs, the change from the channel opening and the
	// remaining amount after closing the channel.
	assertBalance(
		t.t, erin, erinAssetBalance, itest.WithAssetID(assetID),
		itest.WithNumUtxos(2),
		itest.WithScriptKeyType(asset.ScriptKeyBip86),
	)

	// The asset balances should still remain unchanged.
	assertBalance(
		t.t, charlie, charlieAssetBalance,
		itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, dave, daveAssetBalance, itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, erin, erinAssetBalance, itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, fabia, fabiaAssetBalance, itest.WithAssetID(assetID),
	)
}
