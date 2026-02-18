//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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

// testCustomChannelsGroupedAsset tests that we can create a network with custom
// channels that use grouped assets and send asset payments over them.
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
func testCustomChannelsGroupedAsset(_ context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// We use Charlie as the proof courier. But in order for Charlie to
	// also use itself, we need to define its port upfront.
	charliePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, charliePort),
	))

	// Create all five nodes. Charlie gets a custom RPC port so it can
	// reference itself as proof courier.
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

	// This is the only public channel, we need everyone to be aware of
	// it.
	assertChannelKnown(t.t, charlie, channelOp)
	assertChannelKnown(t.t, fabia, channelOp)

	groupAssetReq := itest.CopyRequest(&mintrpc.MintAssetRequest{
		Asset: ccItestAsset,
	})
	groupAssetReq.Asset.NewGroupedAsset = true

	// Mint an asset on Charlie and sync all nodes to Charlie as the
	// universe.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{groupAssetReq},
	)

	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId
	groupID := cents.GetAssetGroup().GetTweakedGroupKey()
	groupKey, err := btcec.ParsePubKey(groupID)
	require.NoError(t.t, err)
	fundingScriptTree := tapscript.NewChannelFundingScriptTree()
	fundingScriptKey := fundingScriptTree.TaprootKey
	fundingScriptTreeBytes := fundingScriptKey.SerializeCompressed()

	t.Logf("Minted %d lightning cents, syncing universes...",
		cents.Amount)
	syncUniverses(t.t, charlie, dave, erin, fabia, yara)
	t.Logf("Universes synced between all nodes, distributing " +
		"assets...")

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

	// We'll be tracking the expected asset balances throughout the test,
	// so we can assert it after each action.
	charlieAssetBalance := charlieFundingAmount
	daveAssetBalance := uint64(startAmount)
	erinAssetBalance := uint64(startAmount)
	fabiaAssetBalance := uint64(0)
	yaraAssetBalance := uint64(0)

	// Before we start sending out payments, let's make sure each node
	// can see the other one in the graph and has all required features.
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
	// Test case 1: Send a direct keysend payment from Charlie to Dave.
	// ------------
	const keySendAmount = 100
	sendAssetKeySendPayment(
		t.t, charlie, dave, keySendAmount, nil, fn.None[int64](),
		withGroupKey(groupID),
	)
	logBalance(t.t, nodes, assetID, "after keysend")

	charlieAssetBalance -= keySendAmount
	daveAssetBalance += keySendAmount

	// We should be able to send the 100 assets back immediately,
	// because there is enough on-chain balance on Dave's side to be
	// able to create an HTLC.
	sendAssetKeySendPayment(
		t.t, dave, charlie, keySendAmount, assetID,
		fn.None[int64](),
	)
	logBalance(t.t, nodes, assetID, "after keysend back")

	charlieAssetBalance += keySendAmount
	daveAssetBalance -= keySendAmount

	// We should also be able to do a non-asset (BTC only) keysend
	// payment.
	sendKeySendPayment(t.t, charlie, dave, 2000)
	logBalance(t.t, nodes, assetID, "after BTC only keysend")

	// ------------
	// Test case 2: Pay a normal invoice from Dave by Charlie, making it
	// a direct channel invoice payment with no RFQ SCID present in the
	// invoice.
	// ------------
	createAndPayNormalInvoice(
		t.t, charlie, dave, dave, 20_000, nil, withSmallShards(),
		withFailure(lnrpc.Payment_FAILED, failureIncorrectDetails),
		withGroupKey(groupID),
	)
	logBalance(t.t, nodes, assetID, "after failed invoice")

	// We should also be able to do a multi-hop BTC only payment,
	// paying an invoice from Erin by Charlie.
	createAndPayNormalInvoiceWithBtc(t.t, charlie, erin, 2000)
	logBalance(t.t, nodes, assetID, "after BTC only invoice")

	// ------------
	// Test case 3: Pay an asset invoice from Dave by Charlie, making it
	// a direct channel invoice payment with an RFQ SCID present in the
	// invoice.
	// ------------
	const daveInvoiceAssetAmount = 2_000
	invoiceResp := createAssetInvoice(
		t.t, charlie, dave, daveInvoiceAssetAmount, nil,
		withInvGroupKey(groupID),
	)
	payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp.PaymentRequest, nil,
		withSmallShards(), withGroupKey(groupID),
	)
	logBalance(t.t, nodes, assetID, "after invoice")

	groupBytes := schnorr.SerializePubKey(groupKey)

	// Make sure the invoice on the receiver side and the payment on the
	// sender side show the individual HTLCs that arrived for it and
	// that they show the correct asset amounts when decoded.
	assertInvoiceHtlcAssets(
		t.t, dave, invoiceResp, nil, groupBytes,
		daveInvoiceAssetAmount,
	)
	assertPaymentHtlcAssets(
		t.t, charlie, invoiceResp.RHash, nil, groupBytes,
		daveInvoiceAssetAmount,
	)

	charlieAssetBalance -= daveInvoiceAssetAmount
	daveAssetBalance += daveInvoiceAssetAmount

	// ------------
	// Test case 4: Pay a normal invoice from Erin by Charlie.
	// ------------
	paidAssetAmount := createAndPayNormalInvoice(
		t.t, charlie, dave, erin, 20_000, nil, withSmallShards(),
		withGroupKey(groupID),
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
		t.t, erin, fabia, fabiaInvoiceAssetAmount1, nil,
		withInvGroupKey(groupID),
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
	// Test case 6: Create an asset invoice on Fabia and pay it with
	// just BTC from Dave, making sure it ends up being a multipart
	// payment (we set the maximum shard size to 80k sat and 15k asset
	// units will be more than a single shard).
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
	// Test case 7: Create an asset invoice on Fabia and pay it with
	// assets from Charlie, making sure it ends up being a multipart
	// payment as well, with the high amount of asset units to send and
	// the hard coded 80k sat max shard size.
	// ------------
	const fabiaInvoiceAssetAmount3 = 10_000
	invoiceResp = createAssetInvoice(
		t.t, erin, fabia, fabiaInvoiceAssetAmount3, assetID,
	)
	payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp.PaymentRequest, nil,
		withSmallShards(), withGroupKey(groupID),
	)
	logBalance(t.t, nodes, assetID, "after invoice")

	charlieAssetBalance -= fabiaInvoiceAssetAmount3
	daveAssetBalance += fabiaInvoiceAssetAmount3
	erinAssetBalance -= fabiaInvoiceAssetAmount3
	fabiaAssetBalance += fabiaInvoiceAssetAmount3

	// ------------
	// Test case 8: An invoice payment over two channels that are both
	// asset channels.
	// ------------
	logBalance(t.t, nodes, assetID, "before asset-to-asset")

	const yaraInvoiceAssetAmount1 = 1000
	invoiceResp = createAssetInvoice(
		t.t, dave, yara, yaraInvoiceAssetAmount1, nil,
		withInvGroupKey(groupID),
	)
	payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp.PaymentRequest, assetID,
		withSmallShards(),
	)
	logBalance(t.t, nodes, assetID, "after asset-to-asset")

	charlieAssetBalance -= yaraInvoiceAssetAmount1
	yaraAssetBalance += yaraInvoiceAssetAmount1

	// ------------
	// Test case 9: Now we'll close each of the channels, starting with
	// the Charlie -> Dave custom channel.
	// ------------
	t.Logf("Closing Charlie -> Dave channel")
	closeAssetChannelAndAssert(
		t, net, charlie, dave, chanPointCD, [][]byte{assetID},
		groupID, charlie,
		assertDefaultCoOpCloseBalance(true, true),
	)

	t.Logf("Closing Dave -> Yara channel")
	closeAssetChannelAndAssert(
		t, net, dave, yara, chanPointDY, [][]byte{assetID},
		groupID, charlie,
		assertDefaultCoOpCloseBalance(false, true),
	)

	t.Logf("Closing Erin -> Fabia channel")
	closeAssetChannelAndAssert(
		t, net, erin, fabia, chanPointEF, [][]byte{assetID},
		groupID, charlie,
		assertDefaultCoOpCloseBalance(true, true),
	)

	// We've been tracking the off-chain channel balances all this time,
	// so now that we have the assets on-chain again, we can assert
	// them. Due to rounding errors that happened when sending multiple
	// shards with MPP, we need to do some slight adjustments.
	charlieAssetBalance += 2
	daveAssetBalance -= 1
	erinAssetBalance += 3
	fabiaAssetBalance -= 3
	yaraAssetBalance -= 1
	assertBalance(
		t.t, charlie, charlieAssetBalance,
		itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, dave, daveAssetBalance,
		itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, erin, erinAssetBalance,
		itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, fabia, fabiaAssetBalance,
		itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, yara, yaraAssetBalance,
		itest.WithAssetID(assetID),
	)

	// ------------
	// Test case 10: We now open a new asset channel and close it again,
	// to make sure that a non-existent remote balance is handled
	// correctly.
	// ------------
	t.Logf("Opening new asset channel between Charlie and Dave...")
	fundRespCD, err := asTapd(charlie).FundChannel(
		context.Background(), &tchrpc.FundChannelRequest{
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
		t.t, charlie, nil, groupID, fundingScriptTreeBytes,
		fmt.Sprintf(
			"%v:%v", fundRespCD.Txid, fundRespCD.OutputIndex,
		),
	)
	assertAssetChan(
		t.t, charlie, dave, fundingAmount,
		[]*taprpc.Asset{cents},
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
		t, net, charlie, dave, chanPointCD, [][]byte{assetID},
		groupID, charlie,
		assertDefaultCoOpCloseBalance(false, false),
	)

	// Charlie should have asset outputs: the leftover change from the
	// channel funding, and the new close output.
	assertBalance(
		t.t, charlie, charlieAssetBalance,
		itest.WithAssetID(assetID), itest.WithNumUtxos(2),
	)

	// The asset balances should still remain unchanged.
	assertBalance(
		t.t, charlie, charlieAssetBalance,
		itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, dave, daveAssetBalance,
		itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, erin, erinAssetBalance,
		itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, fabia, fabiaAssetBalance,
		itest.WithAssetID(assetID),
	)
}
