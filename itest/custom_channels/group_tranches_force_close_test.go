//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsGroupTranchesForceClose tests that we can successfully
// open a custom channel with multiple pieces of a grouped asset. We then test
// that we can successfully co-op and force close such channels and sweep the
// remaining channel balances.
func testCustomChannelsGroupTranchesForceClose(ctx context.Context,
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

	// The topology we are going for looks like the following:
	//
	// Charlie --[assets]--> Dave --[sats]--> Erin --[assets]--> Fabia
	//
	// With [assets] being a custom channel and [sats] being a normal,
	// BTC only channel.
	charlieLndArgs := slices.Clone(lndArgs)
	charlieLndArgs = append(charlieLndArgs, fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", charliePort,
	))
	charlie := net.NewNode("Charlie", charlieLndArgs, tapdArgs)
	dave := net.NewNode("Dave", lndArgs, tapdArgs)
	erin := net.NewNode("Erin", lndArgs, tapdArgs)
	fabia := net.NewNode("Fabia", lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{charlie, dave, erin, fabia}
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

	// Mint the asset tranches 1 and 2 on Charlie and sync all nodes to
	// Charlie as the universe.
	mintedAssetsT1 := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{groupAssetReq},
	)
	centsT1 := mintedAssetsT1[0]
	assetID1 := centsT1.AssetGenesis.AssetId
	groupKey := centsT1.GetAssetGroup().GetTweakedGroupKey()

	groupAssetReq = itest.CopyRequest(&mintrpc.MintAssetRequest{
		Asset: ccItestAsset,
	})
	groupAssetReq.Asset.GroupedAsset = true
	groupAssetReq.Asset.GroupKey = groupKey
	groupAssetReq.Asset.Name = "itest-asset-cents-tranche-2"

	mintedAssetsT2 := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{groupAssetReq},
	)
	centsT2 := mintedAssetsT2[0]
	assetID2 := centsT2.AssetGenesis.AssetId

	t.Logf("Minted lightning cents tranche 1 (%x) and 2 (%x) for "+
		"group key %x, syncing universes...",
		assetID1, assetID2, groupKey)
	syncUniverses(t.t, charlie, dave, erin, fabia)
	t.Logf("Universes synced between all nodes, distributing " +
		"assets...")

	chanPointCD, chanPointEF := createTestAssetNetworkGroupKey(
		ctx, t, net, charlie, dave, erin, fabia, charlie,
		[]*taprpc.Asset{centsT1, centsT2},
		fundingAmount, fundingAmount, DefaultPushSat,
	)

	t.Logf("Created channels %v and %v", chanPointCD, chanPointEF)

	// We now send some assets over the channels to test the
	// functionality. Print initial channel balances.
	groupIDs := [][]byte{assetID1, assetID2}
	logBalanceGroup(t.t, nodes, groupIDs, "initial")

	// ------------
	// Test case 1: Send a few direct keysend payments from Charlie to
	// Dave. We want to send at least 30k assets, so we use up one
	// channel internal tranche of assets and should at least once have
	// an HTLC that transports assets from two tranches.
	// ------------
	const (
		keySendAmount    = 5000
		keySendSatAmount = 5000
		numSends         = 6
		totalFirstSend   = keySendAmount * numSends
	)
	for i := 0; i < numSends; i++ {
		sendAssetKeySendPayment(
			t.t, charlie, dave, keySendAmount, nil,
			fn.None[int64](), withGroupKey(groupKey),
		)
	}

	// With noop HTLCs implemented the sats balance of Dave will only
	// increase up to the reserve amount. Let's make a direct non-asset
	// keysend to make sure the sats balance is also enough.
	sendKeySendPayment(t.t, charlie, dave, keySendSatAmount)

	logBalanceGroup(t.t, nodes, groupIDs, "after keysend Charlie->Dave")

	// ------------
	// Test case 2: Send a few direct keysend payments from Erin to
	// Fabia.
	// ------------
	for i := 0; i < numSends; i++ {
		sendAssetKeySendPayment(
			t.t, erin, fabia, keySendAmount, nil,
			fn.None[int64](), withGroupKey(groupKey),
		)
	}
	logBalanceGroup(
		t.t, nodes, groupIDs, "after keysend Erin->Fabia",
	)

	// We also assert that in a grouped channel with multiple grouped
	// asset UTXOs we get a proper error if we try to do payments or
	// create invoices while using a single asset ID.
	sendAssetKeySendPayment(
		t.t, erin, fabia, keySendAmount, assetID1,
		fn.None[int64](),
		withPayErrSubStr(
			"make sure to use group key for grouped "+
				"asset channels",
		),
	)
	createAssetInvoice(
		t.t, charlie, dave, 100, assetID1, withInvoiceErrSubStr(
			"make sure to use group key for grouped "+
				"asset channels",
		),
	)
	invoiceResp := createAssetInvoice(
		t.t, charlie, dave, keySendAmount, nil,
		withInvGroupKey(groupKey),
	)
	payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp.PaymentRequest, assetID1,
		withPayErrSubStr(
			"make sure to use group key for grouped "+
				"asset channels",
		),
	)

	// ------------
	// Test case 3: Co-op close the channel between Charlie and Dave.
	// ------------
	t.Logf("Closing Charlie -> Dave channel")
	closeAssetChannelAndAssert(
		t, net, charlie, dave, chanPointCD,
		[][]byte{assetID1, assetID2}, groupKey, charlie,
		assertDefaultCoOpCloseBalance(true, true),
	)

	assertSpendableBalance(
		t.t, charlie, nil, groupKey,
		fundingAmount-totalFirstSend+2,
	)
	assertSpendableBalance(
		t.t, dave, nil, groupKey, totalFirstSend,
	)

	// ------------
	// Test case 4: Force close the channel between Erin and Fabia.
	// ------------
	_, closeTxid, err := net.CloseChannel(erin, chanPointEF, true)
	require.NoError(t.t, err)

	t.Logf("Channel force closed! Mining blocks, close_txid=%v",
		closeTxid)

	// Next, we'll mine a block to confirm the force close.
	mineBlocks(t, net, 1, 1)

	// At this point, we should have the force close transaction in the
	// set of transfers for both nodes.
	forceCloseTransfer := findForceCloseTransfer(
		t.t, erin, fabia, closeTxid,
	)
	// Now that we have the transfer on disk, we'll also assert that
	// the universe also has proof for both the relevant transfer
	// outputs.
	for _, transfer := range forceCloseTransfer.Transfers {
		for _, transferOut := range transfer.Outputs {
			assertUniverseProofExists(
				t.t, charlie, transferOut.AssetId,
				groupKey, transferOut.ScriptKey,
				transferOut.Anchor.Outpoint,
			)
		}
	}

	t.Logf("Universe proofs located!")

	// We should also have a new sweep transaction in the mempool.
	fabiaSweepTxid, err := waitForNTxsInMempool(
		net.Miner.Client, 1, ccShortTimeout,
	)
	require.NoError(t.t, err)

	t.Logf("Fabia sweep txid: %v", fabiaSweepTxid)

	mineBlocks(t, net, 1, 1)

	// Fabia should have her sweep output confirmed now, and the assets
	// should be back in her on-chain wallet and spendable.
	assertSpendableBalance(
		t.t, fabia, nil, groupKey, totalFirstSend,
	)

	// Next, we'll mine three additional blocks to trigger the CSV
	// delay for Erin.
	mineBlocks(t, net, 4, 0)

	// We expect that Erin's sweep transaction has been broadcast.
	_, err = waitForNTxsInMempool(
		net.Miner.Client, 1, ccShortTimeout,
	)
	require.NoError(t.t, err)

	// Now we'll mine a block to confirm Erin's sweep transaction. We use
	// the txid from the mined block to avoid RBF mismatches.
	erinSweepBlocks := mineBlocks(t, net, 1, 1)
	erinSweepTxHash := erinSweepBlocks[0].Transactions[1].TxHash()

	t.Logf("Erin sweep txid: %v", erinSweepTxHash)

	// Erin should now have an asset transfer for her sweep transaction.
	locateAssetTransfers(t.t, erin, erinSweepTxHash)

	assertSpendableBalance(
		t.t, erin, nil, groupKey, fundingAmount-totalFirstSend,
	)
}
