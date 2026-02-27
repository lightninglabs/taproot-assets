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
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsGroupTranchesHtlcForceClose tests that we can
// successfully open a custom channel with multiple pieces of a grouped
// asset, then force close it while having pending HTLCs. We then test
// that we can successfully sweep all balances from those HTLCs.
func testCustomChannelsGroupTranchesHtlcForceClose(ctx context.Context,
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

	chanPointCD, _ := createTestAssetNetworkGroupKey(
		ctx, t, net, charlie, dave, erin, fabia, charlie,
		[]*taprpc.Asset{centsT1, centsT2},
		fundingAmount, fundingAmount, DefaultPushSat,
	)

	t.Logf("Created channel %v", chanPointCD)

	// We now send some assets over the channels to test the
	// functionality. Print initial channel balances.
	groupIDs := [][]byte{assetID1, assetID2}
	logBalanceGroup(t.t, nodes, groupIDs, "initial")

	// First, we'll send over some funds from Charlie to Dave, as we
	// want Dave to be able to extend HTLCs in the other direction.
	const (
		numPayments      = 10
		keySendAmount    = 2_500
		keySendSatAmount = 5_000
	)
	for i := 0; i < numPayments; i++ {
		sendAssetKeySendPayment(
			t.t, charlie, dave, keySendAmount, nil,
			fn.None[int64](), withGroupKey(groupKey),
		)
	}

	// With noop HTLCs implemented the sats balance of Dave will only
	// increase up to the reserve amount. Let's make a direct non-asset
	// keysend to make sure the sats balance is also enough.
	sendKeySendPayment(t.t, charlie, dave, keySendSatAmount)

	// Now that both parties have some funds, we'll move onto the main
	// test.
	//
	// We'll make 2 hodl invoices for each peer, so 4 total. From
	// Charlie's PoV, he'll have 6 outgoing HTLCs, and two incoming
	// HTLCs.
	var (
		daveHodlInvoices    []assetHodlInvoice
		charlieHodlInvoices []assetHodlInvoice

		// The default oracle rate is 17_180 mSat/asset unit, so
		// 10_000 will be equal to 171_800_000 mSat. When we use the
		// mpp bool for the smallShards param of
		// payInvoiceWithAssets, that means we'll split the payment
		// into shards of 80_000_000 mSat max. So we'll get three
		// shards per payment.
		assetInvoiceAmt   = 10_000
		assetsPerMPPShard = 4656
	)
	for i := 0; i < 2; i++ {
		daveHodlInvoices = append(
			daveHodlInvoices, createAssetHodlInvoice(
				t.t, charlie, dave,
				uint64(assetInvoiceAmt), nil,
				withInvGroupKey(groupKey),
			),
		)
		charlieHodlInvoices = append(
			charlieHodlInvoices, createAssetHodlInvoice(
				t.t, dave, charlie,
				uint64(assetInvoiceAmt), nil,
				withInvGroupKey(groupKey),
			),
		)
	}

	// Now we'll have both Dave and Charlie pay each other's invoices.
	// We only care that they're in flight at this point, as they won't
	// be settled yet.
	baseOpts := []payOpt{
		withGroupKey(groupKey),
		withFailure(
			lnrpc.Payment_IN_FLIGHT,
			lnrpc.PaymentFailureReason_FAILURE_REASON_NONE,
		),
	}
	for _, charlieInvoice := range charlieHodlInvoices {
		// For this direction, we also want to enforce MPP.
		opts := append(slices.Clone(baseOpts), withSmallShards())
		payInvoiceWithAssets(
			t.t, dave, charlie, charlieInvoice.payReq, nil,
			opts...,
		)
	}
	for _, daveInvoice := range daveHodlInvoices {
		payInvoiceWithAssets(
			t.t, charlie, dave, daveInvoice.payReq, nil,
			baseOpts...,
		)
	}

	// Make sure we can sweep all the HTLCs.
	const charlieStartAmount = 2
	charlieExpectedBalance, _ := assertForceCloseSweeps(
		ctx, net, t, charlie, dave, chanPointCD,
		charlieStartAmount, assetInvoiceAmt, assetsPerMPPShard,
		nil, groupKey, charlieHodlInvoices, daveHodlInvoices,
		true,
	)

	// Finally, we'll assert that Charlie's balance has been
	// incremented by the timeout value.
	charlieExpectedBalance += uint64(assetInvoiceAmt - 1)
	t.Logf("Expecting Charlie's balance to be %d",
		charlieExpectedBalance)
	assertSpendableBalance(
		t.t, charlie, nil, groupKey, charlieExpectedBalance,
	)

	t.Logf("Sending all settled funds to Fabia")

	// As a final sanity check, both Charlie and Dave should be able to
	// send their entire balances to Fabia, our 3rd party.
	//
	// We'll make two addrs for Fabia, one for Charlie, and one for
	// Dave.
	charlieSpendableBalanceAsset1, err := spendableBalance(
		charlie, assetID1, nil,
	)
	require.NoError(t.t, err)
	charlieSpendableBalanceAsset2, err := spendableBalance(
		charlie, assetID2, nil,
	)
	require.NoError(t.t, err)

	t.Logf("Charlie's spendable balance asset 1: %d, asset 2: %d",
		charlieSpendableBalanceAsset1,
		charlieSpendableBalanceAsset2)

	fabiaCourierAddr := fmt.Sprintf(
		"%s://%s", proof.UniverseRpcCourierType,
		fabia.RPCAddr(),
	)
	charlieAddr1, err := asTapd(fabia).NewAddr(
		ctx, &taprpc.NewAddrRequest{
			Amt:              charlieSpendableBalanceAsset1,
			AssetId:          assetID1,
			ProofCourierAddr: fabiaCourierAddr,
		},
	)
	require.NoError(t.t, err)
	charlieAddr2, err := asTapd(fabia).NewAddr(
		ctx, &taprpc.NewAddrRequest{
			Amt:              charlieSpendableBalanceAsset2,
			AssetId:          assetID2,
			ProofCourierAddr: fabiaCourierAddr,
		},
	)
	require.NoError(t.t, err)

	daveSpendableBalanceAsset1, err := spendableBalance(
		dave, assetID1, nil,
	)
	require.NoError(t.t, err)
	daveSpendableBalanceAsset2, err := spendableBalance(
		dave, assetID2, nil,
	)
	require.NoError(t.t, err)

	t.Logf("Daves's spendable balance asset 1: %d, asset 2: %d",
		daveSpendableBalanceAsset1, daveSpendableBalanceAsset2)

	daveAddr1, err := asTapd(fabia).NewAddr(
		ctx, &taprpc.NewAddrRequest{
			Amt:              daveSpendableBalanceAsset1,
			AssetId:          assetID1,
			ProofCourierAddr: fabiaCourierAddr,
		},
	)
	require.NoError(t.t, err)
	daveAddr2, err := asTapd(fabia).NewAddr(
		ctx, &taprpc.NewAddrRequest{
			Amt:              daveSpendableBalanceAsset2,
			AssetId:          assetID2,
			ProofCourierAddr: fabiaCourierAddr,
		},
	)
	require.NoError(t.t, err)

	_, err = asTapd(charlie).SendAsset(
		ctx, &taprpc.SendAssetRequest{
			TapAddrs: []string{charlieAddr1.Encoded},
		},
	)
	require.NoError(t.t, err)
	mineBlocks(t, net, 1, 1)

	itest.AssertNonInteractiveRecvComplete(t.t, asTapd(fabia), 1)

	_, err = asTapd(charlie).SendAsset(
		ctx, &taprpc.SendAssetRequest{
			TapAddrs: []string{charlieAddr2.Encoded},
		},
	)
	require.NoError(t.t, err)
	mineBlocks(t, net, 1, 1)

	itest.AssertNonInteractiveRecvComplete(t.t, asTapd(fabia), 2)

	_, err = asTapd(dave).SendAsset(
		ctx, &taprpc.SendAssetRequest{
			TapAddrs: []string{daveAddr1.Encoded},
		},
	)
	require.NoError(t.t, err)
	mineBlocks(t, net, 1, 1)

	itest.AssertNonInteractiveRecvComplete(t.t, asTapd(fabia), 3)

	_, err = asTapd(dave).SendAsset(
		ctx, &taprpc.SendAssetRequest{
			TapAddrs: []string{daveAddr2.Encoded},
		},
	)
	require.NoError(t.t, err)
	mineBlocks(t, net, 1, 1)

	itest.AssertNonInteractiveRecvComplete(t.t, asTapd(fabia), 4)

	// Fabia's balance should now be the sum of Charlie's and Dave's
	// balances.
	fabiaExpectedBalance := uint64(50_002)
	assertSpendableBalance(
		t.t, fabia, nil, groupKey, fabiaExpectedBalance,
	)
}
