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
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsHtlcForceClose tests that we can force close a channel
// with HTLCs in both directions and that the HTLC outputs are correctly
// swept.
func testCustomChannelsHtlcForceClose(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	runCustomChannelsHtlcForceClose(ctx, t, net, false)
}

// testCustomChannelsHtlcForceCloseMpp tests that we can force close a channel
// with HTLCs in both directions and that the HTLC outputs are correctly
// swept, using MPP.
func testCustomChannelsHtlcForceCloseMpp(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	runCustomChannelsHtlcForceClose(ctx, t, net, true)
}

// runCustomChannelsHtlcForceClose is a helper function that runs the HTLC force
// close test with the given MPP setting.
func runCustomChannelsHtlcForceClose(ctx context.Context, t *ccHarnessTest,
	net *itest.IntegratedNetworkHarness, mpp bool) {

	t.Logf("Running test with MPP: %v", mpp)

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// Zane will serve as our designated Universe node.
	zane := net.NewNode("Zane", lndArgs, tapdArgs)

	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType, zane.RPCAddr(),
	))

	// Next, we'll make Alice and Bob, who will be the main nodes under
	// test.
	alice := net.NewNode("Alice", lndArgs, tapdArgs)
	bob := net.NewNode("Bob", lndArgs, tapdArgs)

	// Now we'll connect all nodes, and also fund them with some coins.
	nodes := []*itest.IntegratedNode{alice, bob}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Next, we'll mint an asset for Alice, who will be the node that opens
	// the channel outbound.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(alice),
		[]*mintrpc.MintAssetRequest{
			{
				Asset: ccItestAsset,
			},
		},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId

	t.Logf("Minted %d lightning cents, syncing universes...", cents.Amount)
	syncUniverses(t.t, alice, bob)
	t.Logf("Universes synced between all nodes, distributing assets...")

	// With the assets created, and synced -- we'll now open the channel
	// between Alice and Bob.
	t.Logf("Opening asset channels...")
	assetFundResp, err := alice.FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         bob.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)

	aliceChanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(assetFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: assetFundResp.Txid,
		},
	}

	t.Logf("Funded channel between Alice and Bob: %v", assetFundResp)

	// With the channel open, mine a block to confirm it.
	mineBlocks(t, net, 6, 1)

	// Before we start sending out payments, let's make sure each node can
	// see the other one in the graph and has all required features.
	require.NoError(t.t, net.AssertNodeKnown(alice, bob))
	require.NoError(t.t, net.AssertNodeKnown(bob, alice))

	// First, we'll send over some funds from Alice to Bob, as we want Bob
	// to be able to extend HTLCs in the other direction.
	const (
		numPayments        = 10
		keySendAssetAmount = 2_500
		keySendSatAmount   = 5_000
	)
	for i := 0; i < numPayments; i++ {
		sendAssetKeySendPayment(
			t.t, alice, bob, keySendAssetAmount, assetID,
			fn.None[int64](),
		)
	}

	// With noop HTLCs implemented the sats balance of Bob will only
	// increase up to the reserve amount. Let's make a direct non-asset
	// keysend to make sure the sats balance is also enough.
	sendKeySendPayment(t.t, alice, bob, keySendSatAmount)

	logBalance(t.t, nodes, assetID, "after keysends to Bob")

	// Now that both parties have some funds, we'll move onto the main test.
	//
	// We'll make 2 hodl invoice for each peer, so 4 total. From Alice's
	// PoV, she'll have two outgoing HTLCs (or +4 with MPP), and two
	// incoming HTLCs.
	var (
		bobHodlInvoices   []assetHodlInvoice
		aliceHodlInvoices []assetHodlInvoice

		// The default oracle rate is 17_180 mSat/asset unit, so 10_000
		// will be equal to 171_800_000 mSat. When we use the mpp bool
		// for the smallShards param of payInvoiceWithAssets, that
		// means we'll split the payment into shards of 80_000_000 mSat
		// max. So we'll get three shards per payment.
		assetInvoiceAmt   = 10_000
		assetsPerMPPShard = 4656
	)
	for i := 0; i < 2; i++ {
		bobHodlInvoices = append(
			bobHodlInvoices, createAssetHodlInvoice(
				t.t, alice, bob, uint64(assetInvoiceAmt),
				assetID,
			),
		)
		aliceHodlInvoices = append(
			aliceHodlInvoices, createAssetHodlInvoice(
				t.t, bob, alice, uint64(assetInvoiceAmt),
				assetID,
			),
		)
	}

	// Now we'll have both Bob and Alice pay each other's invoices. We only
	// care that they're in flight at this point, as they won't be settled
	// yet.
	for _, aliceInvoice := range aliceHodlInvoices {
		opts := []payOpt{
			withFailure(
				lnrpc.Payment_IN_FLIGHT,
				lnrpc.PaymentFailureReason_FAILURE_REASON_NONE,
			),
		}
		if mpp {
			opts = append(opts, withSmallShards())
		}
		payInvoiceWithAssets(
			t.t, bob, alice, aliceInvoice.payReq, assetID, opts...,
		)
	}
	for _, bobInvoice := range bobHodlInvoices {
		payInvoiceWithAssets(
			t.t, alice, bob, bobInvoice.payReq, assetID,
			withFailure(
				lnrpc.Payment_IN_FLIGHT,
				lnrpc.PaymentFailureReason_FAILURE_REASON_NONE,
			),
		)
	}

	// Make sure we can sweep all the HTLCs.
	aliceExpectedBalance, bobExpectedBalance := assertForceCloseSweeps(
		ctx, net, t, alice, bob, aliceChanPoint,
		ccItestAsset.Amount-fundingAmount, assetInvoiceAmt,
		assetsPerMPPShard, assetID, nil, aliceHodlInvoices,
		bobHodlInvoices, mpp,
	)

	// Finally, we'll assert that Alice's balance has been incremented by
	// the timeout value.
	aliceExpectedBalance += uint64(assetInvoiceAmt - 1)
	t.Logf("Expecting Alice's balance to be %d", aliceExpectedBalance)
	assertSpendableBalance(
		t.t, alice, assetID, nil, aliceExpectedBalance,
	)

	t.Logf("Sending all settled funds to Zane")

	// As a final sanity check, both Alice and Bob should be able to send
	// their entire balances to Zane, our 3rd party.
	//
	// We'll make two addrs for Zane, one for Alice, and one for bob.
	aliceAddr, err := zane.NewAddr(ctx, &taprpc.NewAddrRequest{
		Amt:     aliceExpectedBalance,
		AssetId: assetID,
		ProofCourierAddr: fmt.Sprintf(
			"%s://%s", proof.UniverseRpcCourierType,
			zane.RPCAddr(),
		),
	})
	require.NoError(t.t, err)
	bobAddr, err := zane.NewAddr(ctx, &taprpc.NewAddrRequest{
		Amt:     bobExpectedBalance,
		AssetId: assetID,
		ProofCourierAddr: fmt.Sprintf(
			"%s://%s", proof.UniverseRpcCourierType,
			zane.RPCAddr(),
		),
	})
	require.NoError(t.t, err)

	_, err = alice.SendAsset(ctx, &taprpc.SendAssetRequest{
		TapAddrs: []string{aliceAddr.Encoded},
	})
	require.NoError(t.t, err)
	mineBlocks(t, net, 1, 1)

	itest.AssertNonInteractiveRecvComplete(t.t, asTapd(zane), 1)

	_, err = bob.SendAsset(ctx, &taprpc.SendAssetRequest{
		TapAddrs: []string{bobAddr.Encoded},
	})
	require.NoError(t.t, err)
	mineBlocks(t, net, 1, 1)

	itest.AssertNonInteractiveRecvComplete(t.t, asTapd(zane), 2)

	// Zane's balance should now be the sum of Alice's and Bob's balances.
	zaneExpectedBalance := aliceExpectedBalance + bobExpectedBalance
	assertSpendableBalance(
		t.t, zane, assetID, nil, zaneExpectedBalance,
	)
}
