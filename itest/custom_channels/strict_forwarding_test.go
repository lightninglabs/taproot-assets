//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsStrictForwarding tests the strict forwarding behavior of
// custom channels. It verifies that:
// 1. A satoshi payment to an asset invoice is rejected by strict forwarding.
// 2. The asset invoice can still be paid with assets after the failed attempt.
// 3. An asset payment to a BTC invoice is rejected.
// 4. The BTC invoice can still be paid with satoshis after the failed attempt.
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
func testCustomChannelsStrictForwarding(_ context.Context,
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
			Amt:         10_000_000,
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

	t.Logf("Minted %d lightning cents, syncing universes...", cents.Amount)
	syncUniverses(t.t, charlie, dave, erin, fabia, yara)
	t.Logf("Universes synced between all nodes, distributing assets...")

	const (
		daveFundingAmount = uint64(400_000)
		erinFundingAmount = uint64(200_000)
	)
	charlieFundingAmount := cents.Amount - uint64(2*400_000)

	_, _, _ = createTestAssetNetwork(
		t, net, charlie, dave, erin, fabia, yara, charlie,
		cents, 400_000, charlieFundingAmount,
		daveFundingAmount, erinFundingAmount, 0,
	)

	// Before we start sending out payments, let's make sure each node can
	// see the other one in the graph and has all required features.
	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))
	require.NoError(t.t, net.AssertNodeKnown(dave, yara))
	require.NoError(t.t, net.AssertNodeKnown(yara, dave))
	require.NoError(t.t, net.AssertNodeKnown(erin, fabia))
	require.NoError(t.t, net.AssertNodeKnown(fabia, erin))
	require.NoError(t.t, net.AssertNodeKnown(charlie, erin))

	logBalance(t.t, nodes, assetID, "initial")

	// Do a payment from Charlie to Erin to shift the balances in all
	// channels enough to allow for the following payments in any direction.
	// Pay a normal bolt11 invoice involving RFQ flow.
	_ = createAndPayNormalInvoice(
		t.t, charlie, dave, erin, 500_000, assetID, withSmallShards(),
	)

	logBalance(t.t, nodes, assetID, "after payment")

	// Edge case: Now Dave creates an asset invoice to be paid for by Erin
	// with satoshi. For the last hop we try to settle the invoice in
	// satoshi, where we will check whether Dave's strict forwarding
	// works as expected. Charlie is only used as a dummy RFQ peer in this
	// case, Erin totally ignores the RFQ hint and just pays with sats.
	assetInvoice := createAssetInvoice(t.t, charlie, dave, 40, assetID)

	ctx := context.Background()
	assetInvoiceStream, err := dave.InvoicesClient.SubscribeSingleInvoice(
		ctx, &invoicesrpc.SubscribeSingleInvoiceRequest{
			RHash: assetInvoice.RHash,
		},
	)
	require.NoError(t.t, err)

	// Erin pays Dave with enough satoshis, but Dave will not settle as
	// he expects assets.
	hops := [][]byte{dave.PubKey[:]}
	payInvoiceWithSatoshiLastHop(t.t, erin, assetInvoice, hops, withFailure(
		lnrpc.Payment_FAILED, 0,
	))

	// Make sure the invoice hasn't been settled and there's no HTLC on the
	// channel between Erin and Dave.
	assertLNDInvoiceState(
		t.t, assetInvoiceStream, lnrpc.Invoice_OPEN,
	)
	assertHTLCNotActive(t.t, erin, channelOp, assetInvoice.RHash)
	assertInvoiceState(
		t.t, dave, assetInvoice.PaymentAddr, lnrpc.Invoice_OPEN,
	)

	logBalance(t.t, nodes, assetID, "after failed payment (asset "+
		"invoice, strict forwarding)")

	// Now let's make sure that we can actually still pay the invoice with
	// assets from Charlie.
	payInvoiceWithAssets(
		t.t, charlie, dave, assetInvoice.PaymentRequest, assetID,
	)
	assertLNDInvoiceState(
		t.t, assetInvoiceStream, lnrpc.Invoice_SETTLED,
	)
	assertInvoiceState(
		t.t, dave, assetInvoice.PaymentAddr, lnrpc.Invoice_SETTLED,
	)

	// Edge case: We now try the opposite: Dave creates a BTC invoice but
	// Charlie tries to pay it with assets. This should fail as well.
	btcInvoice := createNormalInvoice(t.t, dave, 1_000)
	btcInvoiceStream, err := dave.InvoicesClient.SubscribeSingleInvoice(
		ctx, &invoicesrpc.SubscribeSingleInvoiceRequest{
			RHash: btcInvoice.RHash,
		},
	)
	require.NoError(t.t, err)

	payInvoiceWithAssets(
		t.t, charlie, dave, btcInvoice.PaymentRequest, assetID,
		withFailure(lnrpc.Payment_FAILED, failureIncorrectDetails),
	)
	assertLNDInvoiceState(
		t.t, btcInvoiceStream, lnrpc.Invoice_OPEN,
	)
	assertHTLCNotActive(t.t, erin, channelOp, btcInvoice.RHash)
	assertInvoiceState(
		t.t, dave, btcInvoice.PaymentAddr, lnrpc.Invoice_OPEN,
	)

	// And finally we make sure that we can still pay the invoice with
	// satoshis from Erin, using custom records.
	payInvoiceWithSatoshi(t.t, erin, btcInvoice, withDestCustomRecords(
		map[uint64][]byte{106823: {0x01}},
	))
	assertLNDInvoiceState(
		t.t, btcInvoiceStream, lnrpc.Invoice_SETTLED,
	)
	assertInvoiceState(
		t.t, dave, btcInvoice.PaymentAddr, lnrpc.Invoice_SETTLED,
	)
}
