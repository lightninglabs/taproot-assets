//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsLarge tests a 5-node network topology with asset channels,
// BTC channels, multi-hop asset payments, keysend payments, and cooperative
// channel closing.
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
func testCustomChannelsLarge(_ context.Context,
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
			Amt:         10_000_000,
			SatPerVByte: 5,
		},
	)
	defer closeChannelAndAssert(t, net, dave, channelOp, false)

	// This is the only public channel, we need everyone to be aware of
	// it.
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

	t.Logf("Minted %d lightning cents, syncing universes...",
		cents.Amount)
	syncUniverses(t.t, charlie, dave, erin, fabia, yara)
	t.Logf("Universes synced between all nodes, distributing " +
		"assets...")

	const (
		daveFundingAmount = uint64(400_000)
		erinFundingAmount = uint64(200_000)
	)
	charlieFundingAmount := cents.Amount - uint64(2*400_000)

	chanPointCD, _, _ := createTestAssetNetwork(
		t, net, charlie, dave, erin, fabia, yara, charlie,
		cents, 400_000, charlieFundingAmount,
		daveFundingAmount, erinFundingAmount, DefaultPushSat,
	)

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

	// Try larger invoice payments, first from Charlie to Fabia, then
	// half of the amount back in the other direction.
	const fabiaInvoiceAssetAmount = 20_000
	invoiceResp := createAssetInvoice(
		t.t, erin, fabia, fabiaInvoiceAssetAmount, assetID,
	)
	payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp.PaymentRequest, assetID,
	)
	logBalance(t.t, nodes, assetID, "after invoice")

	invoiceResp2 := createAssetInvoice(
		t.t, dave, charlie, fabiaInvoiceAssetAmount/2, assetID,
	)

	// Sleep for a second to make sure the balances fully propagated
	// before we make the payment. Otherwise, we'll make an RFQ order
	// with a max amount of zero.
	time.Sleep(time.Second * 1)

	payInvoiceWithAssets(
		t.t, fabia, erin, invoiceResp2.PaymentRequest, assetID,
	)
	logBalance(t.t, nodes, assetID, "after invoice 2")

	// Now we send a large invoice from Charlie to Dave.
	const largeInvoiceAmount = 100_000
	invoiceResp3 := createAssetInvoice(
		t.t, charlie, dave, largeInvoiceAmount, assetID,
	)
	payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp3.PaymentRequest, assetID,
	)
	logBalance(t.t, nodes, assetID, "after invoice 3")

	// Make sure the invoice on the receiver side and the payment on the
	// sender side show the individual HTLCs that arrived for it and
	// that they show the correct asset amounts when decoded.
	assertInvoiceHtlcAssets(
		t.t, dave, invoiceResp3, assetID, nil, largeInvoiceAmount,
	)
	assertPaymentHtlcAssets(
		t.t, charlie, invoiceResp3.RHash, assetID, nil,
		largeInvoiceAmount,
	)

	// We keysend the rest, so that all the balance is on Dave's side.
	charlieRemainingBalance := charlieFundingAmount -
		largeInvoiceAmount - fabiaInvoiceAssetAmount/2
	sendAssetKeySendPayment(
		t.t, charlie, dave, charlieRemainingBalance,
		assetID, fn.None[int64](),
	)
	logBalance(t.t, nodes, assetID, "after keysend")

	// And now we close the channel to test how things look if all the
	// balance is on the non-initiator (recipient) side.
	t.Logf("Closing Charlie -> Dave channel")
	closeAssetChannelAndAssert(
		t, net, charlie, dave, chanPointCD, [][]byte{assetID},
		nil, charlie,
		initiatorZeroAssetBalanceCoOpBalanceCheck,
	)
}
