//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	rfqrpc "github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsForwardBandwidth is a test that runs through some Taproot
// Assets Channel liquidity edge cases, specifically related to forwarding HTLCs
// into channels with no available asset bandwidth.
//
//nolint:lll
func testCustomChannelsForwardBandwidth(ctx context.Context,
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

	_, _, chanPointEF := createTestAssetNetwork(
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

	// We now deplete the channel between Erin and Fabia by moving all
	// assets to Fabia.
	sendAssetKeySendPayment(
		t.t, erin, fabia, erinFundingAmount, assetID,
		fn.None[int64](),
	)
	logBalance(t.t, nodes, assetID, "after moving assets to Fabia")

	// Test case 1: We cannot keysend more assets from Erin to Fabia.
	sendAssetKeySendPayment(
		t.t, erin, fabia, 1, assetID, fn.None[int64](),
		withFailure(lnrpc.Payment_FAILED, failureNoBalance),
	)

	// Test case 2: We cannot pay an invoice from Charlie to Fabia.
	invoiceResp := createAssetInvoice(t.t, erin, fabia, 123, assetID)
	payInvoiceWithSatoshi(
		t.t, charlie, invoiceResp,
		withFailure(lnrpc.Payment_FAILED, failureNoRoute),
	)

	// Test case 3: We now create an asset buy order for a normal amount of
	// assets. We then "fake" an invoice referencing that buy order that
	// is for an amount that is too small to be paid with a single asset
	// unit. This should be handled gracefully and not lead to a crash.
	// Ideally such an invoice shouldn't be created in the first place, but
	// we want to make sure that the system doesn't crash in this case.
	numUnits := uint64(10)
	buyOrderResp, err := asTapd(fabia).AddAssetBuyOrder(
		ctx, &rfqrpc.AddAssetBuyOrderRequest{
			AssetSpecifier: &rfqrpc.AssetSpecifier{
				Id: &rfqrpc.AssetSpecifier_AssetId{
					AssetId: assetID,
				},
			},
			AssetMaxAmt: numUnits,
			Expiry: uint64(
				time.Now().Add(time.Hour).Unix(),
			),
			PeerPubKey:     erin.PubKey[:],
			TimeoutSeconds: 10,
		},
	)
	require.NoError(t.t, err)

	quoteResp := buyOrderResp.Response
	quote, ok := quoteResp.(*rfqrpc.AddAssetBuyOrderResponse_AcceptedQuote)
	require.True(t.t, ok)

	// We calculate the milli-satoshi amount one below the equivalent of a
	// single asset unit.
	rate, err := rpcutils.UnmarshalRfqFixedPoint(
		quote.AcceptedQuote.AskAssetRate,
	)
	require.NoError(t.t, err)

	oneUnit := uint64(1)
	oneUnitFP := rfqmath.NewBigIntFixedPoint(oneUnit, 0)
	oneUnitMilliSat := rfqmath.UnitsToMilliSatoshi(oneUnitFP, *rate)

	t.Logf("Got quote for %v asset units per BTC", rate)
	msatPerUnit := float64(oneUnitMilliSat) / float64(oneUnit)
	t.Logf("Got quote for %v asset units at %3f msat/unit from peer %s "+
		"with SCID %d", numUnits, msatPerUnit, erin.PubKeyStr,
		quote.AcceptedQuote.Scid)

	// We now manually add the invoice in order to inject the above,
	// manually generated, quote.
	hopHint := &lnrpc.HopHint{
		NodeId:                    erin.PubKeyStr,
		ChanId:                    quote.AcceptedQuote.Scid,
		CltvExpiryDelta:           80,
		FeeBaseMsat:               1000,
		FeeProportionalMillionths: 1,
	}
	invoiceResp2, err := fabia.LightningClient.AddInvoice(
		ctx, &lnrpc.Invoice{
			Memo:      "too small invoice",
			ValueMsat: int64(oneUnitMilliSat - 1),
			RouteHints: []*lnrpc.RouteHint{{
				HopHints: []*lnrpc.HopHint{hopHint},
			}},
		},
	)
	require.NoError(t.t, err)

	payInvoiceWithSatoshi(t.t, dave, invoiceResp2, withFailure(
		lnrpc.Payment_FAILED, failureNoRoute,
	))

	// Let's make sure we can still use the channel between Erin and Fabia
	// by doing a satoshi keysend payment.
	sendKeySendPayment(t.t, erin, fabia, 2000)
	logBalance(t.t, nodes, assetID, "after BTC only keysend")

	// Finally, we close the channel between Erin and Fabia to make sure
	// everything is settled correctly.
	closeAssetChannelAndAssert(
		t, net, erin, fabia, chanPointEF, [][]byte{assetID}, nil,
		charlie, noOpCoOpCloseBalanceCheck,
	)
}
