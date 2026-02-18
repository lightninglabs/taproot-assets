//go:build itest

package custom_channels

import (
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	rfqrpc "github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsLiquidityEdgeCasesCore is the core logic of the liquidity
// edge cases. This test goes through certain scenarios that expose edge cases
// and behaviors that proved to be buggy in the past and have been directly
// addressed. It accepts an extra parameter which dictates whether it should use
// group keys or asset IDs.
//
//nolint:lll
func testCustomChannelsLiquidityEdgeCasesCore(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest,
	groupMode bool) {

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

	// Create the normal channel between Dave and Erin. We don't clean up
	// this channel because we expect there to be in-flight HTLCs due to
	// some of the edge cases we're testing. Waiting for those HTLCs to time
	// out would take too long.
	t.Logf("Opening normal channel between Dave and Erin...")
	channelOp := openChannelAndAssert(
		t, net, dave, erin, lntest.OpenChannelParams{
			Amt:         10_000_000,
			SatPerVByte: 5,
		},
	)

	// This is the only public channel, we need everyone to be aware of it.
	assertChannelKnown(t.t, charlie, channelOp)
	assertChannelKnown(t.t, fabia, channelOp)

	assetReq := itest.CopyRequest(&mintrpc.MintAssetRequest{
		Asset: ccItestAsset,
	})

	// In order to use group keys in this test, the asset must belong to a
	// group.
	if groupMode {
		assetReq.Asset.NewGroupedAsset = true
	}

	// Mint an asset on Charlie and sync all nodes to Charlie as the
	// universe.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{assetReq},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId

	// If groupMode is enabled, treat the asset as part of a group by
	// assigning its tweaked group key. Otherwise, treat it as an ungrouped
	// asset using only its asset ID.
	var (
		groupID  []byte
		groupKey *btcec.PublicKey
		err      error
	)
	if groupMode {
		groupID = cents.GetAssetGroup().GetTweakedGroupKey()

		groupKey, err = btcec.ParsePubKey(groupID)
		require.NoError(t.t, err)
	}

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

	// Edge case: We send a single satoshi keysend payment from Dave to
	// Fabia. Which will make it so that Fabia's balance in the channel
	// between Erin and her is 1 satoshi, which is below the dust limit.
	// This is only allowed while Fabia doesn't have any assets on her side
	// yet.
	erinFabiaChan := fetchChannel(t.t, fabia, chanPointEF)
	hinEF := &lnrpc.HopHint{
		NodeId:                    erin.PubKeyStr,
		ChanId:                    erinFabiaChan.PeerScidAlias,
		CltvExpiryDelta:           80,
		FeeBaseMsat:               1000,
		FeeProportionalMillionths: 1,
	}
	sendKeySendPayment(
		t.t, dave, fabia, 1, withPayRouteHints([]*lnrpc.RouteHint{{
			HopHints: []*lnrpc.HopHint{hinEF},
		}}),
	)
	logBalance(t.t, nodes, assetID, "after single sat keysend")

	// We make sure that a single sat keysend payment is not allowed when
	// it carries assets.
	sendAssetKeySendPayment(
		t.t, erin, fabia, 123, assetID, fn.Some[int64](1),
		withPayErrSubStr(
			fmt.Sprintf("keysend payment satoshi amount must be "+
				"greater than or equal to %d satoshis",
				rfqmath.DefaultOnChainHtlcSat),
		),
	)

	// Normal case.
	// Send 50 assets from Charlie to Dave.
	sendAssetKeySendPayment(
		t.t, charlie, dave, 50, assetID, fn.None[int64](),
		withGroupKey(groupID),
	)

	logBalance(t.t, nodes, assetID, "after 50 assets")

	// Normal case.
	// Send 1k sats from Charlie to Dave.
	sendKeySendPayment(t.t, charlie, dave, 1000)

	logBalance(t.t, nodes, assetID, "after 1k sats")

	// Edge case: The channel reserve check should trigger, and we should
	// get a payment failure, not a timeout.
	//
	// Now Dave tries to send 50 assets to Charlie. There shouldn't be
	// enough sats in the channel.
	//
	// Assume an acceptable completion window which is half the payment
	// timeout. If the payment succeeds within this duration this means we
	// didn't fall into a routing loop.
	timeoutChan := time.After(PaymentTimeout / 2)
	done := make(chan bool, 1)

	go func() {
		sendAssetKeySendPayment(
			t.t, dave, charlie, 50, assetID, fn.None[int64](),
			withFailure(lnrpc.Payment_FAILED, failureNoRoute),
			withGroupKey(groupID),
		)

		done <- true
	}()

	select {
	case <-done:
	case <-timeoutChan:
		t.Fatalf("Payment didn't fail within expected time duration")
	}

	logBalance(t.t, nodes, assetID, "after failed 50 assets")

	// Send 10k sats from Charlie to Dave.
	sendKeySendPayment(t.t, charlie, dave, 10000)

	logBalance(t.t, nodes, assetID, "10k sats")

	// Now Dave tries to send 50 assets again, this time he should have
	// enough sats.
	sendAssetKeySendPayment(
		t.t, dave, charlie, 50, assetID, fn.None[int64](),
		withGroupKey(groupID),
	)

	logBalance(t.t, nodes, assetID, "after 50 sats backwards")

	// Edge case: This refers to a bug where an asset allocation would be
	// expected for this HTLC. This is a dust HTLC and it can not carry
	// assets.
	//
	// Send 1 sat from Charlie to Dave.
	sendKeySendPayment(t.t, charlie, dave, 1)

	logBalance(t.t, nodes, assetID, "after 1 sat")

	// Pay a normal bolt11 invoice involving RFQ flow.
	_ = createAndPayNormalInvoice(
		t.t, charlie, dave, erin, 20_000, assetID, withSmallShards(),
		withGroupKey(groupID),
	)

	logBalance(t.t, nodes, assetID, "after 20k sat asset payment")

	// Edge case: There was a bug when paying an asset invoice that would
	// evaluate to more than the channel capacity, causing a payment failure
	// even though enough asset balance exists.
	//
	// Pay a bolt11 invoice with assets, which evaluates to more than the
	// channel btc capacity.
	_ = createAndPayNormalInvoice(
		t.t, charlie, dave, erin, 1_000_000, assetID,
		withSmallShards(), withGroupKey(groupID),
	)

	logBalance(t.t, nodes, assetID, "after big asset payment (btc "+
		"invoice, multi-hop)")

	// Edge case: Big asset invoice paid by direct peer with assets.
	const bigAssetAmount = 100_000

	invoiceResp := createAssetInvoice(
		t.t, charlie, dave, bigAssetAmount, assetID,
		withInvGroupKey(groupID),
	)

	payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp.PaymentRequest, assetID,
		withGroupKey(groupID),
	)

	logBalance(t.t, nodes, assetID, "after big asset payment (asset "+
		"invoice, direct)")

	var groupBytes []byte
	if groupMode {
		groupBytes = schnorr.SerializePubKey(groupKey)
	}

	// Make sure the invoice on the receiver side and the payment on the
	// sender side show the individual HTLCs that arrived for it and that
	// they show the correct asset amounts when decoded.
	assertInvoiceHtlcAssets(
		t.t, dave, invoiceResp, assetID, groupBytes, bigAssetAmount,
	)
	assertPaymentHtlcAssets(
		t.t, charlie, invoiceResp.RHash, assetID, groupBytes,
		bigAssetAmount,
	)

	// Dave sends 200k assets and 5k sats to Yara.
	sendAssetKeySendPayment(
		t.t, dave, yara, 2*bigAssetAmount, assetID, fn.None[int64](),
		withGroupKey(groupID),
	)
	sendKeySendPayment(t.t, dave, yara, 5_000)

	logBalance(t.t, nodes, assetID, "after 200k assets to Yara")

	// Edge case: Now Charlie creates a big asset invoice to be paid for by
	// Yara with assets. This is a multi-hop payment going over 2 asset
	// channels, where the total asset value exceeds the btc capacity of the
	// channels.
	invoiceResp = createAssetInvoice(
		t.t, dave, charlie, bigAssetAmount, assetID,
		withInvGroupKey(groupID),
	)

	payInvoiceWithAssets(
		t.t, yara, dave, invoiceResp.PaymentRequest, assetID,
		withGroupKey(groupID),
	)

	logBalance(t.t, nodes, assetID, "after big asset payment (asset "+
		"invoice, multi-hop)")

	// Edge case: Now Charlie creates a tiny asset invoice to be paid for by
	// Yara with satoshi. This is a multi-hop payment going over 2 asset
	// channels, where the total asset value is less than the default anchor
	// amount of 354 sats.
	createAssetInvoice(
		t.t, dave, charlie, 1, assetID, withInvoiceErrSubStr(
			"no quotes with sufficient expiry",
		),
		withInvGroupKey(groupID),
	)

	logBalance(t.t, nodes, assetID, "after small payment (asset "+
		"invoice, <354sats)")

	// Edge case: We now create a small BTC invoice on Erin and ask Charlie
	// to pay it with assets. We should get a payment failure as the amount
	// is too small to be paid with assets economically. But a payment is
	// still possible, since the amount is large enough to represent a
	// single unit (17.1 sat per unit).
	btcInvoiceResp, err := erin.LightningClient.AddInvoice(
		ctx, &lnrpc.Invoice{
			Memo:      "small BTC invoice",
			ValueMsat: 18_000,
		},
	)
	require.NoError(t.t, err)

	payInvoiceWithAssets(
		t.t, charlie, dave, btcInvoiceResp.PaymentRequest, assetID,
		withFeeLimit(2_000), withGroupKey(groupID), withPayErrSubStr(
			"failed to acquire any quotes",
		),
	)

	// When we override the uneconomical payment, it should succeed.
	payInvoiceWithAssets(
		t.t, charlie, dave, btcInvoiceResp.PaymentRequest, assetID,
		withFeeLimit(2_000), withAllowOverpay(),
		withGroupKey(groupID),
	)
	logBalance(
		t.t, nodes, assetID, "after small payment (BTC invoice 1 sat)",
	)

	// When we try to pay an invoice amount that's smaller than the
	// corresponding value of a single asset unit, the payment will always
	// be rejected, even if we set the allow_uneconomical flag.
	btcInvoiceResp, err = erin.LightningClient.AddInvoice(
		ctx, &lnrpc.Invoice{
			Memo:      "very small BTC invoice",
			ValueMsat: 1_000,
		},
	)
	require.NoError(t.t, err)

	payInvoiceWithAssets(
		t.t, charlie, dave, btcInvoiceResp.PaymentRequest, assetID,
		withFeeLimit(1_000), withAllowOverpay(), withPayErrSubStr(
			"failed to acquire any quotes",
		), withGroupKey(groupID),
	)

	// Edge case: Check if the RFQ HTLC tracking accounts for cancelled
	// HTLCs. We achieve this by manually creating & using an RFQ quote with
	// a set max amount. We first pay to a hodl invoice that we eventually
	// cancel, then pay to a normal invoice which should succeed.

	// We start by sloshing some funds in the Erin<->Fabia.
	sendAssetKeySendPayment(
		t.t, erin, fabia, 100_000, assetID, fn.Some[int64](20_000),
		withGroupKey(groupID),
	)

	logBalance(t.t, nodes, assetID, "balance after 1st slosh")

	// If we are running this test in group mode, then the manual rfq
	// negotiation needs to also happen on the group key.
	var assetSpecifier rfqrpc.AssetSpecifier
	if groupMode {
		assetSpecifier = rfqrpc.AssetSpecifier{
			Id: &rfqrpc.AssetSpecifier_GroupKey{
				GroupKey: groupID,
			},
		}
	} else {
		assetSpecifier = rfqrpc.AssetSpecifier{
			Id: &rfqrpc.AssetSpecifier_AssetId{
				AssetId: assetID,
			},
		}
	}

	// We create the RFQ order. We set the max amt to ~180k sats which is
	// going to evaluate to about 10k assets.
	inOneHour := time.Now().Add(time.Hour)
	resQ, err := asTapd(charlie).RfqClient.AddAssetSellOrder(
		ctx, &rfqrpc.AddAssetSellOrderRequest{
			AssetSpecifier: &assetSpecifier,
			PaymentMaxAmt:  180_000_000,
			Expiry:         uint64(inOneHour.Unix()),
			PeerPubKey:     dave.PubKey[:],
			TimeoutSeconds: 100,
		},
	)
	require.NoError(t.t, err)

	// We now create a hodl invoice on Fabia, for 10k assets.
	hodlInv := createAssetHodlInvoice(
		t.t, erin, fabia, 10_000, assetID,
		withInvGroupKey(groupID),
	)

	// Charlie tries to pay via Dave, by providing the RFQ quote ID that was
	// manually created above.
	var quoteID rfqmsg.ID
	copy(quoteID[:], resQ.GetAcceptedQuote().Id)

	payInvoiceWithAssets(
		t.t, charlie, dave, hodlInv.payReq, assetID, withSmallShards(),
		withFailure(lnrpc.Payment_IN_FLIGHT, failureNone),
		withRFQ(quoteID), withGroupKey(groupID),
	)

	// We now assert that the expected numbers of HTLCs are present on each
	// node.
	// Reminder, topology looks like this:
	//
	// Charlie <-> Dave <-> Erin <-> Fabia
	//
	// Therefore the routing nodes should have double the number of HTLCs
	// required for the payment present.
	assertNumHtlcs(t.t, charlie, 3)
	assertNumHtlcs(t.t, dave, 6)
	assertNumHtlcs(t.t, erin, 6)
	assertNumHtlcs(t.t, fabia, 3)

	// Now let's cancel the invoice on Fabia.
	payHash := hodlInv.preimage.Hash()
	_, err = fabia.InvoicesClient.CancelInvoice(
		ctx, &invoicesrpc.CancelInvoiceMsg{
			PaymentHash: payHash[:],
		},
	)
	require.NoError(t.t, err)

	// There should be no HTLCs present on any channel.
	assertNumHtlcs(t.t, charlie, 0)
	assertNumHtlcs(t.t, dave, 0)
	assertNumHtlcs(t.t, erin, 0)
	assertNumHtlcs(t.t, fabia, 0)

	// Now Fabia creates another invoice. We also use a fixed msat value for
	// the invoice. Since our itest oracle evaluates every asset to about
	// 17.1 sats, this invoice should be a bit below 10k assets, so roughly
	// the same volume as the previous invoice we just cancelled.
	invoiceResp = createAssetInvoice(
		t.t, erin, fabia, 0, assetID, withInvGroupKey(groupID),
		withMsatAmount(170_000_000),
	)

	// Now Charlie pays the invoice, again by using the manually specified
	// RFQ quote ID. This payment should succeed.
	payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp.PaymentRequest, assetID,
		withSmallShards(), withRFQ(quoteID),
		withGroupKey(groupID),
	)

	logBalance(t.t, nodes, assetID, "after manual rfq hodl")

	// Edge case: Charlie negotiates a quote with Dave which has a low max
	// amount (~170k sats). Then Charlie creates an invoice with a total
	// amount slightly larger than the max allowed in the quote (200k sats).
	// Erin will try to pay that invoice with sats, in shards of max size
	// 80k sats. Dave will eventually stop forwarding HTLCs as the RFQ HTLC
	// tracking mechanism should stop them from being forwarded, as they
	// violate the maximum allowed amount of the quote.

	// Charlie starts by negotiating the quote.
	inOneHour = time.Now().Add(time.Hour)
	res, err := asTapd(charlie).RfqClient.AddAssetBuyOrder(
		ctx, &rfqrpc.AddAssetBuyOrderRequest{
			AssetSpecifier: &assetSpecifier,
			AssetMaxAmt:    10_000,
			Expiry:         uint64(inOneHour.Unix()),
			PeerPubKey:     dave.PubKey[:],
			TimeoutSeconds: 10,
		},
	)
	require.NoError(t.t, err)

	type acceptedQuote = *rfqrpc.AddAssetBuyOrderResponse_AcceptedQuote
	quote, ok := res.Response.(acceptedQuote)
	require.True(t.t, ok)

	// We now manually add the invoice in order to inject the above,
	// manually generated, quote.
	hint := &lnrpc.HopHint{
		NodeId:                    dave.PubKeyStr,
		ChanId:                    quote.AcceptedQuote.Scid,
		CltvExpiryDelta:           80,
		FeeBaseMsat:               1000,
		FeeProportionalMillionths: 1,
	}
	var preimage lntypes.Preimage
	_, _ = rand.Read(preimage[:])
	payHash = preimage.Hash()
	iResp, err := charlie.InvoicesClient.AddHoldInvoice(
		ctx, &invoicesrpc.AddHoldInvoiceRequest{
			Memo:  "",
			Value: 200_000,
			Hash:  payHash[:],
			RouteHints: []*lnrpc.RouteHint{{
				HopHints: []*lnrpc.HopHint{hint},
			}},
		},
	)
	require.NoError(t.t, err)

	htlcStream, err := dave.RouterClient.SubscribeHtlcEvents(
		ctx, &routerrpc.SubscribeHtlcEventsRequest{},
	)
	require.NoError(t.t, err)

	// Now Erin tries to pay the invoice. Since rfq quote cannot satisfy the
	// total amount of the invoice this payment will fail.
	payPayReqWithSatoshi(
		t.t, erin, iResp.PaymentRequest,
		withFailure(lnrpc.Payment_IN_FLIGHT, failureNone),
		withGroupKey(groupID), withMaxShards(4),
	)

	t.Logf("Asserting number of HTLCs on each node...")
	assertMinNumHtlcs(t.t, dave, 2)

	t.Logf("Asserting HTLC events on Dave...")
	assertHtlcEvents(
		t.t, htlcStream, withNumEvents(1), withForwardFailure(),
	)

	_, err = charlie.InvoicesClient.CancelInvoice(
		ctx, &invoicesrpc.CancelInvoiceMsg{
			PaymentHash: payHash[:],
		},
	)
	require.NoError(t.t, err)

	assertNumHtlcs(t.t, dave, 0)

	logBalance(t.t, nodes, assetID, "after small manual rfq")

	_ = htlcStream.CloseSend()
	_, _ = erin.RouterClient.ResetMissionControl(
		context.Background(), &routerrpc.ResetMissionControlRequest{},
	)

	// Edge case: Fabia creates an invoice which Erin cannot satisfy with
	// his side of asset liquidity. This tests that Erin will not try to
	// add an HTLC with more asset units than what his local balance is. To
	// validate that the channel is still healthy, we follow up with a
	// smaller invoice payment which is meant to succeed.

	// We now create a hodl invoice on Fabia, for 125k assets.
	hodlInv = createAssetHodlInvoice(t.t, erin, fabia, 125_000, assetID)

	htlcStream, err = erin.RouterClient.SubscribeHtlcEvents(
		ctx, &routerrpc.SubscribeHtlcEventsRequest{},
	)
	require.NoError(t.t, err)

	// Charlie tries to pay, this is not meant to succeed, as Erin does not
	// have enough assets to forward to Fabia.
	payInvoiceWithAssets(
		t.t, charlie, dave, hodlInv.payReq, assetID,
		withFailure(lnrpc.Payment_IN_FLIGHT, failureNone),
	)

	// Let's check that at least 2 HTLCs were added on the Erin->Fabia link,
	// which means that Erin would have an extra incoming HTLC for each
	// outgoing one. So we expect a minimum of 4 HTLCs present on Erin.
	assertMinNumHtlcs(t.t, erin, 4)

	// We also want to make sure that at least one failure occurred that
	// hinted at the problem (not enough assets to forward).
	assertHtlcEvents(
		t.t, htlcStream, withNumEvents(1),
		withLinkFailure(routerrpc.FailureDetail_INSUFFICIENT_BALANCE),
	)

	logBalance(t.t, nodes, assetID, "with min 4 present HTLCs")

	// Now Fabia cancels the invoice, this is meant to cancel back any
	// locked in HTLCs and reset Erin's local balance back to its original
	// value.
	payHash = hodlInv.preimage.Hash()
	_, err = fabia.InvoicesClient.CancelInvoice(
		ctx, &invoicesrpc.CancelInvoiceMsg{
			PaymentHash: payHash[:],
		},
	)
	require.NoError(t.t, err)

	// Let's assert that Erin cancelled all his HTLCs.
	assertNumHtlcs(t.t, erin, 0)

	logBalance(t.t, nodes, assetID, "after hodl cancel & 0 present HTLCs")

	// Now let's create a smaller invoice and pay it, to validate that the
	// channel is still healthy.
	invoiceResp = createAssetInvoice(t.t, erin, fabia, 50_000, assetID)

	_, _ = charlie.RouterClient.ResetMissionControl(
		context.Background(), &routerrpc.ResetMissionControlRequest{},
	)
	payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp.PaymentRequest, assetID,
	)

	logBalance(t.t, nodes, assetID, "after safe asset htlc failure")

	// Another test case: Make sure an asset invoice contains the correct
	// channel policy. We expect it to be the policy for the direction from
	// edge node to receiver node. To test this, we first set two different
	// policies on the channel between Erin and Fabia.
	resp, err := erin.LightningClient.UpdateChannelPolicy(
		ctx, &lnrpc.PolicyUpdateRequest{
			Scope: &lnrpc.PolicyUpdateRequest_ChanPoint{
				ChanPoint: chanPointEF,
			},
			BaseFeeMsat:   31337,
			FeeRatePpm:    443322,
			TimeLockDelta: 25,
		},
	)
	require.NoError(t.t, err)
	require.Empty(t.t, resp.FailedUpdates)

	resp, err = fabia.LightningClient.UpdateChannelPolicy(
		ctx, &lnrpc.PolicyUpdateRequest{
			Scope: &lnrpc.PolicyUpdateRequest_ChanPoint{
				ChanPoint: chanPointEF,
			},
			BaseFeeMsat:   42069,
			FeeRatePpm:    223344,
			TimeLockDelta: 24,
		},
	)
	require.NoError(t.t, err)
	require.Empty(t.t, resp.FailedUpdates)

	// We now create an invoice on Fabia and expect Erin's policy to be used
	// in the invoice.
	invoiceResp = createAssetInvoice(t.t, erin, fabia, 1_000, assetID)
	req, err := erin.LightningClient.DecodePayReq(
		ctx, &lnrpc.PayReqString{
			PayReq: invoiceResp.PaymentRequest,
		},
	)
	require.NoError(t.t, err)

	require.Len(t.t, req.RouteHints, 1)
	require.Len(t.t, req.RouteHints[0].HopHints, 1)
	invoiceHint := req.RouteHints[0].HopHints[0]
	require.Equal(t.t, erin.PubKeyStr, invoiceHint.NodeId)
	require.EqualValues(t.t, 31337, invoiceHint.FeeBaseMsat)
	require.EqualValues(t.t, 443322, invoiceHint.FeeProportionalMillionths)
	require.EqualValues(t.t, 25, invoiceHint.CltvExpiryDelta)

	// Now we pay the invoice and expect the same policy with very expensive
	// fees to be used.
	payInvoiceWithSatoshi(
		t.t, dave, invoiceResp, withFeeLimit(100_000_000),
	)

	logBalance(t.t, nodes, assetID, "after policy checks")

	resBuy, err := asTapd(dave).RfqClient.AddAssetBuyOrder(
		ctx, &rfqrpc.AddAssetBuyOrderRequest{
			AssetSpecifier: &assetSpecifier,
			AssetMaxAmt:    1_000,
			Expiry:         uint64(inOneHour.Unix()),
			PeerPubKey:     charlie.PubKey[:],
			TimeoutSeconds: 100,
		},
	)
	require.NoError(t.t, err)

	scid := resBuy.GetAcceptedQuote().Scid

	invResp := createAssetInvoice(
		t.t, charlie, dave, 1_000, assetID,
		withInvGroupKey(groupID), withRouteHints([]*lnrpc.RouteHint{
			{
				HopHints: []*lnrpc.HopHint{
					{
						NodeId: charlie.PubKeyStr,
						ChanId: scid,
					},
				},
			},
		}),
	)

	payInvoiceWithAssets(
		t.t, charlie, dave, invResp.PaymentRequest, assetID,
		withGroupKey(groupID),
	)

	logBalance(t.t, nodes, assetID, "after invoice with route hints")
}

// testCustomChannelsLiquidityEdgeCases is a test that runs through some
// taproot asset channel liquidity related edge cases.
func testCustomChannelsLiquidityEdgeCases(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	// Run liquidity edge cases and only use single asset IDs for invoices
	// and payments.
	testCustomChannelsLiquidityEdgeCasesCore(ctx, net, t, false)
}

// testCustomChannelsLiquidityEdgeCasesGroup is a test that runs through some
// taproot asset channel liquidity related edge cases using group keys.
func testCustomChannelsLiquidityEdgeCasesGroup(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	// Run liquidity edge cases and only use group keys for invoices and
	// payments.
	testCustomChannelsLiquidityEdgeCasesCore(ctx, net, t, true)
}
