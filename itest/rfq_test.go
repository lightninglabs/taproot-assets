package itest

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// testRfqAssetBuyHtlcIntercept tests RFQ negotiation, HTLC interception, and
// validation between three peers. The RFQ negotiation is initiated by an asset
// buy request.
//
// The procedure is as follows:
//  1. Carol sends a tap asset buy quote request to Bob.
//  2. Bob's node accepts the quote.
//  3. Carol uses the buy accept message to construct a lightning invoice
//     which will pay for the quote accepted by Bob.
//  4. Alice pays the invoice.
//  5. Bob's node intercepts the lightning payment from Alice and validates it
//     against the quote accepted between Bob and Carol.
//
// As a final step (which is not part of this test), Bob's node will transfer
// the tap asset to Carol's node.
func testRfqAssetBuyHtlcIntercept(t *harnessTest) {
	// Initialize a new test scenario.
	ts := newRfqTestScenario(t)

	// Mint an asset with Bob's tapd node.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, ts.BobTapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)
	mintedAssetId := rpcAssets[0].AssetGenesis.AssetId

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Upsert an asset sell offer to Bob's tapd node. This will allow Bob to
	// sell the newly minted asset to Carol.
	_, err := ts.BobTapd.AddAssetSellOffer(
		ctxt, &rfqrpc.AddAssetSellOfferRequest{
			AssetSpecifier: &rfqrpc.AssetSpecifier{
				Id: &rfqrpc.AssetSpecifier_AssetId{
					AssetId: mintedAssetId,
				},
			},
			MaxUnits: 1000,
		},
	)
	require.NoError(t.t, err, "unable to upsert asset sell offer")

	// Subscribe to Carol's RFQ events stream.
	carolEventNtfns, err := ts.CarolTapd.SubscribeRfqEventNtfns(
		ctxb, &rfqrpc.SubscribeRfqEventNtfnsRequest{},
	)
	require.NoError(t.t, err)

	// Carol sends a buy order to Bob for some amount of the newly minted
	// asset.
	purchaseAssetAmt := uint64(200)
	bidAmt := uint64(42000)
	buyOrderExpiry := uint64(time.Now().Add(24 * time.Hour).Unix())

	_, err = ts.CarolTapd.AddAssetBuyOrder(
		ctxt, &rfqrpc.AddAssetBuyOrderRequest{
			AssetSpecifier: &rfqrpc.AssetSpecifier{
				Id: &rfqrpc.AssetSpecifier_AssetId{
					AssetId: mintedAssetId,
				},
			},
			MinAssetAmount: purchaseAssetAmt,
			MaxBid:         bidAmt,
			Expiry:         buyOrderExpiry,

			// Here we explicitly specify Bob as the destination
			// peer for the buy order. This will prompt Carol's tapd
			// node to send a request for quote message to Bob's
			// node.
			PeerPubKey: ts.BobLnd.PubKey[:],
		},
	)
	require.NoError(t.t, err, "unable to upsert asset buy order")

	// Wait until Carol receives an incoming quote accept message (sent from
	// Bob) RFQ event notification.
	waitErr := wait.NoError(func() error {
		event, err := carolEventNtfns.Recv()
		require.NoError(t.t, err)

		_, ok := event.Event.(*rfqrpc.RfqEvent_PeerAcceptedBuyQuote)
		require.True(t.t, ok, "unexpected event: %v", event)

		return nil
	}, defaultWaitTimeout)
	require.NoError(t.t, waitErr)

	// Carol should have received an accepted quote from Bob. This accepted
	// quote can be used by Carol to make a payment to Bob.
	acceptedQuotes, err := ts.CarolTapd.QueryPeerAcceptedQuotes(
		ctxt, &rfqrpc.QueryPeerAcceptedQuotesRequest{},
	)
	require.NoError(t.t, err, "unable to query accepted quotes")
	require.Len(t.t, acceptedQuotes.BuyQuotes, 1)

	// Carol will now use the accepted quote (received from Bob) to create
	// a lightning invoice which will be given to and settled by Alice.
	//
	// The payment will be routed through Bob (who will handle the
	// BTC->asset conversion as a last step before reaching Carol). Recall
	// that the payment path is: Alice -> Bob -> Carol. And the Bob -> Carol
	// last hop will constitute the tap asset transfer.
	//
	// First, we need to get the short channel ID (scid) for the Alice->Bob
	// channel which Carol will include in her invoice. Then, when Alice
	// pays the invoice, the payment will arrive to Bob's node with the
	// expected scid. Bob will then use the scid to identify the HTLC as
	// relating to the accepted quote.
	acceptedQuote := acceptedQuotes.BuyQuotes[0]
	t.Logf("Accepted quote scid: %d", acceptedQuote.Scid)
	scid := lnwire.NewShortChanIDFromInt(acceptedQuote.Scid)

	// Use the agreed upon scid found in the accepted quote to construct a
	// route hop hint for the Alice->Bob step of the payment. The route hop
	// hint will be included in the invoice that Carol hands to Alice.
	aliceBobHopHint := &lnrpc.HopHint{
		NodeId: ts.BobLnd.PubKeyStr,
		ChanId: scid.ToUint64(),
		FeeBaseMsat: uint32(
			chainreg.DefaultBitcoinBaseFeeMSat,
		),
		FeeProportionalMillionths: uint32(
			chainreg.DefaultBitcoinFeeRate,
		),
		CltvExpiryDelta: chainreg.DefaultBitcoinTimeLockDelta,
	}
	routeHints := []*lnrpc.RouteHint{
		{
			HopHints: []*lnrpc.HopHint{
				aliceBobHopHint,
			},
		},
	}

	// Carol can now finalise the invoice and hand it over to Alice for
	// settlement.
	addInvoiceResp := ts.CarolLnd.RPC.AddInvoice(&lnrpc.Invoice{
		ValueMsat:  int64(bidAmt),
		RouteHints: routeHints,
	})
	invoice := ts.CarolLnd.RPC.LookupInvoice(addInvoiceResp.RHash)

	// Register to receive RFQ events from Bob's tapd node. We'll use this
	// to wait for Bob to receive the HTLC with the asset transfer specific
	// scid.
	bobEventNtfns, err := ts.BobTapd.SubscribeRfqEventNtfns(
		ctxb, &rfqrpc.SubscribeRfqEventNtfnsRequest{},
	)
	require.NoError(t.t, err)

	// Alice pays the invoice.
	t.Log("Alice paying invoice")
	req := &routerrpc.SendPaymentRequest{
		PaymentRequest: invoice.PaymentRequest,
		TimeoutSeconds: int32(wait.PaymentTimeout.Seconds()),
		FeeLimitMsat:   math.MaxInt64,
	}
	ts.AliceLnd.RPC.SendPayment(req)
	t.Log("Alice payment sent")

	// At this point Bob should have received a HTLC with the asset transfer
	// specific scid. We'll wait for Bob to publish an accept HTLC event and
	// then validate it against the accepted quote.
	waitErr = wait.NoError(func() error {
		t.Log("Waiting for Bob to receive HTLC")

		event, err := bobEventNtfns.Recv()
		require.NoError(t.t, err)

		acceptHtlc, ok := event.Event.(*rfqrpc.RfqEvent_AcceptHtlc)
		if ok {
			require.Equal(
				t.t, acceptedQuote.Scid,
				acceptHtlc.AcceptHtlc.Scid,
			)
			t.Log("Bob has accepted the HTLC")
			return nil
		}

		return fmt.Errorf("unexpected event: %v", event)
	}, defaultWaitTimeout)
	require.NoError(t.t, waitErr)

	// Close event streams.
	err = carolEventNtfns.CloseSend()
	require.NoError(t.t, err)

	err = bobEventNtfns.CloseSend()
	require.NoError(t.t, err)
}

// newLndNode creates a new lnd node with the given name and funds its wallet
// with the specified outputs.
func newLndNode(name string, outputFunds []btcutil.Amount,
	ht *lntest.HarnessTest) *node.HarnessNode {

	newNode := ht.NewNode(name, nil)

	// Fund node wallet with specified outputs.
	totalTxes := len(outputFunds)
	const (
		numBlocksSendOutput = 2
		minerFeeRate        = btcutil.Amount(7500)
	)

	for i := range outputFunds {
		amt := outputFunds[i]

		resp := newNode.RPC.NewAddress(&lnrpc.NewAddressRequest{
			Type: lnrpc.AddressType_WITNESS_PUBKEY_HASH},
		)
		addr := ht.DecodeAddress(resp.Address)
		addrScript := ht.PayToAddrScript(addr)

		output := &wire.TxOut{
			PkScript: addrScript,
			Value:    int64(amt),
		}
		ht.Miner.SendOutput(output, minerFeeRate)
	}

	// Mine any funding transactions.
	if totalTxes > 0 {
		ht.MineBlocksAndAssertNumTxes(numBlocksSendOutput, totalTxes)
	}

	return newNode
}

// rfqTestScenario is a struct which holds test scenario helper infra.
type rfqTestScenario struct {
	testHarness *harnessTest

	AliceLnd *node.HarnessNode
	BobLnd   *node.HarnessNode
	CarolLnd *node.HarnessNode

	AliceBobChannel *lnrpc.ChannelPoint
	BobCarolChannel *lnrpc.ChannelPoint

	AliceTapd *tapdHarness
	BobTapd   *tapdHarness
	CarolTapd *tapdHarness
}

// newRfqTestScenario initializes a new test scenario with three new LND nodes
// and connects them to have the following topology,
//
//	Alice --> Bob --> Carol
//
// It also creates new tapd nodes for each of the LND nodes.
func newRfqTestScenario(t *harnessTest) *rfqTestScenario {
	// Specify wallet outputs to fund the wallets of the new nodes.
	const (
		fundAmount  = 1 * btcutil.SatoshiPerBitcoin
		numOutputs  = 100
		totalAmount = fundAmount * numOutputs
	)

	var outputFunds [numOutputs]btcutil.Amount
	for i := range outputFunds {
		outputFunds[i] = fundAmount
	}

	// Create three new nodes.
	aliceLnd := newLndNode("AliceLnd", outputFunds[:], t.lndHarness)
	bobLnd := newLndNode("BobLnd", outputFunds[:], t.lndHarness)
	carolLnd := newLndNode("CarolLnd", outputFunds[:], t.lndHarness)

	// Now we want to wait for the nodes to catch up.
	t.lndHarness.WaitForBlockchainSync(aliceLnd)
	t.lndHarness.WaitForBlockchainSync(bobLnd)
	t.lndHarness.WaitForBlockchainSync(carolLnd)

	// Now block until both wallets have fully synced up.
	t.lndHarness.WaitForBalanceConfirmed(aliceLnd, totalAmount)
	t.lndHarness.WaitForBalanceConfirmed(bobLnd, totalAmount)
	t.lndHarness.WaitForBalanceConfirmed(carolLnd, totalAmount)

	// Connect the nodes.
	t.lndHarness.EnsureConnected(aliceLnd, bobLnd)
	t.lndHarness.EnsureConnected(bobLnd, carolLnd)

	// Open channels between the nodes: Alice -> Bob -> Carol
	const chanAmt = btcutil.Amount(300000)
	p := lntest.OpenChannelParams{Amt: chanAmt}
	reqs := []*lntest.OpenChannelRequest{
		{Local: aliceLnd, Remote: bobLnd, Param: p},
		{Local: bobLnd, Remote: carolLnd, Param: p},
	}
	resp := t.lndHarness.OpenMultiChannelsAsync(reqs)
	aliceBobChannel, bobCarolChannel := resp[0], resp[1]

	// Make sure Alice is aware of channel Bob -> Carol.
	t.lndHarness.AssertTopologyChannelOpen(aliceLnd, bobCarolChannel)

	// Create tapd nodes.
	aliceTapd := setupTapdHarness(t.t, t, aliceLnd, t.universeServer)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	carolTapd := setupTapdHarness(t.t, t, carolLnd, t.universeServer)

	ts := rfqTestScenario{
		testHarness: t,

		AliceLnd: aliceLnd,
		BobLnd:   bobLnd,
		CarolLnd: carolLnd,

		AliceBobChannel: aliceBobChannel,
		BobCarolChannel: bobCarolChannel,

		AliceTapd: aliceTapd,
		BobTapd:   bobTapd,
		CarolTapd: carolTapd,
	}

	// Cleanup the test scenario on test completion. Here we register the
	// test scenario's cleanup function with the test cleanup routine.
	t.t.Cleanup(ts.Cleanup)

	return &ts
}

// Cleanup cleans up the test scenario.
func (s *rfqTestScenario) Cleanup() {
	// Close the LND channels.
	s.testHarness.lndHarness.CloseChannel(s.AliceLnd, s.AliceBobChannel)
	s.testHarness.lndHarness.CloseChannel(s.BobLnd, s.BobCarolChannel)

	// Stop the tapd nodes.
	require.NoError(s.testHarness.t, s.AliceTapd.stop(!*noDelete))
	require.NoError(s.testHarness.t, s.BobTapd.stop(!*noDelete))
	require.NoError(s.testHarness.t, s.CarolTapd.stop(!*noDelete))
}
