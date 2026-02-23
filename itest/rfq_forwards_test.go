package itest

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	oraclerpc "github.com/lightninglabs/taproot-assets/taprpc/priceoraclerpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// testForwardingEventHistory tests that forwarding events are properly logged
// and can be
// queried via the ForwardingHistory RPC endpoint.
//
// The procedure is as follows:
//  1. Alice sends an asset sell order to Bob.
//  2. Bob accepts the quote, creating a purchase policy.
//  3. Alice sends a payment with asset custom records to Carol via Bob.
//  4. Bob intercepts the HTLC and validates it against the accepted quote.
//  5. The payment settles successfully.
//  6. We query Bob's forwarding history and verify the event was recorded.
//  7. We test query filters (timestamp, peer, asset_id) and pagination.
func testForwardingEventHistory(t *harnessTest) {
	oracleAddr := fmt.Sprintf("localhost:%d", port.NextAvailablePort())
	oracle := newOracleHarness(oracleAddr)
	oracle.start(t.t)
	t.t.Cleanup(oracle.stop)

	oracleURL := fmt.Sprintf("rfqrpc://%s", oracleAddr)
	ts := newRfqTestScenario(t, WithRfqOracleServer(oracleURL))

	// Mint an asset with Alice's tapd node.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, ts.AliceTapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)
	mintedAssetIdBytes := rpcAssets[0].AssetGenesis.AssetId

	var mintedAssetId asset.ID
	copy(mintedAssetId[:], mintedAssetIdBytes[:])

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Add an asset buy offer to Bob's tapd node.
	_, err := ts.BobTapd.AddAssetBuyOffer(
		ctxt, &rfqrpc.AddAssetBuyOfferRequest{
			AssetSpecifier: &rfqrpc.AssetSpecifier{
				Id: &rfqrpc.AssetSpecifier_AssetId{
					AssetId: mintedAssetIdBytes,
				},
			},
			MaxUnits: 1000,
		},
	)
	require.NoError(t.t, err)

	aliceEventNtfns, err := ts.AliceTapd.SubscribeRfqEventNtfns(
		ctxb, &rfqrpc.SubscribeRfqEventNtfnsRequest{},
	)
	require.NoError(t.t, err)

	// Alice sends a sell order to Bob.
	askAmt := uint64(46258)
	sellOrderExpiry := uint64(time.Now().Add(24 * time.Hour).Unix())

	sellReq := &rfqrpc.AddAssetSellOrderRequest{
		AssetSpecifier: &rfqrpc.AssetSpecifier{
			Id: &rfqrpc.AssetSpecifier_AssetId{
				AssetId: mintedAssetIdBytes,
			},
		},
		PaymentMaxAmt:         askAmt,
		Expiry:                sellOrderExpiry,
		PeerPubKey:            ts.BobLnd.PubKey[:],
		TimeoutSeconds:        uint32(rfqTimeout.Seconds()),
		SkipAssetChannelCheck: true,
		PriceOracleMetadata:   "forward-history-test",
	}

	// Set up the expected oracle calls.
	buySpecifier := &oraclerpc.AssetSpecifier{
		Id: &oraclerpc.AssetSpecifier_AssetId{
			AssetId: mintedAssetIdBytes,
		},
	}
	btcSpecifier := &oraclerpc.AssetSpecifier{
		Id: &oraclerpc.AssetSpecifier_AssetId{
			AssetId: bytes.Repeat([]byte{0}, 32),
		},
	}

	expiryTimestamp := uint64(time.Now().Add(time.Minute).Unix())
	mockResult := &oraclerpc.QueryAssetRatesResponse{
		Result: &oraclerpc.QueryAssetRatesResponse_Ok{
			Ok: &oraclerpc.QueryAssetRatesOkResponse{
				AssetRates: &oraclerpc.AssetRates{
					SubjectAssetRate: &oraclerpc.FixedPoint{
						Coefficient: "1101000",
						Scale:       3,
					},
					ExpiryTimestamp: expiryTimestamp,
				},
			},
		},
	}

	// Alice initiates the sell order, so Alice's pubkey should appear as
	// node_id for hint/qualify calls. Bob handles the counterparty call.
	alicePubkey := ts.AliceLnd.PubKey[:]
	bobPubkey := ts.BobLnd.PubKey[:]

	oracle.On(
		"QueryAssetRates", oraclerpc.TransactionType_SALE,
		buySpecifier, mock.Anything, btcSpecifier,
		askAmt, mock.Anything,
		oraclerpc.Intent_INTENT_PAY_INVOICE_HINT,
		mock.Anything, "forward-history-test", alicePubkey,
	).Return(mockResult, nil).Once()

	oracle.On(
		"QueryAssetRates", oraclerpc.TransactionType_PURCHASE,
		buySpecifier, mock.Anything, btcSpecifier,
		askAmt, mock.Anything,
		oraclerpc.Intent_INTENT_PAY_INVOICE,
		mock.Anything, "forward-history-test", bobPubkey,
	).Return(mockResult, nil).Once()

	oracle.On(
		"QueryAssetRates", oraclerpc.TransactionType_SALE,
		buySpecifier, mock.Anything, btcSpecifier,
		askAmt, mock.Anything,
		oraclerpc.Intent_INTENT_PAY_INVOICE_QUALIFY,
		mock.Anything, "forward-history-test", alicePubkey,
	).Return(mockResult, nil).Once()

	defer oracle.AssertExpectations(t.t)

	_, err = ts.AliceTapd.AddAssetSellOrder(ctxt, sellReq)
	require.NoError(t.t, err)

	// Wait for Alice to receive the quote accept from Bob.
	BeforeTimeout(t.t, func() {
		event, err := aliceEventNtfns.Recv()
		require.NoError(t.t, err)
		_, ok := event.Event.(*rfqrpc.RfqEvent_PeerAcceptedSellQuote)
		require.True(t.t, ok)
	}, rfqTimeout)

	acceptedQuotes, err := ts.AliceTapd.QueryPeerAcceptedQuotes(
		ctxt, &rfqrpc.QueryPeerAcceptedQuotesRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, acceptedQuotes.SellQuotes, 1)

	acceptedQuote := acceptedQuotes.SellQuotes[0]
	var acceptedQuoteId rfqmsg.ID
	copy(acceptedQuoteId[:], acceptedQuote.Id[:])

	// Record timestamp before payment for filtering tests.
	timestampBeforePayment := time.Now().Unix()

	bobEventNtfns, err := ts.BobTapd.SubscribeRfqEventNtfns(
		ctxb, &rfqrpc.SubscribeRfqEventNtfnsRequest{},
	)
	require.NoError(t.t, err)

	// Carol generates an invoice for Alice to settle via Bob.
	addInvoiceResp := ts.CarolLnd.RPC.AddInvoice(&lnrpc.Invoice{
		ValueMsat: int64(askAmt),
	})
	invoice := ts.CarolLnd.RPC.LookupInvoice(addInvoiceResp.RHash)
	payReq := ts.CarolLnd.RPC.DecodePayReq(invoice.PaymentRequest)

	// Construct route: Alice -> Bob -> Carol.
	routeBuildResp := ts.AliceLnd.RPC.BuildRoute(
		&routerrpc.BuildRouteRequest{
			AmtMsat: int64(askAmt),
			HopPubkeys: [][]byte{
				ts.BobLnd.PubKey[:],
				ts.CarolLnd.PubKey[:],
			},
			PaymentAddr: payReq.PaymentAddr,
		},
	)

	// Construct first hop custom records.
	assetAmounts := []*rfqmsg.AssetBalance{
		rfqmsg.NewAssetBalance(mintedAssetId, 42),
	}
	htlcCustomRecords := rfqmsg.NewHtlc(
		assetAmounts, fn.Some(acceptedQuoteId), fn.None[[]rfqmsg.ID](),
	)
	firstHopCustomRecords, err := tlv.RecordsToMap(
		htlcCustomRecords.Records(),
	)
	require.NoError(t.t, err)

	// Send the payment.
	sendAttempt := ts.AliceLnd.RPC.SendToRouteV2(
		&routerrpc.SendToRouteRequest{
			PaymentHash:           invoice.RHash,
			Route:                 routeBuildResp.Route,
			FirstHopCustomRecords: firstHopCustomRecords,
		},
	)
	require.Equal(t.t, lnrpc.HTLCAttempt_SUCCEEDED, sendAttempt.Status)

	// Wait for Bob to accept the HTLC.
	BeforeTimeout(t.t, func() {
		event, err := bobEventNtfns.Recv()
		require.NoError(t.t, err)
		_, ok := event.Event.(*rfqrpc.RfqEvent_AcceptHtlc)
		require.True(t.t, ok)
	}, rfqTimeout)

	// Confirm Carol received the payment.
	invoice = ts.CarolLnd.RPC.LookupInvoice(addInvoiceResp.RHash)
	require.Equal(t.t, lnrpc.Invoice_SETTLED, invoice.State)

	timestampAfterPayment := time.Now().Unix()

	// Wait for the forward to be logged.
	var forwardsResp *rfqrpc.ForwardingHistoryResponse
	BeforeTimeout(t.t, func() {
		var err error
		forwardsResp, err = ts.BobTapd.ForwardingHistory(
			ctxt, &rfqrpc.ForwardingHistoryRequest{},
		)
		require.NoError(t.t, err)
		require.Len(t.t, forwardsResp.Forwards, 1)
	}, rfqTimeout)

	fwd := forwardsResp.Forwards[0]

	// Verify forwarding event fields.
	require.Equal(t.t, acceptedQuote.Id, fwd.RfqId)
	require.Equal(t.t, rfqrpc.RfqPolicyType_RFQ_POLICY_TYPE_PURCHASE,
		fwd.PolicyType)
	require.Equal(t.t, ts.AliceLnd.PubKeyStr, fwd.Peer)
	require.NotNil(t.t, fwd.AssetSpec)
	require.Equal(t.t, mintedAssetIdBytes, fwd.AssetSpec.Id)
	require.Equal(t.t, uint64(42), fwd.AssetAmt)

	// Verify opened_at is within the expected range.
	require.GreaterOrEqual(t.t, fwd.OpenedAt,
		uint64(timestampBeforePayment),
	)
	require.LessOrEqual(t.t, fwd.OpenedAt, uint64(timestampAfterPayment+10))

	// Verify settled_at is within the expected range and after opened_at.
	require.GreaterOrEqual(t.t, fwd.SettledAt, fwd.OpenedAt)
	require.LessOrEqual(t.t, fwd.SettledAt,
		uint64(timestampAfterPayment+10),
	)

	// Verify failed_at is 0 for a successful forward.
	require.Zero(t.t, fwd.FailedAt)

	// Verify amount fields are set.
	require.Equal(t.t, fwd.AmtInMsat, askAmt+1000)
	require.Equal(t.t, fwd.AmtOutMsat, askAmt)
	require.Equal(t.t, fwd.Rate.Coefficient, "1101000")
	require.Equal(t.t, int64(1), forwardsResp.TotalCount)

	// Test timestamp filters.
	forwardsResp, err = ts.BobTapd.ForwardingHistory(
		ctxt, &rfqrpc.ForwardingHistoryRequest{
			MinTimestamp: uint64(timestampBeforePayment),
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, forwardsResp.Forwards, 1)

	forwardsResp, err = ts.BobTapd.ForwardingHistory(
		ctxt, &rfqrpc.ForwardingHistoryRequest{
			MaxTimestamp: uint64(timestampBeforePayment - 10),
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, forwardsResp.Forwards, 0)

	// Test peer filter.
	forwardsResp, err = ts.BobTapd.ForwardingHistory(
		ctxt, &rfqrpc.ForwardingHistoryRequest{
			Peer: ts.AliceLnd.PubKey[:],
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, forwardsResp.Forwards, 1)

	forwardsResp, err = ts.BobTapd.ForwardingHistory(
		ctxt, &rfqrpc.ForwardingHistoryRequest{
			Peer: ts.CarolLnd.PubKey[:],
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, forwardsResp.Forwards, 0)

	// Test asset filter.
	forwardsResp, err = ts.BobTapd.ForwardingHistory(
		ctxt, &rfqrpc.ForwardingHistoryRequest{
			AssetSpecifier: &rfqrpc.AssetSpecifier{
				Id: &rfqrpc.AssetSpecifier_AssetId{
					AssetId: mintedAssetIdBytes,
				},
			},
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, forwardsResp.Forwards, 1)

	forwardsResp, err = ts.BobTapd.ForwardingHistory(
		ctxt, &rfqrpc.ForwardingHistoryRequest{
			AssetSpecifier: &rfqrpc.AssetSpecifier{
				Id: &rfqrpc.AssetSpecifier_AssetId{
					AssetId: bytes.Repeat([]byte{0xab}, 32),
				},
			},
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, forwardsResp.Forwards, 0)

	// Test pagination.
	forwardsResp, err = ts.BobTapd.ForwardingHistory(
		ctxt, &rfqrpc.ForwardingHistoryRequest{Limit: 100, Offset: 10},
	)
	require.NoError(t.t, err)
	require.Len(t.t, forwardsResp.Forwards, 0)
	require.Equal(t.t, int64(1), forwardsResp.TotalCount)

	// Alice should have no forwards (she's not an edge node).
	aliceForwardsResp, err := ts.AliceTapd.ForwardingHistory(
		ctxt, &rfqrpc.ForwardingHistoryRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, aliceForwardsResp.Forwards, 0)

	// Cleanup.
	require.NoError(t.t, aliceEventNtfns.CloseSend())
	require.NoError(t.t, bobEventNtfns.CloseSend())
}
