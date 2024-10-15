package tapchannel

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

const (
	// The test channel ID to use across the test cases.
	testChanID = 1234
)

var (
	// The node ID to be used for the RFQ peer.
	testNodeID = route.Vertex{1, 2, 3}

	assetRate = big.NewInt(100_000)

	testAssetRate = rfqmath.FixedPoint[rfqmath.BigInt]{
		Coefficient: rfqmath.NewBigInt(assetRate),
		Scale:       0,
	}
)

// mockRfqManager mocks the interface of the rfq manager required by the aux
// invoice manager. It also holds some internal state to return the desired
// quotes.
type mockRfqManager struct {
	peerBuyQuotes   rfq.BuyAcceptMap
	localSellQuotes rfq.SellAcceptMap
}

func (m *mockRfqManager) PeerAcceptedBuyQuotes() rfq.BuyAcceptMap {
	return m.peerBuyQuotes
}

func (m *mockRfqManager) LocalAcceptedSellQuotes() rfq.SellAcceptMap {
	return m.localSellQuotes
}

// mockHtlcModifier mocks the HtlcModifier interface that is required by the
// AuxInvoiceManager.
type mockHtlcModifier struct {
	requestQue     []lndclient.InvoiceHtlcModifyRequest
	expectedResQue []lndclient.InvoiceHtlcModifyResponse
	done           chan bool
	t              *testing.T
}

// HtlcModifier handles the invoice htlc modification requests que, then checks
// the returned error and response against the expected values.
func (m *mockHtlcModifier) HtlcModifier(ctx context.Context,
	handler lndclient.InvoiceHtlcModifyHandler) error {

	// Process the requests that are provided by the test case.
	for i, r := range m.requestQue {
		res, err := handler(ctx, r)

		if err != nil {
			return err
		}

		if m.expectedResQue[i].CancelSet {
			if !res.CancelSet {
				return fmt.Errorf("expected cancel set flag")
			}

			continue
		}

		// Check if there's a match with the expected outcome.
		if res.AmtPaid != m.expectedResQue[i].AmtPaid {
			return fmt.Errorf("invoice paid amount does not match "+
				"expected amount, %v != %v", res.AmtPaid,
				m.expectedResQue[i].AmtPaid)
		}
	}

	// Signal that the htlc modifications are completed.
	close(m.done)

	return nil
}

// TestAuxInvoiceManager tests that the htlc modifications of the aux invoice
// manager align with our expectations.
func TestAuxInvoiceManager(t *testing.T) {
	testCases := []struct {
		name            string
		buyQuotes       rfq.BuyAcceptMap
		sellQuotes      rfq.SellAcceptMap
		requests        []lndclient.InvoiceHtlcModifyRequest
		responses       []lndclient.InvoiceHtlcModifyResponse
		containedErrStr string
	}{
		{
			name: "non asset invoice",
			requests: []lndclient.InvoiceHtlcModifyRequest{
				{
					Invoice:     &lnrpc.Invoice{},
					ExitHtlcAmt: 1234,
				},
			},
			responses: []lndclient.InvoiceHtlcModifyResponse{
				{
					AmtPaid: 1234,
				},
			},
		},
		{
			name: "non asset routing hints",
			requests: []lndclient.InvoiceHtlcModifyRequest{
				{
					Invoice: &lnrpc.Invoice{
						RouteHints: testNonAssetHints(),
						ValueMsat:  1_000_000,
					},
					ExitHtlcAmt: 1234,
				},
			},
			responses: []lndclient.InvoiceHtlcModifyResponse{
				{
					AmtPaid: 1234,
				},
			},
			buyQuotes: map[rfq.SerialisedScid]rfqmsg.BuyAccept{
				testChanID: {
					Peer: testNodeID,
				},
			},
		},
		{
			name: "asset invoice, no custom records",
			requests: []lndclient.InvoiceHtlcModifyRequest{
				{
					Invoice: &lnrpc.Invoice{
						RouteHints:  testRouteHints(),
						PaymentAddr: []byte{1, 1, 1},
					},
					ExitHtlcAmt: 1234,
				},
			},
			responses: []lndclient.InvoiceHtlcModifyResponse{
				{
					CancelSet: true,
				},
			},
			buyQuotes: map[rfq.SerialisedScid]rfqmsg.BuyAccept{
				testChanID: {
					Peer: testNodeID,
				},
			},
		},
		{
			name: "asset invoice, custom records",
			requests: []lndclient.InvoiceHtlcModifyRequest{
				{
					Invoice: &lnrpc.Invoice{
						RouteHints:  testRouteHints(),
						ValueMsat:   3_000_000,
						PaymentAddr: []byte{1, 1, 1},
					},
					WireCustomRecords: newWireCustomRecords(
						t, []*rfqmsg.AssetBalance{
							rfqmsg.NewAssetBalance(
								dummyAssetID(1), 3,
							),
						}, fn.Some(dummyRfqID(31)),
					),
				},
			},
			responses: []lndclient.InvoiceHtlcModifyResponse{
				{
					AmtPaid: 3_000_000,
				},
			},
			buyQuotes: rfq.BuyAcceptMap{
				fn.Ptr(dummyRfqID(31)).Scid(): {
					Peer:      testNodeID,
					AssetRate: testAssetRate,
				},
			},
		},
		{
			name: "asset invoice, not enough amt",
			requests: []lndclient.InvoiceHtlcModifyRequest{
				{
					Invoice: &lnrpc.Invoice{
						RouteHints:  testRouteHints(),
						ValueMsat:   10_000_000,
						PaymentAddr: []byte{1, 1, 1},
					},
					WireCustomRecords: newWireCustomRecords(
						t, []*rfqmsg.AssetBalance{
							rfqmsg.NewAssetBalance(
								dummyAssetID(1),
								4,
							),
						}, fn.Some(dummyRfqID(31)),
					),
					ExitHtlcAmt: 1234,
				},
			},
			responses: []lndclient.InvoiceHtlcModifyResponse{
				{
					AmtPaid: 4_000_000,
				},
			},
			buyQuotes: rfq.BuyAcceptMap{
				fn.Ptr(dummyRfqID(31)).Scid(): {
					Peer:      testNodeID,
					AssetRate: testAssetRate,
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Logf("Running AuxInvoiceManager test case: %v", testCase.name)

		// Instantiate mock rfq manager.
		mockRfq := &mockRfqManager{
			peerBuyQuotes:   testCase.buyQuotes,
			localSellQuotes: testCase.sellQuotes,
		}

		done := make(chan bool)

		// Instantiate mock htlc modifier.
		mockModifier := &mockHtlcModifier{
			requestQue:     testCase.requests,
			expectedResQue: testCase.responses,
			done:           done,
			t:              t,
		}

		// Create the manager.
		manager := NewAuxInvoiceManager(
			&InvoiceManagerConfig{
				ChainParams:         testChainParams,
				InvoiceHtlcModifier: mockModifier,
				RfqManager:          mockRfq,
			},
		)

		err := manager.Start()
		require.NoError(t, err)

		// If the manager is not done processing the htlc modification
		// requests within the specified timeout, assume this is a
		// failure.
		select {
		case <-done:
		case <-time.After(testTimeout):
			t.Fail()
		}
	}
}

func newHash(i []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(i)

	return h.Sum(nil)
}

func dummyAssetID(i byte) asset.ID {
	return asset.ID(newHash([]byte{i}))
}

func dummyRfqID(value int) rfqmsg.ID {
	return rfqmsg.ID(newHash([]byte{byte(value)}))
}

func testRouteHints() []*lnrpc.RouteHint {
	return []*lnrpc.RouteHint{
		{
			HopHints: []*lnrpc.HopHint{
				{
					ChanId: 1111,
					NodeId: route.Vertex{1, 1, 1}.String(),
				},
				{
					ChanId: 1111,
					NodeId: route.Vertex{1, 1, 1}.String(),
				},
			},
		},
		{
			HopHints: []*lnrpc.HopHint{
				{
					ChanId: 1233,
					NodeId: route.Vertex{1, 1, 1}.String(),
				},
				{
					ChanId: 1234,
					NodeId: route.Vertex{1, 2, 3}.String(),
				},
			},
		},
	}
}

func testNonAssetHints() []*lnrpc.RouteHint {
	return []*lnrpc.RouteHint{
		{
			HopHints: []*lnrpc.HopHint{
				{
					ChanId: 1234,
					NodeId: route.Vertex{1, 1, 1}.String(),
				},
				{
					ChanId: 1234,
					NodeId: route.Vertex{1, 1, 1}.String(),
				},
			},
		},
		{
			HopHints: []*lnrpc.HopHint{
				{
					ChanId: 1234,
					NodeId: route.Vertex{2, 2, 2}.String(),
				},
			},
		},
	}
}

func newWireCustomRecords(t *testing.T, amounts []*rfqmsg.AssetBalance,
	rfqID fn.Option[rfqmsg.ID]) lnwire.CustomRecords {

	htlc := rfqmsg.NewHtlc(amounts, rfqID)

	customRecords, err := lnwire.ParseCustomRecords(htlc.Bytes())
	require.NoError(t, err)

	return customRecords
}
