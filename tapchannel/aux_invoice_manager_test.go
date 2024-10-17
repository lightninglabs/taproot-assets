package tapchannel

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

const (
	// The test channel ID to use across the test cases.
	testChanID = 1234
)

var (
	// The node ID to be used for the RFQ peer.
	testNodeID = route.Vertex{1, 2, 3}
)

// mockRfqManager mocks the interface of the rfq manager required by the aux
// invoice manager. It also holds some internal state to return the desired
// quotes.
type mockRfqManager struct {
	peerBuyQuotes   rfq.BuyAcceptMap
	localSellQuotes rfq.SellAcceptMap
}

//nolint:lll
func (m *mockRfqManager) PeerAcceptedBuyQuotes() rfq.BuyAcceptMap {
	return m.peerBuyQuotes
}

//nolint:lll
func (m *mockRfqManager) LocalAcceptedSellQuotes() rfq.SellAcceptMap {
	return m.localSellQuotes
}

// mockHtlcModifier mocks the HtlcModifier interface that is require by the Aux
type mockHtlcModifier struct {
	requestQue     []lndclient.InvoiceHtlcModifyRequest
	expectedResQue []lndclient.InvoiceHtlcModifyResponse
	done           chan bool
	t              *testing.T
}

func (m *mockHtlcModifier) HtlcModifier(ctx context.Context,
	handler lndclient.InvoiceHtlcModifyHandler) error {

	// Process the requests that are provided by the test case.
	for i, r := range m.requestQue {
		res, err := handler(ctx, r)

		if err != nil {
			return err
		}

		// Check if there's a match with the expected outcome.
		if res.AmtPaid != m.expectedResQue[i].AmtPaid {
			return fmt.Errorf("invoice paid amount does not match "+
				"expected amount, %v != %v", res.AmtPaid,
				m.expectedResQue[i])
		}
	}

	// Signal that the htlc modifications are completed.
	close(m.done)

	return nil
}

// mockHtlcModifierProperty mocks the HtlcModifier interface that is required
// by the AuxHtlcModifier. This mock is specific to the property based tests,
// as some more info are needed to run more in-depth checks.
type mockHtlcModifierProperty struct {
	requestQue []lndclient.InvoiceHtlcModifyRequest
	rfqMap     rfq.BuyAcceptMap
	done       chan bool
	t          *rapid.T
}

func (m *mockHtlcModifierProperty) HtlcModifier(ctx context.Context,
	handler lndclient.InvoiceHtlcModifyHandler) error {

	// Process the requests that are provided by the test case.
	for _, r := range m.requestQue {
		res, err := handler(ctx, r)
		if err != nil {
			require.ErrorContains(
				m.t, err, "unable to get price from quote",
			)

			continue
		}

		if len(r.WireCustomRecords) == 0 {
			if len(r.Invoice.RouteHints) != 1 {
				require.Equal(m.t, 1, res.AmtPaid)
				continue
			}

			require.Equal(m.t, r.ExitHtlcAmt, res.AmtPaid)
			continue
		}

		htlcBlob, err := r.WireCustomRecords.Serialize()
		require.NoError(m.t, err)

		htlc, err := rfqmsg.DecodeHtlc(htlcBlob)
		require.NoError(m.t, err)

		if htlc.RfqID.ValOpt().IsNone() {
			require.Equal(m.t, r.ExitHtlcAmt, res.AmtPaid)
			require.Equal(m.t, r.CircuitKey, res.CircuitKey)
			continue
		}

		rfqID := htlc.RfqID.ValOpt().UnsafeFromSome()

		quote, ok := m.rfqMap[rfqID.Scid()]
		require.True(m.t, ok)

		assetUnits := lnwire.MilliSatoshi(htlc.Amounts.Val.Sum())
		assetValueMsat := assetUnits * quote.AskPrice

		acceptedMsat := lnwire.MilliSatoshi(0)
		for _, htlc := range r.Invoice.Htlcs {
			acceptedMsat += lnwire.MilliSatoshi(htlc.AmtMsat)
		}

		marginHtlcs := lnwire.MilliSatoshi(len(r.Invoice.Htlcs) + 1)
		marginMsat := marginHtlcs * quote.AskPrice

		totalMsatIn := marginMsat + assetValueMsat + acceptedMsat

		invoiceValue := lnwire.MilliSatoshi(r.Invoice.ValueMsat)
		if totalMsatIn > invoiceValue {
			require.Equal(
				m.t, invoiceValue-acceptedMsat, res.AmtPaid,
			)
		} else {
			require.Equal(
				m.t, assetValueMsat, res.AmtPaid,
			)
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
			name: "asset invoice, no custom records",
			requests: []lndclient.InvoiceHtlcModifyRequest{
				{
					Invoice: &lnrpc.Invoice{
						RouteHints: testRouteHints(),
					},
					ExitHtlcAmt: 1234,
				},
			},
			responses: []lndclient.InvoiceHtlcModifyResponse{
				{
					AmtPaid: 1,
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
						RouteHints: testRouteHints(),
						ValueMsat:  3_000_000,
					},
					WireCustomRecords: newWireCustomRecords(
						t, []*rfqmsg.AssetBalance{
							rfqmsg.NewAssetBalance(
								assetID(1), 3,
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
				dummyRfqID(31).Scid(): {
					Peer:     testNodeID,
					AskPrice: 1_000_000,
				},
			},
		},
		{
			name: "asset invoice, not enough amt",
			requests: []lndclient.InvoiceHtlcModifyRequest{
				{
					Invoice: &lnrpc.Invoice{
						RouteHints: testRouteHints(),
						ValueMsat:  3_000_000,
					},
					WireCustomRecords: newWireCustomRecords(
						t, []*rfqmsg.AssetBalance{
							rfqmsg.NewAssetBalance(
								assetID(1), 3,
							),
						}, fn.Some(dummyRfqID(31)),
					),
					ExitHtlcAmt: 1234,
				},
			},
			responses: []lndclient.InvoiceHtlcModifyResponse{
				{
					AmtPaid: 1_500_000,
				},
			},
			buyQuotes: rfq.BuyAcceptMap{
				dummyRfqID(31).Scid(): {
					Peer:     testNodeID,
					AskPrice: 500_000,
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

// genRandomRfqID generates a random rfqmsg.ID value.
func genRandomRfqID(t *rapid.T) rfqmsg.ID {
	var rfqID rfqmsg.ID
	for i := 0; i < len(rfqID); i++ {
		rfqID[i] = rapid.Byte().Draw(t, "scid_byte")
		// rapid.SliceOfN(rapid.Byte(), len(rfqID), len(rfqID))
	}
	return rfqID
}

// genInvoice generates an invoice that may have a random amount, and may have
// routing hints.
func genInvoice(t *rapid.T) *lnrpc.Invoice {
	res := &lnrpc.Invoice{}

	// Do a random draw with a 1/8 chance of introducing an empty invoice.
	nullInv := rapid.Uint16().Draw(t, "invoice_exists")
	if nullInv%8 == 0 {
		return res
	}

	// Generate a random invoice value.
	valueMsat := rapid.Int64Range(
		0, 100_000_000,
	).Draw(t, "invoice_value_msat")

	res.ValueMsat = valueMsat

	// Do a random draw with a 1/8 chance to introduce empty routing hints.
	nullHints := rapid.Uint16().Draw(t, "invoice_hints_exist")
	if nullHints%8 == 0 {
		return res
	}

	res.RouteHints = testRouteHints()

	return res
}

// genCustomRecords generates custom records that have a random amount of random
// asset units, and may have an scid as routing hint.
func genCustomRecords(t *rapid.T,
	rfqID rfqmsg.ID) (lnwire.CustomRecords, uint64) {

	assetUnits := rapid.Uint64Range(10_000, 100_000).Draw(t, "asset_units")

	balance := []*rfqmsg.AssetBalance{
		rfqmsg.NewAssetBalance(
			assetID(rapid.Byte().Draw(t, "asset_id")), assetUnits,
		),
	}

	htlc := genHtlc(t, balance, rfqID)

	customRecords, err := lnwire.ParseCustomRecords(htlc.Bytes())
	require.NoError(t, err)

	return customRecords, assetUnits
}

// genHtlc generates an istance of rfqmsg.Htlc with the provided asset amounts
// and rfqID.
func genHtlc(t *rapid.T, balance []*rfqmsg.AssetBalance,
	rfqID rfqmsg.ID) *rfqmsg.Htlc {

	// Introduce a 1/5 chance of no rfqID in this htlc.
	noRfqID := rapid.Uint16().Draw(t, "has_rfqid_probability")
	if noRfqID%5 == 0 {
		return rfqmsg.NewHtlc(balance, fn.None[rfqmsg.ID]())
	}

	// Introduce a 1/5 chance of a mismatch in the expected and actual htlc
	// rfqID.
	rfqIDMatch := rapid.Uint16().Draw(t, "rfqid_match_probability")
	if rfqIDMatch%5 == 0 {
		return rfqmsg.NewHtlc(
			balance,
			fn.Some(
				dummyRfqID(
					rapid.IntRange(0, 255).Draw(t, "scid"),
				),
			),
		)
	}

	return rfqmsg.NewHtlc(balance, fn.Some(rfqID))
}

// genRequest generates an InvoiceHtlcModifyRequest with random values. This
// method also returns the assetUnits and the rfqID used by the htlc.
func genRequest(t *rapid.T) (lndclient.InvoiceHtlcModifyRequest, uint64,
	rfqmsg.ID) {

	request := lndclient.InvoiceHtlcModifyRequest{}

	rfqID := genRandomRfqID(t)

	request.Invoice = genInvoice(t)
	wireRecords, assetUnits := genCustomRecords(t, rfqID)
	request.WireCustomRecords = wireRecords
	request.ExitHtlcAmt = lnwire.MilliSatoshi(request.Invoice.ValueMsat)

	return request, assetUnits, rfqID
}

// genRequests generates a random array of requests to be processed by the
// AuxInvoiceManager. It also returns the rfq map with the related rfq quotes.
func genRequests(t *rapid.T) ([]lndclient.InvoiceHtlcModifyRequest,
	rfq.BuyAcceptMap) {

	rfqMap := rfq.BuyAcceptMap{}

	len := rapid.IntRange(0, 5).Draw(t, "requestsLen")
	requests := make([]lndclient.InvoiceHtlcModifyRequest, len)

	for i := range requests {
		req, numAssets, scid := genRequest(t)
		requests[i] = req

		genBuyQuotes(
			t, rfqMap, numAssets, uint64(req.Invoice.ValueMsat),
			scid,
		)
	}

	return requests, rfqMap
}

// genBuyQuotes populates the provided map of rfq quotes with the desired values
// for a specific
func genBuyQuotes(t *rapid.T, rfqMap rfq.BuyAcceptMap, units, amtMsat uint64,
	scid rfqmsg.ID) {

	var peer route.Vertex
	askPrice := lnwire.MilliSatoshi(0)

	// Introduce a 1/8 chance that the quote's peerID is not correct.
	noPeerMatch := rapid.Uint16().Draw(t, "nodeID_mismatch_probability")
	if noPeerMatch%8 == 0 {
		peer = route.Vertex{3, 1, 4}
	} else {
		peer = testNodeID
	}

	// Introduce a 1/5 chance that the askPrice of this asset will result in
	// a random total asset value.
	noValueMatch := rapid.Uint16().Draw(t, "no_asset_value_match")
	if noValueMatch%5 == 0 {
		askPrice = lnwire.MilliSatoshi(
			rapid.Uint64Range(
				0, 250_000,
			).Draw(t, "asset_msat_value"))
	} else {
		askPrice = lnwire.MilliSatoshi(amtMsat / units)
	}

	rfqMap[scid.Scid()] = rfqmsg.BuyAccept{
		Peer:     peer,
		AskPrice: askPrice,
	}
}

// testInvoiceManager creates an array of requests to be processed by the
// AuxInvoiceManager. Uses the enhanced HtlcMmodifierMockProperty instance.
func testInvoiceManager(t *rapid.T) {
	requests, rfqMap := genRequests(t)

	mockRfq := &mockRfqManager{
		peerBuyQuotes: rfqMap,
	}

	done := make(chan bool)

	mockModifier := &mockHtlcModifierProperty{
		requestQue: requests,
		rfqMap:     rfqMap,
		done:       done,
		t:          t,
	}

	manager := NewAuxInvoiceManager(
		&InvoiceManagerConfig{
			ChainParams:         testChainParams,
			InvoiceHtlcModifier: mockModifier,
			RfqManager:          mockRfq,
		},
	)

	err := manager.Start()
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fail()
	}
}

// TestAuxInvoiceManagerProperty runs property based tests on the
// AuxInvoiceManager.
func TestAuxInvoiceManagerProperty(t *testing.T) {
	t.Parallel()

	t.Run("invoice_manager", rapid.MakeCheck(testInvoiceManager))
}

func newHash(i []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(i)

	return h.Sum(nil)
}

func assetID(i byte) asset.ID {
	return asset.ID(newHash([]byte{i}))
}

func dummyRfqID(value int) rfqmsg.ID {
	var rfqID rfqmsg.ID
	for i := 0; i < len(rfqID); i++ {
		rfqID[i] = byte(value)
	}
	return rfqID
}

func testRouteHints() []*lnrpc.RouteHint {
	return []*lnrpc.RouteHint{
		{
			HopHints: []*lnrpc.HopHint{
				{
					ChanId: 1234,
					NodeId: route.Vertex{1, 2, 3}.String(),
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
