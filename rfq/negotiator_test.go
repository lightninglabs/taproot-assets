package rfq

import (
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// testCaseIncomingSellAccept is a test case for the handling of an incoming
// sell accept message.
type testCaseIncomingSellAccept struct {
	// name is the name of the test case.
	name string

	// incomingSellAcceptRate is the rate in the incoming sell accept
	// message.
	incomingSellAcceptRate rfqmsg.AssetRate

	// priceOracleAskPrice is the rate returned by the price oracle.
	priceOracleAskPrice rfqmsg.AssetRate

	// acceptPriceDeviationPpm is the acceptable price deviation in ppm.
	acceptPriceDeviationPpm uint64

	// quoteRespStatus is the expected status of the quote check.
	quoteRespStatus fn.Option[QuoteRespStatus]
}

// assertIncomingSellAcceptTestCase asserts the handling of an incoming sell
// accept message for a test case.
func assertIncomingSellAcceptTestCase(
	t *testing.T, tc testCaseIncomingSellAccept) {

	// Create a mock price oracle.
	mockPriceOracle := &MockPriceOracle{}

	// Register an expected call and response for price oracle method
	// QueryAskPrice.
	mockPriceOracle.On(
		"QueryAskPrice", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything,
	).Return(
		&OracleResponse{
			AssetRate: tc.priceOracleAskPrice,
		}, nil,
	)

	// Define sell request and sell accept messages.
	var (
		assetSpecifier = asset.NewSpecifierFromId(asset.ID{1, 2, 3})
		peerID         = route.Vertex{1, 2, 3}
		msgID          = rfqmsg.ID{1, 2, 3}
	)

	sellRequest := rfqmsg.SellRequest{
		Peer:           peerID,
		ID:             msgID,
		AssetSpecifier: assetSpecifier,
		PaymentMaxAmt:  lnwire.MilliSatoshi(1000),
		AssetRateHint:  fn.None[rfqmsg.AssetRate](),
	}

	sellAccept := rfqmsg.SellAccept{
		Request:   sellRequest,
		AssetRate: tc.incomingSellAcceptRate,
	}

	// Create the negotiator.
	errChan := make(chan error, 1)
	negotiator, err := NewNegotiator(NegotiatorCfg{
		PriceOracle:             mockPriceOracle,
		OutgoingMessages:        make(chan rfqmsg.OutgoingMsg, 1),
		AcceptPriceDeviationPpm: tc.acceptPriceDeviationPpm,
		ErrChan:                 errChan,
	})
	require.NoError(t, err)

	// Define the finalise callback function.
	finalise := func(msg rfqmsg.SellAccept,
		event fn.Option[InvalidQuoteRespEvent]) {

		// If the actual event is none and the expected status is none,
		// then we don't need to check anything.
		if event.IsNone() && tc.quoteRespStatus.IsNone() {
			return
		}

		require.Equal(t, tc.quoteRespStatus.IsSome(), event.IsSome())

		// Extract the actual event status.
		var actualEventStatus QuoteRespStatus
		event.WhenSome(func(e InvalidQuoteRespEvent) {
			actualEventStatus = e.Status
		})

		// Extract the expected event status.
		var expectedStatus QuoteRespStatus
		tc.quoteRespStatus.WhenSome(func(e QuoteRespStatus) {
			expectedStatus = e
		})

		// Ensure that the actual and expected event statuses are equal.
		require.Equal(t, expectedStatus, actualEventStatus)
	}

	// Handle the incoming sell accept message.
	negotiator.HandleIncomingSellAccept(sellAccept, finalise)

	// Check that there are no errors.
	select {
	case err := <-errChan:
		t.Fatalf("unexpected error: %v", err)
	default:
	}

	// Wait for the negotiator to finish.
	negotiator.Wg.Wait()
}

// TestHandleIncomingSellAccept tests the handling of an incoming sell accept
// message.
func TestHandleIncomingSellAccept(t *testing.T) {
	defaultQuoteExpiry := time.Now().Add(time.Hour)

	testCases := []testCaseIncomingSellAccept{
		{
			name: "accept price just within bounds 1",
			incomingSellAcceptRate: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(1000, 0),
				Expiry: defaultQuoteExpiry,
			},
			priceOracleAskPrice: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(1052, 0),
				Expiry: defaultQuoteExpiry,
			},
			acceptPriceDeviationPpm: DefaultAcceptPriceDeviationPpm,
		},
		{
			name: "accept price just within bounds 2",
			incomingSellAcceptRate: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(1000, 0),
				Expiry: defaultQuoteExpiry,
			},
			priceOracleAskPrice: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(950, 0),
				Expiry: defaultQuoteExpiry,
			},
			acceptPriceDeviationPpm: DefaultAcceptPriceDeviationPpm,
		},
		{
			name: "accept price outside bounds, higher than oracle",
			incomingSellAcceptRate: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(8000, 0),
				Expiry: defaultQuoteExpiry,
			},
			priceOracleAskPrice: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(1000, 0),
				Expiry: defaultQuoteExpiry,
			},
			acceptPriceDeviationPpm: DefaultAcceptPriceDeviationPpm,
			quoteRespStatus: fn.Some[QuoteRespStatus](
				InvalidAssetRatesQuoteRespStatus,
			),
		},
		{
			name: "accept price outside bounds, lower than oracle",
			incomingSellAcceptRate: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(1000, 0),
				Expiry: defaultQuoteExpiry,
			},
			priceOracleAskPrice: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(8000, 0),
				Expiry: defaultQuoteExpiry,
			},
			acceptPriceDeviationPpm: DefaultAcceptPriceDeviationPpm,
			quoteRespStatus: fn.Some[QuoteRespStatus](
				InvalidAssetRatesQuoteRespStatus,
			),
		},
	}

	for idx := range testCases {
		tc := testCases[idx]

		success := t.Run(tc.name, func(t *testing.T) {
			assertIncomingSellAcceptTestCase(t, tc)
		})
		if !success {
			break
		}
	}
}

// testCaseIncomingBuyAccept is a test case for the handling of an incoming
// buy accept message.
type testCaseIncomingBuyAccept struct {
	// name is the name of the test case.
	name string

	// incomingBuyAcceptRate is the rate in the incoming buy accept
	// message.
	incomingBuyAcceptRate rfqmsg.AssetRate

	// priceOracleBidPrice is the rate returned by the price oracle.
	priceOracleBidPrice rfqmsg.AssetRate

	// acceptPriceDeviationPpm is the acceptable price deviation in ppm.
	acceptPriceDeviationPpm uint64

	// quoteRespStatus is the expected status of the quote check.
	quoteRespStatus fn.Option[QuoteRespStatus]
}

// assertIncomingBuyAcceptTestCase asserts the handling of an incoming buy
// accept message for a test case.
func assertIncomingBuyAcceptTestCase(
	t *testing.T, tc testCaseIncomingBuyAccept) {

	// Create a mock price oracle.
	mockPriceOracle := &MockPriceOracle{}

	// Register an expected call and response for price oracle method
	// QueryBidPrice.
	mockPriceOracle.On(
		"QueryBidPrice", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything,
	).Return(
		&OracleResponse{
			AssetRate: tc.priceOracleBidPrice,
		}, nil,
	)

	// Define buy request and buy accept messages.
	var (
		assetSpecifier = asset.NewSpecifierFromId(asset.ID{1, 2, 3})
		peerID         = route.Vertex{1, 2, 3}
		msgID          = rfqmsg.ID{1, 2, 3}
	)

	buyRequest := rfqmsg.BuyRequest{
		Peer:           peerID,
		ID:             msgID,
		AssetSpecifier: assetSpecifier,
		AssetMaxAmt:    1000,
		AssetRateHint:  fn.None[rfqmsg.AssetRate](),
	}

	buyAccept := rfqmsg.BuyAccept{
		Request:   buyRequest,
		AssetRate: tc.incomingBuyAcceptRate,
	}

	// Create the negotiator.
	errChan := make(chan error, 1)
	negotiator, err := NewNegotiator(NegotiatorCfg{
		PriceOracle:             mockPriceOracle,
		OutgoingMessages:        make(chan rfqmsg.OutgoingMsg, 1),
		AcceptPriceDeviationPpm: tc.acceptPriceDeviationPpm,
		ErrChan:                 errChan,
	})
	require.NoError(t, err)

	// Define the finalise callback function.
	finalise := func(msg rfqmsg.BuyAccept,
		event fn.Option[InvalidQuoteRespEvent]) {

		// If the actual event is none and the expected status is none,
		// then we don't need to check anything.
		if event.IsNone() && tc.quoteRespStatus.IsNone() {
			return
		}

		require.Equal(t, tc.quoteRespStatus.IsSome(), event.IsSome())

		// Extract the actual event status.
		var actualEventStatus QuoteRespStatus
		event.WhenSome(func(e InvalidQuoteRespEvent) {
			actualEventStatus = e.Status
		})

		// Extract the expected event status.
		var expectedStatus QuoteRespStatus
		tc.quoteRespStatus.WhenSome(func(e QuoteRespStatus) {
			expectedStatus = e
		})

		// Ensure that the actual and expected event statuses are equal.
		require.Equal(t, expectedStatus, actualEventStatus)
	}

	// Handle the incoming buy accept message.
	negotiator.HandleIncomingBuyAccept(buyAccept, finalise)

	// Check that there are no errors.
	select {
	case err := <-errChan:
		t.Fatalf("unexpected error: %v", err)
	default:
	}

	// Wait for the negotiator to finish.
	negotiator.Wg.Wait()
}

// TestHandleIncomingBuyAccept tests the handling of an incoming buy accept
// message.
func TestHandleIncomingBuyAccept(t *testing.T) {
	defaultQuoteExpiry := time.Now().Add(time.Hour)

	testCases := []testCaseIncomingBuyAccept{
		{
			name: "accept price just within bounds 1",
			incomingBuyAcceptRate: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(1000, 0),
				Expiry: defaultQuoteExpiry,
			},
			priceOracleBidPrice: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(1052, 0),
				Expiry: defaultQuoteExpiry,
			},
			acceptPriceDeviationPpm: DefaultAcceptPriceDeviationPpm,
		},
		{
			name: "accept price just within bounds 2",
			incomingBuyAcceptRate: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(1000, 0),
				Expiry: defaultQuoteExpiry,
			},
			priceOracleBidPrice: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(950, 0),
				Expiry: defaultQuoteExpiry,
			},
			acceptPriceDeviationPpm: DefaultAcceptPriceDeviationPpm,
		},
		{
			name: "accept price outside bounds, higher than oracle",
			incomingBuyAcceptRate: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(8000, 0),
				Expiry: defaultQuoteExpiry,
			},
			priceOracleBidPrice: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(1000, 0),
				Expiry: defaultQuoteExpiry,
			},
			acceptPriceDeviationPpm: DefaultAcceptPriceDeviationPpm,
			quoteRespStatus: fn.Some[QuoteRespStatus](
				InvalidAssetRatesQuoteRespStatus,
			),
		},
		{
			name: "accept price outside bounds, lower than oracle",
			incomingBuyAcceptRate: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(1000, 0),
				Expiry: defaultQuoteExpiry,
			},
			priceOracleBidPrice: rfqmsg.AssetRate{
				Rate:   rfqmath.NewBigIntFixedPoint(8000, 0),
				Expiry: defaultQuoteExpiry,
			},
			acceptPriceDeviationPpm: DefaultAcceptPriceDeviationPpm,
			quoteRespStatus: fn.Some[QuoteRespStatus](
				InvalidAssetRatesQuoteRespStatus,
			),
		},
	}

	for idx := range testCases {
		tc := testCases[idx]

		success := t.Run(tc.name, func(t *testing.T) {
			assertIncomingBuyAcceptTestCase(t, tc)
		})
		if !success {
			break
		}
	}
}
