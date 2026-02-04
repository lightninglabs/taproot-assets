package rfq

import (
	"context"
	"errors"
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

// mockPortfolioPilot is a minimal portfolio pilot used to control
// ResolveRequest responses in tests.
type mockPortfolioPilot struct {
	// resp is the response returned by the portfolio pilot.
	resp ResolveResp

	// err is the error returned by the portfolio pilot.
	err error
}

// ResolveRequest returns the configured response.
func (s *mockPortfolioPilot) ResolveRequest(context.Context,
	rfqmsg.Request) (ResolveResp, error) {

	return s.resp, s.err
}

// VerifyAcceptQuote verifies that an accepted quote from a peer meets
// acceptable conditions.
func (s *mockPortfolioPilot) VerifyAcceptQuote(context.Context,
	rfqmsg.Accept) (QuoteRespStatus, error) {

	return ValidAcceptQuoteRespStatus, nil
}

// QueryAssetRates returns mock asset rate information.
func (s *mockPortfolioPilot) QueryAssetRates(context.Context,
	AssetRateQuery) (rfqmsg.AssetRate, error) {

	// Return a default asset rate for testing
	return rfqmsg.AssetRate{
		Rate:   rfqmath.NewBigIntFixedPoint(1000, 0),
		Expiry: time.Now().Add(time.Hour),
	}, nil
}

func (s *mockPortfolioPilot) Close() error {
	return nil
}

// assertIncomingSellAcceptTestCase asserts the handling of an incoming sell
// accept message for a test case.
func assertIncomingSellAcceptTestCase(
	t *testing.T, tc testCaseIncomingSellAccept) {

	// Create a mock price oracle.
	mockPriceOracle := &MockPriceOracle{}

	// Register an expected call and response for price oracle method
	// QuerySellPrice.
	mockPriceOracle.On(
		"QuerySellPrice", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything,
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
	ctx := context.Background()
	negotiator.HandleIncomingSellAccept(ctx, sellAccept, finalise)

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
	// QueryBuyPrice.
	mockPriceOracle.On(
		"QueryBuyPrice", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything,
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
	ctx := context.Background()
	negotiator.HandleIncomingBuyAccept(ctx, buyAccept, finalise)

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

// TestHandleIncomingQuoteRequestError sends a reject to the peer when the
// portfolio pilot returns an error.
func TestHandleIncomingQuoteRequestError(t *testing.T) {
	pilotErr := errors.New("pilot failure")
	assetSpec := asset.NewSpecifierFromId(asset.ID{8, 8, 8})

	testCases := []struct {
		name    string
		request rfqmsg.Request
	}{
		{
			name: "buy request",
			request: &rfqmsg.BuyRequest{
				Peer:           route.Vertex{9, 9, 9},
				ID:             rfqmsg.ID{7, 7, 7},
				AssetSpecifier: assetSpec,
				AssetMaxAmt:    123,
			},
		},
		{
			name: "sell request",
			request: &rfqmsg.SellRequest{
				Peer:           route.Vertex{9, 9, 9},
				ID:             rfqmsg.ID{7, 7, 7},
				AssetSpecifier: assetSpec,
				PaymentMaxAmt:  lnwire.MilliSatoshi(123),
			},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			outgoing := make(chan rfqmsg.OutgoingMsg, 1)
			errChan := make(chan error, 1)

			negotiator, err := NewNegotiator(NegotiatorCfg{
				PortfolioPilot: &mockPortfolioPilot{
					err: pilotErr,
				},
				OutgoingMessages: outgoing,
				ErrChan:          errChan,
			})
			require.NoError(t, err)

			ctx := context.Background()
			err = negotiator.HandleIncomingQuoteRequest(
				ctx, tc.request,
			)
			require.NoError(t, err)
			negotiator.Wg.Wait()

			select {
			case msg := <-outgoing:
				reject, ok := msg.(*rfqmsg.Reject)
				require.True(t, ok, "expected reject message")
				require.Equal(
					t, tc.request.MsgPeer(),
					reject.MsgPeer(),
				)
				require.Equal(
					t, tc.request.MsgID(), reject.MsgID(),
				)
				require.Equal(
					t, rfqmsg.ErrUnknownReject,
					reject.Err.Val,
				)

			default:
				t.Fatalf("expected reject message on " +
					"outgoing channel")
			}

			select {
			case err := <-errChan:
				require.ErrorContains(
					t, err, "resolve quote request",
				)
				require.ErrorIs(t, err, pilotErr)
			default:
				t.Fatalf("expected error on errChan")
			}
		})
	}
}
