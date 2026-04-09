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

// expectQuerySellPrice configures the shared MockPriceOracle to return the
// supplied response/error.
func expectQuerySellPrice(oracle *MockPriceOracle, resp *OracleResponse,
	err error) {

	oracle.On(
		"QuerySellPrice", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything,
	).Return(resp, err).Once()
}

// expectQueryBuyPrice configures the shared MockPriceOracle to return the
// supplied response/error.
func expectQueryBuyPrice(oracle *MockPriceOracle, resp *OracleResponse,
	err error) {

	oracle.On(
		"QueryBuyPrice", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		mock.Anything,
	).Return(resp, err).Once()
}

// assertSellPriceCall verifies the recorded QuerySellPrice call arguments.
func assertSellPriceCall(t *testing.T, oracle *MockPriceOracle,
	idx int, expAssetSpec asset.Specifier,
	expAssetMax fn.Option[uint64],
	expPaymentMax fn.Option[lnwire.MilliSatoshi],
	expRateHint fn.Option[rfqmsg.AssetRate],
	expCounterparty fn.Option[route.Vertex], expMetadata string,
	expIntent PriceQueryIntent) {

	t.Helper()

	// idx is zero-based while AssertNumberOfCalls expects the total count,
	// hence the +1.
	oracle.AssertNumberOfCalls(t, "QuerySellPrice", idx+1)

	call := oracle.Calls[idx]
	require.Equal(t, "QuerySellPrice", call.Method)

	require.Equal(t, expAssetSpec, call.Arguments[1].(asset.Specifier))
	require.Equal(t, expAssetMax, call.Arguments[2].(fn.Option[uint64]))
	require.Equal(
		t, expPaymentMax,
		call.Arguments[3].(fn.Option[lnwire.MilliSatoshi]),
	)
	require.Equal(
		t, expRateHint,
		call.Arguments[4].(fn.Option[rfqmsg.AssetRate]),
	)
	require.Equal(
		t, expCounterparty,
		call.Arguments[5].(fn.Option[route.Vertex]),
	)
	require.Equal(t, expMetadata, call.Arguments[6].(string))
	require.Equal(t, expIntent, call.Arguments[7].(PriceQueryIntent))
}

// assertBuyPriceCall verifies the recorded QueryBuyPrice call arguments.
func assertBuyPriceCall(t *testing.T, oracle *MockPriceOracle,
	idx int, expAssetSpec asset.Specifier,
	expAssetMax fn.Option[uint64],
	expPaymentMax fn.Option[lnwire.MilliSatoshi],
	expRateHint fn.Option[rfqmsg.AssetRate],
	expCounterparty fn.Option[route.Vertex], expMetadata string,
	expIntent PriceQueryIntent) {

	t.Helper()

	// idx is zero-based while AssertNumberOfCalls expects the total count.
	oracle.AssertNumberOfCalls(t, "QueryBuyPrice", idx+1)

	call := oracle.Calls[idx]
	require.Equal(t, "QueryBuyPrice", call.Method)

	require.Equal(t, expAssetSpec, call.Arguments[1].(asset.Specifier))
	require.Equal(t, expAssetMax, call.Arguments[2].(fn.Option[uint64]))
	require.Equal(
		t, expPaymentMax,
		call.Arguments[3].(fn.Option[lnwire.MilliSatoshi]),
	)
	require.Equal(
		t, expRateHint,
		call.Arguments[4].(fn.Option[rfqmsg.AssetRate]),
	)
	require.Equal(
		t, expCounterparty,
		call.Arguments[5].(fn.Option[route.Vertex]),
	)
	require.Equal(t, expMetadata, call.Arguments[6].(string))
	require.Equal(t, expIntent, call.Arguments[7].(PriceQueryIntent))
}

// TestResolveRequest exercises buy and sell request handling across error and
// success scenarios.
func TestResolveRequest(t *testing.T) {
	newBuyReq := func(
		t *testing.T, assetID byte,
		rateHint fn.Option[rfqmsg.AssetRate],
	) *rfqmsg.BuyRequest {

		t.Helper()

		req, err := rfqmsg.NewBuyRequest(
			route.Vertex{0x01, 0x02, 0x03},
			asset.NewSpecifierFromId(asset.ID{assetID}), 100,
			fn.None[uint64](),
			fn.None[rfqmath.BigIntFixedPoint](),
			rateHint, "order-metadata",
			fn.None[rfqmsg.ExecutionPolicy](),
		)
		require.NoError(t, err)
		return req
	}

	newSellReq := func(
		t *testing.T, assetID byte, paymentMax lnwire.MilliSatoshi,
		rateHint fn.Option[rfqmsg.AssetRate],
	) *rfqmsg.SellRequest {

		t.Helper()

		req, err := rfqmsg.NewSellRequest(
			route.Vertex{0x0A, 0x0B, 0x0C},
			asset.NewSpecifierFromId(asset.ID{assetID}),
			paymentMax,
			fn.None[lnwire.MilliSatoshi](),
			fn.None[rfqmath.BigIntFixedPoint](),
			rateHint, "order-metadata",
			fn.None[rfqmsg.ExecutionPolicy](),
		)
		require.NoError(t, err)
		return req
	}

	hintExpiry := time.Now().Add(2 * time.Minute).UTC()
	requestRateHint := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(75, 0), hintExpiry,
	)
	buyResponseExpiry := time.Now().Add(5 * time.Minute).UTC()
	expectedBuyRate := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(125, 0), buyResponseExpiry,
	)

	sellResponseExpiry := time.Now().Add(3 * time.Minute).UTC()
	expectedSellRate := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(200, 0), sellResponseExpiry,
	)

	tests := []struct {
		// name describes the subtest case.
		name string

		// forwardPeer controls whether the pilot forwards the peer to
		// the oracle.
		forwardPeer bool

		// makeReq builds the request for the test case.
		makeReq func(t *testing.T) rfqmsg.Request

		// setupOracle registers expectations on the mock oracle.
		setupOracle func(*MockPriceOracle)

		// expectErr, if non-empty, is the substring expected in the
		// error.
		expectErr string

		// assertFn performs per-case assertions.
		assertFn func(
			t *testing.T, resp ResolveResp, req rfqmsg.Request,
			oracle *MockPriceOracle,
		)
	}{
		{
			name:        "buy: oracle query error",
			forwardPeer: true,
			makeReq: func(t *testing.T) rfqmsg.Request {
				return newBuyReq(
					t, 0x02, fn.Some(requestRateHint),
				)
			},
			setupOracle: func(o *MockPriceOracle) {
				err := errors.New("oracle unreachable")
				expectQuerySellPrice(o, nil, err)
			},
			expectErr: "query sell price",
			assertFn: func(
				t *testing.T, resp ResolveResp,
				req rfqmsg.Request, oracle *MockPriceOracle,
			) {

				buyReq := req.(*rfqmsg.BuyRequest)

				assertSellPriceCall(
					t, oracle, 0, buyReq.AssetSpecifier,
					fn.Some(buyReq.AssetMaxAmt),
					fn.None[lnwire.MilliSatoshi](),
					buyReq.AssetRateHint,
					fn.Some(buyReq.Peer),
					buyReq.PriceOracleMetadata,
					IntentRecvPayment,
				)
			},
		},
		{
			name: "buy: oracle returned error",
			makeReq: func(t *testing.T) rfqmsg.Request {
				return newBuyReq(
					t, 0x03, fn.None[rfqmsg.AssetRate](),
				)
			},
			setupOracle: func(o *MockPriceOracle) {
				resp := OracleResponse{
					Err: &OracleError{
						Code: 7,
						Msg:  "rate unavailable",
					},
				}
				expectQuerySellPrice(o, &resp, nil)
			},
			expectErr: "price oracle returned error",
		},
		{
			name:        "buy: success forward peer",
			forwardPeer: true,
			makeReq: func(t *testing.T) rfqmsg.Request {
				return newBuyReq(
					t, 0x05, fn.Some(requestRateHint),
				)
			},
			setupOracle: func(o *MockPriceOracle) {
				expectQuerySellPrice(
					o, &OracleResponse{
						AssetRate: expectedBuyRate,
					}, nil,
				)
			},
			assertFn: func(
				t *testing.T, resp ResolveResp,
				req rfqmsg.Request,
				oracle *MockPriceOracle,
			) {

				buyReq := req.(*rfqmsg.BuyRequest)

				require.True(t, resp.IsAccept())

				var assetRate rfqmsg.AssetRate
				resp.WhenAccept(func(rate rfqmsg.AssetRate) {
					assetRate = rate
				})
				require.Equal(t, expectedBuyRate, assetRate)

				assertSellPriceCall(
					t, oracle, 0, buyReq.AssetSpecifier,
					fn.Some(buyReq.AssetMaxAmt),
					fn.None[lnwire.MilliSatoshi](),
					buyReq.AssetRateHint,
					fn.Some(buyReq.Peer),
					buyReq.PriceOracleMetadata,
					IntentRecvPayment,
				)
			},
		},
		{
			name: "buy: success without forwarding peer",
			makeReq: func(t *testing.T) rfqmsg.Request {
				return newBuyReq(
					t, 0x05, fn.Some(requestRateHint),
				)
			},
			setupOracle: func(o *MockPriceOracle) {
				expectQuerySellPrice(
					o, &OracleResponse{
						AssetRate: expectedBuyRate,
					}, nil,
				)
			},
			assertFn: func(
				t *testing.T, resp ResolveResp,
				req rfqmsg.Request,
				oracle *MockPriceOracle,
			) {

				buyReq := req.(*rfqmsg.BuyRequest)

				require.True(t, resp.IsAccept())

				var assetRate rfqmsg.AssetRate
				resp.WhenAccept(func(rate rfqmsg.AssetRate) {
					assetRate = rate
				})
				require.Equal(t, expectedBuyRate, assetRate)

				assertSellPriceCall(
					t, oracle, 0, buyReq.AssetSpecifier,
					fn.Some(buyReq.AssetMaxAmt),
					fn.None[lnwire.MilliSatoshi](),
					buyReq.AssetRateHint,
					fn.None[route.Vertex](),
					buyReq.PriceOracleMetadata,
					IntentRecvPayment,
				)
			},
		},
		{
			name:        "sell: oracle query error",
			forwardPeer: true,
			makeReq: func(t *testing.T) rfqmsg.Request {
				return newSellReq(
					t, 0x07, lnwire.MilliSatoshi(2500),
					fn.None[rfqmsg.AssetRate](),
				)
			},
			setupOracle: func(o *MockPriceOracle) {
				err := errors.New("oracle unreachable")
				expectQueryBuyPrice(o, nil, err)
			},
			expectErr: "query buy price",
			assertFn: func(
				t *testing.T, resp ResolveResp,
				req rfqmsg.Request, oracle *MockPriceOracle,
			) {

				sellReq := req.(*rfqmsg.SellRequest)

				assertBuyPriceCall(
					t, oracle, 0, sellReq.AssetSpecifier,
					fn.None[uint64](),
					fn.Some(sellReq.PaymentMaxAmt),
					fn.None[rfqmsg.AssetRate](),
					fn.Some(sellReq.Peer),
					sellReq.PriceOracleMetadata,
					IntentPayInvoice,
				)
			},
		},
		{
			name: "sell: oracle returned error",
			makeReq: func(t *testing.T) rfqmsg.Request {
				return newSellReq(
					t, 0x08, lnwire.MilliSatoshi(5000),
					fn.None[rfqmsg.AssetRate](),
				)
			},
			setupOracle: func(o *MockPriceOracle) {
				resp := OracleResponse{
					Err: &OracleError{
						Code: 9,
						Msg:  "rate unavailable",
					},
				}
				expectQueryBuyPrice(o, &resp, nil)
			},
			expectErr: "price oracle returned error",
		},
		{
			name:        "sell: success forward peer",
			forwardPeer: true,
			makeReq: func(t *testing.T) rfqmsg.Request {
				return newSellReq(
					t, 0x0D, lnwire.MilliSatoshi(11111),
					fn.None[rfqmsg.AssetRate](),
				)
			},
			setupOracle: func(o *MockPriceOracle) {
				expectQueryBuyPrice(
					o, &OracleResponse{
						AssetRate: expectedSellRate,
					}, nil,
				)
			},
			assertFn: func(
				t *testing.T, resp ResolveResp,
				req rfqmsg.Request, oracle *MockPriceOracle,
			) {

				sellReq := req.(*rfqmsg.SellRequest)

				require.True(t, resp.IsAccept())

				var assetRate rfqmsg.AssetRate
				resp.WhenAccept(func(rate rfqmsg.AssetRate) {
					assetRate = rate
				})
				require.Equal(t, expectedSellRate, assetRate)

				assertBuyPriceCall(
					t, oracle, 0, sellReq.AssetSpecifier,
					fn.None[uint64](),
					fn.Some(sellReq.PaymentMaxAmt),
					fn.None[rfqmsg.AssetRate](),
					fn.Some(sellReq.Peer),
					sellReq.PriceOracleMetadata,
					IntentPayInvoice,
				)
			},
		},
		{
			name: "sell: success without forwarding peer",
			makeReq: func(t *testing.T) rfqmsg.Request {
				return newSellReq(
					t, 0x0D, lnwire.MilliSatoshi(11111),
					fn.None[rfqmsg.AssetRate](),
				)
			},
			setupOracle: func(o *MockPriceOracle) {
				expectQueryBuyPrice(
					o, &OracleResponse{
						AssetRate: expectedSellRate,
					}, nil,
				)
			},
			assertFn: func(
				t *testing.T, resp ResolveResp,
				req rfqmsg.Request, oracle *MockPriceOracle,
			) {

				sellReq := req.(*rfqmsg.SellRequest)

				require.True(t, resp.IsAccept())

				var assetRate rfqmsg.AssetRate
				resp.WhenAccept(func(rate rfqmsg.AssetRate) {
					assetRate = rate
				})
				require.Equal(t, expectedSellRate, assetRate)

				assertBuyPriceCall(
					t, oracle, 0, sellReq.AssetSpecifier,
					fn.None[uint64](),
					fn.Some(sellReq.PaymentMaxAmt),
					fn.None[rfqmsg.AssetRate](),
					fn.None[route.Vertex](),
					sellReq.PriceOracleMetadata,
					IntentPayInvoice,
				)
			},
		},
	}

	for _, tc := range tests {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			req := tc.makeReq(t)
			oracle := &MockPriceOracle{}
			tc.setupOracle(oracle)

			cfg := InternalPortfolioPilotConfig{
				PriceOracle:                 oracle,
				ForwardPeerIDToOracle:       tc.forwardPeer,
				AcceptPriceDeviationPpm:     50_000, // 5%
				MinAssetRatesExpiryLifetime: 10,
			}
			pilot, err := NewInternalPortfolioPilot(cfg)
			require.NoError(t, err)

			ctx := context.Background()
			resp, err := pilot.ResolveRequest(ctx, req)
			switch {
			case tc.expectErr != "":
				require.ErrorContains(t, err, tc.expectErr)
				require.False(t, resp.IsAccept())
				require.False(t, resp.IsReject())

			default:
				require.NoError(t, err)
				require.False(t, resp.IsReject())
			}

			if tc.assertFn != nil {
				tc.assertFn(t, resp, req, oracle)
			}

			oracle.AssertExpectations(t)
		})
	}
}

// TestVerifyAcceptQuote exercises the VerifyAcceptQuote method across various
// error and success scenarios for both buy and sell accept messages.
func TestVerifyAcceptQuote(t *testing.T) {
	t.Parallel()

	// Common test fixtures.
	assetSpec := asset.NewSpecifierFromId(asset.ID{0x01, 0x02, 0x03})
	peerID := route.Vertex{0x0A, 0x0B, 0x0C}

	// Expiry times for testing.
	expiredTime := time.Now().Add(-1 * time.Minute)
	validExpiryFuture := time.Now().Add(30 * time.Second)

	// Price rates for testing.
	peerRate := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(100, 0), validExpiryFuture,
	)
	oracleRateMatch := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(100, 0), validExpiryFuture,
	)
	// Within 5% tolerance (50,000 PPM).
	oracleRateWithinTolerance := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(104, 0), validExpiryFuture,
	)
	// Outside 5% tolerance.
	oracleRateOutsideTolerance := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(110, 0), validExpiryFuture,
	)

	tests := []struct {
		name string

		// makeAccept creates the accept message for this test.
		makeAccept func(t *testing.T) rfqmsg.Accept

		// setupOracle configures the mock price oracle expectations.
		setupOracle func(*MockPriceOracle)

		// expectStatus is the expected QuoteRespStatus.
		// ValidAcceptQuoteRespStatus means success; other values mean
		// validation failure.
		expectStatus QuoteRespStatus

		// expectErr indicates whether we expect an error.
		expectErr bool

		// expectErrSubstring is expected to be in the error message
		// (only checked when expectErr is true).
		expectErrSubstring string
	}{
		{
			name: "buy accept: expired quote",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				buyReq, err := rfqmsg.NewBuyRequest(
					peerID, assetSpec, 100,
					fn.None[uint64](),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				expiredRate := rfqmsg.NewAssetRate(
					rfqmath.NewBigIntFixedPoint(100, 0),
					expiredTime,
				)

				return &rfqmsg.BuyAccept{
					Peer:      peerID,
					Request:   *buyReq,
					AssetRate: expiredRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				// Oracle should not be called for expired
				// quotes.
			},
			expectStatus: InvalidExpiryQuoteRespStatus,
			expectErr:    false,
		},
		{
			name: "buy accept: oracle query error",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				buyReq, err := rfqmsg.NewBuyRequest(
					peerID, assetSpec, 100,
					fn.None[uint64](),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.BuyAccept{
					Peer:      peerID,
					Request:   *buyReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				expectQueryBuyPrice(
					p, nil, errors.New("oracle down"),
				)
			},
			expectStatus:       PriceOracleQueryErrQuoteRespStatus,
			expectErr:          true,
			expectErrSubstring: "query buy price from oracle",
		},
		{
			name: "buy accept: oracle error response",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				buyReq, err := rfqmsg.NewBuyRequest(
					peerID, assetSpec, 100,
					fn.None[uint64](),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.BuyAccept{
					Peer:      peerID,
					Request:   *buyReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				resp := &OracleResponse{
					Err: &OracleError{
						Code: 42,
						Msg:  "rate unavailable",
					},
				}
				expectQueryBuyPrice(p, resp, nil)
			},
			// Oracle returning an error response is expected
			// (the oracle rejected the quote).
			expectStatus: PriceOracleQueryErrQuoteRespStatus,
			expectErr:    true,
		},
		{
			name: "buy accept: price exactly matches",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				buyReq, err := rfqmsg.NewBuyRequest(
					peerID, assetSpec, 100,
					fn.None[uint64](),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.BuyAccept{
					Peer:      peerID,
					Request:   *buyReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				expectQueryBuyPrice(
					p, &OracleResponse{
						AssetRate: oracleRateMatch,
					}, nil,
				)
			},
			expectStatus: ValidAcceptQuoteRespStatus,
			expectErr:    false,
		},
		{
			name: "buy accept: price within tolerance",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				buyReq, err := rfqmsg.NewBuyRequest(
					peerID, assetSpec, 100,
					fn.None[uint64](),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.BuyAccept{
					Peer:      peerID,
					Request:   *buyReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				resp := OracleResponse{
					AssetRate: oracleRateWithinTolerance,
				}
				expectQueryBuyPrice(p, &resp, nil)
			},
			expectStatus: ValidAcceptQuoteRespStatus,
			expectErr:    false,
		},
		{
			name: "buy accept: price outside tolerance",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				buyReq, err := rfqmsg.NewBuyRequest(
					peerID, assetSpec, 100,
					fn.None[uint64](),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.BuyAccept{
					Peer:      peerID,
					Request:   *buyReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				resp := OracleResponse{
					AssetRate: oracleRateOutsideTolerance,
				}
				expectQueryBuyPrice(p, &resp, nil)
			},
			// Price outside tolerance is an expected validation
			// failure (no Go error).
			expectStatus: InvalidAssetRatesQuoteRespStatus,
			expectErr:    false,
		},
		{
			name: "sell accept: expired quote",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				sellReq, err := rfqmsg.NewSellRequest(
					peerID, assetSpec,
					lnwire.MilliSatoshi(1000),
					fn.None[lnwire.MilliSatoshi](),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				expiredRate := rfqmsg.NewAssetRate(
					rfqmath.NewBigIntFixedPoint(100, 0),
					expiredTime,
				)

				return &rfqmsg.SellAccept{
					Peer:      peerID,
					Request:   *sellReq,
					AssetRate: expiredRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				// Oracle should not be called for expired
				// quotes.
			},
			expectStatus: InvalidExpiryQuoteRespStatus,
			expectErr:    false,
		},
		{
			name: "sell accept: oracle query error",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				sellReq, err := rfqmsg.NewSellRequest(
					peerID, assetSpec,
					lnwire.MilliSatoshi(1000),
					fn.None[lnwire.MilliSatoshi](),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.SellAccept{
					Peer:      peerID,
					Request:   *sellReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				expectQuerySellPrice(
					p, nil, errors.New("oracle down"),
				)
			},
			expectStatus:       PriceOracleQueryErrQuoteRespStatus,
			expectErr:          true,
			expectErrSubstring: "query sell price from oracle",
		},
		{
			name: "sell accept: price within tolerance",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				sellReq, err := rfqmsg.NewSellRequest(
					peerID, assetSpec,
					lnwire.MilliSatoshi(1000),
					fn.None[lnwire.MilliSatoshi](),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.SellAccept{
					Peer:      peerID,
					Request:   *sellReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				resp := OracleResponse{
					AssetRate: oracleRateWithinTolerance,
				}
				expectQuerySellPrice(p, &resp, nil)
			},
			expectStatus: ValidAcceptQuoteRespStatus,
			expectErr:    false,
		},
		{
			name: "sell accept: price outside tolerance",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				sellReq, err := rfqmsg.NewSellRequest(
					peerID, assetSpec,
					lnwire.MilliSatoshi(1000),
					fn.None[lnwire.MilliSatoshi](),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.SellAccept{
					Peer:      peerID,
					Request:   *sellReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				resp := OracleResponse{
					AssetRate: oracleRateOutsideTolerance,
				}
				expectQuerySellPrice(p, &resp, nil)
			},
			// Price outside tolerance is an expected validation
			// failure (no Go error).
			expectStatus: InvalidAssetRatesQuoteRespStatus,
			expectErr:    false,
		},

		// --- Rate bound enforcement cases ---

		{
			name: "buy accept: rate below limit",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				// Buyer sets floor at 150 units/BTC,
				// but peer offers only 100.
				limit := rfqmath.NewBigIntFixedPoint(
					150, 0,
				)
				buyReq, err := rfqmsg.NewBuyRequest(
					peerID, assetSpec, 100,
					fn.None[uint64](),
					fn.Some(limit),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.BuyAccept{
					Peer:      peerID,
					Request:   *buyReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				expectQueryBuyPrice(
					p, &OracleResponse{
						AssetRate: oracleRateMatch,
					}, nil,
				)
			},
			expectStatus: RateBoundMissQuoteRespStatus,
			expectErr:    false,
		},
		{
			name: "buy accept: rate at limit",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				// Buyer floor exactly equals accepted
				// rate.
				limit := rfqmath.NewBigIntFixedPoint(
					100, 0,
				)
				buyReq, err := rfqmsg.NewBuyRequest(
					peerID, assetSpec, 100,
					fn.None[uint64](),
					fn.Some(limit),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.BuyAccept{
					Peer:      peerID,
					Request:   *buyReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				expectQueryBuyPrice(
					p, &OracleResponse{
						AssetRate: oracleRateMatch,
					}, nil,
				)
			},
			expectStatus: ValidAcceptQuoteRespStatus,
			expectErr:    false,
		},
		{
			name: "buy accept: rate above limit",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				// Buyer floor is 50, accepted rate is
				// 100 — should pass.
				limit := rfqmath.NewBigIntFixedPoint(
					50, 0,
				)
				buyReq, err := rfqmsg.NewBuyRequest(
					peerID, assetSpec, 100,
					fn.None[uint64](),
					fn.Some(limit),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.BuyAccept{
					Peer:      peerID,
					Request:   *buyReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				expectQueryBuyPrice(
					p, &OracleResponse{
						AssetRate: oracleRateMatch,
					}, nil,
				)
			},
			expectStatus: ValidAcceptQuoteRespStatus,
			expectErr:    false,
		},
		{
			name: "sell accept: rate above limit",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				// Seller ceiling is 50, but accepted
				// rate is 100 — should fail.
				limit := rfqmath.NewBigIntFixedPoint(
					50, 0,
				)
				sellReq, err := rfqmsg.NewSellRequest(
					peerID, assetSpec,
					lnwire.MilliSatoshi(1000),
					fn.None[lnwire.MilliSatoshi](),
					fn.Some(limit),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.SellAccept{
					Peer:      peerID,
					Request:   *sellReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				resp := OracleResponse{
					AssetRate: oracleRateMatch,
				}
				expectQuerySellPrice(p, &resp, nil)
			},
			expectStatus: RateBoundMissQuoteRespStatus,
			expectErr:    false,
		},
		{
			name: "sell accept: rate at limit",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				// Seller ceiling equals accepted rate.
				limit := rfqmath.NewBigIntFixedPoint(
					100, 0,
				)
				sellReq, err := rfqmsg.NewSellRequest(
					peerID, assetSpec,
					lnwire.MilliSatoshi(1000),
					fn.None[lnwire.MilliSatoshi](),
					fn.Some(limit),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.SellAccept{
					Peer:      peerID,
					Request:   *sellReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				resp := OracleResponse{
					AssetRate: oracleRateMatch,
				}
				expectQuerySellPrice(p, &resp, nil)
			},
			expectStatus: ValidAcceptQuoteRespStatus,
			expectErr:    false,
		},

		// --- Min fill enforcement cases ---

		{
			name: "buy accept: min fill zero msat",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				// Rate is very high (1e12 units/BTC),
				// so 1 unit converts to ~0 msat.
				hugeRate := rfqmsg.NewAssetRate(
					rfqmath.NewBigIntFixedPoint(
						1_000_000_000_000, 0,
					),
					validExpiryFuture,
				)
				buyReq, err := rfqmsg.NewBuyRequest(
					peerID, assetSpec, 100,
					fn.Some[uint64](1),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.BuyAccept{
					Peer:      peerID,
					Request:   *buyReq,
					AssetRate: hugeRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				oracleRate := rfqmsg.NewAssetRate(
					rfqmath.NewBigIntFixedPoint(
						1_000_000_000_000, 0,
					),
					validExpiryFuture,
				)
				expectQueryBuyPrice(
					p, &OracleResponse{
						AssetRate: oracleRate,
					}, nil,
				)
			},
			expectStatus: MinFillNotMetQuoteRespStatus,
			expectErr:    false,
		},
		{
			name: "buy accept: min fill transportable",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				// Rate of 100 units/BTC, min of 50
				// units = 0.5 BTC = 500M msat. Easily
				// transportable.
				buyReq, err := rfqmsg.NewBuyRequest(
					peerID, assetSpec, 100,
					fn.Some[uint64](50),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.None[rfqmsg.ExecutionPolicy](),
				)
				require.NoError(t, err)

				return &rfqmsg.BuyAccept{
					Peer:      peerID,
					Request:   *buyReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				expectQueryBuyPrice(
					p, &OracleResponse{
						AssetRate: oracleRateMatch,
					}, nil,
				)
			},
			expectStatus: ValidAcceptQuoteRespStatus,
			expectErr:    false,
		},

		// --- FOK enforcement cases ---

		{
			name: "buy accept: FOK viable",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				buyReq, err := rfqmsg.NewBuyRequest(
					peerID, assetSpec, 100,
					fn.None[uint64](),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.Some(
						rfqmsg.ExecutionPolicyFOK,
					),
				)
				require.NoError(t, err)

				return &rfqmsg.BuyAccept{
					Peer:      peerID,
					Request:   *buyReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				expectQueryBuyPrice(
					p, &OracleResponse{
						AssetRate: oracleRateMatch,
					}, nil,
				)
			},
			expectStatus: ValidAcceptQuoteRespStatus,
			expectErr:    false,
		},
		{
			name: "buy accept: FOK not viable",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				// Rate is huge: 1 unit converts
				// to ~0 msat.
				hugeRate := rfqmsg.NewAssetRate(
					rfqmath.NewBigIntFixedPoint(
						1_000_000_000_000, 0,
					),
					validExpiryFuture,
				)
				buyReq, err := rfqmsg.NewBuyRequest(
					peerID, assetSpec, 1,
					fn.None[uint64](),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.Some(
						rfqmsg.ExecutionPolicyFOK,
					),
				)
				require.NoError(t, err)

				return &rfqmsg.BuyAccept{
					Peer:      peerID,
					Request:   *buyReq,
					AssetRate: hugeRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				oracleRate := rfqmsg.NewAssetRate(
					rfqmath.NewBigIntFixedPoint(
						1_000_000_000_000, 0,
					),
					validExpiryFuture,
				)
				expectQueryBuyPrice(
					p, &OracleResponse{
						AssetRate: oracleRate,
					}, nil,
				)
			},
			expectStatus: FOKNotViableQuoteRespStatus,
			expectErr:    false,
		},
		{
			name: "sell accept: FOK viable",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				// 50B msat at 100 units/BTC =
				// 5 units (non-zero).
				sellReq, err := rfqmsg.NewSellRequest(
					peerID, assetSpec,
					lnwire.MilliSatoshi(50_000_000_000),
					fn.None[lnwire.MilliSatoshi](),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.Some(
						rfqmsg.ExecutionPolicyFOK,
					),
				)
				require.NoError(t, err)

				return &rfqmsg.SellAccept{
					Peer:      peerID,
					Request:   *sellReq,
					AssetRate: peerRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				resp := OracleResponse{
					AssetRate: oracleRateMatch,
				}
				expectQuerySellPrice(p, &resp, nil)
			},
			expectStatus: ValidAcceptQuoteRespStatus,
			expectErr:    false,
		},
		{
			name: "sell accept: FOK not viable",
			makeAccept: func(t *testing.T) rfqmsg.Accept {
				// Low rate (1 unit/BTC): 1 msat
				// converts to 0 units.
				lowRate := rfqmsg.NewAssetRate(
					rfqmath.NewBigIntFixedPoint(
						1, 0,
					),
					validExpiryFuture,
				)
				sellReq, err := rfqmsg.NewSellRequest(
					peerID, assetSpec,
					lnwire.MilliSatoshi(1),
					fn.None[lnwire.MilliSatoshi](),
					fn.None[rfqmath.BigIntFixedPoint](),
					fn.None[rfqmsg.AssetRate](),
					"metadata",
					fn.Some(
						rfqmsg.ExecutionPolicyFOK,
					),
				)
				require.NoError(t, err)

				return &rfqmsg.SellAccept{
					Peer:      peerID,
					Request:   *sellReq,
					AssetRate: lowRate,
				}
			},
			setupOracle: func(p *MockPriceOracle) {
				oracleRate := rfqmsg.NewAssetRate(
					rfqmath.NewBigIntFixedPoint(
						1, 0,
					),
					validExpiryFuture,
				)
				resp := OracleResponse{
					AssetRate: oracleRate,
				}
				expectQuerySellPrice(p, &resp, nil)
			},
			expectStatus: FOKNotViableQuoteRespStatus,
			expectErr:    false,
		},
	}

	for _, tc := range tests {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			accept := tc.makeAccept(t)
			oracle := &MockPriceOracle{}
			tc.setupOracle(oracle)

			cfg := InternalPortfolioPilotConfig{
				PriceOracle:                 oracle,
				ForwardPeerIDToOracle:       false,
				AcceptPriceDeviationPpm:     50_000, // 5%
				MinAssetRatesExpiryLifetime: 10,
			}
			pilot, err := NewInternalPortfolioPilot(cfg)
			require.NoError(t, err)

			ctx := context.Background()
			status, err := pilot.VerifyAcceptQuote(ctx, accept)

			// Verify the status matches expectations.
			require.Equal(t, tc.expectStatus, status)

			// Check error expectations.
			if tc.expectErr {
				// Unexpected error case: err should be non-nil.
				require.Error(t, err)
				require.Contains(
					t, err.Error(), tc.expectErrSubstring,
				)
			} else {
				// Expected validation failure or success:
				// err should be nil.
				require.NoError(t, err)
			}

			oracle.AssertExpectations(t)
		})
	}
}

// TestResolveRequestWithoutPriceOracleRejects ensures that requests are
// rejected during resolution if a price oracle is not configured for the
// internal portfolio pilot.
func TestResolveRequestWithoutPriceOracleRejects(t *testing.T) {
	t.Parallel()

	assetSpec := asset.NewSpecifierFromId(asset.ID{0x01, 0x02, 0x03})
	peerID := route.Vertex{0x0A, 0x0B, 0x0C}

	req, err := rfqmsg.NewBuyRequest(
		peerID, assetSpec, 100,
		fn.None[uint64](),
		fn.None[rfqmath.BigIntFixedPoint](),
		fn.None[rfqmsg.AssetRate](),
		"metadata",
		fn.None[rfqmsg.ExecutionPolicy](),
	)
	require.NoError(t, err)

	cfg := InternalPortfolioPilotConfig{
		PriceOracle:                 nil,
		ForwardPeerIDToOracle:       false,
		AcceptPriceDeviationPpm:     50_000,
		MinAssetRatesExpiryLifetime: 10,
	}
	pilot, err := NewInternalPortfolioPilot(cfg)
	require.NoError(t, err)

	resp, err := pilot.ResolveRequest(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.IsReject())
	require.False(t, resp.IsAccept())

	called := false
	resp.WhenReject(func(rejectErr rfqmsg.RejectErr) {
		called = true
		require.Equal(t, rfqmsg.ErrPriceOracleUnavailable, rejectErr)
	})
	require.True(t, called)
}

// TestVerifyAcceptQuoteWithoutPriceOracle ensures that quote accept messages
// fail verification if a price oracle is not configured for the internal
// portfolio pilot.
func TestVerifyAcceptQuoteWithoutPriceOracle(t *testing.T) {
	t.Parallel()

	assetSpec := asset.NewSpecifierFromId(asset.ID{0x01, 0x02, 0x03})
	peerID := route.Vertex{0x0A, 0x0B, 0x0C}
	expiry := time.Now().Add(30 * time.Second)

	buyReq, err := rfqmsg.NewBuyRequest(
		peerID, assetSpec, 100,
		fn.None[uint64](),
		fn.None[rfqmath.BigIntFixedPoint](),
		fn.None[rfqmsg.AssetRate](),
		"metadata",
		fn.None[rfqmsg.ExecutionPolicy](),
	)
	require.NoError(t, err)

	accept := &rfqmsg.BuyAccept{
		Peer:    peerID,
		Request: *buyReq,
		AssetRate: rfqmsg.NewAssetRate(
			rfqmath.NewBigIntFixedPoint(100, 0), expiry,
		),
	}

	cfg := InternalPortfolioPilotConfig{
		PriceOracle:                 nil,
		ForwardPeerIDToOracle:       false,
		AcceptPriceDeviationPpm:     50_000,
		MinAssetRatesExpiryLifetime: 10,
	}
	pilot, err := NewInternalPortfolioPilot(cfg)
	require.NoError(t, err)

	status, err := pilot.VerifyAcceptQuote(context.Background(), accept)
	require.NoError(t, err)
	require.Equal(t, PriceOracleQueryErrQuoteRespStatus, status)
}

// TestCheckRateBound exercises the checkRateBound helper directly.
func TestCheckRateBound(t *testing.T) {
	t.Parallel()

	spec := asset.NewSpecifierFromId(asset.ID{0x01})
	rate100 := rfqmath.NewBigIntFixedPoint(100, 0)
	rate50 := rfqmath.NewBigIntFixedPoint(50, 0)
	rate150 := rfqmath.NewBigIntFixedPoint(150, 0)
	noLimit := fn.None[rfqmath.BigIntFixedPoint]()

	tests := []struct {
		name   string
		req    rfqmsg.Request
		rate   rfqmath.BigIntFixedPoint
		expect QuoteRespStatus
	}{
		{
			name: "buy: no limit set",
			req: &rfqmsg.BuyRequest{
				AssetSpecifier: spec,
				AssetMaxAmt:    100,
				AssetRateLimit: noLimit,
			},
			rate:   rate100,
			expect: ValidAcceptQuoteRespStatus,
		},
		{
			name: "buy: rate above limit",
			req: &rfqmsg.BuyRequest{
				AssetSpecifier: spec,
				AssetMaxAmt:    100,
				AssetRateLimit: fn.Some(rate50),
			},
			rate:   rate100,
			expect: ValidAcceptQuoteRespStatus,
		},
		{
			name: "buy: rate at limit",
			req: &rfqmsg.BuyRequest{
				AssetSpecifier: spec,
				AssetMaxAmt:    100,
				AssetRateLimit: fn.Some(rate100),
			},
			rate:   rate100,
			expect: ValidAcceptQuoteRespStatus,
		},
		{
			name: "buy: rate below limit",
			req: &rfqmsg.BuyRequest{
				AssetSpecifier: spec,
				AssetMaxAmt:    100,
				AssetRateLimit: fn.Some(rate150),
			},
			rate:   rate100,
			expect: RateBoundMissQuoteRespStatus,
		},
		{
			name: "sell: no limit set",
			req: &rfqmsg.SellRequest{
				AssetSpecifier: spec,
				PaymentMaxAmt:  1000,
				AssetRateLimit: noLimit,
			},
			rate:   rate100,
			expect: ValidAcceptQuoteRespStatus,
		},
		{
			name: "sell: rate below limit",
			req: &rfqmsg.SellRequest{
				AssetSpecifier: spec,
				PaymentMaxAmt:  1000,
				AssetRateLimit: fn.Some(rate150),
			},
			rate:   rate100,
			expect: ValidAcceptQuoteRespStatus,
		},
		{
			name: "sell: rate at limit",
			req: &rfqmsg.SellRequest{
				AssetSpecifier: spec,
				PaymentMaxAmt:  1000,
				AssetRateLimit: fn.Some(rate100),
			},
			rate:   rate100,
			expect: ValidAcceptQuoteRespStatus,
		},
		{
			name: "sell: rate above limit",
			req: &rfqmsg.SellRequest{
				AssetSpecifier: spec,
				PaymentMaxAmt:  1000,
				AssetRateLimit: fn.Some(rate50),
			},
			rate:   rate100,
			expect: RateBoundMissQuoteRespStatus,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			status := checkRateBound(tc.req, tc.rate)
			require.Equal(t, tc.expect, status)
		})
	}
}

// TestCheckMinFill exercises the checkMinFill helper directly.
func TestCheckMinFill(t *testing.T) {
	t.Parallel()

	spec := asset.NewSpecifierFromId(asset.ID{0x01})

	// A rate of 100 units/BTC. 50 units = 0.5 BTC =
	// 50_000_000_000 msat (easily non-zero).
	normalRate := rfqmath.NewBigIntFixedPoint(100, 0)

	// A huge rate: 1e12 units/BTC. 1 unit = 1e-12 BTC =
	// 0.1 msat, rounds to 0.
	hugeRate := rfqmath.NewBigIntFixedPoint(
		1_000_000_000_000, 0,
	)

	tests := []struct {
		name   string
		req    rfqmsg.Request
		rate   rfqmath.BigIntFixedPoint
		expect QuoteRespStatus
	}{
		{
			name: "buy: no min set",
			req: &rfqmsg.BuyRequest{
				AssetSpecifier: spec,
				AssetMaxAmt:    100,
				AssetMinAmt:    fn.None[uint64](),
			},
			rate:   normalRate,
			expect: ValidAcceptQuoteRespStatus,
		},
		{
			name: "buy: min fill transportable",
			req: &rfqmsg.BuyRequest{
				AssetSpecifier: spec,
				AssetMaxAmt:    100,
				AssetMinAmt:    fn.Some[uint64](50),
			},
			rate:   normalRate,
			expect: ValidAcceptQuoteRespStatus,
		},
		{
			name: "buy: min fill rounds to zero",
			req: &rfqmsg.BuyRequest{
				AssetSpecifier: spec,
				AssetMaxAmt:    100,
				AssetMinAmt:    fn.Some[uint64](1),
			},
			rate:   hugeRate,
			expect: MinFillNotMetQuoteRespStatus,
		},
		{
			name: "sell: no min set",
			req: &rfqmsg.SellRequest{
				AssetSpecifier: spec,
				PaymentMaxAmt:  1000,
				PaymentMinAmt:  fn.None[lnwire.MilliSatoshi](),
			},
			rate:   normalRate,
			expect: ValidAcceptQuoteRespStatus,
		},
		{
			name: "sell: min fill transportable",
			req: &rfqmsg.SellRequest{
				AssetSpecifier: spec,
				PaymentMaxAmt: lnwire.MilliSatoshi(
					50_000_000_000,
				),
				PaymentMinAmt: fn.Some(
					lnwire.MilliSatoshi(
						10_000_000_000,
					),
				),
			},
			rate:   normalRate,
			expect: ValidAcceptQuoteRespStatus,
		},
		// NOTE: A sell min fill that rounds to zero units is
		// very hard to trigger with the default arithmetic
		// scale (11), since MilliSatoshiToUnits preserves
		// enough precision for any non-zero msat. The
		// check acts as a safety net for degenerate inputs.
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			status := checkMinFill(tc.req, tc.rate)
			require.Equal(t, tc.expect, status)
		})
	}
}

// TestCheckFOK exercises the checkFOK helper directly.
func TestCheckFOK(t *testing.T) {
	t.Parallel()

	spec := asset.NewSpecifierFromId(asset.ID{0x01})

	// Normal rate: 100 units/BTC.
	normalRate := rfqmath.NewBigIntFixedPoint(100, 0)

	// Huge rate: 1e12 units/BTC. Max of 1 unit converts
	// to ~0 msat.
	hugeRate := rfqmath.NewBigIntFixedPoint(
		1_000_000_000_000, 0,
	)

	tests := []struct {
		name   string
		req    rfqmsg.Request
		rate   rfqmath.BigIntFixedPoint
		expect QuoteRespStatus
	}{
		{
			name: "buy: no policy",
			req: &rfqmsg.BuyRequest{
				AssetSpecifier: spec,
				AssetMaxAmt:    100,
			},
			rate:   normalRate,
			expect: ValidAcceptQuoteRespStatus,
		},
		{
			name: "buy: IOC policy",
			req: &rfqmsg.BuyRequest{
				AssetSpecifier: spec,
				AssetMaxAmt:    100,
				ExecutionPolicy: fn.Some(
					rfqmsg.ExecutionPolicyIOC,
				),
			},
			rate:   normalRate,
			expect: ValidAcceptQuoteRespStatus,
		},
		{
			name: "buy: FOK viable",
			req: &rfqmsg.BuyRequest{
				AssetSpecifier: spec,
				AssetMaxAmt:    100,
				ExecutionPolicy: fn.Some(
					rfqmsg.ExecutionPolicyFOK,
				),
			},
			rate:   normalRate,
			expect: ValidAcceptQuoteRespStatus,
		},
		{
			name: "buy: FOK rounds to zero",
			req: &rfqmsg.BuyRequest{
				AssetSpecifier: spec,
				AssetMaxAmt:    1,
				ExecutionPolicy: fn.Some(
					rfqmsg.ExecutionPolicyFOK,
				),
			},
			rate:   hugeRate,
			expect: FOKNotViableQuoteRespStatus,
		},
		{
			name: "sell: no policy",
			req: &rfqmsg.SellRequest{
				AssetSpecifier: spec,
				PaymentMaxAmt:  1000,
			},
			rate:   normalRate,
			expect: ValidAcceptQuoteRespStatus,
		},
		{
			name: "sell: FOK viable",
			req: &rfqmsg.SellRequest{
				AssetSpecifier: spec,
				PaymentMaxAmt: lnwire.MilliSatoshi(
					50_000_000_000,
				),
				ExecutionPolicy: fn.Some(
					rfqmsg.ExecutionPolicyFOK,
				),
			},
			rate:   normalRate,
			expect: ValidAcceptQuoteRespStatus,
		},
		{
			name: "sell: FOK rounds to zero",
			req: &rfqmsg.SellRequest{
				AssetSpecifier: spec,
				PaymentMaxAmt:  lnwire.MilliSatoshi(1),
				ExecutionPolicy: fn.Some(
					rfqmsg.ExecutionPolicyFOK,
				),
			},
			// 1 unit/BTC: 1 msat = 1e-11 BTC * 1 = 0 units.
			rate:   rfqmath.NewBigIntFixedPoint(1, 0),
			expect: FOKNotViableQuoteRespStatus,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			status := checkFOK(tc.req, tc.rate)
			require.Equal(t, tc.expect, status)
		})
	}
}
