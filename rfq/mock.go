package rfq

import (
	"context"
	"slices"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/mock"
)

// MockPriceOracle is a mock implementation of the PriceOracle interface.
// It returns the suggested rate as the exchange rate.
type MockPriceOracle struct {
	// Mock is the underlying mock object used to track method invocations
	// in tests.
	mock.Mock

	// expiryDelay is the lifetime of a quote in seconds.
	expiryDelay uint64

	// assetToBtcRate is the default asset to BTC exchange rate.
	assetToBtcRate rfqmath.BigIntFixedPoint
}

// NewMockPriceOracle creates a new mock price oracle.
func NewMockPriceOracle(expiryDelay,
	assetRateCoefficient uint64) *MockPriceOracle {

	return &MockPriceOracle{
		expiryDelay: expiryDelay,
		assetToBtcRate: rfqmath.NewBigIntFixedPoint(
			assetRateCoefficient, 0,
		),
	}
}

// NewMockPriceOracleSatPerAsset creates a new mock price oracle with a
// specified satoshis per asset rate.
func NewMockPriceOracleSatPerAsset(expiryDelay uint64,
	satsPerAsset uint64) *MockPriceOracle {

	return &MockPriceOracle{
		expiryDelay:    expiryDelay,
		assetToBtcRate: rfqmath.SatsPerAssetToAssetRate(satsPerAsset),
	}
}

// QueryAskPrice returns the ask price for the given asset amount.
func (m *MockPriceOracle) QueryAskPrice(ctx context.Context,
	assetSpecifier asset.Specifier,
	assetMaxAmt fn.Option[uint64],
	paymentMaxAmt fn.Option[lnwire.MilliSatoshi],
	assetRateHint fn.Option[rfqmsg.AssetRate]) (*OracleResponse, error) {

	// Return early with default value if no expected calls are predefined
	// for this method.
	if !hasExpectedCall(m.ExpectedCalls, "QueryAskPrice") {
		// Calculate the rate expiry timestamp.
		lifetime := time.Duration(m.expiryDelay) * time.Second
		expiry := time.Now().Add(lifetime).UTC()

		return &OracleResponse{
			AssetRate: rfqmsg.NewAssetRate(
				m.assetToBtcRate, expiry,
			),
		}, nil
	}

	// If an expected call exist, call normally.
	args := m.Called(
		ctx, assetSpecifier, assetMaxAmt, paymentMaxAmt, assetRateHint,
	)
	resp, _ := args.Get(0).(*OracleResponse)
	return resp, args.Error(1)
}

// QueryBidPrice returns a bid price for the given asset amount.
func (m *MockPriceOracle) QueryBidPrice(ctx context.Context,
	assetSpecifier asset.Specifier,
	assetMaxAmt fn.Option[uint64],
	paymentMaxAmt fn.Option[lnwire.MilliSatoshi],
	assetRateHint fn.Option[rfqmsg.AssetRate]) (*OracleResponse, error) {

	// Return early with default value if no expected calls are predefined
	// for this method.
	if !hasExpectedCall(m.ExpectedCalls, "QueryBidPrice") {
		// Calculate the rate expiry timestamp.
		lifetime := time.Duration(m.expiryDelay) * time.Second
		expiry := time.Now().Add(lifetime).UTC()

		return &OracleResponse{
			AssetRate: rfqmsg.NewAssetRate(
				m.assetToBtcRate, expiry,
			),
		}, nil
	}

	// If an expected call exist, call normally.
	args := m.Called(
		ctx, assetSpecifier, assetMaxAmt, paymentMaxAmt, assetRateHint,
	)
	resp, _ := args.Get(0).(*OracleResponse)
	return resp, args.Error(1)
}

// Ensure that MockPriceOracle implements the PriceOracle interface.
var _ PriceOracle = (*MockPriceOracle)(nil)

// hasExpectedCall checks if the method call has been registered as an expected
// call with the mock object.
func hasExpectedCall(expectedCalls []*mock.Call, method string) bool {
	return slices.ContainsFunc(expectedCalls, func(call *mock.Call) bool {
		return call.Method == method
	})
}
