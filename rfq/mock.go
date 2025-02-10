package rfq

import (
	"context"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnwire"
)

// MockPriceOracle is a mock implementation of the PriceOracle interface.
// It returns the suggested rate as the exchange rate.
type MockPriceOracle struct {
	// expiryDelay is the lifetime of a quote in seconds.
	expiryDelay    uint64
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
		expiryDelay: expiryDelay,

		// TODO(ffranr): This is incorrect, we should convert
		//  satoshis per asset to assets per BTC.
		assetToBtcRate: rfqmath.NewBigIntFixedPoint(
			satsPerAsset, 0,
		),
	}
}

// QueryAskPrice returns the ask price for the given asset amount.
func (m *MockPriceOracle) QueryAskPrice(_ context.Context,
	_ asset.Specifier, _ fn.Option[uint64],
	_ fn.Option[lnwire.MilliSatoshi],
	_ fn.Option[rfqmsg.AssetRate]) (*OracleResponse, error) {

	// Calculate the rate expiry timestamp.
	lifetime := time.Duration(m.expiryDelay) * time.Second
	expiry := time.Now().Add(lifetime).UTC()

	return &OracleResponse{
		AssetRate: rfqmsg.NewAssetRate(m.assetToBtcRate, expiry),
	}, nil
}

// QueryBidPrice returns a bid price for the given asset amount.
func (m *MockPriceOracle) QueryBidPrice(_ context.Context, _ asset.Specifier,
	_ fn.Option[uint64], _ fn.Option[lnwire.MilliSatoshi],
	_ fn.Option[rfqmsg.AssetRate]) (*OracleResponse, error) {

	// Calculate the rate expiry timestamp.
	lifetime := time.Duration(m.expiryDelay) * time.Second
	expiry := time.Now().Add(lifetime).UTC()

	return &OracleResponse{
		AssetRate: rfqmsg.NewAssetRate(m.assetToBtcRate, expiry),
	}, nil
}

// Ensure that MockPriceOracle implements the PriceOracle interface.
var _ PriceOracle = (*MockPriceOracle)(nil)
