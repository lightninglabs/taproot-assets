package rpcutils

import (
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/taprpc/portfoliopilotrpc"
)

// MarshalPortfolioFixedPoint converts a BigIntFixedPoint to a portfolio pilot
// FixedPoint.
func MarshalPortfolioFixedPoint(
	fp rfqmath.BigIntFixedPoint) *portfoliopilotrpc.FixedPoint {

	return &portfoliopilotrpc.FixedPoint{
		Coefficient: fp.Coefficient.String(),
		Scale:       uint32(fp.Scale),
	}
}

// UnmarshalPortfolioFixedPoint converts a portfolio pilot FixedPoint to a
// BigIntFixedPoint.
func UnmarshalPortfolioFixedPoint(
	fp *portfoliopilotrpc.FixedPoint) (*rfqmath.BigIntFixedPoint, error) {

	if fp == nil {
		return nil, fmt.Errorf("fixed point is nil")
	}

	// Return an error is the scale component of the fixed point is greater
	// than the max value of uint8.
	if fp.Scale > 255 {
		return nil, fmt.Errorf("scale value overflow: %v", fp.Scale)
	}
	scale := uint8(fp.Scale)

	cBigInt := new(big.Int)
	if _, ok := cBigInt.SetString(fp.Coefficient, 10); !ok {
		return nil, fmt.Errorf("invalid fixed point coefficient")
	}

	return &rfqmath.BigIntFixedPoint{
		Coefficient: rfqmath.NewBigInt(cBigInt),
		Scale:       scale,
	}, nil
}

// MarshalPortfolioAssetRate converts an AssetRate to a portfolio pilot RPC
// AssetRate.
func MarshalPortfolioAssetRate(
	assetRate rfqmsg.AssetRate) (*portfoliopilotrpc.AssetRate, error) {

	expiry := assetRate.Expiry.Unix()
	if expiry < 0 {
		return nil, fmt.Errorf("asset rate expiry before unix epoch")
	}

	return &portfoliopilotrpc.AssetRate{
		Rate:            MarshalPortfolioFixedPoint(assetRate.Rate),
		ExpiryTimestamp: uint64(expiry),
	}, nil
}

// UnmarshalPortfolioAssetRate converts a portfolio pilot RPC AssetRate to an
// AssetRate.
func UnmarshalPortfolioAssetRate(
	assetRate *portfoliopilotrpc.AssetRate) (*rfqmsg.AssetRate, error) {

	if assetRate == nil {
		return nil, fmt.Errorf("asset rate is nil")
	}

	if assetRate.Rate == nil {
		return nil, fmt.Errorf("asset rate fixed point is nil")
	}

	if assetRate.ExpiryTimestamp > math.MaxInt64 {
		return nil, fmt.Errorf("expiry timestamp exceeds int64 max")
	}

	rate, err := UnmarshalPortfolioFixedPoint(assetRate.Rate)
	if err != nil {
		return nil, fmt.Errorf("unmarshal fixed point: %w", err)
	}

	expiry := time.Unix(int64(assetRate.ExpiryTimestamp), 0).UTC()
	assetRateMsg := rfqmsg.NewAssetRate(*rate, expiry)

	return &assetRateMsg, nil
}

// UnmarshalPortfolioBuyConstraints returns the limit-order constraints
// of a portfolio pilot buy request. Amounts are in asset units and the
// rate limit is a floor (RateBoundCmp -1). A zero asset_min_amount is
// an unset minimum, and EXECUTION_POLICY_IOC is an unset execution
// policy.
func UnmarshalPortfolioBuyConstraints(
	req *portfoliopilotrpc.BuyRequest) (rfqmsg.RequestConstraints,
	error) {

	if req == nil {
		return rfqmsg.RequestConstraints{},
			fmt.Errorf("buy request is nil")
	}

	return unmarshalPortfolioConstraints(
		req.AssetMaxAmount, req.AssetMinAmount, req.AssetRateLimit,
		-1, req.ExecutionPolicy,
	)
}

// UnmarshalPortfolioSellConstraints returns the limit-order constraints
// of a portfolio pilot sell request. Amounts are in msat and the rate
// limit is a ceiling (RateBoundCmp +1). A zero payment_min_amount is an
// unset minimum, and EXECUTION_POLICY_IOC is an unset execution policy.
func UnmarshalPortfolioSellConstraints(
	req *portfoliopilotrpc.SellRequest) (rfqmsg.RequestConstraints,
	error) {

	if req == nil {
		return rfqmsg.RequestConstraints{},
			fmt.Errorf("sell request is nil")
	}

	return unmarshalPortfolioConstraints(
		req.PaymentMaxAmount, req.PaymentMinAmount,
		req.AssetRateLimit, 1, req.ExecutionPolicy,
	)
}

// unmarshalPortfolioConstraints builds request constraints from the
// limit-order fields of a portfolio pilot request.
func unmarshalPortfolioConstraints(maxAmt, minAmt uint64,
	rateLimit *portfoliopilotrpc.FixedPoint, rateBoundCmp int,
	policy portfoliopilotrpc.ExecutionPolicy) (rfqmsg.RequestConstraints,
	error) {

	var zero rfqmsg.RequestConstraints

	c := rfqmsg.RequestConstraints{
		MaxAmount:    maxAmt,
		RateBoundCmp: rateBoundCmp,
	}

	if minAmt != 0 {
		c.MinAmount = fn.Some(minAmt)
	}

	if rateLimit != nil {
		limit, err := UnmarshalPortfolioFixedPoint(rateLimit)
		if err != nil {
			return zero, fmt.Errorf("unmarshal rate limit: %w",
				err)
		}

		c.RateLimit = fn.Some(*limit)
	}

	switch policy {
	case portfoliopilotrpc.ExecutionPolicy_EXECUTION_POLICY_IOC:
		// IOC maps to an unset execution policy.

	case portfoliopilotrpc.ExecutionPolicy_EXECUTION_POLICY_FOK:
		c.ExecutionPolicy = fn.Some(rfqmsg.ExecutionPolicyFOK)

	default:
		return zero, fmt.Errorf("unknown execution policy: %v",
			policy)
	}

	return c, nil
}
