package rfqmsg

import (
	"bytes"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

// sellRequestRoundtrip encodes a SellRequest to wire and decodes it
// back, returning the decoded request.
func sellRequestRoundtrip(t *testing.T,
	req *SellRequest) *SellRequest {

	t.Helper()

	wireMsg, err := req.ToWire()
	require.NoError(t, err)

	var msgData requestWireMsgData
	err = msgData.Decode(bytes.NewReader(wireMsg.Data))
	require.NoError(t, err)

	decoded, err := NewSellRequestFromWire(wireMsg, msgData)
	require.NoError(t, err)

	return decoded
}

// TestSellRequestMinAmtRoundtrip verifies that PaymentMinAmt survives
// a wire roundtrip.
func TestSellRequestMinAmtRoundtrip(t *testing.T) {
	t.Parallel()

	peer := route.Vertex{0x01}
	spec := asset.NewSpecifierFromId(asset.ID{0xAA})

	req, err := NewSellRequest(
		peer, spec, lnwire.MilliSatoshi(5000),
		fn.Some(lnwire.MilliSatoshi(1000)),
		fn.None[rfqmath.BigIntFixedPoint](),
		fn.None[AssetRate](), "",
		fn.None[ExecutionPolicy](),
	)
	require.NoError(t, err)

	decoded := sellRequestRoundtrip(t, req)

	require.True(t, decoded.PaymentMinAmt.IsSome())
	decoded.PaymentMinAmt.WhenSome(func(v lnwire.MilliSatoshi) {
		require.Equal(t, lnwire.MilliSatoshi(1000), v)
	})
	require.Equal(
		t, lnwire.MilliSatoshi(5000), decoded.PaymentMaxAmt,
	)
}

// TestSellRequestRateLimitRoundtrip verifies that AssetRateLimit
// survives a wire roundtrip.
func TestSellRequestRateLimitRoundtrip(t *testing.T) {
	t.Parallel()

	peer := route.Vertex{0x02}
	spec := asset.NewSpecifierFromId(asset.ID{0xBB})
	limit := rfqmath.NewBigIntFixedPoint(75000, 2)

	req, err := NewSellRequest(
		peer, spec, lnwire.MilliSatoshi(10000),
		fn.None[lnwire.MilliSatoshi](),
		fn.Some(limit), fn.None[AssetRate](), "",
		fn.None[ExecutionPolicy](),
	)
	require.NoError(t, err)

	decoded := sellRequestRoundtrip(t, req)

	require.True(t, decoded.AssetRateLimit.IsSome())
	decoded.AssetRateLimit.WhenSome(
		func(v rfqmath.BigIntFixedPoint) {
			require.Equal(t, 0, v.Cmp(limit))
		},
	)
}

// TestSellRequestNoOptionalFieldsRoundtrip verifies backward
// compatibility when no optional fields are set.
func TestSellRequestNoOptionalFieldsRoundtrip(t *testing.T) {
	t.Parallel()

	peer := route.Vertex{0x03}
	spec := asset.NewSpecifierFromId(asset.ID{0xCC})

	req, err := NewSellRequest(
		peer, spec, lnwire.MilliSatoshi(3000),
		fn.None[lnwire.MilliSatoshi](),
		fn.None[rfqmath.BigIntFixedPoint](),
		fn.None[AssetRate](), "",
		fn.None[ExecutionPolicy](),
	)
	require.NoError(t, err)

	decoded := sellRequestRoundtrip(t, req)

	require.True(t, decoded.PaymentMinAmt.IsNone())
	require.True(t, decoded.AssetRateLimit.IsNone())
	require.Equal(
		t, lnwire.MilliSatoshi(3000), decoded.PaymentMaxAmt,
	)
}

// TestSellRequestAllFieldsRoundtrip verifies that all optional fields
// survive a roundtrip together.
func TestSellRequestAllFieldsRoundtrip(t *testing.T) {
	t.Parallel()

	peer := route.Vertex{0x04}
	spec := asset.NewSpecifierFromId(asset.ID{0xDD})
	limit := rfqmath.NewBigIntFixedPoint(88000, 3)
	expiry := time.Now().Add(5 * time.Minute).UTC()
	rateHint := NewAssetRate(
		rfqmath.NewBigIntFixedPoint(100000, 0), expiry,
	)

	req, err := NewSellRequest(
		peer, spec, lnwire.MilliSatoshi(9000),
		fn.Some(lnwire.MilliSatoshi(2000)),
		fn.Some(limit), fn.Some(rateHint), "sell-meta",
		fn.None[ExecutionPolicy](),
	)
	require.NoError(t, err)

	decoded := sellRequestRoundtrip(t, req)

	require.True(t, decoded.PaymentMinAmt.IsSome())
	decoded.PaymentMinAmt.WhenSome(func(v lnwire.MilliSatoshi) {
		require.Equal(t, lnwire.MilliSatoshi(2000), v)
	})

	require.True(t, decoded.AssetRateLimit.IsSome())
	decoded.AssetRateLimit.WhenSome(
		func(v rfqmath.BigIntFixedPoint) {
			require.Equal(t, 0, v.Cmp(limit))
		},
	)

	require.True(t, decoded.AssetRateHint.IsSome())
	require.Equal(t, "sell-meta", decoded.PriceOracleMetadata)
}

// TestSellRequestValidateMinGtMax ensures Validate rejects min > max.
func TestSellRequestValidateMinGtMax(t *testing.T) {
	t.Parallel()

	req := &SellRequest{
		Version:        V1,
		AssetSpecifier: asset.NewSpecifierFromId(asset.ID{1}),
		PaymentMaxAmt:  lnwire.MilliSatoshi(100),
		PaymentMinAmt: fn.Some(
			lnwire.MilliSatoshi(200),
		),
		AssetRateLimit: fn.None[rfqmath.BigIntFixedPoint](),
		AssetRateHint:  fn.None[AssetRate](),
	}

	err := req.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds max amount")
}

// TestSellRequestValidateMinEqMax ensures min == max is valid.
func TestSellRequestValidateMinEqMax(t *testing.T) {
	t.Parallel()

	req := &SellRequest{
		Version:        V1,
		AssetSpecifier: asset.NewSpecifierFromId(asset.ID{1}),
		PaymentMaxAmt:  lnwire.MilliSatoshi(500),
		PaymentMinAmt: fn.Some(
			lnwire.MilliSatoshi(500),
		),
		AssetRateLimit: fn.None[rfqmath.BigIntFixedPoint](),
		AssetRateHint:  fn.None[AssetRate](),
	}

	err := req.Validate()
	require.NoError(t, err)
}

// TestSellRequestValidateZeroRateLimit ensures a zero rate limit
// coefficient is rejected.
func TestSellRequestValidateZeroRateLimit(t *testing.T) {
	t.Parallel()

	zeroLimit := rfqmath.NewBigIntFixedPoint(0, 0)
	req := &SellRequest{
		Version:        V1,
		AssetSpecifier: asset.NewSpecifierFromId(asset.ID{1}),
		PaymentMaxAmt:  lnwire.MilliSatoshi(1000),
		PaymentMinAmt:  fn.None[lnwire.MilliSatoshi](),
		AssetRateLimit: fn.Some(zeroLimit),
		AssetRateHint:  fn.None[AssetRate](),
	}

	err := req.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be positive")
}

// TestSellRequestExecutionPolicyRoundtrip verifies that a FOK
// execution policy survives a wire roundtrip.
func TestSellRequestExecutionPolicyRoundtrip(t *testing.T) {
	t.Parallel()

	peer := route.Vertex{0x05}
	spec := asset.NewSpecifierFromId(asset.ID{0xEE})

	req, err := NewSellRequest(
		peer, spec, lnwire.MilliSatoshi(7000),
		fn.None[lnwire.MilliSatoshi](),
		fn.None[rfqmath.BigIntFixedPoint](),
		fn.None[AssetRate](), "",
		fn.Some(ExecutionPolicyFOK),
	)
	require.NoError(t, err)

	decoded := sellRequestRoundtrip(t, req)

	require.True(t, decoded.ExecutionPolicy.IsSome())
	decoded.ExecutionPolicy.WhenSome(
		func(v ExecutionPolicy) {
			require.Equal(t, ExecutionPolicyFOK, v)
		},
	)
}

// TestSellRequestNoExecutionPolicyRoundtrip verifies that an
// absent execution policy stays None after a wire roundtrip.
func TestSellRequestNoExecutionPolicyRoundtrip(t *testing.T) {
	t.Parallel()

	peer := route.Vertex{0x06}
	spec := asset.NewSpecifierFromId(asset.ID{0xFF})

	req, err := NewSellRequest(
		peer, spec, lnwire.MilliSatoshi(8000),
		fn.None[lnwire.MilliSatoshi](),
		fn.None[rfqmath.BigIntFixedPoint](),
		fn.None[AssetRate](), "",
		fn.None[ExecutionPolicy](),
	)
	require.NoError(t, err)

	decoded := sellRequestRoundtrip(t, req)

	require.True(t, decoded.ExecutionPolicy.IsNone())
}

// TestSellRequestInvalidExecutionPolicy ensures Validate rejects
// an unknown execution policy value.
func TestSellRequestInvalidExecutionPolicy(t *testing.T) {
	t.Parallel()

	req := &SellRequest{
		Version:        V1,
		AssetSpecifier: asset.NewSpecifierFromId(asset.ID{1}),
		PaymentMaxAmt:  lnwire.MilliSatoshi(1000),
		PaymentMinAmt:  fn.None[lnwire.MilliSatoshi](),
		AssetRateLimit: fn.None[rfqmath.BigIntFixedPoint](),
		AssetRateHint:  fn.None[AssetRate](),
		ExecutionPolicy: fn.Some(
			ExecutionPolicy(2),
		),
	}

	err := req.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "execution policy")
}
