package rfqmsg

import (
	"bytes"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

// buyRequestRoundtrip encodes a BuyRequest to wire and decodes it
// back, returning the decoded request.
func buyRequestRoundtrip(t *testing.T,
	req *BuyRequest) *BuyRequest {

	t.Helper()

	wireMsg, err := req.ToWire()
	require.NoError(t, err)

	var msgData requestWireMsgData
	err = msgData.Decode(bytes.NewReader(wireMsg.Data))
	require.NoError(t, err)

	decoded, err := NewBuyRequestFromWire(wireMsg, msgData)
	require.NoError(t, err)

	return decoded
}

// TestBuyRequestMinAmtRoundtrip verifies that AssetMinAmt survives
// a wire roundtrip.
func TestBuyRequestMinAmtRoundtrip(t *testing.T) {
	t.Parallel()

	peer := route.Vertex{0x01}
	spec := asset.NewSpecifierFromId(asset.ID{0xAA})

	req, err := NewBuyRequest(
		peer, spec, 100, fn.Some[uint64](50),
		fn.None[rfqmath.BigIntFixedPoint](),
		fn.None[AssetRate](), "",
		fn.None[ExecutionPolicy](),
	)
	require.NoError(t, err)

	decoded := buyRequestRoundtrip(t, req)

	require.True(t, decoded.AssetMinAmt.IsSome())
	decoded.AssetMinAmt.WhenSome(func(v uint64) {
		require.Equal(t, uint64(50), v)
	})
	require.Equal(t, uint64(100), decoded.AssetMaxAmt)
}

// TestBuyRequestRateLimitRoundtrip verifies that AssetRateLimit
// survives a wire roundtrip.
func TestBuyRequestRateLimitRoundtrip(t *testing.T) {
	t.Parallel()

	peer := route.Vertex{0x02}
	spec := asset.NewSpecifierFromId(asset.ID{0xBB})
	limit := rfqmath.NewBigIntFixedPoint(42000, 2)

	req, err := NewBuyRequest(
		peer, spec, 200, fn.None[uint64](),
		fn.Some(limit), fn.None[AssetRate](), "",
		fn.None[ExecutionPolicy](),
	)
	require.NoError(t, err)

	decoded := buyRequestRoundtrip(t, req)

	require.True(t, decoded.AssetRateLimit.IsSome())
	decoded.AssetRateLimit.WhenSome(
		func(v rfqmath.BigIntFixedPoint) {
			require.Equal(t, 0, v.Cmp(limit))
		},
	)
}

// TestBuyRequestNoOptionalFieldsRoundtrip verifies backward
// compatibility when no optional fields are set.
func TestBuyRequestNoOptionalFieldsRoundtrip(t *testing.T) {
	t.Parallel()

	peer := route.Vertex{0x03}
	spec := asset.NewSpecifierFromId(asset.ID{0xCC})

	req, err := NewBuyRequest(
		peer, spec, 300, fn.None[uint64](),
		fn.None[rfqmath.BigIntFixedPoint](),
		fn.None[AssetRate](), "",
		fn.None[ExecutionPolicy](),
	)
	require.NoError(t, err)

	decoded := buyRequestRoundtrip(t, req)

	require.True(t, decoded.AssetMinAmt.IsNone())
	require.True(t, decoded.AssetRateLimit.IsNone())
	require.Equal(t, uint64(300), decoded.AssetMaxAmt)
}

// TestBuyRequestAllFieldsRoundtrip verifies that all optional fields
// survive a roundtrip together.
func TestBuyRequestAllFieldsRoundtrip(t *testing.T) {
	t.Parallel()

	peer := route.Vertex{0x04}
	spec := asset.NewSpecifierFromId(asset.ID{0xDD})
	limit := rfqmath.NewBigIntFixedPoint(99000, 3)
	expiry := time.Now().Add(5 * time.Minute).UTC()
	rateHint := NewAssetRate(
		rfqmath.NewBigIntFixedPoint(100000, 0), expiry,
	)

	req, err := NewBuyRequest(
		peer, spec, 500, fn.Some[uint64](10),
		fn.Some(limit), fn.Some(rateHint), "metadata",
		fn.None[ExecutionPolicy](),
	)
	require.NoError(t, err)

	decoded := buyRequestRoundtrip(t, req)

	require.True(t, decoded.AssetMinAmt.IsSome())
	decoded.AssetMinAmt.WhenSome(func(v uint64) {
		require.Equal(t, uint64(10), v)
	})

	require.True(t, decoded.AssetRateLimit.IsSome())
	decoded.AssetRateLimit.WhenSome(
		func(v rfqmath.BigIntFixedPoint) {
			require.Equal(t, 0, v.Cmp(limit))
		},
	)

	require.True(t, decoded.AssetRateHint.IsSome())
	require.Equal(t, "metadata", decoded.PriceOracleMetadata)
}

// TestBuyRequestValidateMinGtMax ensures Validate rejects min > max.
func TestBuyRequestValidateMinGtMax(t *testing.T) {
	t.Parallel()

	req := &BuyRequest{
		Version:        V1,
		AssetSpecifier: asset.NewSpecifierFromId(asset.ID{1}),
		AssetMaxAmt:    100,
		AssetMinAmt:    fn.Some[uint64](200),
		AssetRateLimit: fn.None[rfqmath.BigIntFixedPoint](),
		AssetRateHint:  fn.None[AssetRate](),
	}

	err := req.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds max amount")
}

// TestBuyRequestValidateMinEqMax ensures min == max is valid.
func TestBuyRequestValidateMinEqMax(t *testing.T) {
	t.Parallel()

	req := &BuyRequest{
		Version:        V1,
		AssetSpecifier: asset.NewSpecifierFromId(asset.ID{1}),
		AssetMaxAmt:    100,
		AssetMinAmt:    fn.Some[uint64](100),
		AssetRateLimit: fn.None[rfqmath.BigIntFixedPoint](),
		AssetRateHint:  fn.None[AssetRate](),
	}

	err := req.Validate()
	require.NoError(t, err)
}

// TestBuyRequestValidateZeroRateLimit ensures a zero rate limit
// coefficient is rejected.
func TestBuyRequestValidateZeroRateLimit(t *testing.T) {
	t.Parallel()

	zeroLimit := rfqmath.NewBigIntFixedPoint(0, 0)
	req := &BuyRequest{
		Version:        V1,
		AssetSpecifier: asset.NewSpecifierFromId(asset.ID{1}),
		AssetMaxAmt:    100,
		AssetMinAmt:    fn.None[uint64](),
		AssetRateLimit: fn.Some(zeroLimit),
		AssetRateHint:  fn.None[AssetRate](),
	}

	err := req.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be positive")
}

// TestBuyRequestExecutionPolicyRoundtrip verifies that a FOK
// execution policy survives a wire roundtrip.
func TestBuyRequestExecutionPolicyRoundtrip(t *testing.T) {
	t.Parallel()

	peer := route.Vertex{0x05}
	spec := asset.NewSpecifierFromId(asset.ID{0xEE})

	req, err := NewBuyRequest(
		peer, spec, 400, fn.None[uint64](),
		fn.None[rfqmath.BigIntFixedPoint](),
		fn.None[AssetRate](), "",
		fn.Some(ExecutionPolicyFOK),
	)
	require.NoError(t, err)

	decoded := buyRequestRoundtrip(t, req)

	require.True(t, decoded.ExecutionPolicy.IsSome())
	decoded.ExecutionPolicy.WhenSome(
		func(v ExecutionPolicy) {
			require.Equal(t, ExecutionPolicyFOK, v)
		},
	)
}

// TestBuyRequestNoExecutionPolicyRoundtrip verifies that an absent
// execution policy stays None after a wire roundtrip.
func TestBuyRequestNoExecutionPolicyRoundtrip(t *testing.T) {
	t.Parallel()

	peer := route.Vertex{0x06}
	spec := asset.NewSpecifierFromId(asset.ID{0xFF})

	req, err := NewBuyRequest(
		peer, spec, 500, fn.None[uint64](),
		fn.None[rfqmath.BigIntFixedPoint](),
		fn.None[AssetRate](), "",
		fn.None[ExecutionPolicy](),
	)
	require.NoError(t, err)

	decoded := buyRequestRoundtrip(t, req)

	require.True(t, decoded.ExecutionPolicy.IsNone())
}

// TestBuyRequestInvalidExecutionPolicy ensures Validate rejects
// an unknown execution policy value.
func TestBuyRequestInvalidExecutionPolicy(t *testing.T) {
	t.Parallel()

	req := &BuyRequest{
		Version:         V1,
		AssetSpecifier:  asset.NewSpecifierFromId(asset.ID{1}),
		AssetMaxAmt:     100,
		AssetMinAmt:     fn.None[uint64](),
		AssetRateLimit:  fn.None[rfqmath.BigIntFixedPoint](),
		AssetRateHint:   fn.None[AssetRate](),
		ExecutionPolicy: fn.Some(ExecutionPolicy(2)),
	}

	err := req.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "execution policy")
}
