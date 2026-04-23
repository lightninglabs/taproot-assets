package rfqmsg

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// optionalUint64Gen draws an fn.Option[uint64] that is None half the
// time and Some(v) otherwise, where v is drawn from [1, bound].
func optionalUint64Gen(bound uint64) *rapid.Generator[fn.Option[uint64]] {
	return rapid.Custom(func(t *rapid.T) fn.Option[uint64] {
		if rapid.Bool().Draw(t, "present") {
			// Start from 1: zero is treated as unset
			// on the wire.
			v := rapid.Uint64Range(1, bound).Draw(
				t, "value",
			)
			return fn.Some(v)
		}
		return fn.None[uint64]()
	})
}

// optionalMsatGen draws an fn.Option[lnwire.MilliSatoshi] that is
// None half the time and Some(v) otherwise, where v <= bound.
func optionalMsatGen(
	bound uint64) *rapid.Generator[fn.Option[lnwire.MilliSatoshi]] {

	return rapid.Custom(
		func(t *rapid.T) fn.Option[lnwire.MilliSatoshi] {
			if rapid.Bool().Draw(t, "present") {
				// Start from 1: zero is treated as
				// unset on the wire.
				v := rapid.Uint64Range(1, bound).Draw(
					t, "value",
				)
				return fn.Some(
					lnwire.MilliSatoshi(v),
				)
			}
			return fn.None[lnwire.MilliSatoshi]()
		},
	)
}

// fixedPointGen draws a BigIntFixedPoint with coefficient in [1,1e12]
// and scale in [0,11].
func fixedPointGen() *rapid.Generator[rfqmath.BigIntFixedPoint] {
	return rapid.Custom(
		func(t *rapid.T) rfqmath.BigIntFixedPoint {
			coeff := rapid.Uint64Range(1, 1_000_000_000_000).
				Draw(t, "coeff")
			scale := rapid.Uint8Range(0, 11).Draw(t, "scale")
			return rfqmath.NewBigIntFixedPoint(
				coeff, scale,
			)
		},
	)
}

// optionalFixedPointGen draws an optional BigIntFixedPoint, None half
// the time.
type optFP = fn.Option[rfqmath.BigIntFixedPoint]

func optionalFixedPointGen() *rapid.Generator[optFP] {
	return rapid.Custom(
		func(t *rapid.T) fn.Option[rfqmath.BigIntFixedPoint] {
			if rapid.Bool().Draw(t, "present") {
				return fn.Some(
					fixedPointGen().Draw(t, "fp"),
				)
			}
			return fn.None[rfqmath.BigIntFixedPoint]()
		},
	)
}

// optionalExecutionPolicyGen draws an
// fn.Option[ExecutionPolicy] that is None one-third of the time,
// IOC one-third, and FOK one-third.
func optionalExecutionPolicyGen() *rapid.Generator[fn.Option[ExecutionPolicy]] {
	return rapid.Custom(
		func(t *rapid.T) fn.Option[ExecutionPolicy] {
			v := rapid.IntRange(0, 2).Draw(
				t, "execPolicy",
			)
			switch v {
			case 0:
				return fn.None[ExecutionPolicy]()
			case 1:
				return fn.Some(ExecutionPolicyIOC)
			default:
				return fn.Some(ExecutionPolicyFOK)
			}
		},
	)
}

// assetIDGen draws a random 32-byte asset.ID.
func assetIDGen() *rapid.Generator[asset.ID] {
	return rapid.Custom(func(t *rapid.T) asset.ID {
		var id asset.ID
		for i := range id {
			id[i] = rapid.Byte().Draw(t, "byte")
		}
		return id
	})
}

// peerGen draws a random 33-byte route.Vertex.
func peerGen() *rapid.Generator[route.Vertex] {
	return rapid.Custom(func(t *rapid.T) route.Vertex {
		var v route.Vertex
		for i := range v {
			v[i] = rapid.Byte().Draw(t, "byte")
		}
		return v
	})
}

// TestBuyRequestWireRoundtripProperty checks that any valid
// BuyRequest survives a wire encode/decode roundtrip.
func TestBuyRequestWireRoundtripProperty(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		peer := peerGen().Draw(t, "peer")
		id := assetIDGen().Draw(t, "id")
		spec := asset.NewSpecifierFromId(id)

		maxAmt := rapid.Uint64Range(1, 1_000_000).Draw(
			t, "maxAmt",
		)
		minAmt := optionalUint64Gen(maxAmt).Draw(
			t, "minAmt",
		)
		rateLimit := optionalFixedPointGen().Draw(
			t, "rateLimit",
		)
		execPolicy := optionalExecutionPolicyGen().Draw(
			t, "execPolicy",
		)

		req, err := NewBuyRequest(
			peer, spec, maxAmt, minAmt,
			rateLimit, fn.None[AssetRate](), "",
			execPolicy,
		)
		require.NoError(t, err)

		wireMsg, err := req.ToWire()
		require.NoError(t, err)

		var msgData requestWireMsgData
		err = msgData.Decode(
			bytes.NewReader(wireMsg.Data),
		)
		require.NoError(t, err)

		decoded, err := NewBuyRequestFromWire(
			wireMsg, msgData,
		)
		require.NoError(t, err)

		// Max amount must be preserved.
		require.Equal(t, maxAmt, decoded.AssetMaxAmt)

		// Min amount must match.
		requireOptEq(t, minAmt, decoded.AssetMinAmt)

		// Rate limit must match via Cmp.
		requireOptFpEq(
			t, rateLimit, decoded.AssetRateLimit,
		)
		requireOptExecPolicyEq(
			t, execPolicy, decoded.ExecutionPolicy,
		)
	})
}

// TestSellRequestWireRoundtripProperty checks that any valid
// SellRequest survives a wire encode/decode roundtrip.
func TestSellRequestWireRoundtripProperty(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		peer := peerGen().Draw(t, "peer")
		id := assetIDGen().Draw(t, "id")
		spec := asset.NewSpecifierFromId(id)

		maxAmt := rapid.Uint64Range(1, 1_000_000).Draw(
			t, "maxAmt",
		)
		minAmt := optionalMsatGen(maxAmt).Draw(
			t, "minAmt",
		)
		rateLimit := optionalFixedPointGen().Draw(
			t, "rateLimit",
		)
		execPolicy := optionalExecutionPolicyGen().Draw(
			t, "execPolicy",
		)

		req, err := NewSellRequest(
			peer, spec,
			lnwire.MilliSatoshi(maxAmt), minAmt,
			rateLimit, fn.None[AssetRate](), "",
			execPolicy,
		)
		require.NoError(t, err)

		wireMsg, err := req.ToWire()
		require.NoError(t, err)

		var msgData requestWireMsgData
		err = msgData.Decode(
			bytes.NewReader(wireMsg.Data),
		)
		require.NoError(t, err)

		decoded, err := NewSellRequestFromWire(
			wireMsg, msgData,
		)
		require.NoError(t, err)

		require.Equal(
			t, lnwire.MilliSatoshi(maxAmt),
			decoded.PaymentMaxAmt,
		)

		requireOptMsatEq(
			t, minAmt, decoded.PaymentMinAmt,
		)

		requireOptFpEq(
			t, rateLimit, decoded.AssetRateLimit,
		)
		requireOptExecPolicyEq(
			t, execPolicy, decoded.ExecutionPolicy,
		)
	})
}

// TestMinMaxConstraintProperty verifies that Validate accepts
// min <= max and rejects min > max for both buy and sell requests.
func TestMinMaxConstraintProperty(t *testing.T) {
	t.Parallel()

	t.Run("buy_valid", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			maxAmt := rapid.Uint64Range(1, 1_000_000).
				Draw(t, "max")
			minAmt := rapid.Uint64Range(0, maxAmt).
				Draw(t, "min")

			req := &BuyRequest{
				Version: V1,
				AssetSpecifier: asset.NewSpecifierFromId(
					asset.ID{1},
				),
				AssetMaxAmt:    maxAmt,
				AssetMinAmt:    fn.Some(minAmt),
				AssetRateLimit: fn.None[rfqmath.BigIntFixedPoint](), //nolint:lll
				AssetRateHint:  fn.None[AssetRate](),
			}
			require.NoError(t, req.Validate())
		})
	})

	t.Run("buy_invalid", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			maxAmt := rapid.Uint64Range(
				0, 1_000_000-1,
			).Draw(t, "max")
			minAmt := rapid.Uint64Range(
				maxAmt+1, 1_000_000,
			).Draw(t, "min")

			req := &BuyRequest{
				Version: V1,
				AssetSpecifier: asset.NewSpecifierFromId(
					asset.ID{1},
				),
				AssetMaxAmt:    maxAmt,
				AssetMinAmt:    fn.Some(minAmt),
				AssetRateLimit: fn.None[rfqmath.BigIntFixedPoint](), //nolint:lll
				AssetRateHint:  fn.None[AssetRate](),
			}
			require.Error(t, req.Validate())
		})
	})

	t.Run("sell_valid", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			maxAmt := rapid.Uint64Range(1, 1_000_000).
				Draw(t, "max")
			minAmt := rapid.Uint64Range(0, maxAmt).
				Draw(t, "min")

			req := &SellRequest{
				Version: V1,
				AssetSpecifier: asset.NewSpecifierFromId(
					asset.ID{1},
				),
				PaymentMaxAmt: lnwire.MilliSatoshi(
					maxAmt,
				),
				PaymentMinAmt: fn.Some(
					lnwire.MilliSatoshi(minAmt),
				),
				AssetRateLimit: fn.None[rfqmath.BigIntFixedPoint](), //nolint:lll
				AssetRateHint:  fn.None[AssetRate](),
			}
			require.NoError(t, req.Validate())
		})
	})

	t.Run("sell_invalid", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			maxAmt := rapid.Uint64Range(
				0, 1_000_000-1,
			).Draw(t, "max")
			minAmt := rapid.Uint64Range(
				maxAmt+1, 1_000_000,
			).Draw(t, "min")

			req := &SellRequest{
				Version: V1,
				AssetSpecifier: asset.NewSpecifierFromId(
					asset.ID{1},
				),
				PaymentMaxAmt: lnwire.MilliSatoshi(
					maxAmt,
				),
				PaymentMinAmt: fn.Some(
					lnwire.MilliSatoshi(minAmt),
				),
				AssetRateLimit: fn.None[rfqmath.BigIntFixedPoint](), //nolint:lll
				AssetRateHint:  fn.None[AssetRate](),
			}
			require.Error(t, req.Validate())
		})
	})
}

// TestNegativeRateLimitRejected verifies that Validate rejects a
// rate limit with a non-positive coefficient for both buy and sell
// requests.
func TestNegativeRateLimitRejected(t *testing.T) {
	t.Parallel()

	spec := asset.NewSpecifierFromId(asset.ID{1})
	negLimit := rfqmath.FixedPoint[rfqmath.BigInt]{
		Coefficient: rfqmath.NewBigInt(
			big.NewInt(-5),
		),
		Scale: 0,
	}
	zeroLimit := rfqmath.FixedPoint[rfqmath.BigInt]{
		Coefficient: rfqmath.NewBigIntFromUint64(0),
		Scale:       0,
	}

	t.Run("buy_negative", func(t *testing.T) {
		t.Parallel()
		req := &BuyRequest{
			Version:        V1,
			AssetSpecifier: spec,
			AssetMaxAmt:    100,
			AssetRateLimit: fn.Some(negLimit),
			AssetRateHint:  fn.None[AssetRate](),
		}
		err := req.Validate()
		require.ErrorContains(
			t, err, "coefficient must be positive",
		)
	})

	t.Run("buy_zero", func(t *testing.T) {
		t.Parallel()
		req := &BuyRequest{
			Version:        V1,
			AssetSpecifier: spec,
			AssetMaxAmt:    100,
			AssetRateLimit: fn.Some(zeroLimit),
			AssetRateHint:  fn.None[AssetRate](),
		}
		err := req.Validate()
		require.ErrorContains(
			t, err, "coefficient must be positive",
		)
	})

	t.Run("sell_negative", func(t *testing.T) {
		t.Parallel()
		req := &SellRequest{
			Version:        V1,
			AssetSpecifier: spec,
			PaymentMaxAmt:  1000,
			AssetRateLimit: fn.Some(negLimit),
			AssetRateHint:  fn.None[AssetRate](),
		}
		err := req.Validate()
		require.ErrorContains(
			t, err, "coefficient must be positive",
		)
	})

	t.Run("sell_zero", func(t *testing.T) {
		t.Parallel()
		req := &SellRequest{
			Version:        V1,
			AssetSpecifier: spec,
			PaymentMaxAmt:  1000,
			AssetRateLimit: fn.Some(zeroLimit),
			AssetRateHint:  fn.None[AssetRate](),
		}
		err := req.Validate()
		require.ErrorContains(
			t, err, "coefficient must be positive",
		)
	})
}

// TestRateBoundEnforcementProperty verifies that rate limit fields
// survive a wire roundtrip and preserve the ordering relationship
// that checkRateBound relies on. For each request type we draw a
// random rate limit, encode/decode the request, then confirm that
// Cmp between an independently drawn accepted rate and the decoded
// limit yields the same result as comparing against the original.
func TestRateBoundEnforcementProperty(t *testing.T) {
	t.Parallel()

	t.Run("buy", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			peer := peerGen().Draw(t, "peer")
			id := assetIDGen().Draw(t, "id")
			spec := asset.NewSpecifierFromId(id)

			maxAmt := rapid.Uint64Range(1, 1_000_000).
				Draw(t, "maxAmt")
			limit := fixedPointGen().Draw(t, "limit")

			req, err := NewBuyRequest(
				peer, spec, maxAmt,
				fn.None[uint64](),
				fn.Some(limit),
				fn.None[AssetRate](), "",
				fn.None[ExecutionPolicy](),
			)
			require.NoError(t, err)

			wireMsg, err := req.ToWire()
			require.NoError(t, err)

			var msgData requestWireMsgData
			err = msgData.Decode(
				bytes.NewReader(wireMsg.Data),
			)
			require.NoError(t, err)

			decoded, err := NewBuyRequestFromWire(
				wireMsg, msgData,
			)
			require.NoError(t, err)

			decodedLimit, err := decoded.AssetRateLimit.
				UnwrapOrErr(
					errMissingRateLimit,
				)
			require.NoError(t, err)

			// Ordering vs an independent rate must
			// be identical before and after roundtrip.
			accepted := fixedPointGen().Draw(
				t, "accepted",
			)
			require.Equal(
				t, accepted.Cmp(limit),
				accepted.Cmp(decodedLimit),
				"buy Cmp mismatch after roundtrip",
			)
		})
	})

	t.Run("sell", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(t *rapid.T) {
			peer := peerGen().Draw(t, "peer")
			id := assetIDGen().Draw(t, "id")
			spec := asset.NewSpecifierFromId(id)

			maxAmt := rapid.Uint64Range(
				1, 1_000_000,
			).Draw(t, "maxAmt")
			limit := fixedPointGen().Draw(t, "limit")

			req, err := NewSellRequest(
				peer, spec,
				lnwire.MilliSatoshi(maxAmt),
				fn.None[lnwire.MilliSatoshi](),
				fn.Some(limit),
				fn.None[AssetRate](), "",
				fn.None[ExecutionPolicy](),
			)
			require.NoError(t, err)

			wireMsg, err := req.ToWire()
			require.NoError(t, err)

			var msgData requestWireMsgData
			err = msgData.Decode(
				bytes.NewReader(wireMsg.Data),
			)
			require.NoError(t, err)

			decoded, err := NewSellRequestFromWire(
				wireMsg, msgData,
			)
			require.NoError(t, err)

			decodedLimit, err := decoded.AssetRateLimit.
				UnwrapOrErr(
					errMissingRateLimit,
				)
			require.NoError(t, err)

			accepted := fixedPointGen().Draw(
				t, "accepted",
			)
			require.Equal(
				t, accepted.Cmp(limit),
				accepted.Cmp(decodedLimit),
				"sell Cmp mismatch after roundtrip",
			)
		})
	})
}

// errMissingRateLimit is returned when a rate limit is expected
// but not present after wire roundtrip.
var errMissingRateLimit = fmt.Errorf("rate limit missing")

// TestBuyRequestRoundtripWithHintProperty verifies that a BuyRequest
// with all fields (including AssetRateHint) survives a roundtrip.
func TestBuyRequestRoundtripWithHintProperty(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		peer := peerGen().Draw(t, "peer")
		id := assetIDGen().Draw(t, "id")
		spec := asset.NewSpecifierFromId(id)

		maxAmt := rapid.Uint64Range(1, 1_000_000).Draw(
			t, "maxAmt",
		)
		minAmt := optionalUint64Gen(maxAmt).Draw(
			t, "minAmt",
		)
		rateLimit := optionalFixedPointGen().Draw(
			t, "rateLimit",
		)

		// Always include a rate hint so we test the full
		// field set.
		expiry := time.Now().Add(5 * time.Minute).UTC()
		fp := fixedPointGen().Draw(t, "hintRate")
		hint := fn.Some(NewAssetRate(fp, expiry))

		execPolicy := optionalExecutionPolicyGen().Draw(
			t, "execPolicy",
		)

		req, err := NewBuyRequest(
			peer, spec, maxAmt, minAmt,
			rateLimit, hint, "",
			execPolicy,
		)
		require.NoError(t, err)

		wireMsg, err := req.ToWire()
		require.NoError(t, err)

		var msgData requestWireMsgData
		err = msgData.Decode(
			bytes.NewReader(wireMsg.Data),
		)
		require.NoError(t, err)

		decoded, err := NewBuyRequestFromWire(
			wireMsg, msgData,
		)
		require.NoError(t, err)

		require.Equal(t, maxAmt, decoded.AssetMaxAmt)
		requireOptEq(t, minAmt, decoded.AssetMinAmt)
		requireOptFpEq(
			t, rateLimit, decoded.AssetRateLimit,
		)
		require.True(t, decoded.AssetRateHint.IsSome())
		requireOptExecPolicyEq(
			t, execPolicy, decoded.ExecutionPolicy,
		)
	})
}

// --- helpers ---

// requireOptEq asserts two fn.Option[uint64] values are equal.
func requireOptEq(t require.TestingT,
	want, got fn.Option[uint64]) {

	t.(*rapid.T).Helper()

	if want.IsNone() {
		require.True(t, got.IsNone())
		return
	}

	require.True(t, got.IsSome())

	wantVal := want.UnwrapOr(0)
	gotVal := got.UnwrapOr(0)
	require.Equal(t, wantVal, gotVal)
}

// requireOptMsatEq asserts two fn.Option[lnwire.MilliSatoshi]
// values are equal.
func requireOptMsatEq(t require.TestingT,
	want, got fn.Option[lnwire.MilliSatoshi]) {

	t.(*rapid.T).Helper()

	if want.IsNone() {
		require.True(t, got.IsNone())
		return
	}

	require.True(t, got.IsSome())

	wantVal := want.UnwrapOr(0)
	gotVal := got.UnwrapOr(0)
	require.Equal(t, wantVal, gotVal)
}

// requireOptFpEq asserts two optional BigIntFixedPoint values are
// equal via Cmp.
func requireOptFpEq(t require.TestingT,
	want, got fn.Option[rfqmath.BigIntFixedPoint]) {

	if want.IsNone() {
		require.True(t, got.IsNone())
		return
	}

	require.True(t, got.IsSome())

	wantVal := want.UnwrapOr(
		rfqmath.NewBigIntFixedPoint(0, 0),
	)
	gotVal := got.UnwrapOr(
		rfqmath.NewBigIntFixedPoint(0, 0),
	)
	require.Equal(t, 0, gotVal.Cmp(wantVal))
}

// requireOptExecPolicyEq asserts two optional ExecutionPolicy
// values are equal.
func requireOptExecPolicyEq(t require.TestingT,
	want, got fn.Option[ExecutionPolicy]) {

	if want.IsNone() {
		require.True(t, got.IsNone())
		return
	}

	require.True(t, got.IsSome())

	wantVal := want.UnwrapOr(ExecutionPolicyIOC)
	gotVal := got.UnwrapOr(ExecutionPolicyIOC)
	require.Equal(t, wantVal, gotVal)
}
