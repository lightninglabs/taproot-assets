package rfq

import (
	"math"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/rpcutils"
	pilotrpc "github.com/lightninglabs/taproot-assets/taprpc/portfoliopilotrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// TestRpcMarshalBuyRequest verifies that rpcMarshalBuyRequest
// correctly marshals all constraint fields into the RPC form.
func TestRpcMarshalBuyRequest(t *testing.T) {
	t.Parallel()

	const (
		policyIOC = pilotrpc.ExecutionPolicy_EXECUTION_POLICY_IOC
		policyFOK = pilotrpc.ExecutionPolicy_EXECUTION_POLICY_FOK
	)

	spec := asset.NewSpecifierFromId(asset.ID{0xAA})
	peer := route.Vertex{0x01, 0x02, 0x03}
	rateLimit := rfqmath.NewBigIntFixedPoint(500, 2)

	tests := []struct {
		name       string
		req        *rfqmsg.BuyRequest
		wantPolicy pilotrpc.ExecutionPolicy
		wantMin    uint64
		wantLimit  bool
	}{
		{
			name: "FOK with constraints",
			req: &rfqmsg.BuyRequest{
				Peer:           peer,
				ID:             rfqmsg.ID{0x0B},
				AssetSpecifier: spec,
				AssetMaxAmt:    1000,
				AssetMinAmt:    fn.Some[uint64](100),
				AssetRateLimit: fn.Some(rateLimit),
				ExecutionPolicy: fn.Some(
					rfqmsg.ExecutionPolicyFOK,
				),
			},
			wantPolicy: policyFOK,
			wantMin:    100,
			wantLimit:  true,
		},
		{
			name: "no constraints",
			req: &rfqmsg.BuyRequest{
				Peer:           peer,
				AssetSpecifier: spec,
				AssetMaxAmt:    500,
			},
			wantPolicy: policyIOC,
			wantMin:    0,
			wantLimit:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rpc, err := rpcMarshalBuyRequest(tc.req)
			require.NoError(t, err)

			require.Equal(t, tc.req.ID[:], rpc.RfqId)

			require.Equal(
				t, tc.req.AssetMaxAmt,
				rpc.AssetMaxAmount,
			)
			require.Equal(
				t, tc.wantPolicy,
				rpc.ExecutionPolicy,
			)
			require.Equal(
				t, tc.wantMin,
				rpc.AssetMinAmount,
			)

			if tc.wantLimit {
				require.NotNil(t, rpc.AssetRateLimit)
				require.Equal(
					t, "500",
					rpc.AssetRateLimit.Coefficient,
				)
				require.Equal(
					t, uint32(2),
					rpc.AssetRateLimit.Scale,
				)
			} else {
				require.Nil(t, rpc.AssetRateLimit)
			}
		})
	}
}

// TestRpcMarshalSellRequest verifies that rpcMarshalSellRequest
// correctly marshals all constraint fields into the RPC form.
func TestRpcMarshalSellRequest(t *testing.T) {
	t.Parallel()

	const (
		policyIOC = pilotrpc.ExecutionPolicy_EXECUTION_POLICY_IOC
		policyFOK = pilotrpc.ExecutionPolicy_EXECUTION_POLICY_FOK
	)

	spec := asset.NewSpecifierFromId(asset.ID{0xBB})
	peer := route.Vertex{0x04, 0x05, 0x06}
	rateLimit := rfqmath.NewBigIntFixedPoint(750, 3)

	tests := []struct {
		name       string
		req        *rfqmsg.SellRequest
		wantPolicy pilotrpc.ExecutionPolicy
		wantMin    uint64
		wantLimit  bool
	}{
		{
			name: "FOK with constraints",
			req: &rfqmsg.SellRequest{
				Peer:           peer,
				ID:             rfqmsg.ID{0x0C},
				AssetSpecifier: spec,
				PaymentMaxAmt:  lnwire.MilliSatoshi(2000),
				PaymentMinAmt: fn.Some(
					lnwire.MilliSatoshi(500),
				),
				AssetRateLimit: fn.Some(rateLimit),
				ExecutionPolicy: fn.Some(
					rfqmsg.ExecutionPolicyFOK,
				),
			},
			wantPolicy: policyFOK,
			wantMin:    500,
			wantLimit:  true,
		},
		{
			name: "no constraints",
			req: &rfqmsg.SellRequest{
				Peer:           peer,
				AssetSpecifier: spec,
				PaymentMaxAmt:  lnwire.MilliSatoshi(3000),
			},
			wantPolicy: policyIOC,
			wantMin:    0,
			wantLimit:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rpc, err := rpcMarshalSellRequest(tc.req)
			require.NoError(t, err)

			require.Equal(t, tc.req.ID[:], rpc.RfqId)

			require.Equal(
				t, uint64(tc.req.PaymentMaxAmt),
				rpc.PaymentMaxAmount,
			)
			require.Equal(
				t, tc.wantPolicy,
				rpc.ExecutionPolicy,
			)
			require.Equal(
				t, tc.wantMin,
				rpc.PaymentMinAmount,
			)

			if tc.wantLimit {
				require.NotNil(t, rpc.AssetRateLimit)
				require.Equal(
					t, "750",
					rpc.AssetRateLimit.Coefficient,
				)
				require.Equal(
					t, uint32(3),
					rpc.AssetRateLimit.Scale,
				)
			} else {
				require.Nil(t, rpc.AssetRateLimit)
			}
		})
	}
}

// TestPortfolioConstraintsMatchRequest checks that the constraints
// derived from the RPC form of a request equal the constraints of the
// request, with an IOC execution policy read as unset, and that
// CheckConstraints returns the same status for both.
func TestPortfolioConstraintsMatchRequest(t *testing.T) {
	t.Parallel()

	buyConstraints := rpcutils.UnmarshalPortfolioBuyConstraints
	sellConstraints := rpcutils.UnmarshalPortfolioSellConstraints

	optUint64 := func(t *rapid.T, label string,
		lo, hi uint64) fn.Option[uint64] {

		if !rapid.Bool().Draw(t, label+"_set") {
			return fn.None[uint64]()
		}

		return fn.Some(rapid.Uint64Range(lo, hi).Draw(t, label))
	}

	fixedPoint := func(t *rapid.T,
		label string) rfqmath.BigIntFixedPoint {

		coeff := rapid.Uint64Range(1, 1e15).Draw(t, label+"_coeff")
		scale := rapid.Uint8Range(0, 11).Draw(t, label+"_scale")

		return rfqmath.NewBigIntFixedPoint(coeff, scale)
	}

	rapid.Check(t, func(t *rapid.T) {
		maxAmt := rapid.Uint64Range(1, 1e12).Draw(t, "max")
		minAmt := optUint64(t, "min", 1, maxAmt)

		rateLimit := fn.None[rfqmath.BigIntFixedPoint]()
		if rapid.Bool().Draw(t, "limit_set") {
			rateLimit = fn.Some(fixedPoint(t, "limit"))
		}

		policy := rapid.SampledFrom(
			[]fn.Option[rfqmsg.ExecutionPolicy]{
				fn.None[rfqmsg.ExecutionPolicy](),
				fn.Some(rfqmsg.ExecutionPolicyIOC),
				fn.Some(rfqmsg.ExecutionPolicyFOK),
			},
		).Draw(t, "policy")

		rate := fixedPoint(t, "rate")
		fill := optUint64(t, "fill", 0, 2*maxAmt)

		var (
			req    rfqmsg.Request
			rpcCon rfqmsg.RequestConstraints
		)
		if rapid.Bool().Draw(t, "buy") {
			buyReq := &rfqmsg.BuyRequest{
				AssetMaxAmt:     maxAmt,
				AssetMinAmt:     minAmt,
				AssetRateLimit:  rateLimit,
				ExecutionPolicy: policy,
			}
			rpcReq, err := rpcMarshalBuyRequest(buyReq)
			require.NoError(t, err)

			rpcCon, err = buyConstraints(rpcReq)
			require.NoError(t, err)

			req = buyReq
		} else {
			toMsat := func(v uint64) lnwire.MilliSatoshi {
				return lnwire.MilliSatoshi(v)
			}
			sellReq := &rfqmsg.SellRequest{
				PaymentMaxAmt:   lnwire.MilliSatoshi(maxAmt),
				PaymentMinAmt:   fn.MapOption(toMsat)(minAmt),
				AssetRateLimit:  rateLimit,
				ExecutionPolicy: policy,
			}
			rpcReq, err := rpcMarshalSellRequest(sellReq)
			require.NoError(t, err)

			rpcCon, err = sellConstraints(rpcReq)
			require.NoError(t, err)

			req = sellReq
		}

		want := req.Constraints()
		if !isFOK(want.ExecutionPolicy) {
			want.ExecutionPolicy = fn.None[rfqmsg.ExecutionPolicy]()
		}
		require.Equal(t, want, rpcCon)

		require.Equal(
			t, CheckConstraints(req.Constraints(), rate, fill),
			CheckConstraints(rpcCon, rate, fill),
		)
	})
}

// TestMarshalPortfolioQuoteRespStatus checks that every RPC quote
// response status round-trips through the local enum, and that every
// other local status fails to marshal.
func TestMarshalPortfolioQuoteRespStatus(t *testing.T) {
	t.Parallel()

	mapped := make(map[QuoteRespStatus]bool)
	for v := range pilotrpc.QuoteRespStatus_name {
		rpcStatus := pilotrpc.QuoteRespStatus(v)

		status, err := rpcUnmarshalQuoteRespStatus(rpcStatus)
		require.NoError(t, err)

		got, err := MarshalPortfolioQuoteRespStatus(status)
		require.NoError(t, err)
		require.Equal(t, rpcStatus, got)

		mapped[status] = true
	}

	for v := 0; v <= math.MaxUint8; v++ {
		status := QuoteRespStatus(v)
		if mapped[status] {
			continue
		}

		_, err := MarshalPortfolioQuoteRespStatus(status)
		require.ErrorContains(t, err, "no RPC counterpart")
	}
}

// TestMarshalPortfolioRejectErr checks that every RPC reject code
// round-trips through the local enum, that every other local code
// marshals to REJECT_CODE_UNSPECIFIED, and that the message is kept.
func TestMarshalPortfolioRejectErr(t *testing.T) {
	t.Parallel()

	const msg = "reject message"

	mapped := make(map[rfqmsg.RejectCode]bool)
	for v := range pilotrpc.RejectCode_name {
		rpcCode := pilotrpc.RejectCode(v)
		code := rpcUnmarshalRejectCode(rpcCode)

		got := MarshalPortfolioRejectErr(rfqmsg.RejectErr{
			Code: code,
			Msg:  msg,
		})
		require.Equal(t, rpcCode, got.Code)
		require.Equal(t, msg, got.Message)

		mapped[code] = true
	}

	for v := 0; v <= math.MaxUint8; v++ {
		code := rfqmsg.RejectCode(v)
		if mapped[code] {
			continue
		}

		got := MarshalPortfolioRejectErr(rfqmsg.RejectErr{
			Code: code,
			Msg:  msg,
		})
		require.Equal(
			t, pilotrpc.RejectCode_REJECT_CODE_UNSPECIFIED,
			got.Code,
		)
		require.Equal(t, msg, got.Message)
	}
}
