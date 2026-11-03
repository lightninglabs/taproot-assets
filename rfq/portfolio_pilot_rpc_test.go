package rfq

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	pilotrpc "github.com/lightninglabs/taproot-assets/taprpc/portfoliopilotrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
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
		wantSwap   uint64
		wantLimit  bool
	}{
		{
			name: "FOK with constraints",
			req: &rfqmsg.SellRequest{
				Peer:           peer,
				AssetSpecifier: spec,
				PaymentMaxAmt:  lnwire.MilliSatoshi(2000),
				PaymentMinAmt: fn.Some(
					lnwire.MilliSatoshi(500),
				),
				PaymentSwapAmt: fn.Some(
					lnwire.MilliSatoshi(1800),
				),
				AssetRateLimit: fn.Some(rateLimit),
				ExecutionPolicy: fn.Some(
					rfqmsg.ExecutionPolicyFOK,
				),
			},
			wantPolicy: policyFOK,
			wantMin:    500,
			wantSwap:   1800,
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
			require.Equal(
				t, tc.wantSwap,
				rpc.PaymentSwapAmount,
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

// TestRpcMarshalQueryAssetRatesRequest verifies that the optional amounts of
// an asset rate query are marshaled into the RPC form, with unset amounts
// becoming zero.
func TestRpcMarshalQueryAssetRatesRequest(t *testing.T) {
	t.Parallel()

	spec := asset.NewSpecifierFromId(asset.ID{0xCC})

	query := AssetRateQuery{
		AssetSpecifier:    spec,
		Direction:         AssetTransferSell,
		Intent:            IntentPayInvoiceHint,
		PaymentAmount:     fn.Some(lnwire.MilliSatoshi(2500)),
		PaymentSwapAmount: fn.Some(lnwire.MilliSatoshi(2000)),
	}

	rpc, err := rpcMarshalQueryAssetRatesRequest(query)
	require.NoError(t, err)
	require.EqualValues(t, 2500, rpc.PaymentAmount)
	require.EqualValues(t, 2000, rpc.PaymentSwapAmount)
	require.Zero(t, rpc.AssetAmount)

	query.PaymentSwapAmount = fn.None[lnwire.MilliSatoshi]()
	rpc, err = rpcMarshalQueryAssetRatesRequest(query)
	require.NoError(t, err)
	require.EqualValues(t, 2500, rpc.PaymentAmount)
	require.Zero(t, rpc.PaymentSwapAmount)
}
