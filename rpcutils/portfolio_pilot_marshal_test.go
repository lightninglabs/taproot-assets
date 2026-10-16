package rpcutils

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/taprpc/portfoliopilotrpc"
	"github.com/stretchr/testify/require"
)

// TestUnmarshalPortfolioConstraints checks the request constraints
// derived from portfolio pilot buy and sell requests.
func TestUnmarshalPortfolioConstraints(t *testing.T) {
	t.Parallel()

	const (
		ioc = portfoliopilotrpc.ExecutionPolicy_EXECUTION_POLICY_IOC
		fok = portfoliopilotrpc.ExecutionPolicy_EXECUTION_POLICY_FOK
	)

	rpcLimit := &portfoliopilotrpc.FixedPoint{
		Coefficient: "12345",
		Scale:       2,
	}
	limit := rfqmath.NewBigIntFixedPoint(12345, 2)

	tests := []struct {
		name    string
		buy     *portfoliopilotrpc.BuyRequest
		sell    *portfoliopilotrpc.SellRequest
		want    rfqmsg.RequestConstraints
		wantErr string
	}{
		{
			name: "buy: all fields set",
			buy: &portfoliopilotrpc.BuyRequest{
				AssetMaxAmount:  1000,
				AssetMinAmount:  100,
				AssetRateLimit:  rpcLimit,
				ExecutionPolicy: fok,
			},
			want: rfqmsg.RequestConstraints{
				MaxAmount:    1000,
				MinAmount:    fn.Some[uint64](100),
				RateLimit:    fn.Some(limit),
				RateBoundCmp: -1,
				ExecutionPolicy: fn.Some(
					rfqmsg.ExecutionPolicyFOK,
				),
			},
		},
		{
			name: "buy: optional fields unset",
			buy: &portfoliopilotrpc.BuyRequest{
				AssetMaxAmount:  1000,
				ExecutionPolicy: ioc,
			},
			want: rfqmsg.RequestConstraints{
				MaxAmount:    1000,
				RateBoundCmp: -1,
			},
		},
		{
			name: "buy: unknown execution policy",
			buy: &portfoliopilotrpc.BuyRequest{
				AssetMaxAmount:  1000,
				ExecutionPolicy: 2,
			},
			wantErr: "unknown execution policy",
		},
		{
			name: "buy: invalid rate limit",
			buy: &portfoliopilotrpc.BuyRequest{
				AssetMaxAmount: 1000,
				AssetRateLimit: &portfoliopilotrpc.FixedPoint{
					Coefficient: "x",
				},
			},
			wantErr: "unmarshal rate limit",
		},
		{
			name: "sell: all fields set",
			sell: &portfoliopilotrpc.SellRequest{
				PaymentMaxAmount: 5000,
				PaymentMinAmount: 500,
				AssetRateLimit:   rpcLimit,
				ExecutionPolicy:  fok,
			},
			want: rfqmsg.RequestConstraints{
				MaxAmount:    5000,
				MinAmount:    fn.Some[uint64](500),
				RateLimit:    fn.Some(limit),
				RateBoundCmp: 1,
				ExecutionPolicy: fn.Some(
					rfqmsg.ExecutionPolicyFOK,
				),
			},
		},
		{
			name: "sell: optional fields unset",
			sell: &portfoliopilotrpc.SellRequest{
				PaymentMaxAmount: 5000,
				ExecutionPolicy:  ioc,
			},
			want: rfqmsg.RequestConstraints{
				MaxAmount:    5000,
				RateBoundCmp: 1,
			},
		},
		{
			name: "sell: unknown execution policy",
			sell: &portfoliopilotrpc.SellRequest{
				PaymentMaxAmount: 5000,
				ExecutionPolicy:  2,
			},
			wantErr: "unknown execution policy",
		},
		{
			name: "sell: invalid rate limit",
			sell: &portfoliopilotrpc.SellRequest{
				PaymentMaxAmount: 5000,
				AssetRateLimit: &portfoliopilotrpc.FixedPoint{
					Coefficient: "1",
					Scale:       256,
				},
			},
			wantErr: "unmarshal rate limit",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				got rfqmsg.RequestConstraints
				err error
			)
			if tc.buy != nil {
				got, err = UnmarshalPortfolioBuyConstraints(
					tc.buy,
				)
			} else {
				got, err = UnmarshalPortfolioSellConstraints(
					tc.sell,
				)
			}

			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestUnmarshalPortfolioConstraintsNil checks that nil requests are
// rejected.
func TestUnmarshalPortfolioConstraintsNil(t *testing.T) {
	t.Parallel()

	_, err := UnmarshalPortfolioBuyConstraints(nil)
	require.ErrorContains(t, err, "buy request is nil")

	_, err = UnmarshalPortfolioSellConstraints(nil)
	require.ErrorContains(t, err, "sell request is nil")
}
