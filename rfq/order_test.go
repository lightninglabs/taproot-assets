package rfq

import (
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

// TestNewAssetSalePolicyFillCap tests that NewAssetSalePolicy caps
// MaxOutboundAssetAmount when a fill quantity is present.
func TestNewAssetSalePolicyFillCap(t *testing.T) {
	t.Parallel()

	spec := asset.NewSpecifierFromId(asset.ID{0x01})
	peer := route.Vertex{0x0A}
	rate := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(100, 0),
		time.Now().Add(time.Hour),
	)

	tests := []struct {
		name      string
		maxAmt    uint64
		fill      fn.Option[uint64]
		expectMax uint64
	}{
		{
			name:      "no fill uses request max",
			maxAmt:    100,
			fill:      fn.None[uint64](),
			expectMax: 100,
		},
		{
			name:      "fill < max caps to fill",
			maxAmt:    100,
			fill:      fn.Some[uint64](60),
			expectMax: 60,
		},
		{
			name:      "fill > max uses request max",
			maxAmt:    100,
			fill:      fn.Some[uint64](200),
			expectMax: 100,
		},
		{
			name:      "fill == max uses request max",
			maxAmt:    100,
			fill:      fn.Some[uint64](100),
			expectMax: 100,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			buyReq := &rfqmsg.BuyRequest{
				Peer:           peer,
				AssetSpecifier: spec,
				AssetMaxAmt:    tc.maxAmt,
			}

			accept := rfqmsg.BuyAccept{
				Peer:              peer,
				Request:           *buyReq,
				AssetRate:         rate,
				AcceptedMaxAmount: tc.fill,
			}

			policy := NewAssetSalePolicy(
				accept, false, nil,
			)
			require.Equal(
				t, tc.expectMax,
				policy.MaxOutboundAssetAmount,
			)
		})
	}
}

// TestNewAssetPurchasePolicyFillCap tests that NewAssetPurchasePolicy
// caps PaymentMaxAmt when a fill quantity is present.
func TestNewAssetPurchasePolicyFillCap(t *testing.T) {
	t.Parallel()

	spec := asset.NewSpecifierFromId(asset.ID{0x01})
	peer := route.Vertex{0x0A}
	rate := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(100, 0),
		time.Now().Add(time.Hour),
	)

	tests := []struct {
		name      string
		maxAmt    lnwire.MilliSatoshi
		fill      fn.Option[uint64]
		expectMax lnwire.MilliSatoshi
	}{
		{
			name:      "no fill uses request max",
			maxAmt:    1000,
			fill:      fn.None[uint64](),
			expectMax: 1000,
		},
		{
			name:      "fill < max caps to fill",
			maxAmt:    1000,
			fill:      fn.Some[uint64](600),
			expectMax: 600,
		},
		{
			name:      "fill > max uses request max",
			maxAmt:    1000,
			fill:      fn.Some[uint64](2000),
			expectMax: 1000,
		},
		{
			name:      "fill == max uses request max",
			maxAmt:    1000,
			fill:      fn.Some[uint64](1000),
			expectMax: 1000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sellReq := &rfqmsg.SellRequest{
				Peer:           peer,
				AssetSpecifier: spec,
				PaymentMaxAmt:  tc.maxAmt,
			}

			accept := rfqmsg.SellAccept{
				Peer:              peer,
				Request:           *sellReq,
				AssetRate:         rate,
				AcceptedMaxAmount: tc.fill,
			}

			policy := NewAssetPurchasePolicy(accept)
			require.Equal(
				t, tc.expectMax, policy.PaymentMaxAmt,
			)
		})
	}
}
