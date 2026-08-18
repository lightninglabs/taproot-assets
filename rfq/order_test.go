package rfq

import (
	"testing"
	"time"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/graph/db/models"
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

// TestPolicyAccountingIdempotent tests that tracking and checking the same
// HTLC twice doesn't count its amount twice. lnd asks interceptor clients to
// handle replayed HTLCs idempotently, and it does replay held HTLCs to every
// newly connected interceptor.
func TestPolicyAccountingIdempotent(t *testing.T) {
	t.Parallel()

	const htlcAmt = 1000

	circuitKey := testCircuitKey(1)
	htlc := lndclient.InterceptedHtlc{
		IncomingCircuitKey: circuitKey,
		AmountOutMsat:      htlcAmt,
	}

	t.Run("sale policy", func(t *testing.T) {
		p := &AssetSalePolicy{
			htlcToAmt: make(
				map[models.CircuitKey]lnwire.MilliSatoshi,
			),
		}

		p.TrackAcceptedHtlc(circuitKey, htlcAmt)
		p.TrackAcceptedHtlc(circuitKey, htlcAmt)
		require.EqualValues(t, htlcAmt, p.CurrentAmountMsat)

		// The already tracked amount must not be counted again.
		require.EqualValues(
			t, 0, p.currentAmountExcluding(circuitKey),
		)
		require.EqualValues(
			t, htlcAmt, p.currentAmountExcluding(testCircuitKey(2)),
		)

		// Untracking releases the amount exactly once.
		p.UntrackHtlc(circuitKey)
		require.Zero(t, p.CurrentAmountMsat)
	})

	t.Run("purchase policy", func(t *testing.T) {
		p := &AssetPurchasePolicy{
			htlcToAmt: make(
				map[models.CircuitKey]lnwire.MilliSatoshi,
			),
			PaymentMaxAmt: htlcAmt,
		}

		p.TrackAcceptedHtlc(circuitKey, htlcAmt)
		p.TrackAcceptedHtlc(circuitKey, htlcAmt)
		require.EqualValues(t, htlcAmt, p.CurrentAmountMsat)

		// A replay of the very same HTLC must not be counted against
		// the quote a second time, which is what would make it exceed
		// the policy maximum.
		require.EqualValues(
			t, 0, p.currentAmountExcluding(circuitKey),
		)
		require.Less(
			t, uint64(p.currentAmountExcluding(circuitKey)+
				htlc.AmountOutMsat),
			uint64(p.PaymentMaxAmt)+1,
		)

		p.UntrackHtlc(circuitKey)
		require.Zero(t, p.CurrentAmountMsat)
	})
}
