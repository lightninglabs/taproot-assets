package rfq

import (
	"context"
	"sync"
	"sync/atomic"
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

// TestAssetSalePolicyConcurrentHtlcCap tests that concurrently accepted
// HTLCs referencing the same asset sale policy never exceed the policy's
// agreed maximum amount, even though the HTLC interceptor invokes the
// handler in a new goroutine per HTLC.
func TestAssetSalePolicyConcurrentHtlcCap(t *testing.T) {
	t.Parallel()

	spec := asset.NewSpecifierFromId(asset.ID{0x01})
	peer := route.Vertex{0x0A}
	rate := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(100, 0),
		time.Now().Add(time.Hour),
	)

	buyReq := &rfqmsg.BuyRequest{
		Peer:           peer,
		AssetSpecifier: spec,
		AssetMaxAmt:    1000,
	}
	accept := rfqmsg.BuyAccept{
		Peer:      peer,
		Request:   *buyReq,
		AssetRate: rate,
	}
	policy := NewAssetSalePolicy(accept, false, nil)

	// Compute the policy's maximum outgoing amount in millisatoshis. A
	// single HTLC of this size exactly exhausts the policy.
	maxAssetAmount := rfqmath.NewBigIntFixedPoint(
		policy.MaxOutboundAssetAmount, 0,
	)
	capMsat, err := rfqmath.UnitsToMilliSatoshi(
		maxAssetAmount, policy.AskAssetRate,
	)
	require.NoError(t, err)

	// Fire many concurrent HTLCs at the policy, mimicking the HTLC
	// interceptor invoking the handler in a new goroutine per HTLC. Each
	// HTLC carries the full cap amount, so exactly one HTLC's worth can be
	// accepted.
	const numHtlcs = 32

	var (
		wg       sync.WaitGroup
		accepted atomic.Int32
	)
	start := make(chan struct{})

	for i := 0; i < numHtlcs; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			<-start

			htlc := lndclient.InterceptedHtlc{
				IncomingCircuitKey: models.CircuitKey{
					ChanID: lnwire.NewShortChanIDFromInt(1),
					HtlcID: uint64(i),
				},
				OutgoingChannelID: lnwire.NewShortChanIDFromInt(
					uint64(policy.AcceptedQuoteId.Scid()),
				),
				AmountOutMsat: capMsat,
			}

			// A compliant HTLC is tracked by the policy
			// atomically as part of the compliance check.
			err := policy.CheckHtlcCompliance(
				context.Background(), htlc, nil,
			)
			if err != nil {
				return
			}

			accepted.Add(1)
		}(i)
	}

	close(start)
	wg.Wait()

	// Exactly one HTLC's worth must have been accepted: the tracked total
	// equals the agreed maximum exactly. A check-then-track race would let
	// multiple HTLCs through and exceed the cap, while a policy that never
	// tracks accepted HTLCs would leave the total at zero.
	require.EqualValues(t, 1, accepted.Load())
	require.Equal(t, capMsat, policy.CurrentAmountMsat)
}

// TestAssetPurchasePolicyConcurrentHtlcCap tests that concurrently accepted
// HTLCs referencing the same asset purchase policy never exceed the policy's
// maximum agreed BTC payment, even though the HTLC interceptor invokes the
// handler in a new goroutine per HTLC.
func TestAssetPurchasePolicyConcurrentHtlcCap(t *testing.T) {
	t.Parallel()

	spec := asset.NewSpecifierFromId(asset.ID{0x01})
	peer := route.Vertex{0x0A}
	rate := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(100, 0),
		time.Now().Add(time.Hour),
	)

	sellReq := &rfqmsg.SellRequest{
		Peer:           peer,
		AssetSpecifier: spec,
		PaymentMaxAmt:  1000,
	}
	accept := rfqmsg.SellAccept{
		Peer:      peer,
		Request:   *sellReq,
		AssetRate: rate,
	}
	policy := NewAssetPurchasePolicy(accept)

	// Build the HTLC custom records once. Every HTLC carries an asset
	// balance large enough to cover the outgoing msat amount.
	htlcRecord := rfqmsg.NewHtlc(
		[]*rfqmsg.AssetBalance{
			rfqmsg.NewAssetBalance(asset.ID{0x01}, 1),
		},
		fn.Some(policy.AcceptedQuoteId),
		fn.None[[]rfqmsg.ID](),
	)
	customRecords, err := lnwire.ParseCustomRecords(htlcRecord.Bytes())
	require.NoError(t, err)

	specifierChecker := rfqmsg.SpecifierChecker(
		func(_ context.Context, _ asset.Specifier,
			_ asset.ID) (bool, error) {

			return true, nil
		},
	)

	// Fire many concurrent HTLCs at the policy, mimicking the HTLC
	// interceptor invoking the handler in a new goroutine per HTLC. Each
	// HTLC carries the full maximum payment amount, so exactly one HTLC's
	// worth can be accepted.
	const numHtlcs = 32

	var (
		wg       sync.WaitGroup
		accepted atomic.Int32
	)
	start := make(chan struct{})

	for i := 0; i < numHtlcs; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()
			<-start

			htlc := lndclient.InterceptedHtlc{
				IncomingCircuitKey: models.CircuitKey{
					ChanID: lnwire.NewShortChanIDFromInt(1),
					HtlcID: uint64(i),
				},
				AmountOutMsat:       policy.PaymentMaxAmt,
				InWireCustomRecords: customRecords,
			}

			// A compliant HTLC is tracked by the policy
			// atomically as part of the compliance check.
			err := policy.CheckHtlcCompliance(
				context.Background(), htlc, specifierChecker,
			)
			if err != nil {
				return
			}

			accepted.Add(1)
		}(i)
	}

	close(start)
	wg.Wait()

	// Exactly one HTLC's worth must have been accepted: the tracked total
	// equals the maximum agreed payment exactly. A check-then-track race
	// would let multiple HTLCs through and exceed the cap, while a policy
	// that never tracks accepted HTLCs would leave the total at zero.
	require.EqualValues(t, 1, accepted.Load())
	require.Equal(t, policy.PaymentMaxAmt, policy.CurrentAmountMsat)
}
