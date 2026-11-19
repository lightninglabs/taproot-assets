package rfq

import (
	"context"
	"fmt"
	"math"
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
	"github.com/lightningnetwork/lnd/lnwallet"
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

// TestAssetSalePolicyRejectsUnderpayment verifies that the incoming BTC HTLC
// covers the asset value requested by the outgoing leg before the outgoing
// wire amount is replaced with the asset channel's dust amount.
func TestAssetSalePolicyRejectsUnderpayment(t *testing.T) {
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
		AssetMaxAmt:    100,
	}
	policy := NewAssetSalePolicy(rfqmsg.BuyAccept{
		Peer:      peer,
		Request:   *buyReq,
		AssetRate: rate,
	}, false, nil)

	scid := lnwire.NewShortChanIDFromInt(
		uint64(policy.AcceptedQuoteId.Scid()),
	)
	htlc := lndclient.InterceptedHtlc{
		IncomingCircuitKey: testCircuitKey(1),
		OutgoingChannelID:  scid,
		AmountInMsat:       1_000_000,
		AmountOutMsat:      500_000_000,
	}

	err := policy.CheckHtlcCompliance(context.Background(), htlc, nil)
	require.ErrorContains(t, err, "incoming amount is less")
	require.Zero(t, policy.CurrentAmountMsat)

	htlc.IncomingCircuitKey = testCircuitKey(2)
	htlc.AmountInMsat = htlc.AmountOutMsat + 1000
	require.NoError(t, policy.CheckHtlcCompliance(
		context.Background(), htlc, nil,
	))
	require.Equal(t, htlc.AmountOutMsat, policy.CurrentAmountMsat)
}

// TestAssetForwardPolicyUsesIncomingAssetValue verifies that the outgoing sale
// half of an asset-to-asset forward uses the value proven by the incoming asset
// records instead of comparing the asset channel's dust wire amount.
func TestAssetForwardPolicyUsesIncomingAssetValue(t *testing.T) {
	t.Parallel()

	assetID := asset.ID{0x01}
	incoming := testPurchasePolicy(t, assetID)

	rfqID, err := rfqmsg.NewID()
	require.NoError(t, err)
	peer := route.Vertex{0x0A}
	outgoing := NewAssetSalePolicy(rfqmsg.BuyAccept{
		Peer: peer,
		Request: rfqmsg.BuyRequest{
			Peer:           peer,
			AssetSpecifier: asset.NewSpecifierFromId(assetID),
			AssetMaxAmt:    100,
		},
		AssetRate: rfqmsg.NewAssetRate(
			rfqmath.NewBigIntFixedPoint(100, 0),
			time.Now().Add(time.Hour),
		),
		ID: rfqID,
	}, false, nil)

	forward, err := NewAssetForwardPolicy(incoming, outgoing)
	require.NoError(t, err)

	htlc := testPurchaseHtlc(
		t, incoming, 1234, rfqmsg.NewAssetBalance(assetID, 1),
	)
	htlc.OutgoingChannelID = lnwire.NewShortChanIDFromInt(
		uint64(outgoing.AcceptedQuoteId.Scid()),
	)
	require.Less(t, htlc.AmountInMsat, htlc.AmountOutMsat)

	specifierChecker := func(_ context.Context, _ asset.Specifier,
		_ asset.ID) (bool, error) {

		return true, nil
	}
	require.NoError(t, forward.CheckHtlcCompliance(
		context.Background(), htlc, specifierChecker,
	))
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
				AmountInMsat:  capMsat,
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

// TestGenerateInterceptorResponseOverflow tests that
// GenerateInterceptorResponse handles HTLC asset balances whose sum
// approaches or exceeds the uint64 limit without overflowing.
func TestGenerateInterceptorResponseOverflow(t *testing.T) {
	t.Parallel()

	specifier := asset.NewSpecifierFromId(asset.ID{0x01})
	peer := route.Vertex{0x0A}

	// Use a high units-per-BTC rate so that the resulting milli-satoshi
	// amounts still fit in a uint64.
	rate := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(1_000_000_000_000, 0),
		time.Now().Add(time.Hour),
	)

	sellReq := &rfqmsg.SellRequest{
		Peer:           peer,
		AssetSpecifier: specifier,
		PaymentMaxAmt:  1000,
	}

	accept := rfqmsg.SellAccept{
		Peer:      peer,
		Request:   *sellReq,
		AssetRate: rate,
	}

	policy := NewAssetPurchasePolicy(accept)

	testCases := []struct {
		name     string
		balances []uint64
	}{
		{
			name:     "sum wraps to zero with rounding correction",
			balances: []uint64{math.MaxUint64},
		},
		{
			// A multi-balance sum beyond the uint64 limit is
			// already rejected when the wire record is decoded,
			// so this case sits exactly at the limit and lets
			// the rounding correction push it over.
			name:     "sum at limit wraps with rounding correction",
			balances: []uint64{math.MaxUint64 - 1, 1},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assetBalances := make(
				[]*rfqmsg.AssetBalance, len(tc.balances),
			)
			for i, amt := range tc.balances {
				assetBalances[i] = rfqmsg.NewAssetBalance(
					asset.ID{0x01}, amt,
				)
			}

			htlcRecord := rfqmsg.NewHtlc(
				assetBalances, fn.None[rfqmsg.ID](),
				fn.None[[]rfqmsg.ID](),
			)

			customRecords, err := htlcRecord.ToCustomRecords()
			require.NoError(t, err)

			resp, err := policy.GenerateInterceptorResponse(
				lndclient.InterceptedHtlc{
					InWireCustomRecords: customRecords,
				},
			)
			require.NoError(t, err)

			// Compute the expected incoming amount using big
			// integer arithmetic, including the rounding
			// correction of one asset unit.
			expectedAmt := rfqmath.NewBigIntFromUint64(0)
			for _, amt := range tc.balances {
				expectedAmt = expectedAmt.Add(
					rfqmath.NewBigIntFromUint64(amt),
				)
			}
			expectedAmt = expectedAmt.Add(
				rfqmath.NewBigIntFromUint64(1),
			)

			expectedFp := new(rfqmath.BigIntFixedPoint).SetIntValue(
				expectedAmt,
			)
			expectedMsat, err := rfqmath.UnitsToMilliSatoshi(
				expectedFp, policy.BidAssetRate,
			)
			require.NoError(t, err)

			require.Equal(t, expectedMsat, resp.IncomingAmount)
			require.NotZero(t, resp.IncomingAmount)
		})
	}
}

// mockForwardStore is a minimal ForwardStore implementation that only serves
// settled fill lookups.
type mockForwardStore struct {
	settledFill map[rfqmsg.ID]uint64
	err         error
}

func (m *mockForwardStore) UpsertForward(context.Context, ForwardInput) error {
	return nil
}

func (m *mockForwardStore) PendingForwards(
	context.Context) ([]ForwardInput, error) {

	return nil, nil
}

func (m *mockForwardStore) QueryForwardsWithCount(context.Context,
	QueryForwardsParams) ([]ForwardingEvent, int64, error) {

	return nil, 0, nil
}

func (m *mockForwardStore) SettledFillByRfqID(
	context.Context) (map[rfqmsg.ID]uint64, error) {

	return m.settledFill, m.err
}

// TestRestoreSettledFill tests that restoreSettledFill applies the persisted
// settled fill to restored policies, so that settled quote capacity stays
// consumed across a restart.
func TestRestoreSettledFill(t *testing.T) {
	t.Parallel()

	// Rate of 100 asset units per BTC, so 1 unit = 1e9 msat. The quote cap
	// is 100 units, hence the policy max is 1e11 msat.
	const unitMsat = lnwire.MilliSatoshi(1_000_000_000)

	spec := asset.NewSpecifierFromId(asset.ID{0x01})
	peer := route.Vertex{0x0A}
	rate := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(100, 0),
		time.Now().Add(time.Hour),
	)

	buyReq := &rfqmsg.BuyRequest{
		Peer:           peer,
		AssetSpecifier: spec,
		AssetMaxAmt:    100,
	}
	accept := rfqmsg.BuyAccept{
		Peer:      peer,
		Request:   *buyReq,
		AssetRate: rate,
	}

	policy := NewAssetSalePolicy(accept, false, nil)

	// 80 units (8e10 msat) settled before the restart.
	settledFill := map[rfqmsg.ID]uint64{
		policy.RfqID(): uint64(80 * unitMsat),
		// An entry for an unknown RFQ ID must be ignored.
		{0xFF}: uint64(50 * unitMsat),
	}

	handler, err := NewOrderHandler(OrderHandlerCfg{
		ForwardStore: &mockForwardStore{settledFill: settledFill},
	})
	require.NoError(t, err)

	handler.policies.Store(policy.AcceptedQuoteId.Scid(), policy)

	ctx := context.Background()
	require.NoError(t, handler.restoreSettledFill(ctx))

	scid := lnwire.NewShortChanIDFromInt(
		uint64(policy.AcceptedQuoteId.Scid()),
	)

	// A new 80-unit HTLC must be rejected: only 20 units of lifetime
	// capacity remain.
	require.Error(t, policy.CheckHtlcCompliance(
		ctx, capTestHtlc(scid, 1, 80), nil,
	))

	// A 20-unit HTLC must still be accepted.
	require.NoError(t, policy.CheckHtlcCompliance(
		ctx, capTestHtlc(scid, 2, 20), nil,
	))

	// An error from the forward store must be propagated.
	handler, err = NewOrderHandler(OrderHandlerCfg{
		ForwardStore: &mockForwardStore{err: fmt.Errorf("db error")},
	})
	require.NoError(t, err)
	require.ErrorContains(
		t, handler.restoreSettledFill(ctx), "db error",
	)

	// A nil forward store (forwarding event logging disabled) must be a
	// no-op.
	handler, err = NewOrderHandler(OrderHandlerCfg{})
	require.NoError(t, err)
	require.NoError(t, handler.restoreSettledFill(ctx))
}

// TestAssetSalePolicyRejectsNonBtcHtlc verifies that a standalone sale
// policy rejects incoming HTLCs that do not pay in BTC: HTLCs flagged
// no-op (lnd returns their BTC value to the sender at settle) and HTLCs
// carrying asset records (asset-denominated input the sale never
// validated). Regression test for TA-042.
func TestAssetSalePolicyRejectsNonBtcHtlc(t *testing.T) {
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
		AssetMaxAmt:    100,
	}
	policy := NewAssetSalePolicy(rfqmsg.BuyAccept{
		Peer:      peer,
		Request:   *buyReq,
		AssetRate: rate,
	}, false, nil)

	scid := lnwire.NewShortChanIDFromInt(
		uint64(policy.AcceptedQuoteId.Scid()),
	)

	// Case 1: the incoming HTLC carries only the no-op flag. lnd will
	// convert the add to a NoOpAdd and credit the amount back to the
	// sender at settle (lnwallet entryTypeForHtlc/evaluateNoOpHtlc), so
	// the sale must reject it.
	noopTLV := uint64(lnwallet.NoOpHtlcTLVEntry.TypeVal())
	htlc := lndclient.InterceptedHtlc{
		IncomingCircuitKey: testCircuitKey(1),
		OutgoingChannelID:  scid,
		AmountInMsat:       500_000_000,
		AmountOutMsat:      500_000_000,
		InWireCustomRecords: map[uint64][]byte{
			noopTLV: {},
		},
	}

	err := policy.CheckHtlcCompliance(context.Background(), htlc, nil)
	require.ErrorContains(t, err, "no-op")
	require.Zero(t, policy.CurrentAmountMsat)

	// Case 2: the incoming HTLC carries asset records instead of BTC
	// value. The equal-amount msat check passes, but the sale must
	// reject the asset-denominated input.
	assetRecords := rfqmsg.NewHtlc(
		[]*rfqmsg.AssetBalance{
			rfqmsg.NewAssetBalance(asset.ID{0x02}, 1),
		},
		fn.Some(policy.AcceptedQuoteId), fn.None[[]rfqmsg.ID](),
	)
	customRecords, err := lnwire.ParseCustomRecords(assetRecords.Bytes())
	require.NoError(t, err)

	htlc.IncomingCircuitKey = testCircuitKey(2)
	htlc.InWireCustomRecords = customRecords

	err = policy.CheckHtlcCompliance(context.Background(), htlc, nil)
	require.ErrorContains(t, err, "asset records")
	require.Zero(t, policy.CurrentAmountMsat)

	// A plain BTC-paying HTLC without custom records must still pass.
	htlc.IncomingCircuitKey = testCircuitKey(3)
	htlc.InWireCustomRecords = nil
	require.NoError(t, policy.CheckHtlcCompliance(
		context.Background(), htlc, nil,
	))
	require.Equal(t, htlc.AmountOutMsat, policy.CurrentAmountMsat)
}
