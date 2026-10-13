package rfq

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/graph/db/models"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

// issue119Store is a ForwardStore faithful to the production schema: the
// forwards table is UNIQUE on (chan_id_in, htlc_id) with an UPSERT that
// overwrites, so there is exactly one row per HTLC. The settled fill queries
// mirror the production SQL: SettledFillByRfqID includes both policy legs,
// and QueryForwardsWithCount returns every row with its settled state.
type issue119Store struct {
	forwards []ForwardInput
	policies []Policy
}

func (s *issue119Store) UpsertForward(_ context.Context,
	in ForwardInput) error {

	// The production upsert is ON CONFLICT(chan_id_in, htlc_id) DO
	// UPDATE: a second row for the same HTLC overwrites the first,
	// including its rfq_id.
	for i := range s.forwards {
		if s.forwards[i].ChanIDIn == in.ChanIDIn &&
			s.forwards[i].HtlcID == in.HtlcID {

			s.forwards[i] = in
			return nil
		}
	}
	s.forwards = append(s.forwards, in)
	return nil
}

func (s *issue119Store) PendingForwards(
	context.Context) ([]ForwardInput, error) {

	var pending []ForwardInput
	for _, f := range s.forwards {
		if f.SettledAt.IsNone() && f.FailedAt.IsNone() {
			pending = append(pending, f)
		}
	}
	return pending, nil
}

func (s *issue119Store) SettledFillByRfqID(
	context.Context) (map[rfqmsg.ID]uint64, error) {

	out := make(map[rfqmsg.ID]uint64)
	for _, f := range s.forwards {
		if f.SettledAt.IsSome() {
			out[f.RfqID] += f.AmtOutMsat
			for _, p := range s.policies {
				_, sale := p.(*AssetSalePolicy)
				isForwardLeg := p.Scid() == f.ChanIDOut &&
					p.RfqID() != f.RfqID
				if sale && isForwardLeg {
					out[p.RfqID()] += f.AmtOutMsat
				}
			}
		}
	}
	return out, nil
}

func (s *issue119Store) QueryForwardsWithCount(_ context.Context,
	params QueryForwardsParams) ([]ForwardingEvent, int64, error) {

	var events []ForwardingEvent
	for i, f := range s.forwards {
		if int32(len(events)) >= params.Limit {
			break
		}
		if int32(i) < params.Offset {
			continue
		}

		event := ForwardingEvent{
			OpenedAt:   f.OpenedAt,
			RfqID:      f.RfqID,
			ChanIDIn:   f.ChanIDIn,
			ChanIDOut:  f.ChanIDOut,
			HtlcID:     f.HtlcID,
			AssetAmt:   f.AssetAmt,
			AmtInMsat:  f.AmtInMsat,
			AmtOutMsat: f.AmtOutMsat,
		}
		f.SettledAt.WhenSome(func(settledAt time.Time) {
			event.SettledAt = &settledAt
		})

		events = append(events, event)
	}

	return events, int64(len(s.forwards)), nil
}

// TestIssue119SaleLegFillRestoredAfterRestart asserts that the settled fill
// of the OUTGOING sale leg of an asset-to-asset forward survives a restart
// (issue #119). The forwarding event is one row per HTLC keyed by the
// incoming purchase policy's RFQ ID, so the sale leg is restored by summing
// settled rows on the outgoing channel.
func TestIssue119SaleLegFillRestoredAfterRestart(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := fmt.Sprintf("pending_at_restart=%v", pending)
		t.Run(name, func(t *testing.T) {
			testIssue119Restart(t, pending)
		})
	}
}

func testIssue119Restart(t *testing.T, pending bool) {
	ctx := context.Background()

	// An incoming purchase quote on channel A and an outgoing sale quote
	// on channel B, each capping the routed value at 100 asset units.
	spec := asset.NewSpecifierFromId(asset.ID{0x01})
	peerIn := route.Vertex{0x0A}
	rate := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(capTestUnitsPerBtc, 0),
		time.Now().Add(time.Hour),
	)

	inID, err := rfqmsg.NewID()
	require.NoError(t, err)
	sellAccept := rfqmsg.SellAccept{
		Peer: peerIn,
		Request: rfqmsg.SellRequest{
			Peer:           peerIn,
			AssetSpecifier: spec,
			PaymentMaxAmt:  100_000_000_000,
		},
		AssetRate: rate,
		ID:        inID,
	}
	purchase := NewAssetPurchasePolicy(sellAccept)

	sale, saleScid := capTestSalePolicy(t)

	fwd, err := NewAssetForwardPolicy(purchase, sale)
	require.NoError(t, err)

	// The incoming HTLC: 80 asset units over channel A, forwarded over
	// channel B.
	htlcRecord := rfqmsg.NewHtlc(
		[]*rfqmsg.AssetBalance{
			rfqmsg.NewAssetBalance(asset.ID{0x01}, 80),
		},
		fn.Some(purchase.AcceptedQuoteId), fn.None[[]rfqmsg.ID](),
	)
	customRecords, err := lnwire.ParseCustomRecords(htlcRecord.Bytes())
	require.NoError(t, err)
	specifierChecker := rfqmsg.SpecifierChecker(
		func(_ context.Context, _ asset.Specifier,
			_ asset.ID) (bool, error) {

			return true, nil
		},
	)
	inScid := lnwire.NewShortChanIDFromInt(12345)
	require.NotEqual(t, uint64(purchase.scid), inScid.ToUint64())
	htlc := lndclient.InterceptedHtlc{
		IncomingCircuitKey: models.CircuitKey{
			ChanID: inScid,
			HtlcID: 1,
		},
		OutgoingChannelID:   saleScid,
		AmountOutMsat:       80 * capTestUnitMsat,
		InWireCustomRecords: customRecords,
	}

	// Admit and settle the HTLC on the forward policy: both legs have
	// consumed 80 of their 100 units at runtime.
	require.NoError(t,
		fwd.CheckHtlcCompliance(ctx, htlc, specifierChecker))
	fwd.SettleHtlc(htlc.IncomingCircuitKey)
	require.Error(t,
		sale.CheckHtlcCompliance(
			ctx, capTestHtlc(saleScid, 2, 80), nil,
		),
		"sale leg fill must be consumed after settle")

	// Persist the forwarding event through the production path, then
	// settle the record through the production path as well.
	store := &issue119Store{policies: []Policy{sale}}
	h := &OrderHandler{
		forwardStore: store,
		policies:     lnutils.SyncMap[SerialisedScid, Policy]{},
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
	h.logForwardingEvent(ctx, fwd, htlc, 80)
	if !pending {
		h.handleHtlcSettle(ctx, htlc.IncomingCircuitKey)
	}

	// The persisted record is a single row keyed by the purchase policy's
	// RFQ ID, exactly like the production table (one row per HTLC, the
	// second upsert overwrites the first).
	require.Len(t, store.forwards, 1)
	require.Equal(t, purchase.AcceptedQuoteId, store.forwards[0].RfqID)

	// The aggregate includes both policy legs.
	fill, err := store.SettledFillByRfqID(ctx)
	require.NoError(t, err)
	_, hasSale := fill[sale.AcceptedQuoteId]
	require.Equal(t, !pending, hasSale)

	// Restart: both policies are rebuilt fresh from the persisted quote
	// data, exactly as restorePersistedPolicies does, and are registered
	// in a new order handler whose restoreSettledFill runs against the
	// persisted events.
	restartedPurchase := NewAssetPurchasePolicy(sellAccept)
	restartedSale, restartedSaleScid := capTestSalePolicySameQuote(t, sale)

	restarted := &OrderHandler{
		forwardStore: store,
		policies:     lnutils.SyncMap[SerialisedScid, Policy]{},
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
	restarted.policies.Store(restartedPurchase.scid, restartedPurchase)
	restarted.policies.Store(
		restartedSale.AcceptedQuoteId.Scid(), restartedSale,
	)
	restarted.cfg.HtlcSubscriber = &mockHtlcSubscriber{}
	require.NoError(t, restarted.restorePendingForwards(ctx))
	require.NoError(t, restarted.restoreSettledFill(ctx))

	// Control: the incoming purchase leg's settled fill restored through
	// the row's RFQ ID, so a second 80-unit HTLC over channel A is
	// rejected.
	secondIncoming := htlc
	secondIncoming.IncomingCircuitKey.HtlcID = 2
	require.Error(t, restartedPurchase.CheckHtlcCompliance(
		ctx, secondIncoming, specifierChecker,
	), "incoming leg fill must survive the restart")

	// Regression: the outgoing sale leg's lifetime settled fill must also
	// have survived the restart, restored from the settled row's outgoing
	// channel, so a full 80-unit HTLC over channel B is rejected.
	require.Error(t, restartedSale.CheckHtlcCompliance(
		ctx, capTestHtlc(restartedSaleScid, 3, 80), nil,
	), "sale leg settled fill must survive the restart")

	if pending {
		// A settlement after restart must consume both reservations.
		restarted.handleHtlcSettle(ctx, htlc.IncomingCircuitKey)
		require.Zero(t, restartedPurchase.CurrentAmountMsat)
		require.Zero(t, restartedSale.CurrentAmountMsat)
		require.Error(t, restartedPurchase.CheckHtlcCompliance(
			ctx, secondIncoming, specifierChecker,
		))
		require.Error(t, restartedSale.CheckHtlcCompliance(
			ctx, capTestHtlc(restartedSaleScid, 4, 80), nil,
		))
	}

	// The remaining 20 units remain usable on both legs.
	remaining := secondIncoming
	remaining.IncomingCircuitKey.HtlcID = 5
	remaining.AmountOutMsat = 20 * capTestUnitMsat
	require.NoError(t, restartedPurchase.CheckHtlcCompliance(
		ctx, remaining, specifierChecker,
	))
	require.NoError(t, restartedSale.CheckHtlcCompliance(
		ctx, capTestHtlc(restartedSaleScid, 5, 20), nil,
	))
}

// TestIssue119DirectSaleNotDoubleCounted asserts that a settled direct sale
// on the sale channel (a row keyed by the sale policy's own RFQ ID) is
// restored exactly once: once through the RFQ ID map, and not again through
// the outgoing-channel aggregation.
func TestIssue119DirectSaleNotDoubleCounted(t *testing.T) {
	ctx := context.Background()

	sale, saleScid := capTestSalePolicy(t)
	settledAt := time.Now().UTC()

	store := &issue119Store{policies: []Policy{sale}}
	require.NoError(t, store.UpsertForward(ctx, ForwardInput{
		OpenedAt:   time.Now().UTC(),
		RfqID:      sale.AcceptedQuoteId,
		ChanIDIn:   saleScid.ToUint64(),
		ChanIDOut:  saleScid.ToUint64(),
		HtlcID:     1,
		AssetAmt:   80,
		AmtOutMsat: uint64(80 * capTestUnitMsat),
		SettledAt:  fn.Some(settledAt),
	}))

	h := &OrderHandler{
		forwardStore: store,
		policies:     lnutils.SyncMap[SerialisedScid, Policy]{},
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
	h.policies.Store(sale.AcceptedQuoteId.Scid(), sale)
	require.NoError(t, h.restoreSettledFill(ctx))

	// The single 80-unit direct sale must count exactly once: 20 units of
	// capacity remain, so another 80 is rejected and a 20 is accepted.
	require.Error(t, sale.CheckHtlcCompliance(
		ctx, capTestHtlc(saleScid, 2, 80), nil,
	), "direct sale must count once, not twice")
	require.NoError(t, sale.CheckHtlcCompliance(
		ctx, capTestHtlc(saleScid, 3, 20), nil,
	), "remaining capacity must stay usable")
}

// TestIssue119StorePagination guards the mock's positive-offset behavior.
func TestIssue119StorePagination(t *testing.T) {
	store := &issue119Store{}
	for i := uint64(0); i < 1001; i++ {
		store.forwards = append(store.forwards, ForwardInput{HtlcID: i})
	}
	ctx := context.Background()
	first, total, err := store.QueryForwardsWithCount(ctx,
		QueryForwardsParams{Limit: 1000})
	require.NoError(t, err)
	require.Len(t, first, 1000)
	require.EqualValues(t, 1001, total)
	last, _, err := store.QueryForwardsWithCount(ctx,
		QueryForwardsParams{Limit: 1000, Offset: 1000})
	require.NoError(t, err)
	require.Len(t, last, 1)
	require.EqualValues(t, 1000, last[0].HtlcID)
}
