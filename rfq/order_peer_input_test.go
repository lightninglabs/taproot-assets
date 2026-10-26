package rfq

import (
	"context"
	"testing"
	"time"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestHandleIncomingHtlcPeerInputFailures is a regression test for issue #118.
// An intercepted HTLC is fully peer-controlled input: a malicious or buggy
// peer can attach malformed custom records, or craft an RFQ ID / channel SCID
// combination that doesn't match the stored policies. Such failures must be
// answered with a fail resolution for the offending HTLC. Returning a Go
// error instead would tear down the whole HTLC interception stream, which
// tapd treats as a critical error, taking the daemon down with it.
func TestHandleIncomingHtlcPeerInputFailures(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// malformedHtlc returns an HTLC whose asset-balance custom record is
	// truncated, so it cannot be parsed.
	malformedHtlc := func(htlcID uint64) lndclient.InterceptedHtlc {
		return lndclient.InterceptedHtlc{
			IncomingCircuitKey: testCircuitKey(htlcID),
			AmountOutMsat:      1_000,
			InWireCustomRecords: map[uint64][]byte{
				// Asset balance record with a truncated
				// payload: it
				// announces one balance but doesn't contain its
				// asset ID and amount.
				65536: {0x01},
			},
		}
	}

	t.Run("malformed custom records", func(t *testing.T) {
		t.Parallel()

		handler := newTestOrderHandler(t, newMockHtlcInterceptor())

		resp, err := handler.handleIncomingHtlc(ctx, malformedHtlc(1))
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, lndclient.InterceptorActionFail, resp.Action)
	})

	t.Run("crafted rfq id scid combination", func(t *testing.T) {
		t.Parallel()

		handler := newTestOrderHandler(t, newMockHtlcInterceptor())

		// The incoming HTLC carries an RFQ ID whose SCID resolves to an
		// asset sale policy, while the outgoing channel SCID also has a
		// policy attached. An asset-to-asset forward requires an asset
		// purchase policy on the incoming side, so constructing the
		// forward policy fails. Both the RFQ ID and the outgoing SCID
		// are chosen by the peer that sent the HTLC.
		inPolicy, _ := capTestSalePolicy(t)
		outPolicy, outScid := capTestSalePolicy(t)
		handler.policies.Store(
			SerialisedScid(inPolicy.Scid()), inPolicy,
		)
		handler.policies.Store(
			SerialisedScid(outPolicy.Scid()), outPolicy,
		)

		// Build the custom records that carry the incoming policy's RFQ
		// ID, exactly as a peer would.
		htlcRecord := rfqmsg.NewHtlc(
			nil, fn.Some(inPolicy.AcceptedQuoteId),
			fn.None[[]rfqmsg.ID](),
		)
		customRecords, err := htlcRecord.ToCustomRecords()
		require.NoError(t, err)

		htlc := lndclient.InterceptedHtlc{
			IncomingCircuitKey:  testCircuitKey(1),
			OutgoingChannelID:   outScid,
			AmountOutMsat:       1_000,
			InWireCustomRecords: customRecords,
		}

		resp, err := handler.handleIncomingHtlc(ctx, htlc)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, lndclient.InterceptorActionFail, resp.Action)
	})

	// A well-formed HTLC that no policy applies to must still be resumed,
	// so the fail answers above are not just a blanket rejection.
	t.Run("well formed htlc resumed", func(t *testing.T) {
		t.Parallel()

		handler := newTestOrderHandler(t, newMockHtlcInterceptor())

		htlcRecord := rfqmsg.NewHtlc(
			[]*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(asset.ID{0x01}, 1),
			},
			fn.None[rfqmsg.ID](), fn.None[[]rfqmsg.ID](),
		)
		customRecords, err := htlcRecord.ToCustomRecords()
		require.NoError(t, err)

		htlc := lndclient.InterceptedHtlc{
			IncomingCircuitKey:  testCircuitKey(2),
			OutgoingChannelID:   lnwire.NewShortChanIDFromInt(999),
			AmountOutMsat:       1_000,
			InWireCustomRecords: customRecords,
		}

		resp, err := handler.handleIncomingHtlc(ctx, htlc)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, lndclient.InterceptorActionResume, resp.Action)
	})
}

// TestPurchaseResponseOverflow checks the post-compliance conversion failure.
// The balance sum itself is legal, but the foreign asset overflows msats.
func TestPurchaseResponseOverflow(t *testing.T) {
	ctx := context.Background()
	id, err := rfqmsg.NewID()
	require.NoError(t, err)
	purchase := NewAssetPurchasePolicy(rfqmsg.SellAccept{
		ID: id,
		Request: rfqmsg.SellRequest{
			AssetSpecifier: asset.NewSpecifierFromId(asset.ID{1}),
			PaymentMaxAmt:  100 * capTestUnitMsat,
		},
		AssetRate: rfqmsg.NewAssetRate(
			rfqmath.NewBigIntFixedPoint(capTestUnitsPerBtc, 0),
			time.Now().Add(time.Hour),
		),
	})
	h := newTestOrderHandler(t, newMockHtlcInterceptor())
	h.policies.Store(id.Scid(), purchase)
	h.cfg.AcceptHtlcEvents = make(chan *AcceptHtlcEvent, 1)
	h.cfg.SpecifierChecker = func(_ context.Context, _ asset.Specifier,
		got asset.ID) (bool, error) {

		return got == (asset.ID{1}), nil
	}
	record := rfqmsg.NewHtlc([]*rfqmsg.AssetBalance{
		rfqmsg.NewAssetBalance(asset.ID{1}, 80),
		rfqmsg.NewAssetBalance(asset.ID{2}, 100_000_000_000),
	}, fn.Some(id), fn.None[[]rfqmsg.ID]())
	records, err := record.ToCustomRecords()
	require.NoError(t, err)
	htlc := lndclient.InterceptedHtlc{
		IncomingCircuitKey:  testCircuitKey(1),
		AmountOutMsat:       80 * capTestUnitMsat,
		InWireCustomRecords: records,
	}
	// Prove this reaches response generation, not compliance rejection.
	require.NoError(t, purchase.CheckHtlcCompliance(
		ctx, htlc, h.cfg.SpecifierChecker,
	))
	purchase.UntrackHtlc(htlc.IncomingCircuitKey)
	_, err = purchase.GenerateInterceptorResponse(htlc)
	require.ErrorIs(t, err, ErrPeerInput)
	resp, err := h.handleIncomingHtlc(ctx, htlc)
	require.NoError(t, err)
	require.Equal(t, lndclient.InterceptorActionFail, resp.Action)
	// lnd reports the failed resolution through the HTLC subscription.
	h.handleHtlcFail(ctx, htlc.IncomingCircuitKey)
	require.Zero(t, purchase.CurrentAmountMsat)
	_, tracked := h.htlcToPolicy.Load(htlc.IncomingCircuitKey)
	require.False(t, tracked)
}
