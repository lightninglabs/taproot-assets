package rfq

import (
	"testing"
	"time"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/graph/db/models"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

// Regression tests for the lifetime quote fill cap. A quote's maximum amount
// must bound the total volume traded over the quote's lifetime: admission
// reserves capacity, settlement permanently consumes it, and only failure
// restores the failed reservation.
//
// Setup numbers: rate = 100 asset units per BTC, so 1 unit = 1e9 msat.
// Quote cap = 100 units, hence policyMaxOutMsat = 1e11 msat.

const (
	capTestUnitsPerBtc = 100
	capTestUnitMsat    = lnwire.MilliSatoshi(1_000_000_000) // 1 unit
)

func capTestSalePolicy(t *testing.T) (*AssetSalePolicy, lnwire.ShortChannelID) {
	t.Helper()

	id, err := rfqmsg.NewID()
	require.NoError(t, err)

	spec := asset.NewSpecifierFromId(asset.ID{0x01})
	peer := route.Vertex{0x0A}
	rate := rfqmsg.NewAssetRate(
		rfqmath.NewBigIntFixedPoint(capTestUnitsPerBtc, 0),
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
		ID:        id,
	}

	policy := NewAssetSalePolicy(accept, false, nil)
	scid := lnwire.NewShortChanIDFromInt(uint64(id.Scid()))

	return policy, scid
}

// capTestHtlc returns an HTLC intercept descriptor carrying the given amount
// in asset units, identified by the given HTLC ID on the policy's channel.
func capTestHtlc(scid lnwire.ShortChannelID, htlcID uint64,
	units uint64) lndclient.InterceptedHtlc {

	return lndclient.InterceptedHtlc{
		IncomingCircuitKey: models.CircuitKey{
			ChanID: scid,
			HtlcID: htlcID,
		},
		OutgoingChannelID: scid,
		AmountOutMsat:     lnwire.MilliSatoshi(units) * capTestUnitMsat,
	}
}

// capTestSalePolicySameQuote rebuilds a policy from the same persisted quote
// data, mirroring restorePersistedPolicies (NewAssetSalePolicy on the stored
// BuyAccept, fresh in-memory counters).
func capTestSalePolicySameQuote(t *testing.T,
	old *AssetSalePolicy) (*AssetSalePolicy, lnwire.ShortChannelID) {

	t.Helper()

	accept := rfqmsg.BuyAccept{
		Peer: old.peer,
		Request: rfqmsg.BuyRequest{
			Peer:           old.peer,
			AssetSpecifier: old.AssetSpecifier,
			AssetMaxAmt:    100,
		},
		AssetRate: rfqmsg.NewAssetRate(
			old.AskAssetRate,
			time.Now().Add(time.Hour),
		),
		ID: old.AcceptedQuoteId,
	}

	policy := NewAssetSalePolicy(accept, false, nil)
	scid := lnwire.NewShortChanIDFromInt(
		uint64(policy.AcceptedQuoteId.Scid()),
	)

	return policy, scid
}

// TestSalePolicySettledFillStaysConsumed asserts that a settled HTLC
// permanently consumes quote capacity: an 80-unit HTLC settles against a
// 100-unit quote, then a second 80-unit HTLC must be rejected because only 20
// units of lifetime capacity remain.
func TestSalePolicySettledFillStaysConsumed(t *testing.T) {
	policy, scid := capTestSalePolicy(t)

	key1 := models.CircuitKey{ChanID: scid, HtlcID: 1}

	// Admit the first 80-unit HTLC. Compliance checking tracks the HTLC
	// atomically.
	require.NoError(t,
		policy.CheckHtlcCompliance(nil, capTestHtlc(scid, 1, 80), nil))

	// While it is in flight, a concurrent second 80 must be rejected.
	require.Error(t,
		policy.CheckHtlcCompliance(nil, capTestHtlc(scid, 2, 80), nil))

	// The first HTLC settles. handleHtlcSettle calls SettleHtlc.
	policy.SettleHtlc(key1)

	// Settlement permanently consumes capacity. Only 20 units remain, so a
	// second 80-unit HTLC must still be rejected.
	require.Error(t,
		policy.CheckHtlcCompliance(nil, capTestHtlc(scid, 2, 80), nil),
		"settled quote capacity must not become reusable")

	// A 20-unit HTLC must still be accepted.
	require.NoError(t,
		policy.CheckHtlcCompliance(nil, capTestHtlc(scid, 3, 20), nil),
		"remaining 20 units of capacity must stay usable")
}

// TestSalePolicyFailedFillRestoresCapacity asserts that a failed HTLC
// releases its reservation, so an identical retry is admitted.
func TestSalePolicyFailedFillRestoresCapacity(t *testing.T) {
	policy, scid := capTestSalePolicy(t)

	key1 := models.CircuitKey{ChanID: scid, HtlcID: 1}

	require.NoError(t,
		policy.CheckHtlcCompliance(nil, capTestHtlc(scid, 1, 80), nil))

	// The HTLC fails. handleHtlcFail calls UntrackHtlc, which restores the
	// failed reservation.
	policy.UntrackHtlc(key1)

	require.NoError(t,
		policy.CheckHtlcCompliance(nil, capTestHtlc(scid, 2, 80), nil))
}

// TestSalePolicySettledFillRestoredAfterRestart asserts that settled fill
// survives a daemon restart: after 80 units settle and the policy is rebuilt
// from the persisted quote, restoreSettledFill re-applies the settled fill
// reconstructed from the persisted forwarding events, so a new 80-unit HTLC
// must be rejected.
func TestSalePolicySettledFillRestoredAfterRestart(t *testing.T) {
	policy, scid := capTestSalePolicy(t)

	key1 := models.CircuitKey{ChanID: scid, HtlcID: 1}

	require.NoError(t,
		policy.CheckHtlcCompliance(nil, capTestHtlc(scid, 1, 80), nil))
	policy.SettleHtlc(key1) // settle

	// Simulate restart: the policy is rebuilt from the persisted accept
	// message exactly as restorePersistedPolicies does, with zeroed
	// in-memory counters.
	restartedPolicy, restartedScid := capTestSalePolicySameQuote(t, policy)

	// restoreSettledFill then applies the settled fill reconstructed from
	// the persisted forwarding events (the settled 80-unit HTLC).
	restartedPolicy.AddSettledFill(80 * capTestUnitMsat)

	require.Error(t,
		restartedPolicy.CheckHtlcCompliance(
			nil, capTestHtlc(restartedScid, 2, 80), nil,
		),
		"restart must not reset settled fill accounting")

	// The remaining 20 units of capacity must stay usable.
	require.NoError(t,
		restartedPolicy.CheckHtlcCompliance(
			nil, capTestHtlc(restartedScid, 3, 20), nil,
		),
		"remaining 20 units of capacity must stay usable")
}
