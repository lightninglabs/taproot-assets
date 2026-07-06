package rpcserver

// anchoring_test.go contains unit tests for the ListAnchorings
// marshalling.

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/tapconfig"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/stretchr/testify/require"
)

// TestMarshalAnchoring pins the observability listing's wire shape:
// the phase fields carry the stable phase names — so any listed value
// round-trips through the request's phase filter verbatim — with the
// evidence renderings and delivery bookkeeping alongside.
func TestMarshalAnchoring(t *testing.T) {
	t.Parallel()

	summary := tapdb.AnchoringSummary{
		ID:                7,
		Site:              "minter",
		Threshold:         6,
		CreatedHeight:     812_000,
		Phase:             tapreorg.PhaseCodeBuried,
		PhaseDetail:       "buried(deadbeef@812003)",
		Delivered:         tapreorg.PhaseCodeWitnessed,
		DeliveredDetail:   "witnessed(deadbeef@812003)",
		WitnessTxid:       []byte{0xde, 0xad},
		Stuck:             true,
		DeliveryAttempts:  3,
		LastDeliveryError: "handler down",
		TerminalAt:        1_700_000_000,
		NumCandidates:     2,
	}

	anchoring := marshalAnchoring(summary)
	require.Equal(t, int64(7), anchoring.Id)
	require.Equal(t, "minter", anchoring.Site)
	require.Equal(t, "buried", anchoring.Phase)
	require.Equal(t, summary.PhaseDetail, anchoring.PhaseDetail)
	require.Equal(t, "witnessed", anchoring.DeliveredPhase)
	require.Equal(
		t, summary.DeliveredDetail, anchoring.DeliveredPhaseDetail,
	)
	require.Equal(t, summary.WitnessTxid, anchoring.WitnessTxid)
	require.True(t, anchoring.Stuck)
	require.Equal(t, uint32(3), anchoring.DeliveryAttempts)
	require.Equal(t, "handler down", anchoring.LastDeliveryError)
	require.Equal(t, int64(1_700_000_000), anchoring.TerminalAt)
	require.Equal(t, uint32(2), anchoring.NumCandidates)

	// Every phase name the response can carry resolves back
	// through the filter's parser.
	codes := []tapreorg.PhaseCode{
		tapreorg.PhaseCodeUnwitnessed, tapreorg.PhaseCodeWitnessed,
		tapreorg.PhaseCodeConflicted, tapreorg.PhaseCodeBuried,
		tapreorg.PhaseCodeAbandoned, tapreorg.PhaseCodeWithdrawn,
	}
	for _, code := range codes {
		back, err := tapreorg.PhaseCodeFromName(code.String())
		require.NoError(t, err)
		require.Equal(t, code, back)
	}
}

// TestListAnchoringsRejections covers the listing's request
// validation: a daemon running without the registry refuses cleanly,
// and page bounds and the phase filter are checked before the
// registry is ever consulted.
func TestListAnchoringsRejections(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Without a registry the listing is unavailable.
	r := &RPCServer{cfg: &tapconfig.Config{}}
	_, err := r.ListAnchorings(ctx, &taprpc.ListAnchoringsRequest{})
	require.ErrorContains(t, err, "not available")

	// Rejections must precede any registry access: the zero-value
	// store below fails loudly if a malformed request reaches it.
	r = &RPCServer{cfg: &tapconfig.Config{
		AnchoringRegistry: &tapdb.ReorgRegistryStore{},
	}}

	cases := []struct {
		name string
		req  *taprpc.ListAnchoringsRequest
		want string
	}{{
		name: "negative limit",
		req:  &taprpc.ListAnchoringsRequest{Limit: -1},
		want: "must not be negative",
	}, {
		name: "negative offset",
		req:  &taprpc.ListAnchoringsRequest{Offset: -1},
		want: "must not be negative",
	}, {
		name: "oversized limit",
		req:  &taprpc.ListAnchoringsRequest{Limit: 1001},
		want: "exceeds the maximum page size",
	}, {
		name: "unknown phase",
		req:  &taprpc.ListAnchoringsRequest{Phase: "bogus"},
		want: "unknown phase name",
	}}
	for _, tc := range cases {
		_, err := r.ListAnchorings(ctx, tc.req)
		require.ErrorContains(t, err, tc.want, tc.name)
	}
}
