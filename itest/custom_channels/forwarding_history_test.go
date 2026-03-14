//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsForwardingHistory tests that forwarding events are properly
// recorded and queryable via the ForwardingHistory RPC.
//
// Topology:
//
//	Charlie --[assets]--> Dave --[sats]--> Erin --[assets]--> Fabia
//
// The test sends a payment from Charlie to Fabia, then verifies that both
// Dave (purchase side) and Erin (sale side) have correctly logged forwarding
// events with the expected fields, filters, and pagination.
func testCustomChannelsForwardingHistory(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	charliePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, charliePort),
	))

	charlieLndArgs := slices.Clone(lndArgs)
	charlieLndArgs = append(charlieLndArgs, fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", charliePort,
	))
	charlie := net.NewNode("Charlie", charlieLndArgs, tapdArgs)
	dave := net.NewNode("Dave", lndArgs, tapdArgs)
	erin := net.NewNode("Erin", lndArgs, tapdArgs)
	fabia := net.NewNode("Fabia", lndArgs, tapdArgs)
	yara := net.NewNode("Yara", lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{charlie, dave, erin, fabia, yara}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Create the normal (BTC) channel between Dave and Erin.
	t.Logf("Opening normal channel between Dave and Erin...")
	channelOp := openChannelAndAssert(
		t, net, dave, erin, lntest.OpenChannelParams{
			Amt:         10_000_000,
			SatPerVByte: 5,
		},
	)
	defer closeChannelAndAssert(t, net, dave, channelOp, false)

	// Everyone needs to know about the only public channel.
	assertChannelKnown(t.t, charlie, channelOp)
	assertChannelKnown(t.t, fabia, channelOp)

	// Mint an asset on Charlie and sync universes.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{
			{
				Asset: ccItestAsset,
			},
		},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId

	t.Logf("Minted %d lightning cents, syncing universes...",
		cents.Amount)
	syncUniverses(t.t, charlie, dave, erin, fabia, yara)
	t.Logf("Universes synced, creating asset network...")

	const (
		assetSendAmount   = uint64(400_000)
		daveFundingAmount = uint64(400_000)
		erinFundingAmount = uint64(200_000)
	)
	charlieFundingAmount := cents.Amount - (2 * assetSendAmount)

	createTestAssetNetwork(
		t, net, charlie, dave, erin, fabia, yara, charlie,
		cents, assetSendAmount, charlieFundingAmount,
		daveFundingAmount, erinFundingAmount, DefaultPushSat,
	)

	// Ensure nodes know each other in the graph.
	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))
	require.NoError(t.t, net.AssertNodeKnown(erin, fabia))
	require.NoError(t.t, net.AssertNodeKnown(fabia, erin))
	require.NoError(t.t, net.AssertNodeKnown(charlie, erin))

	logBalance(t.t, nodes, assetID, "initial")

	// Record timestamp before payment for filtering tests.
	timestampBeforePayment := uint64(time.Now().Unix())

	// Send a payment from Charlie to Fabia through Dave and Erin.
	const invoiceAssetAmount = 20_000
	invoiceResp := createAssetInvoice(
		t.t, erin, fabia, invoiceAssetAmount, assetID,
	)
	payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp.PaymentRequest, assetID,
	)
	logBalance(t.t, nodes, assetID, "after payment")

	// --------------------------------------------------------------------
	// Verify forwarding history on Dave (purchase side).
	// Dave receives assets from Charlie and forwards sats to Erin.
	// --------------------------------------------------------------------
	t.Logf("Verifying forwarding history on Dave...")

	daveResp, daveFwd := waitForForwardingEvent(
		ctx, t.t, asTapd(dave),
		&rfqrpc.ForwardingHistoryRequest{},
		func(e *rfqrpc.ForwardingEvent) bool {
			return e.SettledAt > 0 && e.FailedAt == 0
		},
	)

	// Verify Dave's forwarding event fields.
	require.NotEmpty(t.t, daveFwd.RfqId)
	require.Equal(
		t.t, rfqrpc.RfqPolicyType_RFQ_POLICY_TYPE_PURCHASE,
		daveFwd.PolicyType,
	)
	require.Equal(t.t, charlie.PubKeyStr, daveFwd.Peer)
	require.NotNil(t.t, daveFwd.AssetSpec)
	require.Equal(t.t, assetID, daveFwd.AssetSpec.Id)
	require.GreaterOrEqual(
		t.t, daveFwd.AssetAmt, uint64(invoiceAssetAmount),
	)
	require.Greater(t.t, daveFwd.AmtOutMsat, daveFwd.AmtInMsat)
	require.GreaterOrEqual(t.t, daveFwd.SettledAt, daveFwd.OpenedAt)
	require.Zero(t.t, daveFwd.FailedAt)
	require.NotNil(t.t, daveFwd.Rate)
	require.NotEmpty(t.t, daveFwd.Rate.Coefficient)
	require.Equal(t.t, int64(1), daveResp.TotalCount)

	// --------------------------------------------------------------------
	// Verify forwarding history on Erin (sale side).
	// Erin receives sats from Dave and forwards assets to Fabia.
	// --------------------------------------------------------------------
	erinResp, erinFwd := waitForForwardingEvent(
		ctx, t.t, asTapd(erin),
		&rfqrpc.ForwardingHistoryRequest{},
		func(e *rfqrpc.ForwardingEvent) bool {
			return e.SettledAt > 0 && e.FailedAt == 0
		},
	)

	// Verify Erin's forwarding event fields.
	require.NotEmpty(t.t, erinFwd.RfqId)
	require.Equal(
		t.t, rfqrpc.RfqPolicyType_RFQ_POLICY_TYPE_SALE,
		erinFwd.PolicyType,
	)
	require.Equal(t.t, fabia.PubKeyStr, erinFwd.Peer)
	require.NotNil(t.t, erinFwd.AssetSpec)
	require.Equal(t.t, assetID, erinFwd.AssetSpec.Id)
	require.InDelta(
		t.t, invoiceAssetAmount, erinFwd.AssetAmt, 1,
	)
	require.Greater(t.t, erinFwd.AmtInMsat, erinFwd.AmtOutMsat)
	require.GreaterOrEqual(t.t, erinFwd.SettledAt, erinFwd.OpenedAt)
	require.Zero(t.t, erinFwd.FailedAt)
	require.NotNil(t.t, erinFwd.Rate)
	require.NotEmpty(t.t, erinFwd.Rate.Coefficient)
	require.Equal(t.t, int64(1), erinResp.TotalCount)

	// --------------------------------------------------------------------
	// Test query filters on Erin's forwarding history.
	// --------------------------------------------------------------------

	// Timestamp filter: min_timestamp should include the forward.
	resp, err := asTapd(erin).ForwardingHistory(
		ctx, &rfqrpc.ForwardingHistoryRequest{
			MinTimestamp: timestampBeforePayment,
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, resp.Forwards, 1)

	// Timestamp filter: max_timestamp before payment should exclude it.
	resp, err = asTapd(erin).ForwardingHistory(
		ctx, &rfqrpc.ForwardingHistoryRequest{
			MaxTimestamp: timestampBeforePayment - 10,
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, resp.Forwards, 0)

	// Peer filter: Fabia should match.
	resp, err = asTapd(erin).ForwardingHistory(
		ctx, &rfqrpc.ForwardingHistoryRequest{
			Peer: fabia.PubKey[:],
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, resp.Forwards, 1)

	// Peer filter: Charlie should not match on Erin.
	resp, err = asTapd(erin).ForwardingHistory(
		ctx, &rfqrpc.ForwardingHistoryRequest{
			Peer: charlie.PubKey[:],
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, resp.Forwards, 0)

	// Asset filter: correct asset ID should match.
	resp, err = asTapd(erin).ForwardingHistory(
		ctx, &rfqrpc.ForwardingHistoryRequest{
			AssetSpecifier: &rfqrpc.AssetSpecifier{
				Id: &rfqrpc.AssetSpecifier_AssetId{
					AssetId: assetID,
				},
			},
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, resp.Forwards, 1)

	// Asset filter: wrong asset ID should not match.
	wrongAssetID := make([]byte, 32)
	for i := range wrongAssetID {
		wrongAssetID[i] = 0xab
	}
	resp, err = asTapd(erin).ForwardingHistory(
		ctx, &rfqrpc.ForwardingHistoryRequest{
			AssetSpecifier: &rfqrpc.AssetSpecifier{
				Id: &rfqrpc.AssetSpecifier_AssetId{
					AssetId: wrongAssetID,
				},
			},
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, resp.Forwards, 0)

	// Pagination: offset past existing results should return empty.
	resp, err = asTapd(erin).ForwardingHistory(
		ctx, &rfqrpc.ForwardingHistoryRequest{
			Limit:  100,
			Offset: 10,
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, resp.Forwards, 0)
	require.Equal(t.t, int64(1), resp.TotalCount)

	// Charlie and Fabia are endpoints, not forwarders — they should
	// have no forwarding events.
	charlieResp, err := asTapd(charlie).ForwardingHistory(
		ctx, &rfqrpc.ForwardingHistoryRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, charlieResp.Forwards, 0)

	fabiaResp, err := asTapd(fabia).ForwardingHistory(
		ctx, &rfqrpc.ForwardingHistoryRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, fabiaResp.Forwards, 0)
}

// waitForForwardingEvent polls the ForwardingHistory RPC until an event
// matching the given predicate appears. It returns both the full response and
// the matched event.
func waitForForwardingEvent(ctx context.Context, t *testing.T,
	client *tapdAdapter, req *rfqrpc.ForwardingHistoryRequest,
	match func(*rfqrpc.ForwardingEvent) bool) (
	*rfqrpc.ForwardingHistoryResponse, *rfqrpc.ForwardingEvent) {

	t.Helper()

	var (
		resp     *rfqrpc.ForwardingHistoryResponse
		matchEvt *rfqrpc.ForwardingEvent
	)
	err := wait.NoError(func() error {
		var err error
		resp, err = client.ForwardingHistory(ctx, req)
		if err != nil {
			return err
		}

		for _, fwd := range resp.Forwards {
			if match(fwd) {
				matchEvt = fwd
				return nil
			}
		}

		return fmt.Errorf("no matching forwarding event found "+
			"in %d events", len(resp.Forwards))
	}, wait.DefaultTimeout)
	require.NoError(t, err, "timed out waiting for forwarding event")

	return resp, matchEvt
}
