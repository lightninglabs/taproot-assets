//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsBtcDustLimitBalance pays a plain BTC invoice over a
// new asset channel, so the receiver's BTC balance ends up exactly at
// the dust limit (354 sat) with no assets. Repro for the dust limit
// equality bug related to issue 2393: lnd keeps a balance output when
// amount >= dust limit, tapd only allocates when amount > dust limit.
func testCustomChannelsBtcDustLimitBalance(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	const dustLimitSats = 354

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	zane := net.NewNode("Zane", lndArgs, tapdArgs)

	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType, zane.RPCAddr(),
	))

	alice := net.NewNode("Alice", lndArgs, tapdArgs)
	bob := net.NewNode("Bob", lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{alice, bob}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner, asTapd(alice),
		[]*mintrpc.MintAssetRequest{{Asset: ccItestAsset}},
	)
	assetID := mintedAssets[0].AssetGenesis.AssetId
	syncUniverses(t.t, alice, bob)

	assetFundResp, err := alice.FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         bob.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)

	chanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(assetFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: assetFundResp.Txid,
		},
	}
	mineBlocks(t, net, 6, 1)

	assertChannelOutboundPolicyKnown(t.t, alice, chanPoint)

	invoice, err := bob.LightningClient.AddInvoice(ctx, &lnrpc.Invoice{
		Value: dustLimitSats,
	})
	require.NoError(t.t, err)

	payPayReqWithSatoshi(t.t, alice, invoice.PaymentRequest)
	t.Logf("Payment of %d sat succeeded", dustLimitSats)

	time.Sleep(5 * time.Second)
	state := assetChannelState(ctx, t, alice, chanPoint)
	t.Logf("Alice view of the asset channel: %s", state)

	require.Equal(
		t.t, "active, no pending htlcs", state,
		"the asset channel failed after the BTC balance of Bob "+
			"reached the dust limit",
	)
	t.Logf("RESULT: the asset channel stayed usable")
}

// assetChannelState describes the channel from node's view: whether it
// is active and how many HTLCs are still on it.
func assetChannelState(ctx context.Context, t *ccHarnessTest,
	node *itest.IntegratedNode, chanPoint *lnrpc.ChannelPoint) string {

	want := fmt.Sprintf("%s:%d", chanPoint.GetFundingTxidStr(),
		chanPoint.OutputIndex)

	resp, err := node.ListChannels(ctx, &lnrpc.ListChannelsRequest{})
	require.NoError(t.t, err)
	for _, ch := range resp.Channels {
		if ch.ChannelPoint != want {
			continue
		}

		activity := "inactive"
		if ch.Active {
			activity = "active"
		}
		if len(ch.PendingHtlcs) == 0 {
			return activity + ", no pending htlcs"
		}

		numHtlcs := len(ch.PendingHtlcs)
		return fmt.Sprintf("%s, %d pending htlcs (first: %d sat)",
			activity, numHtlcs, ch.PendingHtlcs[0].Amount)
	}

	return "not open"
}
