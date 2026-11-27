//go:build itest

package custom_channels

import (
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/stretchr/testify/require"
)

// restoreCompatCommit is the pre-fix release used by
// TestBtcHtlcForceCloseRestore. It is affected by issue 2393 and
// negotiates asset channels with the current build.
const restoreCompatCommit = "v0.8.9"

// testCustomChannelsBtcHtlcRemoteForceClose is a regression test for
// https://github.com/lightninglabs/taproot-assets/issues/2393. Alice pays a
// plain BTC invoice of Bob over the asset channel, so the HTLC carries no
// assets. Bob holds the HTLC and force closes. Alice must import the
// commitment (which requires an exclusion proof for the plain HTLC output)
// and fully resolve the remote close.
func testCustomChannelsBtcHtlcRemoteForceClose(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

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

	chanPoint := openAssetChannel(ctx, t, net, alice, bob, assetID)

	// Alice pays a plain BTC hold invoice of Bob over the asset
	// channel, and Bob force closes with the BTC-only HTLC still in
	// flight.
	preimage := btcHtlcRemoteForceClose(ctx, t, net, alice, bob, chanPoint)

	// Bob claims the held HTLC on chain with the preimage.
	settleInvoice(t.t, bob, preimage)

	// Alice must fully resolve the remote close. With the bug, importing
	// the commitment fails on the missing exclusion proof for the plain
	// HTLC output, and the channel is stuck in waiting close.
	assertChannelFullyResolved(ctx, net, t, alice, chanPoint)

	// Alice's assets were in the channel and must come back once the
	// sweep of her commitment output confirms.
	assertBalance(t.t, alice, ccItestAsset.Amount)
}

// TestBtcHtlcForceCloseRestore tests that a channel that got stuck in
// waiting close because of issue 2393 is resolved after upgrading to the
// fixed version. Alice runs the pre-fix build, which cannot import the
// force-close commitment that carries a plain BTC-only HTLC output. After
// she is upgraded to the current build and restarted, the close is driven
// to completion.
func TestBtcHtlcForceCloseRestore(t *testing.T) {
	oldBinary := buildCompatBinary(t, restoreCompatCommit)
	t.Logf("Using compat binary for %s: %s", restoreCompatCommit,
		oldBinary)

	runWithCompatHarness(t, func(ctx context.Context,
		net *itest.IntegratedNetworkHarness, ht *ccHarnessTest) {

		lndArgs := slices.Clone(lndArgsTemplate)
		tapdArgs := slices.Clone(tapdArgsTemplate)

		zane := net.NewNode("Zane", lndArgs, tapdArgs)

		tapdArgs = append(tapdArgs, fmt.Sprintf(
			"--proofcourieraddr=%s://%s",
			proof.UniverseRpcCourierType, zane.RPCAddr(),
		))

		// Alice runs the pinned pre-fix binary, Bob runs the
		// current build. Nodes on a custom binary do not get the
		// harness's default binary args, so the universe TLS skip
		// flag is passed explicitly.
		alice := net.NewNodeWithBinary(
			"Alice", oldBinary, lndArgs, append(
				slices.Clone(tapdArgs),
				"--universe.tls.insecure",
			),
		)
		bob := net.NewNode("Bob", lndArgs, tapdArgs)

		nodes := []*itest.IntegratedNode{alice, bob}
		connectAllNodes(t, net, nodes)
		fundAllNodes(t, net, nodes)

		mintedAssets := itest.MintAssetsConfirmBatch(
			t, net.Miner, asTapd(alice),
			[]*mintrpc.MintAssetRequest{{Asset: ccItestAsset}},
		)
		assetID := mintedAssets[0].AssetGenesis.AssetId
		syncUniverses(t, alice, bob)

		chanPoint := openAssetChannel(ctx, ht, net, alice, bob, assetID)

		// Alice pays a plain BTC hold invoice of Bob over the asset
		// channel, and Bob force closes with the BTC-only HTLC
		// still in flight.
		preimage := btcHtlcRemoteForceClose(
			ctx, ht, net, alice, bob, chanPoint,
		)

		// Bob claims the held HTLC on chain with the preimage while
		// Alice is still on the old binary.
		settleInvoice(t, bob, preimage)
		mineBlocks(ht, net, 3, 0)

		// Alice's old binary cannot import the commitment, so her
		// channel stays in waiting close.
		require.Never(t, func() bool {
			state, err := channelState(ctx, alice, chanPoint)
			if err != nil {
				ht.Logf("pre-upgrade channel state error: %v",
					err)

				return false
			}
			ht.Logf("pre-upgrade Alice channel state=%s", state)

			return state == "closed"
		}, 30*time.Second, 5*time.Second, "Alice unexpectedly "+
			"resolved the close on the old binary")

		// Upgrade Alice to the current build. On startup lnd
		// re-detects the confirmed commitment and re-runs the close
		// flow, and the fixed tapd imports the commitment this time.
		net.UpgradeNode(alice)

		assertChannelFullyResolved(ctx, net, ht, alice, chanPoint)
		assertChannelFullyResolved(ctx, net, ht, bob, chanPoint)

		// Alice's assets were in the channel and must come back
		// once the sweep of her commitment output confirms.
		assertBalance(t, alice, ccItestAsset.Amount)
	})
}

// openAssetChannel funds an asset channel from funder to peer and returns
// the channel point once the channel is active.
func openAssetChannel(ctx context.Context, t *ccHarnessTest,
	net *itest.IntegratedNetworkHarness, funder,
	peer *itest.IntegratedNode, assetID []byte) *lnrpc.ChannelPoint {

	assetFundResp, err := funder.FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         peer.PubKey[:],
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

	require.NoError(t.t, net.AssertNodeKnown(funder, peer))
	require.NoError(t.t, net.AssertNodeKnown(peer, funder))
	assertChannelOutboundPolicyKnown(t.t, funder, chanPoint)

	return chanPoint
}

// btcHtlcRemoteForceClose sets up the issue 2393 scenario: payer pays a
// plain BTC hold invoice of payee over the channel, and payee force closes
// with the BTC-only HTLC still in flight. It returns the invoice preimage.
func btcHtlcRemoteForceClose(ctx context.Context, t *ccHarnessTest,
	net *itest.IntegratedNetworkHarness, payer,
	payee *itest.IntegratedNode, chanPoint *lnrpc.ChannelPoint,
) lntypes.Preimage {

	// The payee holds a plain BTC invoice, so the HTLC carries no
	// assets. The amount must be economically sweepable on regtest:
	// below that, both the payee's claim and the payer's timeout sweep
	// fail with "tx has no output", and the close takes unnecessarily
	// long to resolve.
	var preimage lntypes.Preimage
	_, _ = rand.Read(preimage[:])
	payHash := preimage.Hash()

	holdInvoice, err := payee.InvoicesClient.AddHoldInvoice(
		ctx, &invoicesrpc.AddHoldInvoiceRequest{
			Value: 5_000,
			Hash:  payHash[:],
		},
	)
	require.NoError(t.t, err)

	// The asset channel is the only route, so lnd sends a BTC-only HTLC
	// over it.
	payPayReqWithSatoshi(
		t.t, payer, holdInvoice.PaymentRequest,
		withFailure(lnrpc.Payment_IN_FLIGHT, failureNone),
	)
	assertMinNumHtlcs(t.t, payer, 1)

	// The payee force closes with the BTC-only HTLC still in flight.
	_, closeTxid, err := net.CloseChannel(payee, chanPoint, true)
	require.NoError(t.t, err)
	t.Logf("force closed with txid %v", closeTxid)

	mineBlocks(t, net, 1, 1)

	return preimage
}

// settleInvoice settles the hold invoice with the given preimage.
func settleInvoice(t *testing.T, node *itest.IntegratedNode,
	preimage lntypes.Preimage) {

	_, err := node.InvoicesClient.SettleInvoice(
		context.Background(),
		&invoicesrpc.SettleInvoiceMsg{
			Preimage: preimage[:],
		},
	)
	require.NoError(t, err)
}

// assertChannelFullyResolved mines blocks until the channel shows up in the
// node's closed channels list.
func assertChannelFullyResolved(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest,
	node *itest.IntegratedNode, chanPoint *lnrpc.ChannelPoint) {

	deadline := time.Now().Add(5 * time.Minute)
	for {
		state, err := channelState(ctx, node, chanPoint)
		require.NoError(t.t, err)
		t.Logf("channel state=%s", state)

		if state == "closed" {
			return
		}

		require.Less(
			t.t, time.Now(), deadline,
			"channel did not reach closed state",
		)

		mineBlocks(t, net, 1, 0)
		time.Sleep(2 * time.Second)
	}
}

// channelState reports which lnd list holds the channel, so a missing
// channel is never mistaken for a resolved one.
func channelState(ctx context.Context, node *itest.IntegratedNode,
	chanPoint *lnrpc.ChannelPoint) (string, error) {

	want := fmt.Sprintf("%s:%d", chanPoint.GetFundingTxidStr(),
		chanPoint.OutputIndex)

	closed, err := node.ClosedChannels(
		ctx, &lnrpc.ClosedChannelsRequest{},
	)
	if err != nil {
		return "", err
	}
	for _, ch := range closed.Channels {
		if ch.ChannelPoint == want {
			return "closed", nil
		}
	}

	pending, err := node.PendingChannels(
		ctx, &lnrpc.PendingChannelsRequest{},
	)
	if err != nil {
		return "", err
	}
	for _, ch := range pending.WaitingCloseChannels {
		if ch.Channel.ChannelPoint == want {
			return "waiting_close", nil
		}
	}
	for _, ch := range pending.PendingForceClosingChannels {
		if ch.Channel.ChannelPoint == want {
			return "pending_force_closing", nil
		}
	}

	open, err := node.ListChannels(ctx, &lnrpc.ListChannelsRequest{})
	if err != nil {
		return "", err
	}
	for _, ch := range open.Channels {
		if ch.ChannelPoint == want {
			return "open", nil
		}
	}

	return "not_found", nil
}
