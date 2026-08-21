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
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsOnChainHtlcIntercept reproduces the bug reported in issue
// #2223, where tapd refuses to (re)start with:
//
//	cannot resume held htlc in the on-chain flow
//
// Topology:
//
//	Charlie --[assets]--> Dave --[sats]--> Erin --[assets]--> Fabia
//
// Fabia creates a hodl invoice which Charlie pays with assets, so the HTLC
// stays in flight on every hop. We then force close the normal Dave <-> Erin
// channel, which means Erin's *incoming* HTLC has to be resolved on chain. Erin
// is an RFQ edge node, so its tapd has an HTLC interceptor registered with lnd.
//
// lnd's contract court offers such an on-chain HTLC to the registered HTLC
// interceptor (tapd's RFQ order handler) via the preimage beacon, and the
// interceptable switch keeps it in its held HTLC set. Any resolution the
// interceptor sends back for an on-chain forward is rejected by lnd with
// ErrCannotResume/ErrCannotFail ("cannot resume in the on-chain flow"), which
// tears down the whole ForwardHtlcInterceptor stream. Since PR #1899, tapd
// treats a failure of the interception stream as a critical error, so the
// daemon shuts down. On a restart the held HTLC is replayed to the freshly
// connected interceptor, so tapd never manages to come up again.
func testCustomChannelsOnChainHtlcIntercept(ctx context.Context,
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

	// Everyone needs to know about the only public channel.
	assertChannelKnown(t.t, charlie, channelOp)
	assertChannelKnown(t.t, fabia, channelOp)

	// Mint an asset on Charlie and sync universes.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{
			{
				Asset: ccItestAsset,
			},
		},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId

	t.Logf("Minted %d lightning cents, syncing universes...", cents.Amount)
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

	// Fabia creates a hodl invoice, so the multi-hop HTLC will be stuck in
	// flight until we force close below.
	const invoiceAssetAmount = 20_000
	hodlInvoice := createAssetHodlInvoice(
		t.t, erin, fabia, invoiceAssetAmount, assetID,
	)

	t.Logf("Charlie paying Fabia's hodl invoice, HTLC will stay in " +
		"flight...")
	payInvoiceWithAssets(
		t.t, charlie, dave, hodlInvoice.payReq, assetID,
		withFailure(lnrpc.Payment_IN_FLIGHT, failureNone),
	)

	// Make sure Dave actually has the forwarded HTLC on both of his
	// channels before we go on chain.
	assertNumHtlcs(t.t, dave, 2)

	logBalance(t.t, nodes, assetID, "with in-flight HTLC")

	// Now we force close the normal channel between Dave and Erin. This
	// forces Erin to resolve its incoming HTLC on chain, which makes lnd
	// hand that HTLC to tapd's HTLC interceptor.
	t.Logf("Force closing the Dave <-> Erin channel...")
	_, closeTxid, err := net.CloseChannel(dave, channelOp, true)
	require.NoError(t.t, err)

	t.Logf("Channel force closed, close_txid=%v, mining blocks...",
		closeTxid)

	// Confirm the force close transaction, which starts the contract
	// resolution on Erin's side.
	mineBlocks(t, net, 1, 1)

	// Erin's contract court now hands the incoming HTLC to the registered
	// HTLC interceptor. tapd must survive that. Before the fix it goes down
	// with a critical error, because lnd rejects any resolution for an
	// on-chain HTLC and tears down the whole interception stream.
	t.Logf("Asserting Erin stays alive during the on-chain resolution...")
	assertNodeAlive(t.t, erin, 30*time.Second)

	// Sanity check that the on-chain HTLC resolution actually started.
	assertPendingForceCloseHtlcs(t.t, erin, 1)

	// And finally, a restart must work as well: on startup lnd replays all
	// held HTLCs (including the on-chain one) to the newly connected
	// interceptor.
	t.Logf("Restarting Erin...")
	erin.Restart()

	assertNodeAlive(t.t, erin, ccShortTimeout)
}

// assertPendingForceCloseHtlcs waits until the given node reports at least the
// given number of pending HTLCs across all its pending force closing channels.
func assertPendingForceCloseHtlcs(t *testing.T, n *itest.IntegratedNode,
	expected int) {

	t.Helper()

	err := wait.NoError(func() error {
		ctxt, cancel := context.WithTimeout(
			context.Background(), ccShortTimeout,
		)
		defer cancel()

		resp, err := n.PendingChannels(
			ctxt, &lnrpc.PendingChannelsRequest{},
		)
		if err != nil {
			return err
		}

		var numHtlcs int
		for _, c := range resp.PendingForceClosingChannels {
			numHtlcs += len(c.PendingHtlcs)
		}

		if numHtlcs < expected {
			return fmt.Errorf("expected at least %d pending "+
				"HTLCs, got %d", expected, numHtlcs)
		}

		return nil
	}, 2*time.Minute)
	require.NoError(t, err)
}

// assertNodeAlive polls the given node's lnd and tapd RPCs for the given
// duration and fails as soon as the daemon stops responding.
//
// NOTE: The poll loop only queries lnd, as tapd's GetInfo blocks while a new
// block is being processed. That is enough to detect the failure we're guarding
// against: the integrated binary runs lnd in-process, so a critical tapd error
// takes lnd down with it. We then check tapd itself once at the end.
func assertNodeAlive(t *testing.T, n *itest.IntegratedNode, d time.Duration) {
	t.Helper()

	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		ctxt, cancel := context.WithTimeout(
			context.Background(), ccShortTimeout,
		)
		_, err := n.LightningClient.GetInfo(
			ctxt, &lnrpc.GetInfoRequest{},
		)
		cancel()

		require.NoErrorf(t, err, "node %s went down", n.Cfg.Name)

		time.Sleep(time.Second)
	}

	// tapd's GetInfo blocks while a new block is being processed, so we
	// allow for a couple of retries here.
	err := wait.NoError(func() error {
		ctxt, cancel := context.WithTimeout(
			context.Background(), ccShortTimeout,
		)
		defer cancel()

		_, err := n.TaprootAssetsClient.GetInfo(
			ctxt, &taprpc.GetInfoRequest{},
		)

		return err
	}, 3*ccShortTimeout)
	require.NoErrorf(
		t, err, "tapd of node %s is not responding", n.Cfg.Name,
	)
}
