//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsRestartCoopClose exercises the path where the channel
// initiator restarts after the cooperative close transaction has been
// broadcast but before it confirms on-chain. Before the fix, tapd's
// per-channel close state was kept only in memory (the assetCloseInfo
// map), so a restart in this window left FinalizeClose unable to find the
// stashed vPackets when the close tx finally confirmed. That error
// propagated up through the chain watcher and blocked MarkChannelClosed,
// leaving the channel stuck in "waiting close" on the restarted side.
// With the persistence layer in place, both sides converge to a closed
// channel even after the restart.
func testCustomChannelsRestartCoopClose(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// Stand Charlie up on a known port so he can act as the proof
	// courier for both himself and Dave (mirrors the breach test's
	// topology, minimum viable proof distribution).
	charliePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, charliePort),
	))

	charlieLndArgs := append(slices.Clone(lndArgs), fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", charliePort,
	))

	// Charlie is the side we restart between broadcast and confirmation.
	charlie := net.NewNode("Charlie", charlieLndArgs, tapdArgs)
	dave := net.NewNode("Dave", lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{charlie, dave}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{
			{Asset: ccItestAsset},
		},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId

	t.Logf("Minted %d cents, syncing universes...", cents.Amount)
	syncUniverses(t.t, charlie, dave)

	t.Logf("Opening asset channel Charlie -> Dave...")
	assetFundResp, err := asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel: %v", assetFundResp)

	mineBlocks(t, net, 6, 1)

	chanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(assetFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: assetFundResp.Txid,
		},
	}

	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))

	// Initiate cooperative close from Charlie. This drives the shutdown /
	// closing-signed exchange and broadcasts the close tx to the mempool.
	// Both sides' tapd instances populate their in-memory
	// assetCloseInfo[ChanPoint] entry inside AuxCloseOutputs at this
	// point.
	t.Logf("Initiating coop close from Charlie...")
	_, _, err = net.CloseChannel(charlie, chanPoint, false)
	require.NoError(t.t, err)

	// Checkpoint: close tx is in the mempool but not yet confirmed.
	// AuxCloseOutputs has run on both sides; FinalizeClose has not.
	assertWaitingCloseChannelAssetData(t.t, charlie, chanPoint)
	assertWaitingCloseChannelAssetData(t.t, dave, chanPoint)

	// Restart Charlie. This wipes tapd's in-memory assetCloseInfo map.
	// The close tx stays in btcd's mempool.
	t.Logf("Restarting Charlie between coop broadcast and confirmation")
	charlie.Restart()

	net.EnsureConnected(t.t, charlie, dave)

	// Confirm the close. Charlie's chain_watcher fires
	// dispatchCooperativeClose, which calls tapd's FinalizeClose.
	// Before the fix, the in-memory closeInfo was lost and finalize
	// returned "no vPackets found for ChannelPoint(...)", which
	// prevented MarkChannelClosed from being called and left the
	// channel stuck pending on Charlie. With the persistence layer the
	// recovery path picks up where the pre-restart instance left off.
	t.Logf("Mining close tx confirmations post-restart...")
	mineBlocks(t, net, 6, 1)

	// Dave is unaffected by the restart; he should always reach Closed.
	// Charlie is the one that exercises the regression; before the
	// fix his assertion will time out.
	assertClosedChannelAssetData(t.t, dave, chanPoint)
	assertClosedChannelAssetData(t.t, charlie, chanPoint)
}
