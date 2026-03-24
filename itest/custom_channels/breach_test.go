//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightninglabs/taproot-assets/tapscript"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsBreach tests the breach/justice scenario for custom
// channels. Dave backs up his DB state, one more payment advances the state,
// then Dave restores the old state and force-closes (broadcasting a revoked
// commitment). Charlie detects the breach and sweeps both outputs, recovering
// all channel funds.
func testCustomChannelsBreach(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	// Bump the fee rate so the justice transaction has enough fee to
	// pass btcd's minimum relay fee check. The default FeePerKwFloor
	// is borderline for the larger justice transaction.
	net.FeeService.SetFeeRate(chainfee.SatPerKWeight(1000), 1)

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// We use Charlie as the proof courier. But in order for Charlie to
	// also use itself, we need to define its port upfront.
	charliePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, charliePort),
	))

	// Charlie will be the breached party. We set --nolisten to ensure
	// Dave won't be able to connect to him and trigger the channel
	// protection logic automatically. We also can't have Charlie
	// automatically reconnect too early, otherwise DLP would be
	// initiated instead of the breach we want to provoke.
	charlieLndArgs := append(
		slices.Clone(lndArgs), "--nolisten", "--minbackoff=1h",
	)
	charlieLndArgs = append(charlieLndArgs, fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", charliePort,
	))

	// For this simple test, we'll just have Charlie -> Dave as an assets
	// channel.
	charlie := net.NewNode("Charlie", charlieLndArgs, tapdArgs)
	dave := net.NewNode("Dave", lndArgs, tapdArgs)

	// Next we'll connect all the nodes and also fund them with some
	// coins.
	nodes := []*itest.IntegratedNode{charlie, dave}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Now we'll make an asset for Charlie that we'll use in the test to
	// open a channel.
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
	syncUniverses(t.t, charlie, dave)
	t.Logf("Universes synced between all nodes, distributing assets...")

	// Next we can open an asset channel from Charlie -> Dave, then kick
	// off the main scenario.
	t.Logf("Opening asset channels...")
	assetFundResp, err := asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel between Charlie and Dave: %v", assetFundResp)

	// With the channel open, mine a block to confirm it.
	mineBlocks(t, net, 6, 1)

	// A transfer for the funding transaction should be found in
	// Charlie's DB.
	fundingTxid, err := chainhash.NewHashFromStr(assetFundResp.Txid)
	require.NoError(t.t, err)
	locateAssetTransfers(t.t, charlie, *fundingTxid)

	// Charlie's balance should reflect that the funding asset is now
	// excluded from balance reporting by tapd.
	assertBalance(
		t.t, charlie, ccItestAsset.Amount-fundingAmount,
		itest.WithAssetID(assetID), itest.WithNumUtxos(1),
	)

	// Make sure that Charlie properly uploaded funding proof to the
	// Universe server.
	fundingScriptTree := tapscript.NewChannelFundingScriptTree()
	fundingScriptKey := fundingScriptTree.TaprootKey
	fundingScriptTreeBytes := fundingScriptKey.SerializeCompressed()
	assertUniverseProofExists(
		t.t, charlie, assetID, nil, fundingScriptTreeBytes,
		fmt.Sprintf(
			"%v:%v", assetFundResp.Txid,
			assetFundResp.OutputIndex,
		),
	)

	// Make sure the channel shows the correct asset information.
	assertAssetChan(
		t.t, charlie, dave, fundingAmount, []*taprpc.Asset{cents},
	)

	// Before we start sending out payments, let's make sure each node
	// can see the other one in the graph and has all required features.
	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))

	// Next, we'll make keysend payments from Charlie to Dave. We'll use
	// this to reach a state where both parties have funds in the channel.
	const (
		numPayments   = 5
		keySendAmount = 100
		btcAmt        = int64(5_000)
	)
	for i := 0; i < numPayments; i++ {
		sendAssetKeySendPayment(
			t.t, charlie, dave, keySendAmount, assetID,
			fn.Some(btcAmt),
		)
	}

	logBalance(t.t, nodes, assetID, "after keysend -- breach state")

	// Now we'll create an on disk snapshot that we'll use to restore
	// back to as our breached state.
	require.NoError(t.t, net.StopAndBackupDB(dave))
	connectAllNodes(t.t, net, nodes)

	// We'll send one more keysend payment now to revoke the state we
	// were just at above.
	sendAssetKeySendPayment(
		t.t, charlie, dave, keySendAmount, assetID, fn.Some(btcAmt),
	)
	logBalance(t.t, nodes, assetID, "after keysend -- final state")

	// With the final state achieved, we'll now restore Dave (who will
	// be force closing) to that old state, the breach state.
	require.NoError(t.t, net.StopAndRestoreDB(dave))

	// With Dave restored, we'll now execute the force close.
	t.Logf("Force close by Dave to breach...")
	daveChanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(assetFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: assetFundResp.Txid,
		},
	}
	_, breachTxid, err := net.CloseChannel(dave, daveChanPoint, true)
	require.NoError(t.t, err)

	t.Logf("Channel closed! Mining blocks, close_txid=%v", breachTxid)

	// Next, we'll mine a block to confirm the breach transaction.
	mineBlocks(t, net, 1, 1)

	// We should be able to find the transfer of the breach for both
	// parties.
	locateAssetTransfers(t.t, charlie, *breachTxid)
	locateAssetTransfers(t.t, dave, *breachTxid)

	// With the breach transaction mined, Charlie should now have a
	// transaction in the mempool sweeping *both* commitment outputs.
	// We use a generous timeout because Charlie needs to process the
	// block, detect the breach, and construct the justice transaction.
	charlieJusticeTxid, err := waitForNTxsInMempool(
		net.Miner, 1, time.Second*30,
	)
	require.NoError(t.t, err)

	t.Logf("Charlie justice txid: %v", charlieJusticeTxid)

	// Next, we'll mine a block to confirm Charlie's justice transaction.
	mineBlocks(t, net, 1, 1)

	// Charlie should now have a transfer for his justice transaction.
	locateAssetTransfers(t.t, charlie, *charlieJusticeTxid[0])

	// Charlie's balance should now be the same as before the breach
	// attempt: the amount he minted at the very start.
	charlieBalance := ccItestAsset.Amount
	assertBalance(
		t.t, charlie, charlieBalance, itest.WithAssetID(assetID),
		itest.WithNumUtxos(3),
	)

	t.Logf("Charlie balance after breach: %d", charlieBalance)
}
