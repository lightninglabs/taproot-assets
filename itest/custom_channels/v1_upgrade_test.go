//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightninglabs/taproot-assets/tapscript"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsV1Upgrade tests the upgrade path of a taproot assets
// channel. It upgrades one of the peers to a version that utilizes feature bits
// and new features over the channel, testing that backwards compatibility is
// maintained along the way. We also introduce a channel breach, right at the
// point before we switched over to the new features, to test that sweeping is
// done properly.
func testCustomChannelsV1Upgrade(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	// TODO(darioAnongba): This test requires backward compatibility
	// infrastructure to run one node on an older binary. Skip until the
	// harness supports historical binary fixtures.
	t.t.Skip("requires backward compatibility infrastructure")

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	zane := net.NewNode("Zane", lndArgs, tapdArgs)

	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType, zane.RPCAddr(),
	))

	daveLndArgs := append(
		slices.Clone(lndArgs), "--nolisten", "--minbackoff=1h",
	)

	// For this simple test, we'll just have Charlie -> Dave as an assets
	// channel.
	dave := net.NewNode("Dave", daveLndArgs, tapdArgs)
	charlie := net.NewNode("Charlie", lndArgs, tapdArgs)

	// Next we'll connect all the nodes and also fund them with some
	// coins.
	nodes := []*itest.IntegratedNode{dave, charlie}
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

	t.Logf("Minted %d itest asset cents, syncing universes...",
		cents.Amount)

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

	// With the channel open, mine 6 blocks to confirm it.
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
		t.t, zane, assetID, nil, fundingScriptTreeBytes,
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

	logBalance(t.t, nodes, assetID, "start")

	// Let's dispatch 5 asset & 5 keysend payments from Charlie to Dave.
	// At this point Charlie is running the old version.
	for range 5 {
		sendAssetKeySendPayment(
			t.t, charlie, dave, 50, assetID, fn.None[int64](),
		)
		sendKeySendPayment(t.t, charlie, dave, 1_000)
	}

	logBalance(t.t, nodes, assetID, "before upgrade")

	// Let's assert that Charlie & Dave actually run different versions
	// of taproot-assets. We expect Dave to be running the latest
	// version, while Charlie is running an older version.
	daveInfo, err := asTapd(dave).GetInfo(
		ctx, &taprpc.GetInfoRequest{},
	)
	require.NoError(t.t, err)

	charlieInfo, err := asTapd(charlie).GetInfo(
		ctx, &taprpc.GetInfoRequest{},
	)
	require.NoError(t.t, err)

	require.NotEqual(t.t, daveInfo.Version, charlieInfo.Version)

	res, err := charlie.ChannelBalance(
		ctx, &lnrpc.ChannelBalanceRequest{},
	)
	require.NoError(t.t, err)

	charlieSatsBefore := res.LocalBalance

	// Now we'll restart Charlie and assert that he upgraded. We also
	// back up the DB at this point, in order to induce a breach later
	// right at the switching point before upgrading the channel. We
	// will verify that the breach transaction will be swept by the
	// right party.
	require.NoError(t.t, net.StopAndBackupDB(charlie))
	connectAllNodes(t.t, net, nodes)

	charlieInfo, err = asTapd(charlie).GetInfo(
		ctx, &taprpc.GetInfoRequest{},
	)
	require.NoError(t.t, err)

	// Dave and Charlie should both be running the same version (latest).
	require.Equal(t.t, daveInfo.Version, charlieInfo.Version)

	// Let's send another 5 asset payments from Charlie to Dave.
	// Charlie is now on the latest version and the channel upgraded.
	for range 5 {
		sendAssetKeySendPayment(
			t.t, charlie, dave, 50, assetID, fn.None[int64](),
		)
	}

	res, err = charlie.ChannelBalance(
		ctx, &lnrpc.ChannelBalanceRequest{},
	)
	require.NoError(t.t, err)

	charlieSatsAfter := res.LocalBalance

	// Because of no-op HTLCs, the satoshi balance of Charlie should not
	// have shifted while sending the asset payments.
	require.Equal(t.t, charlieSatsBefore, charlieSatsAfter)

	logBalance(t.t, nodes, assetID, "after upgrade")

	// Now let's restart Charlie and restore the DB to the previous
	// snapshot which corresponds to a previous (invalid) and unupgraded
	// channel state.
	require.NoError(t.t, net.StopAndRestoreDB(charlie))

	// With Charlie restored, we'll now execute the force close.
	t.Logf("Force close by Charlie to breach...")
	charlieChanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(assetFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: assetFundResp.Txid,
		},
	}
	_, breachTxid, err := net.CloseChannel(
		charlie, charlieChanPoint, true,
	)
	require.NoError(t.t, err)

	t.Logf("Channel closed! Mining blocks, close_txid=%v", breachTxid)

	// Next, we'll mine a block to confirm the breach transaction.
	mineBlocks(t, net, 1, 1)

	// We should be able to find the transfer of the breach for both
	// parties.
	charlieBreachTransfer := locateAssetTransfers(
		t.t, charlie, *breachTxid,
	)
	locateAssetTransfers(t.t, dave, *breachTxid)

	require.Len(t.t, charlieBreachTransfer.Outputs, 2)
	assetOutput := charlieBreachTransfer.Outputs[0]
	assertUniverseProofExists(
		t.t, zane, assetID, nil, assetOutput.ScriptKey,
		assetOutput.Anchor.Outpoint,
	)

	op, err := wire.NewOutPointFromString(assetOutput.Anchor.Outpoint)
	require.NoError(t.t, err)

	// We'll manually export the proof of the breach transfer, in order
	// to verify that it indeed did not use STXO proofs.
	proofResp, err := asTapd(dave).ExportProof(
		ctx, &taprpc.ExportProofRequest{
			AssetId:   assetID,
			ScriptKey: assetOutput.ScriptKey,
			Outpoint: &taprpc.OutPoint{
				Txid:        op.Hash[:],
				OutputIndex: op.Index,
			},
		},
	)
	require.NoError(t.t, err)

	proofFile, err := proof.DecodeFile(proofResp.RawProofFile)
	require.NoError(t.t, err)
	require.Equal(t.t, proofFile.NumProofs(), 3)
	latestProof, err := proofFile.LastProof()
	require.NoError(t.t, err)

	// This proof should not contain the STXO exclusion proofs, since
	// the breach occurred right before the channel upgraded.
	stxoProofs := latestProof.ExclusionProofs[0].CommitmentProof.STXOProofs
	require.Nil(t.t, stxoProofs)

	// With the breach transaction mined, Dave should now have a
	// transaction in the mempool sweeping *both* commitment outputs.
	daveJusticeTxid, err := waitForNTxsInMempool(
		net.Miner, 1, time.Second*5,
	)
	require.NoError(t.t, err)

	t.Logf("Dave justice txid: %v", daveJusticeTxid)

	// Next, we'll mine a block to confirm Dave's justice transaction.
	mineBlocks(t, net, 1, 1)

	// Dave should now have a transfer for his justice transaction.
	daveJusticeTransfer := locateAssetTransfers(
		t.t, dave, *daveJusticeTxid[0],
	)

	// Dave should claim all of the asset balance that was put into the
	// channel.
	daveBalance := uint64(fundingAmount)

	assertBalance(
		t.t, dave, daveBalance, itest.WithAssetID(assetID),
		itest.WithNumUtxos(2),
	)

	t.Logf("Dave balance after breach: %d", daveBalance)

	require.Len(t.t, daveJusticeTransfer.Outputs, 2)
	assetOutput = daveJusticeTransfer.Outputs[0]
	op, err = wire.NewOutPointFromString(assetOutput.Anchor.Outpoint)
	require.NoError(t.t, err)

	// We'll now also export the proof for the justice transaction. Here
	// we expect to find STXO proofs, as the sweeping party is an
	// upgraded node that supports it.
	proofResp, err = asTapd(dave).ExportProof(
		ctx, &taprpc.ExportProofRequest{
			AssetId:   assetID,
			ScriptKey: assetOutput.ScriptKey,
			Outpoint: &taprpc.OutPoint{
				Txid:        op.Hash[:],
				OutputIndex: op.Index,
			},
		},
	)
	require.NoError(t.t, err)

	proofFile, err = proof.DecodeFile(proofResp.RawProofFile)
	require.NoError(t.t, err)
	require.Equal(t.t, 4, proofFile.NumProofs())
	latestProof, err = proofFile.LastProof()
	require.NoError(t.t, err)

	// This proof should contain the STXO exclusion proofs.
	stxoProofs = latestProof.InclusionProof.CommitmentProof.STXOProofs
	require.NotNil(t.t, stxoProofs)
}
