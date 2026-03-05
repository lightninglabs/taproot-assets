//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightninglabs/taproot-assets/tapscript"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsForceClose tests a force close scenario where both parties
// have an active asset balance after keysend payments, the channel is force
// closed, and both sides sweep their outputs. It then verifies that both
// parties can spend the swept outputs in normal on-chain transfers.
//
//nolint:lll
func testCustomChannelsForceClose(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// Explicitly set the proof courier as Zane (now has no other role
	// other than proof shuffling), otherwise a hashmail courier will be
	// used. For the funding transaction, we're just posting it and don't
	// expect a true receiver.
	zane := net.NewNode("Zane", lndArgs, tapdArgs)

	// For our tapd args, make sure that they all seen Zane as the main
	// Universe server.
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType, zane.RPCAddr(),
	))

	// For this simple test, we'll just have Carol -> Dave as an assets
	// channel.
	charlie := net.NewNode("Charlie", lndArgs, tapdArgs)
	dave := net.NewNode("Dave", lndArgs, tapdArgs)

	// Next we'll connect all the nodes and also fund them with some coins.
	nodes := []*itest.IntegratedNode{charlie, dave}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Now we'll make an asset for Charlie that we'll use in the test to
	// open a channel.
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

	t.Logf("Minted %d lightning cents, syncing universes...", cents.Amount)
	syncUniverses(t.t, charlie, dave)
	t.Logf("Universes synced between all nodes, distributing assets...")

	// Before we actually create the asset channel, we want to make sure
	// that failed attempts of creating a channel (e.g. due to insufficient
	// on-chain funds) are cleaned up properly on the recipient side.
	// We do this by sending all of Charlie's coins to a burn address then
	// just sending him 50k sats, which isn't enough to fund a channel.
	_, err := charlie.SendCoins(
		ctx, &lnrpc.SendCoinsRequest{
			Addr:             burnAddr,
			SendAll:          true,
			MinConfs:         0,
			SpendUnconfirmed: true,
		},
	)
	require.NoError(t.t, err)
	net.SendCoins(t.t, 50_000, charlie)

	// The attempt should fail. But the recipient should receive the error,
	// clean up the state and allow Charlie to try again after acquiring
	// more funds.
	_, err = asTapd(charlie).FundChannel(ctx, &tchrpc.FundChannelRequest{
		AssetAmount:        fundingAmount,
		AssetId:            assetID,
		PeerPubkey:         dave.PubKey[:],
		FeeRateSatPerVbyte: 5,
	})
	require.ErrorContains(t.t, err, "not enough witness outputs to create")

	// Now we'll fund the channel with the correct amount.
	net.SendCoins(t.t, btcutil.SatoshiPerBitcoin, charlie)

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

	// A transfer for the funding transaction should be found in Charlie's
	// DB.
	fundingTxid, err := chainhash.NewHashFromStr(assetFundResp.Txid)
	require.NoError(t.t, err)
	locateAssetTransfers(t.t, charlie, *fundingTxid)

	// Charlie's balance should reflect that the funding asset is now
	// excluded from balance reporting by tapd.
	assertBalance(
		t.t, charlie, ccItestAsset.Amount-fundingAmount,
		itest.WithAssetID(assetID),
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

	// Before we start sending out payments, let's make sure each node can
	// see the other one in the graph and has all required features.
	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))

	// We'll also have dave sync with Charlie+Zane to ensure he has the
	// proof for the funding output. We sync the transfers as well so he
	// has all the proofs needed.
	mode := unirpc.UniverseSyncMode_SYNC_FULL
	_, err = asTapd(dave).SyncUniverse(
		ctx, &unirpc.SyncRequest{
			UniverseHost: zane.RPCAddr(),
			SyncMode:     mode,
		},
	)
	require.NoError(t.t, err)

	// With the channel confirmed, we'll push over some keysend payments
	// from Carol to Dave. We'll send over a bit more BTC each time so
	// Dave will go to chain sweep his output (default fee rate is 50
	// sat/vb).
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

	logBalance(t.t, nodes, assetID, "after keysend")

	// With the payments sent, we'll now go on chain with a force close
	// from Carol.
	t.Logf("Force closing channel...")
	charlieChanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(assetFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: assetFundResp.Txid,
		},
	}
	_, closeTxid, err := net.CloseChannel(
		charlie, charlieChanPoint, true,
	)
	require.NoError(t.t, err)

	t.Logf("Channel closed! Mining blocks, close_txid=%v", closeTxid)

	// Next, we'll mine a block to confirm the force close.
	mineBlocks(t, net, 1, 1)

	// At this point, we should have the force close transaction in the set
	// of transfers for both nodes.
	forceCloseTransfer := findForceCloseTransfer(
		t.t, charlie, dave, closeTxid,
	)
	// Now that we have the transfer on disk, we'll also assert that the
	// universe also has proof for both the relevant transfer outputs.
	for _, transfer := range forceCloseTransfer.Transfers {
		for _, transferOut := range transfer.Outputs {
			assertUniverseProofExists(
				t.t, zane, assetID, nil,
				transferOut.ScriptKey,
				transferOut.Anchor.Outpoint,
			)
		}
	}

	t.Logf("Universe proofs located!")

	// We should also have a new sweep transaction in the mempool.
	_, err = waitForNTxsInMempool(
		net.Miner.Client, 1, ccShortTimeout,
	)
	require.NoError(t.t, err)

	// Next, we'll mine a block to confirm Dave's sweep transaction.
	// This'll sweep his non-delay commitment output. We use the txid from
	// the mined block (not the mempool) to avoid RBF mismatches.
	daveSweepBlocks := mineBlocks(t, net, 1, 1)
	daveSweepTxHash := daveSweepBlocks[0].Transactions[1].TxHash()

	t.Logf("Dave sweep txid: %v", daveSweepTxHash)

	// At this point, a transfer should have been created for Dave's sweep
	// transaction.
	locateAssetTransfers(t.t, dave, daveSweepTxHash)

	time.Sleep(time.Second * 1)

	// Next, we'll mine three additional blocks to trigger the CSV delay
	// for Charlie.
	mineBlocks(t, net, 4, 0)

	// We expect that Charlie's sweep transaction has been broadcast.
	charlieSweepTxid, err := waitForNTxsInMempool(
		net.Miner.Client, 1, ccShortTimeout,
	)
	require.NoError(t.t, err)

	t.Logf("Charlie sweep txid: %v", charlieSweepTxid)

	// Now we'll mine a block to confirm Charlie's sweep transaction.
	mineBlocks(t, net, 1, 0)

	// Both sides should now reflect their updated asset balances.
	daveBalance := uint64(numPayments * keySendAmount)
	charlieBalance := ccItestAsset.Amount - daveBalance
	assertBalance(
		t.t, dave, daveBalance, itest.WithAssetID(assetID),
		itest.WithNumUtxos(1),
	)
	assertBalance(
		t.t, charlie, charlieBalance, itest.WithAssetID(assetID),
		itest.WithNumUtxos(2),
	)

	// We'll make sure Dave can spend his asset UTXO by sending it all but
	// one unit to Zane (the universe).
	assetSendAmount := daveBalance - 1
	zaneAddr, err := asTapd(zane).NewAddr(ctx, &taprpc.NewAddrRequest{
		Amt:     assetSendAmount,
		AssetId: assetID,
		ProofCourierAddr: fmt.Sprintf(
			"%s://%s", proof.UniverseRpcCourierType,
			charlie.RPCAddr(),
		),
	})
	require.NoError(t.t, err)

	t.Logf("Sending %v asset from Dave units to Zane...", assetSendAmount)

	// Send the assets to Zane. We expect Dave to have 3 transfers: the
	// funding txn, their force close sweep, and now this new send.
	itest.AssertAddrCreated(t.t, asTapd(zane), cents, zaneAddr)
	sendResp, err := dave.SendAsset(ctx, &taprpc.SendAssetRequest{
		TapAddrs: []string{zaneAddr.Encoded},
	})
	require.NoError(t.t, err)
	itest.ConfirmAndAssertOutboundTransfer(
		t.t, net.Miner.Client, asTapd(dave), sendResp, assetID,
		[]uint64{1, assetSendAmount}, 2, 3,
	)
	itest.AssertNonInteractiveRecvComplete(t.t, asTapd(zane), 1)

	// And now we also send all assets but one from Charlie to the universe
	// to make sure the time lock sweep output can also be spent correctly.
	assetSendAmount = charlieBalance - 1
	zaneAddr2, err := asTapd(zane).NewAddr(ctx, &taprpc.NewAddrRequest{
		Amt:     assetSendAmount,
		AssetId: assetID,
		ProofCourierAddr: fmt.Sprintf(
			"%s://%s", proof.UniverseRpcCourierType,
			charlie.RPCAddr(),
		),
	})
	require.NoError(t.t, err)

	t.Logf("Sending %v asset from Charlie units to Zane...",
		assetSendAmount)

	itest.AssertAddrCreated(t.t, asTapd(zane), cents, zaneAddr2)
	sendResp2, err := charlie.SendAsset(ctx, &taprpc.SendAssetRequest{
		TapAddrs: []string{zaneAddr2.Encoded},
	})
	require.NoError(t.t, err)
	itest.ConfirmAndAssertOutboundTransfer(
		t.t, net.Miner.Client, asTapd(charlie), sendResp2, assetID,
		[]uint64{1, assetSendAmount}, 3, 4,
	)
	itest.AssertNonInteractiveRecvComplete(t.t, asTapd(zane), 2)
}
