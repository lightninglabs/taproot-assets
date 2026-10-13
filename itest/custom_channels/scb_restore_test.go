//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/btcsuite/btcd/chainhash/v2"
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

// testCustomChannelsSCBRestore tests the static channel backup (SCB)
// recovery flow for a Taproot Assets channel. Dave loses his channel DB and
// restores from an SCB, which rebuilds the channel as a shell with the
// TapscriptRoot taken from the backup's CloseTxInputs extension (lnd
// TapscriptRootVersion backups). Charlie then force closes, and Dave's chain
// watcher must detect the spend of the overlay funding output (DLP). This is
// a regression test for lnd#11197: previously the restored shell carried an
// empty TapscriptRoot, so the watcher derived a BIP-86 funding script and
// never saw the force close.
func testCustomChannelsSCBRestore(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	// Bump the fee rate so the sweep transactions have enough fee to
	// pass btcd's minimum relay fee check.
	net.FeeService.SetFeeRate(chainfee.SatPerKWeight(1000), 1)

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// We use Charlie as the proof courier for all parties. In order for
	// Charlie to also use itself, we need to define its RPC port upfront
	// and pin its lnd RPC listener to that port (the universe RPC is
	// served on the same listener in the integrated binary).
	charliePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, charliePort),
	))

	charlieLndArgs := append(
		slices.Clone(lndArgsTemplate),
		fmt.Sprintf("--rpclisten=127.0.0.1:%d", charliePort),
	)
	charlie := net.NewNode("Charlie", charlieLndArgs, tapdArgs)
	dave := net.NewNode("Dave", lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{charlie, dave}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Mint the asset that backs the channel.
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

	syncUniverses(t.t, charlie, dave)

	// Open the asset channel Charlie -> Dave.
	t.Logf("Opening asset channel...")
	assetFundResp, err := asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)

	mineBlocks(t, net, 6, 1)

	fundingTxid, err := chainhash.NewHashFromStr(assetFundResp.Txid)
	require.NoError(t.t, err)
	locateAssetTransfers(t.t, charlie, *fundingTxid)

	fundingScriptTree := tapscript.NewChannelFundingScriptTree()
	fundingScriptKey := fundingScriptTree.TaprootKey
	assertUniverseProofExists(
		t.t, charlie, assetID, nil,
		fundingScriptKey.SerializeCompressed(),
		fmt.Sprintf(
			"%v:%v", assetFundResp.Txid, assetFundResp.OutputIndex,
		),
	)

	assertAssetChan(
		t.t, charlie, dave, fundingAmount, []*taprpc.Asset{cents},
	)

	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))

	// Send some keysend payments so Dave has an asset balance in the
	// channel.
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

	logBalance(t.t, nodes, assetID, "after keysends")

	// Export Dave's SCB for the channel before we destroy his state.
	chanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(assetFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: assetFundResp.Txid,
		},
	}
	chanBackup, err := dave.ExportChannelBackup(
		ctx, &lnrpc.ExportChannelBackupRequest{
			ChanPoint: chanPoint,
		},
	)
	require.NoError(t.t, err)
	require.NotNil(t.t, chanBackup.ChanBackup)

	// Simulate channel state loss on Dave's side: stop the node, remove
	// the lnd channel database, and restart. The node's seed lives in the
	// wallet DB (in the same lnd dir), so we only remove the channel DB.
	dave.Stop()

	lndDir := filepath.Join(dave.Cfg.BaseDir, "lnd")
	chanDBPattern := filepath.Join(
		lndDir, "data", "graph", "regtest", "channel.db*",
	)
	chanDBs, err := filepath.Glob(chanDBPattern)
	require.NoError(t.t, err)
	require.NotEmpty(
		t.t, chanDBs, "expected to find Dave's channel.db to delete",
	)
	for _, dbFile := range chanDBs {
		require.NoError(t.t, os.Remove(dbFile))
	}

	// Restart Dave on the wiped channel DB, then restore the channel
	// shell from the exported SCB. With the fix in lnd#11197, the shell
	// retains the tapscript root from the backup.
	dave.Restart()

	_, err = dave.RestoreChannelBackups(
		ctx, &lnrpc.RestoreChanBackupRequest{
			Backup: &lnrpc.RestoreChanBackupRequest_ChanBackups{
				ChanBackups: &lnrpc.ChannelBackups{
					ChanBackups: []*lnrpc.ChannelBackup{
						chanBackup,
					},
				},
			},
		},
	)
	require.NoError(t.t, err)

	// Dave's persistent peer store survives the channel DB wipe (it lives
	// in the peer store, not channel.db), so he reconnects to Charlie on
	// his own after the restart. An explicit reconnect can therefore fail
	// with "already connected"; all we need is that a connection exists.
	ctxb := context.Background()
	if _, err := charlie.ConnectPeer(ctxb, &lnrpc.ConnectPeerRequest{
		Addr: &lnrpc.LightningAddress{
			Pubkey: dave.PubKeyStr,
			Host:   dave.P2PAddr(),
		},
	}); err != nil {
		require.Contains(t.t, err.Error(), "already connected")
	}

	// Charlie now force closes. With a correct shell, Dave's chain
	// watcher detects the spend of the overlay funding output and sweeps
	// his non-delayed output (DLP).
	t.Logf("Charlie force closing channel (DLP)...")
	_, closeTxid, err := net.CloseChannel(charlie, chanPoint, true)
	require.NoError(t.t, err)

	t.Logf("Channel closed! Mining blocks, close_txid=%v", closeTxid)

	mineBlocks(t, net, 1, 1)

	// Both parties should see the force close as an asset transfer. For
	// Dave this only works if his chain watcher matched the force-close
	// tx against the correct tapscript-root funding script.
	findForceCloseTransfer(t.t, charlie, dave, closeTxid)

	// Dave should promptly broadcast a sweep of his non-delay
	// commitment output.
	daveSweepTxid, err := waitForNTxsInMempool(
		net.Miner, 1, ccShortTimeout,
	)
	require.NoError(t.t, err)

	t.Logf("Dave DLP sweep txid: %v", daveSweepTxid)

	mineBlocks(t, net, 1, 1)

	// Dave's sweep should appear as an asset transfer, and his asset
	// balance should reflect what he had in the channel.
	locateAssetTransfers(t.t, dave, *daveSweepTxid[0])

	daveBalance := uint64(numPayments * keySendAmount)
	assertBalance(
		t.t, dave, daveBalance, itest.WithAssetID(assetID),
		itest.WithNumUtxos(1),
	)

	// Charlie's remaining balance is what he minted minus the assets he
	// sent to Dave, mirroring the force close test's bookkeeping.
	charlieBalance := ccItestAsset.Amount - daveBalance

	// Charlie's output is time locked; mine past the CSV delay and
	// confirm his sweep as well.
	mineBlocks(t, net, 4, 0)

	charlieSweepTxid, err := waitForNTxsInMempool(
		net.Miner, 1, ccShortTimeout,
	)
	require.NoError(t.t, err)

	t.Logf("Charlie sweep txid: %v", charlieSweepTxid)

	mineBlocks(t, net, 1, 0)

	assertBalance(
		t.t, charlie, charlieBalance, itest.WithAssetID(assetID),
		itest.WithNumUtxos(2),
	)
}
