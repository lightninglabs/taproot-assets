//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsFundingReorg exercises a re-org of the asset
// channel funding transaction while the funder's porter anchoring
// sits at the potency tier: the funding confirms once, is re-orged
// out (the anchoring honestly downgrades and the funding returns to
// the mempool), re-confirms on the rewritten chain, and buries at the
// safe depth — after which the channel activates over the re-organized
// funding, carries payments, and closes cleanly.
func testCustomChannelsFundingReorg(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// Zane serves as the proof courier and Universe server.
	zane := net.NewNode("Zane", lndArgs, tapdArgs)
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType, zane.RPCAddr(),
	))

	// Both channel parties run a burial depth deeper than the fork,
	// so their funding anchorings stay at the potency tier through
	// the re-org window instead of absorbing at first confirmation.
	// The channel itself also requires more confirmations than the
	// fork is deep: lnd then computes the channel's short ID from
	// the post-re-org confirmation instead of racing its 1-conf
	// announcement machinery against the fork.
	deepLndArgs := append(
		slices.Clone(lndArgs), "--bitcoin.defaultchanconfs=4",
	)
	deepTapdArgs := append(slices.Clone(tapdArgs), "--reorgsafedepth=6")
	charlie := net.NewNode("Charlie", deepLndArgs, deepTapdArgs)
	dave := net.NewNode("Dave", deepLndArgs, deepTapdArgs)

	nodes := []*itest.IntegratedNode{charlie, dave}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Mint the asset Charlie funds the channel with, and bury the
	// mint past the coming fork point: the re-org under test targets
	// the funding transaction alone. At Charlie's burial depth the
	// universe publication is act-gated, so the leaves are waited on
	// only after the burial blocks.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{{Asset: ccItestAsset}},
		itest.WithNoUniverseLeafWait(),
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId

	mineBlocks(t, net, 5, 0)
	itest.WaitForMintUniverseLeaves(
		t.t, asTapd(charlie), mintedAssets,
	)
	syncUniverses(t.t, charlie, dave)

	// The fork point: the funding confirmation lies past it.
	tempMiner := spawnTempMiner(net)

	// Fund the channel: the funding transaction broadcasts, and the
	// porter stakes the funding transfer as an anchoring the moment
	// it is handed the parcel.
	preFund := listPorterAnchoringIDs(t.t, charlie)

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

	fundingAnchoring := findPorterAnchoring(t.t, charlie, preFund)
	assertAnchoringPhase(t.t, charlie, fundingAnchoring, "unwitnessed")

	// One confirmation is potency, not act: the anchoring
	// witnesses, five confirmations short of its burial depth (and
	// the channel itself is still three short of activating).
	mineBlocks(t, net, 1, 1)

	fundingTxid, err := chainhash.NewHashFromStr(assetFundResp.Txid)
	require.NoError(t.t, err)
	assertAnchoringPhase(t.t, charlie, fundingAnchoring, "witnessed")
	locateAssetTransfers(t.t, charlie, *fundingTxid)

	// Re-org the funding confirmation out: the funding transaction
	// returns to the mempool, and the anchoring honestly reports
	// unwitnessed. Nothing is compensated — the transaction can (and
	// will) confirm again.
	generateReOrg(t, net, tempMiner, 3, 2)

	_, tempHeight := tempMiner.GetBestBlock()
	waitForNodeHeight(t.t, charlie, uint32(tempHeight))
	waitForNodeHeight(t.t, dave, uint32(tempHeight))

	assertAnchoringPhase(t.t, charlie, fundingAnchoring, "unwitnessed")

	// The funding re-confirms on the rewritten chain and buries at
	// the safe depth; the channel activates on top of the
	// re-organized funding.
	mineBlocks(t, net, 6, 1)
	assertAnchoringPhase(t.t, charlie, fundingAnchoring, "buried")
	locateAssetTransfers(t.t, charlie, *fundingTxid)

	assertAssetChan(
		t.t, charlie, dave, fundingAmount, []*taprpc.Asset{cents},
	)
	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))

	// The channel carries value over the re-organized funding.
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

	// And closes cleanly on top of it: the cooperative close settles
	// both sides' asset outputs from channel state that was carried
	// across the re-org.
	chanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(assetFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: assetFundResp.Txid,
		},
	}

	t.Logf("Closing channel...")
	_, _, err = net.CloseChannel(charlie, chanPoint, false)
	require.NoError(t.t, err)

	mineBlocks(t, net, 6, 1)

	assertClosedChannelAssetData(t.t, charlie, chanPoint)
	assertClosedChannelAssetData(t.t, dave, chanPoint)

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
}
