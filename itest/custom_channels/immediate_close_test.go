//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsImmediateClose tests that an asset channel can be funded
// and then force closed immediately after the funding transaction confirms,
// without any in-channel asset movement.
func testCustomChannelsImmediateClose(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// We use Alice as the Universe proof courier and also as the funder, so
	// we pin her RPC listen port up front.
	alicePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, alicePort),
	))

	aliceLndArgs := slices.Clone(lndArgs)
	aliceLndArgs = append(aliceLndArgs, fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", alicePort,
	))
	alice := net.NewNode("Alice", aliceLndArgs, tapdArgs)
	bob := net.NewNode("Bob", lndArgs, tapdArgs)
	charlie := net.NewNode("Charlie", lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{alice, bob, charlie}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner, asTapd(alice),
		[]*mintrpc.MintAssetRequest{
			{
				Asset: ccItestAsset,
			},
		},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId

	t.Logf("Minted %d lightning cents, syncing universes...", cents.Amount)
	syncUniverses(t.t, alice, bob)
	syncUniverses(t.t, alice, charlie)

	t.Logf("Opening asset channel...")
	fundResp, err := asTapd(alice).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         bob.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)

	chanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(fundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: fundResp.Txid,
		},
	}

	mineBlocks(t, net, 6, 1)

	fundingScriptTree := tapscript.NewChannelFundingScriptTree()
	fundingScriptKey := fundingScriptTree.TaprootKey
	assertUniverseProofExists(
		t.t, alice, assetID, nil,
		fundingScriptKey.SerializeCompressed(),
		fmt.Sprintf("%v:%v", fundResp.Txid, fundResp.OutputIndex),
	)
	assertAssetChan(
		t.t, alice, bob, fundingAmount, []*taprpc.Asset{cents},
	)

	t.Logf("Force closing asset channel immediately after confirmation...")
	_, _, err = net.CloseChannel(alice, chanPoint, true)
	require.NoError(t.t, err)

	// The channel first enters waiting close until the commitment
	// transaction confirms.
	assertWaitingCloseChannelAssetData(t.t, alice, chanPoint)
	mineBlocks(t, net, 1, 1)

	// After confirmation, Alice should enter pending force close. Unlike the
	// cooperative close path, the local force close commitment transaction
	// itself is not immediately tracked as an asset transfer for Alice.
	assertPendingForceCloseChannelAssetData(t.t, alice, chanPoint)

	// With no remote asset balance, Alice eventually sweeps the local output
	// after the CSV delay and regains the full on-chain balance.
	mineBlocks(t, net, 4, 0)

	aliceSweepTxid, err := waitForNTxsInMempool(
		net.Miner, 1, ccShortTimeout,
	)
	require.NoError(t.t, err)

	t.Logf("Alice sweep txid: %v", aliceSweepTxid)

	aliceSweepBlocks := mineBlocks(t, net, 1, 1)
	aliceSweepTxHash := aliceSweepBlocks[0].Transactions[1].TxHash()

	locateAssetTransfers(t.t, alice, aliceSweepTxHash)

	assertBalance(
		t.t, alice, ccItestAsset.Amount, itest.WithAssetID(assetID),
		itest.WithNumUtxos(2),
	)

	// Finally, assert the swept asset can be spent onward to a third party.
	const assetSendAmount = 1000
	charlieAddr, err := asTapd(charlie).NewAddr(
		ctx, &taprpc.NewAddrRequest{
			Amt:     assetSendAmount,
			AssetId: assetID,
			ProofCourierAddr: fmt.Sprintf(
				"%s://%s", proof.UniverseRpcCourierType,
				alice.RPCAddr(),
			),
		},
	)
	require.NoError(t.t, err)

	itest.AssertAddrCreated(t.t, asTapd(charlie), cents, charlieAddr)
	_, err = asTapd(alice).SendAsset(
		ctx, &taprpc.SendAssetRequest{
			TapAddrs: []string{charlieAddr.Encoded},
		},
	)
	require.NoError(t.t, err)
	mineBlocks(t, net, 1, 1)
	itest.AssertNonInteractiveRecvComplete(t.t, asTapd(charlie), 1)

	assertBalance(
		t.t, alice, ccItestAsset.Amount-assetSendAmount,
		itest.WithAssetID(assetID),
	)
	assertBalance(
		t.t, charlie, assetSendAmount, itest.WithAssetID(assetID),
	)
}
