//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsSingleAssetMultiInput tests whether it is possible to fund
// a channel using FundChannel that uses multiple inputs from the same asset.
func testCustomChannelsSingleAssetMultiInput(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// We use Charlie as the proof courier. But in order for Charlie to also
	// use itself, we need to define its port upfront.
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

	nodes := []*itest.IntegratedNode{charlie, dave}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Mint an assets on Charlie and sync Dave to Charlie as the universe.
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

	t.Logf("Minted %d lightning cents, syncing universes...",
		cents.Amount)
	syncUniverses(t.t, charlie, dave)
	t.Logf("Universes synced between all nodes, distributing assets...")

	// Charlie should have two balance outputs with the full balance.
	assertBalance(
		t.t, charlie, cents.Amount, itest.WithAssetID(assetID),
		itest.WithNumUtxos(1),
		itest.WithScriptKeyType(asset.ScriptKeyBip86),
	)

	// Send assets to Dave so he can fund a channel.
	halfCentsAmount := cents.Amount / 2
	daveAddr1, err := asTapd(dave).NewAddr(ctx, &taprpc.NewAddrRequest{
		Amt:     halfCentsAmount,
		AssetId: assetID,
		ProofCourierAddr: fmt.Sprintf(
			"%s://%s", proof.UniverseRpcCourierType,
			charlie.RPCAddr(),
		),
	})
	require.NoError(t.t, err)
	daveAddr2, err := asTapd(dave).NewAddr(ctx, &taprpc.NewAddrRequest{
		Amt:     halfCentsAmount,
		AssetId: assetID,
		ProofCourierAddr: fmt.Sprintf(
			"%s://%s", proof.UniverseRpcCourierType,
			charlie.RPCAddr(),
		),
	})
	require.NoError(t.t, err)

	t.Logf("Sending %v asset units to Dave twice...", halfCentsAmount)

	// Send the assets to Dave.
	itest.AssertAddrCreated(t.t, asTapd(dave), cents, daveAddr1)
	itest.AssertAddrCreated(t.t, asTapd(dave), cents, daveAddr2)
	sendResp, err := asTapd(charlie).SendAsset(
		ctx, &taprpc.SendAssetRequest{
			TapAddrs: []string{
				daveAddr1.Encoded, daveAddr2.Encoded,
			},
		},
	)
	require.NoError(t.t, err)
	itest.ConfirmAndAssertOutboundTransferWithOutputs(
		t.t, net.Miner.Client, asTapd(charlie), sendResp, assetID,
		[]uint64{
			cents.Amount - 2*halfCentsAmount, halfCentsAmount,
			halfCentsAmount,
		}, 0, 1, 3,
	)
	itest.AssertNonInteractiveRecvComplete(t.t, asTapd(dave), 2)

	// Fund a channel using multiple inputs from the same asset.
	fundRespCD, err := asTapd(dave).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        2 * halfCentsAmount,
			AssetId:            assetID,
			PeerPubkey:         charlie.PubKey[:],
			FeeRateSatPerVbyte: 5,
			PushSat:            0,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel between Charlie and Dave: %v", fundRespCD)

	// Let's confirm the channel.
	mineBlocks(t, net, 6, 1)

	// Tapd should not report any balance for Charlie, since the asset is
	// used in a funding transaction. It should also not report any balance
	// for Dave. All those balances are reported through channel balances.
	assertBalance(t.t, charlie, 0, itest.WithAssetID(assetID))
	assertBalance(t.t, dave, 0, itest.WithAssetID(assetID))

	// Make sure the channel shows the correct asset information.
	assertAssetChan(
		t.t, charlie, dave, 2*halfCentsAmount,
		[]*taprpc.Asset{cents},
	)
}
