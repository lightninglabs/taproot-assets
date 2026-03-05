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
	"github.com/lightninglabs/taproot-assets/tapscript"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsBalanceConsistency is a test that test the balance of nodes
// under channel opening circumstances.
func testCustomChannelsBalanceConsistency(ctx context.Context,
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

	// Mint an asset on Charlie and sync Dave to Charlie as the universe.
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
	var groupKey []byte
	if cents.AssetGroup != nil {
		groupKey = cents.AssetGroup.TweakedGroupKey
	}

	t.Logf("Minted %d lightning cents, syncing universes...", cents.Amount)
	syncUniverses(t.t, charlie, dave)
	t.Logf("Universes synced between all nodes, distributing assets...")

	charlieBalance := cents.Amount

	// Charlie should have a single balance output with the full balance.
	assertBalance(
		t.t, charlie, cents.Amount, itest.WithAssetID(assetID),
		itest.WithNumUtxos(1),
	)

	// The script key should be local to charlie, and the script key should
	// be known. It is after all the asset he just minted himself.
	assertBalance(
		t.t, charlie, cents.Amount, itest.WithAssetID(assetID),
		itest.WithNumUtxos(1), itest.WithScriptKey(cents.ScriptKey),
		itest.WithScriptKeyType(asset.ScriptKeyBip86),
	)

	fundingScriptTree := tapscript.NewChannelFundingScriptTree()
	fundingScriptKey := fundingScriptTree.TaprootKey
	fundingScriptKeyBytes := fundingScriptKey.SerializeCompressed()

	fundRespCD, err := asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        charlieBalance,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
			PushSat:            0,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel between Charlie and Dave: %v", fundRespCD)

	// Make sure the pending channel shows up in the list and has the
	// custom records set as JSON.
	assertPendingChannels(
		t.t, charlie, cents, 1, charlieBalance, 0,
	)

	// Let's confirm the channel.
	mineBlocks(t, net, 6, 1)

	// Tapd should not report any balance for Charlie, since the asset is
	// used in a funding transaction. It should also not report any balance
	// for Dave. All those balances are reported through channel balances.
	assertBalance(t.t, charlie, 0, itest.WithAssetID(assetID))
	assertBalance(t.t, dave, 0, itest.WithAssetID(assetID))

	// There should only be a single asset piece for Charlie, the one in the
	// channel.
	assertBalance(
		t.t, charlie, charlieBalance, itest.WithAssetID(assetID),
		itest.WithNumUtxos(1),
		itest.WithScriptKeyType(asset.ScriptKeyScriptPathChannel),
		itest.WithScriptKey(fundingScriptKeyBytes),
	)

	// Assert that the proofs for both channels has been uploaded to the
	// designated Universe server.
	assertUniverseProofExists(
		t.t, charlie, assetID, groupKey, fundingScriptKeyBytes,
		fmt.Sprintf("%v:%v", fundRespCD.Txid, fundRespCD.OutputIndex),
	)

	// Make sure the channel shows the correct asset information.
	assertAssetChan(
		t.t, charlie, dave, charlieBalance,
		[]*taprpc.Asset{cents},
	)

	logBalance(t.t, nodes, assetID, "initial")

	// Normal case.
	// Send 500 assets from Charlie to Dave.
	sendAssetKeySendPayment(
		t.t, charlie, dave, 500, assetID, fn.None[int64](),
	)

	logBalance(t.t, nodes, assetID, "after 500 assets")

	// Tapd should still not report balances for Charlie and Dave, since
	// they are still locked up in the funding transaction.
	assertBalance(t.t, charlie, 0, itest.WithAssetID(assetID))
	assertBalance(t.t, dave, 0, itest.WithAssetID(assetID))

	// Send 10k sats from Charlie to Dave. Dave needs the sats to be able to
	// send assets.
	sendKeySendPayment(t.t, charlie, dave, 10000)

	// Now Dave tries to send 250 assets.
	sendAssetKeySendPayment(
		t.t, dave, charlie, 250, assetID, fn.None[int64](),
	)

	logBalance(t.t, nodes, assetID, "after 250 sats backwards")

	// Tapd should still not report balances for Charlie and Dave, since
	// they are still locked up in the funding transaction.
	assertBalance(t.t, charlie, 0, itest.WithAssetID(assetID))
	assertBalance(t.t, dave, 0, itest.WithAssetID(assetID))

	// We will now close the channel.
	t.Logf("Close the channel between Charlie and Dave...")
	charlieChanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(fundRespCD.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: fundRespCD.Txid,
		},
	}

	closeChannelAndAssert(t, net, charlie, charlieChanPoint, false)

	// Charlie should have a single balance output with the balance 250 less
	// than the total amount minted.
	assertBalance(
		t.t, charlie, charlieBalance-250, itest.WithAssetID(assetID),
		itest.WithNumUtxos(1),
		itest.WithScriptKeyType(asset.ScriptKeyBip86),
	)
	assertBalance(
		t.t, dave, 250, itest.WithAssetID(assetID),
		itest.WithNumUtxos(1),
		itest.WithScriptKeyType(asset.ScriptKeyBip86),
	)
}
