//go:build itest

package custom_channels

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsPassiveAssets tests that passive assets
// (assets in the same input commitment but not used for channel
// funding) are not included in the funding assets sent to the
// responder.
func testCustomChannelsPassiveAssets(ctx context.Context,
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

	nodes := []*itest.IntegratedNode{charlie, dave}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Mint two assets in the same batch with the same group key.
	// This puts them in the same anchor UTXO/commitment.
	assetA := &mintrpc.MintAsset{
		AssetType:       taprpc.AssetType_NORMAL,
		Name:            "asset-a-for-channel",
		AssetMeta:       ccDummyMetaData,
		Amount:          100_000,
		NewGroupedAsset: true,
	}
	assetB := &mintrpc.MintAsset{
		AssetType:   taprpc.AssetType_NORMAL,
		Name:        "asset-b-passive",
		AssetMeta:   ccDummyMetaData,
		Amount:      50_000,
		GroupedAsset: true,
		GroupAnchor: "asset-a-for-channel",
	}
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{
			{Asset: assetA},
			{Asset: assetB},
		},
	)
	require.Len(t.t, mintedAssets, 2)

	mintedA := mintedAssets[0]
	mintedB := mintedAssets[1]
	assetIDA := mintedA.AssetGenesis.AssetId

	// Both assets should have the same group key.
	require.NotNil(t.t, mintedA.AssetGroup)
	require.NotNil(t.t, mintedB.AssetGroup)
	groupKey := mintedA.AssetGroup.TweakedGroupKey
	require.Equal(
		t.t, groupKey, mintedB.AssetGroup.TweakedGroupKey,
	)

	// Check if both assets share the same anchor outpoint.
	outpointA := mintedA.ChainAnchor.AnchorOutpoint
	outpointB := mintedB.ChainAnchor.AnchorOutpoint
	t.Logf("Asset A anchor outpoint: %s", outpointA)
	t.Logf("Asset B anchor outpoint: %s", outpointB)
	require.Equal(t.t, outpointA, outpointB,
		"assets must be in same UTXO for passive asset test")

	syncUniverses(t.t, charlie, dave)
	mineBlocks(t, net, 1, 0)

	// Fund a channel using the group key. We request 75,000
	// units which forces Asset A (100,000) to be selected since
	// Asset B (50,000) is insufficient. Asset B should become
	// passive and not appear in Dave's view of the channel.
	const fundingAmount = 75_000
	fundResp, err := asTapd(charlie).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			GroupKey:            groupKey,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
			PushSat:            DefaultPushSat,
		},
	)
	require.NoError(t.t, err)

	mineBlocks(t, net, 6, 1)

	// Assert Dave (responder) only sees Asset A in the channel,
	// not the passive Asset B.
	err = wait.NoError(func() error {
		chanData, chanErr := getChannelCustomData(
			dave, charlie,
		)
		if chanErr != nil {
			return chanErr
		}

		// There should be exactly one funding asset.
		if len(chanData.FundingAssets) != 1 {
			return fmt.Errorf("expected 1 funding "+
				"asset, got %d",
				len(chanData.FundingAssets))
		}

		// Verify it's Asset A, not Asset B.
		fundingAssetID :=
			chanData.FundingAssets[0].AssetGenesis.AssetID
		if hex.EncodeToString(assetIDA) != fundingAssetID {
			return fmt.Errorf("funding asset should be "+
				"Asset A, got %s", fundingAssetID)
		}

		// Verify capacity matches funding amount, not
		// inflated by Asset B.
		if chanData.Capacity != uint64(fundingAmount) {
			return fmt.Errorf("capacity should be %d, "+
				"not inflated by passive assets, "+
				"got %d", fundingAmount,
				chanData.Capacity)
		}

		return nil
	}, wait.DefaultTimeout)
	require.NoError(t.t, err)

	chanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(fundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: fundResp.Txid,
		},
	}
	closeAssetChannelAndAssert(
		t, net, charlie, dave, chanPoint,
		[][]byte{assetIDA}, nil, charlie,
		noOpCoOpCloseBalanceCheck,
	)
}
