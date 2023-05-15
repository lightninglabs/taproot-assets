package itest

import (
	"context"
	"encoding/hex"
	"sort"

	"github.com/lightninglabs/taro/taprpc"
	"github.com/lightninglabs/taro/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

// testCollectibleSend tests that we can properly send a collectible asset
// with split commitments.
func testCollectibleSend(t *harnessTest) {
	// First, we'll make a collectible with emission enabled.
	rpcAssets := mintAssetsConfirmBatch(
		t, t.tapd, []*mintrpc.MintAssetRequest{
			issuableAssets[1],
			// Our "passive" asset.
			{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "itestbuxx-passive",
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte("some metadata"),
					},
					Amount: 123,
				},
			},
		},
	)

	groupKey := rpcAssets[0].AssetGroup.TweakedGroupKey
	genInfo := rpcAssets[0].AssetGenesis

	ctxb := context.Background()

	// Now that we have the asset created, we'll make a new node that'll
	// serve as the node which'll receive the assets.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.startupSyncNode = t.tapd
			params.startupSyncNumAssets = len(rpcAssets)
		},
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(true))
	}()

	// Next, we'll attempt to complete three transfers of the full value of
	// the asset between our main node and Bob.
	var (
		numSends            = 3
		senderTransferIdx   = 0
		receiverTransferIdx = 0
		fullAmount          = rpcAssets[0].Amount
		receiverAddr        *taprpc.Addr
		err                 error
	)

	for i := 0; i < numSends; i++ {
		// Create an address for the receiver and send the asset. We
		// start with Bob receiving the asset, then sending it back
		// to the main node, and so on.
		if i%2 == 0 {
			receiverAddr, err = secondTapd.NewAddr(
				ctxb, &taprpc.NewAddrRequest{
					AssetId: genInfo.AssetId,
					Amt:     fullAmount,
				},
			)
			require.NoError(t.t, err)

			assertAddrCreated(
				t.t, secondTapd, rpcAssets[0], receiverAddr,
			)
			sendResp := sendAssetsToAddr(t, t.tapd, receiverAddr)
			confirmAndAssertOutboundTransfer(
				t, t.tapd, sendResp, genInfo.AssetId,
				[]uint64{0, fullAmount}, senderTransferIdx,
				senderTransferIdx+1,
			)
			_ = sendProof(
				t, t.tapd, secondTapd, receiverAddr.ScriptKey,
				genInfo,
			)
			senderTransferIdx++
		} else {
			receiverAddr, err = t.tapd.NewAddr(
				ctxb, &taprpc.NewAddrRequest{
					AssetId: genInfo.AssetId,
					Amt:     fullAmount,
				},
			)
			require.NoError(t.t, err)

			assertAddrCreated(
				t.t, t.tapd, rpcAssets[0], receiverAddr,
			)
			sendResp := sendAssetsToAddr(
				t, secondTapd, receiverAddr,
			)
			confirmAndAssertOutboundTransfer(
				t, secondTapd, sendResp, genInfo.AssetId,
				[]uint64{0, fullAmount}, receiverTransferIdx,
				receiverTransferIdx+1,
			)
			_ = sendProof(
				t, secondTapd, t.tapd, receiverAddr.ScriptKey,
				genInfo,
			)
			receiverTransferIdx++
		}
	}

	// Check the final state of both nodes. The main node should list 2
	// zero-value transfers. and Bob should have 1. The main node should
	// show a balance of zero, and Bob should hold the total asset supply.
	assertTransfer(t.t, t.tapd, 0, 2, []uint64{0, fullAmount})
	assertTransfer(t.t, t.tapd, 1, 2, []uint64{0, fullAmount})
	assertBalanceByID(t.t, t.tapd, genInfo.AssetId, 0)

	assertTransfer(t.t, secondTapd, 0, 1, []uint64{0, fullAmount})
	assertBalanceByID(t.t, secondTapd, genInfo.AssetId, fullAmount)

	// The second daemon should list one group with one asset.
	listGroupsResp, err := secondTapd.ListGroups(
		ctxb, &taprpc.ListGroupsRequest{},
	)
	require.NoError(t.t, err)

	groupKeys := maps.Keys(listGroupsResp.Groups)
	require.Len(t.t, groupKeys, 1)

	rpcGroupKey, err := hex.DecodeString(groupKeys[0])
	require.NoError(t.t, err)
	require.Equal(t.t, groupKey, rpcGroupKey)

	groupedAssets := listGroupsResp.Groups[groupKeys[0]].Assets
	require.Len(t.t, groupedAssets, 1)

	// Sort the assets with a group by amount, descending.
	sort.Slice(groupedAssets, func(i, j int) bool {
		return groupedAssets[i].Amount > groupedAssets[j].Amount
	})

	listAssetsResp, err := secondTapd.ListAssets(
		ctxb, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)

	// Sort all assets by amount, descending.
	allAssets := listAssetsResp.Assets
	sort.Slice(allAssets, func(i, j int) bool {
		return allAssets[i].Amount > allAssets[j].Amount
	})

	// Only compare the spendable asset.
	assertGroup(t.t, allAssets[0], groupedAssets[0], rpcGroupKey)

	aliceAssetsResp, err := t.tapd.ListAssets(
		ctxb, &taprpc.ListAssetRequest{IncludeSpent: true},
	)
	require.NoError(t.t, err)

	assetsJSON, err := formatProtoJSON(aliceAssetsResp)
	require.NoError(t.t, err)
	t.Logf("Got alice assets: %s", assetsJSON)

	// Finally, make sure we can still send out the passive asset.
	passiveGen := rpcAssets[1].AssetGenesis
	bobAddr, err := secondTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: passiveGen.AssetId,
		Amt:     rpcAssets[1].Amount,
	})
	require.NoError(t.t, err)

	assertAddrCreated(t.t, secondTapd, rpcAssets[1], bobAddr)
	sendResp := sendAssetsToAddr(t, t.tapd, bobAddr)
	confirmAndAssertOutboundTransfer(
		t, t.tapd, sendResp, passiveGen.AssetId,
		[]uint64{0, rpcAssets[1].Amount}, 2, 3,
	)
	_ = sendProof(
		t, t.tapd, secondTapd, bobAddr.ScriptKey, passiveGen,
	)

	// There's only one non-interactive receive event.
	assertNonInteractiveRecvComplete(t, secondTapd, 3)
}
