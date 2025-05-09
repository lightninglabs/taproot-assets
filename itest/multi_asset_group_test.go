package itest

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// testMintMultiAssetGroups tests that we can properly mint a batch containing
// an asset group with multiple assets, and that the daemon handles assets
// created in such a batch correctly.
func testMintMultiAssetGroups(t *harnessTest) {
	// First, we'll build a batch to mint. We'll include one asset with no
	// group, one asset with emission enabled, one new group of 2 assets,
	// and one new group of 3 assets.
	complexBatch := []*mintrpc.MintAssetRequest{simpleAssets[0]}
	issuableAsset := CopyRequest(simpleAssets[1])
	issuableAsset.Asset.NewGroupedAsset = true
	complexBatch = append(complexBatch, issuableAsset)

	normalGroupMembers := 2
	normalGroup, normalGroupSum := createMultiAssetGroup(
		issuableAssets[0], uint64(normalGroupMembers),
	)
	collectGroupMembers := 1
	collectGroup, collectGroupSum := createMultiAssetGroup(
		issuableAssets[1], uint64(collectGroupMembers),
	)
	complexBatch = append(complexBatch, normalGroup...)
	complexBatch = append(complexBatch, collectGroup...)

	// The minted batch should contain 7 assets total, and the daemon should
	// now be aware of 3 asset groups. Each group should have a different
	// number of assets, and a different total balance.
	mintedBatch := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd, complexBatch,
	)

	// Once the batch is minted, we can verify that all asset groups were
	// created correctly. We begin by verifying the number of asset groups.
	ctxb := context.Background()
	groupCount := 3
	AssertNumGroups(t.t, t.tapd, groupCount)
	balancesResp, err := t.tapd.ListBalances(
		ctxb, &taprpc.ListBalancesRequest{
			GroupBy: &taprpc.ListBalancesRequest_GroupKey{
				GroupKey: true,
			},
		},
	)
	require.NoError(t.t, err)

	// For each group minted, we check that the total balance for each
	// group matches our minting requests.
	var singleAssetGroupKey, normalGroupKey, collectGroupKey string
	for groupKey, groupBalance := range balancesResp.AssetGroupBalances {
		switch groupBalance.Balance {
		case issuableAsset.Asset.Amount:
			singleAssetGroupKey = groupKey
		case normalGroupSum:
			normalGroupKey = groupKey
		case collectGroupSum:
			collectGroupKey = groupKey
		default:
			t.t.Fatalf("minted group %v has unexpected balance %v",
				groupKey, groupBalance.Balance)
		}
	}

	// We also check the number of assets in each group. Each group size
	// is incremented by 1 to account for the group anchor.
	orderedGroupKeys := []string{
		singleAssetGroupKey, normalGroupKey, collectGroupKey,
	}
	orderedGroupSizes := []int{
		1, normalGroupMembers + 1, collectGroupMembers + 1,
	}
	AssertGroupSizes(t.t, t.tapd, orderedGroupKeys, orderedGroupSizes)

	// Now that we've verified the group count, size, and balance, we also
	// need to check that the intended asset was used as the group anchor.
	// We can do this by re-deriving the tweaked group key.
	normalAnchorName := issuableAssets[0].Asset.Name
	normalAnchor := VerifyGroupAnchor(t.t, mintedBatch, normalAnchorName)

	collectAnchorName := issuableAssets[1].Asset.Name
	collectAnchor := VerifyGroupAnchor(t.t, mintedBatch, collectAnchorName)

	// Finally, we send some assets from the multi-asset group to Bob to
	// ensure that they can be sent and received correctly.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	normalMember, err := fn.First(
		mintedBatch, func(asset *taprpc.Asset) bool {
			return asset.Amount == normalAnchor.Amount/2
		},
	)
	require.NoError(t.t, err)

	normalMemberGenInfo := normalMember.AssetGenesis

	// The assets to send are selected; we now generate an address, send,
	// and verify the transfer.
	bobNormalAddr, err := secondTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: normalMemberGenInfo.AssetId,
		Amt:     normalMember.Amount,
	})
	require.NoError(t.t, err)

	normalGroupSend, normalSendEvents := sendAssetsToAddr(
		t, t.tapd, bobNormalAddr,
	)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, normalGroupSend,
		normalMember.AssetGenesis.AssetId,
		[]uint64{0, normalMember.Amount}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 1)
	AssertSendEventsComplete(t.t, bobNormalAddr.ScriptKey, normalSendEvents)

	AssertBalanceByGroup(
		t.t, secondTapd, normalGroupKey, normalMember.Amount,
	)

	// We want to select the one collectible that is in the same group as
	// the collectible group anchor, and is not the anchor itself.
	isCollectGroupMember := func(asset *taprpc.Asset) bool {
		isNotAnchor := asset.AssetGenesis.Name !=
			collectAnchor.AssetGenesis.Name

		if asset.AssetGroup == nil {
			return false
		}

		isGrouped := collectGroupKey == hex.EncodeToString(
			asset.AssetGroup.TweakedGroupKey,
		)
		return isNotAnchor && isGrouped
	}
	collectMember, err := fn.First(mintedBatch, isCollectGroupMember)
	require.NoError(t.t, err)

	collectMemberGenInfo := collectMember.AssetGenesis
	bobCollectAddr, err := secondTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId: collectMemberGenInfo.AssetId,
		Amt:     collectMember.Amount,
	})
	require.NoError(t.t, err)

	collectGroupSend, groupSendEvents := sendAssetsToAddr(
		t, t.tapd, bobCollectAddr,
	)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, collectGroupSend,
		collectMember.AssetGenesis.AssetId,
		[]uint64{0, collectMember.Amount}, 1, 2,
	)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 2)
	AssertSendEventsComplete(t.t, bobCollectAddr.ScriptKey, groupSendEvents)

	AssertBalanceByGroup(
		t.t, secondTapd, collectGroupKey, collectMember.Amount,
	)
}

// createMultiAssetGroup creates a list of minting requests that represent a
// multi-asset group, using the anchor asset to generate parameters for the
// other assets in the group.
func createMultiAssetGroup(anchor *mintrpc.MintAssetRequest,
	numAssets uint64) ([]*mintrpc.MintAssetRequest, uint64) {

	// We'll use descending amounts for the assets in the group, and use
	// the asset name to indicate the asset's place in the group.
	groupRequests := []*mintrpc.MintAssetRequest{CopyRequest(anchor)}
	anchorAmount := anchor.Asset.Amount
	anchorName := anchor.Asset.Name
	groupSum := uint64(0)
	for i := uint64(1); i <= numAssets; i++ {
		assetReq := CopyRequest(anchor)
		assetReq.Asset.NewGroupedAsset = false
		assetReq.Asset.GroupedAsset = true
		assetReq.Asset.GroupAnchor = anchorName
		assetReq.Asset.Name = fmt.Sprintf(
			"%s-tranche-%d", anchorName, i,
		)

		if assetReq.Asset.AssetType == taprpc.AssetType_NORMAL {
			reqAmount := anchorAmount / (2 * i)
			if reqAmount == 0 {
				reqAmount = 1
			}

			assetReq.Asset.Amount = reqAmount
		}

		groupSum += assetReq.Asset.Amount
		groupRequests = append(groupRequests, assetReq)
	}

	groupSum += anchorAmount
	return groupRequests, groupSum
}

// testMintMultiAssetGroupErrors tests that the minter rejects series of minting
// requests that incorrectly try to construct a multi-asset group.
func testMintMultiAssetGroupErrors(t *harnessTest) {
	ctxb := context.Background()

	// First, construct a request for a grouped asset. Any request with a
	// group anchor is invalid if there is no pending batch.
	groupedAsset := CopyRequest(simpleAssets[0])
	groupedAsset.Asset.GroupAnchor = groupedAsset.Asset.Name
	groupedAsset.Asset.GroupedAsset = true

	_, err := t.tapd.MintAsset(ctxb, groupedAsset)
	require.ErrorContains(t.t, err, "batch empty, group anchor")

	// The current request references a group anchor that does not exist,
	// which makes it invalid.
	simpleAsset := CopyRequest(simpleAssets[1])
	_, err = t.tapd.MintAsset(ctxb, simpleAsset)
	require.NoError(t.t, err)

	_, err = t.tapd.MintAsset(ctxb, groupedAsset)
	require.ErrorContains(t.t, err, "not present in batch")

	// Now we'll construct an asset to use as an invalid group anchor;
	// group anchors must have emission enabled.
	validAnchor := CopyRequest(simpleAssets[0])
	validAnchorName := validAnchor.Asset.Name + validAnchor.Asset.Name
	validAnchor.Asset.Name = validAnchorName
	_, err = t.tapd.MintAsset(ctxb, validAnchor)
	require.NoError(t.t, err)

	groupedAsset.Asset.GroupAnchor = validAnchorName
	_, err = t.tapd.MintAsset(ctxb, groupedAsset)
	require.ErrorContains(t.t, err, "isn't starting a new group")

	// Finally, we'll modify the assets to make the multi-asset group valid.
	validAnchor.Asset.NewGroupedAsset = true
	validAnchor.Asset.AssetMeta = &taprpc.AssetMeta{
		Data: []byte("metadata for itest group anchors"),
	}

	_, err = t.tapd.CancelBatch(ctxb, &mintrpc.CancelBatchRequest{})
	require.NoError(t.t, err)
	multiAssetGroup := []*mintrpc.MintAssetRequest{validAnchor, groupedAsset}

	// The assets should be minted into the same group.
	rpcGroupedAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd, multiAssetGroup,
	)
	AssertNumGroups(t.t, t.tapd, 1)
	groupKey := rpcGroupedAssets[0].AssetGroup.TweakedGroupKey
	groupKeyHex := hex.EncodeToString(groupKey)
	expectedGroupBalance := groupedAsset.Asset.Amount +
		validAnchor.Asset.Amount
	AssertBalanceByGroup(t.t, t.tapd, groupKeyHex, expectedGroupBalance)
}

// testMultiAssetGroupSend tests that we can randomly send assets from a group
// of collectibles one after another from one node to the other.
func testMultiAssetGroupSend(t *harnessTest) {
	// We use a hashmail proof courier for this test, which takes a bit
	// longer to send proofs. So we use a longer timeout.
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout*3)
	defer cancel()

	// First, we'll build a batch to mint.
	issuableAsset := CopyRequest(simpleAssets[1])
	issuableAsset.Asset.NewGroupedAsset = true

	collectibleGroupMembers := 50
	collectibleGroup, collectibleGroupSum := createMultiAssetGroup(
		issuableAsset, uint64(collectibleGroupMembers),
	)

	// The minted batch should contain 51 assets total, and the daemon
	// should now be aware of one asset group.
	mintedBatch := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd, collectibleGroup,
	)
	require.Len(t.t, mintedBatch, collectibleGroupMembers+1)

	// Once the batch is minted, we can verify that all asset groups were
	// created correctly. We begin by verifying the number of asset groups.
	groupCount := 1
	AssertNumGroups(t.t, t.tapd, groupCount)
	balancesResp, err := t.tapd.ListBalances(
		ctxt, &taprpc.ListBalancesRequest{
			GroupBy: &taprpc.ListBalancesRequest_GroupKey{
				GroupKey: true,
			},
		},
	)
	require.NoError(t.t, err)

	require.NotNil(t.t, mintedBatch[0].AssetGroup)
	groupKeyStr := hex.EncodeToString(
		mintedBatch[0].AssetGroup.TweakedGroupKey,
	)

	require.Contains(t.t, balancesResp.AssetGroupBalances, groupKeyStr)
	require.EqualValues(
		t.t, collectibleGroupSum,
		balancesResp.AssetGroupBalances[groupKeyStr].Balance,
	)

	AssertGroupSizes(t.t, t.tapd, []string{groupKeyStr}, []int{
		collectibleGroupMembers + 1,
	})

	AssertUniverseRootEqualityEventually(
		t.t, t.tapd, t.universeServer.service,
	)

	// We'll make a second node now that'll be the receiver of all the
	// assets made above.
	lndBob := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, lndBob, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	AssertUniverseRootEqualityEventually(
		t.t, secondTapd, t.universeServer.service,
	)

	// Send 5 of the assets to Bob, and verify that they are received.
	numUnits := issuableAsset.Asset.Amount
	assetType := issuableAsset.Asset.AssetType
	for i := 0; i < 5; i++ {
		// Query the asset we'll be sending, so we can assert some
		// things about it later.
		sendAsset := assetIDWithBalance(
			t.t, t.tapd, numUnits, assetType,
		)
		genInfo := sendAsset.AssetGenesis
		t.Logf("Attempt %d: Sending %d asset(s) with ID %x from "+
			"alice to bob", i+1, numUnits, genInfo.AssetId)

		addr, err := secondTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
			AssetId: genInfo.AssetId,
			Amt:     numUnits,
		})
		require.NoError(t.t, err)
		AssertAddrCreated(t.t, secondTapd, sendAsset, addr)

		sendResp, sendEvents := sendAssetsToAddr(t, t.tapd, addr)

		ConfirmAndAssertOutboundTransfer(
			t.t, t.lndHarness.Miner().Client, t.tapd,
			sendResp, genInfo.AssetId,
			[]uint64{0, numUnits}, i, i+1,
		)

		AssertNonInteractiveRecvComplete(t.t, secondTapd, i+1)
		AssertSendEventsComplete(t.t, addr.ScriptKey, sendEvents)
	}
}

// assetIDWithBalance returns the asset ID of an asset that has at least the
// given balance. If no such asset is found, nil is returned.
func assetIDWithBalance(t *testing.T, node *tapdHarness,
	minBalance uint64, assetType taprpc.AssetType) *taprpc.Asset {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	balances, err := node.ListBalances(ctxt, &taprpc.ListBalancesRequest{
		GroupBy: &taprpc.ListBalancesRequest_AssetId{
			AssetId: true,
		},
	})
	require.NoError(t, err)

	for assetIDHex, balance := range balances.AssetBalances {
		if balance.Balance >= minBalance &&
			balance.AssetGenesis.AssetType == assetType {

			assetIDBytes, err := hex.DecodeString(assetIDHex)
			require.NoError(t, err)

			assets, err := node.ListAssets(
				ctxt, &taprpc.ListAssetRequest{},
			)
			require.NoError(t, err)

			for _, asset := range assets.Assets {
				if bytes.Equal(
					asset.AssetGenesis.AssetId,
					assetIDBytes,
				) {

					return asset
				}
			}
		}
	}

	return nil
}
