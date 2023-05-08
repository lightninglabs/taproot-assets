package itest

import (
	"context"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/tarorpc"
	"github.com/lightninglabs/taro/tarorpc/mintrpc"
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
	issuableAsset := copyRequest(simpleAssets[1])
	issuableAsset.EnableEmission = true
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
	mintedBatch := mintAssetsConfirmBatch(t, t.tarod, complexBatch)

	// Once the batch is minted, we can verify that all asset groups were
	// created correctly. We begin by verifying the number of asset groups.
	ctxb := context.Background()
	groupCount := 3
	assertNumGroups(t.t, t.tarod, groupCount)
	balancesResp, err := t.tarod.ListBalances(
		ctxb, &tarorpc.ListBalancesRequest{
			GroupBy: &tarorpc.ListBalancesRequest_GroupKey{
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
	assertGroupSizes(t.t, t.tarod, orderedGroupKeys, orderedGroupSizes)

	// Now that we've verified the group count, size, and balance, we also
	// need to check that the intended asset was used as the group anchor.
	// We can do this by re-deriving the tweaked group key.
	matchingName := func(asset *tarorpc.Asset, name string) bool {
		return asset.AssetGenesis.Name == name
	}

	// We need to fetch the minted group anchor asset, which includes the
	// genesis information used to compute the tweak for the group key.
	normalAnchor, err := chanutils.First(
		mintedBatch, func(asset *tarorpc.Asset) bool {
			return matchingName(asset, issuableAssets[0].Asset.Name)
		},
	)
	require.NoError(t.t, err)
	normalAnchorGen := parseGenInfo(t.t, normalAnchor.AssetGenesis)
	normalAnchorGen.Type = asset.Type(normalAnchor.AssetType)
	assertGroupAnchor(
		t.t, normalAnchorGen, normalAnchor.AssetGroup.RawGroupKey,
		normalAnchor.AssetGroup.TweakedGroupKey,
	)

	collectAnchor, err := chanutils.First(
		mintedBatch, func(asset *tarorpc.Asset) bool {
			return matchingName(asset, issuableAssets[1].Asset.Name)
		},
	)
	require.NoError(t.t, err)
	collectAnchorGen := parseGenInfo(t.t, collectAnchor.AssetGenesis)
	collectAnchorGen.Type = asset.Type(collectAnchor.AssetType)
	assertGroupAnchor(
		t.t, collectAnchorGen, collectAnchor.AssetGroup.RawGroupKey,
		collectAnchor.AssetGroup.TweakedGroupKey,
	)

	// Finally, we send some assets from the multi-asset group to Bob to
	// ensure that they can be sent and received correctly.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tarodHarnessParams) {
			params.startupSyncNode = t.tarod
			params.startupSyncNumAssets = 4
		},
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	normalMember, err := chanutils.First(
		mintedBatch, func(asset *tarorpc.Asset) bool {
			return asset.Amount == normalAnchor.Amount/2
		},
	)
	require.NoError(t.t, err)

	normalMemberGenInfo := normalMember.AssetGenesis

	// The assets to send are selected; we now generate an address, send,
	// and verify the transfer.
	bobNormalAddr, err := secondTarod.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		AssetId: normalMemberGenInfo.AssetId,
		Amt:     normalMember.Amount,
	})
	require.NoError(t.t, err)

	normalGroupSend := sendAssetsToAddr(t, t.tarod, bobNormalAddr)
	confirmAndAssertOutboundTransfer(
		t, t.tarod, normalGroupSend, normalMember.AssetGenesis.AssetId,
		[]uint64{0, normalMember.Amount}, 0, 1,
	)
	_ = sendProof(
		t, t.tarod, secondTarod, bobNormalAddr.ScriptKey,
		normalMemberGenInfo,
	)
	assertNonInteractiveRecvComplete(t, secondTarod, 1)

	assertBalanceByGroup(
		t.t, secondTarod, normalGroupKey, normalMember.Amount,
	)

	// We want to select the one collectible that is in the same group as
	// the collectible group anchor, and is not the anchor itself.
	isCollectGroupMember := func(asset *tarorpc.Asset) bool {
		isNotAnchor := asset.AssetGenesis.Name != collectAnchorGen.Tag
		if asset.AssetGroup == nil {
			return false
		}

		isGrouped := collectGroupKey == hex.EncodeToString(
			asset.AssetGroup.TweakedGroupKey,
		)
		return isNotAnchor && isGrouped
	}
	collectMember, err := chanutils.First(mintedBatch, isCollectGroupMember)
	require.NoError(t.t, err)

	collectMemberGenInfo := collectMember.AssetGenesis
	bobCollectAddr, err := secondTarod.NewAddr(ctxb, &tarorpc.NewAddrRequest{
		AssetId: collectMemberGenInfo.AssetId,
		Amt:     collectMember.Amount,
	})
	require.NoError(t.t, err)

	collectGroupSend := sendAssetsToAddr(t, t.tarod, bobCollectAddr)
	confirmAndAssertOutboundTransfer(
		t, t.tarod, collectGroupSend, collectMember.AssetGenesis.AssetId,
		[]uint64{0, collectMember.Amount}, 1, 2,
	)
	sendProof(
		t, t.tarod, secondTarod, bobCollectAddr.ScriptKey,
		collectMemberGenInfo,
	)
	assertNonInteractiveRecvComplete(t, secondTarod, 2)

	assertBalanceByGroup(
		t.t, secondTarod, collectGroupKey, collectMember.Amount,
	)
}

// createMultiAssetGroup creates a list of minting requests that represent a
// multi-asset group, using the anchor asset to generate parameters for the
// other assets in the group.
func createMultiAssetGroup(anchor *mintrpc.MintAssetRequest,
	numAssets uint64) ([]*mintrpc.MintAssetRequest, uint64) {

	// We'll use descending amounts for the assets in the group, and use
	// the asset name to indicate the asset's place in the group.
	groupRequests := []*mintrpc.MintAssetRequest{copyRequest(anchor)}
	anchorAmount := anchor.Asset.Amount
	anchorName := anchor.Asset.Name
	nameModifier := "-tranche-"
	groupSum := uint64(0)
	for i := uint64(1); i < numAssets+1; i++ {
		assetReq := copyRequest(anchor)
		assetReq.EnableEmission = false
		assetReq.Asset.GroupAnchor = anchorName
		reqName := anchorName + nameModifier + strconv.FormatUint(i, 10)
		assetReq.Asset.Name = reqName

		if assetReq.Asset.AssetType == tarorpc.AssetType_NORMAL {
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
	groupedAsset := copyRequest(simpleAssets[0])
	groupedAsset.Asset.GroupAnchor = groupedAsset.Asset.Name

	_, err := t.tarod.MintAsset(ctxb, groupedAsset)
	require.ErrorContains(t.t, err, "batch empty, group anchor")

	// The current request references a group anchor that does not exist,
	// which makes it invalid.
	simpleAsset := copyRequest(simpleAssets[1])
	_, err = t.tarod.MintAsset(ctxb, simpleAsset)
	require.NoError(t.t, err)
	_, err = t.tarod.MintAsset(ctxb, groupedAsset)
	require.ErrorContains(t.t, err, "not present in batch")

	// Now we'll construct an asset to use as an invalid group anchor;
	// group anchors must have emission enabled.
	validAnchor := copyRequest(simpleAssets[0])
	validAnchorName := validAnchor.Asset.Name + validAnchor.Asset.Name
	validAnchor.Asset.Name = validAnchorName
	_, err = t.tarod.MintAsset(ctxb, validAnchor)
	require.NoError(t.t, err)

	groupedAsset.Asset.GroupAnchor = validAnchorName
	_, err = t.tarod.MintAsset(ctxb, groupedAsset)
	require.ErrorContains(t.t, err, "has emission disabled")

	// Finally, we'll modify the assets to make the multi-asset group valid.
	validAnchor.EnableEmission = true
	validAnchor.Asset.AssetMeta = &tarorpc.AssetMeta{
		Data: []byte("metadata for itest group anchors"),
	}

	_, err = t.tarod.CancelBatch(ctxb, &mintrpc.CancelBatchRequest{})
	require.NoError(t.t, err)
	multiAssetGroup := []*mintrpc.MintAssetRequest{validAnchor, groupedAsset}

	// The assets should be minted into the same group.
	rpcGroupedAssets := mintAssetsConfirmBatch(t, t.tarod, multiAssetGroup)
	assertNumGroups(t.t, t.tarod, 1)
	groupKey := rpcGroupedAssets[0].AssetGroup.TweakedGroupKey
	groupKeyHex := hex.EncodeToString(groupKey)
	expectedGroupBalance := groupedAsset.Asset.Amount +
		validAnchor.Asset.Amount
	assertBalanceByGroup(t.t, t.tarod, groupKeyHex, expectedGroupBalance)
}

func parseGenInfo(t *testing.T, genInfo *tarorpc.GenesisInfo) *asset.Genesis {
	genPoint, err := parseOutPoint(genInfo.GenesisPoint)
	require.NoError(t, err)

	parsedGenesis := asset.Genesis{
		FirstPrevOut: *genPoint,
		Tag:          genInfo.Name,
		OutputIndex:  genInfo.OutputIndex,
	}
	copy(parsedGenesis.MetaHash[:], genInfo.MetaHash)

	return &parsedGenesis
}
