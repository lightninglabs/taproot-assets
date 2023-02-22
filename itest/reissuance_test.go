package itest

import (
	"context"
	"encoding/hex"

	"github.com/lightninglabs/taro/tarorpc"
	"github.com/stretchr/testify/require"
)

// testReissuance tests that we can properly reissue an asset into group, and
// that the daemon handles a group with multiple assets correctly.
func testReissuance(t *harnessTest) {
	// First, we'll mint a collectible and a normal asset, both with
	// emission enabled.
	normalGroupGen := mintAssetsConfirmBatch(
		t, t.tarod, []*tarorpc.MintAssetRequest{issuableAssets[0]},
	)
	collectGroupGen := mintAssetsConfirmBatch(
		t, t.tarod, []*tarorpc.MintAssetRequest{issuableAssets[1]},
	)
	require.Equal(t.t, 1, len(normalGroupGen))
	require.Equal(t.t, 1, len(collectGroupGen))

	ctxb := context.Background()
	groupCount := 2

	// We'll confirm that the node created two separate groups during minting.
	assertNumGroups(t.t, t.tarod, groupCount)

	// We'll store the group keys and geneses from the minting to use
	// later when creating addresses.
	normalGroupKey := normalGroupGen[0].AssetGroup.TweakedGroupKey
	encodedNormalGroupKey := hex.EncodeToString(normalGroupKey)
	normalGenInfo := normalGroupGen[0].AssetGenesis
	collectGroupKey := collectGroupGen[0].AssetGroup.TweakedGroupKey
	encodedCollectGroupKey := hex.EncodeToString(collectGroupKey)
	collectGenInfo := collectGroupGen[0].AssetGenesis
	normalGroupMintHalf := normalGroupGen[0].Amount / 2

	// Create a second node, which will have no information about previously
	// minted assets or asset groups.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.BackendCfg, t.lndHarness.Bob,
		t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	// Send the minted collectible to the second node so that it imports
	// the asset group.
	collectGroupAddr, err := secondTarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			GenesisBootstrapInfo: collectGenInfo.GenesisBootstrapInfo,
			GroupKey:             collectGroupKey,
			Amt:                  1,
		},
	)
	require.NoError(t.t, err)

	firstCollectSend := sendAssetsToAddr(t, t.tarod, collectGroupAddr)
	confirmAndAssertOutboundTransfer(
		t, t.tarod, firstCollectSend, collectGenInfo.AssetId, 0, 0, 1,
	)
	sendProof(t, t.tarod, secondTarod, collectGroupAddr, collectGenInfo)

	// Check the state of both nodes. The first node should show one
	// zero-value transfer representing the send of the collectible.
	assertTransfers(t.t, t.tarod, []int64{0})
	assertBalanceByID(t.t, t.tarod, collectGenInfo.AssetId, int64(0))

	// The second node should show a balance of 1 for exactly one group.
	assertBalanceByID(t.t, secondTarod, collectGenInfo.AssetId, int64(1))
	assertBalanceByGroup(t.t, secondTarod, collectGroupKey, int64(1))

	// Send half of the normal asset to the second node before reissuance.
	normalGroupAddr, err := secondTarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			GenesisBootstrapInfo: normalGenInfo.GenesisBootstrapInfo,
			GroupKey:             normalGroupKey,
			Amt:                  normalGroupMintHalf,
		},
	)
	require.NoError(t.t, err)

	firstNormalSend := sendAssetsToAddr(t, t.tarod, normalGroupAddr)
	confirmAndAssertOutboundTransfer(
		t, t.tarod, firstNormalSend, normalGenInfo.AssetId,
		normalGroupMintHalf, 1, 2,
	)
	sendProof(t, t.tarod, secondTarod, normalGroupAddr, normalGenInfo)

	// Reissue one more collectible and half the original mint amount for
	// the normal asset.
	reissuedAssets := copyRequests(simpleAssets)

	reissuedAssets[0].Amount = normalGroupMintHalf
	reissuedAssets[0].GroupKey = normalGroupKey
	reissuedAssets[1].GroupKey = collectGroupKey

	normalReissueGen := mintAssetsConfirmBatch(
		t, t.tarod, []*tarorpc.MintAssetRequest{reissuedAssets[0]},
	)
	collectReissueGen := mintAssetsConfirmBatch(
		t, t.tarod, []*tarorpc.MintAssetRequest{reissuedAssets[1]},
	)
	require.Equal(t.t, 1, len(normalReissueGen))
	require.Equal(t.t, 1, len(collectReissueGen))

	// Check the node state after reissuance. The total number of groups
	// should still be two.
	assertNumGroups(t.t, t.tarod, groupCount)

	// Both groups should hold two assets; the collectible group has both
	// the reissued collectible and the zero-value root asset from the send.
	groupsAfterReissue, err := t.tarod.ListGroups(
		ctxb, &tarorpc.ListGroupsRequest{},
	)
	require.NoError(t.t, err)

	normalGroup := groupsAfterReissue.Groups[encodedNormalGroupKey]
	require.Equal(t.t, 2, len(normalGroup.Assets))

	collectGroup := groupsAfterReissue.Groups[encodedCollectGroupKey]
	require.Equal(t.t, 2, len(collectGroup.Assets))

	// The normal group balance should account for the reissuance and equal
	// the original mint amount. The collectible group balance should be
	// back at 1.
	assertBalanceByGroup(
		t.t, t.tarod, normalGroupKey, normalGroupGen[0].Amount,
	)
	assertBalanceByGroup(t.t, t.tarod, collectGroupKey, 1)

	// We'll send the new collectible to the second node to ensure that
	// non-local groups are also handled properly.
	collectReissueInfo := collectReissueGen[0].AssetGenesis
	collectReissueAddr, err := secondTarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			GenesisBootstrapInfo: collectReissueInfo.
				GenesisBootstrapInfo,
			GroupKey: collectGroupKey,
			Amt:      1,
		},
	)
	require.NoError(t.t, err)

	secondCollectSend := sendAssetsToAddr(t, t.tarod, collectReissueAddr)
	confirmAndAssertOutboundTransfer(
		t, t.tarod, secondCollectSend,
		collectReissueInfo.AssetId, 0, 2, 3,
	)
	sendProof(t, t.tarod, secondTarod, collectReissueAddr, collectReissueInfo)

	// The second node should show two groups, with two assets in
	// the collectible group and a total balance of 2 for that group.
	assertNumGroups(t.t, secondTarod, groupCount)
	groupsSecondNode, err := secondTarod.ListGroups(
		ctxb, &tarorpc.ListGroupsRequest{},
	)
	require.NoError(t.t, err)

	collectGroupSecondNode := groupsSecondNode.Groups[encodedCollectGroupKey]
	require.Equal(t.t, 2, len(collectGroupSecondNode.Assets))

	assertBalanceByGroup(t.t, secondTarod, collectGroupKey, 2)

	// We should also be able to send a collectile back to the minting node.
	collectGenAddr, err := t.tarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			GenesisBootstrapInfo: collectGenInfo.GenesisBootstrapInfo,
			GroupKey:             collectGroupKey,
			Amt:                  1,
		},
	)
	require.NoError(t.t, err)

	thirdCollectSend := sendAssetsToAddr(t, secondTarod, collectGenAddr)
	confirmAndAssertOutboundTransfer(
		t, secondTarod, thirdCollectSend,
		collectGenInfo.AssetId, 0, 0, 1,
	)
	sendProof(t, secondTarod, t.tarod, collectReissueAddr, collectReissueInfo)

	// The collectible balance on the minting node should be 1, and there
	// should still be only two groups.
	assertBalanceByGroup(t.t, t.tarod, collectGroupKey, 1)
	assertNumGroups(t.t, t.tarod, groupCount)
}

// testMintWithGroupKeyErrors tests that the minter rejects minting requests
// that incorrectly try to specify a group for reissuance.
func testMintWithGroupKeyErrors(t *harnessTest) {
	// First, mint a collectible with emission enabled to create one group.
	collectGroupGen := mintAssetsConfirmBatch(
		t, t.tarod, []*tarorpc.MintAssetRequest{issuableAssets[1]},
	)
	require.Equal(t.t, 1, len(collectGroupGen))

	ctxb := context.Background()

	// We'll store the group key and genesis from the minting to use
	// later when creating addresses.
	collectGroupKey := collectGroupGen[0].AssetGroup.TweakedGroupKey
	collectGenInfo := collectGroupGen[0].AssetGenesis

	// Now, create a minting request to try and reissue into the group
	// created during minting.
	reissueRequest := copyRequest(simpleAssets[0])
	reissueRequest.GroupKey = collectGroupKey

	// A request must not have the emission flag set if a group key is given.
	reissueRequest.EnableEmission = true

	_, err := t.tarod.MintAsset(ctxb, reissueRequest)
	require.ErrorContains(t.t, err, "must disable emission")

	// Restore the emission flag.
	reissueRequest.EnableEmission = false

	// A given group key must be parseable, so a group key with an invalid
	// parity byte should be rejected.
	grouKeyParity := reissueRequest.GroupKey[0]
	reissueRequest.GroupKey[0] = 0xFF

	_, err = t.tarod.MintAsset(ctxb, reissueRequest)
	require.ErrorContains(t.t, err, "invalid group key")

	// Restore the group key parity byte.
	reissueRequest.GroupKey[0] = grouKeyParity

	// The minting request asset type must match the type of the asset group.
	_, err = t.tarod.MintAsset(ctxb, reissueRequest)
	require.ErrorContains(t.t, err, "seedling type does not match")

	// Create a second node, which will have no information about previously
	// minted assets or asset groups.
	secondTarod := setupTarodHarness(
		t.t, t, t.lndHarness.BackendCfg, t.lndHarness.Bob,
		t.universeServer,
	)
	defer func() {
		require.NoError(t.t, secondTarod.stop(true))
	}()

	// The node must have information on the group to reissue, so this
	// minting request must fail on the second node.
	_, err = secondTarod.MintAsset(ctxb, reissueRequest)
	require.ErrorContains(t.t, err, "not found")

	// Send the minted collectible to the second node so that it imports
	// the asset group.
	collectGroupAddr, err := secondTarod.NewAddr(
		ctxb, &tarorpc.NewAddrRequest{
			GenesisBootstrapInfo: collectGenInfo.GenesisBootstrapInfo,
			GroupKey:             collectGroupKey,
			Amt:                  1,
		},
	)
	require.NoError(t.t, err)

	collectSend := sendAssetsToAddr(t, t.tarod, collectGroupAddr)
	confirmAndAssertOutboundTransfer(
		t, t.tarod, collectSend, collectGenInfo.AssetId, 0, 0, 1,
	)
	sendProof(t, t.tarod, secondTarod, collectGroupAddr, collectGenInfo)

	// A reissuance with the second node should still fail because the
	// group key was not created by that node.
	_, err = secondTarod.MintAsset(ctxb, reissueRequest)
	require.ErrorContains(t.t, err, "can't sign with group key")
}
