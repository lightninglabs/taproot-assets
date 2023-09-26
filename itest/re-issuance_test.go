package itest

import (
	"context"
	"encoding/hex"
	"math"

	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// testReIssuance tests that we can properly reissue an asset into group, and
// that the daemon handles a group with multiple assets correctly.
func testReIssuance(t *harnessTest) {
	miner := t.lndHarness.Miner.Client

	// First, we'll mint a collectible and a normal asset, both with
	// emission enabled.
	normalGroupGen := MintAssetsConfirmBatch(
		t.t, miner, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)
	collectGroupGen := MintAssetsConfirmBatch(
		t.t, miner, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[1]},
	)
	require.Equal(t.t, 1, len(normalGroupGen))
	require.Equal(t.t, 1, len(collectGroupGen))

	ctxb := context.Background()
	groupCount := 2

	// We'll confirm that the node created two separate groups during
	// minting.
	AssertNumGroups(t.t, t.tapd, groupCount)

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
	numTotalAssets := len(normalGroupGen) + len(collectGroupGen)
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.startupSyncNode = t.tapd
			params.startupSyncNumAssets = numTotalAssets
		},
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	// Send the minted collectible to the second node so that it imports
	// the asset group.
	collectGroupAddr, err := secondTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: collectGenInfo.AssetId,
			Amt:     1,
		},
	)
	require.NoError(t.t, err)

	firstCollectSend := sendAssetsToAddr(t, t.tapd, collectGroupAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, t.tapd, firstCollectSend,
		collectGenInfo.AssetId, []uint64{0, 1}, 0, 1,
	)
	sendProof(
		t, t.tapd, secondTapd, collectGroupAddr.ScriptKey,
		collectGenInfo,
	)

	// Check the state of both nodes. The first node should show one
	// zero-value transfer representing the send of the collectible.
	AssertTransfer(t.t, t.tapd, 0, 1, []uint64{0, 1})
	AssertBalanceByID(t.t, t.tapd, collectGenInfo.AssetId, 0)

	// The second node should show a balance of 1 for exactly one group.
	AssertBalanceByID(t.t, secondTapd, collectGenInfo.AssetId, 1)
	AssertBalanceByGroup(t.t, secondTapd, encodedCollectGroupKey, 1)

	// Send half of the normal asset to the second node before reissuance.
	normalGroupAddr, err := secondTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: normalGenInfo.AssetId,
			Amt:     normalGroupMintHalf,
		},
	)
	require.NoError(t.t, err)

	firstNormalSend := sendAssetsToAddr(t, t.tapd, normalGroupAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, t.tapd, firstNormalSend,
		normalGenInfo.AssetId,
		[]uint64{normalGroupMintHalf, normalGroupMintHalf}, 1, 2,
	)
	sendProof(
		t, t.tapd, secondTapd, normalGroupAddr.ScriptKey,
		normalGenInfo,
	)

	// Reissue one more collectible and half the original mint amount for
	// the normal asset.
	reissuedAssets := CopyRequests(simpleAssets)

	reissuedAssets[0].Asset.Amount = normalGroupMintHalf
	reissuedAssets[0].Asset.GroupKey = normalGroupKey
	reissuedAssets[1].Asset.GroupKey = collectGroupKey

	normalReissueGen := MintAssetsConfirmBatch(
		t.t, miner, t.tapd,
		[]*mintrpc.MintAssetRequest{reissuedAssets[0]},
	)
	collectReissueGen := MintAssetsConfirmBatch(
		t.t, miner, t.tapd,
		[]*mintrpc.MintAssetRequest{reissuedAssets[1]},
	)
	require.Equal(t.t, 1, len(normalReissueGen))
	require.Equal(t.t, 1, len(collectReissueGen))

	// Sync the second node with the new universe state.
	t.syncUniverseState(
		t.tapd, secondTapd,
		len(normalReissueGen)+len(collectReissueGen),
	)

	// Check the node state after re-issuance. The total number of groups
	// should still be two.
	AssertNumGroups(t.t, t.tapd, groupCount)

	// The normal group should hold two assets, while the collectible
	// should only hold one, since the zero-value tombstone is only visible
	// in the transfers and is not re-created as an asset.
	groupsAfterReissue, err := t.tapd.ListGroups(
		ctxb, &taprpc.ListGroupsRequest{},
	)
	require.NoError(t.t, err)

	normalGroup := groupsAfterReissue.Groups[encodedNormalGroupKey]
	require.Len(t.t, normalGroup.Assets, 2)

	collectGroup := groupsAfterReissue.Groups[encodedCollectGroupKey]
	require.Len(t.t, collectGroup.Assets, 1)

	AssertSplitTombstoneTransfer(t.t, t.tapd, collectGenInfo.AssetId)

	// The normal group balance should account for the re-issuance and
	// equal the original mint amount. The collectible group balance should
	// be back at 1.
	AssertBalanceByGroup(
		t.t, t.tapd, hex.EncodeToString(normalGroupKey),
		normalGroupGen[0].Amount,
	)
	AssertBalanceByGroup(
		t.t, t.tapd, hex.EncodeToString(collectGroupKey), 1,
	)

	// We'll send the new collectible to the second node to ensure that
	// non-local groups are also handled properly.
	collectReissueInfo := collectReissueGen[0].AssetGenesis
	collectReissueAddr, err := secondTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: collectReissueInfo.AssetId,
			Amt:     1,
		},
	)
	require.NoError(t.t, err)

	secondCollectSend := sendAssetsToAddr(t, t.tapd, collectReissueAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, t.tapd, secondCollectSend,
		collectReissueInfo.AssetId, []uint64{0, 1}, 2, 3,
	)
	sendProof(
		t, t.tapd, secondTapd, collectReissueAddr.ScriptKey,
		collectReissueInfo,
	)

	// The second node should show two groups, with two assets in
	// the collectible group and a total balance of 2 for that group.
	AssertNumGroups(t.t, secondTapd, groupCount)
	groupsSecondNode, err := secondTapd.ListGroups(
		ctxb, &taprpc.ListGroupsRequest{},
	)
	require.NoError(t.t, err)

	collectGroupSecondNode := groupsSecondNode.Groups[encodedCollectGroupKey]
	require.Equal(t.t, 2, len(collectGroupSecondNode.Assets))

	AssertBalanceByGroup(
		t.t, secondTapd, hex.EncodeToString(collectGroupKey), 2,
	)

	// We should also be able to send a collectible back to the minting node.
	collectGenAddr, err := t.tapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: collectGenInfo.AssetId,
			Amt:     1,
		},
	)
	require.NoError(t.t, err)

	thirdCollectSend := sendAssetsToAddr(t, secondTapd, collectGenAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, secondTapd.ht.lndHarness.Miner.Client, secondTapd,
		thirdCollectSend, collectGenInfo.AssetId, []uint64{0, 1}, 0, 1,
	)
	sendProof(
		t, secondTapd, t.tapd, collectReissueAddr.ScriptKey,
		collectReissueInfo,
	)

	// The collectible balance on the minting node should be 1, and there
	// should still be only two groups.
	AssertBalanceByGroup(
		t.t, t.tapd, hex.EncodeToString(collectGroupKey), 1,
	)
	AssertNumGroups(t.t, t.tapd, groupCount)
}

// testReIssuanceAmountOverflow tests that an error is returned when attempting
// to issue a further quantity of an asset beyond the integer overflow limit.
func testReIssuanceAmountOverflow(t *harnessTest) {
	// Mint an asset with the maximum possible amount supported by the RPC
	// endpoint.
	t.Log("Minting asset with maximum possible amount")

	assetIssueReqs := CopyRequests(issuableAssets)
	assetIssueReq := assetIssueReqs[0]

	assetIssueReq.EnableEmission = true
	assetIssueReq.Asset.Amount = math.MaxUint64

	assets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{assetIssueReq},
	)
	require.Equal(t.t, 1, len(assets))

	groupKey := assets[0].AssetGroup.TweakedGroupKey

	// Re-issue a further quantity of the asset at the maximum possible
	// amount supported by the RPC endpoint.
	t.Log("Re-issuing asset with maximum possible amount")

	assetIssueReqs = CopyRequests(simpleAssets)
	assetIssueReq = assetIssueReqs[0]

	// Reissue an amount which is minimally sufficient to lead to an
	// overflow error.
	assetIssueReq.Asset.Amount = 1
	assetIssueReq.EnableEmission = false
	assetIssueReq.Asset.GroupKey = groupKey

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()
	_, err := t.tapd.MintAsset(ctxt, assetIssueReq)
	require.ErrorContains(t.t, err, mssmt.ErrIntegerOverflow.Error())
}

// testMintWithGroupKeyErrors tests that the minter rejects minting requests
// that incorrectly try to specify a group for reissuance.
func testMintWithGroupKeyErrors(t *harnessTest) {
	// First, mint a collectible with emission enabled to create one group.
	collectGroupGen := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner.Client, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[1]},
	)
	require.Equal(t.t, 1, len(collectGroupGen))

	ctxb := context.Background()

	// We'll store the group key and genesis from the minting to use
	// later when creating addresses.
	collectGroupKey := collectGroupGen[0].AssetGroup.TweakedGroupKey
	collectGenInfo := collectGroupGen[0].AssetGenesis

	// Now, create a minting request to try and reissue into the group
	// created during minting.
	reissueRequest := CopyRequest(simpleAssets[0])
	reissueRequest.Asset.GroupKey = collectGroupKey

	// A request must not have the emission flag set if a group key is given.
	reissueRequest.EnableEmission = true

	_, err := t.tapd.MintAsset(ctxb, reissueRequest)
	require.ErrorContains(t.t, err, "must disable emission")

	// Restore the emission flag.
	reissueRequest.EnableEmission = false

	// A given group key must be parseable, so a group key with an invalid
	// parity byte should be rejected.
	grouKeyParity := reissueRequest.Asset.GroupKey[0]
	reissueRequest.Asset.GroupKey[0] = 0xFF

	_, err = t.tapd.MintAsset(ctxb, reissueRequest)
	require.ErrorContains(t.t, err, "invalid group key")

	// Restore the group key parity byte.
	reissueRequest.Asset.GroupKey[0] = grouKeyParity

	// The minting request asset type must match the type of the asset group.
	_, err = t.tapd.MintAsset(ctxb, reissueRequest)
	require.ErrorContains(t.t, err, "seedling type does not match")

	// Create a second node, which will have no information about previously
	// minted assets or asset groups.
	secondTapd := setupTapdHarness(
		t.t, t, t.lndHarness.Bob, t.universeServer,
		func(params *tapdHarnessParams) {
			params.startupSyncNode = t.tapd
			params.startupSyncNumAssets = len(collectGroupGen)
		},
	)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	// The node must have information on the group to reissue, so this
	// minting request must fail on the second node.
	_, err = secondTapd.MintAsset(ctxb, reissueRequest)
	require.ErrorContains(t.t, err, "can't sign")

	// Send the minted collectible to the second node so that it imports
	// the asset group.
	collectGroupAddr, err := secondTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId: collectGenInfo.AssetId,
			Amt:     1,
		},
	)
	require.NoError(t.t, err)

	collectSend := sendAssetsToAddr(t, t.tapd, collectGroupAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner.Client, t.tapd, collectSend,
		collectGenInfo.AssetId, []uint64{0, 1}, 0, 1,
	)
	sendProof(
		t, t.tapd, secondTapd, collectGroupAddr.ScriptKey,
		collectGenInfo,
	)

	// A reissuance with the second node should still fail because the
	// group key was not created by that node.
	_, err = secondTapd.MintAsset(ctxb, reissueRequest)
	require.ErrorContains(t.t, err, "can't sign with group key")
}
