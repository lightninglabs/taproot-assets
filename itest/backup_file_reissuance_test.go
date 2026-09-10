package itest

import (
	"context"

	"github.com/lightninglabs/taproot-assets/backup"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// testBackupFileReissuance asserts that a wallet holding only reissued assets,
// leaves whose genesis proof carries a group key but no group key reveal, is
// restored in full from the backup file. A reveal is only present on the
// genesis proof of the asset that created the group, so the restore cannot
// learn the group from the proofs in the file and must rely on the group
// information recorded in the backup entries.
//
// Flow:
//  1. Alice mints a grouped asset (the group anchor) and then reissues a
//     second tranche into the same group.
//  2. Alice sends part of the reissued tranche to Bob. Bob now holds a single
//     leaf of the group and never saw the anchor's proof.
//  3. Bob's tapd is stopped and its data dropped. A fresh tapd on the same
//     lnd, with no universe server to learn the group from, imports the
//     file and must recover the leaf without skipping it. The restored
//     node's own backup file describes the group again and a second wiped
//     node restores from that file.
//  4. The restored leaf is spendable: Bob sends it back to Alice.
func testBackupFileReissuance(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout*6)
	defer cancel()

	// === Stage 1: Mint the group anchor and a reissuance on Alice ===
	anchorReq := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      "backup-reissue-anchor",
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("backup reissuance test"),
			},
			Amount:          1000,
			NewGroupedAsset: true,
		},
	}
	anchor := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner(), t.tapd,
		[]*mintrpc.MintAssetRequest{anchorReq},
	)[0]
	require.NotNil(t.t, anchor.AssetGroup)
	groupKey := anchor.AssetGroup.TweakedGroupKey

	reissueReq := CopyRequest(anchorReq)
	reissueReq.Asset.Name = "backup-reissue-tranche-2"
	reissueReq.Asset.Amount = 500
	reissueReq.Asset.NewGroupedAsset = false
	reissueReq.Asset.GroupedAsset = true
	reissueReq.Asset.GroupKey = groupKey
	reissued := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner(), t.tapd,
		[]*mintrpc.MintAssetRequest{reissueReq},
	)[0]
	require.Equal(t.t, groupKey, reissued.AssetGroup.TweakedGroupKey)
	AssertNumGroups(t.t, t.tapd, 1)

	// === Stage 2: Send part of the reissued tranche to Bob ===
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)

	bobLndClient, err := t.newLndClient(bobLnd)
	require.NoError(t.t, err)
	defer bobLndClient.Close()

	const bobAmount = 400
	bobAddr, err := bobTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:      reissued.AssetGenesis.AssetId,
		Amt:          bobAmount,
		AssetVersion: reissued.Version,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, bobTapd, reissued, bobAddr)

	sendResp, _ := sendAssetsToAddr(t, t.tapd, bobAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner(), t.tapd, sendResp,
		reissued.AssetGenesis.AssetId,
		[]uint64{reissued.Amount - bobAmount, bobAmount}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)

	// Bob holds exactly one leaf, a reissuance, and knows its group.
	bobAssets, err := bobTapd.ListAssets(ctxt, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, bobAssets.Assets, 1)
	AssertNumGroups(t.t, bobTapd, 1)

	bobRaw, bobBackup := waitForBackupFile(
		t, bobTapd, bobLndClient, expectEntries(bobAmount),
	)
	entry := bobBackup.Assets[0]
	require.NotNil(t.t, entry.Asset.GroupKey)

	// The genesis proof of a reissuance carries no group key reveal, so
	// the entry must describe the group itself, anchored at the genesis of
	// the asset that created the group.
	assertGroupKeyInfo(t, entry, anchor, groupKey)

	// === Stage 3: Restore Bob from the file on a wiped node ===
	// The fresh node must not learn the group from anywhere but the file,
	// so it is started without the universe server in its federation. A
	// real wallet does not sync every issuance tree of its federation
	// either, that is off by default.
	require.NoError(t.t, bobTapd.stop(!*noDelete))

	bobTapd2 := setupTapdHarness(
		t.t, t, bobLnd, t.universeServer,
		func(params *tapdHarnessParams) {
			params.noDefaultUniverseSync = true
		},
	)

	bobAssets, err = bobTapd2.ListAssets(ctxt, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)
	require.Empty(t.t, bobAssets.Assets)
	AssertNumGroups(t.t, bobTapd2, 0)

	importResp, err := bobTapd2.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{Backup: bobRaw},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(0), importResp.NumSkipped)
	require.Equal(t.t, uint32(1), importResp.NumImported)

	assertRestoredReissuance(t, bobTapd2, reissued, bobAmount)

	// The restored node learned the group from the file, so its own
	// backup file describes the group again. A restore from it must work
	// the same way, otherwise the file degrades with every restore.
	bobRaw2, bobBackup2 := waitForBackupFile(
		t, bobTapd2, bobLndClient, expectEntries(bobAmount),
	)
	assertGroupKeyInfo(t, bobBackup2.Assets[0], anchor, groupKey)

	require.NoError(t.t, bobTapd2.stop(!*noDelete))
	bobTapd3 := setupTapdHarness(
		t.t, t, bobLnd, t.universeServer,
		func(params *tapdHarnessParams) {
			params.noDefaultUniverseSync = true
		},
	)
	defer func() {
		require.NoError(t.t, bobTapd3.stop(!*noDelete))
	}()

	importResp, err = bobTapd3.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{Backup: bobRaw2},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(0), importResp.NumSkipped)
	require.Equal(t.t, uint32(1), importResp.NumImported)

	assertRestoredReissuance(t, bobTapd3, reissued, bobAmount)

	// === Stage 4: The restored leaf is spendable ===
	aliceAddr, err := t.tapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:      reissued.AssetGenesis.AssetId,
		Amt:          bobAmount,
		AssetVersion: reissued.Version,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, t.tapd, reissued, aliceAddr)

	sendResp, _ = sendAssetsToAddr(t, bobTapd3, aliceAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner(), bobTapd3, sendResp,
		reissued.AssetGenesis.AssetId, []uint64{0, bobAmount}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, t.tapd, 1)

	waitForBackupFile(t, bobTapd3, bobLndClient, expectEntries())
}

// assertGroupKeyInfo asserts that a backup entry records the asset group of
// its leaf: the genesis of the group anchor and parameters that re-derive the
// tweaked group key.
func assertGroupKeyInfo(t *harnessTest, entry *backup.AssetBackup,
	anchor *taprpc.Asset, groupKey []byte) {

	require.NotNil(t.t, entry.GroupKeyInfo)
	anchorID := entry.GroupKeyInfo.AnchorGenesis.ID()
	require.Equal(t.t, anchor.AssetGenesis.AssetId, anchorID[:])
	require.NotEmpty(t.t, entry.GroupKeyInfo.Witness)

	derived, err := entry.GroupKeyInfo.GroupKey()
	require.NoError(t.t, err)
	require.Equal(t.t, groupKey, derived.GroupPubKey.SerializeCompressed())
}

// assertRestoredReissuance asserts that a restored node lists the reissued
// leaf with the default filters, in ListAssets and in ListBalances, and knows
// the asset group it belongs to.
func assertRestoredReissuance(t *harnessTest, tapd *tapdHarness,
	reissued *taprpc.Asset, amount uint64) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	assets, err := tapd.ListAssets(ctxt, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, assets.Assets, 1)
	require.Equal(t.t, reissued.AssetGenesis.AssetId,
		assets.Assets[0].AssetGenesis.AssetId)
	require.Equal(t.t, amount, assets.Assets[0].Amount)
	require.Equal(t.t, taprpc.ScriptKeyType_SCRIPT_KEY_BIP86,
		assets.Assets[0].ScriptKeyType)
	require.NotNil(t.t, assets.Assets[0].AssetGroup)
	require.Equal(t.t, reissued.AssetGroup.TweakedGroupKey,
		assets.Assets[0].AssetGroup.TweakedGroupKey)

	balances, err := tapd.ListBalances(ctxt, &taprpc.ListBalancesRequest{
		GroupBy: &taprpc.ListBalancesRequest_GroupKey{GroupKey: true},
	})
	require.NoError(t.t, err)
	require.Len(t.t, balances.AssetGroupBalances, 1)
	for _, b := range balances.AssetGroupBalances {
		require.Equal(t.t, amount, b.Balance)
	}

	AssertNumGroups(t.t, tapd, 1)
}
