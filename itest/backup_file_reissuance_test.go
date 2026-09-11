package itest

import (
	"context"
	"encoding/hex"

	"github.com/lightninglabs/taproot-assets/asset"
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
// The group here is a V0 group, minted with a key of the node's own wallet.
func testBackupFileReissuance(t *harnessTest) {
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

	reissueReq := CopyRequest(anchorReq)
	reissueReq.Asset.Name = "backup-reissue-tranche-2"
	reissueReq.Asset.Amount = 500
	reissueReq.Asset.NewGroupedAsset = false
	reissueReq.Asset.GroupedAsset = true
	reissueReq.Asset.GroupKey = anchor.AssetGroup.TweakedGroupKey
	reissued := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner(), t.tapd,
		[]*mintrpc.MintAssetRequest{reissueReq},
	)[0]

	runBackupFileReissuance(t, anchor, reissued, asset.GroupKeyV0)
}

// testBackupFileReissuanceV1 is the same restore flow for a V1 group, minted
// with an external group key held by chantools. V1 is the construction used
// whenever the group key is not in the node's own wallet, and its version and
// custom subtree root must survive the round trip through the receiver's
// database and the backup entry, otherwise the group cannot be re-derived on
// import.
func testBackupFileReissuanceV1(t *harnessTest) {
	externalGroupKey, signerCallback := newChantoolsGroupKey(t)

	anchorReq := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      "backup-reissue-v1-anchor",
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("backup reissuance v1 test"),
			},
			Amount:           1000,
			NewGroupedAsset:  true,
			ExternalGroupKey: externalGroupKey,
		},
	}
	anchor := MintAssetExternalSigner(
		t, t.tapd, []*mintrpc.MintAssetRequest{anchorReq},
		signerCallback,
	)[0]
	require.NotNil(t.t, anchor.AssetGroup)

	reissueReq := CopyRequest(anchorReq)
	reissueReq.Asset.Name = "backup-reissue-v1-tranche-2"
	reissueReq.Asset.Amount = 500
	reissueReq.Asset.NewGroupedAsset = false
	reissueReq.Asset.GroupedAsset = true
	reissueReq.Asset.GroupKey = anchor.AssetGroup.TweakedGroupKey
	reissued := MintAssetExternalSigner(
		t, t.tapd, []*mintrpc.MintAssetRequest{reissueReq},
		signerCallback,
	)[0]

	runBackupFileReissuance(t, anchor, reissued, asset.GroupKeyV1)
}

// testBackupFileLegacyAnchor asserts that a wallet restored from a backup
// entry without group info, as written before the group was recorded, ends up
// knowing the group in full when the entry is the group anchor itself. The
// import learns the group from the reveal in the anchor's genesis proof, and
// storing the proof must keep the reveal's raw key, version and roots. The
// restored node's own backup file then describes the group and a second
// restore from it, again without a universe server, works.
//
// The group is a V1 group with an external key, the construction whose
// version and custom subtree root are easiest to lose on the way.
func testBackupFileLegacyAnchor(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout*6)
	defer cancel()

	externalGroupKey, signerCallback := newChantoolsGroupKey(t)
	anchorReq := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      "backup-legacy-v1-anchor",
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("backup legacy anchor test"),
			},
			Amount:           1000,
			NewGroupedAsset:  true,
			ExternalGroupKey: externalGroupKey,
		},
	}
	anchor := MintAssetExternalSigner(
		t, t.tapd, []*mintrpc.MintAssetRequest{anchorReq},
		signerCallback,
	)[0]
	require.NotNil(t.t, anchor.AssetGroup)
	groupKey := anchor.AssetGroup.TweakedGroupKey

	// === Stage 1: Send part of the anchor to Bob ===
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)

	bobLndClient, err := t.newLndClient(bobLnd)
	require.NoError(t.t, err)
	defer bobLndClient.Close()

	const bobAmount = 400
	bobAddr, err := bobTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:      anchor.AssetGenesis.AssetId,
		Amt:          bobAmount,
		AssetVersion: anchor.Version,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, bobTapd, anchor, bobAddr)

	sendResp, _ := sendAssetsToAddr(t, t.tapd, bobAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner(), t.tapd, sendResp,
		anchor.AssetGenesis.AssetId,
		[]uint64{anchor.Amount - bobAmount, bobAmount}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)

	_, bobBackup := waitForBackupFile(
		t, bobTapd, bobLndClient, expectEntries(bobAmount),
	)
	assertGroupKeyInfo(
		t, bobBackup.Assets[0], anchor, groupKey, asset.GroupKeyV1,
	)

	// A file written before groups were recorded has entries without
	// group info. Strip it and hand the import the plaintext, which it
	// accepts as well.
	for _, ab := range bobBackup.Assets {
		ab.GroupKeyInfo = nil
	}
	legacyRaw, err := backup.EncodeWalletBackup(bobBackup)
	require.NoError(t.t, err)

	// === Stage 2: Restore Bob from the legacy entry on a wiped node ===
	require.NoError(t.t, bobTapd.stop(!*noDelete))

	bobTapd2 := setupTapdHarness(
		t.t, t, bobLnd, t.universeServer,
		func(params *tapdHarnessParams) {
			params.noDefaultUniverseSync = true
		},
	)
	AssertNumGroups(t.t, bobTapd2, 0)

	// The group is learned from the reveal in the anchor's genesis proof.
	importResp, err := bobTapd2.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{Backup: legacyRaw},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(0), importResp.NumSkipped)
	require.Equal(t.t, uint32(1), importResp.NumImported)
	assertRestoredReissuance(t, bobTapd2, anchor, bobAmount)

	// Storing the anchor's proof must have kept the group's raw key,
	// version and custom root, so the restored node's own file describes
	// the group as a V1 group again.
	bobRaw2, bobBackup2 := waitForBackupFile(
		t, bobTapd2, bobLndClient, expectEntries(bobAmount),
	)
	assertGroupKeyInfo(
		t, bobBackup2.Assets[0], anchor, groupKey, asset.GroupKeyV1,
	)

	// === Stage 3: Restore again from the restored node's file ===
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
	assertRestoredReissuance(t, bobTapd3, anchor, bobAmount)

	// === Stage 4: The restored leaf is spendable ===
	aliceAddr, err := t.tapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:      anchor.AssetGenesis.AssetId,
		Amt:          bobAmount,
		AssetVersion: anchor.Version,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, t.tapd, anchor, aliceAddr)

	sendResp, _ = sendAssetsToAddr(t, bobTapd3, aliceAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner(), bobTapd3, sendResp,
		anchor.AssetGenesis.AssetId, []uint64{0, bobAmount}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, t.tapd, 1)
}

// newChantoolsGroupKey derives a group key in a fresh chantools wallet and
// returns it as an external key together with the callback that signs group
// virtual PSBTs with it. Groups minted with it use the V1 construction.
func newChantoolsGroupKey(t *harnessTest) (*taprpc.ExternalKey,
	ExternalSigCallback) {

	chantools := NewChantoolsHarness(t.t)
	chantools.CreateWallet(t.t)
	groupKeyXpub, groupKeyFingerprint := chantools.DeriveKey(t.t)

	fingerPrintBytes, err := hex.DecodeString(groupKeyFingerprint)
	require.NoError(t.t, err)

	externalGroupKey := &taprpc.ExternalKey{
		Xpub:              groupKeyXpub,
		MasterFingerprint: fingerPrintBytes,
		DerivationPath:    "m/86'/1'/0'/0/0",
	}

	signerCallback := func(
		unsealedAssets []*mintrpc.UnsealedAsset) []ExternalSigRes {

		var res []ExternalSigRes
		for _, unsealed := range unsealedAssets {
			var assetID asset.ID
			copy(
				assetID[:],
				unsealed.GroupKeyRequest.AnchorGenesis.AssetId,
			)
			res = append(res, ExternalSigRes{
				SignedPsbt: chantools.SignPsbt(
					t.t, unsealed.GroupVirtualPsbt,
				),
				AssetID: assetID,
			})
		}

		return res
	}

	return externalGroupKey, signerCallback
}

// runBackupFileReissuance sends part of the reissued tranche to a fresh node
// and restores that node from its backup file.
//
// Flow:
//  1. Alice sends part of the reissued tranche to Bob. Bob now holds a single
//     leaf of the group and never saw the anchor's proof, he learned the
//     group through a universe sync when creating the address.
//  2. Bob's tapd is stopped and its data dropped. A fresh tapd on the same
//     lnd, with no universe server to learn the group from, imports the
//     file and must recover the leaf without skipping it. The restored
//     node's own backup file describes the group again and a second wiped
//     node restores from that file.
//  3. The restored leaf is spendable: Bob sends it back to Alice.
func runBackupFileReissuance(t *harnessTest, anchor, reissued *taprpc.Asset,
	groupVersion asset.GroupKeyVersion) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout*6)
	defer cancel()

	groupKey := anchor.AssetGroup.TweakedGroupKey
	require.Equal(t.t, groupKey, reissued.AssetGroup.TweakedGroupKey)
	AssertNumGroups(t.t, t.tapd, 1)

	// === Stage 1: Send part of the reissued tranche to Bob ===
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
	assertGroupKeyInfo(t, entry, anchor, groupKey, groupVersion)

	// === Stage 2: Restore Bob from the file on a wiped node ===
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
	assertGroupKeyInfo(
		t, bobBackup2.Assets[0], anchor, groupKey, groupVersion,
	)

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

	// === Stage 3: The restored leaf is spendable ===
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
// its leaf: the genesis of the group anchor, the group key version and the
// parameters that re-derive the tweaked group key.
func assertGroupKeyInfo(t *harnessTest, entry *backup.AssetBackup,
	anchor *taprpc.Asset, groupKey []byte,
	groupVersion asset.GroupKeyVersion) {

	require.NotNil(t.t, entry.GroupKeyInfo)
	require.Equal(t.t, groupVersion, entry.GroupKeyInfo.Version)
	anchorID := entry.GroupKeyInfo.AnchorGenesis.ID()
	require.Equal(t.t, anchor.AssetGenesis.AssetId, anchorID[:])
	require.NotEmpty(t.t, entry.GroupKeyInfo.Witness)

	derived, err := entry.GroupKeyInfo.GroupKey()
	require.NoError(t.t, err)
	require.Equal(t.t, groupKey, derived.GroupPubKey.SerializeCompressed())
}

// assertRestoredReissuance asserts that a restored node lists the single
// grouped leaf with the default filters, in ListAssets and in ListBalances,
// and knows the asset group it belongs to.
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
