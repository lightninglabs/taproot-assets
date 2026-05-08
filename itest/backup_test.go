package itest

import (
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/backup"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// testBackupRestoreGenesis tests backup/restore with genesis assets and
// idempotent import behavior.
//
// Flow:
//  1. Alice mints an asset, exports a compact backup
//  2. Bob (fresh LND) imports the backup, verifies the asset matches
//  3. Bob imports the same backup again — 0 imported (idempotent)
func testBackupRestoreGenesis(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Mint a single asset on Alice.
	backupAssets := []*mintrpc.MintAssetRequest{
		{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_NORMAL,
				Name:      "backup-test-asset",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("backup test metadata"),
				},
				Amount: 1000,
			},
		},
	}

	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner(), t.tapd, backupAssets,
	)
	require.Len(t.t, rpcAssets, 1)

	// Export a compact backup from Alice.
	exportResp, err := t.tapd.ExportAssetWalletBackup(
		ctxt, &wrpc.ExportAssetWalletBackupRequest{
			Mode: wrpc.BackupMode_COMPACT,
		},
	)
	require.NoError(t.t, err)
	require.NotEmpty(t.t, exportResp.Backup)

	t.Logf("Backup size: %s", formatBytes(len(exportResp.Backup)))

	// Create Bob (fresh LND) and import the backup.
	bob := t.lndHarness.NewNode("bob", lndDefaultArgs)
	bobTapd := setupTapdHarness(t.t, t, bob, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	// First import: 1 asset imported.
	importResp, err := bobTapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{
			Backup: exportResp.Backup,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(1), importResp.NumImported)

	// Verify the asset matches.
	bobAssets, err := bobTapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, bobAssets.Assets, 1)

	original := rpcAssets[0]
	imported := bobAssets.Assets[0]
	require.Equal(t.t, original.Amount, imported.Amount)
	require.Equal(t.t, original.AssetGenesis.AssetId,
		imported.AssetGenesis.AssetId)
	require.Equal(t.t, original.AssetGenesis.Name,
		imported.AssetGenesis.Name)

	// Second import: 0 imported (idempotent).
	importResp2, err := bobTapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{
			Backup: exportResp.Backup,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(0), importResp2.NumImported)

	// Still exactly 1 asset.
	bobAssetsFinal, err := bobTapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, bobAssetsFinal.Assets, 1)

	t.Logf("Genesis backup: imported 1, re-import 0 (idempotent)")
}

// testBackupRestoreTransferred tests backup/restore across all three modes
// (RAW, COMPACT, OPTIMISTIC) with transferred assets, size comparison,
// post-restore spendability, and stale backup detection.
//
// Flow:
//  1. Alice mints 2 assets in separate batches
//  2. Alice sends both to Bob (full value)
//  3. Bob exports RAW, COMPACT, OPTIMISTIC backups; log size comparison
//  4. Charlie (fresh LND) imports RAW — verify 2 assets match
//  5. Dave (fresh LND) imports COMPACT — verify 2 assets match
//  6. Stop Bob; Eve (Bob's LND, noDefaultUniverseSync) imports
//     OPTIMISTIC — decode backup, verify federation URLs, verify
//     2 assets match
//  7. Eve sends both assets (full value) to Alice — proves spendability
//  8. Stop Eve; fresh tapd on Bob's LND imports RAW backup — 0
//     imported (both anchor outpoints spent in step 7)
func testBackupRestoreTransferred(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout*4)
	defer cancel()

	// === Stage 1: Mint 2 assets on Alice in separate batches ===
	t.Logf("=== Stage 1: Minting assets on Alice ===")

	var mintedAssets []*taprpc.Asset
	assetConfigs := []struct {
		name   string
		amount uint64
	}{
		{"transfer-test-asset-1", 1000},
		{"transfer-test-asset-2", 500},
	}

	for _, cfg := range assetConfigs {
		mintReq := []*mintrpc.MintAssetRequest{{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_NORMAL,
				Name:      cfg.name,
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("transfer test"),
				},
				Amount: cfg.amount,
			},
		}}
		rpcAssets := MintAssetsConfirmBatch(
			t.t, t.lndHarness.Miner(), t.tapd, mintReq,
		)
		require.Len(t.t, rpcAssets, 1)
		mintedAssets = append(mintedAssets, rpcAssets[0])
	}

	// === Stage 2: Send both assets from Alice to Bob ===
	t.Logf("=== Stage 2: Transferring assets to Bob ===")

	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	// We explicitly stop Bob later to reuse his LND for Eve and
	// the stale check, so we don't defer here.

	for i, asset := range mintedAssets {
		bobAddr, err := bobTapd.NewAddr(
			ctxt, &taprpc.NewAddrRequest{
				AssetId:      asset.AssetGenesis.AssetId,
				Amt:          asset.Amount,
				AssetVersion: asset.Version,
			},
		)
		require.NoError(t.t, err)

		AssertAddrCreated(t.t, bobTapd, asset, bobAddr)
		sendResp, _ := sendAssetsToAddr(t, t.tapd, bobAddr)
		ConfirmAndAssertOutboundTransfer(
			t.t, t.lndHarness.Miner(), t.tapd,
			sendResp, asset.AssetGenesis.AssetId,
			[]uint64{0, asset.Amount}, i, i+1,
		)
	}

	AssertNonInteractiveRecvComplete(t.t, bobTapd, len(mintedAssets))

	// === Stage 3: Export all three backup modes ===
	t.Logf("=== Stage 3: Exporting backups (RAW, COMPACT, " +
		"OPTIMISTIC) ===")

	rawBackup, err := bobTapd.ExportAssetWalletBackup(
		ctxt, &wrpc.ExportAssetWalletBackupRequest{
			Mode: wrpc.BackupMode_RAW,
		},
	)
	require.NoError(t.t, err)

	compactBackup, err := bobTapd.ExportAssetWalletBackup(
		ctxt, &wrpc.ExportAssetWalletBackupRequest{
			Mode: wrpc.BackupMode_COMPACT,
		},
	)
	require.NoError(t.t, err)

	optimisticBackup, err := bobTapd.ExportAssetWalletBackup(
		ctxt, &wrpc.ExportAssetWalletBackupRequest{
			Mode: wrpc.BackupMode_OPTIMISTIC,
		},
	)
	require.NoError(t.t, err)

	require.Less(t.t, len(compactBackup.Backup),
		len(rawBackup.Backup),
		"compact backup should be smaller than raw")
	require.Less(t.t, len(optimisticBackup.Backup),
		len(compactBackup.Backup),
		"optimistic backup should be smaller than compact")

	savings := float64(
		len(rawBackup.Backup)-len(optimisticBackup.Backup),
	) / float64(len(rawBackup.Backup)) * 100
	t.Logf("Sizes — RAW: %s, COMPACT: %s, OPTIMISTIC: %s "+
		"(%.1f%% savings)",
		formatBytes(len(rawBackup.Backup)),
		formatBytes(len(compactBackup.Backup)),
		formatBytes(len(optimisticBackup.Backup)),
		savings)

	// === Stage 4: Import RAW on Charlie ===
	t.Logf("=== Stage 4: Import RAW on Charlie ===")

	charlieLnd := t.lndHarness.NewNode("Charlie", lndDefaultArgs)
	charlieTapd := setupTapdHarness(
		t.t, t, charlieLnd, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, charlieTapd.stop(!*noDelete))
	}()

	charlieImport, err := charlieTapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{
			Backup: rawBackup.Backup,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(len(mintedAssets)),
		charlieImport.NumImported)

	charlieAssets, err := charlieTapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	assertAssetsMatch(t, mintedAssets, charlieAssets.Assets)
	t.Logf("Charlie (RAW): %d assets imported",
		charlieImport.NumImported)

	// === Stage 5: Import COMPACT on Dave ===
	t.Logf("=== Stage 5: Import COMPACT on Dave ===")

	daveLnd := t.lndHarness.NewNode("Dave", lndDefaultArgs)
	daveTapd := setupTapdHarness(
		t.t, t, daveLnd, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, daveTapd.stop(!*noDelete))
	}()

	daveImport, err := daveTapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{
			Backup: compactBackup.Backup,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(len(mintedAssets)),
		daveImport.NumImported)

	daveAssets, err := daveTapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	assertAssetsMatch(t, mintedAssets, daveAssets.Assets)
	t.Logf("Dave (COMPACT): %d assets imported",
		daveImport.NumImported)

	// === Stage 6: Import OPTIMISTIC on Eve (Bob's LND) ===
	t.Logf("=== Stage 6: Import OPTIMISTIC on Eve " +
		"(Bob's LND) ===")

	// Decode the backup and verify federation URLs are present.
	decoded, err := backup.DecodeWalletBackup(optimisticBackup.Backup)
	require.NoError(t.t, err)

	require.Equal(t.t, backup.BackupVersionOptimistic,
		decoded.Version,
		"optimistic backup version should be v3")
	require.NotEmpty(t.t, decoded.FederationURLs,
		"optimistic backup must contain federation URLs")

	uniHost := t.universeServer.service.rpcHost()
	require.Contains(t.t, decoded.FederationURLs, uniHost,
		"backup federation URLs should include the "+
			"universe server address")

	t.Logf("Backup contains %d federation URL(s): %v",
		len(decoded.FederationURLs), decoded.FederationURLs)

	// Stop Bob's tapd to free the LND connection for Eve.
	require.NoError(t.t, bobTapd.stop(!*noDelete))

	// Eve is on Bob's LND with noDefaultUniverseSync — the only
	// way to obtain proofs is through the backup's federation URLs.
	eveTapd := setupTapdHarness(
		t.t, t, bobLnd, t.universeServer,
		func(params *tapdHarnessParams) {
			params.noDefaultUniverseSync = true
		},
	)
	// We explicitly stop Eve later for the stale check.

	eveImport, err := eveTapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{
			Backup: optimisticBackup.Backup,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(len(mintedAssets)),
		eveImport.NumImported)

	eveAssets, err := eveTapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	assertAssetsMatch(t, mintedAssets, eveAssets.Assets)
	t.Logf("Eve (OPTIMISTIC): %d assets imported",
		eveImport.NumImported)

	// === Stage 7: Eve sends both assets to Alice ===
	t.Logf("=== Stage 7: Eve sends both assets to Alice ===")

	// Snapshot Alice's inbound event count before the sends so we
	// can wait for exactly the right total afterwards.
	aliceRecvs, err := t.tapd.AddrReceives(
		ctxt, &taprpc.AddrReceivesRequest{},
	)
	require.NoError(t.t, err)
	aliceRecvBase := len(aliceRecvs.Events)

	for i, asset := range eveAssets.Assets {
		aliceAddr, err := t.tapd.NewAddr(
			ctxt, &taprpc.NewAddrRequest{
				AssetId:      asset.AssetGenesis.AssetId,
				Amt:          asset.Amount,
				AssetVersion: asset.Version,
			},
		)
		require.NoError(t.t, err)

		AssertAddrCreated(t.t, t.tapd, asset, aliceAddr)
		sendResp, _ := sendAssetsToAddr(t, eveTapd, aliceAddr)
		ConfirmAndAssertOutboundTransfer(
			t.t, t.lndHarness.Miner(), eveTapd,
			sendResp, asset.AssetGenesis.AssetId,
			[]uint64{0, asset.Amount}, i, i+1,
		)

		t.Logf("Eve sent %d units of %s to Alice",
			asset.Amount, asset.AssetGenesis.Name)
	}

	// Wait for Alice to receive all proofs, then verify the
	// assets appear in her wallet.
	AssertNonInteractiveRecvComplete(
		t.t, t.tapd, aliceRecvBase+len(mintedAssets),
	)

	aliceAssets, err := t.tapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)

	for _, exp := range mintedAssets {
		found := false
		for _, act := range aliceAssets.Assets {
			if act.AssetGenesis.Name ==
				exp.AssetGenesis.Name &&
				act.Amount == exp.Amount {

				found = true

				break
			}
		}
		require.True(t.t, found,
			"Alice should have %s after Eve's send",
			exp.AssetGenesis.Name)
	}
	t.Logf("Alice received both assets from Eve")

	// === Stage 8: Stale backup detection ===
	t.Logf("=== Stage 8: Verify stale backup detection ===")

	// Stop Eve, create a fresh tapd on Bob's LND.
	require.NoError(t.t, eveTapd.stop(!*noDelete))

	restoredTapd := setupTapdHarness(
		t.t, t, bobLnd, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, restoredTapd.stop(!*noDelete))
	}()

	// Re-import Bob's RAW backup. Both assets had their anchor
	// outpoints spent on-chain when Eve sent them to Alice, so
	// both should be detected as stale and skipped.
	staleImport, err := restoredTapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{
			Backup: rawBackup.Backup,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(0), staleImport.NumImported,
		"expected 0 imported (both outpoints are spent)")

	t.Logf("Stale detection: 0 of %d imported (all outpoints "+
		"spent)", len(mintedAssets))
}

// assertAssetsMatch verifies that all expected assets appear in the actual
// list with matching amounts and genesis IDs.
func assertAssetsMatch(t *harnessTest, expected []*taprpc.Asset,
	actual []*taprpc.Asset) {

	require.Len(t.t, actual, len(expected))

	for _, exp := range expected {
		found := false
		for _, act := range actual {
			if act.AssetGenesis.Name ==
				exp.AssetGenesis.Name {

				require.Equal(
					t.t, exp.Amount, act.Amount,
				)
				require.Equal(
					t.t,
					exp.AssetGenesis.AssetId,
					act.AssetGenesis.AssetId,
				)
				found = true

				break
			}
		}
		require.True(
			t.t, found, "asset %s not found after import",
			exp.AssetGenesis.Name,
		)
	}
}

// testBackupRestoreGrouped tests that backups containing grouped
// assets can be imported on a node that has never seen the group
// key (no federation server, no prior universe sync).
//
// This exercises the fix for #2111: the import pre-extracts group
// keys from GroupKeyReveal in genesis proofs so the GroupVerifier
// accepts them during proof chain verification.
//
// Flow:
//  1. Alice mints a grouped asset (group anchor) and an
//     ungrouped asset in one batch
//  2. Alice exports RAW and COMPACT backups
//  3. Bob (fresh LND, no federation) imports RAW — both assets
//     imported, NumSkipped=0
//  4. Charlie (fresh LND, no federation) imports COMPACT — same
//  5. Verify asset counts and group key presence on both nodes
func testBackupRestoreGrouped(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Mint a grouped asset and an ungrouped asset together.
	mintReqs := []*mintrpc.MintAssetRequest{
		{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_NORMAL,
				Name:      "grouped-backup-anchor",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("group anchor"),
				},
				Amount:          5000,
				NewGroupedAsset: true,
			},
		},
		{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_NORMAL,
				Name:      "ungrouped-backup-asset",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("no group"),
				},
				Amount: 1000,
			},
		},
	}

	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner(), t.tapd, mintReqs,
	)
	require.Len(t.t, rpcAssets, 2)

	// Verify Alice has the group.
	AssertNumGroups(t.t, t.tapd, 1)

	// Export RAW and COMPACT backups.
	rawBackup, err := t.tapd.ExportAssetWalletBackup(
		ctxt, &wrpc.ExportAssetWalletBackupRequest{
			Mode: wrpc.BackupMode_RAW,
		},
	)
	require.NoError(t.t, err)

	compactBackup, err := t.tapd.ExportAssetWalletBackup(
		ctxt, &wrpc.ExportAssetWalletBackupRequest{
			Mode: wrpc.BackupMode_COMPACT,
		},
	)
	require.NoError(t.t, err)

	// === Import RAW on Bob (no federation) ===
	t.Logf("=== Import RAW on Bob (no federation) ===")

	bobLnd := t.lndHarness.NewNode("Bob", lndDefaultArgs)
	bobTapd := setupTapdHarness(
		t.t, t, bobLnd, t.universeServer,
		func(params *tapdHarnessParams) {
			params.noDefaultUniverseSync = true
		},
	)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	bobImport, err := bobTapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{
			Backup: rawBackup.Backup,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(2), bobImport.NumImported,
		"both assets should import (grouped + ungrouped)")
	require.Equal(t.t, uint32(0), bobImport.NumSkipped,
		"no assets should be skipped")

	bobAssets, err := bobTapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	assertAssetsMatch(t, rpcAssets, bobAssets.Assets)

	t.Logf("Bob (RAW, no federation): imported %d, "+
		"skipped %d", bobImport.NumImported,
		bobImport.NumSkipped)

	// === Import COMPACT on Charlie (no federation) ===
	t.Logf("=== Import COMPACT on Charlie (no federation) ===")

	charlieLnd := t.lndHarness.NewNode("Charlie", lndDefaultArgs)
	charlieTapd := setupTapdHarness(
		t.t, t, charlieLnd, t.universeServer,
		func(params *tapdHarnessParams) {
			params.noDefaultUniverseSync = true
		},
	)
	defer func() {
		require.NoError(t.t, charlieTapd.stop(!*noDelete))
	}()

	charlieImport, err := charlieTapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{
			Backup: compactBackup.Backup,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(2), charlieImport.NumImported,
		"both assets should import (grouped + ungrouped)")
	require.Equal(t.t, uint32(0), charlieImport.NumSkipped,
		"no assets should be skipped")

	charlieAssets, err := charlieTapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	assertAssetsMatch(t, rpcAssets, charlieAssets.Assets)

	t.Logf("Charlie (COMPACT, no federation): imported %d, "+
		"skipped %d", charlieImport.NumImported,
		charlieImport.NumSkipped)
}

// testBackupRestoreOptimistic tests that OPTIMISTIC (v3) backups
// with grouped assets — including reissuances — can be imported on
// a node with no federation sync. The proofs are fetched from the
// universe server via the federation URLs embedded in the backup.
//
// The test decodes the backup and swaps the asset order so the
// reissuance is iterated before the group anchor. This forces
// the retry pass: the reissuance fails pre-verify with
// ErrGroupKeyUnknown, then the anchor is processed (populating
// the group key), and the retry pass resolves the reissuance.
//
// Flow:
//  1. Alice mints a group anchor (batch 1)
//  2. Alice mints a reissuance into the same group (batch 2)
//  3. Alice exports an OPTIMISTIC backup
//  4. Decode, swap asset order, re-encode
//  5. Bob (fresh LND, no federation sync) imports the reordered
//     backup
//  6. Verify all assets imported, none skipped, group key present
func testBackupRestoreOptimistic(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout*2)
	defer cancel()

	miner := t.lndHarness.Miner()

	// Mint a group anchor.
	anchorAssets := MintAssetsConfirmBatch(
		t.t, miner, t.tapd,
		[]*mintrpc.MintAssetRequest{
			{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "optimistic-anchor",
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte("anchor"),
					},
					Amount:          5000,
					NewGroupedAsset: true,
				},
			},
		},
	)
	require.Len(t.t, anchorAssets, 1)

	groupKey := anchorAssets[0].AssetGroup.TweakedGroupKey
	AssertNumGroups(t.t, t.tapd, 1)

	// Mint a reissuance into the same group.
	reissueAssets := MintAssetsConfirmBatch(
		t.t, miner, t.tapd,
		[]*mintrpc.MintAssetRequest{
			{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "optimistic-reissue",
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte("reissue"),
					},
					Amount:       2000,
					GroupKey:     groupKey,
					GroupedAsset: true,
				},
			},
		},
	)
	require.Len(t.t, reissueAssets, 1)

	// Still one group, now with two assets.
	AssertNumGroups(t.t, t.tapd, 1)

	// Export OPTIMISTIC backup.
	optimisticBackup, err := t.tapd.ExportAssetWalletBackup(
		ctxt, &wrpc.ExportAssetWalletBackupRequest{
			Mode: wrpc.BackupMode_OPTIMISTIC,
		},
	)
	require.NoError(t.t, err)

	decoded, err := backup.DecodeWalletBackup(
		optimisticBackup.Backup,
	)
	require.NoError(t.t, err)
	require.Equal(t.t, backup.BackupVersionOptimistic,
		decoded.Version)
	require.NotEmpty(t.t, decoded.FederationURLs)

	// The export orders assets by ascending asset_id, so the
	// anchor (minted first) is Assets[0] and the reissuance
	// is Assets[1]. In that order, the main loop processes
	// the anchor first and the retry pass is never needed.
	//
	// To exercise the retry pass, swap the asset order so the
	// reissuance is processed first. It will fail pre-verify
	// with ErrGroupKeyUnknown (no prior group key knowledge),
	// then the anchor is processed (populating the group key),
	// and finally the retry pass resolves the reissuance.
	require.Len(t.t, decoded.Assets, 2)
	decoded.Assets[0], decoded.Assets[1] =
		decoded.Assets[1], decoded.Assets[0]

	swappedBlob, err := backup.EncodeWalletBackup(decoded)
	require.NoError(t.t, err)

	// Import the reordered backup on Bob.
	bobLnd := t.lndHarness.NewNode("Bob", lndDefaultArgs)
	bobTapd := setupTapdHarness(
		t.t, t, bobLnd, t.universeServer,
		func(params *tapdHarnessParams) {
			params.noDefaultUniverseSync = true
		},
	)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	bobImport, err := bobTapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{
			Backup: swappedBlob,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(2), bobImport.NumImported,
		"both anchor and reissuance should import")
	require.Equal(t.t, uint32(0), bobImport.NumSkipped,
		"no assets should be skipped")

	bobAssets, err := bobTapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)

	allMinted := append(anchorAssets, reissueAssets...)
	assertAssetsMatch(t, allMinted, bobAssets.Assets)

	// Verify the group key is present on Bob.
	AssertNumGroups(t.t, bobTapd, 1)

	t.Logf("Bob (OPTIMISTIC, swapped order): imported %d, "+
		"skipped %d", bobImport.NumImported,
		bobImport.NumSkipped)
}

// formatBytes formats a byte count as a human-readable string.
func formatBytes(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	return fmt.Sprintf("%.2f KB", float64(bytes)/1024)
}
