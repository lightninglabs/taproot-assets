package itest

import (
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// testBackupRestoreGenesis tests that we can export a wallet backup containing
// genesis assets (minted assets that haven't been transferred) and import them
// on a different node.
func testBackupRestoreGenesis(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Define a single simple asset for this test.
	// Using a single asset avoids complex exclusion proofs that arise
	// when multiple assets are in the same anchor transaction.
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

	// Mint the asset on Alice's node.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd, backupAssets,
	)
	require.Len(t.t, rpcAssets, 1)

	t.Logf("Minted %d assets for backup test", len(rpcAssets))

	// Export the wallet backup from Alice.
	exportResp, err := t.tapd.ExportAssetWalletBackup(
		ctxt, &wrpc.ExportAssetWalletBackupRequest{},
	)
	require.NoError(t.t, err)
	require.NotEmpty(t.t, exportResp.Backup)

	// Log backup size metrics.
	backupSize := len(exportResp.Backup)
	numAssets := len(rpcAssets)
	avgBytesPerAsset := backupSize / numAssets
	t.Logf("=== Backup Size Metrics ===")
	t.Logf("Total backup size: %d bytes (%.2f KB)",
		backupSize, float64(backupSize)/1024)
	t.Logf("Number of assets: %d", numAssets)
	t.Logf("Average bytes per asset: %d bytes", avgBytesPerAsset)

	// Create a new tapd node (Bob) to import the backup into.
	// Bob is connected to the same LND node but has a fresh database.
	bob := t.lndHarness.NewNode("bob", lndDefaultArgs)
	bobTapd := setupTapdHarness(t.t, t, bob, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	// Verify Bob has no assets initially.
	bobAssets, err := bobTapd.ListAssets(ctxt, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, bobAssets.Assets, 0)

	t.Logf("Bob has %d assets before import", len(bobAssets.Assets))

	// Import the backup into Bob's node.
	importResp, err := bobTapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{
			Backup: exportResp.Backup,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(1), importResp.NumImported)

	t.Logf("Imported %d assets from backup", importResp.NumImported)

	// Verify Bob now has the asset.
	bobAssetsAfter, err := bobTapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, bobAssetsAfter.Assets, 1)

	// Verify the asset details match.
	for _, originalAsset := range rpcAssets {
		found := false
		for _, importedAsset := range bobAssetsAfter.Assets {
			if importedAsset.AssetGenesis.Name ==
				originalAsset.AssetGenesis.Name {

				require.Equal(
					t.t, originalAsset.Amount,
					importedAsset.Amount,
				)
				require.Equal(
					t.t, originalAsset.AssetGenesis.AssetId,
					importedAsset.AssetGenesis.AssetId,
				)
				found = true
				break
			}
		}
		require.True(
			t.t, found,
			"Asset %s not found after import",
			originalAsset.AssetGenesis.Name,
		)
	}

	t.Logf("Successfully verified %d imported assets", len(rpcAssets))
}

// testBackupIdempotent tests that importing the same backup twice doesn't
// create duplicate assets and that the imported assets are spendable.
//
// Flow:
//  1. Alice mints an asset, sends it to Bob (creates a transfer proof chain)
//  2. Bob exports backup, imports it twice into a fresh tapd on the same LND
//  3. Verify second import is a no-op (0 imported)
//  4. Restored node sends to Eve to prove spendability after idempotent import
func testBackupIdempotent(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout*2)
	defer cancel()

	// Mint a single asset on Alice.
	idempotentAssets := []*mintrpc.MintAssetRequest{
		{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_NORMAL,
				Name:      "idempotent-test-asset",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("idempotent test"),
				},
				Amount: 1000,
			},
		},
	}

	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd, idempotentAssets,
	)
	require.Len(t.t, rpcAssets, 1)
	mintedAsset := rpcAssets[0]

	// Transfer the asset from Alice to Bob so we have a non-genesis
	// proof chain (transfer proofs are more interesting than genesis).
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)

	bobAddr, err := bobTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:      mintedAsset.AssetGenesis.AssetId,
		Amt:          mintedAsset.Amount,
		AssetVersion: mintedAsset.Version,
	})
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, bobTapd, mintedAsset, bobAddr)
	sendResp, _ := sendAssetsToAddr(t, t.tapd, bobAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, t.tapd, sendResp,
		mintedAsset.AssetGenesis.AssetId,
		[]uint64{0, mintedAsset.Amount}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)

	// Export Bob's backup (contains a transfer proof chain).
	exportResp, err := bobTapd.ExportAssetWalletBackup(
		ctxt, &wrpc.ExportAssetWalletBackupRequest{},
	)
	require.NoError(t.t, err)

	// Stop Bob's tapd and create a fresh tapd on the same LND (simulates
	// a restore scenario with the same wallet keys).
	require.NoError(t.t, bobTapd.stop(!*noDelete))

	restoredTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, restoredTapd.stop(!*noDelete))
	}()

	// First import should succeed and import 1 asset.
	importResp1, err := restoredTapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{
			Backup: exportResp.Backup,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(1), importResp1.NumImported)

	// Second import should succeed but import 0 assets (already exists).
	importResp2, err := restoredTapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{
			Backup: exportResp.Backup,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(0), importResp2.NumImported)

	// Verify the restored node still has exactly 1 asset.
	restoredAssets, err := restoredTapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, restoredAssets.Assets, 1)

	t.Logf("Idempotent import verified: 1 then 0 assets imported")

	// Prove the restored node can spend by sending half to Eve.
	eveLnd := t.lndHarness.NewNodeWithCoins("Eve", nil)
	eveTapd := setupTapdHarness(t.t, t, eveLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, eveTapd.stop(!*noDelete))
	}()

	assetToSend := restoredAssets.Assets[0]
	sendAmount := assetToSend.Amount / 2

	eveAddr, err := eveTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:      assetToSend.AssetGenesis.AssetId,
		Amt:          sendAmount,
		AssetVersion: assetToSend.Version,
	})
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, eveTapd, assetToSend, eveAddr)
	sendResp, _ = sendAssetsToAddr(t, restoredTapd, eveAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, restoredTapd, sendResp,
		assetToSend.AssetGenesis.AssetId,
		[]uint64{assetToSend.Amount - sendAmount, sendAmount}, 0, 1,
	)

	AssertNonInteractiveRecvComplete(t.t, eveTapd, 1)

	eveAssets, err := eveTapd.ListAssets(ctxt, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, eveAssets.Assets, 1)
	require.Equal(t.t, sendAmount, eveAssets.Assets[0].Amount)

	t.Logf("Idempotent import test passed: restored node spent %d "+
		"units to Eve", sendAmount)
}

// testBackupSizeFootprint tests the backup size footprint by minting multiple
// assets in separate batches and measuring the backup size.
func testBackupSizeFootprint(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// Track backup sizes as we add assets.
	type sizeMetric struct {
		numAssets int
		sizeBytes int
	}
	var metrics []sizeMetric

	// Mint assets in separate batches to avoid exclusion proof complexity.
	// Each batch creates one asset in its own anchor transaction.
	assetNames := []string{
		"size-test-asset-1",
		"size-test-asset-2",
		"size-test-asset-3",
	}

	for i, name := range assetNames {
		// Mint a single asset.
		mintReq := []*mintrpc.MintAssetRequest{
			{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      name,
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte("size test"),
					},
					Amount: uint64(100 * (i + 1)),
				},
			},
		}

		rpcAssets := MintAssetsConfirmBatch(
			t.t, t.lndHarness.Miner().Client, t.tapd, mintReq,
		)
		require.Len(t.t, rpcAssets, 1)

		// Export backup and measure size.
		exportResp, err := t.tapd.ExportAssetWalletBackup(
			ctxt, &wrpc.ExportAssetWalletBackupRequest{},
		)
		require.NoError(t.t, err)

		metrics = append(metrics, sizeMetric{
			numAssets: i + 1,
			sizeBytes: len(exportResp.Backup),
		})
	}

	// Log the size metrics.
	t.Logf("=== Backup Size Footprint Analysis ===")
	t.Logf("%-12s %-15s %-15s %-15s", "Assets", "Total Size", "Per Asset",
		"Incremental")

	var prevSize int
	for _, m := range metrics {
		avgPerAsset := m.sizeBytes / m.numAssets
		incremental := m.sizeBytes - prevSize
		t.Logf("%-12d %-15s %-15s %-15s",
			m.numAssets,
			formatBytes(m.sizeBytes),
			formatBytes(avgPerAsset),
			formatBytes(incremental),
		)
		prevSize = m.sizeBytes
	}

	// Verify the backup can still be imported.
	exportResp, err := t.tapd.ExportAssetWalletBackup(
		ctxt, &wrpc.ExportAssetWalletBackupRequest{},
	)
	require.NoError(t.t, err)

	// Create a new node and import.
	dave := t.lndHarness.NewNode("dave", lndDefaultArgs)
	daveTapd := setupTapdHarness(t.t, t, dave, t.universeServer)
	defer func() {
		require.NoError(t.t, daveTapd.stop(!*noDelete))
	}()

	importResp, err := daveTapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{
			Backup: exportResp.Backup,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(len(assetNames)), importResp.NumImported)

	// Verify all assets were imported.
	daveAssets, err := daveTapd.ListAssets(ctxt, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, daveAssets.Assets, len(assetNames))

	t.Logf("Successfully imported %d assets from backup",
		importResp.NumImported)
}

// formatBytes formats a byte count as a human-readable string.
func formatBytes(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	return fmt.Sprintf("%.2f KB", float64(bytes)/1024)
}

// testBackupRestoreTransferred tests backup/restore with transferred assets,
// verifying that proof chains grow with each transfer and that imported assets
// can be spent.
//
// Flow:
//  1. Alice mints 2 assets, exports backup (genesis proofs)
//  2. Alice sends both to Bob, Bob exports backup (1 transfer each)
//  3. Bob sends both to Charlie, Charlie exports backup (2 transfers each)
//  4. Dave imports Charlie's backup and sends assets to verify spendability
func testBackupRestoreTransferred(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout*2)
	defer cancel()

	// Track backup sizes at each stage.
	type backupMetric struct {
		stage        string
		numAssets    int
		sizeBytes    int
		numTransfers int
	}
	var metrics []backupMetric

	// Mint 2 assets on Alice in separate batches.
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
			t.t, t.lndHarness.Miner().Client, t.tapd, mintReq,
		)
		require.Len(t.t, rpcAssets, 1)
		mintedAssets = append(mintedAssets, rpcAssets[0])
	}

	// Export Alice's backup (genesis proofs only).
	aliceBackup, err := t.tapd.ExportAssetWalletBackup(
		ctxt, &wrpc.ExportAssetWalletBackupRequest{},
	)
	require.NoError(t.t, err)

	metrics = append(metrics, backupMetric{
		stage:        "Alice (genesis)",
		numAssets:    len(mintedAssets),
		sizeBytes:    len(aliceBackup.Backup),
		numTransfers: 0,
	})
	t.Logf("Alice backup after mint: %s",
		formatBytes(len(aliceBackup.Backup)))

	// Create Bob's node.
	t.Logf("=== Stage 2: Transferring assets to Bob ===")
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	// Send both assets from Alice to Bob.
	for i, asset := range mintedAssets {
		bobAddr, err := bobTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
			AssetId:      asset.AssetGenesis.AssetId,
			Amt:          asset.Amount,
			AssetVersion: asset.Version,
		})
		require.NoError(t.t, err)

		AssertAddrCreated(t.t, bobTapd, asset, bobAddr)
		sendResp, _ := sendAssetsToAddr(t, t.tapd, bobAddr)
		ConfirmAndAssertOutboundTransfer(
			t.t, t.lndHarness.Miner().Client, t.tapd, sendResp,
			asset.AssetGenesis.AssetId,
			[]uint64{0, asset.Amount}, i, i+1,
		)
	}

	// Wait for Bob to receive both assets.
	AssertNonInteractiveRecvComplete(t.t, bobTapd, len(mintedAssets))

	// Export Bob's backup (1 transfer per asset).
	bobBackup, err := bobTapd.ExportAssetWalletBackup(
		ctxt, &wrpc.ExportAssetWalletBackupRequest{},
	)
	require.NoError(t.t, err)

	metrics = append(metrics, backupMetric{
		stage:        "Bob (1 transfer)",
		numAssets:    len(mintedAssets),
		sizeBytes:    len(bobBackup.Backup),
		numTransfers: 1,
	})
	t.Logf("Bob backup after receiving: %s",
		formatBytes(len(bobBackup.Backup)))

	// Create Charlie's node.
	t.Logf("=== Stage 3: Transferring assets to Charlie ===")
	charlieLnd := t.lndHarness.NewNodeWithCoins("Charlie", nil)
	charlieTapd := setupTapdHarness(t.t, t, charlieLnd, t.universeServer)
	// Note: we don't defer charlieTapd.stop() here because we
	// explicitly stop it in Stage 4 before creating a fresh tapd
	// on the same LND node.

	// Get Bob's current assets.
	bobAssets, err := bobTapd.ListAssets(ctxt, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, bobAssets.Assets, len(mintedAssets))

	// Send both assets from Bob to Charlie.
	for i, asset := range bobAssets.Assets {
		charlieAddr, err := charlieTapd.NewAddr(
			ctxt, &taprpc.NewAddrRequest{
				AssetId:      asset.AssetGenesis.AssetId,
				Amt:          asset.Amount,
				AssetVersion: asset.Version,
			},
		)
		require.NoError(t.t, err)

		AssertAddrCreated(t.t, charlieTapd, asset, charlieAddr)
		sendResp, _ := sendAssetsToAddr(t, bobTapd, charlieAddr)
		ConfirmAndAssertOutboundTransfer(
			t.t, t.lndHarness.Miner().Client, bobTapd, sendResp,
			asset.AssetGenesis.AssetId,
			[]uint64{0, asset.Amount}, i, i+1,
		)
	}

	// Wait for Charlie to receive both assets.
	AssertNonInteractiveRecvComplete(t.t, charlieTapd, len(mintedAssets))

	// Export Charlie's backup (2 transfers per asset).
	charlieBackup, err := charlieTapd.ExportAssetWalletBackup(
		ctxt, &wrpc.ExportAssetWalletBackupRequest{},
	)
	require.NoError(t.t, err)

	metrics = append(metrics, backupMetric{
		stage:        "Charlie (2 transfers)",
		numAssets:    len(mintedAssets),
		sizeBytes:    len(charlieBackup.Backup),
		numTransfers: 2,
	})
	t.Logf("Charlie backup after receiving: %s",
		formatBytes(len(charlieBackup.Backup)))

	// Log size growth analysis.
	t.Logf("=== Backup Size Growth Analysis ===")
	t.Logf("%-25s %-12s %-15s %-15s", "Stage", "Transfers", "Total Size",
		"Per Asset")
	for _, m := range metrics {
		perAsset := m.sizeBytes / m.numAssets
		t.Logf("%-25s %-12d %-15s %-15s",
			m.stage, m.numTransfers,
			formatBytes(m.sizeBytes), formatBytes(perAsset))
	}

	// Calculate growth per transfer.
	genesisSize := metrics[0].sizeBytes / metrics[0].numAssets
	transfer1Size := metrics[1].sizeBytes / metrics[1].numAssets
	transfer2Size := metrics[2].sizeBytes / metrics[2].numAssets
	t.Logf("Size growth per transfer: ~%s",
		formatBytes((transfer2Size-genesisSize)/2))
	t.Logf("Genesis proof size: ~%s per asset", formatBytes(genesisSize))
	t.Logf("After 1 transfer: ~%s per asset", formatBytes(transfer1Size))
	t.Logf("After 2 transfers: ~%s per asset", formatBytes(transfer2Size))

	// Stage 4: Simulate backup restore by stopping Charlie's tapd and
	// creating a fresh tapd instance on the same LND node (same wallet
	// keys). This mirrors a real restore scenario where the LND wallet
	// is intact but the tapd database is lost.
	t.Logf("=== Stage 4: Import backup into fresh tapd and verify " +
		"spending ===")

	// Stop Charlie's tapd to release the LND connection.
	require.NoError(t.t, charlieTapd.stop(!*noDelete))

	// Create a fresh tapd instance on Charlie's same LND node.
	restoredTapd := setupTapdHarness(
		t.t, t, charlieLnd, t.universeServer,
	)
	defer func() {
		require.NoError(t.t, restoredTapd.stop(!*noDelete))
	}()

	// Verify the fresh node has no assets initially.
	restoredAssetsBefore, err := restoredTapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, restoredAssetsBefore.Assets, 0)

	// Import Charlie's backup into the fresh tapd.
	importResp, err := restoredTapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{
			Backup: charlieBackup.Backup,
		},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(len(mintedAssets)), importResp.NumImported)
	t.Logf("Restored node imported %d assets from backup",
		importResp.NumImported)

	// Verify the restored node has the assets.
	restoredAssets, err := restoredTapd.ListAssets(
		ctxt, &taprpc.ListAssetRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, restoredAssets.Assets, len(mintedAssets))

	// Create a recipient node (Eve) to verify the restored node can
	// spend.
	eveLnd := t.lndHarness.NewNodeWithCoins("Eve", nil)
	eveTapd := setupTapdHarness(t.t, t, eveLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, eveTapd.stop(!*noDelete))
	}()

	// Send one asset from the restored node to Eve to prove
	// spendability.
	assetToSend := restoredAssets.Assets[0]
	sendAmount := assetToSend.Amount / 2 // Send half

	eveAddr, err := eveTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:      assetToSend.AssetGenesis.AssetId,
		Amt:          sendAmount,
		AssetVersion: assetToSend.Version,
	})
	require.NoError(t.t, err)

	AssertAddrCreated(t.t, eveTapd, assetToSend, eveAddr)
	sendResp, _ := sendAssetsToAddr(t, restoredTapd, eveAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner().Client, restoredTapd, sendResp,
		assetToSend.AssetGenesis.AssetId,
		[]uint64{assetToSend.Amount - sendAmount, sendAmount}, 0, 1,
	)

	// Wait for Eve to receive.
	AssertNonInteractiveRecvComplete(t.t, eveTapd, 1)

	// Verify Eve received the asset.
	eveAssets, err := eveTapd.ListAssets(ctxt, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, eveAssets.Assets, 1)
	require.Equal(t.t, sendAmount, eveAssets.Assets[0].Amount)

	t.Logf("SUCCESS: Restored node was able to spend imported assets!")
	t.Logf("Asset %s: sent %d units to Eve",
		assetToSend.AssetGenesis.Name, sendAmount)
}
