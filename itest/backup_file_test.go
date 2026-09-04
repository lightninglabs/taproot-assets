package itest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/backup"
	"github.com/lightninglabs/taproot-assets/taprpc"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// backupFilePath returns the default location of the encrypted asset wallet
// backup file of the given tapd node.
func backupFilePath(tapd *tapdHarness) string {
	return filepath.Join(
		tapd.cfg.BaseDir, "data", tapd.cfg.NetParams.Name,
		backup.DefaultBackupFileName,
	)
}

// readBackupFile reads, decrypts and decodes the backup file of the given
// node, using the lnd node it is connected to for the encryption key.
func readBackupFile(ctx context.Context, tapd *tapdHarness,
	lnd *lndclient.GrpcLndServices) ([]byte, *backup.WalletBackup, error) {

	raw, err := os.ReadFile(backupFilePath(tapd))
	if err != nil {
		return nil, nil, err
	}

	if !backup.IsEncryptedBackup(raw) {
		return nil, nil, fmt.Errorf("backup file is not encrypted")
	}

	encrypter, err := backup.NewKeyRingEncrypter(ctx, lnd.WalletKit)
	if err != nil {
		return nil, nil, err
	}

	plaintext, err := backup.DecryptBackup(encrypter, raw)
	if err != nil {
		return nil, nil, err
	}

	wb, err := backup.DecodeWalletBackup(plaintext)
	if err != nil {
		return nil, nil, err
	}

	return raw, wb, nil
}

// waitForBackupFile waits until the backup file of the given node decodes
// and satisfies the condition, then returns the raw file and decoded backup.
func waitForBackupFile(t *harnessTest, tapd *tapdHarness,
	lnd *lndclient.GrpcLndServices,
	cond func(*backup.WalletBackup) error) ([]byte, *backup.WalletBackup) {

	ctx := context.Background()

	var (
		raw []byte
		wb  *backup.WalletBackup
	)
	err := wait.NoError(func() error {
		var err error
		raw, wb, err = readBackupFile(ctx, tapd, lnd)
		if err != nil {
			return err
		}

		return cond(wb)
	}, defaultWaitTimeout)
	require.NoError(t.t, err)

	return raw, wb
}

// expectEntries returns a backup file condition that requires exactly the
// given amounts to be present, in any order.
func expectEntries(amounts ...uint64) func(*backup.WalletBackup) error {
	return func(wb *backup.WalletBackup) error {
		if len(wb.Assets) != len(amounts) {
			return fmt.Errorf("expected %d entries, got %d",
				len(amounts), len(wb.Assets))
		}

		remaining := append([]uint64{}, amounts...)
		for _, ab := range wb.Assets {
			if ab.Asset == nil {
				return fmt.Errorf("entry without asset")
			}

			found := false
			for i, amt := range remaining {
				if ab.Asset != nil && ab.Asset.Amount == amt {
					remaining = append(
						remaining[:i],
						remaining[i+1:]...,
					)
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("unexpected entry with "+
					"amount %d", ab.Asset.Amount)
			}
		}

		return nil
	}
}

// testBackupFileUpdates asserts that the encrypted asset wallet backup file
// is written on startup, follows sends and receives, can only be read with the
// wallet key and can be used to restore a fresh tapd on the same lnd.
//
// Flow:
//  1. Alice mints an asset, her backup file contains the minted leaf.
//  2. Alice sends part of it to Bob. Alice's file swaps the minted leaf for
//     the change leaf, Bob's file gains the received leaf. Alice also mints
//     a grouped asset and sends it to a V2 address of Bob, whose script key
//     is a unique Pedersen key: tweaked, yet spent like a BIP-86 key.
//  3. Alice cannot import Bob's file (different wallet key).
//  4. Bob's tapd is stopped and a fresh tapd on Bob's lnd imports the file,
//     recovering the leaf.
//  5. Only Bob's database is wiped, the proofs directory and the file stay.
//     The restarted tapd imports the file and recovers the leaf again.
func testBackupFileUpdates(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout*6)
	defer cancel()

	aliceLnd, err := t.newLndClient(t.tapd.cfg.LndNode)
	require.NoError(t.t, err)
	defer aliceLnd.Close()

	// A fresh node with no assets still writes an (empty) file on
	// startup.
	waitForBackupFile(t, t.tapd, aliceLnd, expectEntries())

	// === Stage 1: Mint on Alice ===
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner(), t.tapd,
		[]*mintrpc.MintAssetRequest{{
			Asset: &mintrpc.MintAsset{
				AssetType: taprpc.AssetType_NORMAL,
				Name:      "backup-file-asset",
				AssetMeta: &taprpc.AssetMeta{
					Data: []byte("backup file test"),
				},
				Amount: 1000,
			},
		}},
	)
	require.Len(t.t, rpcAssets, 1)
	minted := rpcAssets[0]

	_, aliceBackup := waitForBackupFile(
		t, t.tapd, aliceLnd, expectEntries(1000),
	)
	mintedEntry := aliceBackup.Assets[0]
	require.Equal(t.t, backup.BackupVersionStripped, aliceBackup.Version)

	mintedID := mintedEntry.Asset.ID()
	require.Equal(t.t, minted.AssetGenesis.AssetId, mintedID[:])
	require.Equal(t.t, minted.ScriptKey,
		mintedEntry.Asset.ScriptKey.PubKey.SerializeCompressed())
	require.NotEmpty(t.t, mintedEntry.StrippedProofFileBlob)
	require.Empty(t.t, mintedEntry.ProofFileBlob)
	require.NotNil(t.t, mintedEntry.AnchorInternalKeyInfo)
	require.NotZero(
		t.t, mintedEntry.AnchorInternalKeyInfo.KeyLocator.Family,
	)

	// === Stage 2: Send part of the asset to Bob ===
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)

	bobLndClient, err := t.newLndClient(bobLnd)
	require.NoError(t.t, err)
	defer bobLndClient.Close()

	bobAddr, err := bobTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:      minted.AssetGenesis.AssetId,
		Amt:          300,
		AssetVersion: minted.Version,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, bobTapd, minted, bobAddr)

	sendResp, _ := sendAssetsToAddr(t, t.tapd, bobAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner(), t.tapd, sendResp,
		minted.AssetGenesis.AssetId, []uint64{700, 300}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 1)

	// Alice's file now holds the change leaf only, anchored at a new
	// outpoint.
	_, aliceBackup = waitForBackupFile(
		t, t.tapd, aliceLnd, expectEntries(700),
	)
	require.NotEqual(t.t, mintedEntry.AnchorOutpoint,
		aliceBackup.Assets[0].AnchorOutpoint)

	// Bob's file holds the received leaf.
	_, bobBackup := waitForBackupFile(
		t, bobTapd, bobLndClient, expectEntries(300),
	)
	bobID := bobBackup.Assets[0].Asset.ID()
	require.Equal(t.t, minted.AssetGenesis.AssetId, bobID[:])

	// A grouped asset received on a V2 address lands on a unique Pedersen
	// script key. Its entry must record that type, otherwise a restore
	// files it as an external script path key and hides it.
	grouped := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner(), t.tapd,
		[]*mintrpc.MintAssetRequest{CopyRequest(issuableAssets[0])},
	)[0]
	groupAddr, err := bobTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V2,
		GroupKey:       grouped.AssetGroup.TweakedGroupKey,
	})
	require.NoError(t.t, err)

	sendResp, err = t.tapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		AddressesWithAmounts: []*taprpc.AddressWithAmount{{
			TapAddr: groupAddr.Encoded,
			Amount:  grouped.Amount,
		}},
	})
	require.NoError(t.t, err)
	AssertAssetOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner(), t.tapd, sendResp.Transfer,
		[][]byte{grouped.AssetGenesis.AssetId},
		[]uint64{grouped.Amount}, 1, 2, 1, true,
	)
	AssertNonInteractiveRecvComplete(t.t, bobTapd, 2)

	bobRaw, bobBackup := waitForBackupFile(
		t, bobTapd, bobLndClient, expectEntries(300, grouped.Amount),
	)
	for _, ab := range bobBackup.Assets {
		require.NotNil(t.t, ab.ScriptKeyInfo)
		if ab.Asset.Amount == grouped.Amount {
			require.Equal(t.t, asset.ScriptKeyUniquePedersen,
				ab.ScriptKeyInfo.Type)
			require.NotEmpty(t.t, ab.ScriptKeyInfo.Tweak)
		} else {
			require.Equal(t.t, asset.ScriptKeyBip86,
				ab.ScriptKeyInfo.Type)
		}
	}

	// Both leaves are visible with the default listing filter.
	bobAssets, err := bobTapd.ListAssets(ctxt, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, bobAssets.Assets, 2)

	// === Stage 3: Wrong key ===
	// Alice's wallet key cannot decrypt Bob's file.
	_, err = t.tapd.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{Backup: bobRaw},
	)
	require.ErrorContains(t.t, err, "unable to decrypt")

	// === Stage 4: Restore Bob from the file ===
	// Stop Bob's tapd, dropping its database, and start a fresh tapd on
	// the same lnd node.
	require.NoError(t.t, bobTapd.stop(!*noDelete))

	bobTapd2 := setupTapdHarness(t.t, t, bobLnd, t.universeServer)

	bobAssets, err = bobTapd2.ListAssets(ctxt, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)
	require.Empty(t.t, bobAssets.Assets)

	importResp, err := bobTapd2.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{Backup: bobRaw},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(2), importResp.NumImported)
	require.Equal(t.t, uint32(0), importResp.NumSkipped)

	// Both leaves are back, visible with the default filter, and the
	// balances see them too. This is what a restore is for.
	assertRestoredLeaves(t, bobTapd2, minted, grouped)

	// Importing again is a no-op.
	importResp, err = bobTapd2.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{Backup: bobRaw},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(0), importResp.NumImported)

	// The restored node's own backup file catches up with the imported
	// leaves.
	waitForBackupFile(
		t, bobTapd2, bobLndClient, expectEntries(300, grouped.Amount),
	)

	// === Stage 5: Wipe only the database ===
	// A common way to "reset" tapd is to delete tapd.db and keep the rest
	// of the data directory, including the proof files and the backup
	// file itself. The import must still recover the leaf: proof files
	// on disk are not the wallet. With the postgres backend every harness
	// gets its own database, so reusing the data directory alone produces
	// the same state: fresh database, old proofs directory.
	require.NoError(t.t, bobTapd2.stop(false))

	dataDir := filepath.Dir(backupFilePath(bobTapd2))
	dbFiles, err := filepath.Glob(filepath.Join(dataDir, "tapd.db*"))
	require.NoError(t.t, err)
	if *dbbackend == "sqlite" {
		require.NotEmpty(t.t, dbFiles)
	}
	for _, f := range dbFiles {
		require.NoError(t.t, os.Remove(f))
	}
	require.FileExists(t.t, backupFilePath(bobTapd2))
	require.DirExists(t.t, filepath.Join(dataDir, "proofs"))

	bobTapd3 := setupTapdHarness(
		t.t, t, bobLnd, t.universeServer,
		WithBaseDir(bobTapd2.cfg.BaseDir),
	)
	defer func() {
		require.NoError(t.t, bobTapd3.stop(!*noDelete))
	}()

	bobAssets, err = bobTapd3.ListAssets(ctxt, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)
	require.Empty(t.t, bobAssets.Assets)

	// The file on disk was retained across the restart and is what we
	// import from.
	bobRaw, _ = waitForBackupFile(
		t, bobTapd3, bobLndClient, expectEntries(300, grouped.Amount),
	)
	importResp, err = bobTapd3.ImportAssetsFromBackup(
		ctxt, &wrpc.ImportAssetsFromBackupRequest{Backup: bobRaw},
	)
	require.NoError(t.t, err)
	require.Equal(t.t, uint32(2), importResp.NumImported)
	require.Equal(t.t, uint32(0), importResp.NumSkipped)

	assertRestoredLeaves(t, bobTapd3, minted, grouped)

	// The restored leaf is spendable: send it back to Alice.
	aliceAddr, err := t.tapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AssetId:      minted.AssetGenesis.AssetId,
		Amt:          300,
		AssetVersion: minted.Version,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, t.tapd, minted, aliceAddr)

	sendResp, _ = sendAssetsToAddr(t, bobTapd3, aliceAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner(), bobTapd3, sendResp,
		minted.AssetGenesis.AssetId, []uint64{0, 300}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, t.tapd, 1)

	waitForBackupFile(
		t, bobTapd3, bobLndClient, expectEntries(grouped.Amount),
	)
	waitForBackupFile(t, t.tapd, aliceLnd, expectEntries(700, 300))

	// The restored Pedersen leaf is spendable as well: send it back to a
	// V2 address of Alice.
	aliceGroupAddr, err := t.tapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V2,
		GroupKey:       grouped.AssetGroup.TweakedGroupKey,
	})
	require.NoError(t.t, err)

	sendResp, err = bobTapd3.SendAsset(ctxt, &taprpc.SendAssetRequest{
		AddressesWithAmounts: []*taprpc.AddressWithAmount{{
			TapAddr: aliceGroupAddr.Encoded,
			Amount:  grouped.Amount,
		}},
	})
	require.NoError(t.t, err)
	AssertAssetOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner(), bobTapd3, sendResp.Transfer,
		[][]byte{grouped.AssetGenesis.AssetId},
		[]uint64{grouped.Amount}, 1, 2, 1, true,
	)
	AssertNonInteractiveRecvComplete(t.t, t.tapd, 2)

	waitForBackupFile(t, bobTapd3, bobLndClient, expectEntries())
	waitForBackupFile(
		t, t.tapd, aliceLnd, expectEntries(700, 300, grouped.Amount),
	)
}

// assertRestoredLeaves asserts that a restored node lists both the BIP-86
// leaf of the minted asset and the unique Pedersen leaf of the grouped asset
// with the default filters, in ListAssets and in ListBalances.
func assertRestoredLeaves(t *harnessTest, tapd *tapdHarness,
	minted, grouped *taprpc.Asset) {

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	assets, err := tapd.ListAssets(ctxt, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)
	require.Len(t.t, assets.Assets, 2)

	amounts := make(map[string]uint64)
	types := make(map[string]taprpc.ScriptKeyType)
	for _, a := range assets.Assets {
		id := fmt.Sprintf("%x", a.AssetGenesis.AssetId)
		amounts[id] = a.Amount
		types[id] = a.ScriptKeyType
	}
	mintedID := fmt.Sprintf("%x", minted.AssetGenesis.AssetId)
	groupedID := fmt.Sprintf("%x", grouped.AssetGenesis.AssetId)
	require.Equal(t.t, uint64(300), amounts[mintedID])
	require.Equal(t.t, grouped.Amount, amounts[groupedID])
	require.Equal(t.t, taprpc.ScriptKeyType_SCRIPT_KEY_BIP86,
		types[mintedID])
	require.Equal(t.t, taprpc.ScriptKeyType_SCRIPT_KEY_UNIQUE_PEDERSEN,
		types[groupedID])

	balances, err := tapd.ListBalances(ctxt, &taprpc.ListBalancesRequest{
		GroupBy: &taprpc.ListBalancesRequest_AssetId{AssetId: true},
	})
	require.NoError(t.t, err)
	require.Len(t.t, balances.AssetBalances, 2)
	require.Equal(t.t, uint64(300),
		balances.AssetBalances[mintedID].Balance)
	require.Equal(t.t, grouped.Amount,
		balances.AssetBalances[groupedID].Balance)
}
