package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/backup"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapcustody"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightninglabs/taproot-assets/tapreorg/chainsim"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// unspentChecker answers every spend registration with silence, which the
// backup importer reads as "unspent" once its per-outpoint timeout elapses.
type unspentChecker struct{}

func (unspentChecker) RegisterSpendNtfn(context.Context, *wire.OutPoint,
	[]byte, int32, ...lndclient.NotifierOption) (
	chan *chainntnfs.SpendDetail, chan error, error) {

	return make(chan *chainntnfs.SpendDetail), make(chan error), nil
}

// staticKeyDeriver derives every backup key from one private key.
type staticKeyDeriver struct {
	priv *btcec.PrivateKey
}

func (d *staticKeyDeriver) DeriveKey(_ context.Context,
	locator *keychain.KeyLocator) (*keychain.KeyDescriptor, error) {

	return &keychain.KeyDescriptor{
		KeyLocator: *locator,
		PubKey:     d.priv.PubKey(),
	}, nil
}

// TestBackupRestoresGroupedAsset restores a backup carrying a grouped
// asset into an empty wallet through ImportBackup and the custody staking
// boundary, verified the way the wallet verifies: headers against the chain
// the proofs describe, and group keys against a database that has never seen
// the group. The backup carries the group's genesis reveal, which is all a
// restore has to go on.
func TestBackupRestoresGroupedAsset(t *testing.T) {
	t.Parallel()

	const threshold = 6
	ctx := context.Background()
	db := NewTestDB(t)
	mintingStore, assetsStore := newAssetStoreFromDB(db.BaseDB)
	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)
	registry := NewReorgRegistryStore(
		executor, clock.NewTestClock(time.Unix(1_000_000, 0)),
	)

	// The proofs describe the simulator's chain, one transaction per
	// block.
	sim := chainsim.New()
	bridge := &simChainBridge{sim: sim}
	anchor := func(tx *wire.MsgTx) (*wire.MsgBlock, uint32) {
		height := sim.MineBlock(tx)
		block, err := bridge.GetBlockByHeight(ctx, int64(height))
		require.NoError(t, err)

		return block, height
	}
	file, recipientKey, anchorOut := proof.RandTransferProofFile(t, anchor)
	var fileBuf bytes.Buffer
	require.NoError(t, file.Encode(&fileBuf))
	tip, err := file.LastProof()
	require.NoError(t, err)
	require.NotNil(t, tip.Asset.GroupKey)

	// The wallet as the server wires it: the watcher over the wallet's
	// registry, and a custodian verifying with the wallet's chain bridge
	// and database-backed group verifier.
	errChan := make(chan error, 16)
	watcher := tapreorg.NewWatcher(&tapreorg.WatcherConfig{
		Notifier:               sim,
		Registry:               registry,
		DefaultThreshold:       threshold,
		InitialDeliveryBackoff: 10 * time.Millisecond,
		MaxDeliveryBackoff:     40 * time.Millisecond,
		ScanInterval:           20 * time.Millisecond,
		DispatchTimeout:        100 * time.Millisecond,
		ErrChan:                errChan,
	})
	custodian := tapcustody.NewCustodian(&tapcustody.Config{
		ChainBridge:        bridge,
		GroupVerifier:      tapnode.GenGroupVerifier(ctx, mintingStore),
		AnchoringWatcher:   watcher,
		AnchoringLog:       assetsStore,
		ProofAdoptionLog:   assetsStore,
		AnchoringThreshold: threshold,
	})
	require.NoError(t, watcher.RegisterSite(custodian.AnchoringSite()))
	require.NoError(t, watcher.Start())
	t.Cleanup(func() {
		require.NoError(t, watcher.Stop())
		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
		}
	})

	addrTx := NewTransactionExecutor(
		db, func(tx *sql.Tx) AddrBook {
			return db.WithTx(tx)
		},
	)
	addrBook := NewTapAddressBook(
		addrTx, chainParams, clock.NewTestClock(time.Now()),
	)

	// The backup, as the wallet that held the asset wrote it.
	backupPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	deriver := &staticKeyDeriver{priv: backupPriv}
	encrypter, err := backup.NewKeyRingEncrypter(ctx, deriver)
	require.NoError(t, err)
	plain, err := backup.EncodeWalletBackup(&backup.WalletBackup{
		Version: backup.BackupVersionOriginal,
		Assets: []*backup.AssetBackup{{
			Asset:             &tip.Asset,
			AnchorOutpoint:    anchorOut,
			AnchorBlockHeight: tip.BlockHeight,
			ScriptKeyInfo: &backup.ScriptKeyBackup{
				PubKey: tip.Asset.ScriptKey.PubKey,
				RawKey: recipientKey,
			},
			AnchorInternalKeyInfo: &backup.KeyDescriptorBackup{
				PubKey: tip.InclusionProof.InternalKey,
				KeyLocator: keychain.KeyLocator{
					Family: 1,
					Index:  1,
				},
			},
			ProofFileBlob:        fileBuf.Bytes(),
			AnchorOutputPkScript: tip.AnchorTx.TxOut[0].PkScript,
		}},
	})
	require.NoError(t, err)
	packed, err := backup.EncryptBackup(encrypter, plain)
	require.NoError(t, err)

	// The importer's own verifier context, as the RPC server builds it.
	groupVerifier := tapnode.GenGroupVerifier(ctx, mintingStore)
	verifierCtx := proof.VerifierCtx{
		HeaderVerifier:      tapnode.GenHeaderVerifier(ctx, bridge),
		MerkleVerifier:      proof.DefaultMerkleVerifier,
		GroupVerifier:       groupVerifier,
		GroupAnchorVerifier: proof.MockGroupAnchorVerifier,
		ChainLookupGen:      bridge,
	}
	imported, skipped, err := backup.ImportBackup(
		ctx, packed, &backup.ImportConfig{
			SpendChecker:      unspentChecker{},
			SpendCheckTimeout: 50 * time.Millisecond,
			ProofArchive:      assetsStore,
			ProofStaker:       custodian,
			KeyRegistrar:      addrBook,
			ProofVerifier:     verifierCtx,
			KeyDeriver:        deriver,
		},
	)
	require.NoError(t, err,
		"restoring a grouped asset into an empty wallet")
	require.EqualValues(t, 1, imported)
	require.Zero(t, skipped)

	// The asset is held, and its young transitions are staked.
	assetID := tip.Asset.ID()
	has, err := assetsStore.HasProof(ctx, proof.Locator{
		AssetID:   &assetID,
		ScriptKey: *tip.Asset.ScriptKey.PubKey,
		OutPoint:  &anchorOut,
	})
	require.NoError(t, err)
	require.True(t, has)

	tipTxid := tip.AnchorTx.TxHash()
	anchoring, err := watcher.LookupByMatchKey(
		ctx, tapcustody.ReceiveSiteID, tipTxid.CloneBytes(),
	)
	require.NoError(t, err)
	require.NotNil(t, anchoring)
}
