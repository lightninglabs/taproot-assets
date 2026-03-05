package backup

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/keychain"
)

var (
	// ErrKeyLocatorNotFound is returned when a key locator cannot be found
	// for a given public key.
	ErrKeyLocatorNotFound = errors.New("key locator not found")
)

// ExportMode controls which backup format is used when exporting.
type ExportMode int

const (
	// ExportModeRaw produces a v1 backup with full proof data.
	ExportModeRaw ExportMode = iota

	// ExportModeCompact produces a v2 backup with stripped proofs and
	// rehydration hints.
	ExportModeCompact

	// ExportModeOptimistic produces a v3 backup with no proof data.
	// Proofs are fetched from a universe server on import.
	ExportModeOptimistic
)

// KeyLocatorLookup is an interface for looking up key locators by public key.
// This allows the backup package to fetch full key derivation information
// for internal keys.
type KeyLocatorLookup interface {
	// FetchInternalKeyLocator returns the key locator for an internal key
	// given its public key. Returns ErrKeyLocatorNotFound if the key is
	// not found.
	FetchInternalKeyLocator(ctx context.Context,
		pubKey *btcec.PublicKey) (keychain.KeyLocator, error)
}

// AssetBackup contains the essential data needed to restore a single asset.
// It stores the full proof file blob to preserve the complete proof chain
// and avoid encoding/decoding issues with complex proof structures.
type AssetBackup struct {
	// Asset contains the core asset state including amount, version,
	// script key, and witnesses.
	Asset *asset.Asset

	// AnchorOutpoint is the outpoint where this asset is currently
	// anchored.
	AnchorOutpoint wire.OutPoint

	// AnchorBlockHeight is the block height where this asset was confirmed.
	AnchorBlockHeight uint32

	// ScriptKeyInfo contains the key derivation information needed to
	// reconstruct the script key for spending.
	ScriptKeyInfo *ScriptKeyBackup

	// AnchorInternalKeyInfo contains the key derivation information for the
	// internal key used in the anchor taproot output.
	AnchorInternalKeyInfo *KeyDescriptorBackup

	// ProofFileBlob contains the complete encoded proof file for
	// this asset. This preserves the full proof chain and all
	// proof data without needing to reconstruct anything.
	// Used in v1 backups.
	ProofFileBlob []byte

	// StrippedProofFileBlob contains a proof file with blockchain-
	// derivable fields removed (BlockHeader, AnchorTx, TxMerkleProof,
	// BlockHeight). Used in v2+ backups to reduce backup size.
	StrippedProofFileBlob []byte

	// RehydrationHintsBlob contains the serialized FileHints needed
	// to reconstruct the stripped fields from blockchain data.
	// Used in v2+ backups alongside StrippedProofFileBlob.
	RehydrationHintsBlob []byte

	// AnchorOutputPkScript is the pk_script of the anchor output.
	// Needed for registering spend notifications during import.
	AnchorOutputPkScript []byte
}

// ScriptKeyBackup contains the key material needed to restore a script key.
type ScriptKeyBackup struct {
	// PubKey is the final tweaked script key.
	PubKey *btcec.PublicKey

	// RawKey is the key descriptor for the internal key before tweaking.
	RawKey keychain.KeyDescriptor

	// Tweak is the tweak applied to derive the final script key.
	// If nil, a BIP-0086 tweak is assumed.
	Tweak []byte
}

// KeyDescriptorBackup contains the key derivation info for an internal key.
type KeyDescriptorBackup struct {
	// PubKey is the public key.
	PubKey *btcec.PublicKey

	// KeyLocator contains the derivation path info (family + index).
	KeyLocator keychain.KeyLocator
}

// WalletBackup contains all the data needed to restore a wallet's assets.
type WalletBackup struct {
	// Version is the backup format version.
	Version uint32

	// Assets contains the backup data for each active asset.
	Assets []*AssetBackup

	// FederationURLs contains the universe federation server URLs used
	// in v3 (optimistic) backups to fetch proofs on import.
	FederationURLs []string
}

// createAssetBackup creates a backup for a single asset by storing the
// complete proof file blob along with key derivation information needed
// for spending.
func createAssetBackup(ctx context.Context,
	chainAsset *asset.ChainAsset, proofBlob proof.Blob,
	keyLookup KeyLocatorLookup) (*AssetBackup, error) {

	if chainAsset == nil || chainAsset.Asset == nil {
		return nil, fmt.Errorf("chain asset is nil")
	}

	backup := &AssetBackup{
		Asset:             chainAsset.Asset,
		AnchorOutpoint:    chainAsset.AnchorOutpoint,
		AnchorBlockHeight: chainAsset.AnchorBlockHeight,
		ProofFileBlob:     proofBlob,
	}

	// Store the anchor output's pk_script for spend detection on import.
	if chainAsset.AnchorTx != nil {
		idx := chainAsset.AnchorOutpoint.Index
		if int(idx) < len(chainAsset.AnchorTx.TxOut) {
			backup.AnchorOutputPkScript =
				chainAsset.AnchorTx.TxOut[idx].PkScript
		}
	}

	// Extract script key info if available.
	if chainAsset.ScriptKey.TweakedScriptKey != nil {
		backup.ScriptKeyInfo = &ScriptKeyBackup{
			PubKey: chainAsset.ScriptKey.PubKey,
			RawKey: chainAsset.ScriptKey.TweakedScriptKey.RawKey,
			Tweak:  chainAsset.ScriptKey.TweakedScriptKey.Tweak,
		}
	}

	// Extract anchor internal key info if available.
	if chainAsset.AnchorInternalKey != nil {
		backup.AnchorInternalKeyInfo = &KeyDescriptorBackup{
			PubKey: chainAsset.AnchorInternalKey,
		}

		// Try to look up the key locator for full derivation info.
		if keyLookup != nil {
			keyLoc, err := keyLookup.FetchInternalKeyLocator(
				ctx, chainAsset.AnchorInternalKey,
			)
			if err == nil {
				backup.AnchorInternalKeyInfo.KeyLocator = keyLoc
			}
			// If lookup fails, we still have the public key which
			// may be sufficient for some recovery scenarios.
		}
	}

	return backup, nil
}

// collectAssetBackups collects backup data for all provided assets.
// The keyLookup parameter is optional - if nil, anchor internal key locators
// will not be populated (only the public keys will be included).
func collectAssetBackups(ctx context.Context,
	assets []*asset.ChainAsset,
	proofArchive proof.Archiver,
	keyLookup KeyLocatorLookup) ([]*AssetBackup, error) {

	backups := make([]*AssetBackup, 0, len(assets))

	for _, chainAsset := range assets {
		if chainAsset == nil || chainAsset.Asset == nil {
			continue
		}

		// Get the asset ID for the locator.
		assetID := chainAsset.ID()

		// Create a locator to fetch the proof for this asset.
		locator := proof.Locator{
			ScriptKey: *chainAsset.ScriptKey.PubKey,
			AssetID:   &assetID,
			OutPoint:  &chainAsset.AnchorOutpoint,
		}

		// Fetch the proof file blob for this asset.
		proofBlob, err := proofArchive.FetchProof(ctx, locator)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch proof for "+
				"asset %x: %w", chainAsset.ID(), err)
		}

		// Create the backup for this asset using the raw proof blob.
		assetBackup, err := createAssetBackup(
			ctx, chainAsset, proofBlob, keyLookup,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create backup for "+
				"asset %x: %w", chainAsset.ID(), err)
		}

		backups = append(backups, assetBackup)
	}

	return backups, nil
}

// collectAssetBackupsOptimistic collects backup data for all provided assets
// without fetching proof data. This is used for v3 optimistic backups where
// proofs are fetched from a universe server on import instead of being stored
// in the backup.
func collectAssetBackupsOptimistic(ctx context.Context,
	assets []*asset.ChainAsset,
	keyLookup KeyLocatorLookup) ([]*AssetBackup, error) {

	backups := make([]*AssetBackup, 0, len(assets))

	for _, chainAsset := range assets {
		if chainAsset == nil || chainAsset.Asset == nil {
			continue
		}

		// Create the backup with no proof blob.
		assetBackup, err := createAssetBackup(
			ctx, chainAsset, nil, keyLookup,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create backup for "+
				"asset %x: %w", chainAsset.ID(), err)
		}

		backups = append(backups, assetBackup)
	}

	return backups, nil
}
