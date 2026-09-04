package backup

import (
	"bytes"
	"context"
	"fmt"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
)

// ExportBackup creates a wallet backup from the given assets. For
// ExportModeCompact, proofs are stripped of blockchain-derivable fields. For
// ExportModeOptimistic, no proofs are included and federationURLs must be
// non-empty.
func ExportBackup(ctx context.Context, mode ExportMode,
	assets []*asset.ChainAsset, proofArchive proof.Exporter,
	keyLookup KeyLocatorLookup,
	federationURLs []string) ([]byte, error) {

	assetBackups, backupVersion, err := CollectBackups(
		ctx, mode, assets, proofArchive, keyLookup, federationURLs,
	)
	if err != nil {
		return nil, err
	}

	log.Infof("Collected backup data for %d assets (mode=%v)",
		len(assetBackups), mode)

	// Create the wallet backup structure and encode it.
	walletBackup := &WalletBackup{
		Version:        backupVersion,
		Assets:         assetBackups,
		FederationURLs: federationURLs,
	}

	backupBytes, err := EncodeWalletBackup(walletBackup)
	if err != nil {
		return nil, fmt.Errorf("failed to encode wallet "+
			"backup: %w", err)
	}

	log.Infof("Encoded wallet backup: %d bytes", len(backupBytes))

	return backupBytes, nil
}

// CollectBackups builds the per-asset backup entries for the given assets in
// the requested mode and returns them together with the backup format version
// they must be encoded with.
func CollectBackups(ctx context.Context, mode ExportMode,
	assets []*asset.ChainAsset, proofArchive proof.Exporter,
	keyLookup KeyLocatorLookup,
	federationURLs []string) ([]*AssetBackup, uint32, error) {

	var (
		assetBackups  []*AssetBackup
		backupVersion uint32
		err           error
	)

	switch mode {
	case ExportModeOptimistic:
		// Validate federation URLs before collecting backups to
		// avoid wasted work.
		if len(federationURLs) == 0 {
			return nil, 0, fmt.Errorf("no federation servers " +
				"configured; optimistic backup requires " +
				"at least one universe server")
		}

		// v3: Collect asset backups without fetching proofs.
		assetBackups, err = collectAssetBackupsOptimistic(
			ctx, assets, keyLookup,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to collect "+
				"optimistic asset backups: %w", err)
		}

		backupVersion = BackupVersionOptimistic

	case ExportModeCompact:
		// v2: Collect backups with proofs, then strip them.
		assetBackups, err = collectAssetBackups(
			ctx, assets, proofArchive, keyLookup,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to collect "+
				"asset backups: %w", err)
		}

		for i, ab := range assetBackups {
			if err := stripAssetBackup(ab); err != nil {
				return nil, 0, fmt.Errorf("asset %d: %w", i,
					err)
			}
		}

		backupVersion = BackupVersionStripped

	default:
		// v1 (RAW): Full backup with complete proof data.
		assetBackups, err = collectAssetBackups(
			ctx, assets, proofArchive, keyLookup,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to collect "+
				"asset backups: %w", err)
		}

		backupVersion = BackupVersionOriginal
	}

	return assetBackups, backupVersion, nil
}

// stripAssetBackup converts a raw (v1) asset backup entry into a compact (v2)
// one by stripping the proof file of blockchain-derivable fields and storing
// the rehydration hints alongside it. Entries without a proof blob are left
// untouched.
func stripAssetBackup(ab *AssetBackup) error {
	if len(ab.ProofFileBlob) == 0 {
		return nil
	}

	strippedBlob, hints, err := StripProofFile(ab.ProofFileBlob)
	if err != nil {
		return fmt.Errorf("failed to strip proof: %w", err)
	}

	var hintsBuf bytes.Buffer
	if err := EncodeFileHints(&hintsBuf, hints); err != nil {
		return fmt.Errorf("failed to encode hints: %w", err)
	}

	log.Debugf("Stripped proof %d -> %d bytes (saved %d bytes)",
		len(ab.ProofFileBlob), len(strippedBlob),
		len(ab.ProofFileBlob)-len(strippedBlob))

	ab.StrippedProofFileBlob = strippedBlob
	ab.RehydrationHintsBlob = hintsBuf.Bytes()
	ab.ProofFileBlob = nil

	return nil
}
