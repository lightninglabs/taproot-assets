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
	assets []*asset.ChainAsset, proofArchive proof.Archiver,
	keyLookup KeyLocatorLookup,
	federationURLs []string) ([]byte, error) {

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
			return nil, fmt.Errorf("no federation servers " +
				"configured; optimistic backup requires " +
				"at least one universe server")
		}

		// v3: Collect asset backups without fetching proofs.
		assetBackups, err = collectAssetBackupsOptimistic(
			ctx, assets, keyLookup,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to collect "+
				"optimistic asset backups: %w", err)
		}

		backupVersion = BackupVersionOptimistic

	case ExportModeCompact:
		// v2: Collect backups with proofs, then strip them.
		assetBackups, err = collectAssetBackups(
			ctx, assets, proofArchive, keyLookup,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to collect "+
				"asset backups: %w", err)
		}

		for i, ab := range assetBackups {
			if len(ab.ProofFileBlob) == 0 {
				continue
			}

			strippedBlob, hints, err := StripProofFile(
				ab.ProofFileBlob,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to strip "+
					"proof for asset %d: %w", i, err)
			}

			var hintsBuf bytes.Buffer
			err = EncodeFileHints(&hintsBuf, hints)
			if err != nil {
				return nil, fmt.Errorf("failed to encode "+
					"hints for asset %d: %w",
					i, err)
			}

			log.Debugf("Asset %d: proof %d -> %d bytes "+
				"(stripped %d bytes)", i,
				len(ab.ProofFileBlob),
				len(strippedBlob),
				len(ab.ProofFileBlob)-len(strippedBlob))

			ab.StrippedProofFileBlob = strippedBlob
			ab.RehydrationHintsBlob = hintsBuf.Bytes()
			ab.ProofFileBlob = nil
		}

		backupVersion = BackupVersionStripped

	default:
		// v1 (RAW): Full backup with complete proof data.
		assetBackups, err = collectAssetBackups(
			ctx, assets, proofArchive, keyLookup,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to collect "+
				"asset backups: %w", err)
		}

		backupVersion = BackupVersionOriginal
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
