package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/keychain"
)

const (
	// spendCheckTimeout is how long we wait for spend notifications
	// when checking whether a backup's anchor outpoints have been
	// spent. All outpoints are checked concurrently, so this is a
	// single wait for the entire batch. Historical spends are
	// reported almost immediately; the timeout only fires for
	// unspent (valid) outpoints.
	spendCheckTimeout = 10 * time.Second
)

// SpendChecker can determine whether an outpoint has been spent.
type SpendChecker interface {
	// RegisterSpendNtfn dispatches a spend notification request to the
	// chain notifier. If the outpoint has already been spent, the
	// notification is dispatched immediately.
	RegisterSpendNtfn(ctx context.Context, outpoint *wire.OutPoint,
		pkScript []byte, heightHint int32,
		optFuncs ...lndclient.NotifierOption) (
		chan *chainntnfs.SpendDetail, chan error, error)
}

// KeyRegistrar allows registering keys needed for wallet operations.
type KeyRegistrar interface {
	// InsertInternalKey inserts an internal key into the database.
	InsertInternalKey(ctx context.Context,
		keyDesc keychain.KeyDescriptor) error

	// InsertScriptKey inserts a script key into the database.
	InsertScriptKey(ctx context.Context, scriptKey asset.ScriptKey,
		keyType asset.ScriptKeyType) error
}

// ImportConfig holds the dependencies needed to import a backup.
type ImportConfig struct {
	// SpendChecker is used to detect stale backup entries whose anchor
	// outpoints have already been spent.
	SpendChecker SpendChecker

	// ChainQuerier provides access to blockchain data for rehydrating
	// stripped proofs.
	ChainQuerier ChainQuerier

	// ProofArchive is used to check for existing proofs and to import
	// new proofs.
	ProofArchive proof.Archiver

	// KeyRegistrar is used to register anchor internal keys and script
	// keys so the wallet can sign for imported assets.
	KeyRegistrar KeyRegistrar

	// ProofVerifier provides the verification context for imported proofs.
	ProofVerifier proof.VerifierCtx
}

// ImportBackup decodes and imports assets from a backup blob. Returns the
// number of newly imported assets.
func ImportBackup(ctx context.Context, backupBlob []byte,
	cfg *ImportConfig) (uint32, error) {

	if len(backupBlob) == 0 {
		return 0, fmt.Errorf("backup data is empty")
	}

	log.Infof("Importing assets from backup (%d bytes)",
		len(backupBlob))

	// Decode and verify the backup.
	walletBackup, err := DecodeWalletBackup(backupBlob)
	if err != nil {
		return 0, fmt.Errorf("failed to decode backup: %w", err)
	}

	log.Infof("Decoded backup version %d with %d assets",
		walletBackup.Version, len(walletBackup.Assets))

	// Check on-chain whether each asset's anchor outpoint has been
	// spent. We register spend notifications for all outpoints
	// concurrently and wait once, so stale assets are detected
	// without adding per-asset latency.
	spentOutpoints, err := detectSpentOutpoints(
		ctx, cfg.SpendChecker, walletBackup.Assets,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to check outpoint "+
			"status: %w", err)
	}

	var numImported uint32

	for i, assetBackup := range walletBackup.Assets {
		log.Debugf("Processing asset %d: outpoint=%v, amount=%d",
			i, assetBackup.AnchorOutpoint,
			assetBackup.Asset.Amount)

		// Skip assets whose anchor outpoint has been spent.
		if spentOutpoints[i] {
			assetID := assetBackup.Asset.ID()
			log.Warnf("Skipping asset %d (id=%x): "+
				"anchor outpoint %v has been spent, "+
				"backup is stale", i, assetID[:],
				assetBackup.AnchorOutpoint)
			continue
		}

		// Check if asset already exists by trying to fetch its
		// proof.
		assetID := assetBackup.Asset.ID()
		locator := proof.Locator{
			AssetID:   &assetID,
			ScriptKey: *assetBackup.Asset.ScriptKey.PubKey,
			OutPoint:  &assetBackup.AnchorOutpoint,
		}

		_, err := cfg.ProofArchive.FetchProof(ctx, locator)
		if err == nil {
			log.Debugf("Asset %d already exists, skipping", i)
			continue
		}
		if !errors.Is(err, proof.ErrProofNotFound) {
			return 0, fmt.Errorf("error checking existing "+
				"asset %d: %w", i, err)
		}

		// For v2+ backups, rehydrate the stripped proof by
		// fetching blockchain data. This reconstructs the full
		// proof file.
		if len(assetBackup.StrippedProofFileBlob) > 0 {
			hints, err := DecodeFileHints(
				bytes.NewReader(
					assetBackup.RehydrationHintsBlob,
				),
			)
			if err != nil {
				return 0, fmt.Errorf("failed to decode "+
					"hints for asset %d: %w", i, err)
			}

			fullBlob, err := RehydrateProofFile(
				ctx, assetBackup.StrippedProofFileBlob,
				hints, cfg.ChainQuerier,
			)
			if err != nil {
				return 0, fmt.Errorf("failed to rehydrate "+
					"proof for asset %d: %w", i, err)
			}

			assetBackup.ProofFileBlob = fullBlob
		}

		// For v3 optimistic backups, fetch proofs from a universe
		// server when no proof data is present.
		if len(assetBackup.ProofFileBlob) == 0 &&
			len(assetBackup.StrippedProofFileBlob) == 0 &&
			len(walletBackup.FederationURLs) > 0 {

			proofBlob, err := fetchProofFromUniverse(
				ctx, walletBackup.FederationURLs,
				assetBackup, cfg.ProofArchive,
			)
			if err != nil {
				return 0, fmt.Errorf("failed to fetch "+
					"proof from universe for asset "+
					"%d: %w", i, err)
			}

			assetBackup.ProofFileBlob = proofBlob
		}

		// Verify we have a proof blob.
		if len(assetBackup.ProofFileBlob) == 0 {
			return 0, fmt.Errorf("asset %d has no proof blob", i)
		}

		// Register keys BEFORE importing the proof so that when
		// ImportProofs stores the asset, it can find the existing
		// key records with full key locator info. This is
		// essential for the wallet to be able to sign spends
		// later.

		// Register the anchor internal key so LND can sign for
		// the anchor output when spending.
		if assetBackup.AnchorInternalKeyInfo != nil {
			info := assetBackup.AnchorInternalKeyInfo
			anchorKey := keychain.KeyDescriptor{
				PubKey:     info.PubKey,
				KeyLocator: info.KeyLocator,
			}

			err = cfg.KeyRegistrar.InsertInternalKey(
				ctx, anchorKey,
			)
			if err != nil {
				log.Warnf("Failed to insert anchor "+
					"internal key for asset %d: %v",
					i, err)
			}
		}

		// Register the script key so the wallet can identify the
		// asset as locally owned and sign virtual transactions.
		if assetBackup.ScriptKeyInfo != nil {
			skInfo := assetBackup.ScriptKeyInfo
			scriptKey := asset.ScriptKey{
				PubKey: skInfo.PubKey,
				TweakedScriptKey: &asset.TweakedScriptKey{
					RawKey: skInfo.RawKey,
					Tweak:  skInfo.Tweak,
				},
			}

			scriptKeyType := asset.ScriptKeyBip86
			if len(skInfo.Tweak) > 0 {
				scriptKeyType =
					asset.ScriptKeyScriptPathExternal
			}

			err = cfg.KeyRegistrar.InsertScriptKey(
				ctx, scriptKey, scriptKeyType,
			)
			if err != nil {
				log.Warnf("Failed to insert script key "+
					"for asset %d: %v", i, err)
			}
		}

		// Import the proof blob directly into the archive.
		// The backup stores the complete original proof file, so
		// we can import it without any reconstruction.
		err = cfg.ProofArchive.ImportProofs(
			ctx, cfg.ProofVerifier, false,
			&proof.AnnotatedProof{
				Locator: locator,
				Blob:    assetBackup.ProofFileBlob,
			},
		)
		if err != nil {
			return 0, fmt.Errorf("failed to import proof "+
				"for asset %d: %w", i, err)
		}

		log.Debugf("Successfully imported asset %d", i)
		numImported++
	}

	log.Infof("Imported %d assets from backup", numImported)

	return numImported, nil
}

// detectSpentOutpoints registers spend notifications for every asset's
// anchor outpoint concurrently, giving each outpoint its own timeout.
// Returns a slice indexed by asset position: true = spent.
func detectSpentOutpoints(ctx context.Context,
	spendChecker SpendChecker,
	assets []*AssetBackup) ([]bool, error) {

	spent := make([]bool, len(assets))
	if len(assets) == 0 {
		return spent, nil
	}

	// Create a child context so all goroutines are cancelled
	// promptly if we return early on error.
	detectCtx, detectCancel := context.WithCancel(ctx)
	defer detectCancel()

	type spendResult struct {
		index int
		spent bool
		err   error
	}

	results := make(chan spendResult, len(assets))

	// Register spend notifications and spawn a goroutine per
	// outpoint. Each goroutine gets its own timeout so that even
	// with thousands of assets, every outpoint has the full
	// duration for lnd to respond.
	for i, ab := range assets {
		spendChan, errChan, err :=
			spendChecker.RegisterSpendNtfn(
				detectCtx, &ab.AnchorOutpoint,
				ab.AnchorOutputPkScript,
				int32(ab.AnchorBlockHeight),
			)
		if err != nil {
			return nil, fmt.Errorf("unable to register "+
				"spend ntfn for asset %d: %w", i, err)
		}

		go func(idx int,
			sc chan *chainntnfs.SpendDetail,
			ec chan error) {

			assetCtx, cancel := context.WithTimeout(
				detectCtx, spendCheckTimeout,
			)
			defer cancel()

			select {
			case <-sc:
				results <- spendResult{
					index: idx, spent: true,
				}
			case err := <-ec:
				results <- spendResult{
					index: idx, err: err,
				}
			case <-assetCtx.Done():
				results <- spendResult{
					index: idx, spent: false,
				}
			}
		}(i, spendChan, errChan)
	}

	// Collect exactly len(assets) results. All goroutines run in
	// parallel, so wall-clock time is ~spendCheckTimeout regardless
	// of asset count. Spent outpoints resolve almost instantly
	// (lnd checks the UTXO set synchronously); only unspent ones
	// wait for the timeout.
	for range assets {
		r := <-results
		if r.err != nil {
			return nil, fmt.Errorf("spend check error "+
				"for asset %d: %w", r.index, r.err)
		}
		spent[r.index] = r.spent
	}

	return spent, nil
}
