package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/chainntnfs"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
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

	// maxConcurrentSpendChecks limits the number of concurrent
	// goroutines spawned for spend detection. This bounds memory
	// usage for wallets with many assets.
	maxConcurrentSpendChecks = 100
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

	// ProofVerifier provides the verification context for imported
	// proofs.
	ProofVerifier proof.VerifierCtx
}

// extractGroupKeys extracts group public keys from genesis proofs
// that contain a GroupKeyReveal. The keys are added to the provided
// map. Errors are non-fatal; this is a best-effort extraction used
// to pre-populate the augmented GroupVerifier.
func extractGroupKeys(proofBlob []byte,
	keys map[asset.SerializedKey]bool) {

	file, err := proof.DecodeFile(proofBlob)
	if err != nil {
		log.Debugf("extractGroupKeys: decode file: %v", err)
		return
	}

	if file.NumProofs() == 0 {
		return
	}

	rawGenesis, err := file.RawProofAt(0)
	if err != nil {
		log.Debugf("extractGroupKeys: raw proof: %v", err)
		return
	}

	// Use SparseDecode to extract only the fields we need.
	// This works on both full and stripped proof bytes.
	var p proof.Proof
	err = proof.SparseDecode(
		bytes.NewReader(rawGenesis),
		proof.AssetLeafRecord(&p.Asset),
		proof.GroupKeyRevealRecord(&p.GroupKeyReveal),
	)
	if err != nil {
		log.Debugf("extractGroupKeys: sparse decode: %v", err)
		return
	}

	if p.GroupKeyReveal == nil || p.Asset.GroupKey == nil {
		return
	}

	// Verify the reveal actually derives the claimed group key.
	// Without this check, a tampered backup could whitelist an
	// arbitrary group key. This mirrors verifyGroupKeyReveal()
	// in proof/verifier.go.
	derivedKey, err := p.GroupKeyReveal.GroupPubKey(
		p.Asset.ID(),
	)
	if err != nil {
		log.Debugf("extractGroupKeys: derive key: %v", err)
		return
	}
	if !derivedKey.IsEqual(&p.Asset.GroupKey.GroupPubKey) {
		assetID := p.Asset.ID()
		log.Warnf("extractGroupKeys: asset %x — derived "+
			"key %x does not match claimed group "+
			"key %x; backup may be tampered",
			assetID[:],
			asset.ToSerialized(derivedKey),
			asset.ToSerialized(
				&p.Asset.GroupKey.GroupPubKey,
			))
		return
	}

	gk := asset.ToSerialized(&p.Asset.GroupKey.GroupPubKey)
	keys[gk] = true

	log.Debugf("Pre-extracted group key %x from proof chain",
		gk[:])
}

// ImportBackup decodes and imports assets from a backup blob.
// Returns the number of newly imported assets and the number
// skipped due to per-asset errors.
func ImportBackup(ctx context.Context, backupBlob []byte,
	cfg *ImportConfig) (uint32, uint32, error) {

	if len(backupBlob) == 0 {
		return 0, 0, fmt.Errorf("backup data is empty")
	}

	log.Infof("Importing assets from backup (%d bytes)",
		len(backupBlob))

	// Decode and verify the backup.
	walletBackup, err := DecodeWalletBackup(backupBlob)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to decode backup: "+
			"%w", err)
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
		return 0, 0, fmt.Errorf("failed to check outpoint "+
			"status: %w", err)
	}

	// Pre-extract group keys from all available proof data.
	// For v1 (raw) backups, ProofFileBlob is available. For v2
	// (compact) backups, StrippedProofFileBlob retains the
	// GroupKeyReveal (TLV type 25, odd/optional). This
	// eliminates ordering issues: all group keys are known
	// before any asset is imported.
	knownGroupKeys := make(map[asset.SerializedKey]bool)
	for _, ab := range walletBackup.Assets {
		switch {
		case len(ab.ProofFileBlob) > 0:
			extractGroupKeys(ab.ProofFileBlob, knownGroupKeys)
		case len(ab.StrippedProofFileBlob) > 0:
			extractGroupKeys(
				ab.StrippedProofFileBlob, knownGroupKeys,
			)
		}
	}

	if len(knownGroupKeys) > 0 {
		log.Infof("Pre-extracted %d group key(s) from "+
			"backup proof data", len(knownGroupKeys))
	}

	// Build an augmented GroupVerifier that accepts
	// pre-extracted group keys alongside the normal DB lookup.
	// Security is preserved: File.Verify still runs
	// verifyGroupKeyReveal() on genesis proofs with reveals.
	origGroupVerifier := cfg.ProofVerifier.GroupVerifier
	augmentedVerifier := func(gk *btcec.PublicKey) error {
		if knownGroupKeys[asset.ToSerialized(gk)] {
			return nil
		}
		return origGroupVerifier(gk)
	}

	// Two verifier contexts: one for pre-verification (data
	// checks only, no infrastructure dependencies) and one for
	// the actual import (full verification including chain
	// backend). Pre-verification catches per-asset data issues
	// (unknown group keys, bad proofs) which are skippable.
	// Import verification catches everything including chain
	// and storage errors which are fatal.
	//
	// The pre-verify context uses no-op header verification
	// and a mock chain lookup so it never hits the chain
	// backend. The only code path that consumes the chain
	// lookup is timelock validation, which is disabled via
	// WithSkipTimeLockValidationForAllProofs.
	preVerifyCtx := proof.VerifierCtx{
		HeaderVerifier: func(_ wire.BlockHeader,
			_ uint32) error {

			return nil
		},
		MerkleVerifier:      cfg.ProofVerifier.MerkleVerifier,
		GroupVerifier:       augmentedVerifier,
		GroupAnchorVerifier: cfg.ProofVerifier.GroupAnchorVerifier,
		ChainLookupGen:      proof.MockChainLookup,
		IgnoreChecker:       lfn.None[proof.IgnoreChecker](),
	}

	importVCtx := proof.VerifierCtx{
		HeaderVerifier:      cfg.ProofVerifier.HeaderVerifier,
		MerkleVerifier:      cfg.ProofVerifier.MerkleVerifier,
		GroupVerifier:       augmentedVerifier,
		GroupAnchorVerifier: cfg.ProofVerifier.GroupAnchorVerifier,
		ChainLookupGen:      cfg.ProofVerifier.ChainLookupGen,
		IgnoreChecker:       cfg.ProofVerifier.IgnoreChecker,
	}

	var (
		numImported  uint32
		numSkipped   uint32
		retryIndices []int
		verifier     proof.BaseVerifier
	)

	for i, assetBackup := range walletBackup.Assets {
		if assetBackup.Asset == nil ||
			assetBackup.Asset.ScriptKey.PubKey == nil {

			log.Warnf("Skipping asset %d: nil asset "+
				"or script key", i)
			numSkipped++
			continue
		}

		log.Debugf("Processing asset %d: outpoint=%v, "+
			"amount=%d", i, assetBackup.AnchorOutpoint,
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

		// Check if asset already exists by trying to fetch
		// its proof. DB errors here are fatal.
		assetID := assetBackup.Asset.ID()
		locator := proof.Locator{
			AssetID:   &assetID,
			ScriptKey: *assetBackup.Asset.ScriptKey.PubKey,
			OutPoint:  &assetBackup.AnchorOutpoint,
		}

		_, err := cfg.ProofArchive.FetchProof(ctx, locator)
		if err == nil {
			log.Debugf("Asset %d already exists, "+
				"skipping", i)
			continue
		}
		if !errors.Is(err, proof.ErrProofNotFound) {
			return numImported, numSkipped,
				fmt.Errorf("error checking existing "+
					"asset %d: %w", i, err)
		}

		// For v2+ backups, rehydrate the stripped proof by
		// fetching blockchain data.
		if len(assetBackup.StrippedProofFileBlob) > 0 &&
			len(assetBackup.ProofFileBlob) == 0 {

			hints, err := DecodeFileHints(
				bytes.NewReader(
					assetBackup.RehydrationHintsBlob,
				),
			)
			if err != nil {
				log.Warnf("Skipping asset %d (id=%x):"+
					" failed to decode hints: %v",
					i, assetID[:], err)
				numSkipped++
				continue
			}

			fullBlob, err := RehydrateProofFile(
				ctx,
				assetBackup.StrippedProofFileBlob,
				hints, cfg.ChainQuerier,
			)
			if err != nil {
				log.Warnf("Skipping asset %d (id=%x):"+
					" failed to rehydrate proof:"+
					" %v", i, assetID[:], err)
				numSkipped++
				continue
			}

			assetBackup.ProofFileBlob = fullBlob
		}

		// For v3 optimistic backups, fetch proofs from a
		// universe server when no proof data is present.
		if len(assetBackup.ProofFileBlob) == 0 &&
			len(assetBackup.StrippedProofFileBlob) == 0 &&
			len(walletBackup.FederationURLs) > 0 {

			proofBlob, err := fetchProofFromUniverse(
				ctx, walletBackup.FederationURLs,
				assetBackup, cfg.ProofArchive,
			)
			if err != nil {
				log.Warnf("Skipping asset %d (id=%x):"+
					" failed to fetch proof from"+
					" universe: %v",
					i, assetID[:], err)
				numSkipped++
				continue
			}

			assetBackup.ProofFileBlob = proofBlob
		}

		// After rehydration or universe fetch, extract any
		// group keys from the newly-available proof blob so
		// that subsequent assets can benefit (v3 ordering).
		if len(assetBackup.ProofFileBlob) > 0 {
			extractGroupKeys(
				assetBackup.ProofFileBlob,
				knownGroupKeys,
			)
		}

		// Verify we have a proof blob.
		if len(assetBackup.ProofFileBlob) == 0 {
			log.Warnf("Skipping asset %d (id=%x): "+
				"no proof blob available",
				i, assetID[:])
			numSkipped++
			continue
		}

		// Register keys BEFORE importing the proof so that
		// when ImportProofs stores the asset, it can find
		// the existing key records with full key locator
		// info. This is essential for the wallet to be able
		// to sign spends later. The key upserts are
		// idempotent (ON CONFLICT), so duplicate keys from
		// a re-import are harmless — including for assets
		// that fail pre-verify and enter the retry pass,
		// whose keys must already be registered when the
		// retry succeeds.
		//
		// Key registration errors are fatal since they
		// indicate DB/infrastructure problems.

		// Register the anchor internal key so LND can sign
		// for the anchor output when spending.
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
				return numImported, numSkipped,
					fmt.Errorf("failed to insert "+
						"anchor internal key "+
						"for asset %d: %w",
						i, err)
			}
		}

		// Register the script key so the wallet can
		// identify the asset as locally owned and sign
		// virtual transactions.
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
				return numImported, numSkipped,
					fmt.Errorf("failed to insert "+
						"script key for asset "+
						"%d: %w", i, err)
			}
		}

		// Pre-verify the proof with a context that skips
		// infrastructure-dependent checks (chain backend,
		// ignore checker, timelock validation). This catches
		// per-asset data issues (bad proof, unknown group
		// key) which are skippable. The full import step
		// below re-verifies with the real chain backend;
		// failures there are fatal.
		_, err = verifier.Verify(
			ctx,
			bytes.NewReader(assetBackup.ProofFileBlob),
			preVerifyCtx,
			proof.WithSkipTimeLockValidationForAllProofs(),
		)
		if err != nil {
			// Track ErrGroupKeyUnknown failures for the
			// retry pass.
			if errors.Is(err,
				proof.ErrGroupKeyUnknown) {

				retryIndices = append(
					retryIndices, i,
				)
			}

			log.Warnf("Skipping asset %d (id=%x): "+
				"verification failed: %v",
				i, assetID[:], err)
			numSkipped++
			continue
		}

		// Import the verified proof into the archive. The
		// locator is derived from the same backup entry as
		// the proof blob, so the asset ID and script key
		// are guaranteed to be consistent. Errors here are
		// storage/infrastructure issues — fail fast.
		err = cfg.ProofArchive.ImportProofs(
			ctx, importVCtx, false,
			&proof.AnnotatedProof{
				Locator: locator,
				Blob:    assetBackup.ProofFileBlob,
			},
		)
		if err != nil {
			return numImported, numSkipped,
				fmt.Errorf("failed to import "+
					"proof for asset %d: %w",
					i, err)
		}

		log.Debugf("Successfully imported asset %d", i)
		numImported++
	}

	// Retry pass: re-attempt assets that failed specifically
	// with ErrGroupKeyUnknown. By now, the main loop has
	// processed all other assets and populated knownGroupKeys
	// from their proof blobs. This handles v3 optimistic backup
	// ordering where a grouped asset was processed before the
	// group anchor.
	if len(retryIndices) > 0 {
		log.Infof("Retrying %d asset(s) that failed with "+
			"group key unknown", len(retryIndices))
	}

	for _, idx := range retryIndices {
		ab := walletBackup.Assets[idx]
		if ab.Asset == nil ||
			ab.Asset.ScriptKey.PubKey == nil {

			log.Warnf("Skipping retry asset %d: nil "+
				"asset or script key", idx)
			continue
		}

		retryID := ab.Asset.ID()
		retryLocator := proof.Locator{
			AssetID:   &retryID,
			ScriptKey: *ab.Asset.ScriptKey.PubKey,
			OutPoint:  &ab.AnchorOutpoint,
		}

		// Pre-verify with the data-only context, same as
		// the main loop.
		_, err := verifier.Verify(
			ctx,
			bytes.NewReader(ab.ProofFileBlob),
			preVerifyCtx,
			proof.WithSkipTimeLockValidationForAllProofs(),
		)
		if err != nil {
			log.Warnf("Retry verification failed for "+
				"asset %d (id=%x): %v",
				idx, retryID[:], err)
			continue
		}

		// Import — storage errors are fatal.
		err = cfg.ProofArchive.ImportProofs(
			ctx, importVCtx, false,
			&proof.AnnotatedProof{
				Locator: retryLocator,
				Blob:    ab.ProofFileBlob,
			},
		)
		if err != nil {
			return numImported, numSkipped,
				fmt.Errorf("failed to import proof "+
					"for asset %d (retry): %w",
					idx, err)
		}

		log.Infof("Retry succeeded for asset %d (id=%x)",
			idx, retryID[:])
		numImported++
		numSkipped--
	}

	log.Infof("Imported %d assets from backup (%d skipped)",
		numImported, numSkipped)

	return numImported, numSkipped, nil
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

	// Limit concurrent goroutines to avoid excessive resource
	// usage for wallets with many assets.
	sem := make(chan struct{}, maxConcurrentSpendChecks)

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

		sem <- struct{}{}

		go func(idx int,
			sc chan *chainntnfs.SpendDetail,
			ec chan error) {

			defer func() { <-sem }()

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
				// Timeout means lnd did not report a
				// spend, so the outpoint is unspent.
				// A parent context cancellation is
				// propagated as an error.
				if detectCtx.Err() != nil {
					results <- spendResult{
						index: idx,
						err:   detectCtx.Err(),
					}
				} else {
					results <- spendResult{
						index: idx,
						spent: false,
					}
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
