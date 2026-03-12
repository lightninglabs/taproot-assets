package backup

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/lightninglabs/taproot-assets/proof"
)

// noopTransferLog is a no-op implementation of proof.TransferLog used when
// fetching proofs from a universe server during backup import. No delivery
// tracking is needed in this context.
type noopTransferLog struct{}

func (n *noopTransferLog) LogProofTransferAttempt(context.Context,
	proof.Locator, proof.TransferType) error {

	return nil
}

func (n *noopTransferLog) QueryProofTransferLog(context.Context,
	proof.Locator, proof.TransferType) ([]time.Time, error) {

	return nil, nil
}

// fetchProofFromUniverse tries each federation URL in order to fetch a
// complete proof file for the given asset backup. It constructs a
// proof.Locator from the backup's fields, creates a universe RPC courier,
// and calls ReceiveProof which internally uses FetchProofProvenance to walk
// the full proof chain from tip back to genesis.
func fetchProofFromUniverse(ctx context.Context,
	fedURLs []string, ab *AssetBackup,
	archive proof.Archiver) ([]byte, error) {

	assetID := ab.Asset.ID()
	locator := proof.Locator{
		AssetID:   &assetID,
		ScriptKey: *ab.Asset.ScriptKey.PubKey,
		OutPoint:  &ab.AnchorOutpoint,
	}

	// If the asset has a group key, include it in the locator so the
	// courier queries the correct universe.
	if ab.Asset.GroupKey != nil {
		locator.GroupKey = &ab.Asset.GroupKey.GroupPubKey
	}

	var lastErr error
	for _, rawURL := range fedURLs {
		addr, err := url.Parse("universerpc://" + rawURL)
		if err != nil {
			log.Warnf("Skipping invalid federation URL "+
				"%q: %v", rawURL, err)
			continue
		}

		courierCfg := &proof.UniverseRpcCourierCfg{
			BackoffCfg: &proof.BackoffCfg{
				BackoffResetWait: time.Second,
				NumTries:         1,
				InitialBackoff:   time.Second,
				MaxBackoff:       time.Second,
			},
			ServiceRequestTimeout: 30 * time.Second,
		}

		courier, err := proof.NewUniverseRpcCourier(
			ctx, courierCfg, &noopTransferLog{},
			archive, addr, false,
		)
		if err != nil {
			log.Warnf("Failed to connect to universe "+
				"%s: %v", rawURL, err)
			lastErr = err
			continue
		}

		annotated, err := courier.ReceiveProof(
			ctx, proof.Recipient{}, locator,
		)

		closeErr := courier.Close()
		if closeErr != nil {
			log.Warnf("Failed to close courier for %s: %v",
				rawURL, closeErr)
		}

		if err != nil {
			log.Warnf("Failed to fetch proof from "+
				"universe %s: %v", rawURL, err)
			lastErr = err
			continue
		}

		log.Infof("Fetched proof from universe %s for "+
			"asset %x", rawURL, assetID[:])

		return annotated.Blob, nil
	}

	if lastErr == nil {
		return nil, fmt.Errorf("failed to fetch proof from " +
			"any universe server: all URLs were invalid")
	}

	return nil, fmt.Errorf("failed to fetch proof from any universe "+
		"server: %w", lastErr)
}
