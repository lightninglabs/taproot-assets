package tapdb

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapgarden"
)

// This file houses the transaction-scoped body of the minting side's
// compensation, run inside the re-org watcher's delivery transaction
// by the cultivator's site handler. Mint (re)confirmation and the
// potency-tier unconfirm reuse the receive-side bodies verbatim: a
// minted asset's speculative state has exactly the same shape as a
// received one's — asset rows anchored in outputs of the transaction,
// with single-suffix proof files whose tip attests it — plus the
// batch row, whose chain linkage lives in the same chain_txns row the
// shared bodies already maintain.

// ApplyMintAbandonment compensates an abandoned minting batch: the
// chain decided against the genesis transaction with act-level
// finality (its funding inputs were claimed by a buried conflicting
// transaction), so the batch's assets never came to be. The minted
// asset rows (any successor's passive references to them, witnesses,
// proofs, the assets themselves) are deleted, the chain transaction
// is unconfirmed, and the batch is moved to the sprout-cancelled
// state so it is neither resumed nor counted. Returns the locators
// of the proofs it deleted.
func (a *AssetStore) ApplyMintAbandonment(ctx context.Context,
	q *sqlc.Queries, genesisTxid chainhash.Hash,
	rawBatchKey []byte) ([]proof.Locator, error) {

	rows, err := q.AnchoredAssetsByAnchorTxPrefix(ctx, genesisTxid[:])
	if err != nil {
		return nil, fmt.Errorf("unable to find minted assets: %w", err)
	}

	deleted := make([]proof.Locator, 0, len(rows))
	for _, row := range rows {
		loc, err := anchoredAssetLocator(row)
		if err != nil {
			return nil, err
		}

		// A successor transfer may already have staked this row as
		// a passive holding: passive references are written before
		// broadcast, so one can exist against an asset this
		// transaction materialized. That reference must go before
		// the row it points at (passive_assets.asset_id is NOT
		// NULL with no ON DELETE), and with the same finality —
		// the successor re-anchors a holding that, on the
		// surviving chain, was never created.
		_, err = q.DeletePassiveAssetsByAssetID(ctx, row.AssetID)
		if err != nil {
			return nil, fmt.Errorf("unable to delete passive "+
				"asset references: %w", err)
		}

		err = q.DeleteAssetWitnesses(ctx, row.AssetID)
		if err != nil {
			return nil, fmt.Errorf("unable to delete "+
				"witnesses: %w", err)
		}
		err = q.DeleteAssetProofByAssetID(ctx, row.AssetID)
		if err != nil {
			return nil, fmt.Errorf("unable to delete proof: %w",
				err)
		}
		if err := q.DeleteAssetByID(ctx, row.AssetID); err != nil {
			return nil, fmt.Errorf("unable to delete asset: %w",
				err)
		}

		deleted = append(deleted, loc)
	}

	if err := q.UnconfirmChainAnchorTx(ctx, genesisTxid[:]); err != nil {
		return nil, fmt.Errorf("unable to unconfirm genesis tx: %w",
			err)
	}

	err = q.UpdateMintingBatchState(ctx, BatchStateUpdate{
		RawKey: rawBatchKey,
		BatchState: int16(
			tapgarden.BatchStateSproutCancelled,
		),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to cancel batch: %w", err)
	}

	return deleted, nil
}

// A compile-time assertion that the asset store provides the mint
// site's persistence surface.
var _ tapgarden.MintAnchoringLog = (*AssetStore)(nil)
