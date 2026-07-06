package tapdb

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
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
// asset rows (witnesses, proofs, the assets themselves) are deleted,
// the chain transaction is unconfirmed, and the batch is moved to the
// sprout-cancelled state so it is neither resumed nor counted.
func (a *AssetStore) ApplyMintAbandonment(ctx context.Context,
	q *sqlc.Queries, genesisTxid chainhash.Hash,
	rawBatchKey []byte) error {

	assetIDs, err := q.AssetIDsByAnchorTxPrefix(ctx, genesisTxid[:])
	if err != nil {
		return fmt.Errorf("unable to find minted assets: %w", err)
	}

	for _, assetID := range assetIDs {
		if err := q.DeleteAssetWitnesses(ctx, assetID); err != nil {
			return fmt.Errorf("unable to delete witnesses: %w",
				err)
		}
		if err := q.DeleteAssetProofByAssetID(ctx, assetID); err != nil {
			return fmt.Errorf("unable to delete proof: %w", err)
		}
		if err := q.DeleteAssetByID(ctx, assetID); err != nil {
			return fmt.Errorf("unable to delete asset: %w", err)
		}
	}

	if err := q.UnconfirmChainAnchorTx(ctx, genesisTxid[:]); err != nil {
		return fmt.Errorf("unable to unconfirm genesis tx: %w", err)
	}

	err = q.UpdateMintingBatchState(ctx, BatchStateUpdate{
		RawKey: rawBatchKey,
		BatchState: int16(
			tapgarden.BatchStateSproutCancelled,
		),
	})
	if err != nil {
		return fmt.Errorf("unable to cancel batch: %w", err)
	}

	return nil
}

// A compile-time assertion that the asset store provides the mint
// site's persistence surface.
var _ tapgarden.MintAnchoringLog = (*AssetStore)(nil)
