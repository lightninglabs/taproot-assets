package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapcustody"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
)

// This file houses the transaction-scoped bodies of the receive
// side's persistence operations, run inside the re-org watcher's
// delivery transactions by the custodian's site handlers. The
// receiver's speculative state is what a received proof's import
// materialized: asset rows anchored in the sender's transaction,
// the address events completed against it, and the stored proof
// files themselves.

// ApplyReceiveReconfirm converges received state to a (re)confirmed
// anchor: the chain transaction's recorded confirmation refreshes,
// and every anchored asset's stored proof file has its tip proof
// re-stamped with the witness's block context. Convergent — safe for
// re-delivered signals and same-transaction re-confirmations in new
// blocks alike.
func (a *AssetStore) ApplyReceiveReconfirm(ctx context.Context,
	q *sqlc.Queries, anchorTxid chainhash.Hash,
	blockHash chainhash.Hash, blockHeight, txIndex uint32,
	header wire.BlockHeader, merkle proof.TxMerkleProof) error {

	err := q.ConfirmChainAnchorTx(ctx, AnchorTxConf{
		Txid:        anchorTxid[:],
		BlockHash:   blockHash[:],
		BlockHeight: sqlInt32(blockHeight),
		TxIndex:     sqlInt32(txIndex),
	})
	if err != nil {
		return fmt.Errorf("unable to confirm anchor tx: %w", err)
	}

	assetIDs, err := q.AssetIDsByAnchorTxPrefix(ctx, anchorTxid[:])
	if err != nil {
		return fmt.Errorf("unable to find anchored assets: %w", err)
	}

	for _, assetID := range assetIDs {
		blob, err := q.AssetProofBlobByAssetID(ctx, assetID)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// The asset's proof file is not yet materialized.
			// On the minting path the first witness delivery
			// precedes the cultivator's confirmation branch —
			// which this delivery itself unblocks, and which
			// writes the proof with this same block context.
			// Converge what exists; skip what doesn't.
			continue

		case err != nil:
			return fmt.Errorf("unable to fetch proof for "+
				"asset %d: %w", assetID, err)
		}

		file := &proof.File{}
		if err := file.Decode(bytes.NewReader(blob)); err != nil {
			return fmt.Errorf("unable to decode proof file: %w",
				err)
		}

		numProofs := file.NumProofs()
		if numProofs == 0 {
			continue
		}
		tip, err := file.ProofAt(uint32(numProofs - 1))
		if err != nil {
			return fmt.Errorf("unable to read tip proof: %w", err)
		}
		if tip.AnchorTx.TxHash() != anchorTxid {
			continue
		}

		tip.BlockHeader = header
		tip.BlockHeight = blockHeight
		tip.TxMerkleProof = merkle
		if err := file.ReplaceLastProof(*tip); err != nil {
			return fmt.Errorf("unable to replace tip proof: %w",
				err)
		}

		var buf bytes.Buffer
		if err := file.Encode(&buf); err != nil {
			return fmt.Errorf("unable to encode proof file: %w",
				err)
		}

		err = q.UpsertAssetProofByID(ctx, ProofUpdateByID{
			AssetID:   assetID,
			ProofFile: buf.Bytes(),
		})
		if err != nil {
			return fmt.Errorf("unable to store patched proof: "+
				"%w", err)
		}
	}

	return nil
}

// ApplyReceiveUnconfirm withdraws the anchor transaction's recorded
// confirmation: the potency-tier soft downgrade for a lost witness or
// an on-chain conflict. Nothing else is reversed.
func (a *AssetStore) ApplyReceiveUnconfirm(ctx context.Context,
	q *sqlc.Queries, anchorTxid chainhash.Hash) error {

	return q.UnconfirmChainAnchorTx(ctx, anchorTxid[:])
}

// ApplyReceiveAbandonment compensates an abandoned receive: the chain
// decided against the sender's anchor transaction with act-level
// finality, so the received assets never materialized on the
// surviving chain. The anchored asset rows (witnesses, proofs, the
// assets themselves) are deleted, the address events shed their
// completion and return to the given status, and the chain
// transaction is unconfirmed. If the logical send is re-attempted in
// a new form, the sender's courier delivers fresh proofs, which
// arrive as a fresh receive with its own anchoring.
//
// The reset status is the caller's choice; note that the events'
// recorded outpoints reference a transaction the chain has discarded,
// so they will not progress again on their own — they document the
// failed receive until a replacement arrives.
func (a *AssetStore) ApplyReceiveAbandonment(ctx context.Context,
	q *sqlc.Queries, anchorTxid chainhash.Hash,
	resetStatus int16) error {

	assetIDs, err := q.AssetIDsByAnchorTxPrefix(ctx, anchorTxid[:])
	if err != nil {
		return fmt.Errorf("unable to find anchored assets: %w", err)
	}

	// The address events must shed their asset/proof references
	// before those rows can be deleted: the status returns to the
	// given pre-completion value, and the materialized custody
	// references (addr_event_proofs) are removed outright.
	numReset, err := q.ResetAddrEventsByAnchorTx(
		ctx, sqlc.ResetAddrEventsByAnchorTxParams{
			NewStatus: resetStatus,
			Txid:      anchorTxid[:],
		},
	)
	if err != nil {
		return fmt.Errorf("unable to reset address events: %w", err)
	}
	if numReset > 0 {
		log.Infof("Reset %d address event(s) for abandoned anchor "+
			"tx %v", numReset, anchorTxid)
	}

	_, err = q.DeleteAddrEventProofsByAnchorTx(ctx, anchorTxid[:])
	if err != nil {
		return fmt.Errorf("unable to delete address event proof "+
			"references: %w", err)
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

	if err := q.UnconfirmChainAnchorTx(ctx, anchorTxid[:]); err != nil {
		return fmt.Errorf("unable to unconfirm anchor tx: %w", err)
	}

	return nil
}

// A compile-time assertion that the asset store provides the receive
// site's persistence surface.
var _ tapcustody.ReceiveAnchoringLog = (*AssetStore)(nil)

// hasReceivedProof reports whether the database holds a proof for
// exactly the asset the locator names. A script key alone is not an
// identity here — the leaves of a grouped receive share one — so the
// locator must carry the asset ID and the outpoint as well, and
// presence is judged on all three, as the proof fetch does.
func hasReceivedProof(ctx context.Context, q ActiveAssetsStore,
	locator proof.Locator) (bool, error) {

	if locator.AssetID == nil || locator.OutPoint == nil {
		return false, fmt.Errorf("received proof locator must name " +
			"the asset and the outpoint")
	}

	args, err := locatorToProofQuery(locator)
	if err != nil {
		return false, err
	}

	rows, err := q.FetchAssetProof(ctx, args)
	if err != nil {
		return false, fmt.Errorf("unable to look up asset proof: %w",
			err)
	}

	return len(rows) > 0, nil
}

// HasReceivedProof reports whether the database holds a proof for
// exactly the asset the locator names: asset ID, script key and
// outpoint together. The database is the authority on what a receive
// holds; the proof-file mirror trails it.
func (a *AssetStore) HasReceivedProof(ctx context.Context,
	locator proof.Locator) (bool, error) {

	var have bool
	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		var err error
		have, err = hasReceivedProof(ctx, q, locator)

		return err
	})
	if dbErr != nil {
		return false, dbErr
	}

	return have, nil
}

// StakeReceivedProofs imports verified received proofs on the
// registration transaction, skipping any the database already holds
// (judged on the whole locator: asset ID, script key and outpoint),
// and returns the blobs it imported. Running on the registry's
// transaction is what makes a received stake and the custody that
// covers it commit together: a registration the registry refuses
// rolls the import back with it, and a re-driven registration finds
// the earlier import and stakes nothing twice.
func (a *AssetStore) StakeReceivedProofs(ctx context.Context,
	tx tapreorg.RegistryTx,
	proofs ...proof.VerifiedAnnotatedProof) ([]proof.Blob, error) {

	q := tx.Queries()

	var imported []proof.Blob
	for _, verified := range proofs {
		p := verified.AnnotatedProof()

		have, err := hasReceivedProof(ctx, q, p.Locator)
		if err != nil {
			return nil, err
		}
		if have {
			continue
		}

		if err := a.importAssetFromProof(ctx, q, p); err != nil {
			return nil, fmt.Errorf("unable to import asset: %w",
				err)
		}
		imported = append(imported, p.Blob)
	}

	return imported, nil
}
