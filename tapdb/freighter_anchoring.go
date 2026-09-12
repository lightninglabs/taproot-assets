package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
)

// This file houses the transaction-scoped bodies of the chain
// porter's persistence operations, callable inside a caller-owned
// transaction — specifically the re-org watcher's, whose registry
// advances run site handlers atomically. The Log* wrappers in
// assets_store.go run the same bodies inside transactions of their
// own.
//
// The confirmation body is convergent: it can be re-run for the same
// confirmation (a re-delivered signal) or for a re-organized
// confirmation of the same anchor transaction (a new block), from
// whatever partial state a previous run left, and lands on the same
// final state.

// ApplyPendingParcel writes the pending (pre-broadcast) state of an
// outbound parcel using the given transaction-scoped query set. This
// is the porter site's phase-1 write: it commits atomically with the
// anchoring registration itself.
func (a *AssetStore) ApplyPendingParcel(ctx context.Context,
	q *sqlc.Queries, spend *tapfreighter.OutboundParcel,
	finalLeaseOwner [32]byte, finalLeaseExpiry time.Time) error {

	return a.applyPendingParcel(
		ctx, q, spend, finalLeaseOwner, finalLeaseExpiry,
	)
}

// applyPendingParcel is the extracted body of LogPendingParcel.
func (a *AssetStore) applyPendingParcel(ctx context.Context,
	q ActiveAssetsStore, spend *tapfreighter.OutboundParcel,
	finalLeaseOwner [32]byte, finalLeaseExpiry time.Time) error {

	newAnchorTXID := spend.AnchorTx.TxHash()
	anchorTxBytes, err := fn.Serialize(spend.AnchorTx)
	if err != nil {
		return err
	}

	// First, we'll insert the new transaction that anchors the new
	// anchor point (commits to the set of new outputs).
	txnID, err := q.UpsertChainTx(ctx, ChainTxParams{
		Txid:      newAnchorTXID[:],
		RawTx:     anchorTxBytes,
		ChainFees: spend.ChainFees,
	})
	if err != nil {
		return fmt.Errorf("unable to insert new chain tx: %w", err)
	}

	// The transfer itself is just a shell which the inputs and
	// outputs will reference. We'll insert this next, so we can use
	// its ID.
	transferID, err := q.InsertAssetTransfer(ctx, NewAssetTransfer{
		HeightHint:            int32(spend.AnchorTxHeightHint),
		AnchorTxid:            newAnchorTXID[:],
		TransferTimeUnix:      spend.TransferTime,
		Label:                 sqlStr(spend.Label),
		SkipAnchorTxBroadcast: spend.SkipAnchorTxBroadcast,
	})
	if err != nil {
		return fmt.Errorf("unable to insert asset transfer: %w", err)
	}

	// Next, we'll insert the inputs to this transfer.
	for idx := range spend.Inputs {
		err := insertAssetTransferInput(
			ctx, q, transferID, spend.Inputs[idx],
			finalLeaseOwner, finalLeaseExpiry,
		)
		if err != nil {
			return fmt.Errorf("unable to insert asset transfer "+
				"input: %w", err)
		}
	}

	// Also extend leases for any zero-value UTXOs being swept.
	for _, zeroValueInput := range spend.ZeroValueInputs {
		outpointBytes, err := encodeOutpoint(zeroValueInput.OutPoint)
		if err != nil {
			return fmt.Errorf("unable to encode zero-value "+
				"outpoint: %w", err)
		}

		err = q.UpdateUTXOLease(ctx, UpdateUTXOLease{
			LeaseOwner:  finalLeaseOwner[:],
			LeaseExpiry: sqlTime(finalLeaseExpiry.UTC()),
			Outpoint:    outpointBytes,
		})
		if err != nil {
			return fmt.Errorf("unable to extend zero-value "+
				"UTXO lease: %w", err)
		}
	}

	// Then the passive assets.
	if len(spend.PassiveAssets) > 0 {
		if spend.PassiveAssetsAnchor == nil {
			return fmt.Errorf("passive assets anchor is required")
		}

		err = insertPassiveAssets(
			ctx, q, transferID, txnID, spend.PassiveAssetsAnchor,
			spend.PassiveAssets,
		)
		if err != nil {
			return fmt.Errorf("unable to insert passive "+
				"assets: %w", err)
		}
	}

	// And then finally the outputs.
	for idx := range spend.Outputs {
		err = insertAssetTransferOutput(
			ctx, q, transferID, txnID, spend.Outputs[idx],
		)
		if err != nil {
			return fmt.Errorf("unable to insert asset transfer "+
				"output: %w", err)
		}
	}

	return nil
}

// ApplyAnchorTxConfirm applies a transfer confirmation using the
// given transaction-scoped query set: inputs spent, conflicting
// transfers superseded, outputs materialized, passives re-anchored,
// the chain transaction confirmed, zero-value inputs swept, and burn
// rows recorded. It returns the identifiers of the local outputs
// whose proofs were stored, for post-commit notification.
//
// The body is convergent: re-running it — after a re-delivered
// signal, or for a re-organized confirmation of the same anchor
// transaction carrying refreshed proofs — converges on the same
// state rather than duplicating rows.
func (a *AssetStore) ApplyAnchorTxConfirm(ctx context.Context,
	q *sqlc.Queries, conf *tapfreighter.AssetConfirmEvent,
	burns []*tapfreighter.AssetBurn) ([]tapfreighter.OutputIdentifier,
	error) {

	return a.applyAnchorTxConfirm(ctx, q, conf, burns)
}

// applyAnchorTxConfirm is the extracted, convergent body of
// LogAnchorTxConfirm.
func (a *AssetStore) applyAnchorTxConfirm(ctx context.Context,
	q ActiveAssetsStore, conf *tapfreighter.AssetConfirmEvent,
	burns []*tapfreighter.AssetBurn) ([]tapfreighter.OutputIdentifier,
	error) {

	var localProofKeys []tapfreighter.OutputIdentifier

	// First, we'll fetch the asset transfer based on its outpoint
	// bytes, so we can apply the delta it describes.
	assetTransfers, err := q.QueryAssetTransfers(ctx, TransferQuery{
		AnchorTxHash: conf.AnchorTXID[:],
	})
	if err != nil {
		return nil, fmt.Errorf("unable to query asset transfers: %w",
			err)
	}
	assetTransfer := assetTransfers[0]

	// Next, we'll mark all input assets as spent. But we need to
	// fetch the inputs first to do that.
	inputs, err := q.FetchTransferInputs(ctx, assetTransfer.ID)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch transfer inputs: %w",
			err)
	}

	// We'll keep around the IDs of the assets that we set to being
	// spent. We'll need one of them as our template to create the
	// new assets from. We only require one per asset ID, to make
	// sure the group key and asset genesis references are correct.
	// But if we spend multiple inputs from the same asset ID, it
	// doesn't matter if they collide here, as we just need any of
	// them as the copy template.
	copyTemplateIDs := make(map[asset.ID]int64, len(inputs))
	for idx := range inputs {
		var assetID asset.ID
		copy(assetID[:], inputs[idx].AssetID)
		copyTemplateIDs[assetID], err = q.SetAssetSpent(
			ctx, SetAssetSpentParams{
				ScriptKey:   inputs[idx].ScriptKey,
				GenAssetID:  inputs[idx].AssetID,
				AnchorPoint: inputs[idx].AnchorPoint,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("unable to set asset "+
				"spent: %w, script_key=%x", err,
				inputs[idx].ScriptKey)
		}
	}

	// Any other unconfirmed transfer that claims one of the inputs
	// just spent can never confirm now: its anchor transaction
	// conflicts with the one that confirmed (e.g. a fee-bumped
	// replacement of a sweep transaction). Mark such transfers as
	// superseded so they're no longer treated as pending and
	// aren't resumed at startup.
	for idx := range inputs {
		anchorPoint := inputs[idx].AnchorPoint
		numMarked, err := q.SupersedeConflictingTransfers(
			ctx, sqlc.SupersedeConflictingTransfersParams{
				ConfirmedTransferID: assetTransfer.ID,
				AnchorPoint:         anchorPoint,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("unable to mark conflicting "+
				"transfers as superseded: %w", err)
		}

		if numMarked > 0 {
			log.Infof("Marked %d conflicting transfer(s) as "+
				"superseded by transfer_id=%d "+
				"(anchor_txid=%v)", numMarked,
				assetTransfer.ID, conf.AnchorTXID)
		}
	}

	// This transfer may itself carry the superseded flag, as the
	// loser of an earlier race whose winner the chain has since
	// discarded. Its confirmation is the chain deciding for it:
	// lift the flag, or the transfer is skipped at startup and
	// never completes.
	err = q.UnsupersedeTransfer(ctx, assetTransfer.ID)
	if err != nil {
		return nil, fmt.Errorf("unable to lift superseded flag: %w",
			err)
	}

	// Now is the time to fetch our outputs and create new assets
	// for them.
	outputs, err := q.FetchTransferOutputs(ctx, assetTransfer.ID)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch transfer "+
			"outputs: %w", err)
	}
	for idx := range outputs {
		out := outputs[idx]

		// Decode the witness first, so we can find out if this
		// is a burn or not.
		var witnessData []asset.Witness
		err = asset.WitnessDecoder(
			bytes.NewReader(out.SerializedWitnesses),
			&witnessData, &[8]byte{},
			uint64(len(out.SerializedWitnesses)),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode "+
				"witness: %w", err)
		}

		fullScriptKey, err := parseScriptKey(
			out.InternalKey, out.ScriptKey,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode script "+
				"key: %w", err)
		}

		// If this is an outbound transfer (meaning that our
		// node doesn't control the script key, and it isn't a
		// burn), we don't create an asset entry in the DB. The
		// transfer will be the only reference to the asset
		// leaving the node. The same goes for outputs that are
		// only used to anchor passive assets, which are handled
		// separately.
		skipAssetCreation, markSpent := shouldSkipAssetCreation(
			out, fullScriptKey, witnessData,
		)
		if skipAssetCreation {
			continue
		}

		// If we create the asset, we'll also import the proof.
		// We need to find out the asset ID this output is for,
		// since a transfer can host multiple virtual
		// transactions, with potentially different asset IDs.
		var (
			outProofAsset  asset.Asset
			inclusionProof proof.TaprootProof
		)
		err = proof.SparseDecode(
			bytes.NewReader(out.ProofSuffix),
			proof.AssetLeafRecord(&outProofAsset),
			proof.InclusionProofRecord(&inclusionProof),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to sparse decode "+
				"proof: %w", err)
		}

		// The convergence guard: an earlier run of this body may
		// already have materialized this output. If so, the
		// asset row stands; only its proof is refreshed below.
		outAssetID := outProofAsset.ID()
		newAssetID, err := q.TransferOutputAssetID(
			ctx, sqlc.TransferOutputAssetIDParams{
				ScriptKeyID:  out.ScriptKey.ScriptKeyID,
				AnchorUtxoID: sqlInt64(out.AnchorUtxoID),
				AssetID:      outAssetID[:],
			},
		)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// We can take any of the inputs for a certain
			// asset ID as a template for the new asset, since
			// the genesis and group key will be the same.
			// We'll overwrite all other fields.
			templateID, ok := copyTemplateIDs[outProofAsset.ID()]
			if !ok {
				return nil, fmt.Errorf("no spent asset "+
					"found for output with asset ID %v",
					outProofAsset.ID())
			}

			//nolint:lll
			params := ApplyPendingOutput{
				ScriptKeyID:              out.ScriptKey.ScriptKeyID,
				AnchorUtxoID:             sqlInt64(out.AnchorUtxoID),
				Amount:                   out.Amount,
				LockTime:                 out.LockTime,
				RelativeLockTime:         out.RelativeLockTime,
				SplitCommitmentRootHash:  out.SplitCommitmentRootHash,
				SplitCommitmentRootValue: out.SplitCommitmentRootValue,
				SpentAssetID:             templateID,
				Spent:                    markSpent,
				AssetVersion:             out.AssetVersion,
			}
			newAssetID, err = q.ApplyPendingOutput(ctx, params)
			if err != nil {
				return nil, fmt.Errorf("unable to apply "+
					"pending output: %w", err)
			}

			// With the old witnesses removed, we'll insert the
			// new set on disk.
			err = a.insertAssetWitnesses(
				ctx, q, newAssetID, witnessData,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to insert "+
					"asset witnesses: %w", err)
			}

		case err != nil:
			return nil, fmt.Errorf("unable to check for "+
				"materialized output: %w", err)
		}

		scriptPubKey := fullScriptKey.PubKey
		outKey := tapfreighter.NewOutputIdentifier(
			outProofAsset.ID(), inclusionProof.OutputIndex,
			*scriptPubKey,
		)

		receiverProof, ok := conf.FinalProofs[outKey]
		if !ok {
			return nil, fmt.Errorf("no proof found for output "+
				"with script key %x",
				scriptPubKey.SerializeCompressed())
		}
		localProofKeys = append(localProofKeys, outKey)

		// Upload proof by the dbAssetId, which is the _primary
		// key_ of the asset in table assets, not the BIPS
		// concept of `asset_id`.
		err = q.UpsertAssetProofByID(ctx, ProofUpdateByID{
			AssetID:   newAssetID,
			ProofFile: receiverProof.Blob,
		})
		if err != nil {
			return nil, err
		}
	}

	// Before we confirm the anchor TX, let's re-anchor the passive
	// assets to that new UTXO.
	err = a.reAnchorPassiveAssets(
		ctx, q, assetTransfer.ID, conf.PassiveAssetProofFiles,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to re-anchor passive "+
			"assets: %w", err)
	}

	// To confirm a delivery (successful send) all we need to do is
	// update the chain information for the transaction that anchors
	// the new anchor point.
	err = q.ConfirmChainAnchorTx(ctx, AnchorTxConf{
		Txid:        conf.AnchorTXID[:],
		BlockHash:   conf.BlockHash[:],
		BlockHeight: sqlInt32(conf.BlockHeight),
		TxIndex:     sqlInt32(conf.TxIndex),
	})
	if err != nil {
		return nil, err
	}

	// Mark all zero-value UTXOs as swept since they were spent as
	// additional inputs to the Bitcoin transaction.
	for _, zeroValueInput := range conf.ZeroValueInputs {
		outpointBytes, err := encodeOutpoint(zeroValueInput.OutPoint)
		if err != nil {
			return nil, fmt.Errorf("failed to encode "+
				"zero-value outpoint: %w", err)
		}

		err = q.MarkManagedUTXOAsSwept(
			ctx, MarkManagedUTXOAsSweptParams{
				Outpoint:     outpointBytes,
				SweepingTxid: conf.AnchorTXID[:],
			},
		)
		if err != nil {
			return nil, fmt.Errorf("unable to mark zero-value "+
				"UTXO as swept: %w", err)
		}
	}

	// Burn rows converge by replacement: delete whatever a previous
	// run recorded, then insert the current set.
	err = q.DeleteBurnsByTransferID(ctx, assetTransfer.ID)
	if err != nil {
		return nil, fmt.Errorf("unable to clear burns: %w", err)
	}
	for _, b := range burns {
		_, err = q.InsertBurn(ctx, sqlc.InsertBurnParams{
			TransferID: assetTransfer.ID,
			Note:       sqlStr(b.Note),
			AssetID:    b.AssetID,
			GroupKey:   b.GroupKey,
			Amount:     int64(b.Amount),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to insert burn in "+
				"db: %v", err)
		}
	}

	return localProofKeys, nil
}

// ApplyAnchorTxUnconfirm withdraws the recorded confirmation of the
// transfer's anchor transaction: the soft, potency-tier downgrade for
// a witness lost with no successor. Nothing else is reversed — the
// materialized state stands until the chain decides against the
// transfer with act-level finality — except that the transfer
// re-enters supersession if a confirmed rival claims one of its
// inputs, so it is not resumed as pending.
func (a *AssetStore) ApplyAnchorTxUnconfirm(ctx context.Context,
	q *sqlc.Queries, anchorTxid chainhash.Hash) error {

	if err := q.UnconfirmChainAnchorTx(ctx, anchorTxid[:]); err != nil {
		return fmt.Errorf("unable to unconfirm anchor tx: %w", err)
	}

	// An unconfirmed transfer is a pending one, resumed at startup
	// — unless a confirmed rival claims one of its inputs, in which
	// case it is a rivalry loser whose anchor can never confirm.
	// The rival's confirmation could not have superseded this
	// transfer, which was confirmed at the time, so supersession is
	// entered here instead; a later re-confirmation lifts it again.
	err := q.SupersedeIfConflictingConfirmed(ctx, anchorTxid[:])
	if err != nil {
		return fmt.Errorf("unable to supersede transfer under a "+
			"confirmed rival: %w", err)
	}

	return nil
}

// ApplyTransferAbandonment compensates an abandoned transfer: the
// chain decided against its anchor transaction with act-level
// finality, so everything staked on it is reversed. Inputs are
// un-spent, conflicting transfers un-superseded where safe,
// materialized outputs deleted, passive assets restored to their
// pre-transfer state (by truncating the proof suffix the transfer
// appended), the chain transaction unconfirmed, sweeps cleared,
// burns deleted, and the transfer itself marked superseded so it is
// never resumed.
//
// foreclosure, when non-nil, is the transaction the chain decided
// for: the buried foreign spend that abandoned this transfer (or the
// witness whose burial foreclosed a depended-upon parent). Its input
// set bounds the reversal — an outpoint that transaction consumed is
// gone from the node's control, not restorable. Un-spending such an
// input would fabricate balance the chain assigned to someone else
// (routine for tapchannel anchorings, whose trigger outpoints a
// counterparty can spend via HTLC paths), and a rival transfer
// needing it could never confirm. A nil foreclosure reverses
// everything not claimed by a surviving local transfer, which is the
// only information available without a cause.
//
// The body is convergent: it reverses whatever a (possibly partial
// or absent) confirmation application left, and re-running it is
// harmless.
func (a *AssetStore) ApplyTransferAbandonment(ctx context.Context,
	q *sqlc.Queries, anchorTxid chainhash.Hash,
	foreclosure *wire.MsgTx) ([]proof.Locator, error) {

	assetTransfers, err := q.QueryAssetTransfers(ctx, TransferQuery{
		AnchorTxHash: anchorTxid[:],
	})
	if err != nil {
		return nil, fmt.Errorf("unable to query asset transfers: %w",
			err)
	}
	if len(assetTransfers) == 0 {
		return nil, nil
	}
	assetTransfer := assetTransfers[0]

	foreclosedPoints := make(map[wire.OutPoint]struct{})
	if foreclosure != nil {
		for _, txIn := range foreclosure.TxIn {
			foreclosedPoints[txIn.PreviousOutPoint] = struct{}{}
		}
	}

	// Delete whatever outputs a confirmation application
	// materialized, reporting their proof locators so the file
	// mirror can shed the same proofs once this transaction commits.
	outputs, err := q.FetchTransferOutputs(ctx, assetTransfer.ID)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch transfer outputs: "+
			"%w", err)
	}
	var deleted []proof.Locator
	for idx := range outputs {
		out := outputs[idx]
		if len(out.ProofSuffix) == 0 {
			continue
		}

		// The suffix identifies which asset this output row
		// materialized: outputs of distinct assets can share
		// both script key and anchor UTXO.
		var outProofAsset asset.Asset
		err = proof.SparseDecode(
			bytes.NewReader(out.ProofSuffix),
			proof.AssetLeafRecord(&outProofAsset),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to sparse decode "+
				"proof: %w", err)
		}
		outAssetID := outProofAsset.ID()

		assetID, err := q.TransferOutputAssetID(
			ctx, sqlc.TransferOutputAssetIDParams{
				ScriptKeyID:  out.ScriptKey.ScriptKeyID,
				AnchorUtxoID: sqlInt64(out.AnchorUtxoID),
				AssetID:      outAssetID[:],
			},
		)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			continue

		case err != nil:
			return nil, fmt.Errorf("unable to look up "+
				"materialized output: %w", err)
		}

		scriptKey, err := btcec.ParsePubKey(
			out.ScriptKey.TweakedScriptKey,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to parse output "+
				"script key: %w", err)
		}
		var anchorPoint wire.OutPoint
		err = readOutPoint(
			bytes.NewReader(out.AnchorOutpoint), 0, 0,
			&anchorPoint,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode output "+
				"anchor point: %w", err)
		}
		deleted = append(deleted, proof.Locator{
			AssetID:   &outAssetID,
			ScriptKey: *scriptKey,
			OutPoint:  &anchorPoint,
		})

		// A self-send stakes this row from the receive side too,
		// which holds a custody reference to it. The reference
		// must go before the row it points at; the address event
		// itself is the receive compensation's to reset.
		_, err = q.DeleteAddrEventProofsByAssetID(
			ctx, sqlInt64(assetID),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to delete address "+
				"event proof references: %w", err)
		}

		// A successor transfer may already have staked this row as
		// a passive holding: passive references are written before
		// broadcast, so one can exist against an output this
		// transfer materialized while it was still confirmed. That
		// reference must go too, for the same reason as the custody
		// one above and with the same finality — the successor
		// re-anchors a holding that, on the surviving chain, was
		// never created.
		_, err = q.DeletePassiveAssetsByAssetID(ctx, assetID)
		if err != nil {
			return nil, fmt.Errorf("unable to delete passive "+
				"asset references: %w", err)
		}

		if err := q.DeleteAssetWitnesses(ctx, assetID); err != nil {
			return nil, fmt.Errorf("unable to delete asset "+
				"witnesses: %w", err)
		}
		err = q.DeleteAssetProofByAssetID(ctx, assetID)
		if err != nil {
			return nil, fmt.Errorf("unable to delete asset proof: "+
				"%w", err)
		}
		if err := q.DeleteAssetByID(ctx, assetID); err != nil {
			return nil, fmt.Errorf("unable to delete asset: %w",
				err)
		}
	}

	// Restore passive assets: the re-anchor appended one proof to
	// each passive's file and moved it to the new anchor. Truncating
	// that suffix recovers the pre-transfer state exactly.
	err = a.restorePassiveAssets(
		ctx, q, assetTransfer.ID, anchorTxid, foreclosedPoints,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to restore passive assets: %w",
			err)
	}

	// Withdraw this transaction's confirmation before deciding what
	// its inputs owe. Both the un-spend and the revive below ask
	// whether some *other* confirmed transfer still claims an input;
	// leaving this transfer's own stale confirmation in place would
	// answer that question with itself.
	if err := q.UnconfirmChainAnchorTx(ctx, anchorTxid[:]); err != nil {
		return nil, fmt.Errorf("unable to unconfirm anchor tx: %w", err)
	}

	// Un-spend the inputs the forecloser left alone, then revive the
	// rivals sharing them where safe.
	inputs, err := q.FetchTransferInputs(ctx, assetTransfer.ID)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch transfer inputs: %w",
			err)
	}
	restored := make([]bool, len(inputs))
	revivePoints := make([][]byte, 0, len(inputs))
	for idx := range inputs {
		var inputPoint wire.OutPoint
		err := readOutPoint(
			bytes.NewReader(inputs[idx].AnchorPoint), 0, 0,
			&inputPoint,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to decode input anchor "+
				"point: %w", err)
		}

		// An input the foreclosing transaction consumed is not
		// restorable: the chain gave it to that transaction, so
		// the asset stays spent, no rival needing the outpoint
		// can ever confirm, and there is nothing here for coin
		// selection to reclaim.
		if _, gone := foreclosedPoints[inputPoint]; gone {
			log.Infof("Input %v of abandoned transfer_id=%d "+
				"was consumed by the foreclosing "+
				"transaction; leaving it spent",
				inputPoint, assetTransfer.ID)

			continue
		}

		_, unspendErr := q.SetAssetUnspent(
			ctx, sqlc.SetAssetUnspentParams{
				ScriptKey:   inputs[idx].ScriptKey,
				GenAssetID:  inputs[idx].AssetID,
				AnchorPoint: inputs[idx].AnchorPoint,
			},
		)
		if unspendErr != nil && !errors.Is(unspendErr, sql.ErrNoRows) {
			return nil, fmt.Errorf("unable to un-spend asset: %w",
				unspendErr)
		}
		restored[idx] = unspendErr == nil
		revivePoints = append(revivePoints, inputs[idx].AnchorPoint)
	}

	numRevived, err := reviveSafeRivals(
		ctx, q, assetTransfer.ID, revivePoints, foreclosedPoints,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to revive conflicting "+
			"transfers: %w", err)
	}
	if numRevived > 0 {
		log.Infof("Revived %d transfer(s) superseded by abandoned "+
			"transfer_id=%d", numRevived, assetTransfer.ID)
	}

	// Release the leases the pending write took on the restored
	// inputs, so the coins are selectable again without waiting for
	// expiry. An un-restored input still answers to a surviving
	// claimant and keeps its lease. A restored input is released
	// only when no live transfer other than this one still claims
	// it: a revived rival's replacement is in flight to spend every
	// input the rival shares with this transfer, and the lease on
	// each must outlive the abandonment or a new send can select
	// the input from under it. Revival is a per-transfer flag, so
	// this is asked of the claimants per input rather than inferred
	// from which input's revive step happened to flip the rival.
	for idx := range inputs {
		if !restored[idx] {
			continue
		}

		numLive, err := q.CountLiveTransfersSpendingPoint(
			ctx, sqlc.CountLiveTransfersSpendingPointParams{
				AnchorPoint:         inputs[idx].AnchorPoint,
				AbandonedTransferID: assetTransfer.ID,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("unable to count live "+
				"claimants of input: %w", err)
		}
		if numLive > 0 {
			continue
		}

		err = q.DeleteUTXOLease(ctx, inputs[idx].AnchorPoint)
		if err != nil {
			return nil, fmt.Errorf("unable to release input "+
				"lease: %w", err)
		}
	}

	if err := q.UnsweepManagedUTXOsByTxid(ctx, anchorTxid[:]); err != nil {
		return nil, fmt.Errorf("unable to unsweep UTXOs: %w", err)
	}
	err = q.DeleteBurnsByTransferID(ctx, assetTransfer.ID)
	if err != nil {
		return nil, fmt.Errorf("unable to delete burns: %w", err)
	}

	// The abandoned transfer is permanently dead: it must not be
	// resumed, and it must not count as pending.
	err = q.MarkTransferSuperseded(ctx, assetTransfer.ID)
	if err != nil {
		return nil, fmt.Errorf("unable to mark transfer "+
			"superseded: %w", err)
	}

	return deleted, nil
}

// reviveSafeRivals is the inverse of the supersession a confirmation
// applies, run when the confirming transfer is abandoned: the
// superseded rivals sharing one of the given anchor points with the
// abandoned transfer become live again where safe. A rival is revived
// only if no confirmed transfer conflicts with it on any of its
// inputs and none of its inputs was consumed by the foreclosing
// transaction. Both conditions range over the rival's whole input
// set, not just the input it shares with the abandoned transfer: a
// rival failing either can never confirm, and reviving it would
// resume a parcel that rebroadcasts a doomed anchor. Such a rival
// keeps its flags as they are — if it holds materialized state, its
// own anchoring's abandonment is what compensates it.
//
// Only rivalry losers are candidates. A transfer marked abandoned was
// compensated by its own abandonment and is never revived.
func reviveSafeRivals(ctx context.Context, q *sqlc.Queries,
	abandonedID int64, anchorPoints [][]byte,
	foreclosedPoints map[wire.OutPoint]struct{}) (int, error) {

	candidates := make(map[int64]struct{})
	for _, anchorPoint := range anchorPoints {
		rivals, err := q.SupersededTransfersSpendingPoint(
			ctx, sqlc.SupersededTransfersSpendingPointParams{
				AnchorPoint:         anchorPoint,
				AbandonedTransferID: abandonedID,
			},
		)
		if err != nil {
			return 0, fmt.Errorf("unable to query superseded "+
				"rivals: %w", err)
		}
		for _, id := range rivals {
			candidates[id] = struct{}{}
		}
	}

	ids := make([]int64, 0, len(candidates))
	for id := range candidates {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	numRevived := 0
	for _, id := range ids {
		foreclosed, err := transferSpendsAny(
			ctx, q, id, foreclosedPoints,
		)
		if err != nil {
			return 0, err
		}
		if foreclosed {
			log.Infof("Leaving transfer_id=%d superseded: one of "+
				"its inputs was consumed by the foreclosing "+
				"transaction", id)

			continue
		}

		revived, err := q.UnsupersedeSafeTransfer(ctx, id)
		if err != nil {
			return 0, fmt.Errorf("unable to revive "+
				"transfer_id=%d: %w", id, err)
		}
		if revived > 0 {
			numRevived++
		}
	}

	return numRevived, nil
}

// transferSpendsAny reports whether one of the transfer's inputs is
// among the given outpoints.
func transferSpendsAny(ctx context.Context, q *sqlc.Queries,
	transferID int64, points map[wire.OutPoint]struct{}) (bool, error) {

	if len(points) == 0 {
		return false, nil
	}

	inputs, err := q.FetchTransferInputs(ctx, transferID)
	if err != nil {
		return false, fmt.Errorf("unable to fetch transfer inputs: "+
			"%w", err)
	}
	for idx := range inputs {
		var point wire.OutPoint
		err := readOutPoint(
			bytes.NewReader(inputs[idx].AnchorPoint), 0, 0, &point,
		)
		if err != nil {
			return false, fmt.Errorf("unable to decode input "+
				"anchor point: %w", err)
		}
		if _, ok := points[point]; ok {
			return true, nil
		}
	}

	return false, nil
}

// restorePassiveAssets undoes reAnchorPassiveAssets for an abandoned
// transfer: for each passive asset whose proof file ends in a proof
// anchored by the abandoned transaction, the file is truncated by one
// proof and the asset's witnesses, spend-template fields and anchor
// UTXO are restored from the now-final proof.
//
// A passive restored to an anchor outpoint the foreclosing
// transaction consumed is additionally marked spent: the restored
// provenance is true — the asset last verifiably sat at that
// outpoint — but the outpoint itself has been taken by a transaction
// that is not ours, so the holding is no longer in the node's
// control and must not count toward balances or coin selection.
func (a *AssetStore) restorePassiveAssets(ctx context.Context,
	q *sqlc.Queries, transferID int64, anchorTxid chainhash.Hash,
	foreclosedPoints map[wire.OutPoint]struct{}) error {

	passiveAssets, err := q.QueryPassiveAssets(ctx, transferID)
	if err != nil {
		return fmt.Errorf("failed to query passive assets: %w", err)
	}

	for _, passiveAsset := range passiveAssets {
		blob, err := q.AssetProofBlobByAssetID(
			ctx, passiveAsset.AssetID,
		)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// Never re-anchored: nothing to restore.
			continue

		case err != nil:
			return fmt.Errorf("unable to fetch passive proof: "+
				"%w", err)
		}

		file := &proof.File{}
		if err := file.Decode(bytes.NewReader(blob)); err != nil {
			return fmt.Errorf("unable to decode passive proof "+
				"file: %w", err)
		}

		numProofs := file.NumProofs()
		if numProofs < 2 {
			continue
		}

		lastProof, err := file.ProofAt(uint32(numProofs - 1))
		if err != nil {
			return fmt.Errorf("unable to read last proof: %w",
				err)
		}

		// Only a file whose tip was contributed by the abandoned
		// transaction is rolled back; anything else means the
		// re-anchor never applied (or was already reversed).
		if lastProof.AnchorTx.TxHash() != anchorTxid {
			continue
		}

		prevProof, err := file.ProofAt(uint32(numProofs - 2))
		if err != nil {
			return fmt.Errorf("unable to read prior proof: %w",
				err)
		}

		// Rebuild the truncated file.
		kept := make([]proof.Proof, 0, numProofs-1)
		for i := 0; i < numProofs-1; i++ {
			p, err := file.ProofAt(uint32(i))
			if err != nil {
				return fmt.Errorf("unable to read proof "+
					"%d: %w", i, err)
			}
			kept = append(kept, *p)
		}
		truncated, err := proof.NewFile(file.Version, kept...)
		if err != nil {
			return fmt.Errorf("unable to build truncated "+
				"file: %w", err)
		}
		var truncatedBuf bytes.Buffer
		if err := truncated.Encode(&truncatedBuf); err != nil {
			return fmt.Errorf("unable to encode truncated "+
				"file: %w", err)
		}

		// The pre-transfer anchor UTXO row still exists locally:
		// nothing deletes it, whether or not the outpoint
		// survived on chain. Whether it did decides below if the
		// restored holding is still ours.
		oldOutpoint, err := encodeOutpoint(prevProof.OutPoint())
		if err != nil {
			return fmt.Errorf("unable to encode prior "+
				"outpoint: %w", err)
		}
		oldUtxo, err := q.FetchManagedUTXO(
			ctx, sqlc.FetchManagedUTXOParams{
				Outpoint: oldOutpoint,
			},
		)
		if err != nil {
			return fmt.Errorf("unable to fetch prior anchor "+
				"UTXO: %w", err)
		}

		// Restore the spend-template fields the re-anchor reset.
		var (
			splitRootHash  []byte
			splitRootValue sql.NullInt64
		)
		if prevProof.Asset.SplitCommitmentRoot != nil {
			rootHash := prevProof.Asset.SplitCommitmentRoot.
				NodeHash()
			splitRootHash = rootHash[:]
			splitRootValue = sqlInt64(
				int64(prevProof.Asset.SplitCommitmentRoot.
					NodeSum()),
			)
		}
		err = q.RestoreAssetSpendTemplate(
			ctx, sqlc.RestoreAssetSpendTemplateParams{
				AssetID:      passiveAsset.AssetID,
				AnchorUtxoID: sqlInt64(oldUtxo.UtxoID),
				//nolint:lll
				SplitCommitmentRootHash:  splitRootHash,
				SplitCommitmentRootValue: splitRootValue,
				LockTime: sqlInt32(
					prevProof.Asset.LockTime,
				),
				RelativeLockTime: sqlInt32(
					prevProof.Asset.RelativeLockTime,
				),
			},
		)
		if err != nil {
			return fmt.Errorf("unable to restore passive "+
				"asset: %w", err)
		}

		// Restore the pre-transfer witnesses.
		err = q.DeleteAssetWitnesses(ctx, passiveAsset.AssetID)
		if err != nil {
			return fmt.Errorf("unable to delete witnesses: %w",
				err)
		}
		err = a.insertAssetWitnesses(
			ctx, q, passiveAsset.AssetID,
			prevProof.Asset.PrevWitnesses,
		)
		if err != nil {
			return fmt.Errorf("unable to restore witnesses: %w",
				err)
		}

		// And the truncated proof file.
		err = q.UpsertAssetProofByID(ctx, ProofUpdateByID{
			AssetID:   passiveAsset.AssetID,
			ProofFile: truncatedBuf.Bytes(),
		})
		if err != nil {
			return fmt.Errorf("unable to store truncated "+
				"proof: %w", err)
		}

		// A holding restored to an outpoint the foreclosing
		// transaction consumed is no longer ours: the provenance
		// above is true up to that outpoint, but the chain gave
		// the outpoint itself to someone else. Mark it spent so
		// it counts toward neither balances nor coin selection.
		_, gone := foreclosedPoints[prevProof.OutPoint()]
		if gone {
			err := q.SetAssetSpentByID(
				ctx, passiveAsset.AssetID,
			)
			if err != nil {
				return fmt.Errorf("unable to mark "+
					"foreclosed passive spent: %w", err)
			}

			log.Infof("Passive asset %d restored to foreclosed "+
				"outpoint %v; marked spent",
				passiveAsset.AssetID, prevProof.OutPoint())
		}
	}

	return nil
}

// RebuildAnchorConfirm reconstructs a transfer's confirmation event
// purely from stored state plus the witness's block context (header
// and merkle inclusion proof, captured by the re-org watcher at
// sensing time). No chain, archive or porter-memory access is
// needed, so the rebuild can run inside the watcher's delivery
// transaction — including after a restart, and again with fresh
// block context when the same anchor transaction re-confirms
// elsewhere.
//
// Zero-value swept inputs are not persisted before confirmation, but
// their set is derivable — an anchor-transaction input with a
// managed-UTXO row that is not one of the transfer's asset inputs —
// so rebuilt events carry it and the confirmation application marks
// the sweeps. The burn note is supplied by the caller (the porter
// site carries it in its anchoring payload).
func (a *AssetStore) RebuildAnchorConfirm(ctx context.Context,
	q *sqlc.Queries, anchorTx *wire.MsgTx, blockHash chainhash.Hash,
	blockHeight, txIndex uint32, header wire.BlockHeader,
	merkle proof.TxMerkleProof,
	burnNote string) (*tapfreighter.AssetConfirmEvent,
	[]*tapfreighter.AssetBurn, error) {

	return a.rebuildAnchorConfirm(
		ctx, q, anchorTx, blockHash, blockHeight, txIndex, header,
		merkle, burnNote,
	)
}

// rebuildAnchorConfirm is the store-interface-typed body of
// RebuildAnchorConfirm.
func (a *AssetStore) rebuildAnchorConfirm(ctx context.Context,
	q ActiveAssetsStore, anchorTx *wire.MsgTx, blockHash chainhash.Hash,
	blockHeight, txIndex uint32, header wire.BlockHeader,
	merkle proof.TxMerkleProof,
	burnNote string) (*tapfreighter.AssetConfirmEvent,
	[]*tapfreighter.AssetBurn, error) {

	anchorTxid := anchorTx.TxHash()

	assetTransfers, err := q.QueryAssetTransfers(ctx, TransferQuery{
		AnchorTxHash: anchorTxid[:],
	})
	if err != nil {
		return nil, nil, fmt.Errorf("unable to query asset "+
			"transfers: %w", err)
	}
	if len(assetTransfers) == 0 {
		return nil, nil, fmt.Errorf("no transfer found for anchor "+
			"tx %v", anchorTxid)
	}
	assetTransfer := assetTransfers[0]

	inputs, err := q.FetchTransferInputs(ctx, assetTransfer.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch transfer "+
			"inputs: %w", err)
	}
	outputs, err := q.FetchTransferOutputs(ctx, assetTransfer.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to fetch transfer "+
			"outputs: %w", err)
	}

	// Decode the transfer's inputs into their previous IDs. Each
	// output picks out its own inputs from these below, by witness
	// reference: an anchor transaction can carry several independent
	// same-asset transitions (aggregated sweeps), so grouping by
	// asset ID alone would staple a suffix onto an unrelated input's
	// file.
	inputPrevIDs := make([]asset.PrevID, 0, len(inputs))
	for idx := range inputs {
		in := inputs[idx]

		var op wire.OutPoint
		err := readOutPoint(
			bytes.NewReader(in.AnchorPoint), 0, 0, &op,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to decode "+
				"input anchor point: %w", err)
		}

		var assetID asset.ID
		copy(assetID[:], in.AssetID)

		var scriptKey asset.SerializedKey
		copy(scriptKey[:], in.ScriptKey)

		inputPrevIDs = append(inputPrevIDs, asset.PrevID{
			OutPoint:  op,
			ID:        assetID,
			ScriptKey: scriptKey,
		})
	}

	// Rebuild the zero-value sweep set. The live confirmation event
	// carries the funding step's selection out of porter memory; the
	// rebuilt event must derive the same set, or the confirmation
	// application never marks the swept anchors and coin selection
	// can fund a later transfer with an outpoint this transaction
	// already spent, once the sweep lease expires. The set is
	// recoverable from stored state: a zero-value sweep is an
	// anchor-transaction input that carries a managed-UTXO row but
	// is not one of the transfer's asset inputs (wallet-funded fee
	// inputs have no managed row). Only the outpoint is rebuilt —
	// it is all the confirmation application consumes; the remaining
	// fields serve funding-time signing.
	inputAnchors := make(map[wire.OutPoint]struct{}, len(inputPrevIDs))
	for _, prevID := range inputPrevIDs {
		inputAnchors[prevID.OutPoint] = struct{}{}
	}

	var zeroValueInputs []*tapfreighter.ZeroValueInput
	for _, txIn := range anchorTx.TxIn {
		op := txIn.PreviousOutPoint
		if _, ok := inputAnchors[op]; ok {
			continue
		}

		outpointBytes, err := encodeOutpoint(op)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to encode "+
				"anchor input outpoint: %w", err)
		}

		_, err = q.FetchManagedUTXO(ctx, UtxoQuery{
			Outpoint: outpointBytes,
		})
		switch {
		case errors.Is(err, sql.ErrNoRows):
			continue

		case err != nil:
			return nil, nil, fmt.Errorf("unable to look up "+
				"managed UTXO for anchor input %v: %w", op,
				err)
		}

		zeroValueInputs = append(
			zeroValueInputs, &tapfreighter.ZeroValueInput{
				OutPoint: op,
			},
		)
	}

	// fetchInputFile loads an input's full proof file from the
	// database by its previous ID.
	fetchInputFile := func(prevID asset.PrevID) (*proof.File, error) {
		outpointBytes, err := encodeOutpoint(prevID.OutPoint)
		if err != nil {
			return nil, err
		}

		rows, err := q.FetchAssetProof(
			ctx, sqlc.FetchAssetProofParams{
				TweakedScriptKey: prevID.ScriptKey[:],
				Outpoint:         outpointBytes,
				AssetID:          prevID.ID[:],
			},
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch input "+
				"proof: %w", err)
		}
		if len(rows) == 0 {
			return nil, fmt.Errorf("no input proof for %v",
				prevID.OutPoint)
		}

		file := &proof.File{}
		err = file.Decode(bytes.NewReader(rows[0].ProofFile))
		if err != nil {
			return nil, fmt.Errorf("unable to decode input "+
				"proof file: %w", err)
		}

		return file, nil
	}

	var (
		finalProofs = make(
			map[tapfreighter.OutputIdentifier]*proof.AnnotatedProof,
			len(outputs),
		)
		burns []*tapfreighter.AssetBurn
	)
	for idx := range outputs {
		out := outputs[idx]
		if len(out.ProofSuffix) == 0 {
			continue
		}

		suffix := &proof.Proof{}
		err := suffix.Decode(bytes.NewReader(out.ProofSuffix))
		if err != nil {
			return nil, nil, fmt.Errorf("unable to decode "+
				"proof suffix: %w", err)
		}

		// Stamp the witness's block context onto the suffix; this
		// is exactly what confirmation adds to the pre-broadcast
		// suffix.
		suffix.AnchorTx = *anchorTx
		suffix.BlockHeader = header
		suffix.BlockHeight = blockHeight
		suffix.TxMerkleProof = merkle

		// The output's full proof file is its primary input's
		// file with the suffix appended, and any additional
		// inputs' files attached to the suffix. Which inputs
		// those are is determined by the suffix's own witnesses
		// (resolved through the split commitment root where
		// applicable), exactly as at pre-broadcast verification.
		assetID := suffix.Asset.ID()
		witnesses := suffix.Asset.Witnesses()
		var prevIDs []asset.PrevID
		for _, in := range inputPrevIDs {
			for _, witness := range witnesses {
				if witness.PrevID != nil &&
					in == *witness.PrevID {

					prevIDs = append(prevIDs, in)
				}
			}
		}
		if len(prevIDs) == 0 {
			return nil, nil, fmt.Errorf("no inputs found for "+
				"output asset %v", assetID)
		}

		for extra := 1; extra < len(prevIDs); extra++ {
			extraFile, err := fetchInputFile(prevIDs[extra])
			if err != nil {
				return nil, nil, err
			}
			suffix.AdditionalInputs = append(
				suffix.AdditionalInputs, *extraFile,
			)
		}

		file, err := fetchInputFile(prevIDs[0])
		if err != nil {
			return nil, nil, err
		}
		if err := file.AppendProof(*suffix); err != nil {
			return nil, nil, fmt.Errorf("unable to append "+
				"proof: %w", err)
		}
		var blob bytes.Buffer
		if err := file.Encode(&blob); err != nil {
			return nil, nil, fmt.Errorf("unable to encode "+
				"proof file: %w", err)
		}

		fullScriptKey, err := parseScriptKey(
			out.InternalKey, out.ScriptKey,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to decode "+
				"script key: %w", err)
		}
		scriptPubKey := fullScriptKey.PubKey

		outKey := tapfreighter.NewOutputIdentifier(
			assetID, suffix.InclusionProof.OutputIndex,
			*scriptPubKey,
		)
		finalProofs[outKey] = &proof.AnnotatedProof{
			Locator: proof.Locator{
				AssetID:   &assetID,
				ScriptKey: *scriptPubKey,
				OutPoint:  fn.Ptr(suffix.OutPoint()),
			},
			Blob: blob.Bytes(),
		}

		// Burns are recognizable from the suffix itself.
		if suffix.Asset.IsBurn() {
			burn := &tapfreighter.AssetBurn{
				Note:      burnNote,
				AssetID:   assetID[:],
				AssetType: suffix.Asset.Type,
				Amount:    uint64(out.Amount),
				//nolint:lll
				AnchorTxid: anchorTxid,
				ScriptKey:  &suffix.Asset.ScriptKey,
				Proof:      suffix,
				OutPoint: wire.OutPoint{
					Hash: anchorTxid,
					//nolint:lll
					Index: suffix.InclusionProof.OutputIndex,
				},
			}
			if suffix.Asset.GroupKey != nil {
				groupKey := suffix.Asset.GroupKey.GroupPubKey
				burn.GroupKey = groupKey.
					SerializeCompressed()
			}

			burns = append(burns, burn)
		}
	}

	// Passive assets: each carries its post-transfer suffix in its
	// passive row, and — since the re-anchor has not yet applied in
	// this transaction — its pre-transfer file as its current proof
	// blob.
	passiveFiles := make(map[asset.ID][]*proof.AnnotatedProof)
	passiveAssets, err := q.QueryPassiveAssets(ctx, assetTransfer.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query passive "+
			"assets: %w", err)
	}
	for _, passiveAsset := range passiveAssets {
		suffix := &proof.Proof{}
		err := suffix.Decode(bytes.NewReader(passiveAsset.NewProof))
		if err != nil {
			return nil, nil, fmt.Errorf("unable to decode "+
				"passive suffix: %w", err)
		}

		suffix.AnchorTx = *anchorTx
		suffix.BlockHeader = header
		suffix.BlockHeight = blockHeight
		suffix.TxMerkleProof = merkle

		blobBytes, err := q.AssetProofBlobByAssetID(
			ctx, passiveAsset.AssetID,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to fetch "+
				"passive proof: %w", err)
		}
		file := &proof.File{}
		if err := file.Decode(bytes.NewReader(blobBytes)); err != nil {
			return nil, nil, fmt.Errorf("unable to decode "+
				"passive proof file: %w", err)
		}

		// A rebuild after a partial application may see the file
		// already extended by this very transaction's suffix; the
		// append then replaces rather than duplicates.
		alreadyExtended := false
		if numProofs := file.NumProofs(); numProofs > 0 {
			last, err := file.ProofAt(uint32(numProofs - 1))
			if err != nil {
				return nil, nil, err
			}
			alreadyExtended = last.AnchorTx.TxHash() == anchorTxid
		}
		if alreadyExtended {
			if err := file.ReplaceLastProof(*suffix); err != nil {
				return nil, nil, fmt.Errorf("unable to "+
					"replace proof: %w", err)
			}
		} else if err := file.AppendProof(*suffix); err != nil {
			return nil, nil, fmt.Errorf("unable to append "+
				"passive proof: %w", err)
		}

		var blob bytes.Buffer
		if err := file.Encode(&blob); err != nil {
			return nil, nil, fmt.Errorf("unable to encode "+
				"passive file: %w", err)
		}

		scriptKey, err := btcec.ParsePubKey(passiveAsset.ScriptKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse "+
				"passive script key: %w", err)
		}

		var genesisID asset.ID
		copy(genesisID[:], passiveAsset.GenesisID)

		passiveFiles[genesisID] = append(
			passiveFiles[genesisID], &proof.AnnotatedProof{
				Locator: proof.Locator{
					AssetID:   &genesisID,
					ScriptKey: *scriptKey,
					OutPoint: fn.Ptr(
						suffix.OutPoint(),
					),
				},
				Blob: blob.Bytes(),
			},
		)
	}

	conf := &tapfreighter.AssetConfirmEvent{
		AnchorTXID:             anchorTxid,
		BlockHash:              blockHash,
		BlockHeight:            int32(blockHeight),
		TxIndex:                int32(txIndex),
		FinalProofs:            finalProofs,
		PassiveAssetProofFiles: passiveFiles,
		ZeroValueInputs:        zeroValueInputs,
	}

	return conf, burns, nil
}

// RebuildConfirmEvent is RebuildAnchorConfirm inside a read
// transaction of its own, for callers outside the watcher's delivery
// path (the porter's proof-file mirroring and burn-event dispatch).
func (a *AssetStore) RebuildConfirmEvent(ctx context.Context,
	anchorTx *wire.MsgTx, blockHash chainhash.Hash,
	blockHeight, txIndex uint32, header wire.BlockHeader,
	merkle proof.TxMerkleProof,
	burnNote string) (*tapfreighter.AssetConfirmEvent,
	[]*tapfreighter.AssetBurn, error) {

	var (
		conf  *tapfreighter.AssetConfirmEvent
		burns []*tapfreighter.AssetBurn
	)
	readOpts := NewAssetStoreReadTx()
	dbErr := a.db.ExecTx(ctx, &readOpts, func(q ActiveAssetsStore) error {
		var err error
		conf, burns, err = a.rebuildAnchorConfirm(
			ctx, q, anchorTx, blockHash, blockHeight, txIndex,
			header, merkle, burnNote,
		)

		return err
	})
	if dbErr != nil {
		return nil, nil, dbErr
	}

	return conf, burns, nil
}

// A compile-time assertion that the asset store provides the porter
// site's persistence surface.
var _ tapfreighter.AnchoringLog = (*AssetStore)(nil)
