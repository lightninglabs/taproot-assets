package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
)

// storedChainTx is a decoded chain_txns row.
type storedChainTx struct {
	id          int64
	tx          *wire.MsgTx
	blockHeight sql.NullInt32
	blockHash   []byte
}

// repairGenesisAnchorMigration is migration 74. It restores
// genesis_points.anchor_tx_id after transfer proofs retargeted it, then
// drops never-confirmed supply commitments that spend neither a mint
// pre-commit nor a confirmed commitment outpoint.
func repairGenesisAnchorMigration(ctx context.Context,
	db sqlc.Querier) error {

	if err := repairGenesisAnchors(ctx, db); err != nil {
		return err
	}

	return abandonInvalidUnconfirmedSupplyCommits(ctx, db)
}

// repairGenesisAnchors points each genesis anchor at the chain
// transaction that spends the genesis outpoint.
//
// A genesis with no spending chain transaction is left unchanged: the
// issuance proof may not have been stored yet. When several chain
// transactions spend the genesis outpoint, the migration prefers the
// mint batch's recorded mint transaction, else the sole confirmed
// spender, else leaves the pointer unchanged and continues. An anchor
// that already spends the genesis outpoint is left in place.
//
// Block metadata that ConfirmChainTx wrote onto a retargeted anchor
// before the mint confirmed is not moved. Confirm-then-send leaves the
// mint's own chain_txns row with its block fields intact.
func repairGenesisAnchors(ctx context.Context, db sqlc.Querier) error {
	points, err := db.GenesisPoints(ctx)
	if err != nil {
		return fmt.Errorf("listing genesis points: %w", err)
	}
	if len(points) == 0 {
		return nil
	}

	rows, err := db.FetchAllChainTxns(ctx)
	if err != nil {
		return fmt.Errorf("listing chain transactions: %w", err)
	}

	byID := make(map[int64]*wire.MsgTx, len(rows))
	decoded := make([]storedChainTx, 0, len(rows))
	for _, row := range rows {
		parsed := new(wire.MsgTx)
		err := parsed.Deserialize(bytes.NewReader(row.RawTx))
		if err != nil {
			return fmt.Errorf("decoding chain txn %d: %w",
				row.TxnID, err)
		}

		byID[row.TxnID] = parsed
		decoded = append(decoded, storedChainTx{
			id:          row.TxnID,
			tx:          parsed,
			blockHeight: row.BlockHeight,
			blockHash:   row.BlockHash,
		})
	}

	for _, point := range points {
		err := repairOneGenesisAnchor(ctx, db, point, byID, decoded)
		if err != nil {
			return err
		}
	}

	return nil
}

// repairOneGenesisAnchor repairs a single genesis point.
func repairOneGenesisAnchor(ctx context.Context, db sqlc.Querier,
	point sqlc.GenesisPoint, byID map[int64]*wire.MsgTx,
	decoded []storedChainTx) error {

	var genesis wire.OutPoint
	err := readOutPoint(bytes.NewReader(point.PrevOut), 0, 0, &genesis)
	if err != nil {
		return fmt.Errorf("decoding genesis outpoint %d: %w",
			point.GenesisID, err)
	}

	if point.AnchorTxID.Valid {
		current, ok := byID[point.AnchorTxID.Int64]
		if ok && anchorSpendsGenesis(current, genesis) {
			return nil
		}
	}

	var spenders []storedChainTx
	for _, row := range decoded {
		if anchorSpendsGenesis(row.tx, genesis) {
			spenders = append(spenders, row)
		}
	}

	switch len(spenders) {
	case 0:
		return nil

	default:
		spenderID, ok := resolveGenesisSpender(
			ctx, db, point, genesis, spenders,
		)
		if !ok {
			return nil
		}

		if point.AnchorTxID.Valid &&
			point.AnchorTxID.Int64 == spenderID {

			return nil
		}

		err := db.AnchorGenesisPoint(ctx, sqlc.AnchorGenesisPointParams{
			PrevOut: point.PrevOut,
			AnchorTxID: sql.NullInt64{
				Int64: spenderID,
				Valid: true,
			},
		})
		if err != nil {
			return fmt.Errorf("retargeting genesis %d: %w",
				point.GenesisID, err)
		}

		log.Infof("Repaired genesis anchor %d to chain txn %d",
			point.GenesisID, spenderID)

		return nil
	}
}

// resolveGenesisSpender picks the chain_txns row that should anchor a
// genesis outpoint when one or more stored transactions spend it.
func resolveGenesisSpender(ctx context.Context, db sqlc.Querier,
	point sqlc.GenesisPoint, genesis wire.OutPoint,
	spenders []storedChainTx) (int64, bool) {

	if len(spenders) == 1 {
		return spenders[0].id, true
	}

	batchHashes, err := mintBatchMintTxHashes(ctx, db, point.GenesisID)
	if err != nil {
		log.Warnf("Migration 74: genesis %d (%v): cannot read "+
			"mint batch mint tx: %v; leaving anchor unchanged",
			point.GenesisID, genesis, err)

		return 0, false
	}

	if len(batchHashes) > 0 {
		var batchMatches []storedChainTx
		for _, row := range spenders {
			hash := row.tx.TxHash()
			for _, want := range batchHashes {
				if hash == want {
					batchMatches = append(
						batchMatches, row,
					)
					break
				}
			}
		}

		switch len(batchMatches) {
		case 1:
			return batchMatches[0].id, true

		case 0:
			// Fall through to confirmed selection.

		default:
			logAmbiguousGenesisSpenders(
				point.GenesisID, genesis, spenders,
				"several spenders match the mint batch mint tx",
			)

			return 0, false
		}
	}

	var confirmed []storedChainTx
	for _, row := range spenders {
		if chainTxConfirmed(row) {
			confirmed = append(confirmed, row)
		}
	}

	switch len(confirmed) {
	case 1:
		return confirmed[0].id, true

	case 0:
		logAmbiguousGenesisSpenders(
			point.GenesisID, genesis, spenders,
			"no unique mint-batch or confirmed spender",
		)

		return 0, false

	default:
		logAmbiguousGenesisSpenders(
			point.GenesisID, genesis, spenders,
			"several confirmed spenders",
		)

		return 0, false
	}
}

// mintBatchMintTxHashes returns mint-transaction hashes recorded on
// mint_supply_pre_commit rows for the minting batch tied to genesisID.
func mintBatchMintTxHashes(ctx context.Context, db sqlc.Querier,
	genesisID int64) ([]chainhash.Hash, error) {

	encoded, err := db.FetchMintPreCommitOutpointsByGenesisID(
		ctx, sql.NullInt64{
			Int64: genesisID,
			Valid: true,
		},
	)
	if err != nil {
		return nil, err
	}

	seen := make(map[chainhash.Hash]struct{})
	var hashes []chainhash.Hash
	for _, raw := range encoded {
		var op wire.OutPoint
		err := readOutPoint(bytes.NewReader(raw), 0, 0, &op)
		if err != nil {
			return nil, fmt.Errorf("decoding pre-commit "+
				"outpoint: %w", err)
		}

		if _, ok := seen[op.Hash]; ok {
			continue
		}

		seen[op.Hash] = struct{}{}
		hashes = append(hashes, op.Hash)
	}

	return hashes, nil
}

// chainTxConfirmed reports whether chain_txns block metadata is set.
func chainTxConfirmed(row storedChainTx) bool {
	return row.blockHeight.Valid && len(row.blockHash) > 0
}

// logAmbiguousGenesisSpenders logs when migration 74 cannot pick a
// unique spender for a genesis outpoint.
func logAmbiguousGenesisSpenders(genesisID int64, genesis wire.OutPoint,
	spenders []storedChainTx, reason string) {

	txids := make([]chainhash.Hash, len(spenders))
	for i, row := range spenders {
		txids[i] = row.tx.TxHash()
	}

	log.Warnf("Migration 74: genesis %d (%v) is spent by %d "+
		"chain transactions (%v); %s; leaving anchor_tx_id "+
		"unchanged", genesisID, genesis, len(spenders), txids,
		reason)
}

// abandonInvalidUnconfirmedSupplyCommits deletes never-confirmed
// CommitBroadcast commitments that do not spend a stored pre-commit
// outpoint or a confirmed supply-commitment outpoint.
//
// A valid unconfirmed commitment spends one of those outpoints and is
// left to be rebroadcast. When no known outpoints exist, nothing is
// abandoned: the migration cannot tell a bad input from a missing row.
// Supply update events on the transition are kept, and the state
// machine returns to UpdatesPendingState.
func abandonInvalidUnconfirmedSupplyCommits(ctx context.Context,
	db sqlc.Querier) error {

	known, err := loadKnownSupplyOutpoints(ctx, db)
	if err != nil {
		return err
	}
	if len(known) == 0 {
		return nil
	}

	rows, err := db.FetchUnconfirmedBroadcastSupplyCommits(ctx)
	if err != nil {
		return fmt.Errorf("listing unconfirmed supply "+
			"commitments: %w", err)
	}

	for _, row := range rows {
		var tx wire.MsgTx
		err := tx.Deserialize(bytes.NewReader(row.RawTx))
		if err != nil {
			return fmt.Errorf("decoding supply commitment "+
				"%d: %w", row.CommitID, err)
		}
		if commitSpendsKnownOutpoint(&tx, known) {
			continue
		}

		err = abandonSupplyCommitment(ctx, db, row)
		if err != nil {
			return err
		}
	}

	return nil
}

// loadKnownSupplyOutpoints returns mint pre-commit outpoints, remote
// pre-commit outpoints, and confirmed supply-commitment outpoints.
func loadKnownSupplyOutpoints(ctx context.Context,
	db sqlc.Querier) (map[wire.OutPoint]struct{}, error) {

	known := make(map[wire.OutPoint]struct{})

	mintOps, err := db.FetchMintSupplyPreCommitOutpoints(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing mint pre-commit "+
			"outpoints: %w", err)
	}
	if err := addEncodedOutpoints(known, mintOps); err != nil {
		return nil, err
	}

	remoteOps, err := db.FetchRemoteSupplyPreCommitOutpoints(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing remote pre-commit "+
			"outpoints: %w", err)
	}
	if err := addEncodedOutpoints(known, remoteOps); err != nil {
		return nil, err
	}

	confirmed, err := db.FetchConfirmedSupplyCommitOutpoints(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing confirmed supply "+
			"commitments: %w", err)
	}
	for _, row := range confirmed {
		if !row.OutputIndex.Valid ||
			len(row.Txid) != chainhash.HashSize {

			continue
		}

		var hash chainhash.Hash
		copy(hash[:], row.Txid)
		op := wire.OutPoint{
			Hash:  hash,
			Index: uint32(row.OutputIndex.Int32),
		}
		known[op] = struct{}{}
	}

	return known, nil
}

// addEncodedOutpoints decodes wire outpoints into the set.
func addEncodedOutpoints(known map[wire.OutPoint]struct{},
	encoded [][]byte) error {

	for _, raw := range encoded {
		var op wire.OutPoint
		err := readOutPoint(bytes.NewReader(raw), 0, 0, &op)
		if err != nil {
			return fmt.Errorf("decoding outpoint: %w", err)
		}
		known[op] = struct{}{}
	}

	return nil
}

// commitSpendsKnownOutpoint reports whether any input spends a known
// supply outpoint.
func commitSpendsKnownOutpoint(tx *wire.MsgTx,
	known map[wire.OutPoint]struct{}) bool {

	for _, in := range tx.TxIn {
		if _, ok := known[in.PreviousOutPoint]; ok {
			return true
		}
	}

	return false
}

// abandonSupplyCommitment removes one never-confirmed commitment and
// returns its state machine to UpdatesPendingState.
func abandonSupplyCommitment(ctx context.Context, db sqlc.Querier,
	row sqlc.FetchUnconfirmedBroadcastSupplyCommitsRow) error {

	commitID := sql.NullInt64{
		Int64: row.CommitID,
		Valid: true,
	}

	err := db.UnmarkMintPreCommitsSpentBy(ctx, commitID)
	if err != nil {
		return fmt.Errorf("clearing mint pre-commit spends: %w", err)
	}
	err = db.UnmarkRemotePreCommitsSpentBy(ctx, commitID)
	if err != nil {
		return fmt.Errorf("clearing remote pre-commit spends: %w",
			err)
	}
	err = db.ClearSpentCommitmentRef(ctx, commitID)
	if err != nil {
		return fmt.Errorf("clearing spent commitment refs: %w", err)
	}
	err = db.ClearSupplyCommitmentRefs(ctx, commitID)
	if err != nil {
		return fmt.Errorf("detaching commitment %d: %w",
			row.CommitID, err)
	}
	err = db.ClearPendingSupplyCommitTransition(ctx, row.TransitionID)
	if err != nil {
		return fmt.Errorf("clearing transition %d: %w",
			row.TransitionID, err)
	}

	stateName, err := stateToDBString(
		&supplycommit.UpdatesPendingState{},
	)
	if err != nil {
		return err
	}
	err = db.ResetSupplyCommitMachineForAbandon(
		ctx, sqlc.ResetSupplyCommitMachineForAbandonParams{
			StateName:          stateName,
			LatestCommitmentID: commitID,
			GroupKey:           row.GroupKey,
		},
	)
	if err != nil {
		return fmt.Errorf("resetting state machine: %w", err)
	}

	err = db.DeleteSupplyCommitment(ctx, row.CommitID)
	if err != nil {
		return fmt.Errorf("deleting supply commitment %d: %w",
			row.CommitID, err)
	}

	log.Infof("Abandoned unconfirmed supply commitment %d", row.CommitID)

	return nil
}
