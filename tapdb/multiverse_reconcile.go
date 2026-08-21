package tapdb

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
)

// defaultReconcileBatchSize bounds the number of universes repaired
// per coalescer submission during startup reconciliation, so repairs
// make durable forward progress in bounded steps.
const defaultReconcileBatchSize = 512

// ReconcileMultiverse verifies that the shared multiverse trees commit
// to the current root of every universe, and repairs any entries that
// diverged. The multiverse trees are fully derived from the universe
// roots, so a daemon that stopped between a proof insert committing
// and its multiverse update being flushed is always repairable here.
// This is intended to run at startup, before the store serves
// concurrent traffic; the given context bounds it, so a daemon
// shutdown interrupts it.
func (b *MultiverseStore) ReconcileMultiverse(ctx context.Context) error {
	log.Infof("Checking multiverse trees for divergence")
	start := time.Now()

	diverged, err := b.multiverseDivergence(ctx)
	if err != nil {
		return fmt.Errorf("unable to check multiverse "+
			"divergence: %w", err)
	}

	if len(diverged) == 0 {
		log.Infof("Multiverse reconcile: no divergence found, took=%v",
			time.Since(start))
		return nil
	}

	log.Warnf("Repairing %d diverged multiverse entries", len(diverged))

	// Repair in bounded chunks, each committing independently: a
	// failure part-way through preserves the chunks already repaired,
	// so a restart resumes with strictly less divergence rather than
	// re-attempting one wholesale repair forever.
	batchSize := b.reconcileBatchSize
	for chunk := 0; chunk < len(diverged); chunk += batchSize {
		end := min(chunk+batchSize, len(diverged))

		err = b.rootCoalescer.updateRoots(ctx, diverged[chunk:end])
		if err != nil {
			return fmt.Errorf("unable to repair multiverse "+
				"entries %d-%d of %d: %w", chunk, end-1,
				len(diverged), err)
		}

		log.Infof("Multiverse reconcile: repaired %d/%d entries",
			end, len(diverged))
	}

	log.Infof("Multiverse reconcile: repaired %d entries, took=%v",
		len(diverged), time.Since(start))

	return nil
}

// multiverseDivergence returns the identifier of every universe whose
// current root is not committed to by its multiverse leaf, either
// because the leaf is missing or because it holds a stale root.
//
// The scan pages through the universe roots by keyset on their table
// id — each page costs the same, unlike offset pagination — and
// resolves each page's multiverse leaves with point lookups inside the
// same read transaction, so memory use is bounded by the page size no
// matter how many universes the store holds.
func (b *MultiverseStore) multiverseDivergence(
	ctx context.Context) ([]universe.Identifier, error) {

	var (
		diverged []universe.Identifier
		checked  int
		afterID  int64
		start    = time.Now()
	)
	for {
		var (
			numRows      int
			pageDiverged = len(diverged)
			pageAfter    = afterID
		)
		readTx := NewBaseMultiverseReadTx()
		dbErr := b.db.ExecTx(
			ctx, &readTx, func(db BaseMultiverseStore) error {
				// The transaction may retry the closure
				// wholesale, so reset the state a previous
				// attempt of this page populated.
				diverged = diverged[:pageDiverged]
				afterID = pageAfter

				rows, err := db.UniverseRootsAfterID(
					ctx, sqlc.UniverseRootsAfterIDParams{
						AfterID:  afterID,
						NumLimit: b.reconcilePageSize,
					},
				)
				if err != nil {
					return err
				}

				numRows = len(rows)
				for _, row := range rows {
					afterID = row.ID

					isDiverged, id, err := rootDiverged(
						ctx, db, row,
					)
					if err != nil {
						return err
					}

					if isDiverged {
						diverged = append(diverged, id)
					}
				}

				return nil
			},
		)
		if dbErr != nil {
			return nil, dbErr
		}

		checked += numRows
		log.Debugf("Multiverse reconcile: checked %d universe "+
			"roots, %d diverged so far", checked, len(diverged))

		if numRows < int(b.reconcilePageSize) {
			break
		}
	}

	log.Debugf("Multiverse reconcile: divergence scan of %d roots "+
		"took=%v", checked, time.Since(start))

	return diverged, nil
}

// rootDiverged reports whether the given universe root row diverges
// from its multiverse leaf, resolving the leaf with a point lookup in
// the same transaction. Universe roots of proof types without a
// multiverse tree — the supply-commitment sub-trees (mint supply,
// burns, ignores), and any type added in the future — have no leaf to
// reconcile against, and are never reported as diverged.
func rootDiverged(ctx context.Context, db BaseMultiverseStore,
	row sqlc.UniverseRootsAfterIDRow) (bool, universe.Identifier, error) {

	var id universe.Identifier

	proofType, err := universe.ParseStrProofType(row.ProofType.String)
	if err != nil {
		return false, id, err
	}
	id.ProofType = proofType

	// The error only marks the proof type as having no multiverse
	// tree; that is a skip, not a failure.
	//nolint:nilerr
	if _, err := namespaceForProof(id.ProofType); err != nil {
		return false, id, nil
	}

	if row.AssetID != nil {
		copy(id.AssetID[:], row.AssetID)
	}
	if row.GroupKey != nil {
		id.GroupKey, err = schnorr.ParsePubKey(row.GroupKey)
		if err != nil {
			return false, id, err
		}
	}

	var rootHash mssmt.NodeHash
	copy(rootHash[:], row.RootHash)
	rootNode := mssmt.NewComputedBranch(rootHash, uint64(row.RootSum))

	expected := multiverseLeafNode(id, rootNode)

	// Look up the universe's multiverse leaf directly, keyed the same
	// way the insert path keys it: by group key when the universe is
	// grouped, by asset ID otherwise.
	query := QueryMultiverseLeaves{
		ProofType: id.ProofType.String(),
	}
	if id.GroupKey != nil {
		query.GroupKey = schnorr.SerializePubKey(id.GroupKey)
	} else {
		query.AssetID = id.AssetID[:]
	}

	leaves, err := db.QueryMultiverseLeaves(ctx, query)
	if err != nil {
		return false, id, err
	}

	for _, leaf := range leaves {
		if bytes.Equal(leaf.UniverseRootHash, rootHash[:]) &&
			uint64(leaf.UniverseRootSum) == expected.NodeSum() {

			return false, id, nil
		}
	}

	return true, id, nil
}
