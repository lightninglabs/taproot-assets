package tapdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

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
// concurrent traffic.
func (b *MultiverseStore) ReconcileMultiverse(ctx context.Context) error {
	log.Infof("Checking multiverse trees for divergence")

	diverged, err := b.multiverseDivergence(ctx)
	if err != nil {
		return fmt.Errorf("unable to check multiverse "+
			"divergence: %w", err)
	}

	if len(diverged) == 0 {
		log.Infof("Multiverse reconcile: no divergence found")
		return nil
	}

	log.Warnf("Repairing %d diverged multiverse entries", len(diverged))

	// Repair in bounded chunks, each committing independently: a
	// failure part-way through preserves the chunks already repaired,
	// so a restart resumes with strictly less divergence rather than
	// re-attempting one wholesale repair forever.
	batchSize := b.reconcileBatchSize
	for start := 0; start < len(diverged); start += batchSize {
		end := min(start+batchSize, len(diverged))

		err = b.rootCoalescer.updateRoots(ctx, diverged[start:end])
		if err != nil {
			return fmt.Errorf("unable to repair multiverse "+
				"entries %d-%d of %d: %w", start, end-1,
				len(diverged), err)
		}

		log.Infof("Multiverse reconcile: repaired %d/%d entries",
			end, len(diverged))
	}

	return nil
}

// committedMultiverseLeaf is the universe root value a multiverse leaf
// currently commits to.
type committedMultiverseLeaf struct {
	rootHash []byte
	rootSum  uint64
}

// multiverseDivergence returns the identifier of every universe whose
// current root is not committed to by its multiverse leaf, either
// because the leaf is missing or because it holds a stale root.
func (b *MultiverseStore) multiverseDivergence(
	ctx context.Context) ([]universe.Identifier, error) {

	// Load the committed multiverse leaves for both proof types,
	// keyed the same way multiverse leaf keys are derived (asset ID,
	// or hash of the schnorr-serialized group key).
	proofTypes := []universe.ProofType{
		universe.ProofTypeIssuance, universe.ProofTypeTransfer,
	}
	committed := make(
		map[universe.ProofType]map[[32]byte]committedMultiverseLeaf,
		len(proofTypes),
	)

	readTx := NewBaseMultiverseReadTx()
	dbErr := b.db.ExecTx(
		ctx, &readTx, func(db BaseMultiverseStore) error {
			for _, proofType := range proofTypes {
				leaves, err := db.QueryMultiverseLeaves(
					ctx, QueryMultiverseLeaves{
						ProofType: proofType.String(),
					},
				)
				if err != nil {
					return err
				}

				byKey := make(
					map[[32]byte]committedMultiverseLeaf,
					len(leaves),
				)
				for _, leaf := range leaves {
					var key [32]byte
					if len(leaf.GroupKey) > 0 {
						key = sha256.Sum256(
							leaf.GroupKey,
						)
					} else {
						copy(key[:], leaf.AssetID)
					}

					sum := uint64(leaf.UniverseRootSum)
					byKey[key] = committedMultiverseLeaf{
						rootHash: leaf.UniverseRootHash,
						rootSum:  sum,
					}
				}
				committed[proofType] = byKey
			}

			return nil
		},
	)
	if dbErr != nil {
		return nil, dbErr
	}

	// Page through all universe roots and collect those whose
	// multiverse leaf doesn't commit to them.
	var (
		diverged []universe.Identifier
		checked  int
	)
	params := sqlc.UniverseRootsParams{
		SortDirection: sqlInt16(universe.SortAscending),
		NumOffset:     0,
		NumLimit:      universe.RequestPageSize,
	}
	for {
		roots, err := b.queryRootNodes(ctx, params, false)
		if err != nil {
			return nil, err
		}

		for _, root := range roots {
			expected := multiverseLeafNode(root.ID, root.Node)
			expectedHash := root.Node.NodeHash()

			byKey := committed[root.ID.ProofType]
			leaf, ok := byKey[root.ID.Bytes()]
			if ok && bytes.Equal(leaf.rootHash, expectedHash[:]) &&
				leaf.rootSum == expected.NodeSum() {

				continue
			}

			diverged = append(diverged, root.ID)
		}

		checked += len(roots)
		log.Debugf("Multiverse reconcile: checked %d universe "+
			"roots, %d diverged so far", checked, len(diverged))

		params.NumOffset += universe.RequestPageSize
		if len(roots) < universe.RequestPageSize {
			break
		}
	}

	return diverged, nil
}
