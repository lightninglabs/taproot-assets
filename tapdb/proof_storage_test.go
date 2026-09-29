package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

type indexedProofCase struct {
	file    IndexedProofFile
	blob    proof.Blob
	present map[chainhash.Hash]bool
}

// TestIndexedProofStorageProperties checks that arbitrary replacements expose
// exactly the latest proof's anchor set, never a union with stale provenance.
func TestIndexedProofStorageProperties(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	_, assetStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	assetGen := newAssetGenerator(t, 1, 1)
	assetGen.genAssets(t, assetStore, []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		amt:         10,
	}})

	var assetID int64
	err := db.DB.QueryRowContext(
		ctx, "SELECT asset_id FROM asset_proofs LIMIT 1",
	).Scan(&assetID)
	require.NoError(t, err)

	proofs := make([]proof.Proof, 3)
	for idx := range proofs {
		amount := uint64(idx + 1)
		proofs[idx], _ = proof.RandGenesisProofWithKey(
			t, asset.Normal, &amount, nil, true, nil, nil, nil,
			nil, asset.V0,
		)
	}

	inputFile, err := proof.NewFile(proof.V0, proofs[2])
	require.NoError(t, err)
	proofWithInput := proofs[1]
	proofWithInput.AdditionalInputs = []proof.File{*inputFile}

	cases := []struct {
		proofs  []proof.Proof
		present []int
	}{
		{proofs: []proof.Proof{proofs[0]}, present: []int{0}},
		{proofs: []proof.Proof{proofWithInput}, present: []int{1, 2}},
		{
			proofs:  []proof.Proof{proofs[0], proofs[2]},
			present: []int{0, 2},
		},
	}

	indexedCases := make([]indexedProofCase, len(cases))
	for idx, testCase := range cases {
		proofFile, err := proof.NewFile(proof.V0, testCase.proofs...)
		require.NoError(t, err)

		var encoded bytes.Buffer
		require.NoError(t, proofFile.Encode(&encoded))
		blob := proof.Blob(encoded.Bytes())
		indexed, err := NewIndexedProofFile(blob)
		require.NoError(t, err)

		present := make(map[chainhash.Hash]bool)
		for _, proofIdx := range testCase.present {
			present[proofs[proofIdx].AnchorTx.TxHash()] = true
		}
		indexedCases[idx] = indexedProofCase{
			file:    indexed,
			blob:    append(proof.Blob(nil), blob...),
			present: present,
		}
	}

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	rapid.Check(t, func(rt *rapid.T) {
		sequence := rapid.SliceOfN(
			rapid.IntRange(0, len(indexedCases)-1), 1, 12,
		).Draw(rt, "replacement_sequence")

		err := executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				for _, caseIdx := range sequence {
					testCase := indexedCases[caseIdx]
					err := StoreIndexedAssetProof(
						ctx, q, assetID, testCase.file,
					)
					if err != nil {
						return err
					}

					err = assertIndexedProofCase(
						ctx, q, proofs, testCase,
					)
					if err != nil {
						return err
					}
				}

				return nil
			},
		)
		require.NoError(rt, err)
	})

	// A legacy/raw write is visible to adoption, but its stale reverse rows
	// are immediately hidden from transaction lookups.
	rawCase := indexedCases[1]
	err = db.UpsertAssetProofByID(ctx, ProofUpdateByID{
		AssetID:   assetID,
		ProofFile: rawCase.blob,
	})
	require.NoError(t, err)

	unindexed, err := db.FetchUnindexedAssetProofs(ctx, 10)
	require.NoError(t, err)
	require.Len(t, unindexed, 1)
	for idx := range proofs {
		txID := proofs[idx].AnchorTx.TxHash()
		rows, err := db.FetchAssetProofsByAnchorTx(ctx, txID[:])
		require.NoError(t, err)
		require.Empty(t, rows)
	}

	proofID := unindexed[0].ProofID

	// A proof-ID/file pairing whose bytes differ from the stored blob is
	// refused before any index write.
	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return IndexStoredAssetProof(
				ctx, q, proofID, indexedCases[0].file,
			)
		},
	)
	require.ErrorContains(t, err, "does not match indexed proof")
	unindexed, err = db.FetchUnindexedAssetProofs(ctx, 10)
	require.NoError(t, err)
	require.Len(t, unindexed, 1)

	err = executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return backfillProofProvenance(ctx, q)
		},
	)
	require.NoError(t, err)
	require.Contains(t, programmaticMigrations,
		uint(Migration72BackfillProofProvenance))

	unindexed, err = db.FetchUnindexedAssetProofs(ctx, 10)
	require.NoError(t, err)
	require.Empty(t, unindexed)
	for idx := range proofs {
		txID := proofs[idx].AnchorTx.TxHash()
		rows, err := db.FetchAssetProofsByAnchorTx(ctx, txID[:])
		require.NoError(t, err)
		if rawCase.present[txID] {
			require.Len(t, rows, 1)
		} else {
			require.Empty(t, rows)
		}
	}
}

// TestIndexedProofFileSingleProofBlob asserts that a historical bare
// single-proof blob indexes under its anchor transaction and is stored as
// written, so the index and its consumers share one reading of the blob.
func TestIndexedProofFileSingleProofBlob(t *testing.T) {
	t.Parallel()

	amount := uint64(1)
	bareProof, _ := proof.RandGenesisProofWithKey(
		t, asset.Normal, &amount, nil, true, nil, nil, nil, nil,
		asset.V0,
	)
	blob, err := bareProof.Bytes()
	require.NoError(t, err)
	require.True(t, proof.Blob(blob).IsSingleProof())

	indexed, err := NewIndexedProofFile(blob)
	require.NoError(t, err)
	require.Equal(t, proof.Blob(blob), indexed.proofBlob())
	require.Equal(
		t, []chainhash.Hash{bareProof.AnchorTx.TxHash()},
		indexed.anchorTxIDs(),
	)
}

func assertIndexedProofCase(ctx context.Context, q *sqlc.Queries,
	proofs []proof.Proof, testCase indexedProofCase) error {

	for proofIdx := range proofs {
		txID := proofs[proofIdx].AnchorTx.TxHash()
		rows, err := q.FetchAssetProofsByAnchorTx(ctx, txID[:])
		if err != nil {
			return err
		}

		expected := testCase.present[txID]
		if (len(rows) == 1) != expected {
			return fmt.Errorf(
				"tx %v present=%v, rows=%d", txID, expected,
				len(rows),
			)
		}

		if len(rows) != 1 {
			continue
		}

		if !bytes.Equal(rows[0].ProofFile, testCase.blob) {
			return fmt.Errorf("stored proof mismatch")
		}
	}

	return nil
}
