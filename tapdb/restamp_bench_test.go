package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/stretchr/testify/require"
)

// benchAnchor stamps each transaction into its own fabricated block at the
// next height, so a proof file carries well-formed block context without a
// chain behind it.
type benchAnchor struct {
	height uint32
}

func (a *benchAnchor) anchor(tx *wire.MsgTx) (*wire.MsgBlock, uint32) {
	a.height++

	return &wire.MsgBlock{
		Header: wire.BlockHeader{
			MerkleRoot: tx.TxHash(),
			Timestamp:  time.Unix(1_700_000_000, 0),
			Nonce:      a.height,
		},
		Transactions: []*wire.MsgTx{tx},
	}, a.height
}

// benchSnapshot describes a file's tip the way the importer needs it,
// without verifying the file.
func benchSnapshot(b *testing.B, tip *proof.Proof) *proof.AssetSnapshot {
	b.Helper()

	tapCommitment, err := commitment.FromAssets(nil, &tip.Asset)
	require.NoError(b, err)

	return &proof.AssetSnapshot{
		Asset:             &tip.Asset,
		OutPoint:          tip.OutPoint(),
		AnchorBlockHash:   tip.BlockHeader.BlockHash(),
		AnchorBlockHeight: tip.BlockHeight,
		AnchorTx:          &tip.AnchorTx,
		OutputIndex:       tip.InclusionProof.OutputIndex,
		InternalKey:       tip.InclusionProof.InternalKey,
		ScriptRoot:        tapCommitment,
	}
}

// benchRestampWallet stores the given number of proof files, each of the
// given depth, that share every proof but their tip. It returns the shared
// genesis proof and the total size of the stored blobs.
func benchRestampWallet(b *testing.B, store *AssetStore, files,
	depth int) (proof.Proof, int64) {

	b.Helper()
	require.GreaterOrEqual(b, depth, 2)

	anchor := &benchAnchor{height: 100}
	genesisProof, holderPriv := proof.RandAnchoredGenesisProof(
		b, anchor.anchor,
	)
	prefix := proof.NewEmptyFile(proof.V0)
	require.NoError(b, prefix.AppendProof(genesisProof))
	for idx := 1; idx < depth-1; idx++ {
		_, holderPriv, _ = proof.AppendRandTransfer(
			b, prefix, holderPriv, anchor.anchor,
		)
	}
	var prefixBytes bytes.Buffer
	require.NoError(b, prefix.Encode(&prefixBytes))

	ctx := context.Background()
	var totalBytes int64
	for idx := 0; idx < files; idx++ {
		file, err := proof.Blob(prefixBytes.Bytes()).AsFile()
		require.NoError(b, err)
		proof.AppendRandTransfer(b, file, holderPriv, anchor.anchor)
		tip, err := file.LastProof()
		require.NoError(b, err)

		var encoded bytes.Buffer
		require.NoError(b, file.Encode(&encoded))
		totalBytes += int64(encoded.Len())

		require.NoError(b, store.ImportProofs(
			ctx, proof.MockVerifierCtx, false,
			&proof.AnnotatedProof{
				Locator: proof.Locator{
					AssetID:   fn.Ptr(tip.Asset.ID()),
					ScriptKey: *tip.Asset.ScriptKey.PubKey,
					OutPoint:  fn.Ptr(tip.OutPoint()),
				},
				Blob:          encoded.Bytes(),
				AssetSnapshot: benchSnapshot(b, tip),
			},
		))
	}

	return genesisProof, totalBytes
}

// BenchmarkRestampStoredProofs measures a transaction-wide repair as a
// re-confirmation delivery runs it: every stored file containing the
// re-confirmed transaction is decoded, restamped, re-encoded and
// re-indexed inside one write transaction. The re-confirmed transaction
// is the genesis every file shares, so each op rewrites every file in
// full. Bytes per op are the stored blobs the op rewrites.
func BenchmarkRestampStoredProofs(b *testing.B) {
	for _, files := range []int{1, 10, 100, 1000} {
		for _, depth := range []int{2, 10, 30} {
			name := fmt.Sprintf("files=%d/depth=%d", files, depth)
			b.Run(name, func(b *testing.B) {
				benchRestampStoredProofs(b, files, depth)
			})
		}
	}
}

func benchRestampStoredProofs(b *testing.B, files, depth int) {
	db := NewTestDB(b)
	_, store := newAssetStoreFromDB(db.BaseDB)
	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)
	genesisProof, totalBytes := benchRestampWallet(
		b, store, files, depth,
	)
	merkle, err := proof.NewTxMerkleProof(
		[]*wire.MsgTx{&genesisProof.AnchorTx}, 0,
	)
	require.NoError(b, err)
	ctx := context.Background()

	b.SetBytes(totalBytes)
	b.ResetTimer()
	for idx := 0; idx < b.N; idx++ {
		// A fresh nonce each op keeps every stored file stale, so
		// each op rewrites rather than confirms.
		header := genesisProof.BlockHeader
		header.Nonce = uint32(1_000_000 + idx)
		blockCtx, err := proof.NewVerifiedBlockContext(
			&genesisProof.AnchorTx, header,
			genesisProof.BlockHeight, *merkle,
		)
		require.NoError(b, err)

		require.NoError(b, executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				restamped, err := store.RestampStoredProofs(
					ctx, q, blockCtx,
				)
				if err != nil {
					return err
				}
				if len(restamped) != files {
					return fmt.Errorf("restamped %d of %d "+
						"files", len(restamped), files)
				}

				return nil
			},
		))
	}
}
