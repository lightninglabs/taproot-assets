package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/stretchr/testify/require"
)

// customMintTx builds a mint transaction that spends the genesis outpoint
// as input 0, carries an extra input, and places the pre-commit at output
// index 1. That is the shape of a custom-genesis mint.
func customMintTx(t *testing.T, genesis wire.OutPoint) *wire.MsgTx {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: genesis})
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: test.RandOp(t)})
	tx.AddTxOut(&wire.TxOut{
		Value:    1000,
		PkScript: []byte{0x51, 0x20},
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    2000,
		PkScript: []byte{0x51, 0x21},
	})

	return tx
}

// transferSpendingMint spends a mint output and does not spend the genesis
// outpoint.
func transferSpendingMint(mint *wire.MsgTx) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  mint.TxHash(),
			Index: 0,
		},
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    900,
		PkScript: []byte{0x00},
	})

	return tx
}

// anchorProof wraps an anchor transaction in the proof upsertAssetGen reads.
func anchorProof(t *testing.T, genesis asset.Genesis,
	anchor wire.MsgTx) *proof.Proof {

	t.Helper()

	proofAsset := asset.RandAsset(t, asset.Normal)
	proofAsset.Genesis = genesis
	proofAsset.GroupKey = nil
	proofAsset.PrevWitnesses = nil

	return &proof.Proof{
		BlockHeader: wire.BlockHeader{
			Timestamp: time.Unix(1, 0),
		},
		BlockHeight: 100,
		AnchorTx:    anchor,
		Asset:       *proofAsset,
	}
}

// genesisAnchorID returns the chain_txns id stored for the genesis outpoint.
func genesisAnchorID(t *testing.T, db sqlc.Querier,
	genesis wire.OutPoint) int64 {

	t.Helper()

	ctx := context.Background()
	encoded, err := encodeOutpoint(genesis)
	require.NoError(t, err)

	points, err := db.GenesisPoints(ctx)
	require.NoError(t, err)

	for _, point := range points {
		if bytes.Equal(point.PrevOut, encoded) {
			require.True(t, point.AnchorTxID.Valid)
			return point.AnchorTxID.Int64
		}
	}

	t.Fatalf("genesis outpoint %v not found", genesis)
	return 0
}

// TestTransferProofKeepsCustomGenesisPreCommit upserts a custom-genesis
// mint proof and then a transfer proof. The genesis anchor and the
// unspent pre-commit query must still return the mint transaction and
// the caller-selected output index.
func TestTransferProofKeepsCustomGenesisPreCommit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := NewTestDB(t)

	genesis := asset.RandGenesis(t, asset.Normal)
	mintTx := customMintTx(t, genesis.FirstPrevOut)
	const preCommitIdx = int32(1)

	_, err := upsertAssetGen(
		ctx, db, genesis, nil,
		anchorProof(t, genesis, *mintTx),
	)
	require.NoError(t, err)

	mintTxid := mintTx.TxHash()
	mintChain, err := db.FetchChainTx(ctx, mintTxid[:])
	require.NoError(t, err)
	require.Equal(t, mintChain.TxnID, genesisAnchorID(
		t, db, genesis.FirstPrevOut,
	))

	groupPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	groupKey := schnorr.SerializePubKey(groupPriv.PubKey())
	insertMintPreCommit(t, db, genesis, mintTx, preCommitIdx, groupKey)

	transfer := transferSpendingMint(mintTx)
	_, err = upsertAssetGen(
		ctx, db, genesis, nil,
		anchorProof(t, genesis, *transfer),
	)
	require.NoError(t, err)

	require.Equal(t, mintChain.TxnID, genesisAnchorID(
		t, db, genesis.FirstPrevOut,
	))

	rows, err := db.FetchUnspentMintSupplyPreCommits(ctx, groupKey)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, preCommitIdx, rows[0].TxOutputIndex)

	var got wire.MsgTx
	err = got.Deserialize(bytes.NewReader(rows[0].RawTx))
	require.NoError(t, err)
	require.Equal(t, mintTx.TxHash(), got.TxHash())
}

// insertMintPreCommit stores a local mint pre-commit at the given index
// of mintTx, bound to the genesis already inserted for that mint.
func insertMintPreCommit(t *testing.T, db sqlc.Querier, genesis asset.Genesis,
	mintTx *wire.MsgTx, outIdx int32, groupKey []byte) {

	t.Helper()

	ctx := context.Background()
	batchDesc, _ := test.RandKeyDesc(t)
	batchKey := batchDesc.PubKey.SerializeCompressed()
	batchID, err := db.UpsertInternalKey(ctx, sqlc.UpsertInternalKeyParams{
		RawKey:    batchKey,
		KeyFamily: int32(batchDesc.Family),
		KeyIndex:  int32(batchDesc.Index),
	})
	require.NoError(t, err)

	genBytes, err := encodeOutpoint(genesis.FirstPrevOut)
	require.NoError(t, err)
	genID, err := db.UpsertGenesisPoint(ctx, genBytes)
	require.NoError(t, err)

	err = db.NewMintingBatch(ctx, sqlc.NewMintingBatchParams{
		BatchID:          batchID,
		HeightHint:       100,
		CreationTimeUnix: time.Now(),
	})
	require.NoError(t, err)

	_, err = db.BindMintingBatchWithTx(
		ctx, sqlc.BindMintingBatchWithTxParams{
			RawKey:    batchKey,
			GenesisID: sqlInt64(genID),
		},
	)
	require.NoError(t, err)

	internalDesc, _ := test.RandKeyDesc(t)
	internalID, err := db.UpsertInternalKey(
		ctx, sqlc.UpsertInternalKeyParams{
			RawKey: internalDesc.PubKey.SerializeCompressed(),
			KeyFamily: int32(
				internalDesc.KeyLocator.Family,
			),
			KeyIndex: int32(internalDesc.KeyLocator.Index),
		},
	)
	require.NoError(t, err)

	outpoint := wire.OutPoint{
		Hash:  mintTx.TxHash(),
		Index: uint32(outIdx),
	}
	var buf bytes.Buffer
	err = wire.WriteOutPoint(&buf, 0, 0, &outpoint)
	require.NoError(t, err)

	_, err = db.UpsertMintSupplyPreCommit(
		ctx, sqlc.UpsertMintSupplyPreCommitParams{
			TxOutputIndex:        outIdx,
			TaprootInternalKeyID: internalID,
			GroupKey:             groupKey,
			Outpoint:             buf.Bytes(),
			BatchKey:             batchKey,
		},
	)
	require.NoError(t, err)
}

// confirmChainTx sets block metadata on a stored chain transaction.
func confirmChainTx(t *testing.T, db sqlc.Querier, tx *wire.MsgTx) {
	t.Helper()

	txid := tx.TxHash()
	blockHash := test.RandHash()
	err := db.ConfirmChainAnchorTx(
		context.Background(), sqlc.ConfirmChainAnchorTxParams{
			Txid: txid[:],
			BlockHeight: sql.NullInt32{
				Int32: 100,
				Valid: true,
			},
			BlockHash: blockHash[:],
			TxIndex: sql.NullInt32{
				Int32: 0,
				Valid: true,
			},
		},
	)
	require.NoError(t, err)
}

// upsertChainTx inserts a transaction and returns its chain_txns id.
func upsertChainTx(t *testing.T, db sqlc.Querier, tx *wire.MsgTx) int64 {
	t.Helper()

	raw, err := encodeTx(tx)
	require.NoError(t, err)
	txid := tx.TxHash()
	id, err := db.UpsertChainTx(
		context.Background(), sqlc.UpsertChainTxParams{
			Txid:  txid[:],
			RawTx: raw,
		},
	)
	require.NoError(t, err)

	return id
}

// anchorGenesisTo points the genesis outpoint at a chain_txns row.
func anchorGenesisTo(t *testing.T, db sqlc.Querier, genesis wire.OutPoint,
	chainID int64) {

	t.Helper()

	encoded, err := encodeOutpoint(genesis)
	require.NoError(t, err)
	err = db.AnchorGenesisPoint(
		context.Background(), sqlc.AnchorGenesisPointParams{
			PrevOut: encoded,
			AnchorTxID: sql.NullInt64{
				Int64: chainID,
				Valid: true,
			},
		},
	)
	require.NoError(t, err)
}

// TestRepairGenesisAnchor restores a retargeted anchor from the mint
// transaction still stored in chain_txns, leaves a genesis with no
// spender alone, and resolves ambiguous multi-spender cases.
func TestRepairGenesisAnchor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("restores mint spend", func(t *testing.T) {
		db := NewTestDB(t)
		genesis := asset.RandGenesis(t, asset.Normal)
		mintTx := customMintTx(t, genesis.FirstPrevOut)

		_, err := upsertAssetGen(
			ctx, db, genesis, nil,
			anchorProof(t, genesis, *mintTx),
		)
		require.NoError(t, err)
		mintID := genesisAnchorID(t, db, genesis.FirstPrevOut)

		bogus := wire.NewMsgTx(2)
		bogus.AddTxIn(&wire.TxIn{PreviousOutPoint: test.RandOp(t)})
		bogus.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
		bogusID := upsertChainTx(t, db, bogus)
		anchorGenesisTo(t, db, genesis.FirstPrevOut, bogusID)
		require.Equal(t, bogusID, genesisAnchorID(
			t, db, genesis.FirstPrevOut,
		))

		require.NoError(t, repairGenesisAnchors(ctx, db))
		require.Equal(t, mintID, genesisAnchorID(
			t, db, genesis.FirstPrevOut,
		))

		require.NoError(t, repairGenesisAnchors(ctx, db))
		require.Equal(t, mintID, genesisAnchorID(
			t, db, genesis.FirstPrevOut,
		))
	})

	t.Run("no spender is left unchanged", func(t *testing.T) {
		db := NewTestDB(t)
		genesis := asset.RandGenesis(t, asset.Normal)
		encoded, err := encodeOutpoint(genesis.FirstPrevOut)
		require.NoError(t, err)
		_, err = db.UpsertGenesisPoint(ctx, encoded)
		require.NoError(t, err)

		bogus := wire.NewMsgTx(2)
		bogus.AddTxIn(&wire.TxIn{PreviousOutPoint: test.RandOp(t)})
		bogus.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
		bogusID := upsertChainTx(t, db, bogus)
		anchorGenesisTo(t, db, genesis.FirstPrevOut, bogusID)

		require.NoError(t, repairGenesisAnchors(ctx, db))
		require.Equal(t, bogusID, genesisAnchorID(
			t, db, genesis.FirstPrevOut,
		))
	})

	t.Run("prefers mint batch spender", func(t *testing.T) {
		db := NewTestDB(t)
		genesis := asset.RandGenesis(t, asset.Normal)
		mintTx := customMintTx(t, genesis.FirstPrevOut)

		_, err := upsertAssetGen(
			ctx, db, genesis, nil,
			anchorProof(t, genesis, *mintTx),
		)
		require.NoError(t, err)
		mintID := genesisAnchorID(t, db, genesis.FirstPrevOut)

		groupPriv, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		groupKey := schnorr.SerializePubKey(groupPriv.PubKey())
		insertMintPreCommit(t, db, genesis, mintTx, 1, groupKey)

		transfer := transferSpendingMint(mintTx)
		transfer.AddTxIn(&wire.TxIn{
			PreviousOutPoint: genesis.FirstPrevOut,
		})
		transferID := upsertChainTx(t, db, transfer)

		bogus := wire.NewMsgTx(2)
		bogus.AddTxIn(&wire.TxIn{PreviousOutPoint: test.RandOp(t)})
		bogus.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
		bogusID := upsertChainTx(t, db, bogus)
		anchorGenesisTo(t, db, genesis.FirstPrevOut, bogusID)
		require.Equal(t, bogusID, genesisAnchorID(
			t, db, genesis.FirstPrevOut,
		))

		require.NoError(t, repairGenesisAnchors(ctx, db))
		require.Equal(t, mintID, genesisAnchorID(
			t, db, genesis.FirstPrevOut,
		))
		require.NotEqual(t, transferID, mintID)
	})

	t.Run("prefers confirmed spender", func(t *testing.T) {
		db := NewTestDB(t)
		genesis := asset.RandGenesis(t, asset.Normal)
		encoded, err := encodeOutpoint(genesis.FirstPrevOut)
		require.NoError(t, err)
		_, err = db.UpsertGenesisPoint(ctx, encoded)
		require.NoError(t, err)

		unconfirmed := wire.NewMsgTx(2)
		unconfirmed.AddTxIn(&wire.TxIn{
			PreviousOutPoint: genesis.FirstPrevOut,
		})
		unconfirmed.AddTxOut(&wire.TxOut{
			Value: 100, PkScript: []byte{0x01},
		})
		upsertChainTx(t, db, unconfirmed)

		confirmed := wire.NewMsgTx(2)
		confirmed.AddTxIn(&wire.TxIn{
			PreviousOutPoint: genesis.FirstPrevOut,
		})
		confirmed.AddTxOut(&wire.TxOut{
			Value: 200, PkScript: []byte{0x02},
		})
		confirmedID := upsertChainTx(t, db, confirmed)
		confirmChainTx(t, db, confirmed)

		bogus := wire.NewMsgTx(2)
		bogus.AddTxIn(&wire.TxIn{PreviousOutPoint: test.RandOp(t)})
		bogus.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
		bogusID := upsertChainTx(t, db, bogus)
		anchorGenesisTo(t, db, genesis.FirstPrevOut, bogusID)

		require.NoError(t, repairGenesisAnchors(ctx, db))
		require.Equal(t, confirmedID, genesisAnchorID(
			t, db, genesis.FirstPrevOut,
		))
	})

	t.Run("ambiguous spenders leave anchor unchanged", func(t *testing.T) {
		db := NewTestDB(t)
		genesis := asset.RandGenesis(t, asset.Normal)
		encoded, err := encodeOutpoint(genesis.FirstPrevOut)
		require.NoError(t, err)
		_, err = db.UpsertGenesisPoint(ctx, encoded)
		require.NoError(t, err)

		bogus := wire.NewMsgTx(2)
		bogus.AddTxIn(&wire.TxIn{PreviousOutPoint: test.RandOp(t)})
		bogus.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
		bogusID := upsertChainTx(t, db, bogus)
		anchorGenesisTo(t, db, genesis.FirstPrevOut, bogusID)

		for i := 0; i < 2; i++ {
			spender := wire.NewMsgTx(2)
			spender.AddTxIn(&wire.TxIn{
				PreviousOutPoint: genesis.FirstPrevOut,
			})
			spender.AddTxOut(&wire.TxOut{
				Value:    int64(100 + i),
				PkScript: []byte{byte(i + 1)},
			})
			upsertChainTx(t, db, spender)
		}

		require.NoError(t, repairGenesisAnchors(ctx, db))
		require.Equal(t, bogusID, genesisAnchorID(
			t, db, genesis.FirstPrevOut,
		))
	})
}

// signedCommitTx inserts a signed commitment that spends prevOut and
// returns that transaction.
func signedCommitTx(t *testing.T, h *supplyCommitTestHarness,
	prevOut wire.OutPoint) *wire.MsgTx {

	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: prevOut})
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})

	internalKey, _ := test.RandKeyDesc(t)
	err := h.commitMachine.InsertSignedCommitTx(
		h.ctx, h.assetSpec, supplycommit.SupplyCommitTxn{
			Txn:         tx,
			InternalKey: internalKey,
			OutputKey:   test.RandPubKey(t),
			OutputIndex: 0,
		},
	)
	require.NoError(t, err)

	return tx
}

// TestAbandonInvalidUnconfirmedSupplyCommit drops a broadcast commitment
// that spends neither the mint pre-commit nor a confirmed commitment,
// and keeps the pending update. A commitment that spends the real
// pre-commit is left in CommitBroadcastState.
func TestAbandonInvalidUnconfirmedSupplyCommit(t *testing.T) {
	t.Parallel()

	t.Run("abandons unknown input", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t)
		batchKey, _, mintTx, _, _ := h.addTestMintingBatch()
		_, _ = h.addTestMintAnchorUniCommitment(
			batchKey, sql.NullInt64{}, mintTx.TxHash(),
		)

		err := h.commitMachine.InsertPendingUpdate(
			h.ctx, h.assetSpec, h.randMintEvent(),
		)
		require.NoError(t, err)

		signedCommitTx(t, h, test.RandOp(t))
		h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})

		err = abandonInvalidUnconfirmedSupplyCommits(h.ctx, h.db)
		require.NoError(t, err)

		h.assertCurrentStateIs(&supplycommit.UpdatesPendingState{})
		transition := h.assertPendingTransitionExists()
		require.False(t, transition.NewCommitmentID.Valid)
		require.False(t, transition.PendingCommitTxnID.Valid)
		require.False(t, transition.Frozen)

		fetched := h.currentTransition().UnwrapOrFail(t)
		require.Nil(t, fetched.NewCommitment.Txn)
		require.Len(t, fetched.PendingUpdates, 1)

		left, err := h.db.FetchUnconfirmedBroadcastSupplyCommits(
			h.ctx,
		)
		require.NoError(t, err)
		require.Empty(t, left)
	})

	t.Run("keeps pre-commit spend", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t)
		batchKey, _, mintTx, _, _ := h.addTestMintingBatch()
		_, preOut := h.addTestMintAnchorUniCommitment(
			batchKey, sql.NullInt64{}, mintTx.TxHash(),
		)

		err := h.commitMachine.InsertPendingUpdate(
			h.ctx, h.assetSpec, h.randMintEvent(),
		)
		require.NoError(t, err)

		signedCommitTx(t, h, preOut)
		err = abandonInvalidUnconfirmedSupplyCommits(h.ctx, h.db)
		require.NoError(t, err)

		h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})
		transition := h.assertPendingTransitionExists()
		require.True(t, transition.NewCommitmentID.Valid)
	})
}

// confirmBroadcastTx writes block metadata onto the signed commitment
// transaction. The state machine stays in CommitBroadcastState.
func confirmBroadcastTx(h *supplyCommitTestHarness, tx *wire.MsgTx) {
	h.t.Helper()

	raw, err := encodeTx(tx)
	require.NoError(h.t, err)
	txid := tx.TxHash()
	transition := h.assertPendingTransitionExists()
	require.True(h.t, transition.PendingCommitTxnID.Valid)
	h.confirmChainTx(transition.PendingCommitTxnID.Int64, txid[:], raw)
}

// insertCustomGenesisPreCommit stores a mint whose pre-commit output is
// at outIdx, then points the genesis anchor at that mint transaction.
// The returned outpoint is mint_txid:outIdx.
func insertCustomGenesisPreCommit(t *testing.T, h *supplyCommitTestHarness,
	outIdx int32) (wire.OutPoint, *wire.MsgTx, int64) {

	t.Helper()

	genesis := asset.RandGenesis(t, asset.Normal)
	mintTx := customMintTx(t, genesis.FirstPrevOut)
	raw, err := encodeTx(mintTx)
	require.NoError(t, err)
	mintTxid := mintTx.TxHash()
	mintChainID, err := h.db.UpsertChainTx(
		h.ctx, sqlc.UpsertChainTxParams{
			Txid:  mintTxid[:],
			RawTx: raw,
		},
	)
	require.NoError(t, err)

	insertMintPreCommit(
		t, h.db, genesis, mintTx, outIdx, h.groupKeyBytes,
	)

	encoded, err := encodeOutpoint(genesis.FirstPrevOut)
	require.NoError(t, err)
	err = h.db.AnchorGenesisPoint(
		h.ctx, sqlc.AnchorGenesisPointParams{
			PrevOut: encoded,
			AnchorTxID: sql.NullInt64{
				Int64: mintChainID,
				Valid: true,
			},
		},
	)
	require.NoError(t, err)

	preOut := wire.OutPoint{
		Hash:  mintTxid,
		Index: uint32(outIdx),
	}
	return preOut, mintTx, mintChainID
}

// retargetGenesisAnchor points the mint's genesis outpoint at a transfer
// that does not spend it. That is the anchor-retarget corruption.
func retargetGenesisAnchor(t *testing.T, h *supplyCommitTestHarness,
	mintTx *wire.MsgTx) int64 {

	t.Helper()

	transfer := transferSpendingMint(mintTx)
	raw, err := encodeTx(transfer)
	require.NoError(t, err)
	txid := transfer.TxHash()
	transferID, err := h.db.UpsertChainTx(
		h.ctx, sqlc.UpsertChainTxParams{
			Txid:  txid[:],
			RawTx: raw,
		},
	)
	require.NoError(t, err)

	encoded, err := encodeOutpoint(mintTx.TxIn[0].PreviousOutPoint)
	require.NoError(t, err)
	err = h.db.AnchorGenesisPoint(
		h.ctx, sqlc.AnchorGenesisPointParams{
			PrevOut: encoded,
			AnchorTxID: sql.NullInt64{
				Int64: transferID,
				Valid: true,
			},
		},
	)
	require.NoError(t, err)

	return transferID
}

// assertGenesisAnchorID asserts the genesis outpoint's anchor_tx_id.
func assertGenesisAnchorID(t *testing.T, h *supplyCommitTestHarness,
	genesis wire.OutPoint, chainID int64) {

	t.Helper()

	encoded, err := encodeOutpoint(genesis)
	require.NoError(t, err)
	points, err := h.db.GenesisPoints(h.ctx)
	require.NoError(t, err)

	for _, point := range points {
		if bytes.Equal(point.PrevOut, encoded) {
			require.True(t, point.AnchorTxID.Valid)
			require.Equal(t, chainID, point.AnchorTxID.Int64)
			return
		}
	}

	t.Fatalf("genesis outpoint %v not found", genesis)
}

// TestMigration74CommitmentSafety checks the abandon rule against a
// confirmed commitment and against an unconfirmed commitment that spends
// a confirmed commitment outpoint.
func TestMigration74CommitmentSafety(t *testing.T) {
	t.Parallel()

	t.Run("keeps confirmed commitment", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t)
		batchKey, _, mintTx, _, _ := h.addTestMintingBatch()
		_, _ = h.addTestMintAnchorUniCommitment(
			batchKey, sql.NullInt64{}, mintTx.TxHash(),
		)

		err := h.commitMachine.InsertPendingUpdate(
			h.ctx, h.assetSpec, h.randMintEvent(),
		)
		require.NoError(t, err)

		// The input is not a pre-commit. Confirmation is what
		// keeps the row: the migration only considers commitments
		// whose chain transaction has no block hash.
		tx := signedCommitTx(t, h, test.RandOp(t))
		confirmBroadcastTx(h, tx)

		err = repairGenesisAnchorMigration(h.ctx, h.db)
		require.NoError(t, err)

		h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})
		kept := h.assertPendingTransitionExists()
		require.True(t, kept.NewCommitmentID.Valid)
		_, err = h.fetchCommitmentByID(kept.NewCommitmentID.Int64)
		require.NoError(t, err)

		left, err := h.db.FetchUnconfirmedBroadcastSupplyCommits(
			h.ctx,
		)
		require.NoError(t, err)
		require.Empty(t, left)
	})

	t.Run("keeps mempool spend of confirmed commit", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t)

		prior := wire.NewMsgTx(2)
		prior.AddTxIn(&wire.TxIn{
			PreviousOutPoint: test.RandOp(t),
		})
		prior.AddTxOut(&wire.TxOut{
			Value:    1000,
			PkScript: []byte{0x51},
		})
		raw, err := encodeTx(prior)
		require.NoError(t, err)
		txid := prior.TxHash()
		chainID, err := h.db.UpsertChainTx(
			h.ctx, sqlc.UpsertChainTxParams{
				Txid:  txid[:],
				RawTx: raw,
			},
		)
		require.NoError(t, err)
		h.addTestSupplyCommitment(chainID, txid[:], raw, true)

		spent := wire.OutPoint{Hash: txid, Index: 0}
		err = h.commitMachine.InsertPendingUpdate(
			h.ctx, h.assetSpec, h.randMintEvent(),
		)
		require.NoError(t, err)
		signedCommitTx(t, h, spent)

		err = repairGenesisAnchorMigration(h.ctx, h.db)
		require.NoError(t, err)

		h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})
		kept := h.assertPendingTransitionExists()
		require.True(t, kept.NewCommitmentID.Valid)
		require.True(t, kept.PendingCommitTxnID.Valid)
	})

	t.Run("keeps custom genesis pre-commit spend", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t)
		const preCommitIdx = int32(1)
		preOut, mintTx, mintChainID := insertCustomGenesisPreCommit(
			t, h, preCommitIdx,
		)
		require.Equal(t, uint32(preCommitIdx), preOut.Index)

		transferID := retargetGenesisAnchor(t, h, mintTx)
		assertGenesisAnchorID(
			t, h, mintTx.TxIn[0].PreviousOutPoint, transferID,
		)

		err := h.commitMachine.InsertPendingUpdate(
			h.ctx, h.assetSpec, h.randMintEvent(),
		)
		require.NoError(t, err)
		signedCommitTx(t, h, preOut)

		err = repairGenesisAnchorMigration(h.ctx, h.db)
		require.NoError(t, err)

		assertGenesisAnchorID(
			t, h, mintTx.TxIn[0].PreviousOutPoint, mintChainID,
		)
		h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})
		kept := h.assertPendingTransitionExists()
		require.True(t, kept.NewCommitmentID.Valid)

		rows, err := h.db.FetchUnspentMintSupplyPreCommits(
			h.ctx, h.groupKeyBytes,
		)
		require.NoError(t, err)
		require.NotEmpty(t, rows)
		require.Equal(t, preCommitIdx, rows[0].TxOutputIndex)
		var got wire.MsgTx
		err = got.Deserialize(bytes.NewReader(rows[0].RawTx))
		require.NoError(t, err)
		require.Equal(t, mintTx.TxHash(), got.TxHash())
	})
}
