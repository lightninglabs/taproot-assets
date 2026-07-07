package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/stretchr/testify/require"
)

// TestMintAnchoringAbandonment asserts the compensation for a minting
// batch the chain decided against: the minted asset rows are deleted,
// the genesis transaction is unconfirmed, and the batch parks in the
// sprout-cancelled state. Applied twice: phases coalesce and
// deliveries redeliver, so twice must equal once.
func TestMintAnchoringAbandonment(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	mintingStore, assetsStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	// Minted assets, anchored by the generator's genesis tx.
	assetGen := newAssetGenerator(t, 1, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		amt:         10,
	}})

	genesisTxid := assetGen.anchorTxs[0].TxHash()

	// The batch row the compensation cancels, keyed by its internal
	// key.
	mintingBatch := tapgarden.RandMintingBatch(t)
	require.NoError(t, mintingStore.CommitMintingBatch(
		ctx, mintingBatch,
		tapgarden.MockBindDataForBatch(mintingBatch),
	))
	rawBatchKey := mintingBatch.BatchKey.PubKey.SerializeCompressed()

	abandon := func() error {
		return executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				return assetsStore.ApplyMintAbandonment(
					ctx, q, genesisTxid, rawBatchKey,
				)
			},
		)
	}

	assertAbandoned := func() {
		t.Helper()

		assets, err := assetsStore.FetchAllAssets(
			ctx, true, true, nil,
		)
		require.NoError(t, err)
		require.Len(t, assets, 0)

		chainTx, err := db.FetchChainTx(ctx, genesisTxid[:])
		require.NoError(t, err)
		require.Nil(t, chainTx.BlockHash)

		var batchState int16
		err = db.DB.QueryRowContext(
			ctx, "SELECT batch_state FROM asset_minting_batches "+
				"batches JOIN internal_keys keys "+
				"ON batches.batch_id = keys.key_id "+
				"WHERE keys.raw_key = $1",
			rawBatchKey,
		).Scan(&batchState)
		require.NoError(t, err)
		require.EqualValues(
			t, tapgarden.BatchStateSproutCancelled, batchState,
		)
	}

	require.NoError(t, abandon())
	assertAbandoned()

	// A redelivered abandonment converges to the same end state.
	require.NoError(t, abandon())
	assertAbandoned()
}

// TestMintAnchoringConfirmCycle drives a minting batch's genesis
// transaction through the mint site's confirmation cycle against the
// mint-shaped fixture: confirmation before any proof file exists (the
// first witness delivery precedes the cultivator's proof writes),
// re-stamping of materialized proofs on a re-organized
// re-confirmation, and the potency-tier unconfirm. Every stage is
// applied twice: phases coalesce and deliveries redeliver, so twice
// must equal once.
func TestMintAnchoringConfirmCycle(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	mintingStore, assetsStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	// Minted assets, anchored by the generator's genesis tx, plus
	// the batch row.
	assetGen := newAssetGenerator(t, 1, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		amt:         10,
	}})

	genesisTx := assetGen.anchorTxs[0]
	genesisTxid := genesisTx.TxHash()

	mintingBatch := tapgarden.RandMintingBatch(t)
	require.NoError(t, mintingStore.CommitMintingBatch(
		ctx, mintingBatch,
		tapgarden.MockBindDataForBatch(mintingBatch),
	))

	reconfirm := func(blockHash chainhash.Hash, header wire.BlockHeader,
		merkle proof.TxMerkleProof, height uint32) error {

		return executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				return assetsStore.ApplyReceiveReconfirm(
					ctx, q, genesisTxid, blockHash,
					height, 0, header, merkle,
				)
			},
		)
	}

	// The first confirmation lands before the caretaker has written
	// any proof file: the chain row converges, nothing fails.
	// Applied twice equals once.
	blockHashA, headerA, merkleA := blockContextFor(t, genesisTx, 30)
	require.NoError(t, reconfirm(blockHashA, headerA, merkleA, 900))
	require.NoError(t, reconfirm(blockHashA, headerA, merkleA, 900))

	chainTx, err := db.FetchChainTx(ctx, genesisTxid[:])
	require.NoError(t, err)
	require.Equal(t, blockHashA[:], chainTx.BlockHash)

	// The minted asset survives the cycle untouched.
	assets, err := assetsStore.FetchAllAssets(ctx, true, true, nil)
	require.NoError(t, err)
	require.Len(t, assets, 1)

	// The caretaker writes the proof file (tip attesting the
	// genesis tx, stamped with block A).
	tipProof := randProof(t, assets[0].Asset)
	tipProof.AnchorTx = *genesisTx
	tipProof.BlockHeader = headerA
	tipProof.BlockHeight = 900
	file, err := proof.NewFile(proof.V0, *tipProof)
	require.NoError(t, err)
	var fileBuf bytes.Buffer
	require.NoError(t, file.Encode(&fileBuf))

	var assetDBID int64
	err = db.DB.QueryRowContext(
		ctx, "SELECT assets.asset_id FROM assets "+
			"JOIN script_keys ON assets.script_key_id = "+
			"script_keys.script_key_id "+
			"WHERE script_keys.tweaked_script_key = $1",
		assets[0].ScriptKey.PubKey.SerializeCompressed(),
	).Scan(&assetDBID)
	require.NoError(t, err)
	require.NoError(t, db.UpsertAssetProofByID(ctx, ProofUpdateByID{
		AssetID:   assetDBID,
		ProofFile: fileBuf.Bytes(),
	}))

	// A re-organized re-confirmation in block B refreshes the chain
	// row and re-stamps the stored proof tip, without growing the
	// file. Applied twice equals once.
	blockHashB, headerB, merkleB := blockContextFor(t, genesisTx, 31)
	require.NoError(t, reconfirm(blockHashB, headerB, merkleB, 901))
	require.NoError(t, reconfirm(blockHashB, headerB, merkleB, 901))

	chainTx, err = db.FetchChainTx(ctx, genesisTxid[:])
	require.NoError(t, err)
	require.Equal(t, blockHashB[:], chainTx.BlockHash)

	blob, err := db.AssetProofBlobByAssetID(ctx, assetDBID)
	require.NoError(t, err)
	patched := &proof.File{}
	require.NoError(t, patched.Decode(bytes.NewReader(blob)))
	require.EqualValues(t, 1, patched.NumProofs())
	tip, err := patched.ProofAt(0)
	require.NoError(t, err)
	require.Equal(t, blockHashB, tip.BlockHeader.BlockHash())
	require.EqualValues(t, 901, tip.BlockHeight)

	// The potency-tier downgrade withdraws the recorded
	// confirmation and reverses nothing else. Applied twice.
	unconfirm := func() error {
		return executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				return assetsStore.ApplyReceiveUnconfirm(
					ctx, q, genesisTxid,
				)
			},
		)
	}
	require.NoError(t, unconfirm())
	require.NoError(t, unconfirm())

	chainTx, err = db.FetchChainTx(ctx, genesisTxid[:])
	require.NoError(t, err)
	require.Nil(t, chainTx.BlockHash)

	assets, err = assetsStore.FetchAllAssets(ctx, true, true, nil)
	require.NoError(t, err)
	require.Len(t, assets, 1)

	// Re-confirmation after the downgrade converges back.
	require.NoError(t, reconfirm(blockHashB, headerB, merkleB, 901))
	chainTx, err = db.FetchChainTx(ctx, genesisTxid[:])
	require.NoError(t, err)
	require.Equal(t, blockHashB[:], chainTx.BlockHash)
}

// TestMintAbandonmentReleasesPreCommit asserts that a cancelled batch's
// supply pre-commitment stops being offered to the next commitment
// cycle.
//
// The pre-commitment outpoint lives on the batch's genesis
// transaction. When a conflicting spender is buried the mint site
// cancels the batch, and that outpoint ceases to exist on the
// surviving chain — so a commitment built on it could never be
// broadcast, and its own anchoring would never witness.
//
// Both terminal cancellations are covered: releasing the
// pre-commitment is a property of cancellation, not of the particular
// state the abandonment handler happens to set today.
func TestMintAbandonmentReleasesPreCommit(t *testing.T) {
	t.Parallel()

	cancelledStates := []tapgarden.BatchState{
		tapgarden.BatchStateSeedlingCancelled,
		tapgarden.BatchStateSproutCancelled,
	}

	for _, cancelled := range cancelledStates {
		t.Run(cancelled.String(), func(t *testing.T) {
			t.Parallel()

			assertPreCommitReleased(t, cancelled)
		})
	}
}

func assertPreCommitReleased(t *testing.T, cancelled tapgarden.BatchState) {
	db := NewTestDB(t)
	mintingStore, _ := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	batch := tapgarden.RandMintingBatch(t)
	require.NoError(t, mintingStore.CommitMintingBatch(
		ctx, batch, tapgarden.MockBindDataForBatch(batch),
	))
	rawBatchKey := batch.BatchKey.PubKey.SerializeCompressed()

	// The query reaches the pre-commitment through the batch's
	// genesis point and its anchor transaction, so both must exist
	// for the pre-condition below to mean anything.
	genesisTx := batch.GenesisPacket.Pkt.UnsignedTx
	genesisTxBytes, err := encodeTx(genesisTx)
	require.NoError(t, err)

	genesisTxID := genesisTx.TxHash()
	genesisTxDBID, err := db.UpsertChainTx(ctx, sqlc.UpsertChainTxParams{
		Txid:  genesisTxID[:],
		RawTx: genesisTxBytes,
	})
	require.NoError(t, err)

	genesisPointBytes, err := encodeOutpoint(batch.GenesisPacket.Pkt.
		UnsignedTx.TxIn[0].PreviousOutPoint)
	require.NoError(t, err)
	require.NoError(t, db.AnchorGenesisPoint(
		ctx, sqlc.AnchorGenesisPointParams{
			PrevOut:    genesisPointBytes,
			AnchorTxID: sqlInt64(genesisTxDBID),
		},
	))

	groupKey := test.RandBytes(32)
	keyDesc, _ := test.RandKeyDesc(t)
	internalKeyID, err := db.UpsertInternalKey(ctx, InternalKey{
		RawKey:    keyDesc.PubKey.SerializeCompressed(),
		KeyFamily: int32(keyDesc.Family),
		KeyIndex:  int32(keyDesc.Index),
	})
	require.NoError(t, err)

	outpoint, err := encodeOutpoint(wire.OutPoint{
		Hash:  genesisTxID,
		Index: 0,
	})
	require.NoError(t, err)

	_, err = db.UpsertMintSupplyPreCommit(ctx, UpsertBatchPreCommitParams{
		BatchKey:             rawBatchKey,
		TxOutputIndex:        0,
		TaprootInternalKeyID: internalKeyID,
		GroupKey:             groupKey,
		Outpoint:             outpoint,
	})
	require.NoError(t, err)

	// While the batch is live its pre-commitment is a legitimate
	// input for the next commitment cycle.
	unspent, err := db.FetchUnspentMintSupplyPreCommits(ctx, groupKey)
	require.NoError(t, err)
	require.Len(
		t, unspent, 1, "live batch's pre-commitment should be offered",
	)

	// The chain decided against the batch.
	require.NoError(t, executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return q.UpdateMintingBatchState(
				ctx, sqlc.UpdateMintingBatchStateParams{
					RawKey:     rawBatchKey,
					BatchState: int16(cancelled),
				},
			)
		},
	))

	unspent, err = db.FetchUnspentMintSupplyPreCommits(ctx, groupKey)
	require.NoError(t, err)
	require.Empty(
		t, unspent,
		"cancelled batch still offers its pre-commitment; the next "+
			"commitment would spend an outpoint that does not "+
			"exist",
	)
}
