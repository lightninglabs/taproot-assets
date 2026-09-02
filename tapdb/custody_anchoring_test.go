package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// TestReceiveAnchoringPersistence drives received state through the
// receive site's persistence cycle: reconfirmation with refreshed
// block context (chain row and stored proof tip both updated), the
// potency-tier unconfirm, and act-level abandonment deleting the
// materialized asset. Every handler body is applied twice at its
// stage: phases coalesce and deliveries redeliver, so twice must
// equal once.
func TestReceiveAnchoringPersistence(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	// One received asset, anchored by the generator's anchor tx.
	assetGen := newAssetGenerator(t, 1, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		amt:         10,
	}})

	anchorTx := assetGen.anchorTxs[0]
	anchorTxid := anchorTx.TxHash()

	assets, err := assetsStore.FetchAllAssets(ctx, true, true, nil)
	require.NoError(t, err)
	require.Len(t, assets, 1)

	// The received proof file: its tip attests the anchor tx.
	tipProof := randProof(t, assets[0].Asset)
	tipProof.AnchorTx = *anchorTx
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

	// A completed address event keyed to the anchor transaction and
	// referencing the received asset and proof — the shape a real
	// receive leaves behind (the custody references live in
	// addr_event_proofs, and abandonment must shed them before it can
	// delete the rows they point at).
	testClock := clock.NewTestClock(time.Now())
	addrTx := NewTransactionExecutor(
		db, func(tx *sql.Tx) AddrBook {
			return db.WithTx(tx)
		},
	)
	addrBook := NewTapAddressBook(addrTx, chainParams, testClock)

	addrVersion := test.RandFlip(address.V0, address.V1)
	proofCourierAddr := address.RandProofCourierAddrForVersion(
		t, addrVersion,
	)
	addr, addrGen, addrGroup := address.RandAddrWithVersion(
		t, chainParams, proofCourierAddr, addrVersion,
	)
	err = addrTx.ExecTx(
		ctx, WriteTxOption(),
		insertFullAssetGen(ctx, addrGen, addrGroup),
	)
	require.NoError(t, err)
	require.NoError(t, addrBook.InsertAddrs(ctx, *addr))

	event, err := addrBook.GetOrCreateEvent(
		ctx, address.StatusCompleted, newTransfer(
			t, addr, &lndclient.Transaction{
				Tx:        anchorTx,
				Timestamp: time.Now(),
			}, 0,
		),
	)
	require.NoError(t, err)

	_, err = db.DB.ExecContext(
		ctx, "INSERT INTO addr_event_proofs "+
			"(addr_event_id, asset_proof_id, asset_id_fk) "+
			"SELECT $1, proof_id, asset_id FROM asset_proofs "+
			"WHERE asset_id = $2",
		event.ID, assetDBID,
	)
	require.NoError(t, err)

	reconfirm := func(blockHash chainhash.Hash, header wire.BlockHeader,
		merkle proof.TxMerkleProof, height uint32) error {

		return executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				return assetsStore.ApplyReceiveReconfirm(
					ctx, q, anchorTxid, blockHash, height,
					0, header, merkle,
				)
			},
		)
	}

	// Reconfirmation in block A: chain row and proof tip both carry
	// the new context. Applied twice: a redelivered confirmation
	// equals one, and in particular the proof file does not grow.
	blockHashA, headerA, merkleA := blockContextFor(t, anchorTx, 10)
	require.NoError(t, reconfirm(blockHashA, headerA, merkleA, 700))
	require.NoError(t, reconfirm(blockHashA, headerA, merkleA, 700))

	chainTx, err := db.FetchChainTx(ctx, anchorTxid[:])
	require.NoError(t, err)
	require.Equal(t, blockHashA[:], chainTx.BlockHash)

	blob, err := db.AssetProofBlobByAssetID(ctx, assetDBID)
	require.NoError(t, err)
	patched := &proof.File{}
	require.NoError(t, patched.Decode(bytes.NewReader(blob)))
	require.EqualValues(t, 1, patched.NumProofs())
	tip, err := patched.ProofAt(uint32(patched.NumProofs() - 1))
	require.NoError(t, err)
	require.Equal(t, blockHashA, tip.BlockHeader.BlockHash())
	require.EqualValues(t, 700, tip.BlockHeight)

	// Reconfirmation in block B (the re-org case) refreshes both
	// again — convergently.
	blockHashB, headerB, merkleB := blockContextFor(t, anchorTx, 11)
	require.NoError(t, reconfirm(blockHashB, headerB, merkleB, 701))

	blob, err = db.AssetProofBlobByAssetID(ctx, assetDBID)
	require.NoError(t, err)
	patched = &proof.File{}
	require.NoError(t, patched.Decode(bytes.NewReader(blob)))
	tip, err = patched.ProofAt(uint32(patched.NumProofs() - 1))
	require.NoError(t, err)
	require.Equal(t, blockHashB, tip.BlockHeader.BlockHash())

	// The potency-tier downgrade. Applied twice: a redelivered
	// downgrade equals one.
	unconfirm := func() error {
		return executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				return assetsStore.ApplyReceiveUnconfirm(
					ctx, q, anchorTxid,
				)
			},
		)
	}
	require.NoError(t, unconfirm())
	require.NoError(t, unconfirm())

	chainTx, err = db.FetchChainTx(ctx, anchorTxid[:])
	require.NoError(t, err)
	require.Nil(t, chainTx.BlockHash)

	// Act-level abandonment: the received asset never materialized
	// on the surviving chain. A redelivered abandonment converges to
	// the same end state.
	detected := int16(address.StatusTransactionDetected)
	abandon := func() error {
		return executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				return assetsStore.ApplyReceiveAbandonment(
					ctx, q, anchorTxid, detected,
				)
			},
		)
	}
	require.NoError(t, abandon())

	assets, err = assetsStore.FetchAllAssets(ctx, true, true, nil)
	require.NoError(t, err)
	require.Len(t, assets, 0)

	// The address event documents the failed receive: reset to the
	// detected status, its custody references shed.
	assertEventReset := func() {
		t.Helper()

		events, err := addrBook.QueryAddrEvents(
			ctx, address.EventQueryParams{},
		)
		require.NoError(t, err)
		require.Len(t, events, 1)
		require.Equal(
			t, address.StatusTransactionDetected,
			events[0].Status,
		)

		var numRefs int
		err = db.DB.QueryRowContext(
			ctx, "SELECT COUNT(*) FROM addr_event_proofs",
		).Scan(&numRefs)
		require.NoError(t, err)
		require.Zero(t, numRefs)
	}
	assertEventReset()

	require.NoError(t, abandon())

	assets, err = assetsStore.FetchAllAssets(ctx, true, true, nil)
	require.NoError(t, err)
	require.Len(t, assets, 0)

	chainTx, err = db.FetchChainTx(ctx, anchorTxid[:])
	require.NoError(t, err)
	require.Nil(t, chainTx.BlockHash)
	assertEventReset()
}

// TestReceiveAnchoringReconfirmBeforeProofs asserts that reconfirmation
// converges what exists and skips what doesn't: an anchored asset whose
// proof file is not yet materialized (the minting path's first witness
// delivery precedes the cultivator's proof writes, which that delivery
// itself unblocks) must not fail the delivery transaction.
func TestReceiveAnchoringReconfirmBeforeProofs(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	// One anchored asset with no stored proof file.
	assetGen := newAssetGenerator(t, 1, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		amt:         10,
	}})

	anchorTx := assetGen.anchorTxs[0]
	anchorTxid := anchorTx.TxHash()

	blockHash, header, merkle := blockContextFor(t, anchorTx, 10)
	err := executor.ExecTx(
		ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return assetsStore.ApplyReceiveReconfirm(
				ctx, q, anchorTxid, blockHash, 700, 0,
				header, merkle,
			)
		},
	)
	require.NoError(t, err)

	// The chain transaction's confirmation converged even though no
	// proof could be patched.
	chainTx, err := db.FetchChainTx(ctx, anchorTxid[:])
	require.NoError(t, err)
	require.Equal(t, blockHash[:], chainTx.BlockHash)
}

// TestReceiveAnchoringMultiLeaf drives the receive persistence cycle
// against two distinct assets anchored at one outpoint under one
// shared script key — the multi-asset shape a grouped-asset receive
// can materialize. Each leaf owns its rows and its proof file:
// reconfirmation must re-stamp both files without crossing them, and
// abandonment must compensate both.
func TestReceiveAnchoringMultiLeaf(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)
	ctx := context.Background()

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	// Two distinct assets at one anchor point, held by one shared
	// script key.
	sharedKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
		KeyLocator: keychain.KeyLocator{
			Family: test.RandInt[keychain.KeyFamily](),
			Index:  uint32(test.RandInt[int32]()),
		},
	})

	assetGen := newAssetGenerator(t, 2, 1)
	assetGen.genAssets(t, assetsStore, []assetDesc{{
		assetGen:    assetGen.assetGens[0],
		anchorPoint: assetGen.anchorPoints[0],
		scriptKey:   &sharedKey,
		amt:         10,
	}, {
		assetGen:    assetGen.assetGens[1],
		anchorPoint: assetGen.anchorPoints[0],
		scriptKey:   &sharedKey,
		amt:         20,
	}})

	anchorTx := assetGen.anchorTxs[0]
	anchorTxid := anchorTx.TxHash()

	assets, err := assetsStore.FetchAllAssets(ctx, true, true, nil)
	require.NoError(t, err)
	require.Len(t, assets, 2)
	require.NotEqual(t, assets[0].ID(), assets[1].ID())

	// Each leaf's proof file tip attests the anchor tx and carries
	// the leaf's own asset.
	type leaf struct {
		dbID    int64
		assetID asset.ID
	}
	leaves := make([]leaf, 0, 2)
	for _, a := range assets {
		tipProof := randProof(t, a.Asset)
		tipProof.AnchorTx = *anchorTx
		file, err := proof.NewFile(proof.V0, *tipProof)
		require.NoError(t, err)
		var buf bytes.Buffer
		require.NoError(t, file.Encode(&buf))

		var dbID int64
		assetID := a.ID()
		err = db.DB.QueryRowContext(
			ctx, "SELECT assets.asset_id FROM assets "+
				"JOIN genesis_assets ON assets.genesis_id = "+
				"genesis_assets.gen_asset_id "+
				"WHERE genesis_assets.asset_id = $1",
			assetID[:],
		).Scan(&dbID)
		require.NoError(t, err)
		require.NoError(t, db.UpsertAssetProofByID(
			ctx, ProofUpdateByID{
				AssetID:   dbID,
				ProofFile: buf.Bytes(),
			},
		))

		leaves = append(leaves, leaf{dbID: dbID, assetID: assetID})
	}

	reconfirm := func(blockHash chainhash.Hash, header wire.BlockHeader,
		merkle proof.TxMerkleProof, height uint32) error {

		return executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				return assetsStore.ApplyReceiveReconfirm(
					ctx, q, anchorTxid, blockHash, height,
					0, header, merkle,
				)
			},
		)
	}

	// Reconfirmation re-stamps both files without crossing them:
	// each tip keeps its own asset. Applied twice equals once.
	assertLeafFiles := func(wantBlock chainhash.Hash,
		wantHeight uint32) {

		t.Helper()

		for _, l := range leaves {
			blob, err := db.AssetProofBlobByAssetID(ctx, l.dbID)
			require.NoError(t, err)
			file := &proof.File{}
			require.NoError(
				t, file.Decode(bytes.NewReader(blob)),
			)
			require.EqualValues(t, 1, file.NumProofs())

			tip, err := file.ProofAt(0)
			require.NoError(t, err)
			require.Equal(
				t, wantBlock, tip.BlockHeader.BlockHash(),
			)
			require.EqualValues(t, wantHeight, tip.BlockHeight)
			require.Equal(t, l.assetID, tip.Asset.ID())
		}
	}

	blockHashA, headerA, merkleA := blockContextFor(t, anchorTx, 20)
	require.NoError(t, reconfirm(blockHashA, headerA, merkleA, 800))
	require.NoError(t, reconfirm(blockHashA, headerA, merkleA, 800))
	assertLeafFiles(blockHashA, 800)

	// Re-organized re-confirmation in a new block: both refresh.
	blockHashB, headerB, merkleB := blockContextFor(t, anchorTx, 21)
	require.NoError(t, reconfirm(blockHashB, headerB, merkleB, 801))
	assertLeafFiles(blockHashB, 801)

	// The potency-tier downgrade, applied twice.
	unconfirm := func() error {
		return executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				return assetsStore.ApplyReceiveUnconfirm(
					ctx, q, anchorTxid,
				)
			},
		)
	}
	require.NoError(t, unconfirm())
	require.NoError(t, unconfirm())

	chainTx, err := db.FetchChainTx(ctx, anchorTxid[:])
	require.NoError(t, err)
	require.Nil(t, chainTx.BlockHash)

	// Act-level abandonment compensates both leaves; applied twice
	// converges to the same end state.
	detected := int16(address.StatusTransactionDetected)
	abandon := func() error {
		return executor.ExecTx(
			ctx, WriteTxOption(), func(q *sqlc.Queries) error {
				return assetsStore.ApplyReceiveAbandonment(
					ctx, q, anchorTxid, detected,
				)
			},
		)
	}
	require.NoError(t, abandon())
	require.NoError(t, abandon())

	assets, err = assetsStore.FetchAllAssets(ctx, true, true, nil)
	require.NoError(t, err)
	require.Len(t, assets, 0)

	var numProofs int
	err = db.DB.QueryRowContext(
		ctx, "SELECT COUNT(*) FROM asset_proofs",
	).Scan(&numProofs)
	require.NoError(t, err)
	require.Zero(t, numProofs)
}
