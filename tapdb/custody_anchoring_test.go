package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
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

// completeLocator names an annotated proof by its snapshot's asset and
// outpoint, as the custodian names a received file by its tip.
func completeLocator(p *proof.AnnotatedProof) {
	p.Locator.AssetID = fn.Ptr(p.Asset.ID())
	p.Locator.ScriptKey = *p.Asset.ScriptKey.PubKey
	p.Locator.OutPoint = fn.Ptr(p.AssetSnapshot.OutPoint)
}

// snapshotVerifier answers every verification with a fixed snapshot,
// standing in for chain verification the store's tests cannot do.
type snapshotVerifier struct {
	snapshot *proof.AssetSnapshot
}

func (v snapshotVerifier) Verify(context.Context, io.Reader,
	proof.VerifierCtx, ...proof.VerifyOption) (*proof.AssetSnapshot,
	error) {

	return v.snapshot, nil
}

// TestStakeReceivedProofsAtomic pins the receive stake to the
// registration transaction: a registration that fails after the
// import rolls the import back with it, a registration that commits
// holds both the asset and the anchoring, and a re-driven registration
// attaches without importing twice.
func TestStakeReceivedProofsAtomic(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)
	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)
	registry := NewReorgRegistryStore(
		executor, clock.NewTestClock(time.Unix(1_000_000, 0)),
	)

	// A verified proof for an asset this database does not hold: the
	// scratch handle that built it is a different database. The
	// custodian names the proof by its tip; here the locator is
	// completed by hand.
	sharedKey := asset.NewScriptKeyBip86(keychain.KeyDescriptor{
		PubKey: test.RandPubKey(t),
	})
	_, annotated := NewDbHandle(t).AddRandomAssetProof(
		t, withScriptKey(sharedKey),
	)
	completeLocator(annotated)
	verified, err := proof.VerifyAnnotatedProofsWithVerifier(
		ctx, snapshotVerifier{snapshot: annotated.AssetSnapshot},
		proof.MockVerifierCtx, annotated,
	)
	require.NoError(t, err)
	locator := proof.Locator{ScriptKey: annotated.ScriptKey}

	anchorTxid := annotated.AnchorTx.TxHash()
	spec := testSpec(
		t, "receiver", annotated.AnchorTx.TxIn[0].PreviousOutPoint,
	)
	spec.MatchKey = anchorTxid.CloneBytes()
	spec.Phase1OnAttach = true

	var imported []proof.Blob
	stake := func(ctx context.Context, tx tapreorg.RegistryTx,
		_ tapreorg.AnchoringID) error {

		var err error
		imported, err = assetsStore.StakeReceivedProofs(
			ctx, tx, verified...,
		)

		return err
	}

	// A failure after the import, inside the transaction, leaves no
	// asset behind.
	boom := errors.New("registration fails after the stake")
	stakeThenFail := func(ctx context.Context, tx tapreorg.RegistryTx,
		id tapreorg.AnchoringID) error {

		if err := stake(ctx, tx, id); err != nil {
			return err
		}

		return boom
	}
	_, err = registry.Register(ctx, spec, 500, stakeThenFail, nil)
	require.ErrorIs(t, err, boom)
	require.Len(t, imported, 1)

	has, err := assetsStore.HasProof(ctx, locator)
	require.NoError(t, err)
	require.False(t, has, "rolled-back stake left the asset behind")

	existing, err := registry.LookupByMatchKey(
		ctx, "receiver", spec.MatchKey,
	)
	require.NoError(t, err)
	require.Nil(t, existing, "rolled-back stake left the anchoring")

	// The same registration, committing: asset and anchoring together.
	id, err := registry.Register(ctx, spec, 500, stake, nil)
	require.NoError(t, err)
	require.Len(t, imported, 1)

	has, err = assetsStore.HasProof(ctx, locator)
	require.NoError(t, err)
	require.True(t, has)

	// Re-driven, the registration attaches and imports nothing twice.
	again, err := registry.Register(ctx, spec, 500, stake, nil)
	require.NoError(t, err)
	require.Equal(t, id, again)
	require.Empty(t, imported)

	// A second leaf under the same script key — the multi-asset shape
	// a grouped receive materializes — is a different asset at a
	// different outpoint, and presence is judged on the whole
	// locator: it is imported, not mistaken for the first.
	_, sibling := NewDbHandle(t).AddRandomAssetProof(
		t, withScriptKey(sharedKey),
	)
	completeLocator(sibling)
	require.Equal(t, annotated.ScriptKey, sibling.ScriptKey)
	require.NotEqual(t, *annotated.AssetID, *sibling.AssetID)

	verifiedSibling, err := proof.VerifyAnnotatedProofsWithVerifier(
		ctx, snapshotVerifier{snapshot: sibling.AssetSnapshot},
		proof.MockVerifierCtx, sibling,
	)
	require.NoError(t, err)

	has, err = assetsStore.HasReceivedProof(ctx, sibling.Locator)
	require.NoError(t, err)
	require.False(t, has, "sibling leaf mistaken for the first")

	siblingTxid := sibling.AnchorTx.TxHash()
	siblingSpec := testSpec(
		t, "receiver", sibling.AnchorTx.TxIn[0].PreviousOutPoint,
	)
	siblingSpec.MatchKey = siblingTxid.CloneBytes()
	siblingSpec.Phase1OnAttach = true
	stakeSibling := func(ctx context.Context, tx tapreorg.RegistryTx,
		_ tapreorg.AnchoringID) error {

		var err error
		imported, err = assetsStore.StakeReceivedProofs(
			ctx, tx, verifiedSibling...,
		)

		return err
	}
	_, err = registry.Register(ctx, siblingSpec, 500, stakeSibling, nil)
	require.NoError(t, err)
	require.Len(t, imported, 1)

	for _, loc := range []proof.Locator{
		annotated.Locator, sibling.Locator,
	} {
		has, err = assetsStore.HasReceivedProof(ctx, loc)
		require.NoError(t, err)
		require.True(t, has)
	}
}
