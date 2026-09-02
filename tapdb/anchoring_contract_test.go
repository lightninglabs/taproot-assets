package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// The compensation contract.
//
// Every anchoring site stakes local state on a chain outcome and must
// withdraw that stake when the outcome goes against it. The per-site
// tests drive rich phase sequences — soft unconfirmation, abandonment,
// redelivery — but each builds the same minimal world: one asset, one
// address event, one transfer, one site per transaction.
//
// Deployments are not minimal. A transfer re-anchors passive assets
// into its own outputs, a completed receive leaves custody references
// behind, and a self-send stakes one transaction from two sites at
// once. The properties below generate those shapes rather than
// hand-building them, and assert the contract that every compensation
// handler owes its caller:
//
//   - Totality: a handler never fails. It runs inside the watcher's
//     delivery transaction, so an error rolls back the phase
//     acknowledgement too and the anchoring retries forever.
//   - Convergence: applying a phase twice equals applying it once.
//   - Scope: compensation withdraws exactly the state its own site
//     staked — no more, no less.

// contractWorld is one generated ledger state staked on a single
// anchor transaction.
type contractWorld struct {
	anchorTx   *wire.MsgTx
	anchorTxid chainhash.Hash

	// assetDBIDs are the asset rows anchored in the transaction's
	// outputs, in generation order.
	assetDBIDs []int64

	// passiveDBIDs is the subset of assetDBIDs carrying a
	// passive_assets reference: assets that a transfer re-anchored
	// into an output of this transaction. They are staked by the
	// porter's transfer, never by a receive.
	passiveDBIDs []int64

	// eventDBIDs is the subset of assetDBIDs carrying an
	// addr_event_proofs custody reference from a completed address
	// event.
	eventDBIDs []int64

	// outputDBIDs is the complement of passiveDBIDs: assets the
	// transfer materialized as its own outputs, staked by the
	// porter (and, when carrying a custody reference, by a receive
	// too — the self-send shape).
	outputDBIDs []int64

	// transferID is the asset_transfers row staked on the anchor
	// transaction, owning the outputs and passive references.
	transferID int64
}

// contractFixture holds the shared, expensive scaffolding. A fresh
// database costs seconds of migrations, so it is built once and every
// iteration scopes itself to its own anchor transaction.
type contractFixture struct {
	// db is the backend-agnostic handle: the fixture only needs raw
	// SQL and the generated querier, both of which BaseDB provides
	// for SQLite and Postgres alike.
	db          *BaseDB
	assetsStore *AssetStore
	executor    *TransactionExecutor[*sqlc.Queries]
	addrBook    *TapAddressBook
	addrTx      *TransactionExecutor[AddrBook]

	// anchorNonce keeps each iteration's anchor transaction distinct
	// on the shared database.
	anchorNonce uint64
}

func newContractFixture(t *testing.T) *contractFixture {
	db := NewTestDB(t)
	_, assetsStore := newAssetStoreFromDB(db.BaseDB)

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)
	addrTx := NewTransactionExecutor(
		db, func(tx *sql.Tx) AddrBook {
			return db.WithTx(tx)
		},
	)
	addrBook := NewTapAddressBook(
		addrTx, chainParams, clock.NewTestClock(time.Now()),
	)

	return &contractFixture{
		db:          db.BaseDB,
		assetsStore: assetsStore,
		executor:    executor,
		addrBook:    addrBook,
		addrTx:      addrTx,
	}
}

// assetDBID resolves an asset's row ID from its script key.
func (f *contractFixture) assetDBID(t require.TestingT,
	scriptKey []byte) int64 {

	var id int64
	err := f.db.DB.QueryRowContext(
		context.Background(), "SELECT assets.asset_id FROM assets "+
			"JOIN script_keys ON assets.script_key_id = "+
			"script_keys.script_key_id "+
			"WHERE script_keys.tweaked_script_key = $1", scriptKey,
	).Scan(&id)
	require.NoError(t, err)

	return id
}

// liveAssets reports which of the given asset rows still exist.
func (f *contractFixture) liveAssets(t require.TestingT,
	ids []int64) map[int64]bool {

	live := make(map[int64]bool, len(ids))
	for _, id := range ids {
		var count int
		err := f.db.DB.QueryRowContext(
			context.Background(),
			"SELECT COUNT(*) FROM assets WHERE asset_id = $1", id,
		).Scan(&count)
		require.NoError(t, err)

		live[id] = count > 0
	}

	return live
}

// genContractWorld draws a ledger state: a unique anchor transaction,
// one to three assets anchored in it, and — per asset — an optional
// passive-asset reference and an optional completed address event.
//
// The anchor transaction is made unique per iteration so that the
// txid-prefix scoping used by the receive site isolates iterations
// from one another on the shared database.
func genContractWorld(rt *rapid.T, t *testing.T,
	f *contractFixture) *contractWorld {

	ctx := context.Background()

	numAssets := rapid.IntRange(1, 3).Draw(rt, "numAssets")

	// A unique anchor transaction for this iteration. The generator
	// builds deterministic anchors, which would collide across
	// iterations on the shared database, so we register our own and
	// let genAssets resolve it through the generator's maps.
	//
	// The nonce is a counter rather than a draw: the anchor's
	// identity is not part of any property here, only the shape of
	// the state staked on it. Drawing it would let a shrunk replay
	// reuse an earlier iteration's transaction and inherit its rows,
	// which reports failures that do not reproduce in isolation.
	f.anchorNonce++
	var nonce [8]byte
	binary.BigEndian.PutUint64(nonce[:], f.anchorNonce)

	anchorTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{
			PkScript: append(
				bytes.Repeat([]byte{0xab}, 26), nonce[:]...,
			),
			Value: 1000,
		}},
	}
	anchorPoint := wire.OutPoint{Hash: anchorTx.TxHash(), Index: 0}

	assetGen := newAssetGenerator(t, numAssets, 1)
	assetGen.anchorPointsToTx[anchorPoint] = anchorTx
	assetGen.anchorPointsToHeights[anchorPoint] = 500

	descs := make([]assetDesc, numAssets)
	for i := 0; i < numAssets; i++ {
		descs[i] = assetDesc{
			assetGen:    assetGen.assetGens[i],
			anchorPoint: anchorPoint,
			amt:         uint64(10 + i),
		}
	}
	newAssets, _ := assetGen.genAssets(t, f.assetsStore, descs)

	w := &contractWorld{
		anchorTx:   anchorTx,
		anchorTxid: anchorTx.TxHash(),
	}

	suffixes := make(map[int64][]byte, len(newAssets))
	for i, a := range newAssets {
		dbID := f.assetDBID(
			t, a.ScriptKey.PubKey.SerializeCompressed(),
		)
		w.assetDBIDs = append(w.assetDBIDs, dbID)

		// Store a proof file for the asset: both the receive and
		// porter compensation paths read and rewrite these. The
		// bare tip proof doubles as the transfer output's proof
		// suffix, which is how the porter's compensation
		// identifies the asset a given output materialized.
		tipProof := randProof(t, a)
		tipProof.AnchorTx = *anchorTx
		file, err := proof.NewFile(proof.V0, *tipProof)
		require.NoError(t, err)

		var fileBuf bytes.Buffer
		require.NoError(t, file.Encode(&fileBuf))
		require.NoError(t, f.db.UpsertAssetProofByID(
			ctx, ProofUpdateByID{
				AssetID:   dbID,
				ProofFile: fileBuf.Bytes(),
			},
		))

		var suffixBuf bytes.Buffer
		require.NoError(t, tipProof.Encode(&suffixBuf))
		suffixes[dbID] = suffixBuf.Bytes()

		label := fmt.Sprintf("passive%d", i)
		if rapid.Bool().Draw(rt, label) {
			w.passiveDBIDs = append(w.passiveDBIDs, dbID)
		} else {
			w.outputDBIDs = append(w.outputDBIDs, dbID)
		}

		label = fmt.Sprintf("event%d", i)
		if rapid.Bool().Draw(rt, label) {
			w.eventDBIDs = append(w.eventDBIDs, dbID)
		}
	}

	w.transferID = f.addTransfer(t, w, suffixes)
	for _, dbID := range w.eventDBIDs {
		f.addAddrEventRef(t, anchorTx, dbID)
	}

	return w
}

// addTransfer records the asset_transfers row staked on the anchor
// transaction: one materialized output per non-passive asset — the
// state a confirmation application leaves behind — and a
// passive_assets reference per passive one, the state
// reAnchorPassiveAssets leaves behind.
func (f *contractFixture) addTransfer(t *testing.T, w *contractWorld,
	suffixes map[int64][]byte) int64 {

	ctx := context.Background()

	_, err := f.db.DB.ExecContext(
		ctx, "INSERT INTO asset_transfers "+
			"(height_hint, anchor_txn_id, transfer_time_unix) "+
			"SELECT 1, txn_id, CURRENT_TIMESTAMP FROM chain_txns "+
			"WHERE txid = $1", w.anchorTxid[:],
	)
	require.NoError(t, err)

	var transferID int64
	err = f.db.DB.QueryRowContext(
		ctx, "SELECT id FROM asset_transfers ORDER BY id DESC LIMIT 1",
	).Scan(&transferID)
	require.NoError(t, err)

	for _, dbID := range w.passiveDBIDs {
		_, err = f.db.DB.ExecContext(
			ctx, "INSERT INTO passive_assets "+
				"(transfer_id, asset_id, new_anchor_utxo, "+
				"script_key, asset_version) "+
				"SELECT $1, $2, assets.anchor_utxo_id, "+
				"script_keys.tweaked_script_key, 0 "+
				"FROM assets "+
				"JOIN script_keys ON assets.script_key_id = "+
				"script_keys.script_key_id "+
				"WHERE assets.asset_id = $2",
			transferID, dbID,
		)
		require.NoError(t, err)
	}

	for idx, dbID := range w.outputDBIDs {
		_, err = f.db.DB.ExecContext(
			ctx, "INSERT INTO asset_transfer_outputs "+
				"(transfer_id, anchor_utxo, script_key, "+
				"script_key_local, amount, asset_version, "+
				"proof_suffix, num_passive_assets, "+
				"output_type, position) "+
				"SELECT $1, assets.anchor_utxo_id, "+
				"assets.script_key_id, TRUE, assets.amount, "+
				"0, $2, 0, 0, $3 "+
				"FROM assets WHERE assets.asset_id = $4",
			transferID, suffixes[dbID], idx, dbID,
		)
		require.NoError(t, err)
	}

	return transferID
}

// custodyRefs counts the addr_event_proofs references pointing at the
// given asset row.
func (f *contractFixture) custodyRefs(t require.TestingT, dbID int64) int {
	var count int
	err := f.db.DB.QueryRowContext(
		context.Background(),
		"SELECT COUNT(*) FROM addr_event_proofs WHERE asset_id_fk = $1",
		dbID,
	).Scan(&count)
	require.NoError(t, err)

	return count
}

// addAddrEventRef attaches a completed address event holding a custody
// reference to the given asset — the state a finished receive leaves.
func (f *contractFixture) addAddrEventRef(t *testing.T,
	anchorTx *wire.MsgTx, dbID int64) {

	ctx := context.Background()

	addrVersion := test.RandFlip(address.V0, address.V1)
	courierAddr := address.RandProofCourierAddrForVersion(t, addrVersion)
	addr, addrGen, addrGroup := address.RandAddrWithVersion(
		t, chainParams, courierAddr, addrVersion,
	)
	require.NoError(t, f.addrTx.ExecTx(
		ctx, WriteTxOption(),
		insertFullAssetGen(ctx, addrGen, addrGroup),
	))
	require.NoError(t, f.addrBook.InsertAddrs(ctx, *addr))

	_, err := f.addrBook.GetOrCreateEvent(
		ctx, address.StatusCompleted, newTransfer(
			t, addr, &lndclient.Transaction{
				Tx:        anchorTx,
				Timestamp: time.Now(),
			}, 0,
		),
	)
	require.NoError(t, err)

	_, err = f.db.DB.ExecContext(
		ctx, "INSERT INTO addr_event_proofs "+
			"(addr_event_id, asset_proof_id, asset_id_fk) "+
			"SELECT (SELECT id FROM addr_events "+
			"ORDER BY id DESC LIMIT 1), proof_id, asset_id "+
			"FROM asset_proofs WHERE asset_id = $1", dbID,
	)
	require.NoError(t, err)
}

// TestPorterCompensationContract asserts the compensation contract for
// the porter's abandonment over generated ledger states, including the
// self-send shape: a completed receive holds custody references to the
// very asset rows the porter materialized, and on a self-send both
// sites stake the same transaction and compensate in whichever order
// delivery happens to run.
func TestPorterCompensationContract(t *testing.T) {
	t.Parallel()

	f := newContractFixture(t)
	ctx := context.Background()

	rapid.Check(t, func(rt *rapid.T) {
		w := genContractWorld(rt, t, f)

		detected := int16(address.StatusTransactionDetected)
		porterAbandon := func() error {
			return f.executor.ExecTx(
				ctx, WriteTxOption(),
				func(q *sqlc.Queries) error {
					return f.assetsStore.
						ApplyTransferAbandonment(
							ctx, q, w.anchorTxid,
						)
				},
			)
		}
		receiveAbandon := func() error {
			return f.executor.ExecTx(
				ctx, WriteTxOption(),
				func(q *sqlc.Queries) error {
					return f.assetsStore.
						ApplyReceiveAbandonment(
							ctx, q, w.anchorTxid,
							detected,
						)
				},
			)
		}

		// Totality, in whichever order the two sites' deliveries
		// run. Either handler failing rolls back its phase
		// acknowledgement and retries forever.
		porterFirst := rapid.Bool().Draw(rt, "porterFirst")
		if porterFirst {
			require.NoError(rt, porterAbandon(), "porter first")
			require.NoError(rt, receiveAbandon(), "receive second")
		} else {
			require.NoError(rt, receiveAbandon(), "receive first")
			require.NoError(rt, porterAbandon(), "porter second")
		}

		// Scope: the materialized outputs are withdrawn, the
		// passive holdings survive (they pre-existed the
		// transfer), and no custody reference is left dangling.
		live := f.liveAssets(rt, w.assetDBIDs)
		for _, dbID := range w.outputDBIDs {
			require.False(
				rt, live[dbID],
				"abandonment left materialized output %d",
				dbID,
			)
		}
		for _, dbID := range w.passiveDBIDs {
			require.True(
				rt, live[dbID],
				"abandonment deleted passive asset %d", dbID,
			)
		}
		for _, dbID := range w.assetDBIDs {
			require.Zero(
				rt, f.custodyRefs(rt, dbID),
				"custody reference left on asset %d", dbID,
			)
		}

		// Convergence: replaying both handlers reaches the same
		// state.
		require.NoError(rt, porterAbandon(), "porter redelivery")
		require.NoError(rt, receiveAbandon(), "receive redelivery")

		after := f.liveAssets(rt, w.assetDBIDs)
		require.Equal(
			rt, live, after,
			"abandonment is not convergent under redelivery",
		)
	})
}

// TestAnchoringCompensationContract asserts the compensation contract
// over generated ledger states.
//
// Totality is the property that matters most: these handlers run
// inside the watcher's delivery transaction, so a returned error rolls
// back the phase acknowledgement along with the compensation and the
// anchoring is retried forever without ever converging.
func TestAnchoringCompensationContract(t *testing.T) {
	t.Parallel()

	f := newContractFixture(t)
	ctx := context.Background()

	rapid.Check(t, func(rt *rapid.T) {
		w := genContractWorld(rt, t, f)

		detected := int16(address.StatusTransactionDetected)
		abandon := func() error {
			return f.executor.ExecTx(
				ctx, WriteTxOption(),
				func(q *sqlc.Queries) error {
					return f.assetsStore.
						ApplyReceiveAbandonment(
							ctx, q, w.anchorTxid,
							detected,
						)
				},
			)
		}

		// Totality.
		require.NoError(
			rt, abandon(),
			"receive abandonment must not fail; it runs inside "+
				"the delivery transaction",
		)

		// Scope: a passive asset was re-anchored into this
		// transaction's outputs by a transfer. It is the
		// porter's stake, not the receive's, and the receive
		// must leave it alone.
		live := f.liveAssets(rt, w.assetDBIDs)
		for _, dbID := range w.passiveDBIDs {
			require.True(
				rt, live[dbID],
				"receive abandonment deleted passive asset "+
					"%d, which it never staked", dbID,
			)
		}

		// Convergence: a redelivered abandonment reaches the
		// same state.
		require.NoError(rt, abandon(), "redelivered abandonment failed")

		after := f.liveAssets(rt, w.assetDBIDs)
		require.Equal(
			rt, live, after,
			"abandonment is not convergent under redelivery",
		)
	})
}
