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
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapgarden"
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

	// inputDBIDs are the asset rows the transfer spent: holdings at
	// prior anchors, marked spent, each referenced by one of the
	// transfer's asset_transfer_inputs rows.
	inputDBIDs []int64

	// inputPoints are the anchor outpoints of inputDBIDs, in order.
	inputPoints []wire.OutPoint

	// foreclosure is the transaction the chain decided for, when the
	// abandonment has a known cause. It consumes a drawn subset of
	// inputPoints, which compensation must then leave spent. Nil
	// models an abandonment without a cause to bound the reversal.
	foreclosure *wire.MsgTx

	// foreclosed marks the input rows whose outpoint foreclosure
	// consumed.
	foreclosed map[int64]bool
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

// worldOption adjusts the shape genContractWorld draws.
type worldOption func(*worldConfig)

type worldConfig struct {
	events bool
}

// withoutEvents draws a world with no address events: the shape a
// minting batch leaves, whose assets no receive ever completed.
func withoutEvents() worldOption {
	return func(cfg *worldConfig) {
		cfg.events = false
	}
}

// genContractWorld draws a ledger state: a unique anchor transaction,
// one to three assets anchored in it, and — per asset — an optional
// passive-asset reference and an optional completed address event;
// plus up to two spent inputs at prior anchors for the transaction's
// transfer, and an optional foreclosing transaction consuming a subset
// of them.
//
// The anchor transaction is made unique per iteration so that the
// txid-prefix scoping used by the receive site isolates iterations
// from one another on the shared database.
func genContractWorld(rt *rapid.T, t *testing.T, f *contractFixture,
	opts ...worldOption) *contractWorld {

	cfg := &worldConfig{events: true}
	for _, opt := range opts {
		opt(cfg)
	}

	ctx := context.Background()

	numAssets := rapid.IntRange(1, 3).Draw(rt, "numAssets")
	numInputs := rapid.IntRange(0, 2).Draw(rt, "numInputs")

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

	assetGen := newAssetGenerator(t, numAssets+numInputs, 1)
	assetGen.anchorPointsToTx[anchorPoint] = anchorTx
	assetGen.anchorPointsToHeights[anchorPoint] = 500

	descs := make([]assetDesc, 0, numAssets+numInputs)
	for i := 0; i < numAssets; i++ {
		descs = append(descs, assetDesc{
			assetGen:    assetGen.assetGens[i],
			anchorPoint: anchorPoint,
			amt:         uint64(10 + i),
		})
	}

	// The transfer's inputs: one holding per prior anchor
	// transaction, already spent, as the pending write leaves them.
	// Distinct anchors keep the outpoints distinct, so a foreclosure
	// can consume some inputs and not others.
	inputPoints := make([]wire.OutPoint, numInputs)
	for i := 0; i < numInputs; i++ {
		pkScript := bytes.Repeat([]byte{0xcd}, 25)
		pkScript = append(pkScript, byte(i))
		pkScript = append(pkScript, nonce[:]...)

		priorTx := &wire.MsgTx{
			TxIn: []*wire.TxIn{{}},
			TxOut: []*wire.TxOut{{
				PkScript: pkScript,
				Value:    1000,
			}},
		}
		point := wire.OutPoint{Hash: priorTx.TxHash(), Index: 0}
		assetGen.anchorPointsToTx[point] = priorTx
		assetGen.anchorPointsToHeights[point] = 400
		inputPoints[i] = point

		descs = append(descs, assetDesc{
			assetGen:    assetGen.assetGens[numAssets+i],
			anchorPoint: point,
			amt:         uint64(20 + i),
			spent:       true,
		})
	}
	newAssets, _ := assetGen.genAssets(t, f.assetsStore, descs)

	w := &contractWorld{
		anchorTx:    anchorTx,
		anchorTxid:  anchorTx.TxHash(),
		inputPoints: inputPoints,
		foreclosed:  make(map[int64]bool),
	}

	suffixes := make(map[int64][]byte, numAssets)
	for i, a := range newAssets[:numAssets] {
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
		if cfg.events && rapid.Bool().Draw(rt, label) {
			w.eventDBIDs = append(w.eventDBIDs, dbID)
		}
	}

	inputs := newAssets[numAssets:]
	for _, a := range inputs {
		w.inputDBIDs = append(w.inputDBIDs, f.assetDBID(
			t, a.ScriptKey.PubKey.SerializeCompressed(),
		))
	}

	w.transferID = f.addTransfer(t, w, suffixes, inputs)
	for _, dbID := range w.eventDBIDs {
		f.addAddrEventRef(t, anchorTx, dbID)
	}

	// The foreclosing transaction, when the loss has a cause: it
	// consumes a drawn subset of the transfer's inputs.
	if numInputs > 0 && rapid.Bool().Draw(rt, "foreclosure") {
		w.foreclosure = &wire.MsgTx{
			TxOut: []*wire.TxOut{{
				PkScript: bytes.Repeat([]byte{0xef}, 34),
				Value:    500,
			}},
		}
		for i, dbID := range w.inputDBIDs {
			label := fmt.Sprintf("foreclosed%d", i)
			if !rapid.Bool().Draw(rt, label) {
				continue
			}

			w.foreclosure.TxIn = append(
				w.foreclosure.TxIn, &wire.TxIn{
					PreviousOutPoint: w.inputPoints[i],
				},
			)
			w.foreclosed[dbID] = true
		}
	}

	return w
}

// addTransfer records the asset_transfers row staked on the anchor
// transaction: one materialized output per non-passive asset — the
// state a confirmation application leaves behind — a passive_assets
// reference per passive one, the state reAnchorPassiveAssets leaves
// behind, and one asset_transfer_inputs row per spent input, the
// state the pending write leaves behind.
func (f *contractFixture) addTransfer(t *testing.T, w *contractWorld,
	suffixes map[int64][]byte, inputs []*asset.Asset) int64 {

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

	for i, in := range inputs {
		anchorPoint, err := encodeOutpoint(w.inputPoints[i])
		require.NoError(t, err)
		assetID := in.ID()

		_, err = f.db.DB.ExecContext(
			ctx, "INSERT INTO asset_transfer_inputs "+
				"(transfer_id, anchor_point, asset_id, "+
				"script_key, amount) "+
				"VALUES ($1, $2, $3, $4, $5)",
			transferID, anchorPoint, assetID[:],
			in.ScriptKey.PubKey.SerializeCompressed(),
			int64(in.Amount),
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

// count runs a COUNT(*) query against the fixture's database.
func (f *contractFixture) count(t require.TestingT, query string,
	args ...any) int {

	var n int
	err := f.db.DB.QueryRowContext(
		context.Background(), query, args...,
	).Scan(&n)
	require.NoError(t, err)

	return n
}

// witnessRows counts the witness rows stored for the given asset.
func (f *contractFixture) witnessRows(t require.TestingT, dbID int64) int {
	return f.count(
		t, "SELECT COUNT(*) FROM asset_witnesses WHERE asset_id = $1",
		dbID,
	)
}

// proofRows counts the proof files stored for the given asset.
func (f *contractFixture) proofRows(t require.TestingT, dbID int64) int {
	return f.count(
		t, "SELECT COUNT(*) FROM asset_proofs WHERE asset_id = $1",
		dbID,
	)
}

// eventsWithStatus counts the address events keyed to the anchor
// transaction that record the given status.
func (f *contractFixture) eventsWithStatus(t require.TestingT,
	txid chainhash.Hash, status address.Status) int {

	return f.count(
		t, "SELECT COUNT(*) FROM addr_events "+
			"WHERE status = $1 AND chain_txn_id IN "+
			"(SELECT txn_id FROM chain_txns WHERE txid = $2)",
		int16(status), txid[:],
	)
}

// transferAbandoned reports a transfer's abandoned flag.
func (f *contractFixture) transferAbandoned(t require.TestingT,
	transferID int64) bool {

	var abandoned bool
	err := f.db.DB.QueryRowContext(
		context.Background(),
		"SELECT abandoned FROM asset_transfers WHERE id = $1",
		transferID,
	).Scan(&abandoned)
	require.NoError(t, err)

	return abandoned
}

// addMintingBatch records a minting batch in the broadcast state,
// keyed to a fresh internal key, and returns the raw batch key.
func (f *contractFixture) addMintingBatch(t *testing.T) []byte {
	ctx := context.Background()

	rawKey := test.RandPubKey(t).SerializeCompressed()
	_, err := f.db.DB.ExecContext(
		ctx, "INSERT INTO internal_keys (raw_key, key_family, "+
			"key_index) VALUES ($1, 0, 0)", rawKey,
	)
	require.NoError(t, err)

	_, err = f.db.DB.ExecContext(
		ctx, "INSERT INTO asset_minting_batches "+
			"(batch_id, batch_state, height_hint, "+
			"creation_time_unix) "+
			"SELECT key_id, $1, 1, CURRENT_TIMESTAMP "+
			"FROM internal_keys WHERE raw_key = $2",
		int16(tapgarden.BatchStateBroadcast), rawKey,
	)
	require.NoError(t, err)

	return rawKey
}

// batchState reports the recorded state of the batch with the given
// raw key.
func (f *contractFixture) batchState(t require.TestingT,
	rawKey []byte) tapgarden.BatchState {

	var state int16
	err := f.db.DB.QueryRowContext(
		context.Background(),
		"SELECT batch_state FROM asset_minting_batches "+
			"JOIN internal_keys ON batch_id = key_id "+
			"WHERE raw_key = $1", rawKey,
	).Scan(&state)
	require.NoError(t, err)

	return tapgarden.BatchState(state)
}

// assertOutputsWithdrawn asserts that the assets a compensation must
// delete are gone along with everything that hung off them: the rows,
// their witnesses and their proof files.
func (f *contractFixture) assertOutputsWithdrawn(t require.TestingT,
	w *contractWorld, where string) {

	live := f.liveAssets(t, w.assetDBIDs)
	for _, dbID := range w.outputDBIDs {
		require.False(
			t, live[dbID], "%s: materialized asset %d survived",
			where, dbID,
		)
		require.Zero(
			t, f.witnessRows(t, dbID),
			"%s: witnesses of asset %d survived", where, dbID,
		)
		require.Zero(
			t, f.proofRows(t, dbID),
			"%s: proof of asset %d survived", where, dbID,
		)
	}
}

// assertReceiveCompensated asserts the state a receive abandonment
// owes its caller: the materialized assets withdrawn, every address
// event keyed to the transaction returned to the reset status with no
// custody reference left, and the transaction unconfirmed. numEvents
// is the number of address events keyed to the transaction.
func (f *contractFixture) assertReceiveCompensated(t require.TestingT,
	w *contractWorld, numEvents int, where string) {

	f.assertOutputsWithdrawn(t, w, where)

	for _, dbID := range w.assetDBIDs {
		require.Zero(
			t, f.custodyRefs(t, dbID),
			"%s: custody reference left on asset %d", where, dbID,
		)
	}
	require.Zero(
		t, f.eventsWithStatus(t, w.anchorTxid, address.StatusCompleted),
		"%s: a completed receive survived", where,
	)
	require.Equal(
		t, numEvents, f.eventsWithStatus(
			t, w.anchorTxid, address.StatusTransactionDetected,
		),
		"%s: address events not reset to the given status", where,
	)
	require.Nil(
		t, f.chainConfirmed(t, w.anchorTxid),
		"%s: the discarded transaction is still confirmed", where,
	)
}

// assertTransferCompensated asserts the state a transfer abandonment
// owes its caller: the materialized outputs withdrawn, every input
// released except those the foreclosing transaction consumed, the
// transfer marked superseded and abandoned, and the transaction
// unconfirmed.
func (f *contractFixture) assertTransferCompensated(t require.TestingT,
	w *contractWorld, where string) {

	f.assertOutputsWithdrawn(t, w, where)

	for _, dbID := range w.inputDBIDs {
		require.Equal(
			t, w.foreclosed[dbID], f.assetSpent(t, dbID),
			"%s: input %d spent flag; a foreclosed input stays "+
				"spent, any other is released", where, dbID,
		)
	}
	require.True(
		t, f.transferSuperseded(t, w.transferID),
		"%s: abandoned transfer not superseded", where,
	)
	require.True(
		t, f.transferAbandoned(t, w.transferID),
		"%s: abandoned transfer not marked abandoned", where,
	)
	require.Nil(
		t, f.chainConfirmed(t, w.anchorTxid),
		"%s: the discarded transaction is still confirmed", where,
	)
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
							w.foreclosure,
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

		// The staked state before the loss, so that the assertions
		// below are not vacuous: the transaction is confirmed, the
		// inputs are spent and every output's proof is stored.
		require.NotNil(rt, f.chainConfirmed(rt, w.anchorTxid))
		for _, dbID := range w.inputDBIDs {
			require.True(rt, f.assetSpent(rt, dbID))
		}
		for _, dbID := range w.outputDBIDs {
			require.Equal(rt, 1, f.proofRows(rt, dbID))
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

		// Scope: the porter's stake is withdrawn in full — the
		// materialized outputs, the spent inputs (except those the
		// foreclosure took), the transfer's liveness and the
		// transaction's confirmation — the passive holdings survive
		// (they pre-existed the transfer), and no custody reference
		// is left dangling.
		f.assertTransferCompensated(rt, w, "abandonment")

		live := f.liveAssets(rt, w.assetDBIDs)
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
		f.assertTransferCompensated(rt, w, "redelivery")
	})
}

// TestAnchoringCompensationContract asserts the compensation contract
// for the receive's abandonment over generated ledger states.
//
// Totality is the property that matters most: these handlers run
// inside the watcher's delivery transaction, so a returned error rolls
// back the phase acknowledgement along with the compensation and the
// anchoring is retried forever without ever converging.
//
// The scope assertions cover the receive's own stake: the assets it
// materialized, the events it completed and the confirmation it
// recorded. Passive holdings are the porter's transfer's, not the
// receive's, and are left out.
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

		// The staked state before the loss, so that the assertions
		// below are not vacuous: the transaction is confirmed,
		// every output's proof is stored, and each event records a
		// completed receive.
		require.NotNil(rt, f.chainConfirmed(rt, w.anchorTxid))
		for _, dbID := range w.outputDBIDs {
			require.Equal(rt, 1, f.proofRows(rt, dbID))
		}
		numEvents := f.eventsWithStatus(
			rt, w.anchorTxid, address.StatusCompleted,
		)
		require.Equal(rt, len(w.eventDBIDs), numEvents)

		// Totality.
		require.NoError(
			rt, abandon(),
			"receive abandonment must not fail; it runs inside "+
				"the delivery transaction",
		)

		// Scope: the receive's stake is withdrawn in full.
		f.assertReceiveCompensated(rt, w, numEvents, "abandonment")

		// Convergence: a redelivered abandonment reaches the
		// same state.
		live := f.liveAssets(rt, w.assetDBIDs)
		require.NoError(rt, abandon(), "redelivered abandonment failed")

		after := f.liveAssets(rt, w.assetDBIDs)
		require.Equal(
			rt, live, after,
			"abandonment is not convergent under redelivery",
		)
		f.assertReceiveCompensated(rt, w, numEvents, "redelivery")
	})
}

// TestMintCompensationContract asserts the compensation contract for
// the mint's abandonment over generated ledger states. A minted batch
// stakes the shape a receive does — asset rows anchored in the genesis
// transaction's outputs, with their proofs — plus the batch row, which
// the compensation must move out of every resumable state.
func TestMintCompensationContract(t *testing.T) {
	t.Parallel()

	f := newContractFixture(t)
	ctx := context.Background()

	rapid.Check(t, func(rt *rapid.T) {
		// A minted asset has no address event: nothing was received.
		w := genContractWorld(rt, t, f, withoutEvents())
		rawBatchKey := f.addMintingBatch(t)

		abandon := func() error {
			return f.executor.ExecTx(
				ctx, WriteTxOption(),
				func(q *sqlc.Queries) error {
					return f.assetsStore.
						ApplyMintAbandonment(
							ctx, q, w.anchorTxid,
							rawBatchKey,
						)
				},
			)
		}

		require.NotNil(rt, f.chainConfirmed(rt, w.anchorTxid))
		for _, dbID := range w.outputDBIDs {
			require.Equal(rt, 1, f.proofRows(rt, dbID))
		}

		// Totality.
		require.NoError(
			rt, abandon(),
			"mint abandonment must not fail; it runs inside the "+
				"delivery transaction",
		)

		// Scope: the minted assets are withdrawn, the genesis
		// transaction is unconfirmed, and the batch is cancelled so
		// it is neither resumed nor counted.
		assertCompensated := func(where string) {
			f.assertOutputsWithdrawn(rt, w, where)
			require.Nil(
				rt, f.chainConfirmed(rt, w.anchorTxid),
				"%s: the discarded genesis transaction is "+
					"still confirmed", where,
			)
			require.Equal(
				rt, tapgarden.BatchStateSproutCancelled,
				f.batchState(rt, rawBatchKey),
				"%s: batch not cancelled", where,
			)
		}
		assertCompensated("abandonment")

		// Convergence: a redelivered abandonment reaches the same
		// state.
		live := f.liveAssets(rt, w.assetDBIDs)
		require.NoError(rt, abandon(), "redelivered abandonment failed")

		after := f.liveAssets(rt, w.assetDBIDs)
		require.Equal(
			rt, live, after,
			"abandonment is not convergent under redelivery",
		)
		assertCompensated("redelivery")
	})
}
