package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnutils"
	"github.com/stretchr/testify/require"
)

// supplyCommitTestSetup holds the components initialized by
// setupSupplyCommitTest.
type supplyCommitTestSetup struct {
	commitMachine   *SupplyCommitMachine
	commitTreeStore *SupplyTreeStore
	db              sqlc.Querier
	baseGenesis     asset.Genesis
	groupPubKey     *btcec.PublicKey
}

// setupSupplyCommitTest initializes the core components needed for supply
// commitment tests.
func setupSupplyCommitTest(t *testing.T) *supplyCommitTestSetup {
	t.Helper()

	db := NewTestDB(t)
	sqlDB := db.BaseDB

	txCreatorCommit := func(tx *sql.Tx) SupplyCommitStore {
		return db.WithTx(tx)
	}
	batchedDBCommit := NewTransactionExecutor[SupplyCommitStore](
		sqlDB, txCreatorCommit,
	)
	commitMachine := NewSupplyCommitMachine(batchedDBCommit)

	// Create a group key that'll be used in the test context.
	groupPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	groupPubKey := groupPrivKey.PubKey()

	baseGenesis := asset.RandGenesis(t, asset.Normal)

	ctx := context.Background()

	// Insert the base genesis needed for burn/ignore events.
	txCreatorTree := func(tx *sql.Tx) BaseUniverseStore {
		return db.WithTx(tx)
	}
	batchedDBTree := NewTransactionExecutor[BaseUniverseStore](
		db.BaseDB, txCreatorTree,
	)
	genesisPointID, err := upsertGenesisPoint(
		ctx, batchedDBTree, baseGenesis.FirstPrevOut,
	)
	require.NoError(t, err)
	_, err = upsertGenesis(ctx, batchedDBTree, genesisPointID, baseGenesis)
	require.NoError(t, err)

	// Initialize the SupplyTreeStore using the same batched DB.
	commitTreeStore := NewSupplyTreeStore(batchedDBTree)

	return &supplyCommitTestSetup{
		commitMachine:   commitMachine,
		commitTreeStore: commitTreeStore,
		db:              db,
		baseGenesis:     baseGenesis,
		groupPubKey:     groupPubKey,
	}
}

// addTestMintingBatch inserts a basic minting batch and related data using
// harness components.
func (h *supplyCommitTestHarness) addTestMintingBatch() (int64, int64,
	*wire.MsgTx, []byte, []byte) {

	h.t.Helper()

	ctx := h.ctx
	db := h.db

	batchKeyDesc, _ := test.RandKeyDesc(h.t)
	batchKeyID, err := db.UpsertInternalKey(
		ctx, sqlc.UpsertInternalKeyParams{
			RawKey:    batchKeyDesc.PubKey.SerializeCompressed(),
			KeyFamily: int32(batchKeyDesc.Family),
			KeyIndex:  int32(batchKeyDesc.Index),
		},
	)
	require.NoError(h.t, err)

	genesisPoint := test.RandOp(h.t)
	genesisPointID, err := upsertGenesisPoint(ctx, db, genesisPoint)
	require.NoError(h.t, err)

	mintingTx := wire.NewMsgTx(2)
	mintingTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: genesisPoint,
	})
	mintingTx.AddTxOut(&wire.TxOut{
		Value:    1000,
		PkScript: test.RandBytes(20),
	})

	mintTxBytes, err := encodeTx(mintingTx)
	require.NoError(h.t, err)
	mintTxID := mintingTx.TxHash()
	mintTxDbID, err := db.UpsertChainTx(ctx, sqlc.UpsertChainTxParams{
		Txid:  mintTxID[:],
		RawTx: mintTxBytes,
	})
	require.NoError(h.t, err)

	genesisPointBytes, err := encodeOutpoint(genesisPoint)
	require.NoError(h.t, err)
	err = db.AnchorGenesisPoint(ctx, sqlc.AnchorGenesisPointParams{
		PrevOut:    genesisPointBytes,
		AnchorTxID: sqlInt64(mintTxDbID),
	})
	require.NoError(h.t, err)

	err = db.NewMintingBatch(ctx, sqlc.NewMintingBatchParams{
		BatchID:          batchKeyID,
		HeightHint:       100,
		CreationTimeUnix: time.Now(),
	})
	require.NoError(h.t, err)

	_, err = db.BindMintingBatchWithTx(
		ctx, sqlc.BindMintingBatchWithTxParams{
			RawKey:    batchKeyDesc.PubKey.SerializeCompressed(),
			GenesisID: sqlInt64(genesisPointID),
		},
	)
	require.NoError(h.t, err)

	return batchKeyID, mintTxDbID, mintingTx, mintTxID[:], mintTxBytes
}

// stateTransitionOutput encapsulates the results of a simulated state
// transition performed by performSingleTransition.
type stateTransitionOutput struct {
	appliedUpdates []supplycommit.SupplyUpdateEvent
	internalKey    *btcec.PublicKey
	outputKey      *btcec.PublicKey
	commitTx       *wire.MsgTx
	chainProof     supplycommit.ChainProof
	txOutIndex     uint32
}

// supplyCommitTestHarness holds the necessary components for testing the
// SupplyCommitMachine's StateMachineStore implementation.
type supplyCommitTestHarness struct {
	t               *testing.T
	ctx             context.Context
	commitMachine   *SupplyCommitMachine
	db              sqlc.Querier
	groupPubKey     *btcec.PublicKey
	groupKeyBytes   []byte
	assetSpec       asset.Specifier
	baseGenesis     asset.Genesis
	groupKey        *asset.GroupKey
	batchedTreeDB   BatchedUniverseTree
	commitTreeStore *SupplyTreeStore
}

// newSupplyCommitTestHarness creates a new test harness instance.
func newSupplyCommitTestHarness(t *testing.T) *supplyCommitTestHarness {
	t.Helper()

	setup := setupSupplyCommitTest(t)
	ctx := context.Background()

	groupKey := &asset.GroupKey{GroupPubKey: *setup.groupPubKey}

	// Use the baseGenesis ID for the initial specifier if needed, or empty
	// ID. Let's use an empty ID for a generic harness setup.
	spec := asset.NewSpecifierOptionalGroupPubKey(
		asset.ID{}, setup.groupPubKey,
	)

	return &supplyCommitTestHarness{
		t:               t,
		ctx:             ctx,
		commitMachine:   setup.commitMachine,
		db:              setup.db,
		groupPubKey:     setup.groupPubKey,
		groupKeyBytes:   setup.groupPubKey.SerializeCompressed(),
		assetSpec:       spec,
		baseGenesis:     setup.baseGenesis,
		groupKey:        groupKey,
		batchedTreeDB:   setup.commitTreeStore.db,
		commitTreeStore: setup.commitTreeStore,
	}
}

// addTestMintAnchorUniCommitment inserts a mint_anchor_uni_commitments record
// using harness data.
func (h *supplyCommitTestHarness) addTestMintAnchorUniCommitment(batchID int64,
	spentBy sql.NullInt64) int64 {

	h.t.Helper()

	internalKey := test.RandPubKey(h.t)
	anchorCommitID, err := h.db.UpsertMintAnchorUniCommitment(
		h.ctx, sqlc.UpsertMintAnchorUniCommitmentParams{
			BatchID:            int32(batchID),
			TxOutputIndex:      int32(test.RandInt[uint32]() % 100),
			TaprootInternalKey: internalKey.SerializeCompressed(),
			GroupKey:           h.groupKeyBytes,
			SpentBy:            spentBy,
		},
	)
	require.NoError(h.t, err)

	return anchorCommitID
}

// currentState fetches the current state of the state machine via FetchState.
func (h *supplyCommitTestHarness) currentState() supplycommit.State {
	h.t.Helper()

	state, _, err := h.commitMachine.FetchState(h.ctx, h.assetSpec)
	require.NoError(h.t, err)
	return state
}

// currentTransition fetches the current pending transition via FetchState.
// Returns None if no transition is pending.
//
//nolint:lll
func (h *supplyCommitTestHarness) currentTransition() lfn.Option[supplycommit.SupplyStateTransition] {
	h.t.Helper()

	_, transitionOpt, err := h.commitMachine.FetchState(h.ctx, h.assetSpec)
	require.NoError(h.t, err)
	return transitionOpt
}

// assertPendingTransitionExists asserts that a pending (non-finalized)
// transition exists.
//
//nolint:lll
func (h *supplyCommitTestHarness) assertPendingTransitionExists() SupplyCommitTransition {
	h.t.Helper()

	dbTransition, err := h.fetchPendingTransition()
	require.NoError(h.t, err, "expected pending transition to exist")
	require.False(h.t, dbTransition.Finalized)
	return dbTransition
}

// assertNoPendingTransition asserts that no pending (non-finalized) transition
// exists.
func (h *supplyCommitTestHarness) assertNoPendingTransition() {
	h.t.Helper()

	_, err := h.fetchPendingTransition()
	require.ErrorIs(h.t, err, sql.ErrNoRows,
		"expected no pending transition")
}

// assertTransitionInitialState asserts basic fields for a newly created
// transition.
func (h *supplyCommitTestHarness) assertTransitionInitialState(
	dbTransition SupplyCommitTransition) {

	h.t.Helper()

	require.False(h.t, dbTransition.Finalized)
	require.False(h.t, dbTransition.NewCommitmentID.Valid)
	require.False(h.t, dbTransition.PendingCommitTxnID.Valid)
}

// randMintEvent generates a random mint event using the harness's group key.
func (h *supplyCommitTestHarness) randMintEvent() *supplycommit.NewMintEvent {
	gen := randMintEventGen(h.groupPubKey)
	mintEvent := gen.Example().(*supplycommit.NewMintEvent)

	// For an asset, the witness isn't encoded when we encode the group key.
	mintEvent.IssuanceProof.GenesisWithGroup.GroupKey.Witness = nil
	mintEvent.IssuanceProof.Asset.GroupKey.Witness = nil

	mintEvent.IssuanceProof.Asset.ScriptKey.TweakedScriptKey = nil

	return mintEvent
}

// randBurnEvent generates a random burn event using the harness's base genesis
// and group key.
func (h *supplyCommitTestHarness) randBurnEvent() *supplycommit.NewBurnEvent {
	gen := randBurnEventGen(h.baseGenesis, h.groupKey, h.batchedTreeDB)
	return gen.Example().(*supplycommit.NewBurnEvent)
}

// randIgnoreEvent generates a random ignore event using the harness's base
// genesis ID.
//
//nolint:lll
func (h *supplyCommitTestHarness) randIgnoreEvent() *supplycommit.NewIgnoreEvent {
	gen := randIgnoreEventGen(h.baseGenesis.ID(), h.batchedTreeDB)
	return gen.Example().(*supplycommit.NewIgnoreEvent)
}

// fetchPendingTransition fetches the current pending transition directly via
// SQL.
func (h *supplyCommitTestHarness) fetchPendingTransition() (
	SupplyCommitTransition, error) {

	var transition SupplyCommitTransition
	readTx := NewSupplyCommitReadTx()
	err := h.commitMachine.db.ExecTx(
		h.ctx, &readTx, func(db SupplyCommitStore) error {
			var txErr error
			transition, txErr = db.QueryPendingSupplyCommitTransition( //nolint:lll
				h.ctx, h.groupKeyBytes,
			)
			return txErr
		},
	)
	return transition, err
}

// assertCurrentStateIs fetches the current state and asserts it matches the
// expected state type.
func (h *supplyCommitTestHarness) assertCurrentStateIs(
	expectedState supplycommit.State) {

	h.t.Helper()
	state := h.currentState()
	require.IsType(h.t, expectedState, state)
}

// assertPendingUpdates fetches the current transition, asserts the number of
// pending updates, and compares the serialized versions of the updates with the
// expected events after sorting both slices by their universe leaf key.
func (h *supplyCommitTestHarness) assertPendingUpdates(
	expectedEvents []supplycommit.SupplyUpdateEvent) {

	h.t.Helper()
	transitionOpt := h.currentTransition()
	require.True(
		h.t, transitionOpt.IsSome(),
		"expected pending transition for update check",
	)
	transition := transitionOpt.UnwrapOrFail(h.t)
	actualEvents := transition.PendingUpdates
	require.Len(h.t, actualEvents, len(expectedEvents))

	// Create copies to avoid modifying the original slices.
	expectedCopy := make(
		[]supplycommit.SupplyUpdateEvent, len(expectedEvents),
	)
	copy(expectedCopy, expectedEvents)
	actualCopy := make([]supplycommit.SupplyUpdateEvent, len(actualEvents))
	copy(actualCopy, actualEvents)

	// Define a sorting function based on the UniverseLeafKey.
	sorter := func(events []supplycommit.SupplyUpdateEvent) {
		sort.SliceStable(events, func(i, j int) bool {
			keyI := events[i].UniverseLeafKey().UniverseKey()
			keyJ := events[j].UniverseLeafKey().UniverseKey()
			// Compare byte slices lexicographically.
			return bytes.Compare(keyI[:], keyJ[:]) < 0
		})
	}

	// Sort both copies.
	sorter(expectedCopy)
	sorter(actualCopy)

	// Compare the serialized bytes of each event pair. There're a lot of
	// fields that aren't actually encoded, so a simple equals check won't
	// work.
	for i := range expectedCopy {
		expectedEvent := expectedCopy[i]
		actualEvent := actualCopy[i]

		var expectedBytes bytes.Buffer
		err := serializeSupplyUpdateEvent(&expectedBytes, expectedEvent)
		require.NoError(
			h.t, err, "failed to serialize expected event %d", i,
		)

		var actualBytes bytes.Buffer
		err = serializeSupplyUpdateEvent(&actualBytes, actualEvent)
		require.NoError(
			h.t, err, "failed to serialize actual event %d", i,
		)

		require.Equal(h.t,
			expectedBytes.String(), actualBytes.String(),
			"mismatch for serialized event %d "+
				"(expected %T, actual %T)",
			i, expectedEvent, actualEvent,
		)
	}
}

// fetchStateMachine fetches the state machine details directly via SQL.
func (h *supplyCommitTestHarness) fetchStateMachine() (
	QuerySupplyStateMachineResp, error) {

	var stateMachine QuerySupplyStateMachineResp
	readTx := NewSupplyCommitReadTx()
	err := h.commitMachine.db.ExecTx(h.ctx, &readTx,
		func(db SupplyCommitStore) error {
			var txErr error
			stateMachine, txErr = db.QuerySupplyCommitStateMachine(
				h.ctx, h.groupKeyBytes,
			)
			return txErr
		},
	)
	return stateMachine, err
}

// addTestSupplyCommitment inserts a supply_commitments record using harness
// data.
func (h *supplyCommitTestHarness) addTestSupplyCommitment(chainTxID int64,
	txidBytes, rawTxBytes []byte, isConfirmed bool) int64 {

	h.t.Helper()

	ctx := h.ctx
	db := h.db
	groupKeyBytes := h.groupKeyBytes
	groupPubKey := h.groupPubKey
	baseGenesis := h.baseGenesis
	groupKey := h.groupKey
	batchedTreeDB := h.batchedTreeDB
	commitDB := h.commitMachine
	assetSpec := h.assetSpec

	internalKeyDesc, _ := test.RandKeyDesc(h.t)
	internalKeyID, err := db.UpsertInternalKey(
		ctx, sqlc.UpsertInternalKeyParams{
			RawKey:    internalKeyDesc.PubKey.SerializeCompressed(),
			KeyFamily: int32(internalKeyDesc.Family),
			KeyIndex:  int32(internalKeyDesc.Index),
		},
	)
	require.NoError(h.t, err)

	outputKey := test.RandPubKey(h.t)

	// Instantiate generators and create example events.
	mintGen := randMintEventGen(groupPubKey)
	burnGen := randBurnEventGen(baseGenesis, groupKey, batchedTreeDB)
	ignoreGen := randIgnoreEventGen(baseGenesis.ID(), batchedTreeDB)

	exampleMint := mintGen.Example()
	exampleBurn := burnGen.Example()
	exampleIgnore := ignoreGen.Example()

	// Apply the dummy updates to create the SMT roots implicitly.
	var (
		writeTxOpts SupplyCommitTxOptions
		finalRoot   mssmt.Node
	)
	err = commitDB.db.ExecTx(
		ctx, &writeTxOpts, func(dbtx SupplyCommitStore) error {
			finalRoot, err = applySupplyUpdatesInternal(
				ctx, dbtx, assetSpec,
				[]supplycommit.SupplyUpdateEvent{
					exampleMint, exampleBurn, exampleIgnore,
				},
			)
			return err
		},
	)
	require.NoError(h.t, err)

	// Update the chain TX confirmation status.
	var blockHash []byte
	var blockHeight sql.NullInt32
	if isConfirmed {
		blockHash = test.RandBytes(32)
		blockHeight = sqlInt32(123)
	}

	// Upsert the chain tx with confirmation details (or lack thereof).
	_, err = db.UpsertChainTx(ctx, sqlc.UpsertChainTxParams{
		Txid:        txidBytes,
		RawTx:       rawTxBytes,
		ChainFees:   0,
		BlockHash:   blockHash,
		BlockHeight: blockHeight,
		TxIndex:     sqlInt32(1),
	})
	require.NoError(h.t, err)

	commitID, err := db.InsertSupplyCommitment(
		ctx, sqlc.InsertSupplyCommitmentParams{
			GroupKey:       groupKeyBytes,
			ChainTxnID:     chainTxID,
			InternalKeyID:  internalKeyID,
			OutputKey:      outputKey.SerializeCompressed(),
			BlockHeight:    blockHeight,
			BlockHeader:    test.RandBytes(80),
			MerkleProof:    test.RandBytes(64),
			OutputIndex:    sqlInt32(0),
			SupplyRootHash: lnutils.ByteSlice(finalRoot.NodeHash()),
			SupplyRootSum:  sqlInt64(finalRoot.NodeSum()),
		},
	)
	require.NoError(h.t, err)
	return commitID
}

// addTestStateMachine inserts a supply_commit_state_machines record
// using harness data.
func (h *supplyCommitTestHarness) addTestStateMachine(
	latestCommitID sql.NullInt64) {

	h.t.Helper()

	_, err := h.db.UpsertSupplyCommitStateMachine(
		h.ctx, sqlc.UpsertSupplyCommitStateMachineParams{
			GroupKey:           h.groupKeyBytes,
			StateName:          sqlStr("DefaultState"),
			LatestCommitmentID: latestCommitID,
		},
	)
	require.NoError(h.t, err)
}

// fetchCommitmentByID fetches a commitment by ID directly via SQL.
func (h *supplyCommitTestHarness) fetchCommitmentByID(
	commitID int64) (sqlc.SupplyCommitment, error) {

	var commitment sqlc.SupplyCommitment
	readTx := NewSupplyCommitReadTx()
	err := h.commitMachine.db.ExecTx(h.ctx, &readTx,
		func(db SupplyCommitStore) error {
			var txErr error
			commitment, txErr = db.QuerySupplyCommitment(
				h.ctx, commitID,
			)
			return txErr
		},
	)
	return commitment, err
}

// fetchInternalKeyByID fetches an internal key by ID directly via SQL.
//
//nolint:lll
func (h *supplyCommitTestHarness) fetchInternalKeyByID(keyID int64) FetchInternalKeyByIDRow {
	h.t.Helper()
	var keyRow FetchInternalKeyByIDRow
	readTx := NewSupplyCommitReadTx()
	err := h.commitMachine.db.ExecTx(h.ctx, &readTx,
		func(db SupplyCommitStore) error {
			var txErr error
			keyRow, txErr = db.FetchInternalKeyByID(h.ctx, keyID)
			return txErr
		},
	)
	require.NoError(h.t, err)
	return keyRow
}

// fetchChainTxByID fetches a chain tx by ID directly via SQL.
func (h *supplyCommitTestHarness) fetchChainTxByID(txID int64,
) (FetchChainTxByIDRow, error) {

	var chainTx FetchChainTxByIDRow
	readTx := NewSupplyCommitReadTx()
	err := h.commitMachine.db.ExecTx(h.ctx, &readTx,
		func(db SupplyCommitStore) error {
			var txErr error
			chainTx, txErr = db.FetchChainTxByID(h.ctx, txID)
			return txErr
		},
	)
	return chainTx, err
}

// linkTxToPendingTransition manually updates the pending_commit_txn_id for the
// current pending transition.
func (h *supplyCommitTestHarness) linkTxToPendingTransition(chainTxID int64) {
	h.t.Helper()
	dbTransition := h.assertPendingTransitionExists()

	var writeTx SupplyCommitTxOptions
	err := h.commitMachine.db.ExecTx(
		h.ctx, &writeTx, func(db SupplyCommitStore) error {
			// Link the TX ID, NewCommitmentID remains NULL for now.
			//nolint:lll
			return db.UpdateSupplyCommitTransitionCommitment(
				h.ctx, UpdateSupplyCommitTransitionCommitmentParams{
					PendingCommitTxnID: sqlInt64(chainTxID),
					NewCommitmentID:    sql.NullInt64{},
					TransitionID:       dbTransition.TransitionID,
				},
			)
		},
	)
	require.NoError(h.t, err)
}

// confirmChainTx confirms a chain tx directly via SQL.
func (h *supplyCommitTestHarness) confirmChainTx(txID int64, txidBytes,
	rawTxBytes []byte) {

	blockHash := test.RandBytes(32)
	blockHeight := sqlInt32(test.RandInt[int32]())
	txIndex := sqlInt32(test.RandInt[int32]())
	_, err := h.db.UpsertChainTx(h.ctx, sqlc.UpsertChainTxParams{
		Txid:        txidBytes,
		RawTx:       rawTxBytes,
		ChainFees:   0,
		BlockHash:   blockHash,
		BlockHeight: blockHeight,
		TxIndex:     txIndex,
	})
	require.NoError(h.t, err)
}

// performSingleTransition simulates a full state transition cycle: inserting
// updates, inserting the signed commit TX (which sets DB state), and finally
// calling ApplyStateTransition with simulated confirmation data. It returns the
// list of updates applied, the generated keys, the commit TX, and the simulated
// chain proof details for assertion purposes.
func (h *supplyCommitTestHarness) performSingleTransition(
	updates []supplycommit.SupplyUpdateEvent) stateTransitionOutput {

	h.t.Helper()

	// Assert initial state is DefaultState (assuming test starts clean).
	h.assertCurrentStateIs(&supplycommit.DefaultState{})

	// First, we'll insert the set of pending updates into the DB. This'll
	// create a new state transition record with the updates.
	for _, event := range updates {
		err := h.commitMachine.InsertPendingUpdate(
			h.ctx, h.assetSpec, event,
		)
		require.NoError(h.t, err)
	}

	// Assert state transitioned to UpdatesPendingState.
	h.assertCurrentStateIs(&supplycommit.UpdatesPendingState{})

	// Next, we'll generate a new "fake" commitment transaction along with
	// sample internal and output keys.
	commitTx := randTx(h.t, 1)
	internalKey := test.RandPubKey(h.t)
	outputKey := test.RandPubKey(h.t)

	// We'll now simulate the next phase of the state transition where we
	// make the new commitment, capture that in a new commit tx, then sign
	// and commit that.
	commitDetails := supplycommit.SupplyCommitTxn{
		Txn:         commitTx,
		InternalKey: internalKey,
		OutputKey:   outputKey,
		OutputIndex: 1,
	}
	err := h.commitMachine.InsertSignedCommitTx(
		h.ctx, h.assetSpec, commitDetails,
	)
	require.NoError(h.t, err)

	// Assert state transitioned to CommitBroadcastState.
	h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})

	// Next, we''ll make a fake confirmation proof, this'll be used when we
	// go to apply the state transition, which is only meant to be done once
	// it has confirmed on chain.
	blockHeader := &wire.BlockHeader{
		Version:    int32(test.RandInt[uint32]()),
		PrevBlock:  test.RandHash(),
		MerkleRoot: test.RandHash(),
		Timestamp:  time.Unix(test.RandInt[int64](), 0),
		Bits:       test.RandInt[uint32](),
		Nonce:      test.RandInt[uint32](),
	}
	merkleProof := proof.TxMerkleProof{
		Bits:  []bool{test.RandBool()},
		Nodes: []chainhash.Hash{test.RandHash()},
	}
	blockHeight := uint32(test.RandInt[int32]())
	chainProof := supplycommit.ChainProof{
		Header:      *blockHeader,
		BlockHeight: blockHeight,
		MerkleProof: merkleProof,
	}

	// With the signed commitment inserted above, we'll now fetch the state
	// on disk, as we'll use this to construct the new commitment based on
	// the set of updates.
	_, currentTransitionOpt, err := h.commitMachine.FetchState(
		h.ctx, h.assetSpec,
	)
	require.NoError(h.t, err, "failed fetching state before apply")
	require.True(
		h.t, currentTransitionOpt.IsSome(),
		"expected transition before apply",
	)
	currentTransition := currentTransitionOpt.UnwrapOrFail(h.t)

	// Given the on disk information of the current state transition
	// (contains the old commitment), we'll now use that along with the
	// updates to make what we expect the new supply root to be.
	expectedNewRoot := h.calculateExpectedRoot(
		currentTransition.OldCommitment, updates,
	)

	// With all the above gathered, we'll now make the state transition
	// object as expected, then apply the state transition.
	applyTransition := supplycommit.SupplyStateTransition{
		OldCommitment:  currentTransition.OldCommitment,
		PendingUpdates: updates,
		NewCommitment: supplycommit.RootCommitment{
			Txn:         commitTx,
			TxOutIdx:    test.RandInt[uint32](),
			InternalKey: internalKey,
			OutputKey:   outputKey,
			SupplyRoot:  expectedNewRoot,
		},
		ChainProof: lfn.Some(chainProof),
	}
	err = h.commitMachine.ApplyStateTransition(
		h.ctx, h.assetSpec, applyTransition,
	)
	require.NoError(h.t, err)

	return stateTransitionOutput{
		appliedUpdates: updates,
		internalKey:    internalKey,
		outputKey:      outputKey,
		commitTx:       commitTx,
		chainProof:     chainProof,
		txOutIndex:     applyTransition.NewCommitment.TxOutIdx,
	}
}

// applyTreeUpdates takes a map of in-memory supply sub-trees and applies a list
// of pending updates to them. It returns the map containing the updated trees.
// This function operates purely in-memory and is used for calculating expected
// SMT roots during testing.
func applyTreeUpdates(supplyTrees supplycommit.SupplyTrees,
	pendingUpdates []supplycommit.SupplyUpdateEvent,
) (supplycommit.SupplyTrees, error) {

	ctx := context.Background()

	// For each tree update, we'll select the proper tree, then insert apply
	// the update to said tree.
	for _, treeUpdate := range pendingUpdates {
		// Obtain the universe leaf key and node directly from the event
		// using the interface methods.
		leafKey := treeUpdate.UniverseLeafKey()
		leafValue, err := treeUpdate.UniverseLeafNode()
		if err != nil {
			return nil, fmt.Errorf("unable to create leaf node "+
				"for update event %T: %w", treeUpdate, err)
		}

		targetTree := supplyTrees.FetchOrCreate(
			treeUpdate.SupplySubTreeType(),
		)

		_, err = targetTree.Insert(
			ctx, leafKey.UniverseKey(), leafValue,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to insert leaf into "+
				"target tree %v: %w",
				treeUpdate.SupplySubTreeType(), err)
		}

		supplyTrees[treeUpdate.SupplySubTreeType()] = targetTree
	}

	return supplyTrees, nil
}

// calculateExpectedRoot calculates the expected SMT root after applying
// updates.
func (h *supplyCommitTestHarness) calculateExpectedRoot(
	oldCommitmentOpt lfn.Option[supplycommit.RootCommitment],
	updates []supplycommit.SupplyUpdateEvent) *mssmt.BranchNode {

	h.t.Helper()

	// If we have a root commitment, then we'll fetch the root tree from DB
	// (not the first state transition). Otherwise, we'll just start with a
	// new blank tree.
	oldRootTreeRes := lfn.MapOption(
		//nolint:lll
		func(oldCommitment supplycommit.RootCommitment) lfn.Result[mssmt.Tree] {
			treeRes := h.commitTreeStore.FetchRootSupplyTree(
				h.ctx, h.assetSpec,
			)
			fetchedTree, err := treeRes.Unpack()
			if err != nil {
				return lfn.Err[mssmt.Tree](fmt.Errorf("failed "+
					"fetching root tree: %w", err))
			}

			return lfn.Ok(fetchedTree)
		},
	)(oldCommitmentOpt).UnwrapOr(
		lfn.Ok[mssmt.Tree](mssmt.NewCompactedTree(
			mssmt.NewDefaultStore()),
		),
	)

	oldRootTree, err := oldRootTreeRes.Unpack()
	require.NoError(h.t, err)

	// We'll now copy over the old root tree to a temporary tree, so we can
	// insert the updates directly.
	tempRootTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	err = oldRootTree.Copy(h.ctx, tempRootTree)
	require.NoError(h.t, err)

	// Next, we'll read out all the existing sub-tres, to store in a map as
	// we'll insert into them below.
	tempSubTrees := make(supplycommit.SupplyTrees)
	for _, treeType := range []supplycommit.SupplySubTree{
		supplycommit.IgnoreTreeType,
		supplycommit.MintTreeType, supplycommit.BurnTreeType,
	} {
		subTree, err := h.commitTreeStore.FetchSubTree(
			h.ctx, h.assetSpec, treeType,
		).Unpack()
		require.NoError(h.t, err)

		if subTree == nil {
			continue
		}

		// If we have a sub-tree created, then we'll copy it into the in
		// memory tree, so we can insert the updates directly.
		// Otherwise, we'll make a new blank one.
		tempSubTrees[treeType] = mssmt.NewCompactedTree(
			mssmt.NewDefaultStore(),
		)
		err = subTree.Copy(h.ctx, tempSubTrees[treeType])
		require.NoError(h.t, err)
	}

	// Apply the set of updates to each of the sub-trees we have in memory.
	updatedSubTrees, err := applyTreeUpdates(tempSubTrees, updates)
	require.NoError(h.t, err)

	// With the sub-trees updated, we can now update the root tree by
	// inserting in the new sub-tree.
	for treeType, subTree := range updatedSubTrees {
		subRoot, err := subTree.Root(h.ctx)
		require.NoError(h.t, err)

		leafNode := mssmt.NewLeafNode(lnutils.ByteSlice(
			subRoot.NodeHash()), subRoot.NodeSum(),
		)
		leafKey := treeType.UniverseKey()

		_, err = tempRootTree.Insert(h.ctx, leafKey, leafNode)
		require.NoError(h.t, err)
	}

	// Obtain the finalroot tree after our insertions.
	finalRoot, err := tempRootTree.Root(h.ctx)
	require.NoError(h.t, err)

	return finalRoot
}

// assertTransitionApplied verifies the state of the database and SMTs after
// ApplyStateTransition has successfully completed. We ensure that the state
// machine was updated properly, the new trees are in place, and the transition
// is properly finalized.
func (h *supplyCommitTestHarness) assertTransitionApplied(
	output stateTransitionOutput) {

	h.t.Helper()

	commitTxid := output.commitTx.TxHash()
	internalKey := output.internalKey
	appliedUpdates := output.appliedUpdates
	outputKey := output.outputKey
	chainProof := output.chainProof

	// Verify via FetchState that the machine is back in DefaultState and
	// there's no pending transition object returned.
	fetchedState, fetchedTransitionOpt, err := h.commitMachine.FetchState(
		h.ctx, h.assetSpec,
	)
	require.NoError(h.t, err, "FetchState failed after apply")
	require.IsType(
		h.t, &supplycommit.DefaultState{}, fetchedState,
		"state should be DefaultState after apply",
	)
	require.False(
		h.t, fetchedTransitionOpt.IsSome(),
		"no pending transition should be returned after apply",
	)

	// Next, we'll verify that the internal state machine matches the same
	// state, and we'll then assert that the commitment pointer was updated
	// properly on disk.
	stateMachine, err := h.fetchStateMachine()
	require.NoError(h.t, err)
	require.Equal(
		h.t, int32(0), stateMachine.CurrentStateID,
		"state should be DefaultState",
	)
	require.True(
		h.t, stateMachine.LatestCommitmentID.Valid,
		"LatestCommitmentID should be set",
	)

	latestCommitmentID := stateMachine.LatestCommitmentID.Int64

	// At this point, there should be no pending transition, on disk (it
	// should have been finalized).
	h.assertNoPendingTransition()

	// We should be able to fetch the latest commitment on disk now.
	dbCommitment, err := h.fetchCommitmentByID(latestCommitmentID)
	require.NoError(h.t, err)

	// The transaction we inserted on disk as the latest commitment tx
	// should also be found now.
	chainTxRecord, err := h.db.FetchChainTx(h.ctx, commitTxid[:])
	require.NoError(h.t, err)
	require.Equal(
		h.t, chainTxRecord.TxnID, dbCommitment.ChainTxnID,
		"commitment linked to wrong ChainTxnID",
	)

	// The keys should also be inserted, and the db commitment should match
	// what we inserted.
	require.Equal(
		h.t, internalKey.SerializeCompressed(),
		h.fetchInternalKeyByID(dbCommitment.InternalKeyID).RawKey,
		"internalKey mismatch",
	)
	require.Equal(
		h.t, outputKey.SerializeCompressed(), dbCommitment.OutputKey,
		"outputKey mismatch",
	)

	// Check stored root hash/sum are not empty.
	require.NotNil(
		h.t, dbCommitment.SupplyRootHash,
		"SupplyRootHash should be set",
	)
	require.True(
		h.t, dbCommitment.SupplyRootSum.Valid,
		"SupplyRootSum should be set",
	)

	// All the chain details should should also be populated as expected.
	require.True(
		h.t, dbCommitment.BlockHeight.Valid,
		"blockHeight should be set",
	)
	require.Equal(
		h.t, int32(chainProof.BlockHeight),
		dbCommitment.BlockHeight.Int32, "blockHeight mismatch",
	)
	require.NotEmpty(
		h.t, dbCommitment.BlockHeader, "blockHeader should be set",
	)
	require.NotEmpty(
		h.t, dbCommitment.MerkleProof, "merkleProof should be set",
	)
	require.True(
		h.t, dbCommitment.OutputIndex.Valid,
		"outputIndex should be set",
	)
	require.Equal(
		h.t, int32(output.txOutIndex), dbCommitment.OutputIndex.Int32,
	)

	// As a final step, we'll verify that the root supply tree for the asset
	// spec matches what we re-created in memory.
	rootSupplyTreeRes := h.commitTreeStore.FetchRootSupplyTree(
		h.ctx, h.assetSpec,
	)
	rootSupplyTree, err := rootSupplyTreeRes.Unpack()
	require.NoError(h.t, err)
	finalRootSupplyNode, err := rootSupplyTree.Root(h.ctx)
	require.NoError(h.t, err)

	// Compare DB stored root with calculated root from fetched tree.
	require.Equal(
		h.t, lnutils.ByteSlice(finalRootSupplyNode.NodeHash()),
		dbCommitment.SupplyRootHash,
	)
	require.Equal(
		h.t, int64(finalRootSupplyNode.NodeSum()),
		dbCommitment.SupplyRootSum.Int64,
	)

	// We'll now run through all the updates that should have been applied,
	// and verify that we can verify a merkle tree inclusion proof for them.
	subTreeRoots := make(map[supplycommit.SupplySubTree]mssmt.Node)
	for _, event := range appliedUpdates {
		treeType := event.SupplySubTreeType()
		leafKey := event.UniverseLeafKey()
		leafNode, err := event.UniverseLeafNode()
		require.NoError(h.t, err)

		// We'll now fetch the sub-tree on disk, to make our assertio
		// below.
		subTreeRes := h.commitTreeStore.FetchSubTree(
			h.ctx, h.assetSpec, treeType,
		)
		subTree, err := subTreeRes.Unpack()
		require.NoError(h.t, err)

		subTreeRoot, err := subTree.Root(h.ctx)
		require.NoError(h.t, err)

		// We'll store this root later to make sure that we can verify
		// an inclusion proof from the in memory root tree we created.
		subTreeRoots[treeType] = subTreeRoot

		// We'll now generate a merkle proof from the sub-tree on disk
		// for this update. We should be able to verify it np.
		subProof, err := subTree.MerkleProof(
			h.ctx, leafKey.UniverseKey(),
		)
		require.NoError(h.t, err)
		isValidSubProof := mssmt.VerifyMerkleProof(
			leafKey.UniverseKey(), leafNode, subProof, subTreeRoot,
		)
		require.True(
			h.t, isValidSubProof,
			"invalid sub-tree proof for %v key %x", treeType,
			leafKey.UniverseKey(),
		)
	}

	// As a final set of assertions, we'll verify that we can generate then
	// verify a merkle proof for each of the sub-trees based on the root
	// supply tree.
	for treeType, subTreeRoot := range subTreeRoots {
		rootTreeLeafKey := treeType.UniverseKey()
		rootTreeLeafNode := mssmt.NewLeafNode(
			lnutils.ByteSlice(subTreeRoot.NodeHash()),
			subTreeRoot.NodeSum(),
		)

		rootProof, err := rootSupplyTree.MerkleProof(
			h.ctx, rootTreeLeafKey,
		)
		require.NoError(h.t, err)
		isValidRootProof := mssmt.VerifyMerkleProof(
			rootTreeLeafKey, rootTreeLeafNode, rootProof,
			finalRootSupplyNode,
		)
		require.True(
			h.t, isValidRootProof,
			"invalid root tree proof for sub-tree %v", treeType,
		)
	}

	// Finally, use the public SupplyCommit method to fetch the latest
	// confirmed commitment and verify its fields match our expectations.
	fetchedCommitRes := h.commitMachine.SupplyCommit(h.ctx, h.assetSpec)
	fetchedCommitOpt, err := fetchedCommitRes.Unpack()
	require.NoError(h.t, err, "SupplyCommit failed")
	require.True(
		h.t, fetchedCommitOpt.IsSome(), "SupplyCommit should return a "+
			"commitment",
	)

	fetchedCommit := fetchedCommitOpt.UnwrapOrFail(h.t)

	// Make sure this matches what the output state transition set.
	require.Equal(
		h.t, output.commitTx.TxHash(), fetchedCommit.Txn.TxHash(),
		"SupplyCommit returned wrong Txn hash",
	)
	require.Equal(
		h.t, output.internalKey.SerializeCompressed(),
		fetchedCommit.InternalKey.SerializeCompressed(),
		"SupplyCommit returned wrong InternalKey",
	)
	require.Equal(
		h.t, output.outputKey.SerializeCompressed(),
		fetchedCommit.OutputKey.SerializeCompressed(),
		"SupplyCommit returned wrong OutputKey",
	)
	require.Equal(
		h.t, uint32(dbCommitment.OutputIndex.Int32),
		fetchedCommit.TxOutIdx,
		"SupplyCommit returned wrong TxOutIdx",
	)
	require.Equal(
		h.t, dbCommitment.SupplyRootHash,
		lnutils.ByteSlice(fetchedCommit.SupplyRoot.NodeHash()),
		"SupplyCommit returned wrong SupplyRoot hash",
	)
	require.Equal(
		h.t, dbCommitment.SupplyRootSum.Int64,
		int64(fetchedCommit.SupplyRoot.NodeSum()),
		"SupplyCommit returned wrong SupplyRoot sum",
	)
}

// TestSupplyCommitInsertPendingUpdate tests the insertion of pending updates.
func TestSupplyCommitInsertPendingUpdate(t *testing.T) {
	t.Parallel()

	h := newSupplyCommitTestHarness(t)

	var insertedEvents []supplycommit.SupplyUpdateEvent

	// First, we'll insert a new update of a minting event.
	event1 := h.randMintEvent()
	insertedEvents = append(insertedEvents, event1)
	err := h.commitMachine.InsertPendingUpdate(
		h.ctx, h.assetSpec, event1,
	)
	require.NoError(t, err)

	// Verify state machine is now in UpdatesPendingState.
	h.assertCurrentStateIs(&supplycommit.UpdatesPendingState{})

	// Verify a pending transition exists and is in initial state.
	dbTransition1 := h.assertPendingTransitionExists()
	h.assertTransitionInitialState(dbTransition1)

	// There should be a pending update now, and after we read it from disk
	// it should exactly match what we inserted.
	h.assertPendingUpdates(insertedEvents)

	// Next, we'll insert a new update type.
	event2 := h.randBurnEvent()
	insertedEvents = append(insertedEvents, event2)
	err = h.commitMachine.InsertPendingUpdate(h.ctx, h.assetSpec, event2)
	require.NoError(t, err)

	// Verify state is still UpdatesPendingState.
	h.assertCurrentStateIs(&supplycommit.UpdatesPendingState{})

	// Verify it uses the same transition.
	dbTransition2 := h.assertPendingTransitionExists()
	require.Equal(t, dbTransition1.TransitionID, dbTransition2.TransitionID)

	// Verify two events are now stored.
	h.assertPendingUpdates(insertedEvents)

	// Next, we'll insert yet another update type.
	event3 := h.randIgnoreEvent()
	insertedEvents = append(insertedEvents, event3)
	err = h.commitMachine.InsertPendingUpdate(h.ctx, h.assetSpec, event3)
	require.NoError(t, err)

	// Once again the state should be the same, and the transition ID should
	// match.
	h.assertCurrentStateIs(&supplycommit.UpdatesPendingState{})
	dbTransition3 := h.assertPendingTransitionExists()
	require.Equal(t, dbTransition1.TransitionID, dbTransition3.TransitionID)

	// Verify three events are now stored.
	h.assertPendingUpdates(insertedEvents)

	// Next, let's test an error path, we'll set the state to broadcast,
	// then attempt to insert a new event.
	err = h.commitMachine.CommitState(
		h.ctx, h.assetSpec, &supplycommit.CommitBroadcastState{},
	)
	require.NoError(t, err)
	h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})

	// Attempting to insert now should fail.
	event4 := h.randMintEvent()
	err = h.commitMachine.InsertPendingUpdate(h.ctx, h.assetSpec, event4)
	require.Error(t, err)
	require.ErrorContains(
		t, err, "cannot insert pending update "+
			"in state: CommitBroadcastState",
	)

	// Verify no new event was added.
	h.assertPendingUpdates(insertedEvents)
}

// TestSupplyCommitInsertSignedCommitTx tests associating a signed commit tx
// with a transition.
func TestSupplyCommitInsertSignedCommitTx(t *testing.T) {
	t.Parallel()

	h := newSupplyCommitTestHarness(t)

	// First, insert a pending update to create the initial transition
	// record.
	event1 := h.randMintEvent()
	err := h.commitMachine.InsertPendingUpdate(
		h.ctx, h.assetSpec, event1,
	)
	require.NoError(t, err)

	// Verify the transition exists but has no commit TX linked yet.
	dbTransition := h.assertPendingTransitionExists()
	require.False(t, dbTransition.PendingCommitTxnID.Valid)

	// Create a _first_ dummy commit TX, insert it into chain_txns, and
	// manually link it to the transition. This simulates the state after
	// funding but before signing/finalizing.
	commitTx1 := randTx(t, 1)
	commitTxid1 := commitTx1.TxHash()
	commitRawTx1, err := encodeTx(commitTx1)
	require.NoError(t, err)
	chainTxID1, err := h.db.UpsertChainTx(h.ctx, sqlc.UpsertChainTxParams{
		Txid:  commitTxid1[:],
		RawTx: commitRawTx1,
	})
	require.NoError(t, err)
	h.linkTxToPendingTransition(chainTxID1)

	// Now, create the _second_ (final, signed) commit TX.
	commitTx2 := randTx(t, 1)
	commitTxid2 := commitTx2.TxHash()

	// Insert the signed commitment with the updated transaction.
	internalKey := test.RandPubKey(t)
	outputKey := test.RandPubKey(t)
	commitDetails := supplycommit.SupplyCommitTxn{
		Txn:         commitTx2,
		InternalKey: internalKey,
		OutputKey:   outputKey,
		OutputIndex: 1,
	}
	err = h.commitMachine.InsertSignedCommitTx(
		h.ctx, h.assetSpec, commitDetails,
	)
	require.NoError(t, err)

	// Verify the state machine transitioned to CommitBroadcastState.
	h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})

	// Verify the transition record now points to the DB ID of the second
	// (final) commit TX and the new commitment ID.
	dbTransition = h.assertPendingTransitionExists()
	require.True(t, dbTransition.PendingCommitTxnID.Valid)
	require.True(t, dbTransition.NewCommitmentID.Valid)
	newCommitmentID := dbTransition.NewCommitmentID.Int64

	// Fetch the chain_txns record for the second commit TX to get its ID.
	chainTx2Record, err := h.db.FetchChainTx(
		h.ctx, commitTxid2[:],
	)
	require.NoError(t, err)

	// Assert that the transition points to the correct chain tx ID.
	require.Equal(
		t, chainTx2Record.TxnID, dbTransition.PendingCommitTxnID.Int64,
	)

	// Assert that a new commitment record was inserted.
	newDbCommitment, err := h.fetchCommitmentByID(newCommitmentID)
	require.NoError(t, err)
	require.Equal(t, chainTx2Record.TxnID, newDbCommitment.ChainTxnID)
	require.Equal(t,
		internalKey.SerializeCompressed(),
		h.fetchInternalKeyByID(newDbCommitment.InternalKeyID).RawKey,
	)
	require.Equal(
		t, outputKey.SerializeCompressed(), newDbCommitment.OutputKey,
	)
	require.Equal(
		t, int(commitDetails.OutputIndex),
		int(newDbCommitment.OutputIndex.Int32),
	)

	// Use FetchState to verify the NewCommitment field is populated
	// correctly in the returned transition object.
	_, fetchedTransitionOpt, err := h.commitMachine.FetchState(
		h.ctx, h.assetSpec,
	)
	fetchedTransition := fetchedTransitionOpt.UnwrapOrFail(t)
	require.NoError(t, err)
	require.NotNil(t, fetchedTransition.NewCommitment.Txn)
	require.Equal(
		t, commitTxid2, fetchedTransition.NewCommitment.Txn.TxHash(),
	)
	require.Equal(
		t, internalKey.SerializeCompressed(),
		fetchedTransition.NewCommitment.InternalKey.SerializeCompressed(), //nolint:lll
	)
	require.Equal(
		t, outputKey.SerializeCompressed(),
		fetchedTransition.NewCommitment.OutputKey.SerializeCompressed(),
	)
}

// TestSupplyCommitState tests committing different state machine states.
func TestSupplyCommitState(t *testing.T) {
	t.Parallel()

	h := newSupplyCommitTestHarness(t)

	// To start with, we'll insert a new state machine to disk.
	h.addTestStateMachine(sql.NullInt64{})

	allStates := []supplycommit.State{
		&supplycommit.DefaultState{},
		&supplycommit.UpdatesPendingState{},
		&supplycommit.CommitTreeCreateState{},
		&supplycommit.CommitTxCreateState{},
		&supplycommit.CommitTxSignState{},
		&supplycommit.CommitBroadcastState{},
		&supplycommit.CommitFinalizeState{},
	}

	// We'll now run through all the tests, then make sure that when we
	// commit a new state, we can read it out again properly to ensure that
	// it has been committed.
	for _, targetState := range allStates {
		t.Run(targetState.String(), func(t *testing.T) {
			err := h.commitMachine.CommitState(
				h.ctx, h.assetSpec, targetState,
			)
			require.NoError(t, err)

			// Verify that via the public we can verify the state
			// was committed.
			fetchedState, _, err := h.commitMachine.FetchState(
				h.ctx, h.assetSpec,
			)
			require.NoError(t, err)
			require.Equal(
				t, targetState.String(), fetchedState.String(),
			)

			// We'll also fetch via the direct SQL API to verify
			// that things have been committed properly.
			stateMachineRow, err := h.fetchStateMachine()
			require.NoError(t, err)
			expectedStateID, err := stateToInt(targetState)
			require.NoError(t, err)
			require.Equal(
				t, expectedStateID,
				stateMachineRow.CurrentStateID,
			)
		})
	}
}

// TestSupplyCommitFetchState tests fetching the state machine state and
// transition details.
func TestSupplyCommitFetchState(t *testing.T) {
	t.Parallel()
	h := newSupplyCommitTestHarness(t)

	// If not state machine exists, then just the default state should be
	// returned.
	state, transitionOpt, err := h.commitMachine.FetchState(
		h.ctx, h.assetSpec,
	)
	require.NoError(t, err)
	require.IsType(t, &supplycommit.DefaultState{}, state)
	require.False(t, transitionOpt.IsSome())

	// Now, we'll create a state machine, then query for the state again. We
	// should still get the default state, but not transition should exist
	// yet.
	h.addTestStateMachine(sql.NullInt64{})
	state, transitionOpt, err = h.commitMachine.FetchState(
		h.ctx, h.assetSpec,
	)
	require.NoError(t, err)
	require.IsType(t, &supplycommit.DefaultState{}, state)
	require.False(t, transitionOpt.IsSome())

	// Next, we'll make a pending update, then query for the state again. We
	// should also be able to query for the transition inserted on disk.
	event1 := h.randMintEvent()
	err = h.commitMachine.InsertPendingUpdate(
		h.ctx, h.assetSpec, event1,
	)
	require.NoError(t, err)
	_, err = h.fetchPendingTransition()
	require.NoError(t, err)

	// Now we'll query the state again, after we inserted the pending
	// update, the state should have transitioned.
	state, transitionOpt, err = h.commitMachine.FetchState(
		h.ctx, h.assetSpec,
	)
	require.NoError(t, err)
	require.IsType(t, &supplycommit.UpdatesPendingState{}, state)
	require.True(t, transitionOpt.IsSome())
	transition := transitionOpt.UnwrapOrFail(t)
	require.False(t, transition.OldCommitment.IsSome())
	require.Len(t, transition.PendingUpdates, 1)
	require.Nil(t, transition.NewCommitment.Txn)
	require.False(t, transition.ChainProof.IsSome())

	// Next, we'll insert a signed commitment transaction.
	commitTx := randTx(t, 1)
	internalKey := test.RandPubKey(t)
	outputKey := test.RandPubKey(t)

	commitDetails := supplycommit.SupplyCommitTxn{
		Txn:         commitTx,
		InternalKey: internalKey,
		OutputKey:   outputKey,
		OutputIndex: 1,
	}
	err = h.commitMachine.InsertSignedCommitTx(
		h.ctx, h.assetSpec, commitDetails,
	)
	require.NoError(t, err)

	// After the commitment transaction was inserted, the state should be
	// updated, and the pending commitment accounted for.
	state, transitionOpt, err = h.commitMachine.FetchState(
		h.ctx, h.assetSpec,
	)
	require.NoError(t, err)
	require.IsType(t, &supplycommit.CommitBroadcastState{}, state)
	require.True(t, transitionOpt.IsSome())
	transition = transitionOpt.UnwrapOrFail(t)
	require.False(t, transition.OldCommitment.IsSome())
	require.Len(t, transition.PendingUpdates, 1)
	require.NotNil(t, transition.NewCommitment.Txn)
	require.Equal(
		t, commitTx.TxHash(), transition.NewCommitment.Txn.TxHash(),
	)
	require.False(t, transition.ChainProof.IsSome())

	// Next, we'll simulate a chain confirmation by confirming the
	// transaction on-chain.
	updatedTransition, err := h.fetchPendingTransition()
	require.NoError(t, err)
	require.True(t, updatedTransition.PendingCommitTxnID.Valid)
	commitTxID := updatedTransition.PendingCommitTxnID.Int64
	commitTxRow, err := h.fetchChainTxByID(commitTxID)
	require.NoError(t, err)
	h.confirmChainTx(
		commitTxID, lnutils.ByteSlice(commitTx.TxHash()),
		commitTxRow.RawTx,
	)

	// As a final step, we'll modify the state machine to finalize the
	// transition, and go back to the default state.
	var writeTx SupplyCommitTxOptions
	err = h.commitMachine.db.ExecTx(h.ctx, &writeTx, func(db SupplyCommitStore) error { //nolint:lll
		_, err := db.UpsertSupplyCommitStateMachine(
			h.ctx, SupplyCommitMachineParams{
				GroupKey:           h.groupKeyBytes,
				LatestCommitmentID: updatedTransition.NewCommitmentID, //nolint:lll
				StateName:          sqlStr("DefaultState"),
			})
		if err != nil {
			return err
		}
		return db.FinalizeSupplyCommitTransition(
			h.ctx, updatedTransition.TransitionID,
		)
	},
	)
	require.NoError(t, err)

	// Now that the transition is finalized, the state should be default,
	// and no state transition should be found (it's now finalized).
	state, transitionOpt, err = h.commitMachine.FetchState(
		h.ctx, h.assetSpec,
	)
	require.NoError(t, err)
	require.IsType(t, &supplycommit.DefaultState{}, state)
	require.False(t, transitionOpt.IsSome())
}

// TestSupplyCommitApplyStateTransition tests the full state transition
// application using the public StateMachineStore interface methods via the test
// harness.
func TestSupplyCommitApplyStateTransition(t *testing.T) {
	t.Parallel()

	h := newSupplyCommitTestHarness(t)

	// To kick off our test, we'll perform a single state transition. This
	// entails: adding a set of pending updates, committing the signed
	// commit tx, and finally applying the state transition. After
	// application, we should find that the transition is now final, the
	// state machine points to the latest commitment, and all the supply
	// tress have been updated.
	updates1 := []supplycommit.SupplyUpdateEvent{
		h.randMintEvent(), h.randBurnEvent(),
	}
	stateTransition1 := h.performSingleTransition(updates1)
	h.assertTransitionApplied(stateTransition1)

	// To ensure that we can perform multiple transitions, we'll now do
	// another one, with a new set of events, and then assert that it's been
	// applied properly.
	updates2 := []supplycommit.SupplyUpdateEvent{
		h.randMintEvent(), h.randIgnoreEvent(),
	}
	stateTransition2 := h.performSingleTransition(updates2)
	h.assertTransitionApplied(stateTransition2)
}

// TestSupplyCommitUnspentPrecommits tests the UnspentPrecommits method.
func TestSupplyCommitUnspentPrecommits(t *testing.T) {
	t.Parallel()

	h := newSupplyCommitTestHarness(t)

	// Use a spec specific to this test if needed, or the harness default.
	// Let's create one based on the harness group key but a random ID.
	spec := asset.NewSpecifierOptionalGroupPubKey(
		asset.RandID(t), h.groupPubKey,
	)

	// To start with, we shouldn't have any precommits.
	precommitsRes := h.commitMachine.UnspentPrecommits(h.ctx, spec)
	precommits, err := precommitsRes.Unpack()
	require.NoError(t, err)
	require.Empty(t, precommits)

	// Next, we'll add a new minting batch, and a pre-commit along with it.
	batchID1, _, mintTx1, _, _ := h.addTestMintingBatch()
	_ = h.addTestMintAnchorUniCommitment(batchID1, sql.NullInt64{})

	// At this point, we should find a single pre commitment on disk.
	precommitsRes = h.commitMachine.UnspentPrecommits(h.ctx, spec)
	precommits, err = precommitsRes.Unpack()
	require.NoError(t, err)
	require.Len(t, precommits, 1)
	require.Equal(t, mintTx1.TxHash(), precommits[0].MintingTxn.TxHash())

	// Next, we'll add another pre commitment, and this time associate it
	// (spend it) by a supply commitment.
	//nolint:lll
	batchID2, commitTxDbID2, _, commitTxid2, commitRawTx2 := h.addTestMintingBatch()
	commitID2 := h.addTestSupplyCommitment(
		commitTxDbID2, commitTxid2, commitRawTx2, false,
	)
	_ = h.addTestMintAnchorUniCommitment(batchID2, sqlInt64(commitID2))

	// We should now find two pre-commitments.
	precommitsRes = h.commitMachine.UnspentPrecommits(h.ctx, spec)
	precommits, err = precommitsRes.Unpack()
	require.NoError(t, err)
	require.Len(t, precommits, 2)

	// Next, we'll confirm the transaction associated with the second pre
	// commitment spend.
	blockHash := test.RandBytes(32)
	blockHeight := sqlInt32(123)
	txIndex := sqlInt32(1)
	_, err = h.db.UpsertChainTx(h.ctx, sqlc.UpsertChainTxParams{
		Txid:        commitTxid2,
		RawTx:       commitRawTx2,
		ChainFees:   0,
		BlockHash:   blockHash,
		BlockHeight: blockHeight,
		TxIndex:     txIndex,
	})
	require.NoError(t, err)

	// As the transaction was confirmed above, we should now only have a
	// single pre commitment on disk.
	precommitsRes = h.commitMachine.UnspentPrecommits(h.ctx, spec)
	precommits, err = precommitsRes.Unpack()
	require.NoError(t, err)
	require.Len(t, precommits, 1)

	// If we pick a new random public key, then we shouldn't be able to find
	// any pre-commitments for it.
	otherGroupKey := test.RandPubKey(t)
	otherSpec := asset.NewSpecifierOptionalGroupPubKey(
		asset.RandID(t), otherGroupKey,
	)
	precommitsRes = h.commitMachine.UnspentPrecommits(h.ctx, otherSpec)
	precommits, err = precommitsRes.Unpack()
	require.NoError(t, err)
	require.Empty(t, precommits)

	// Finally, trying with a missing group key should yield an error.
	emptySpec := asset.NewSpecifierOptionalGroupKey(asset.RandID(t), nil)
	precommitsRes = h.commitMachine.UnspentPrecommits(h.ctx, emptySpec)
	require.ErrorIs(t, precommitsRes.Err(), ErrMissingGroupKey)
}

// TestSupplyCommitMachineFetch tests the SupplyCommit method.
func TestSupplyCommitMachineFetch(t *testing.T) {
	t.Parallel()

	h := newSupplyCommitTestHarness(t)

	// Use a spec specific to this test if needed, or the harness default.
	spec := asset.NewSpecifierOptionalGroupPubKey(
		asset.RandID(t), h.groupPubKey,
	)

	// At the very start, we shouldn't have any commitments at all for this
	// spec.
	commitRes := h.commitMachine.SupplyCommit(h.ctx, spec)
	commitOpt, err := commitRes.Unpack()
	require.NoError(t, err)
	require.True(t, commitOpt.IsNone())

	// If we add a state machine, then we should still find no commitments.
	h.addTestStateMachine(sql.NullInt64{})
	commitRes = h.commitMachine.SupplyCommit(h.ctx, spec)
	commitOpt, err = commitRes.Unpack()
	require.NoError(t, err)
	require.True(t, commitOpt.IsNone())

	// Next, we'll add a new supply commitment, and also a state machine to
	// go along with it which we'll link to the commitment.
	//nolint:lll
	_, commitTxDbID1, commitTx1, commitTxid1, commitRawTx1 := h.addTestMintingBatch()
	commitID1 := h.addTestSupplyCommitment(
		commitTxDbID1, commitTxid1, commitRawTx1, false,
	)
	h.addTestStateMachine(sqlInt64(commitID1))

	// At this point, with the default query, as the above commitment isn't
	// confirmed yet, we should still find no commitments.
	commitRes = h.commitMachine.SupplyCommit(h.ctx, spec)
	commitOpt, err = commitRes.Unpack()
	require.NoError(t, err)
	require.True(t, commitOpt.IsNone())

	// If we now confirm the commitment we created, then we should find the
	// supply commitment.
	blockHash := test.RandBytes(32)
	blockHeight := sqlInt32(123)
	txIndex := sqlInt32(1)
	_, err = h.db.UpsertChainTx(h.ctx, sqlc.UpsertChainTxParams{
		Txid:        commitTxid1,
		RawTx:       commitRawTx1,
		ChainFees:   0,
		BlockHash:   blockHash,
		BlockHeight: blockHeight,
		TxIndex:     txIndex,
	})
	require.NoError(t, err)

	// We should find the supply commitment has been found now, as we
	// confirmed it above.
	commitRes = h.commitMachine.SupplyCommit(h.ctx, spec)
	commitOpt, err = commitRes.Unpack()
	require.NoError(t, err)
	require.False(t, commitOpt.IsNone())

	// Fetch the commitment details directly for comparison.
	var dbCommit sqlc.SupplyCommitment
	readTx := NewSupplyCommitReadTx()
	err = h.commitMachine.db.ExecTx(
		h.ctx, &readTx, func(dbtx SupplyCommitStore) error {
			var txErr error
			dbCommit, txErr = dbtx.QuerySupplyCommitment(
				h.ctx, commitID1,
			)
			return txErr
		},
	)
	require.NoError(t, err)

	// We'll now assert that the populated commitment we just read matches
	// what we have on disk.
	rootCommit := commitOpt.UnwrapOrFail(t)
	require.Equal(t, commitTx1.TxHash(), rootCommit.Txn.TxHash())
	require.Equal(
		t, uint32(dbCommit.OutputIndex.Int32), rootCommit.TxOutIdx,
	)

	dbInternalKeyRow, err := h.db.FetchInternalKeyByID(
		h.ctx, dbCommit.InternalKeyID,
	)
	require.NoError(t, err)
	require.Equal(
		t, dbInternalKeyRow.RawKey,
		rootCommit.InternalKey.SerializeCompressed(),
	)
	require.Equal(
		t, dbCommit.OutputKey,
		rootCommit.OutputKey.SerializeCompressed(),
	)

	// Verify the root constructed from stored hash/sum.
	require.NotNil(t, rootCommit.SupplyRoot)
	require.Equal(
		t, dbCommit.SupplyRootHash,
		lnutils.ByteSlice(rootCommit.SupplyRoot.NodeHash()),
	)
	require.Equal(
		t, dbCommit.SupplyRootSum.Int64,
		int64(rootCommit.SupplyRoot.NodeSum()),
	)

	// Assert that using a different group key should yield no commitments.
	emptySpec := asset.NewSpecifierOptionalGroupKey(asset.RandID(t), nil)
	commitRes = h.commitMachine.SupplyCommit(h.ctx, emptySpec)
	require.ErrorIs(t, commitRes.Err(), ErrMissingGroupKey)
}

// randTx creates a random transaction for testing purposes.
func randTx(t *testing.T, numOutputs int) *wire.MsgTx {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: test.RandOp(t),
	})

	for i := 0; i < numOutputs; i++ {
		tx.AddTxOut(&wire.TxOut{
			Value:    1000,
			PkScript: test.RandBytes(22),
		})
	}

	return tx
}

// TestSupplyCommitMultipleSupplyCommitments tests that multiple rows can be
// inserted into the supply_commitments table without violating foreign key
// constraints related to SMT root namespaces, reusing the existing test setup
// helper.
func TestSupplyCommitMultipleSupplyCommitments(t *testing.T) {
	t.Parallel()

	h := newSupplyCommitTestHarness(t)

	// Helper to generate unique transaction data for each commitment
	genTxData := func() (int64, []byte, []byte) {
		genesisPoint := test.RandOp(h.t)
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: genesisPoint,
		})
		tx.AddTxOut(&wire.TxOut{
			Value:    1000,
			PkScript: test.RandBytes(20),
		})

		txBytes, err := encodeTx(tx)
		require.NoError(h.t, err)
		txid := tx.TxHash()
		chainTxID, err := h.db.UpsertChainTx(
			h.ctx, sqlc.UpsertChainTxParams{
				Txid:  txid[:],
				RawTx: txBytes,
			},
		)
		require.NoError(h.t, err)
		return chainTxID, txid[:], txBytes
	}

	// Insert the first commitment using the harness method.
	chainTxID1, txid1, rawTx1 := genTxData()
	_ = h.addTestSupplyCommitment(
		chainTxID1, txid1, rawTx1, false,
	)

	// Insert the second commitment with the same group key, but distinct
	// data, using the harness method.
	chainTxID2, txid2, rawTx2 := genTxData()
	_ = h.addTestSupplyCommitment(
		chainTxID2, txid2, rawTx2, false,
	)

	// If we reached here without errors during the addTestSupplyCommitment
	// calls (which includes InsertSupplyCommitment), the test passes.
}

func encodeTx(tx *wire.MsgTx) ([]byte, error) {
	var buf bytes.Buffer
	err := tx.Serialize(&buf)
	return buf.Bytes(), err
}
