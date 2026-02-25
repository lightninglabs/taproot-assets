package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightninglabs/taproot-assets/universe/supplyverifier"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
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
func (h *supplyCommitTestHarness) addTestMintingBatch() ([]byte, int64,
	*wire.MsgTx, []byte, []byte) {

	h.t.Helper()

	ctx := h.ctx
	db := h.db

	batchKeyDesc, _ := test.RandKeyDesc(h.t)
	batchKeyBytes := batchKeyDesc.PubKey.SerializeCompressed()
	batchKeyID, err := db.UpsertInternalKey(
		ctx, sqlc.UpsertInternalKeyParams{
			RawKey:    batchKeyBytes,
			KeyFamily: int32(batchKeyDesc.Family),
			KeyIndex:  int32(batchKeyDesc.Index),
		},
	)
	require.NoError(h.t, err)

	genesisPoint := test.RandOp(h.t)
	genesisPointID, err := upsertGenesisPoint(ctx, db, genesisPoint)
	require.NoError(h.t, err)

	mintingTx := wire.NewMsgTx(3)
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

	return batchKeyBytes, mintTxDbID, mintingTx, mintTxID[:], mintTxBytes
}

// stateTransitionOutput encapsulates the results of a simulated state
// transition performed by performSingleTransition.
type stateTransitionOutput struct {
	appliedUpdates []supplycommit.SupplyUpdateEvent
	internalKey    keychain.KeyDescriptor
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
		groupKeyBytes:   schnorr.SerializePubKey(setup.groupPubKey),
		assetSpec:       spec,
		baseGenesis:     setup.baseGenesis,
		groupKey:        groupKey,
		batchedTreeDB:   setup.commitTreeStore.db,
		commitTreeStore: setup.commitTreeStore,
	}
}

// addTestMintAnchorUniCommitment inserts a mint_anchor_uni_commitments record
// using harness data and returns both the commitment ID and the outpoint.
func (h *supplyCommitTestHarness) addTestMintAnchorUniCommitment(
	batchKeyBytes []byte, spentBy sql.NullInt64,
	mintTxid chainhash.Hash) (int64, wire.OutPoint) {

	h.t.Helper()

	internalKey, _ := test.RandKeyDesc(h.t)
	internalKeyID, err := h.db.UpsertInternalKey(
		h.ctx, sqlc.UpsertInternalKeyParams{
			RawKey:    internalKey.PubKey.SerializeCompressed(),
			KeyFamily: int32(internalKey.KeyLocator.Family),
			KeyIndex:  int32(internalKey.KeyLocator.Index),
		},
	)
	require.NoError(h.t, err)

	txOutputIndex := int32(test.RandInt[uint32]())

	outpoint := wire.OutPoint{
		Hash:  mintTxid,
		Index: uint32(txOutputIndex),
	}

	var outpointBuf bytes.Buffer
	err = wire.WriteOutPoint(&outpointBuf, 0, 0, &outpoint)
	require.NoError(h.t, err)

	anchorCommitID, err := h.db.UpsertMintSupplyPreCommit(
		h.ctx, UpsertBatchPreCommitParams{
			BatchKey:             batchKeyBytes,
			TxOutputIndex:        txOutputIndex,
			TaprootInternalKeyID: internalKeyID,
			GroupKey:             h.groupKeyBytes,
			SpentBy:              spentBy,
			Outpoint:             outpointBuf.Bytes(),
		},
	)
	require.NoError(h.t, err)

	return anchorCommitID, outpoint
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

// fetchDanglingUpdates fetches all dangling updates for the harness's group key.
//
//nolint:lll
func (h *supplyCommitTestHarness) fetchDanglingUpdates() []QueryDanglingSupplyUpdateResp {
	h.t.Helper()

	var danglingUpdates []QueryDanglingSupplyUpdateResp
	readTx := ReadTxOption()
	err := h.commitMachine.db.ExecTx(h.ctx, readTx,
		func(db SupplyCommitStore) error {
			var txErr error
			danglingUpdates, txErr = db.QueryDanglingSupplyUpdateEvents(
				h.ctx, h.groupKeyBytes,
			)
			if errors.Is(txErr, sql.ErrNoRows) {
				return nil
			}
			return txErr
		},
	)
	require.NoError(h.t, err)

	return danglingUpdates
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

	// Check that creation time is set and is recent. We allow a small delta
	// to account for test execution time and potential slight clock
	// differences if the DB were remote (though it's embedded for tests).
	require.NotZero(h.t, dbTransition.CreationTime)
	creationTime := time.Unix(dbTransition.CreationTime, 0)
	require.WithinDuration(
		h.t, time.Now(), creationTime, 5*time.Second,
	)
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
	readTx := ReadTxOption()
	err := h.commitMachine.db.ExecTx(
		h.ctx, readTx, func(db SupplyCommitStore) error {
			pendingRow, txErr := db.QueryPendingSupplyCommitTransition( //nolint:lll
				h.ctx, h.groupKeyBytes,
			)
			if txErr == nil {
				transition = pendingRow.SupplyCommitTransition
			}
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
	readTx := ReadTxOption()
	err := h.commitMachine.db.ExecTx(h.ctx, readTx,
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
		finalRoot mssmt.Node
	)
	err = commitDB.db.ExecTx(
		ctx, WriteTxOption(), func(dbtx SupplyCommitStore) error {
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
	readTx := ReadTxOption()
	err := h.commitMachine.db.ExecTx(
		h.ctx, readTx, func(db SupplyCommitStore) error {
			row, err := db.QuerySupplyCommitment(h.ctx, commitID)
			if err != nil {
				return err
			}

			commitment = row.SupplyCommitment

			return nil
		},
	)
	return commitment, err
}

// fetchInternalKeyByID fetches an internal key by ID directly via SQL.
func (h *supplyCommitTestHarness) fetchInternalKeyByID(
	keyID int64) FetchInternalKeyByIDRow {

	h.t.Helper()
	var keyRow FetchInternalKeyByIDRow
	readTx := ReadTxOption()
	err := h.commitMachine.db.ExecTx(
		h.ctx, readTx, func(db SupplyCommitStore) error {
			var txErr error
			keyRow, txErr = db.FetchInternalKeyByID(h.ctx, keyID)
			return txErr
		},
	)
	require.NoError(h.t, err)
	return keyRow
}

// assertDbCommit checks that the given db supply commitment matches the
// expected root commitment and returns an error if they don't match.
func (h *supplyCommitTestHarness) assertDbCommit(
	dbSupplyCommit sqlc.SupplyCommitment,
	expectedCommit supplycommit.RootCommitment) error {

	// Verify the supply root matches (if set).
	if len(dbSupplyCommit.SupplyRootHash) > 0 &&
		dbSupplyCommit.SupplyRootSum.Valid {

		if expectedCommit.SupplyRoot == nil {
			return fmt.Errorf("expected root commitment has nil " +
				"SupplyRoot")
		}

		expectedSum := int64(expectedCommit.SupplyRoot.NodeSum())
		if dbSupplyCommit.SupplyRootSum.Int64 != expectedSum {
			return fmt.Errorf("supply root sum mismatch: db=%d, "+
				"expected=%d",
				dbSupplyCommit.SupplyRootSum.Int64, expectedSum)
		}

		expectedRootHash := lnutils.ByteSlice(
			expectedCommit.SupplyRoot.NodeHash(),
		)
		if !bytes.Equal(
			dbSupplyCommit.SupplyRootHash, expectedRootHash,
		) {

			return fmt.Errorf("supply root hash mismatch: db=%x, "+
				"expected=%x", dbSupplyCommit.SupplyRootHash,
				expectedRootHash)
		}
	}

	// Verify the transaction hash matches.
	expectedTxRow, err := h.fetchChainTxByID(dbSupplyCommit.ChainTxnID)
	if err != nil {
		return fmt.Errorf("failed to fetch chain tx by ID %d: %w",
			dbSupplyCommit.ChainTxnID, err)
	}

	var expectedTx wire.MsgTx
	err = expectedTx.Deserialize(bytes.NewReader(expectedTxRow.RawTx))
	if err != nil {
		return fmt.Errorf("failed to deserialize expected tx: %w", err)
	}

	if expectedTx.TxHash() != expectedCommit.Txn.TxHash() {
		return fmt.Errorf("transaction hash mismatch: db=%s, "+
			"expected=%s", expectedTx.TxHash(),
			expectedCommit.Txn.TxHash())
	}

	// Verify the output index matches.
	expectedOutIdx := uint32(dbSupplyCommit.OutputIndex.Int32)
	if expectedOutIdx != expectedCommit.TxOutIdx {
		return fmt.Errorf("output index mismatch: db=%d, expected=%d",
			expectedOutIdx, expectedCommit.TxOutIdx)
	}

	// Verify the internal key matches.
	dbInternalKeyRow := h.fetchInternalKeyByID(
		dbSupplyCommit.InternalKeyID,
	)
	expectedInternalKeyBytes :=
		expectedCommit.InternalKey.PubKey.SerializeCompressed()
	if !bytes.Equal(dbInternalKeyRow.RawKey, expectedInternalKeyBytes) {
		return fmt.Errorf("internal key mismatch: db=%x, expected=%x",
			dbInternalKeyRow.RawKey, expectedInternalKeyBytes)
	}

	// Verify the output key matches.
	expectedOutputKeyBytes :=
		expectedCommit.OutputKey.SerializeCompressed()
	if !bytes.Equal(dbSupplyCommit.OutputKey, expectedOutputKeyBytes) {
		return fmt.Errorf("output key mismatch: db=%x, expected=%x",
			dbSupplyCommit.OutputKey, expectedOutputKeyBytes)
	}

	return nil
}

// assertLatestCommit fetches the latest supply commitment using the public
// FetchLatestCommitment method and asserts it matches the given db supply
// commitment.
func (h *supplyCommitTestHarness) assertLatestCommit(
	dbSupplyCommit sqlc.SupplyCommitment) {

	h.t.Helper()

	// Fetch the latest commitment using the public method.
	latestCommit, err := h.commitMachine.FetchLatestCommitment(
		h.ctx, h.assetSpec,
	)
	require.NoError(h.t, err)
	require.NotNil(h.t, latestCommit)

	// Verify the commitments are equal.
	err = h.assertDbCommit(dbSupplyCommit, *latestCommit)
	require.NoError(h.t, err)
}

// fetchChainTxByID fetches a chain tx by ID directly via SQL.
func (h *supplyCommitTestHarness) fetchChainTxByID(
	txID int64) (FetchChainTxByIDRow, error) {

	var chainTx FetchChainTxByIDRow
	readTx := ReadTxOption()
	err := h.commitMachine.db.ExecTx(
		h.ctx, readTx, func(db SupplyCommitStore) error {
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

	writeTx := WriteTxOption()
	err := h.commitMachine.db.ExecTx(
		h.ctx, writeTx, func(db SupplyCommitStore) error {
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
	updates []supplycommit.SupplyUpdateEvent,
	preCommitOutpoints []wire.OutPoint,
	blockHeight uint32) stateTransitionOutput {

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

	// Add inputs to the transaction that spend the pre-commitment outputs.
	for _, outpoint := range preCommitOutpoints {
		commitTx.TxIn = append(commitTx.TxIn, &wire.TxIn{
			PreviousOutPoint: outpoint,
		})
	}

	internalKey, _ := test.RandKeyDesc(h.t)
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

	// Obtain the final root tree after our insertions.
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
	h.assertLatestCommit(dbCommitment)

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
		h.t, internalKey.PubKey.SerializeCompressed(),
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
		h.t, output.internalKey.PubKey.SerializeCompressed(),
		fetchedCommit.InternalKey.PubKey.SerializeCompressed(),
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

// TestSupplyCommitInsertPendingUpdate tests the insertion of pending updates,
// including the creation of dangling events when a transition is frozen.
func TestSupplyCommitInsertPendingUpdate(t *testing.T) {
	t.Parallel()

	h := newSupplyCommitTestHarness(t)

	// Insert a first event. This should create a new non-frozen transition
	// and associate this event with it.
	event1 := h.randMintEvent()
	err := h.commitMachine.InsertPendingUpdate(h.ctx, h.assetSpec, event1)
	require.NoError(t, err)

	// Verify state machine is now in UpdatesPendingState.
	h.assertCurrentStateIs(&supplycommit.UpdatesPendingState{})

	// Verify a pending transition exists and is not frozen.
	dbTransition1 := h.assertPendingTransitionExists()
	h.assertTransitionInitialState(dbTransition1)
	require.False(t, dbTransition1.Frozen)

	// The pending transition should contain exactly our first event.
	h.assertPendingUpdates([]supplycommit.SupplyUpdateEvent{event1})
	require.Empty(t, h.fetchDanglingUpdates())

	// Now we'll insert a second event. Since the transition is not frozen,
	// this should be added to the existing transition.
	event2 := h.randBurnEvent()
	err = h.commitMachine.InsertPendingUpdate(h.ctx, h.assetSpec, event2)
	require.NoError(t, err)

	// State should be the same.
	h.assertCurrentStateIs(&supplycommit.UpdatesPendingState{})
	dbTransition2 := h.assertPendingTransitionExists()
	require.Equal(t, dbTransition1.TransitionID, dbTransition2.TransitionID)

	// The pending transition should now contain both events.
	h.assertPendingUpdates([]supplycommit.SupplyUpdateEvent{event1, event2})
	require.Empty(t, h.fetchDanglingUpdates())

	// Now, freeze the pending transition.
	err = h.commitMachine.FreezePendingTransition(h.ctx, h.assetSpec)
	require.NoError(t, err)

	// Verify it's marked as frozen in the DB.
	dbTransition3 := h.assertPendingTransitionExists()
	require.True(t, dbTransition3.Frozen)

	// Insert a third event. Since the transition is now frozen, this should
	// become a dangling event.
	event3 := h.randIgnoreEvent()
	err = h.commitMachine.InsertPendingUpdate(h.ctx, h.assetSpec, event3)
	require.NoError(t, err)

	// The main transition's updates should be unchanged.
	h.assertPendingUpdates([]supplycommit.SupplyUpdateEvent{event1, event2})

	// We should now have one dangling event.
	danglingEvents := h.fetchDanglingUpdates()
	require.Len(t, danglingEvents, 1)
	deserializedDangling, err := deserializeSupplyUpdateEvent(
		danglingEvents[0].UpdateTypeName,
		bytes.NewReader(danglingEvents[0].EventData),
	)
	require.NoError(t, err)
	assertEqualEvents(t, event3, deserializedDangling)
}

// TestBindDanglingUpdatesToTransition tests the logic for binding dangling
// updates to a new transition.
func TestBindDanglingUpdatesToTransition(t *testing.T) {
	t.Parallel()

	h := newSupplyCommitTestHarness(t)

	// If no dangling updates exist, the method should be a no-op.
	boundEvents, err := h.commitMachine.BindDanglingUpdatesToTransition(
		h.ctx, h.assetSpec,
	)
	require.NoError(t, err)
	require.Empty(t, boundEvents)
	h.assertNoPendingTransition()

	// To create dangling updates, we first need a state machine and a
	// finalized transition.
	updates1 := []supplycommit.SupplyUpdateEvent{h.randMintEvent()}
	// Pass empty outpoints since this test doesn't need pre-commitments
	stateTransition1 := h.performSingleTransition(
		updates1, []wire.OutPoint{}, 442,
	)
	h.assertTransitionApplied(stateTransition1)

	// Now, with the machine in DefaultState, we'll manually insert some
	// dangling events into the DB. This simulates events arriving while a
	// transition was in flight and frozen.
	danglingEvent1 := h.randBurnEvent()
	danglingEvent2 := h.randIgnoreEvent()
	danglingEventsToInsert := []supplycommit.SupplyUpdateEvent{
		danglingEvent1, danglingEvent2,
	}

	// We use a custom transaction to short circuit some of the logic in the
	// public API.
	writeTx := WriteTxOption()
	err = h.commitMachine.db.ExecTx(
		h.ctx, writeTx, func(db SupplyCommitStore) error {
			for _, event := range danglingEventsToInsert {
				var b bytes.Buffer
				err := serializeSupplyUpdateEvent(&b, event)
				require.NoError(t, err)
				updateTypeID, err := updateTypeToInt(
					event.SupplySubTreeType(),
				)
				require.NoError(t, err)

				err = db.InsertSupplyUpdateEvent(
					h.ctx, InsertSupplyUpdateEvent{
						GroupKey:     h.groupKeyBytes,
						TransitionID: sql.NullInt64{},
						UpdateTypeID: updateTypeID,
						EventData:    b.Bytes(),
					},
				)
				require.NoError(t, err)
			}

			return nil
		},
	)
	require.NoError(t, err)

	// We should now that that updates are properly dangling.
	require.Len(t, h.fetchDanglingUpdates(), 2)

	// Now we'll bind the set of dangling updates, this should create a new
	// state transition and associate the events with it.
	boundEvents, err = h.commitMachine.BindDanglingUpdatesToTransition(
		h.ctx, h.assetSpec,
	)
	require.NoError(t, err)

	// Assert that the returned events match what we inserted. We'll sort
	// first to ensure a deterministic comparison.
	sorter := func(events []supplycommit.SupplyUpdateEvent) {
		sort.SliceStable(events, func(i, j int) bool {
			keyI := events[i].UniverseLeafKey().UniverseKey()
			keyJ := events[j].UniverseLeafKey().UniverseKey()
			return bytes.Compare(keyI[:], keyJ[:]) < 0
		})
	}
	sorter(danglingEventsToInsert)
	sorter(boundEvents)
	require.Len(t, boundEvents, 2)

	// The dangling events read out should now match what we inserted.
	assertEqualEvents(t, danglingEventsToInsert[0], boundEvents[0])
	assertEqualEvents(t, danglingEventsToInsert[1], boundEvents[1])

	// A new state transition should have been created, and there should be
	// no dangling updates.
	dbTransition := h.assertPendingTransitionExists()
	require.Empty(t, h.fetchDanglingUpdates())

	// The state transition should also now include the set of dangling
	// updates.
	h.assertPendingUpdates(danglingEventsToInsert)

	// The new transition's old_commitment_id should point to the one from
	// the finalized transition.
	stateMachine, err := h.fetchStateMachine()
	require.NoError(t, err)
	require.True(t, stateMachine.LatestCommitmentID.Valid)
	require.Equal(
		t, stateMachine.LatestCommitmentID,
		dbTransition.OldCommitmentID,
	)
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
	internalKey, _ := test.RandKeyDesc(t)
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
		internalKey.PubKey.SerializeCompressed(),
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
		t, internalKey.PubKey.SerializeCompressed(),
		fetchedTransition.NewCommitment.InternalKey.PubKey.SerializeCompressed(), //nolint:lll
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
	internalKey, _ := test.RandKeyDesc(t)
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
	writeTx := WriteTxOption()
	err = h.commitMachine.db.ExecTx(
		h.ctx, writeTx, func(db SupplyCommitStore) error {
			//nolint:lll
			params := SupplyCommitMachineParams{
				GroupKey:           h.groupKeyBytes,
				LatestCommitmentID: updatedTransition.NewCommitmentID,
				StateName:          sqlStr("DefaultState"),
			}
			_, err := db.UpsertSupplyCommitStateMachine(
				h.ctx, params,
			)
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

	// First, let's create some pre-commitments that should be spent when we
	// apply the state transition. We'll create mint transactions and track
	// their outpoints.
	batchKeyBytes1, _, _, mintTxidBytes1, _ := h.addTestMintingBatch()
	var mintTxid1 chainhash.Hash
	copy(mintTxid1[:], mintTxidBytes1)
	_, outpoint1 := h.addTestMintAnchorUniCommitment(
		batchKeyBytes1, sql.NullInt64{}, mintTxid1,
	)
	batchKeyBytes2, _, _, mintTxidBytes2, _ := h.addTestMintingBatch()
	var mintTxid2 chainhash.Hash
	copy(mintTxid2[:], mintTxidBytes2)
	_, outpoint2 := h.addTestMintAnchorUniCommitment(
		batchKeyBytes2, sql.NullInt64{}, mintTxid2,
	)

	// Create an additional pre-commitment that should NOT be spent. This
	// tests that we're only marking the specific pre-commitments referenced
	// in the transaction inputs as spent.
	//nolint:lll
	batchKeyBytesExtra, _, _, mintTxidBytesExtra, _ := h.addTestMintingBatch()
	var mintTxidExtra chainhash.Hash
	copy(mintTxidExtra[:], mintTxidBytesExtra)
	_, outpointExtra := h.addTestMintAnchorUniCommitment(
		batchKeyBytesExtra, sql.NullInt64{}, mintTxidExtra,
	)

	// Collect only the first two outpoints for the transaction inputs. The
	// extra one should remain unspent
	preCommitOutpoints := []wire.OutPoint{outpoint1, outpoint2}

	// Verify we have all three unspent pre-commitments before the
	// transition.
	precommitsRes := h.commitMachine.UnspentPrecommits(
		h.ctx, h.assetSpec, true,
	)
	precommits, err := precommitsRes.Unpack()
	require.NoError(t, err)
	require.Len(
		t, precommits, 3, "should have 3 unspent pre-commitments "+
			"before transition",
	)

	// To kick off our test, we'll perform a single state transition. This
	// entails: adding a set of pending updates, committing the signed
	// commit tx, and finally applying the state transition. After
	// application, we should find that the transition is now final, the
	// state machine points to the latest commitment, and all the supply
	// tress have been updated.
	updates1 := []supplycommit.SupplyUpdateEvent{
		h.randMintEvent(), h.randBurnEvent(),
	}
	stateTransition1 := h.performSingleTransition(
		updates1, preCommitOutpoints, 1,
	)
	h.assertTransitionApplied(stateTransition1)

	// After the first transition, only the two pre-commitments that were
	// included in the transaction inputs should be marked as spent.
	// The extra pre-commitment should remain unspent.
	precommitsRes = h.commitMachine.UnspentPrecommits(
		h.ctx, h.assetSpec, true,
	)
	precommits, err = precommitsRes.Unpack()
	require.NoError(t, err)
	require.Len(
		t, precommits, 1, "should have 1 unspent pre-commitment after "+
			"first transition (the one not included in tx inputs)",
	)

	// Verify that the remaining unspent pre-commitment is the extra one
	// by checking its outpoint
	remainingPrecommit := precommits[0]
	remainingOutpoint := wire.OutPoint{
		Hash:  remainingPrecommit.MintingTxn.TxHash(),
		Index: remainingPrecommit.OutIdx,
	}

	require.Equal(
		t, outpointExtra, remainingOutpoint,
		"the remaining unspent pre-commitment should be the extra one",
	)

	// Now create new pre-commitments for the second transition.
	batchKeyBytes3, _, _, mintTxidBytes3, _ := h.addTestMintingBatch()
	var mintTxid3 chainhash.Hash
	copy(mintTxid3[:], mintTxidBytes3)
	_, outpoint3 := h.addTestMintAnchorUniCommitment(
		batchKeyBytes3, sql.NullInt64{}, mintTxid3,
	)

	// Verify we have the extra one from before plus the new one.
	precommitsRes = h.commitMachine.UnspentPrecommits(
		h.ctx, h.assetSpec, true,
	)
	precommits, err = precommitsRes.Unpack()
	require.NoError(t, err)
	require.Len(
		t, precommits, 2, "should have 2 unspent pre-commitments "+
			"before second transition (extra from first + new one)",
	)

	// To ensure that we can perform multiple transitions, we'll now do
	// another one, with a new set of events, and then assert that it's been
	// applied properly. This time we'll spend both the extra pre-commitment
	// from the first round and the new one.
	updates2 := []supplycommit.SupplyUpdateEvent{
		h.randMintEvent(), h.randIgnoreEvent(),
	}
	preCommitOutpoints2 := []wire.OutPoint{outpointExtra, outpoint3}
	stateTransition2 := h.performSingleTransition(
		updates2, preCommitOutpoints2, 2,
	)
	h.assertTransitionApplied(stateTransition2)

	// After the second transition, the new pre-commitment should also be
	// spent. Finally, verify that no unspent pre-commitments remain.
	precommitsRes = h.commitMachine.UnspentPrecommits(
		h.ctx, h.assetSpec, true,
	)
	precommits, err = precommitsRes.Unpack()
	require.NoError(t, err)
	require.Empty(
		t, precommits, "should have no unspent pre-commitments after "+
			"all transitions",
	)
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
	precommitsRes := h.commitMachine.UnspentPrecommits(h.ctx, spec, true)
	precommits, err := precommitsRes.Unpack()
	require.NoError(t, err)
	require.Empty(t, precommits)

	// Next, we'll add a new minting batch, and a pre-commit along with it.
	batchKeyBytes, _, mintTx1, mintTxidBytes, _ := h.addTestMintingBatch()
	var mintTxid chainhash.Hash
	copy(mintTxid[:], mintTxidBytes)
	_, _ = h.addTestMintAnchorUniCommitment(
		batchKeyBytes, sql.NullInt64{}, mintTxid,
	)

	// At this point, we should find a single pre commitment on disk.
	precommitsRes = h.commitMachine.UnspentPrecommits(h.ctx, spec, true)
	precommits, err = precommitsRes.Unpack()
	require.NoError(t, err)
	require.Len(t, precommits, 1)
	require.Equal(t, mintTx1.TxHash(), precommits[0].MintingTxn.TxHash())

	// Next, we'll add another pre commitment, and this time associate it
	// (spend it) by a supply commitment.
	//nolint:lll
	batchKeyBytes, commitTxDbID2, _, commitTxidBytes2, commitRawTx2 := h.addTestMintingBatch()
	var commitTxid2 chainhash.Hash
	copy(commitTxid2[:], commitTxidBytes2)
	commitID2 := h.addTestSupplyCommitment(
		commitTxDbID2, commitTxidBytes2, commitRawTx2, false,
	)
	_, _ = h.addTestMintAnchorUniCommitment(
		batchKeyBytes, sqlInt64(commitID2), commitTxid2,
	)

	// We should now find two pre-commitments.
	precommitsRes = h.commitMachine.UnspentPrecommits(h.ctx, spec, true)
	precommits, err = precommitsRes.Unpack()
	require.NoError(t, err)
	require.Len(t, precommits, 2)

	// Next, we'll confirm the transaction associated with the second pre
	// commitment spend.
	blockHash := test.RandBytes(32)
	blockHeight := sqlInt32(123)
	txIndex := sqlInt32(1)
	_, err = h.db.UpsertChainTx(h.ctx, sqlc.UpsertChainTxParams{
		Txid:        commitTxid2[:],
		RawTx:       commitRawTx2,
		ChainFees:   0,
		BlockHash:   blockHash,
		BlockHeight: blockHeight,
		TxIndex:     txIndex,
	})
	require.NoError(t, err)

	// As the transaction was confirmed above, we should now only have a
	// single pre commitment on disk.
	precommitsRes = h.commitMachine.UnspentPrecommits(h.ctx, spec, true)
	precommits, err = precommitsRes.Unpack()
	require.NoError(t, err)
	require.Len(t, precommits, 1)

	// If we pick a new random public key, then we shouldn't be able to find
	// any pre-commitments for it.
	otherGroupKey := test.RandPubKey(t)
	otherSpec := asset.NewSpecifierOptionalGroupPubKey(
		asset.RandID(t), otherGroupKey,
	)
	precommitsRes = h.commitMachine.UnspentPrecommits(
		h.ctx, otherSpec, true,
	)
	precommits, err = precommitsRes.Unpack()
	require.NoError(t, err)
	require.Empty(t, precommits)

	// Finally, trying with a missing group key should yield an error.
	emptySpec := asset.NewSpecifierOptionalGroupKey(asset.RandID(t), nil)
	precommitsRes = h.commitMachine.UnspentPrecommits(
		h.ctx, emptySpec, true,
	)
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
	_, commitTxDbID1, commitTx1, commitTxid1, commitRawTx1 :=
		h.addTestMintingBatch()
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
	dbCommit, err := h.fetchCommitmentByID(commitID1)
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
		rootCommit.InternalKey.PubKey.SerializeCompressed(),
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

// TestSupplyCommitFetchLatestCommitment tests the FetchLatestCommitment method.
func TestSupplyCommitFetchLatestCommitment(t *testing.T) {
	t.Parallel()

	h := newSupplyCommitTestHarness(t)

	spec := asset.NewSpecifierOptionalGroupPubKey(
		asset.RandID(t), h.groupPubKey,
	)

	// At the very start, we shouldn't have any commitments at all for this
	// spec.
	_, err := h.commitMachine.FetchLatestCommitment(h.ctx, spec)
	require.ErrorIs(t, err, supplyverifier.ErrCommitmentNotFound)

	// Add a state machine with no commitment.
	h.addTestStateMachine(sql.NullInt64{})
	_, err = h.commitMachine.FetchLatestCommitment(h.ctx, spec)
	require.ErrorIs(t, err, supplyverifier.ErrCommitmentNotFound)

	// Create the first supply commitment.
	_, commitTxDbID1, _, commitTxid1, commitRawTx1 :=
		h.addTestMintingBatch()
	commitID1 := h.addTestSupplyCommitment(
		commitTxDbID1, commitTxid1, commitRawTx1, false,
	)

	// Confirm the first commitment at block height 100.
	blockHash1 := test.RandBytes(32)
	blockHeight1 := sqlInt32(100)
	txIndex1 := sqlInt32(1)
	_, err = h.db.UpsertChainTx(h.ctx, sqlc.UpsertChainTxParams{
		Txid:        commitTxid1,
		RawTx:       commitRawTx1,
		ChainFees:   0,
		BlockHash:   blockHash1,
		BlockHeight: blockHeight1,
		TxIndex:     txIndex1,
	})
	require.NoError(t, err)

	// Update the state machine to point to the first commitment.
	h.addTestStateMachine(sqlInt64(commitID1))

	// Fetch the first commitment from the DB for comparison.
	dbCommitment1, err := h.fetchCommitmentByID(commitID1)
	require.NoError(t, err)

	// FetchLatestCommitment should return the first commitment.
	h.assertLatestCommit(dbCommitment1)

	// Create a second supply commitment.
	_, commitTxDbID2, _, commitTxid2, commitRawTx2 :=
		h.addTestMintingBatch()
	commitID2 := h.addTestSupplyCommitment(
		commitTxDbID2, commitTxid2, commitRawTx2, false,
	)

	// Confirm the second commitment at block height 200.
	blockHash2 := test.RandBytes(32)
	blockHeight2 := sqlInt32(200)
	txIndex2 := sqlInt32(1)
	_, err = h.db.UpsertChainTx(h.ctx, sqlc.UpsertChainTxParams{
		Txid:        commitTxid2,
		RawTx:       commitRawTx2,
		ChainFees:   0,
		BlockHash:   blockHash2,
		BlockHeight: blockHeight2,
		TxIndex:     txIndex2,
	})
	require.NoError(t, err)

	// Update the state machine to point to the second commitment.
	h.addTestStateMachine(sqlInt64(commitID2))

	// Fetch the second commitment from the DB for comparison.
	dbCommitment2, err := h.fetchCommitmentByID(commitID2)
	require.NoError(t, err)

	// FetchLatestCommitment should now return the second commitment (higher
	// block height).
	h.assertLatestCommit(dbCommitment2)

	// Create a third supply commitment at a lower block height 150 (but
	// inserted later).
	_, commitTxDbID3, _, commitTxid3, commitRawTx3 :=
		h.addTestMintingBatch()
	_ = h.addTestSupplyCommitment(
		commitTxDbID3, commitTxid3, commitRawTx3, false,
	)

	// Confirm the third commitment at block height 150.
	blockHash3 := test.RandBytes(32)
	blockHeight3 := sqlInt32(150)
	txIndex3 := sqlInt32(1)
	_, err = h.db.UpsertChainTx(h.ctx, sqlc.UpsertChainTxParams{
		Txid:        commitTxid3,
		RawTx:       commitRawTx3,
		ChainFees:   0,
		BlockHash:   blockHash3,
		BlockHeight: blockHeight3,
		TxIndex:     txIndex3,
	})
	require.NoError(t, err)

	// FetchLatestCommitment should still return the second commitment
	// (highest block height 200), not the third one (block height 150).
	h.assertLatestCommit(dbCommitment2)

	// Test with a different group key should return ErrCommitmentNotFound.
	otherGroupKey := test.RandPubKey(t)
	otherSpec := asset.NewSpecifierOptionalGroupPubKey(
		asset.RandID(t), otherGroupKey,
	)
	_, err = h.commitMachine.FetchLatestCommitment(
		h.ctx, otherSpec,
	)
	require.ErrorIs(t, err, supplyverifier.ErrCommitmentNotFound)

	// Test with missing group key should yield an error.
	emptySpec := asset.NewSpecifierOptionalGroupKey(asset.RandID(t), nil)
	_, err = h.commitMachine.FetchLatestCommitment(
		h.ctx, emptySpec,
	)
	require.ErrorIs(t, err, ErrMissingGroupKey)
}

// randTx creates a random transaction for testing purposes.
func randTx(t *testing.T, numOutputs int) *wire.MsgTx {
	t.Helper()

	tx := wire.NewMsgTx(3)
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
		tx := wire.NewMsgTx(3)
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

// TestSupplySyncerPushLog tests the LogSupplyCommitPush method which logs
// successful pushes to remote universe servers.
func TestSupplySyncerPushLog(t *testing.T) {
	t.Parallel()

	// Set up the test harness with all necessary components.
	h := newSupplyCommitTestHarness(t)

	// Create a test supply commitment that we can reference.
	// Use the same simple approach as
	// TestSupplyCommitMultipleSupplyCommitments.
	genTxData := func() (int64, []byte, []byte) {
		genesisPoint := test.RandOp(h.t)
		tx := wire.NewMsgTx(3)
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

	chainTxID, txid, rawTx := genTxData()
	commitID := h.addTestSupplyCommitment(chainTxID, txid, rawTx, false)

	// Get the supply root that was created by addTestSupplyCommitment.
	rows, err := h.db.(sqlc.DBTX).QueryContext(h.ctx, `
		SELECT supply_root_hash, supply_root_sum FROM supply_commitments
		WHERE commit_id = $1
	`, commitID)
	require.NoError(t, err)
	defer rows.Close()
	require.True(t, rows.Next(), "Expected supply commitment to exist")

	var (
		rootHashBytes []byte
		rootSum       int64
	)
	err = rows.Scan(&rootHashBytes, &rootSum)
	require.NoError(t, err)
	require.NoError(t, rows.Close())

	var rootHash mssmt.NodeHash
	copy(rootHash[:], rootHashBytes)

	// Decode the raw transaction to get the actual wire.MsgTx used in the
	// test data.
	var actualTx wire.MsgTx
	err = actualTx.Deserialize(bytes.NewReader(rawTx))
	require.NoError(t, err)

	// Create a SupplySyncerStore and test the actual LogSupplyCommitPush
	// method.
	syncerStore := NewSupplySyncerStore(h.batchedTreeDB)

	// Create mock data for the method call.
	serverAddr := universe.NewServerAddrFromStr("localhost:8080")
	supplyRoot := mssmt.NewComputedBranch(rootHash, uint64(rootSum))

	// Create minimal supply leaves - just need something to count.
	// We need at least one leaf or the method returns early without
	// logging.
	mintEvent := supplycommit.NewMintEvent{
		MintHeight: 100,
	}
	leaves := supplycommit.SupplyLeaves{
		IssuanceLeafEntries: []supplycommit.NewMintEvent{mintEvent},
	}

	commitment := supplycommit.RootCommitment{
		SupplyRoot:  supplyRoot,
		Txn:         &actualTx,
		TxOutIdx:    0,
		InternalKey: keychain.KeyDescriptor{PubKey: h.groupPubKey},
		OutputKey:   h.groupPubKey,
	}

	// Record the time before the call to verify timestamp is recent.
	beforeCall := time.Now().Unix()

	// Test the actual LogSupplyCommitPush method.
	err = syncerStore.LogSupplyCommitPush(
		h.ctx, serverAddr, h.assetSpec, commitment, leaves,
	)
	require.NoError(t, err, "LogSupplyCommitPush should work")

	afterCall := time.Now().Unix()

	// Verify the log entry was created correctly using the new fetch query.
	var logEntries []sqlc.SupplySyncerPushLog
	readTx := ReadTxOption()
	err = h.batchedTreeDB.ExecTx(h.ctx, readTx,
		func(dbTx BaseUniverseStore) error {
			var txErr error
			logEntries, txErr = dbTx.FetchSupplySyncerPushLogs(
				h.ctx, h.groupKeyBytes,
			)
			return txErr
		},
	)
	require.NoError(t, err)
	require.Len(t, logEntries, 1, "Expected exactly one push log entry")

	logEntry := logEntries[0]

	// Verify all the fields are correct.
	require.Equal(t, h.groupKeyBytes, logEntry.GroupKey)
	require.Equal(t, int32(100), logEntry.MaxPushedBlockHeight)
	require.Equal(t, "localhost:8080", logEntry.ServerAddress)
	require.Equal(t, txid, logEntry.CommitTxid)
	require.Equal(t, int32(0), logEntry.OutputIndex)
	require.Equal(t, int32(1), logEntry.NumLeavesPushed)
	require.GreaterOrEqual(t, logEntry.CreatedAt, beforeCall)
	require.LessOrEqual(t, logEntry.CreatedAt, afterCall)

	t.Logf("Successfully logged push: commitTxid=%x, outputIndex=%d, "+
		"timestamp=%d, leaves=%d", logEntry.CommitTxid,
		logEntry.OutputIndex, logEntry.CreatedAt,
		logEntry.NumLeavesPushed)
}

// assertEqualEvents compares two supply update events by serializing them and
// comparing the resulting bytes.
func assertEqualEvents(t *testing.T, expected,
	actual supplycommit.SupplyUpdateEvent) {

	t.Helper()

	var expectedBytes, actualBytes bytes.Buffer
	err := serializeSupplyUpdateEvent(&expectedBytes, expected)
	require.NoError(t, err)

	err = serializeSupplyUpdateEvent(&actualBytes, actual)
	require.NoError(t, err)

	require.Equal(t, expectedBytes.String(), actualBytes.String())
}
