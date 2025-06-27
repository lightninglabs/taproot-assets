package supplycommit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/btcutil/txsort"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/chainntnfs"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/protofsm"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	testTimeout = 5 * time.Second

	testGenesis = asset.Genesis{
		FirstPrevOut: wire.OutPoint{
			Hash:  sha256.Sum256([]byte("genesis")),
			Index: 0,
		},
		Tag:         "test-asset",
		MetaHash:    sha256.Sum256([]byte("metadata")),
		OutputIndex: 0,
		Type:        asset.Normal,
	}
	testAssetID = testGenesis.ID()

	dummyRate = chainfee.SatPerKWeight(1000)
)

// randOutPoint generates a random wire.OutPoint.
func randOutPoint(t *testing.T) wire.OutPoint {
	t.Helper()

	var hash [32]byte
	_, err := rand.Read(hash[:])
	require.NoError(t, err)

	return wire.OutPoint{
		Hash:  hash,
		Index: rand.Uint32(),
	}
}

// newTestMintEvent creates a new mint event for testing.
func newTestMintEvent(t *testing.T, scriptKey *btcec.PublicKey,
	outpoint wire.OutPoint) *NewMintEvent {

	mintAsset := asset.RandAsset(t, asset.Normal)
	mintAsset.ScriptKey = asset.NewScriptKey(scriptKey)
	mintAsset.GroupKey = nil

	assetGenesis := mintAsset.Genesis
	assetID := assetGenesis.ID()

	issuanceProof := universe.Leaf{
		GenesisWithGroup: universe.GenesisWithGroup{
			Genesis: assetGenesis,
		},
		Asset: mintAsset,
		Amt:   mintAsset.Amount,
	}

	leafKey := universe.AssetLeafKey{
		BaseLeafKey: universe.BaseLeafKey{
			OutPoint:  outpoint,
			ScriptKey: &asset.ScriptKey{PubKey: scriptKey},
		},
		AssetID: assetID,
	}

	return &NewMintEvent{
		LeafKey:       leafKey,
		IssuanceProof: issuanceProof,
	}
}

// unknownEvent is a dummy event that is used to test that the state machine
// transitions properly fail when an unknown event is received.
type unknownEvent struct{}

func (u *unknownEvent) eventSealed() {}

// harnessCfg holds configuration for the test harness.
type harnessCfg struct {
	initialState State
	assetSpec    asset.Specifier
}

// supplyCommitTestHarness is a test harness for the supply commit state
// machine.
type supplyCommitTestHarness struct {
	t *testing.T

	cfg *harnessCfg

	stateMachine *StateMachine
	env          *Environment

	mockTreeView    *mockSupplyTreeView
	mockCommits     *mockCommitmentTracker
	mockWallet      *mockWallet
	mockChain       *mockChainBridge
	mockStateLog    *mockStateMachineStore
	mockDaemon      *mockDaemonAdapters
	mockErrReporter *mockErrorReporter

	stateSub protofsm.StateSubscriber[Event, *Environment]
}

func newSupplyCommitTestHarness(t *testing.T,
	cfg *harnessCfg) *supplyCommitTestHarness {

	mockTreeView := &mockSupplyTreeView{}
	mockCommits := &mockCommitmentTracker{}
	mockWallet := &mockWallet{}
	mockChain := &mockChainBridge{}
	mockStateLog := &mockStateMachineStore{}
	mockDaemon := newMockDaemonAdapters()
	mockErrReporter := &mockErrorReporter{}

	env := &Environment{
		AssetSpec:        cfg.assetSpec,
		TreeView:         mockTreeView,
		Commitments:      mockCommits,
		Wallet:           mockWallet,
		Chain:            mockChain,
		StateLog:         mockStateLog,
		CommitConfTarget: DefaultCommitConfTarget,
	}

	fsmCfg := Config{
		InitialState:       cfg.initialState,
		Env:                env,
		Daemon:             mockDaemon,
		ErrorReporter:      mockErrReporter,
		InitEvent:          lfn.None[protofsm.DaemonEvent](),
		MsgMapper:          lfn.None[protofsm.MsgMapper[Event]](),
		CustomPollInterval: lfn.Some(time.Second),
	}

	stateMachine := protofsm.NewStateMachine(fsmCfg)

	h := &supplyCommitTestHarness{
		t:               t,
		cfg:             cfg,
		stateMachine:    &stateMachine,
		env:             env,
		mockTreeView:    mockTreeView,
		mockCommits:     mockCommits,
		mockWallet:      mockWallet,
		mockChain:       mockChain,
		mockStateLog:    mockStateLog,
		mockDaemon:      mockDaemon,
		mockErrReporter: mockErrReporter,
	}

	h.stateSub = stateMachine.RegisterStateEvents()

	return h
}

func (h *supplyCommitTestHarness) start() {
	h.t.Helper()
	h.stateMachine.Start(context.Background())

	// Assert initial state emitted.
	h.assertStateTransitions(h.cfg.initialState)
}

func (h *supplyCommitTestHarness) stopAndAssert() {
	h.t.Helper()
	h.stateMachine.Stop()
	h.stateMachine.RemoveStateSub(h.stateSub)

	h.mockTreeView.AssertExpectations(h.t)
	h.mockCommits.AssertExpectations(h.t)
	h.mockWallet.AssertExpectations(h.t)
	h.mockChain.AssertExpectations(h.t)
	h.mockStateLog.AssertExpectations(h.t)
	h.mockDaemon.AssertExpectations(h.t)
	h.mockErrReporter.AssertExpectations(h.t)
}

// assertStateTransitions waits for and asserts specific state transitions.
func assertStateTransitions[Event any, Env protofsm.Environment](
	t *testing.T, stateSub protofsm.StateSubscriber[Event, Env],
	expectedStates []protofsm.State[Event, Env]) {

	t.Helper()

	for _, expectedState := range expectedStates {
		newState, err := lfn.RecvOrTimeout(
			stateSub.NewItemCreated.ChanOut(), testTimeout,
		)
		require.NoError(t, err, "expected state: %T", expectedState)

		require.IsType(t, expectedState, newState)
	}

	select {
	case newState := <-stateSub.NewItemCreated.ChanOut():
		t.Fatalf("unexpected state transition: %v", newState)
	case <-time.After(10 * time.Millisecond):
	}
}

func (h *supplyCommitTestHarness) assertStateTransitions(states ...State) {
	h.t.Helper()

	expectedStates := make(
		[]protofsm.State[Event, *Environment], len(states),
	)
	for i, state := range states {
		expectedStates[i] = state
	}

	assertStateTransitions(h.t, h.stateSub, expectedStates)
}

func (h *supplyCommitTestHarness) assertNoStateTransitions() {
	h.t.Helper()
	select {
	case newState := <-h.stateSub.NewItemCreated.ChanOut():
		h.t.Fatalf("unexpected state transition: %v", newState)

	// A short delay is used to allow time for any unexpected transitions to
	// occur.
	case <-time.After(10 * time.Millisecond):
	}
}

func (h *supplyCommitTestHarness) expectFailure(expectedErr error) {
	h.t.Helper()

	h.mockErrReporter.On(
		"ReportError", mock.MatchedBy(func(err error) bool {
			return errors.Is(err, expectedErr) ||
				err.Error() == expectedErr.Error()
		}),
	).Return().Once()
}

// expectFullCommitmentCycleMocks sets up the common mock expectations for a
// full supply commitment cycle, from tree/transaction creation through to
// broadcast preparation.
func (h *supplyCommitTestHarness) expectFullCommitmentCycleMocks(
	includeTreeFetches bool) {

	h.t.Helper()

	if includeTreeFetches {
		h.expectTreeFetches()
	}
	h.expectCommitmentFetches()
	h.expectKeyDerivationAndImport()
	h.expectFeeEstimation()
	h.expectPsbtFunding()
	h.expectPsbtSigning()
	h.expectInsertSignedCommitTx()
	h.expectBroadcastAndConfRegistration()
}

// assertHandlesInvalidEvent checks that the state machine correctly handles an
// invalid event by reporting the specified error and not transitioning state.
func (h *supplyCommitTestHarness) assertHandlesInvalidEvent(event Event,
	expectedErr error) {

	h.t.Helper()

	h.expectFailure(expectedErr)
	h.sendEvent(event)
	h.assertNoStateTransitions()

	require.ErrorIs(h.t, h.mockErrReporter.GetReportedError(), expectedErr)
}

// assertAndGetCurrentState fetches the current state from the state machine,
// asserts it is of type S (which must be a pointer to a struct
// implementing State), and returns it.
func assertAndGetCurrentState[S State](h *supplyCommitTestHarness) S {
	h.t.Helper()

	currentStateUntyped, err := h.stateMachine.CurrentState()
	require.NoError(h.t, err)

	currentState, ok := currentStateUntyped.(S)
	if !ok {
		// This creates a nil pointer of type S to get its type name.
		// S is expected to be a pointer type like *DefaultState.
		var expectedType S
		h.t.Fatalf("current state is of type %T (%s), but expected %T",
			currentStateUntyped, currentStateUntyped.String(),
			expectedType)
	}

	return currentState
}

func (h *supplyCommitTestHarness) sendEvent(event Event) {
	h.t.Helper()

	h.stateMachine.SendEvent(context.Background(), event)
}

func (h *supplyCommitTestHarness) expectInsertPendingUpdate(
	event SupplyUpdateEvent) {

	h.mockStateLog.On(
		"InsertPendingUpdate", mock.Anything, h.cfg.assetSpec, event,
	).Return(nil).Once()
}

func (h *supplyCommitTestHarness) expectTreeFetches() {
	emptySupplyTrees := SupplyTrees{
		MintTreeType:   mssmt.NewCompactedTree(mssmt.NewDefaultStore()),
		BurnTreeType:   mssmt.NewCompactedTree(mssmt.NewDefaultStore()),
		IgnoreTreeType: mssmt.NewCompactedTree(mssmt.NewDefaultStore()),
	}
	h.mockTreeView.On("FetchSubTrees", mock.Anything).Return(
		lfn.Ok(emptySupplyTrees),
	).Once()

	rootTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	h.mockTreeView.On("FetchRootSupplyTree", mock.Anything).Return(
		lfn.Ok[mssmt.Tree](rootTree),
	).Once()
}

func (h *supplyCommitTestHarness) expectCommitmentFetches() {
	h.mockCommits.On(
		"UnspentPrecommits", mock.Anything, mock.Anything,
	).Return(
		lfn.Ok[PreCommits](nil),
	).Once()

	h.mockCommits.On("SupplyCommit", mock.Anything, mock.Anything).Return(
		lfn.Ok(lfn.None[RootCommitment]()),
	).Once()
}

func (h *supplyCommitTestHarness) expectKeyDerivationAndImport() {
	dummyKeyDesc := keychain.KeyDescriptor{
		PubKey: test.RandPubKey(h.t),
	}
	h.mockWallet.On("DeriveNextKey", mock.Anything).Return(
		dummyKeyDesc, nil,
	).Once()

	pubKeyBytes := dummyKeyDesc.PubKey.SerializeCompressed()[1:]

	dummyTaprootAddr, err := btcutil.NewAddressTaproot(
		pubKeyBytes, &chaincfg.MainNetParams,
	)
	require.NoError(h.t, err)

	h.mockWallet.On(
		"ImportTaprootOutput", mock.Anything, mock.Anything,
	).Return(dummyTaprootAddr, nil).Once()
}

func (h *supplyCommitTestHarness) expectFeeEstimation() {
	h.mockChain.On("EstimateFee", mock.Anything, mock.Anything).Return(
		dummyRate, nil,
	).Once()
}

func (h *supplyCommitTestHarness) expectPsbtFunding() {
	fundPsbtFunc := fundPsbtMockFn(func( //nolint:lll
		ctx context.Context, packet *psbt.Packet,
		minConfs uint32, feeRate chainfee.SatPerKWeight,
		changeIdx int32,
	) (*tapsend.FundedPsbt, error) {

		fundedTx := wire.NewMsgTx(2)
		fundedTx.AddTxIn(
			&wire.TxIn{PreviousOutPoint: randOutPoint(h.t)},
		)

		for _, txOut := range packet.UnsignedTx.TxOut {
			fundedTx.AddTxOut(txOut)
		}

		fundedPsbt, _ := psbt.NewFromUnsignedTx(fundedTx)
		return &tapsend.FundedPsbt{
			Pkt: fundedPsbt, ChangeOutputIndex: -1,
		}, nil
	})

	h.mockWallet.On(
		"FundPsbt", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything,
	).Return(fundPsbtFunc, nil).Once()
}

func (h *supplyCommitTestHarness) expectPsbtSigning() {
	signFn := signAndFinalizePsbtMockFn(func(
		_ context.Context, pkt *psbt.Packet,
	) (*psbt.Packet, error) {
		// The transaction from the PSBT is extracted and used to create
		// a new "signed" PSBT. This ensures that any outputs on the
		// transaction are preserved, which is crucial for subsequent
		// confirmation notifications.
		return newTestSignedPsbt(h.t, pkt.UnsignedTx), nil
	})
	h.mockWallet.On(
		"SignAndFinalizePsbt", mock.Anything, mock.Anything,
	).Return(signFn, nil).Once()
}

func (h *supplyCommitTestHarness) expectInsertSignedCommitTx() {
	h.mockStateLog.On(
		"InsertSignedCommitTx", mock.Anything, mock.Anything,
		mock.Anything,
	).Return(nil).Once()
}

func (h *supplyCommitTestHarness) expectBroadcastAndConfRegistration() {
	h.mockDaemon.On(
		"BroadcastTransaction", mock.Anything, mock.Anything,
	).Return(nil).Once()

	h.mockChain.On("CurrentHeight", mock.Anything).Return(
		uint32(123), nil,
	).Once()

	h.mockDaemon.On(
		"RegisterConfirmationsNtfn", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything,
	).Return(nil).Once()
}

func (h *supplyCommitTestHarness) expectCommitState() {
	h.mockStateLog.On(
		"CommitState", mock.Anything, mock.Anything, mock.Anything,
	).Return(nil).Once()
}

func (h *supplyCommitTestHarness) expectApplyStateTransition() {
	h.mockStateLog.On(
		"ApplyStateTransition", mock.Anything, mock.Anything,
		mock.Anything,
	).Return(nil).Once()
}

// TestSupplyCommitDefaultStateTransitions tests the transitions from the
// DefaultState.
func TestSupplyCommitDefaultStateTransitions(t *testing.T) {
	t.Parallel()

	testScriptKey := test.RandPubKey(t)
	defaultAssetSpec := asset.NewSpecifierFromId(testAssetID)

	// Verify that when the DefaultState receives a SupplyUpdateEvent, it
	// transitions to the UpdatesPendingState, and
	// StateLog.InsertPendingUpdate is called.
	t.Run("supply_update_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &DefaultState{},
			assetSpec:    defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		mintEvent := newTestMintEvent(t, testScriptKey, randOutPoint(t))

		h.expectInsertPendingUpdate(mintEvent)

		h.sendEvent(mintEvent)

		expectedNextState := &UpdatesPendingState{
			pendingUpdates: []SupplyUpdateEvent{mintEvent},
		}
		h.assertStateTransitions(expectedNextState)

		// The pendingUpdates field in the actual state is verified for
		// correctness.
		innerState := assertAndGetCurrentState[*UpdatesPendingState](h)
		require.Len(t, innerState.pendingUpdates, 1)
		require.Equal(t, mintEvent, innerState.pendingUpdates[0])
	})

	// Check that a CommitTickEvent received by the DefaultState results in
	// a no-op, with the state machine remaining in DefaultState.
	t.Run("commit_tick_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &DefaultState{},
			assetSpec:    defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		tickEvent := &CommitTickEvent{}
		h.sendEvent(tickEvent)

		// A self-transition is expected, meaning a new state object of
		// the same type is emitted.
		h.assertStateTransitions(&DefaultState{})
	})

	// Ensure that an unknown event sent to the DefaultState results in an
	// error being reported.
	t.Run("unknown_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &DefaultState{},
			assetSpec:    defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.assertHandlesInvalidEvent(
			&unknownEvent{}, ErrInvalidStateTransition,
		)
	})
}

// TestSupplyCommitUpdatesPendingStateTransitions tests the transitions from the
// UpdatesPendingState.
func TestSupplyCommitUpdatesPendingStateTransitions(t *testing.T) {
	t.Parallel()

	testScriptKey := test.RandPubKey(t)
	defaultAssetSpec := asset.NewSpecifierFromId(testAssetID)
	initialMintEvent := newTestMintEvent(t, testScriptKey, randOutPoint(t))

	// Verify that when the UpdatesPendingState receives a
	// SupplyUpdateEvent, it remains in UpdatesPendingState, and
	// StateLog.InsertPendingUpdate is called.
	t.Run("supply_update_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &UpdatesPendingState{
				pendingUpdates: []SupplyUpdateEvent{
					initialMintEvent,
				},
			},
			assetSpec: defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		anotherMintEvent := newTestMintEvent(
			t, testScriptKey, randOutPoint(t),
		)
		h.expectInsertPendingUpdate(anotherMintEvent)

		h.sendEvent(anotherMintEvent)

		expectedNextState := &UpdatesPendingState{
			pendingUpdates: []SupplyUpdateEvent{
				initialMintEvent, anotherMintEvent,
			},
		}
		h.assertStateTransitions(expectedNextState)

		innerState := assertAndGetCurrentState[*UpdatesPendingState](h)
		require.Len(t, innerState.pendingUpdates, 2)
		require.Equal(t, anotherMintEvent, innerState.pendingUpdates[1])
	})

	// Verify that a CommitTickEvent received by the UpdatesPendingState
	// triggers automatic transitions through multiple states.
	t.Run("commit_tick_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &UpdatesPendingState{
				pendingUpdates: []SupplyUpdateEvent{
					initialMintEvent,
				},
			},
			assetSpec: defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		// Set up expectations for the cascade of transitions.
		h.expectFullCommitmentCycleMocks(true)

		// When a CommitTickEvent is received, the state machine is
		// expected to automatically emit multiple internal events. This
		// leads to a sequence of transitions: UpdatesPendingState ->
		// CommitTreeCreateState -> CommitTxCreateState ->
		// CommitTxSignState. The permissive mocks within the test
		// harness are set up to handle all underlying calls during
		// these transitions.
		tickEvent := &CommitTickEvent{}
		h.sendEvent(tickEvent)

		// The test asserts the full sequence of automatic state
		// transitions: UpdatesPendingState -> CommitTreeCreateState ->
		// CommitTxCreateState -> CommitTxSignState ->
		// CommitBroadcastState.
		h.assertStateTransitions(
			&CommitTreeCreateState{},
			&CommitTxCreateState{},
			&CommitTxSignState{},
			&CommitBroadcastState{},
			&CommitBroadcastState{},
		)
	})

	// Ensures that an unknown event sent to the
	// UpdatesPendingState results in an error being reported.
	t.Run("unknown_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &UpdatesPendingState{
				pendingUpdates: []SupplyUpdateEvent{
					initialMintEvent,
				},
			},
			assetSpec: defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectFailure(ErrInvalidStateTransition)

		unknownEv := &unknownEvent{}
		h.sendEvent(unknownEv)

		h.assertNoStateTransitions()

		require.ErrorIs(
			t, h.mockErrReporter.GetReportedError(),
			ErrInvalidStateTransition,
		)
	})
}

// TestSupplyCommitTreeCreateStateTransitions tests the transitions from the
// CommitTreeCreateState.
func TestSupplyCommitTreeCreateStateTransitions(t *testing.T) {
	t.Parallel()

	defaultAssetSpec := asset.NewSpecifierFromId(testAssetID)
	mintEvent := newTestMintEvent(t, test.RandPubKey(t), randOutPoint(t))

	// Verify that a CommitTickEvent received by the CommitTreeCreateState
	// results in a no-op, with the state machine remaining in
	// CommitTreeCreateState.
	t.Run("commit_tick_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitTreeCreateState{},
			assetSpec:    defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		tickEvent := &CommitTickEvent{}
		h.sendEvent(tickEvent)
		h.assertStateTransitions(&CommitTreeCreateState{})
	})

	// Check that a CreateTreeEvent received by the CommitTreeCreateState
	// leads to a transition to CommitTxCreateState and the emission of a
	// CreateTxEvent.
	t.Run("create_tree_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitTreeCreateState{},
			assetSpec:    defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		// Set up expectations for the cascade of transitions.
		h.expectFullCommitmentCycleMocks(true)

		createTreeEvent := &CreateTreeEvent{
			updatesToCommit: []SupplyUpdateEvent{mintEvent},
		}
		h.sendEvent(createTreeEvent)

		// Upon receiving the CreateTreeEvent, the state machine
		// automatically transitions through several states. This test
		// asserts the sequence: CommitTreeCreateState ->
		// CommitTxCreateState -> CommitTxSignState ->
		// CommitBroadcastState.
		h.assertStateTransitions(
			&CommitTxCreateState{},
			&CommitTxSignState{},
			&CommitBroadcastState{},
			&CommitBroadcastState{},
		)
	})

	// Ensure that an unknown event sent to the CommitTreeCreateState
	// results in an error being reported.
	t.Run("unknown_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitTreeCreateState{},
			assetSpec:    defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.assertHandlesInvalidEvent(
			&unknownEvent{}, ErrInvalidStateTransition,
		)
	})
}

// TestSupplyCommitTxCreateStateTransitions tests the transitions from the
// CommitTxCreateState.
func TestSupplyCommitTxCreateStateTransitions(t *testing.T) {
	t.Parallel()

	defaultAssetSpec := asset.NewSpecifierFromId(testAssetID)
	initialTransition := SupplyStateTransition{
		NewCommitment: RootCommitment{
			SupplyRoot: mssmt.NewBranch(
				mssmt.NewLeafNode([]byte("left"), 0),
				mssmt.NewLeafNode([]byte("right"), 0),
			),
		},
	}

	// Verify that a CreateTxEvent received by the CommitTxCreateState leads
	// to a transition to CommitTxSignState and the emission of a
	// SignTxEvent.
	t.Run("create_tx_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitTxCreateState{
				SupplyTransition: initialTransition,
			},
			assetSpec: defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectFullCommitmentCycleMocks(false)

		createTxEvent := &CreateTxEvent{}
		h.sendEvent(createTxEvent)

		// Upon receiving the CreateTxEvent, the state machine
		// automatically transitions. This test asserts the sequence:
		// CommitTxCreateState -> CommitTxSignState ->
		// CommitBroadcastState -> CommitBroadcastState
		// (self-transition).
		h.assertStateTransitions(
			&CommitTxSignState{}, &CommitBroadcastState{},
			&CommitBroadcastState{},
		)
	})

	// This test ensures that an unknown event sent to the
	// CommitTxCreateState results in an error being reported.
	t.Run("unknown_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitTxCreateState{
				SupplyTransition: initialTransition,
			},
			assetSpec: defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.assertHandlesInvalidEvent(
			&unknownEvent{}, ErrInvalidStateTransition,
		)
	})
}

// TestSupplyCommitTxSignStateTransitions tests the transitions from the
// CommitTxSignState.
func TestSupplyCommitTxSignStateTransitions(t *testing.T) {
	t.Parallel()

	defaultAssetSpec := asset.NewSpecifierFromId(testAssetID)
	dummyTx := wire.NewMsgTx(2)
	dummyTx.AddTxOut(&wire.TxOut{PkScript: []byte("test"), Value: 1})
	initialTransition := SupplyStateTransition{
		NewCommitment: RootCommitment{
			Txn:         dummyTx,
			InternalKey: test.RandPubKey(t),
			TxOutIdx:    0,
		},
	}

	// This test verifies that a SignTxEvent received by the
	// CommitTxSignState leads to a transition to CommitBroadcastState and
	// the emission of a BroadcastEvent.
	t.Run("sign_tx_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitTxSignState{
				SupplyTransition: initialTransition,
			},
			assetSpec: defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectPsbtSigning()
		h.expectInsertSignedCommitTx()
		h.expectBroadcastAndConfRegistration()

		fundedPsbt := newTestFundedPsbt(t, dummyTx)

		signEvent := &SignTxEvent{
			CommitPkt:       fundedPsbt,
			NewSupplyCommit: initialTransition.NewCommitment,
		}
		h.sendEvent(signEvent)

		// The state machine is expected to transition from
		// CommitTxSignState to CommitBroadcastState, and then perform a
		// self-transition in CommitBroadcastState upon receiving an
		// internal BroadcastEvent.
		h.assertStateTransitions(
			&CommitBroadcastState{}, &CommitBroadcastState{},
		)
	})

	// This test ensures that an unknown event sent to the CommitTxSignState
	// results in an error being reported.
	t.Run("unknown_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitTxSignState{
				SupplyTransition: initialTransition,
			},
			assetSpec: defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.assertHandlesInvalidEvent(
			&unknownEvent{}, ErrInvalidStateTransition,
		)
	})
}

// TestSupplyCommitBroadcastStateTransitions tests the transitions from the
// CommitBroadcastState.
func TestSupplyCommitBroadcastStateTransitions(t *testing.T) {
	t.Parallel()

	defaultAssetSpec := asset.NewSpecifierFromId(testAssetID)
	dummyTx := wire.NewMsgTx(2)
	dummyTx.AddTxOut(&wire.TxOut{PkScript: []byte("testscript"), Value: 1})
	initialTransition := SupplyStateTransition{
		NewCommitment: RootCommitment{
			Txn: dummyTx,
			SupplyRoot: mssmt.NewBranch(
				mssmt.NewLeafNode([]byte("L"), 0),
				mssmt.NewLeafNode([]byte("R"), 0),
			),
		},
	}

	// This test verifies that a BroadcastEvent received by the
	// CommitBroadcastState results in a self-transition to the same state
	// and emits daemon events.
	t.Run("broadcast_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitBroadcastState{
				SupplyTransition: initialTransition,
			},
			assetSpec: defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		signedPsbt := newTestSignedPsbt(t, dummyTx)

		h.expectBroadcastAndConfRegistration()

		broadcastEvent := &BroadcastEvent{
			SignedCommitPkt: signedPsbt,
		}
		h.sendEvent(broadcastEvent)

		// A BroadcastEvent should result in a self-transition to the
		// CommitBroadcastState.
		h.assertStateTransitions(&CommitBroadcastState{})
	})

	// This test checks that a ConfEvent received by the
	// CommitBroadcastState leads to a transition to CommitFinalizeState and
	// the emission of a FinalizeEvent.
	t.Run("conf_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitBroadcastState{
				SupplyTransition: initialTransition,
			},
			assetSpec: defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectCommitState()
		h.expectApplyStateTransition()

		// A dummy block containing the transaction is created for the
		// ConfEvent.
		block := &wire.MsgBlock{
			Header:       wire.BlockHeader{Timestamp: time.Now()},
			Transactions: []*wire.MsgTx{dummyTx},
		}
		confEvent := &ConfEvent{
			Tx:          dummyTx,
			TxIndex:     0,
			BlockHeight: 123,
			Block:       block,
		}
		h.sendEvent(confEvent)

		// After a ConfEvent, the state machine is expected to
		// transition automatically through CommitFinalizeState and then
		// back to DefaultState.
		h.assertStateTransitions(
			&CommitFinalizeState{}, &DefaultState{},
		)
	})

	// This test ensures that an unknown event sent to the
	// CommitBroadcastState results in an error being reported.
	t.Run("unknown_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitBroadcastState{
				SupplyTransition: initialTransition,
			},
			assetSpec: defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.assertHandlesInvalidEvent(
			&unknownEvent{}, ErrInvalidStateTransition,
		)
	})
}

// TestSupplyCommitFinalizeStateTransitions tests the transitions from the
// CommitFinalizeState.
func TestSupplyCommitFinalizeStateTransitions(t *testing.T) {
	t.Parallel()

	defaultAssetSpec := asset.NewSpecifierFromId(testAssetID)
	initialTransition := SupplyStateTransition{
		NewCommitment: RootCommitment{
			SupplyRoot: mssmt.NewBranch(
				mssmt.NewLeafNode([]byte("dummy"), 0),
				mssmt.NewLeafNode([]byte("leaf"), 0),
			),
		},
	}

	// This test verifies that a FinalizeEvent received by the
	// CommitFinalizeState leads to a transition back to the DefaultState.
	t.Run("finalize_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitFinalizeState{
				SupplyTransition: initialTransition,
			},
			assetSpec: defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectApplyStateTransition()

		finalizeEvent := &FinalizeEvent{}
		h.sendEvent(finalizeEvent)
		h.assertStateTransitions(&DefaultState{})
	})

	// This test ensures that an unknown event sent to the
	// CommitFinalizeState results in an error being reported.
	t.Run("unknown_event", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitFinalizeState{
				SupplyTransition: initialTransition,
			},
			assetSpec: defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.assertHandlesInvalidEvent(
			&unknownEvent{}, ErrInvalidStateTransition,
		)
	})
}

// newTestFundedPsbt creates a dummy funded PSBT for testing purposes.
func newTestFundedPsbt(t *testing.T, tx *wire.MsgTx) *tapsend.FundedPsbt {
	t.Helper()
	pkt, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	// For simplicity, this dummy PSBT does not include a change output.
	return &tapsend.FundedPsbt{
		Pkt:               pkt,
		ChangeOutputIndex: -1,
		LockedUTXOs:       nil,
	}
}

// newTestSignedPsbt creates a dummy signed PSBT for testing purposes.
func newTestSignedPsbt(t *testing.T, tx *wire.MsgTx) *psbt.Packet {
	t.Helper()

	pkt, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	for i := range pkt.Inputs {
		pkt.Inputs[i].FinalScriptWitness = []byte{0x01, 0x01, 0x01}
	}

	txCopy := tx.Copy()
	txsort.InPlaceSort(txCopy)
	pkt.UnsignedTx = txCopy

	return pkt
}

// TestSupplyUpdateEventTypes tests the different supply update event types that
// were previously untested, improving coverage for NewBurnEvent and
// NewIgnoreEvent.
func TestSupplyUpdateEventTypes(t *testing.T) {
	t.Parallel()

	t.Run("new_burn_event", func(t *testing.T) {
		scriptKey := test.RandPubKey(t)
		outpoint := randOutPoint(t)

		// A random block containing a transaction is generated to serve
		// as part of the proof.
		dummyTx := wire.NewMsgTx(2)
		dummyTx.AddTxOut(
			&wire.TxOut{Value: 1000, PkScript: []byte("dummy")},
		)
		block := wire.MsgBlock{
			Header: wire.BlockHeader{
				Version: 1, Timestamp: time.Now(),
			},
			Transactions: []*wire.MsgTx{dummyTx},
		}

		burnProof := proof.RandProof(
			t, testGenesis, scriptKey, block, 0, 0,
		)

		burnEvent := &NewBurnEvent{
			BurnLeaf: universe.BurnLeaf{
				UniverseKey: universe.AssetLeafKey{
					BaseLeafKey: universe.BaseLeafKey{
						OutPoint: outpoint,
						ScriptKey: &asset.ScriptKey{
							PubKey: scriptKey,
						},
					},
					AssetID: testAssetID,
				},
				BurnProof: &burnProof,
			},
		}

		burnEvent.eventSealed()
		require.Equal(t, BurnTreeType, burnEvent.SupplySubTreeType())

		retrievedScriptKey := burnEvent.ScriptKey()
		require.NotNil(t, retrievedScriptKey)

		leafKey := burnEvent.UniverseLeafKey()
		require.NotNil(t, leafKey)

		leafNode, err := burnEvent.UniverseLeafNode()
		require.NoError(t, err)
		require.NotNil(t, leafNode)
		require.Equal(t, burnProof.Asset.Amount, leafNode.NodeSum())

		// The resulting leaf node's value should contain the encoded
		// proof bytes.
		require.Greater(t, len(leafNode.Value), 0)
	})

	t.Run("new_ignore_event", func(t *testing.T) {
		scriptKey := test.RandPubKey(t)
		outpoint := randOutPoint(t)

		// An ignore tuple is created with the correct structure for the
		// test.
		ignoreTuple := universe.IgnoreTuple{
			PrevID: asset.PrevID{
				ID:        testAssetID,
				ScriptKey: asset.ToSerialized(scriptKey),
				OutPoint:  outpoint,
			},
			Amount: 100,
		}

		// A simple signature is created; an empty signature suffices
		// for this test.
		signature := universe.IgnoreSig{}

		ignoreEvent := &NewIgnoreEvent{
			SignedIgnoreTuple: universe.NewSignedIgnoreTuple(
				ignoreTuple, signature,
			),
		}

		ignoreEvent.eventSealed()
		require.Equal(
			t, IgnoreTreeType, ignoreEvent.SupplySubTreeType(),
		)

		retrievedScriptKey := ignoreEvent.ScriptKey()
		require.NotNil(t, retrievedScriptKey)

		leafKey := ignoreEvent.UniverseLeafKey()
		require.NotNil(t, leafKey)

		leafNode, err := ignoreEvent.UniverseLeafNode()
		require.NoError(t, err)
		require.NotNil(t, leafNode)
	})

	// This subtest focuses on the encoding and decoding of NewMintEvent.
	//nolint:lll
	t.Run("new_mint_event_encode_decode", func(t *testing.T) {
		// To begin, we generate the necessary components to create a
		// random proof using proof.RandProof. This includes a script
		// key and a dummy block containing a transaction.
		scriptKey := test.RandPubKey(t)
		outpoint := randOutPoint(t)

		dummyTx := wire.NewMsgTx(2)
		dummyTx.AddTxIn(
			&wire.TxIn{PreviousOutPoint: outpoint},
		)
		dummyTx.AddTxOut(
			&wire.TxOut{Value: 1000, PkScript: []byte("dummy")},
		)
		block := wire.MsgBlock{
			Header: wire.BlockHeader{
				Version:   1,
				Timestamp: time.Now(),
			},
			Transactions: []*wire.MsgTx{dummyTx},
		}

		randomFullProof := proof.RandProof(
			t, testGenesis, scriptKey, block, 0, 0,
		)
		originalMintEvent := newTestMintEvent(t, scriptKey, outpoint)

		// Ensure the asset within randomFullProof (which gets
		// serialized) matches the asset that newTestMintEvent would
		// create, to ensure AssetID and ScriptKey are consistent.
		// However, RandProof also creates its own asset. We need to use
		// *that* asset as the source of truth for what gets decoded.
		// So, originalMintEvent's IssuanceProof.Asset and LeafKey
		// fields need to be aligned with randomFullProof.Asset.
		originalMintEvent.IssuanceProof.Asset = &randomFullProof.Asset
		originalMintEvent.IssuanceProof.GenesisWithGroup = universe.GenesisWithGroup{ //nolint:lll
			Genesis:  randomFullProof.Asset.Genesis,
			GroupKey: randomFullProof.Asset.GroupKey,
		}
		originalMintEvent.IssuanceProof.Amt = randomFullProof.Asset.Amount

		rawProofBytes, err := randomFullProof.Bytes()
		require.NoError(t, err)
		require.NotEmpty(t, rawProofBytes)
		originalMintEvent.IssuanceProof.RawProof = rawProofBytes

		// Align the LeafKey in the original event with what will be
		// derived from the proof during decode. We need to type assert
		// LeafKey to its concrete type to access the embedded
		// BaseLeafKey.OutPoint.
		assetLeafKeySt, ok := originalMintEvent.LeafKey.(universe.AssetLeafKey)
		require.True(
			t, ok, "LeafKey should be of type "+
				"universe.AssetLeafKey",
		)
		modifiedLeafKey := assetLeafKeySt
		modifiedLeafKey.BaseLeafKey.OutPoint = randomFullProof.OutPoint()
		modifiedLeafKey.AssetID = randomFullProof.Asset.ID()
		modifiedLeafKey.BaseLeafKey.ScriptKey = &randomFullProof.Asset.ScriptKey
		originalMintEvent.LeafKey = modifiedLeafKey

		var buf bytes.Buffer
		err = originalMintEvent.Encode(&buf)
		require.NoError(t, err)

		decodedMintEvent := &NewMintEvent{}
		err = decodedMintEvent.Decode(bytes.NewReader(buf.Bytes()))
		require.NoError(t, err)

		// Finally, we assert that the RawProof field of the decoded
		// event matches the original serialized proof bytes, confirming
		// a successful round trip.
		require.Equal(t, originalMintEvent, decodedMintEvent)

		require.Equal(
			t, MintTreeType,
			originalMintEvent.SupplySubTreeType(),
		)

		scriptKeyBytes := originalMintEvent.ScriptKey()
		require.NotNil(t, scriptKeyBytes)

		leafKey := originalMintEvent.UniverseLeafKey()
		require.NotNil(t, leafKey)

		leafNode, err := originalMintEvent.UniverseLeafNode()
		require.NoError(t, err)
		require.NotNil(t, leafNode)
	})
}

// TestTxInMethods tests the TxIn() methods that had 0% coverage.
func TestTxInMethods(t *testing.T) {
	t.Parallel()

	t.Run("pre_commitment_tx_in", func(t *testing.T) {
		mintingTx := wire.NewMsgTx(2)
		mintingTx.AddTxOut(
			&wire.TxOut{Value: 1000, PkScript: []byte("test")},
		)

		preCommit := PreCommitment{
			MintingTxn: mintingTx,
			OutIdx:     0,
		}

		txIn := preCommit.TxIn()
		require.NotNil(t, txIn)
		require.Equal(t, mintingTx.TxHash(), txIn.PreviousOutPoint.Hash)
		require.Equal(t, uint32(0), txIn.PreviousOutPoint.Index)
	})

	t.Run("root_commitment_tx_in", func(t *testing.T) {
		rootCommit := RootCommitment{
			Txn:      wire.NewMsgTx(2),
			TxOutIdx: 1,
		}

		txIn := rootCommit.TxIn()
		require.NotNil(t, txIn)
		require.Equal(
			t, rootCommit.Txn.TxHash(), txIn.PreviousOutPoint.Hash,
		)
		require.Equal(
			t, rootCommit.TxOutIdx, txIn.PreviousOutPoint.Index,
		)
	})
}

// TestSupplyTreesFetchOrCreate tests the FetchOrCreate method with different
// scenarios to improve coverage from 50% to higher.
func TestSupplyTreesFetchOrCreate(t *testing.T) {
	t.Parallel()

	t.Run("existing_tree", func(t *testing.T) {
		trees := make(SupplyTrees)
		existingTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
		trees[MintTreeType] = existingTree

		// When a tree of the specified type already exists,
		// FetchOrCreate should return it.
		result := trees.FetchOrCreate(MintTreeType)
		require.Equal(t, existingTree, result)
	})

	t.Run("create_new_tree", func(t *testing.T) {
		trees := make(SupplyTrees)

		// If a tree of the specified type does not exist, FetchOrCreate
		// should create and return a new one.
		result := trees.FetchOrCreate(BurnTreeType)
		require.NotNil(t, result)
		require.Contains(t, trees, BurnTreeType)
		require.Equal(t, trees[BurnTreeType], result)
	})
}

// TestCreateCommitmentTxLabel tests the createCommitmentTxLabel function with
// different scenarios to improve coverage.
func TestCreateCommitmentTxLabel(t *testing.T) {
	t.Parallel()

	defaultAssetSpec := asset.NewSpecifierFromId(testAssetID)

	t.Run("with_valid_supply_root", func(t *testing.T) {
		mintEvent := newTestMintEvent(
			t, test.RandPubKey(t), randOutPoint(t),
		)
		transition := SupplyStateTransition{
			PendingUpdates: []SupplyUpdateEvent{mintEvent},
			NewCommitment: RootCommitment{
				SupplyRoot: mssmt.NewBranch(
					mssmt.NewLeafNode([]byte("left"), 100),
					mssmt.NewLeafNode([]byte("right"), 200),
				),
			},
		}

		label := createCommitmentTxLabel(defaultAssetSpec, transition)
		require.Contains(t, label, "tapd-supply-commit")
		require.Contains(t, label, "root=")
		require.Contains(t, label, "sum=300")
		require.Contains(t, label, "m=1")
	})

	t.Run("with_nil_supply_root", func(t *testing.T) {
		transition := SupplyStateTransition{
			NewCommitment: RootCommitment{
				SupplyRoot: nil,
			},
		}

		label := createCommitmentTxLabel(defaultAssetSpec, transition)
		require.Contains(t, label, "no_root")
	})

	t.Run("with_burn_and_ignore_events", func(t *testing.T) {
		scriptKey := test.RandPubKey(t)
		outpoint := randOutPoint(t)

		// Create burn event
		burnAsset := asset.Asset{
			Genesis:   testGenesis,
			ScriptKey: asset.NewScriptKey(scriptKey),
			Amount:    50,
		}
		burnProof := &proof.Proof{Asset: burnAsset}
		burnEvent := &NewBurnEvent{
			BurnLeaf: universe.BurnLeaf{
				UniverseKey: universe.AssetLeafKey{
					BaseLeafKey: universe.BaseLeafKey{
						OutPoint: outpoint,
						ScriptKey: &asset.ScriptKey{
							PubKey: scriptKey,
						},
					},
					AssetID: testAssetID,
				},
				BurnProof: burnProof,
			},
		}

		// Create ignore event
		ignoreTuple := universe.IgnoreTuple{
			PrevID: asset.PrevID{
				ID:        testAssetID,
				ScriptKey: asset.ToSerialized(scriptKey),
				OutPoint:  outpoint,
			},
			Amount: 25,
		}
		signature := universe.IgnoreSig{}
		ignoreEvent := &NewIgnoreEvent{
			SignedIgnoreTuple: universe.NewSignedIgnoreTuple(
				ignoreTuple, signature,
			),
		}

		transition := SupplyStateTransition{
			PendingUpdates: []SupplyUpdateEvent{
				burnEvent, ignoreEvent,
			},
			NewCommitment: RootCommitment{
				SupplyRoot: mssmt.NewBranch(
					mssmt.NewLeafNode([]byte("test"), 75),
					mssmt.NewLeafNode([]byte("node"), 25),
				),
			},
		}

		label := createCommitmentTxLabel(defaultAssetSpec, transition)
		require.Contains(t, label, "tapd-supply-commit")
		require.Contains(t, label, "b=1")
		require.Contains(t, label, "i=1")
		require.Contains(t, label, "m=0")
	})
}

// TestSupplySubTreeString tests the String method of SupplySubTree including
// the default case.
func TestSupplySubTreeString(t *testing.T) {
	t.Parallel()

	require.Equal(t, "mint_supply", MintTreeType.String())
	require.Equal(t, "burn", BurnTreeType.String())
	require.Equal(t, "ignore", IgnoreTreeType.String())

	unknownType := SupplySubTree(99)
	require.Equal(t, "unknown", unknownType.String())
}

// TestSupplySubTreeUniverseKey tests the UniverseKey method.
func TestSupplySubTreeUniverseKey(t *testing.T) {
	t.Parallel()

	mintKey := MintTreeType.UniverseKey()
	burnKey := BurnTreeType.UniverseKey()
	ignoreKey := IgnoreTreeType.UniverseKey()

	require.NotEqual(t, mintKey, burnKey)
	require.NotEqual(t, burnKey, ignoreKey)
	require.NotEqual(t, mintKey, ignoreKey)

	require.Equal(t, mintKey, MintTreeType.UniverseKey())
	require.Equal(t, burnKey, BurnTreeType.UniverseKey())
	require.Equal(t, ignoreKey, IgnoreTreeType.UniverseKey())
}

// TestSpendEventMethods tests SpendEvent methods for coverage.
func TestSpendEventMethods(t *testing.T) {
	t.Parallel()

	tx := wire.NewMsgTx(2)

	spendDetail := &chainntnfs.SpendDetail{
		SpendingTx:     tx,
		SpendingHeight: 456,
	}

	mappedEvent := SpendMapperFunc(spendDetail)
	require.NotNil(t, mappedEvent)

	spendEventMapped, ok := mappedEvent.(*SpendEvent)
	require.True(t, ok)
	require.Equal(t, tx, spendEventMapped.Tx)
	require.Equal(t, uint32(456), spendEventMapped.BlockHeight)
}

// TestStateAndEventMethods calls utility methods on all state and event types
// to ensure basic functionality and improve test coverage.
func TestStateAndEventMethods(t *testing.T) {
	t.Parallel()

	t.Run("events", func(t *testing.T) {
		events := []Event{
			&NewIgnoreEvent{},
			&NewBurnEvent{},
			&NewMintEvent{},
			&CommitTickEvent{},
			&CreateTreeEvent{},
			&CreateTxEvent{},
			&SignTxEvent{},
			&BroadcastEvent{},
			&ConfEvent{},
			&FinalizeEvent{},
			&SpendEvent{},
		}

		for _, e := range events {
			e.eventSealed()
		}
	})

	t.Run("states", func(t *testing.T) {
		states := []State{
			&DefaultState{},
			&UpdatesPendingState{},
			&CommitTreeCreateState{},
			&CommitTxCreateState{},
			&CommitTxSignState{},
			&CommitBroadcastState{},
			&CommitFinalizeState{},
		}

		for _, s := range states {
			s.stateSealed()
			require.NotEmpty(t, s.String())
			// IsTerminal is called for coverage.
			_ = s.IsTerminal()
		}

		// Check terminal state explicitly.
		require.True(t, (&CommitFinalizeState{}).IsTerminal())
		require.False(t, (&DefaultState{}).IsTerminal())
	})
}
