package supplycommit

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightninglabs/taproot-assets/tapsend"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockAnchoringRegistrar mocks the re-org watcher's registration
// surface.
type mockAnchoringRegistrar struct {
	mock.Mock
}

func (m *mockAnchoringRegistrar) Register(ctx context.Context,
	spec tapreorg.RegistrationSpec, phase1 func(context.Context,
		tapreorg.RegistryTx, tapreorg.AnchoringID) error,
) (tapreorg.AnchoringID, error) {

	args := m.Called(ctx, spec, phase1)
	id := args.Get(0).(tapreorg.AnchoringID)
	if err := args.Error(1); err != nil {
		return 0, err
	}

	// Run the phase-1 write as the registry does, inside its
	// registration transaction: its failure fails the registration.
	if phase1 != nil {
		err := phase1(ctx, &recordingSupplyTx{}, id)
		if err != nil {
			return 0, fmt.Errorf("phase-1 write: %w", err)
		}
	}

	return id, nil
}

func (m *mockAnchoringRegistrar) AllAnchorings(ctx context.Context,
	site tapreorg.SiteID) ([]*tapreorg.Anchoring, error) {

	args := m.Called(ctx, site)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*tapreorg.Anchoring), args.Error(1)
}

func (m *mockAnchoringRegistrar) LookupByMatchKey(ctx context.Context,
	site tapreorg.SiteID, matchKey []byte) (*tapreorg.Anchoring,
	error) {

	args := m.Called(ctx, site, matchKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*tapreorg.Anchoring), args.Error(1)
}

func (m *mockAnchoringRegistrar) KickOutbox() {}

// expectFetchState arranges the durable record the resting state
// re-derives from.
func (h *supplyCommitTestHarness) expectFetchState(state State,
	transition lfn.Option[SupplyStateTransition]) {

	h.t.Helper()
	h.mockStateLog.On(
		"FetchState", mock.Anything, mock.Anything,
	).Return(state, transition, nil).Once()
}

// newTestPreCommit builds a pre-commitment output for the group, with
// a minting transaction the trigger derivation reads the script from.
func newTestPreCommit(t *testing.T, groupKey *btcec.PublicKey) PreCommitment {
	t.Helper()

	mintTx := wire.NewMsgTx(2)
	mintTx.AddTxOut(&wire.TxOut{
		Value:    1_000,
		PkScript: append([]byte{0x51, 0x20}, test.RandBytes(32)...),
	})
	internalKey, _ := test.RandKeyDesc(t)

	return PreCommitment{
		MintingTxn:  mintTx,
		OutIdx:      0,
		InternalKey: internalKey,
		GroupPubKey: *groupKey,
	}
}

// expectApplyCommitTxStake arranges the phase-1 stake the signing step
// runs inside the watcher's registration transaction.
func (h *supplyCommitTestHarness) expectApplyCommitTxStake() {
	h.t.Helper()
	h.mockStateLog.On(
		"ApplyCommitTxStake", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything,
	).Return(nil).Once()
}

// expectAnchoringCommitCycle arranges a full commitment cycle on the
// anchoring path, from tree creation through broadcast, where the
// machine registers with the watcher instead of subscribing for a
// confirmation. The commitment fetch provides a real pre-commitment
// and the funding mock preserves the transaction's essential inputs,
// so the registered trigger set is the one production would build:
// exactly the pre-commitment outpoint, the wallet fee input excluded.
func (h *supplyCommitTestHarness) expectAnchoringCommitCycle(
	registrar *mockAnchoringRegistrar) {

	h.t.Helper()

	groupKey, err := h.cfg.assetSpec.UnwrapGroupKeyOrErr()
	require.NoError(h.t, err)

	h.expectTreeFetches()

	// The store resolves the pre-commitment twice: for the
	// transaction's construction, and for the trigger derivation at
	// signing.
	preCommit := newTestPreCommit(h.t, groupKey)
	h.mockCommits.On(
		"UnspentPrecommits", mock.Anything, mock.Anything,
		mock.Anything,
	).Return(
		lfn.Ok[PreCommits]([]PreCommitment{preCommit}),
	).Twice()
	h.mockCommits.On(
		"SupplyCommit", mock.Anything, mock.Anything,
	).Return(
		lfn.Ok(lfn.None[RootCommitment]()),
	).Once()
	h.expectKeyDerivationAndImport()
	h.expectFeeEstimation()

	// Unlike the shared funding mock, preserve the packet's inputs
	// and append a wallet fee input.
	fundPsbtFunc := fundPsbtMockFn(func(
		ctx context.Context, packet *psbt.Packet,
		minConfs uint32, feeRate chainfee.SatPerKWeight,
		changeIdx int32,
	) (*tapsend.FundedPsbt, error) {

		fundedTx := packet.UnsignedTx.Copy()
		fundedTx.AddTxIn(
			&wire.TxIn{
				PreviousOutPoint: randOutPoint(h.t),
			},
		)

		fundedPsbt, _ := psbt.NewFromUnsignedTx(fundedTx)
		return &tapsend.FundedPsbt{
			Pkt: fundedPsbt, ChangeOutputIndex: -1,
		}, nil
	})
	h.mockWallet.On(
		"FundPsbt", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything,
	).Return(fundPsbtFunc, nil).Once()

	h.expectPsbtSigning()
	h.expectAssetLookup()
	h.mockDaemon.On(
		"BroadcastTransaction", mock.Anything, mock.Anything,
	).Return(nil).Once()

	// Signing stakes the transition inside the registration, whose
	// phase-1 write persists the signed transaction; broadcast then
	// finds the anchoring already registered.
	h.expectApplyCommitTxStake()
	registrar.On(
		"Register", mock.Anything,
		mock.MatchedBy(func(spec tapreorg.RegistrationSpec) bool {
			pts := spec.Triggers.OutPoints()
			return len(pts) == 1 &&
				pts[0].OutPoint == preCommit.OutPoint()
		}),
		mock.Anything,
	).Return(tapreorg.AnchoringID(1), nil).Once()
	registrar.On(
		"LookupByMatchKey", mock.Anything, SupplySiteID,
		mock.Anything,
	).Return(&tapreorg.Anchoring{ID: 1}, nil).Once()
}

// TestSupplyCommitBroadcastRestingTick exercises the anchoring path's
// resting broadcast state: the re-org watcher finalizes the transition
// out-of-band, and a tick makes the machine re-derive its position
// from the durable record.
func TestSupplyCommitBroadcastRestingTick(t *testing.T) {
	t.Parallel()

	testScriptKey := test.RandPubKey(t)
	randGroupKey := test.RandPubKey(t)
	defaultAssetSpec := asset.NewSpecifierOptionalGroupPubKey(
		testAssetID, randGroupKey,
	)
	mintEvent := newTestMintEvent(t, testScriptKey, randOutPoint(t))

	// Without a watcher configured, the legacy machine has no
	// business receiving ticks in the broadcast state.
	t.Run("legacy_tick_errors", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitBroadcastState{},
			assetSpec:    defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.assertHandlesInvalidEvent(
			&CommitTickEvent{}, ErrInvalidStateTransition,
		)
	})

	// While the durable record still says broadcast, the machine
	// keeps resting.
	t.Run("still_pending_rests", func(t *testing.T) {
		registrar := &mockAnchoringRegistrar{}
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState:     &CommitBroadcastState{},
			assetSpec:        defaultAssetSpec,
			anchoringWatcher: registrar,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectFetchState(
			&CommitBroadcastState{},
			lfn.None[SupplyStateTransition](),
		)

		h.sendEvent(&CommitTickEvent{})
		h.assertStateTransitions(&CommitBroadcastState{})

		registrar.AssertExpectations(t)
	})

	// Once the watcher has finalized the transition with nothing
	// dangling, a tick brings the machine to rest in the default
	// state.
	t.Run("finalized_rests_default", func(t *testing.T) {
		registrar := &mockAnchoringRegistrar{}
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState:     &CommitBroadcastState{},
			assetSpec:        defaultAssetSpec,
			anchoringWatcher: registrar,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectFetchState(
			&DefaultState{}, lfn.None[SupplyStateTransition](),
		)

		h.sendEvent(&CommitTickEvent{})
		h.assertStateTransitions(&DefaultState{})

		registrar.AssertExpectations(t)
	})

	// When the watcher's finalizer bound dangling updates into a
	// fresh pending transition, a tick adopts it and rolls straight
	// into the next commitment cycle, ending at rest in the broadcast
	// state with a freshly registered anchoring.
	t.Run("finalized_with_dangling_starts_cycle", func(t *testing.T) {
		registrar := &mockAnchoringRegistrar{}
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState:     &CommitBroadcastState{},
			assetSpec:        defaultAssetSpec,
			anchoringWatcher: registrar,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectFetchState(
			&UpdatesPendingState{},
			lfn.Some(SupplyStateTransition{
				PendingUpdates: []SupplyUpdateEvent{
					mintEvent,
				},
			}),
		)
		h.expectFreezePendingTransition()
		h.expectAnchoringCommitCycle(registrar)

		h.sendEvent(&CommitTickEvent{})
		h.assertStateTransitions(
			&UpdatesPendingState{},
			&CommitTreeCreateState{},
			&CommitTxCreateState{},
			&CommitTxSignState{},
			&CommitBroadcastState{},
			&CommitBroadcastState{},
		)

		registrar.AssertExpectations(t)
	})

	// An abandonment returns the foreclosed commitment's updates to a
	// fresh pending transition and parks the durable record in
	// UpdatesPendingState. The nudge effect it enqueues, dispatched
	// through the manager, wakes the resting machine, which adopts
	// the rebound batch and starts the next cycle unattended.
	t.Run("abandonment_nudge_starts_cycle", func(t *testing.T) {
		registrar := &mockAnchoringRegistrar{}
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState:     &CommitBroadcastState{},
			assetSpec:        defaultAssetSpec,
			anchoringWatcher: registrar,
		})
		h.start()
		defer h.stopAndAssert()

		// The nudge reaches the machine through the manager's
		// cache, as it does in production.
		manager := NewManager(ManagerCfg{})
		require.NoError(t, manager.Start())
		manager.smCache.Set(*randGroupKey, h.stateMachine)

		h.expectFetchState(
			&UpdatesPendingState{},
			lfn.Some(SupplyStateTransition{
				PendingUpdates: []SupplyUpdateEvent{
					mintEvent,
				},
			}),
		)
		h.expectFreezePendingTransition()
		h.expectAnchoringCommitCycle(registrar)

		var blob nudgeBlob
		copy(blob.GroupKey[:], randGroupKey.SerializeCompressed())
		err := manager.DispatchCommitNudge(
			context.Background(), fn.None[tapreorg.AnchoringID](),
			encodeNudgeBlob(blob),
		)
		require.NoError(t, err)

		h.assertStateTransitions(
			&UpdatesPendingState{},
			&CommitTreeCreateState{},
			&CommitTxCreateState{},
			&CommitTxSignState{},
			&CommitBroadcastState{},
			&CommitBroadcastState{},
		)

		registrar.AssertExpectations(t)
	})
}

// TestSupplyCommitSignStake pins the signing step's stake on the
// anchoring path: the signed transaction is persisted by the phase-1
// write of the watcher's registration, so the durable broadcast state
// and the anchoring exist together or not at all, and broadcast then
// finds the anchoring already registered.
func TestSupplyCommitSignStake(t *testing.T) {
	t.Parallel()

	randGroupKey := test.RandPubKey(t)
	defaultAssetSpec := asset.NewSpecifierOptionalGroupPubKey(
		testAssetID, randGroupKey,
	)

	// The commit transaction spends a pre-commitment the store
	// resolves by outpoint, and a wallet fee input it does not.
	preCommit := newTestPreCommit(t, randGroupKey)
	commitTx := wire.NewMsgTx(2)
	commitTx.AddTxIn(&wire.TxIn{PreviousOutPoint: preCommit.OutPoint()})
	commitTx.AddTxIn(&wire.TxIn{PreviousOutPoint: randOutPoint(t)})
	commitTx.AddTxOut(&wire.TxOut{PkScript: []byte("test"), Value: 1})
	internalKey, _ := test.RandKeyDesc(t)
	transition := SupplyStateTransition{
		NewCommitment: RootCommitment{
			Txn:         commitTx,
			InternalKey: internalKey,
			OutputKey:   test.RandPubKey(t),
		},
	}
	signEvent := &SignTxEvent{
		CommitPkt:       newTestFundedPsbt(t, commitTx),
		NewSupplyCommit: transition.NewCommitment,
	}
	essentialTrigger := mock.MatchedBy(
		func(spec tapreorg.RegistrationSpec) bool {
			pts := spec.Triggers.OutPoints()
			return len(pts) == 1 &&
				pts[0].OutPoint == preCommit.OutPoint()
		},
	)

	newHarness := func(t *testing.T) (*supplyCommitTestHarness,
		*mockAnchoringRegistrar) {

		registrar := &mockAnchoringRegistrar{}
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &CommitTxSignState{
				SupplyTransition: transition,
			},
			assetSpec:        defaultAssetSpec,
			anchoringWatcher: registrar,
		})
		h.start()

		h.expectPsbtSigning()
		h.mockCommits.On(
			"UnspentPrecommits", mock.Anything, mock.Anything,
			mock.Anything,
		).Return(
			lfn.Ok[PreCommits]([]PreCommitment{preCommit}),
		).Once()

		return h, registrar
	}

	// The registration carries the essential trigger alone, its
	// phase-1 write persists the signed transaction, and broadcast
	// finds the anchoring rather than registering again.
	t.Run("stake_commits_with_registration", func(t *testing.T) {
		h, registrar := newHarness(t)
		defer h.stopAndAssert()

		h.expectApplyCommitTxStake()
		registrar.On(
			"Register", mock.Anything, essentialTrigger,
			mock.Anything,
		).Return(tapreorg.AnchoringID(7), nil).Once()
		registrar.On(
			"LookupByMatchKey", mock.Anything, SupplySiteID,
			mock.Anything,
		).Return(&tapreorg.Anchoring{ID: 7}, nil).Once()
		h.expectAssetLookup()
		h.mockDaemon.On(
			"BroadcastTransaction", mock.Anything, mock.Anything,
		).Return(nil).Once()

		h.sendEvent(signEvent)
		h.assertStateTransitions(
			&CommitBroadcastState{}, &CommitBroadcastState{},
		)

		registrar.AssertExpectations(t)
	})

	// A phase-1 write that fails fails the registration with it: the
	// machine reports the error and stays put, and nothing is
	// persisted outside the registration.
	t.Run("failing_stake_fails_registration", func(t *testing.T) {
		h, registrar := newHarness(t)
		defer h.stopAndAssert()

		stakeErr := errors.New("stake refused")
		h.mockStateLog.On(
			"ApplyCommitTxStake", mock.Anything, mock.Anything,
			mock.Anything, mock.Anything,
		).Return(stakeErr).Once()
		registrar.On(
			"Register", mock.Anything, essentialTrigger,
			mock.Anything,
		).Return(tapreorg.AnchoringID(7), nil).Once()

		h.assertHandlesInvalidEvent(signEvent, stakeErr)

		registrar.AssertExpectations(t)
	})
}

// TestSupplyCommitUpdatesPendingRederive exercises the re-derivation
// of the pending batch from the durable record: a machine resumed from
// disk rests in UpdatesPendingState with no in-memory updates, and a
// tick must commit the durable batch, not an empty one.
func TestSupplyCommitUpdatesPendingRederive(t *testing.T) {
	t.Parallel()

	testScriptKey := test.RandPubKey(t)
	randGroupKey := test.RandPubKey(t)
	defaultAssetSpec := asset.NewSpecifierOptionalGroupPubKey(
		testAssetID, randGroupKey,
	)
	mintEvent := newTestMintEvent(t, testScriptKey, randOutPoint(t))

	// A resumed machine re-derives the batch and runs the legacy
	// cycle (no watcher configured here).
	t.Run("resumed_empty_rederives", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &UpdatesPendingState{},
			assetSpec:    defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectFetchState(
			&UpdatesPendingState{},
			lfn.Some(SupplyStateTransition{
				PendingUpdates: []SupplyUpdateEvent{
					mintEvent,
				},
			}),
		)
		h.expectFreezePendingTransition()
		h.expectFullCommitmentCycleMocks(true)

		h.sendEvent(&CommitTickEvent{})
		h.assertStateTransitions(
			&CommitTreeCreateState{},
			&CommitTxCreateState{},
			&CommitTxSignState{},
			&CommitBroadcastState{},
			&CommitBroadcastState{},
		)
	})

	// With nothing to commit anywhere, ticking is vacuous: the
	// machine returns to rest instead of committing an empty batch.
	t.Run("vacuous_tick_rests_default", func(t *testing.T) {
		h := newSupplyCommitTestHarness(t, &harnessCfg{
			initialState: &UpdatesPendingState{},
			assetSpec:    defaultAssetSpec,
		})
		h.start()
		defer h.stopAndAssert()

		h.expectFetchState(
			&UpdatesPendingState{},
			lfn.None[SupplyStateTransition](),
		)
		h.expectCommitState()

		h.sendEvent(&CommitTickEvent{})
		h.assertStateTransitions(&DefaultState{})
	})
}

// managerDaemon lends the mock daemon adapters the lifecycle methods
// the manager's DaemonAdapters contract adds.
type managerDaemon struct {
	*mockDaemonAdapters
}

func (d *managerDaemon) Start() error { return nil }

func (d *managerDaemon) Stop() error { return nil }

// newManagerHarness builds a manager over the state machine harness's
// mocks, so a restart can be exercised through startAssetSM with the
// harness's expectation helpers. The harness's own machine is never
// started; the manager builds the one under test.
func newManagerHarness(t *testing.T,
	cfg *harnessCfg) (*supplyCommitTestHarness, *Manager) {

	h := newSupplyCommitTestHarness(t, cfg)
	manager := NewManager(ManagerCfg{
		AnchoringWatcher:   cfg.anchoringWatcher,
		TreeView:           h.mockTreeView,
		Commitments:        h.mockCommits,
		Wallet:             h.mockWallet,
		AssetLookup:        h.MockAssetLookup,
		KeyRing:            h.mockKeyRing,
		Chain:              h.mockChain,
		SupplySyncer:       h.mockSupplySyncer,
		DaemonAdapters:     &managerDaemon{h.mockDaemon},
		StateLog:           h.mockStateLog,
		IgnoreCheckerCache: h.mockCache,
	})
	require.NoError(t, manager.Start())

	return h, manager
}

// stopManager stops the manager and checks the harness's expectations.
func stopManager(h *supplyCommitTestHarness, manager *Manager) {
	h.t.Helper()

	require.NoError(h.t, manager.Stop())
	h.assertExpectations()
}

// awaitState waits for the machine to settle, between events, in a
// state of type S, and returns it.
func awaitState[S State](t *testing.T, sm *StateMachine) S {
	t.Helper()

	var settled S
	require.Eventually(t, func() bool {
		current, err := sm.CurrentState()
		if err != nil {
			return false
		}
		state, ok := current.(S)
		if !ok {
			return false
		}
		settled = state

		return true
	}, testTimeout, 10*time.Millisecond)

	return settled
}

// signalCall closes done when the mock call it decorates runs.
func signalCall(done chan struct{}) func(mock.Arguments) {
	return func(mock.Arguments) {
		close(done)
	}
}

// TestSupplyCommitRestart exercises the manager's resumption of a
// machine from the durable record. A restart inside the act window
// finds the record in the broadcast state with the pending transition
// alongside: the resumed state must carry that transition, and on the
// anchoring path the machine must come to rest for the watcher's
// finalization rather than re-run a broadcast the watcher already
// holds. A restored pending batch resumes on the anchoring path and
// waits for the operator on the legacy path.
func TestSupplyCommitRestart(t *testing.T) {
	t.Parallel()

	testScriptKey := test.RandPubKey(t)
	randGroupKey := test.RandPubKey(t)
	defaultAssetSpec := asset.NewSpecifierOptionalGroupPubKey(
		testAssetID, randGroupKey,
	)
	mintEvent := newTestMintEvent(t, testScriptKey, randOutPoint(t))

	// The persisted commitment transaction spends a pre-commitment the
	// store resolves by outpoint; there is no prior commitment.
	preCommit := newTestPreCommit(t, randGroupKey)
	commitTx := wire.NewMsgTx(2)
	commitTx.AddTxIn(&wire.TxIn{PreviousOutPoint: preCommit.OutPoint()})
	commitTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51}))
	broadcastTransition := SupplyStateTransition{
		NewCommitment: RootCommitment{Txn: commitTx},
	}
	essentialTrigger := mock.MatchedBy(
		func(spec tapreorg.RegistrationSpec) bool {
			pts := spec.Triggers.OutPoints()
			return len(pts) == 1 &&
				pts[0].OutPoint == preCommit.OutPoint()
		},
	)
	pendingBatch := lfn.Some(SupplyStateTransition{
		PendingUpdates: []SupplyUpdateEvent{mintEvent},
	})

	// A machine restored in the broadcast state, its anchoring in
	// place, carries the persisted transition and rests: the restart
	// tick re-reads a record that still says broadcast, and the
	// machine keeps running.
	t.Run("anchoring_broadcast_rests", func(t *testing.T) {
		registrar := &mockAnchoringRegistrar{}
		h, manager := newManagerHarness(t, &harnessCfg{
			assetSpec:        defaultAssetSpec,
			anchoringWatcher: registrar,
		})
		defer stopManager(h, manager)

		h.expectFetchState(
			&CommitBroadcastState{}, lfn.Some(broadcastTransition),
		)
		registrar.On(
			"LookupByMatchKey", mock.Anything, SupplySiteID,
			mock.Anything,
		).Return(&tapreorg.Anchoring{ID: 1}, nil).Once()
		ticked := make(chan struct{})
		h.mockStateLog.On(
			"FetchState", mock.Anything, mock.Anything,
		).Return(
			&CommitBroadcastState{},
			lfn.None[SupplyStateTransition](), nil,
		).Run(signalCall(ticked)).Once()

		sm, err := manager.startAssetSM(
			context.Background(), defaultAssetSpec,
		)
		require.NoError(t, err)
		defer sm.Stop()

		_, err = lfn.RecvOrTimeout(ticked, testTimeout)
		require.NoError(t, err)

		state := awaitState[*CommitBroadcastState](t, sm)
		require.Same(
			t, commitTx, state.SupplyTransition.NewCommitment.Txn,
		)
		require.True(t, sm.IsRunning())
		registrar.AssertExpectations(t)
	})

	// A broadcast state persisted without an anchoring — by the code
	// that predated the watcher — is adopted on restart: the machine
	// registers the anchoring from the restored transition, staking
	// nothing since the state is already durable, and then rests.
	t.Run("anchoring_broadcast_adopts_missing", func(t *testing.T) {
		registrar := &mockAnchoringRegistrar{}
		h, manager := newManagerHarness(t, &harnessCfg{
			assetSpec:        defaultAssetSpec,
			anchoringWatcher: registrar,
		})
		defer stopManager(h, manager)

		h.expectFetchState(
			&CommitBroadcastState{}, lfn.Some(broadcastTransition),
		)
		var noAnchoring *tapreorg.Anchoring
		registrar.On(
			"LookupByMatchKey", mock.Anything, SupplySiteID,
			mock.Anything,
		).Return(noAnchoring, nil).Once()
		h.mockCommits.On(
			"UnspentPrecommits", mock.Anything, mock.Anything,
			mock.Anything,
		).Return(
			lfn.Ok[PreCommits]([]PreCommitment{preCommit}),
		).Once()
		registrar.On(
			"Register", mock.Anything, essentialTrigger,
			mock.Anything,
		).Return(tapreorg.AnchoringID(1), nil).Once()
		ticked := make(chan struct{})
		h.mockStateLog.On(
			"FetchState", mock.Anything, mock.Anything,
		).Return(
			&CommitBroadcastState{},
			lfn.None[SupplyStateTransition](), nil,
		).Run(signalCall(ticked)).Once()

		sm, err := manager.startAssetSM(
			context.Background(), defaultAssetSpec,
		)
		require.NoError(t, err)
		defer sm.Stop()

		_, err = lfn.RecvOrTimeout(ticked, testTimeout)
		require.NoError(t, err)

		awaitState[*CommitBroadcastState](t, sm)
		require.True(t, sm.IsRunning())
		registrar.AssertExpectations(t)
	})

	// A machine restored with a parked batch resumes the interrupted
	// cycle: the restart tick re-derives the batch from the record and
	// runs it through to a fresh, registered broadcast.
	t.Run("anchoring_updates_pending_starts_cycle", func(t *testing.T) {
		registrar := &mockAnchoringRegistrar{}
		h, manager := newManagerHarness(t, &harnessCfg{
			assetSpec:        defaultAssetSpec,
			anchoringWatcher: registrar,
		})
		defer stopManager(h, manager)

		h.expectFetchState(&UpdatesPendingState{}, pendingBatch)
		h.expectFetchState(&UpdatesPendingState{}, pendingBatch)
		h.expectFreezePendingTransition()
		h.expectAnchoringCommitCycle(registrar)

		sm, err := manager.startAssetSM(
			context.Background(), defaultAssetSpec,
		)
		require.NoError(t, err)
		defer sm.Stop()

		state := awaitState[*CommitBroadcastState](t, sm)
		require.Equal(
			t, []SupplyUpdateEvent{mintEvent},
			state.SupplyTransition.PendingUpdates,
		)
		require.True(t, sm.IsRunning())
		registrar.AssertExpectations(t)
	})

	// Without a watcher the restored broadcast state re-runs the
	// broadcast from the persisted transition and re-subscribes for
	// the confirmation.
	t.Run("legacy_broadcast_rebroadcasts", func(t *testing.T) {
		h, manager := newManagerHarness(t, &harnessCfg{
			assetSpec: defaultAssetSpec,
		})
		defer stopManager(h, manager)

		h.expectFetchState(
			&CommitBroadcastState{}, lfn.Some(broadcastTransition),
		)
		broadcast := make(chan struct{})
		h.mockDaemon.On(
			"BroadcastTransaction", commitTx, mock.Anything,
		).Return(nil).Run(signalCall(broadcast)).Once()
		h.mockChain.On("CurrentHeight", mock.Anything).Return(
			uint32(123), nil,
		).Once()
		h.mockDaemon.On(
			"RegisterConfirmationsNtfn", mock.Anything,
			mock.Anything, mock.Anything, mock.Anything,
			mock.Anything,
		).Return(nil).Once()

		sm, err := manager.startAssetSM(
			context.Background(), defaultAssetSpec,
		)
		require.NoError(t, err)
		defer sm.Stop()

		_, err = lfn.RecvOrTimeout(broadcast, testTimeout)
		require.NoError(t, err)

		awaitState[*CommitBroadcastState](t, sm)
		require.True(t, sm.IsRunning())
	})

	// Without a watcher a restored pending batch waits for the
	// operator's publish call.
	t.Run("legacy_updates_pending_rests", func(t *testing.T) {
		h, manager := newManagerHarness(t, &harnessCfg{
			assetSpec: defaultAssetSpec,
		})
		defer stopManager(h, manager)

		h.expectFetchState(&UpdatesPendingState{}, pendingBatch)

		sm, err := manager.startAssetSM(
			context.Background(), defaultAssetSpec,
		)
		require.NoError(t, err)
		defer sm.Stop()

		awaitState[*UpdatesPendingState](t, sm)
		require.True(t, sm.IsRunning())
	})
}
