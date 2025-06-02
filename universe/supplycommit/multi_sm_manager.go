package supplycommit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightningnetwork/lnd/msgmux"
	"github.com/lightningnetwork/lnd/protofsm"
)

const (
	// DefaultTimeout is the context guard default timeout.
	DefaultTimeout = 30 * time.Second
)

// MultiStateMachineManagerCfg is the configuration for the
// MultiStateMachineManager. It contains all the dependencies needed to
// manage multiple supply commitment state machines, one for each asset group.
type MultiStateMachineManagerCfg struct {
	// TreeView is the interface that allows the state machine to obtain an
	// up to date snapshot of the root supply tree, and the relevant set of
	// subtrees.
	TreeView SupplyTreeView

	// Commitments is used to track the state of the pre-commitment and
	// commitment outputs that are currently confirmed on-chain.
	Commitments CommitmentTracker

	// Wallet is the interface used interact with the wallet.
	Wallet Wallet

	// KeyRing is the key ring used to derive new keys.
	KeyRing KeyRing

	// Chain is our access to the current main chain.
	//
	// TODO(roasbeef): can make a slimmer version of
	Chain tapgarden.ChainBridge

	// StateLog is the main state log that is used to track the state of the
	// state machine. This is used to persist the state of the state machine
	// across restarts.
	StateLog StateMachineStore
}

// MultiStateMachineManager is a manager for multiple supply commitment state
// machines, one for each asset group. It is responsible for starting and
// stopping the state machines, as well as forwarding sending events to them.
type MultiStateMachineManager struct {
	// cfg is the configuration for the multi state machine manager.
	cfg MultiStateMachineManagerCfg

	// smCache is a cache that maps asset group public keys to their
	// supply commitment state machines.
	smCache *stateMachineCache

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard

	startOnce sync.Once
	stopOnce  sync.Once
}

// NewMultiStateMachineManager creates a new multi state machine manager.
func NewMultiStateMachineManager(
	cfg MultiStateMachineManagerCfg) *MultiStateMachineManager {

	return &MultiStateMachineManager{
		cfg: cfg,
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start starts the multi state machine manager.
func (m *MultiStateMachineManager) Start() error {
	m.startOnce.Do(func() {
		// Initialize the state machine cache.
		m.smCache = newStateMachineCache()
	})

	return nil
}

// Stop stops the multi state machine manager, which in turn stops all asset
// group key specific supply commitment state machines.
func (m *MultiStateMachineManager) Stop() error {
	m.stopOnce.Do(func() {
		// Cancel the state machine context to signal all state machines
		// to stop.
		close(m.Quit)

		// Stop all state machines.
		m.smCache.StopAll()
	})

	return nil
}

// fetchStateMachine retrieves a state machine from the cache or creates a
// new one if it doesn't exist. If a new state machine is created, it is also
// started.
func (m *MultiStateMachineManager) fetchStateMachine(
	assetSpec asset.Specifier) (*StateMachine, error) {

	groupKey, err := assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return nil, fmt.Errorf("asset specifier missing group key: %w",
			err)
	}

	// Check if the state machine for the asset group already exists in the
	// cache.
	sm, ok := m.smCache.Get(*groupKey)
	if ok {
		return sm, nil
	}

	// If the state machine is not found, create a new one.
	env := &Environment{
		AssetSpec:        assetSpec,
		TreeView:         m.cfg.TreeView,
		Commitments:      m.cfg.Commitments,
		Wallet:           m.cfg.Wallet,
		KeyRing:          m.cfg.KeyRing,
		Chain:            m.cfg.Chain,
		StateLog:         m.cfg.StateLog,
		CommitConfTarget: DefaultCommitConfTarget,
	}

	// TODO(ffranr): Get initial state from disk here.
	initialState := &DefaultState{}

	fsmCfg := protofsm.StateMachineCfg[Event, *Environment]{
		InitialState: initialState,
		Env:          env,
	}
	newSm := protofsm.NewStateMachine[Event, *Environment](fsmCfg)

	// Ensure that the state machine is running. We use the manager's
	// context guard to derive a sub context which will be cancelled when
	// the manager is stopped.
	smCtx, _ := m.WithCtxQuitNoTimeout()
	newSm.Start(smCtx)

	m.smCache.Set(*groupKey, &newSm)

	return &newSm, nil
}

// SendEvent sends an event to the state machine associated with the given asset
// specifier. If a state machine for the asset group does not exist, it will be
// created and started.
func (m *MultiStateMachineManager) SendEvent(ctx context.Context,
	assetSpec asset.Specifier, event Event) error {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return fmt.Errorf("unable to get or create state "+
			"machine: %w", err)
	}

	sm.SendEvent(ctx, event)
	return nil
}

// CanHandle determines if the state machine associated with the given asset
// specifier can handle the given message. If a state machine for the asset
// group does not exist, it will be created and started.
func (m *MultiStateMachineManager) CanHandle(assetSpec asset.Specifier,
	msg msgmux.PeerMsg) (bool, error) {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return false, fmt.Errorf("unable to get or create state "+
			"machine: %w", err)
	}

	return sm.CanHandle(msg), nil
}

// Name returns the name of the state machine associated with the given asset
// specifier. If a state machine for the asset group does not exist, it will be
// created and started.
func (m *MultiStateMachineManager) Name(
	assetSpec asset.Specifier) (string, error) {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return "", fmt.Errorf("unable to get or create state "+
			"machine: %w", err)
	}

	return sm.Name(), nil
}

// SendMessage sends a message to the state machine associated with the given
// asset specifier. If a state machine for the asset group does not exist, it
// will be created and started.
func (m *MultiStateMachineManager) SendMessage(ctx context.Context,
	assetSpec asset.Specifier, msg msgmux.PeerMsg) (bool, error) {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return false, fmt.Errorf("unable to get or create state "+
			"machine: %w", err)
	}

	return sm.SendMessage(ctx, msg), nil
}

// CurrentState returns the current state of the state machine associated with
// the given asset specifier. If a state machine for the asset group does not
// exist, it will be created and started.
func (m *MultiStateMachineManager) CurrentState(assetSpec asset.Specifier) (
	protofsm.State[Event, *Environment], error) {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return nil, fmt.Errorf("unable to get or create state "+
			"machine: %w", err)
	}

	return sm.CurrentState()
}

// RegisterStateEvents registers a state event subscriber with the state machine
// associated with the given asset specifier. If a state machine for the asset
// group does not exist, it will be created and started.
func (m *MultiStateMachineManager) RegisterStateEvents(
	assetSpec asset.Specifier) (StateSub, error) {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return nil, fmt.Errorf("unable to get or create state "+
			"machine: %w", err)
	}

	return sm.RegisterStateEvents(), nil
}

// RemoveStateSub removes a state event subscriber from the state machine
// associated with the given asset specifier. If a state machine for the asset
// group does not exist, it will be created and started.
func (m *MultiStateMachineManager) RemoveStateSub(assetSpec asset.Specifier,
	sub StateSub) error {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return fmt.Errorf("unable to get or create state "+
			"machine: %w", err)
	}

	sm.RemoveStateSub(sub)

	return nil
}

// FetchCommitmentResp is the response type for the FetchCommitment method.
type FetchCommitmentResp struct {
	// SupplyTree is the supply tree for an asset. The leaves of this tree
	// commit to the roots of the supply commit subtrees.
	SupplyTree mssmt.Tree

	// Subtrees maps a subtree type to its corresponding supply subtree.
	Subtrees SupplyTrees

	// ChainCommitment links the supply tree to its anchor transaction.
	ChainCommitment RootCommitment
}

// FetchCommitment fetches the supply commitment for the given asset specifier.
func (m *MultiStateMachineManager) FetchCommitment(ctx context.Context,
	assetSpec asset.Specifier) (fn.Option[FetchCommitmentResp], error) {

	var zero fn.Option[FetchCommitmentResp]

	chainCommitOpt, err := m.cfg.Commitments.SupplyCommit(
		ctx, assetSpec,
	).Unpack()
	if err != nil {
		return zero, fmt.Errorf("unable to fetch supply commit: %w",
			err)
	}

	if chainCommitOpt.IsNone() {
		// If the chain commitment is not present, we return an empty
		// response.
		return zero, nil
	}
	chainCommit, err := chainCommitOpt.UnwrapOrErr(
		fmt.Errorf("unable to fetch supply commit: %w", err),
	)
	if err != nil {
		return zero, err
	}

	supplyTree, err := m.cfg.TreeView.FetchRootSupplyTree(
		ctx, assetSpec,
	).Unpack()
	if err != nil {
		return zero, fmt.Errorf("unable to fetch supply commit root "+
			"supply tree: %w", err)
	}

	subtrees, err := m.cfg.TreeView.FetchSubTrees(ctx, assetSpec).Unpack()
	if err != nil {
		return zero, fmt.Errorf("unable to fetch supply commit sub "+
			"trees: %w", err)
	}

	return fn.Some(FetchCommitmentResp{
		SupplyTree:      supplyTree,
		Subtrees:        subtrees,
		ChainCommitment: chainCommit,
	}), nil
}

// stateMachineCache is a thread-safe cache mapping an asset group's public key
// to its supply commitment state machine.
type stateMachineCache struct {
	// mu is a mutex that is used to synchronize access to the cache.
	mu sync.RWMutex

	// cache is a map of serialized asset group public keys to their
	// supply commitment state machines.
	cache map[asset.SerializedKey]*StateMachine
}

// newStateMachineCache creates a new supply commit state machine cache.
func newStateMachineCache() *stateMachineCache {
	return &stateMachineCache{
		cache: make(map[asset.SerializedKey]*StateMachine),
	}
}

// StopAll stops all state machines in the cache.
func (c *stateMachineCache) StopAll() {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Iterate over the cache and append each state machine to the slice.
	for _, sm := range c.cache {
		// Sanity check: ensure sm is not nil.
		if sm == nil {
			continue
		}

		// Stop the state machine.
		sm.Stop()
	}
}

// Get retrieves a state machine from the cache.
func (c *stateMachineCache) Get(groupPubKey btcec.PublicKey) (*StateMachine,
	bool) {

	// Serialize the group key.
	serializedGroupKey := asset.ToSerialized(&groupPubKey)

	c.mu.RLock()
	defer c.mu.RUnlock()

	sm, ok := c.cache[serializedGroupKey]
	return sm, ok
}

// Set adds a state machine to the cache.
func (c *stateMachineCache) Set(groupPubKey btcec.PublicKey, sm *StateMachine) {
	// Serialize the group key.
	serializedGroupKey := asset.ToSerialized(&groupPubKey)

	c.mu.Lock()
	defer c.mu.Unlock()

	// If the state machine already exists, return without updating it.
	// This helps to ensure that we always have a pointer to every state
	// machine in the cache, even if it is not currently active.
	if _, exists := c.cache[serializedGroupKey]; exists {
		return
	}

	c.cache[serializedGroupKey] = sm
}

// Delete removes a state machine from the cache.
func (c *stateMachineCache) Delete(groupPubKey btcec.PublicKey) {
	// Serialize the group key.
	serializedGroupKey := asset.ToSerialized(&groupPubKey)

	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.cache, serializedGroupKey)
}
