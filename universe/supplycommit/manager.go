package supplycommit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/msgmux"
	"github.com/lightningnetwork/lnd/protofsm"
)

const (
	// DefaultTimeout is the context guard default timeout.
	DefaultTimeout = 30 * time.Second
)

// DaemonAdapters is a wrapper around the protofsm.DaemonAdapters interface
// with the addition of Start and Stop methods.
type DaemonAdapters interface {
	protofsm.DaemonAdapters

	// Start starts the daemon adapters handler service.
	Start() error

	// Stop stops the daemon adapters handler service.
	Stop() error
}

// ManagerCfg is the configuration for the
// Manager. It contains all the dependencies needed to
// manage multiple supply commitment state machines, one for each asset group.
type ManagerCfg struct {
	// TreeView is the interface that allows the state machine to obtain an
	// up to date snapshot of the root supply tree, and the relevant set of
	// subtrees.
	TreeView SupplyTreeView

	// Commitments is used to track the state of the pre-commitment and
	// commitment outputs that are currently confirmed on-chain.
	Commitments CommitmentTracker

	// Wallet is the interface used interact with the wallet.
	Wallet Wallet

	// AssetLookup is used to look up asset information such as asset groups
	// and asset metadata.
	AssetLookup AssetLookup

	// KeyRing is the key ring used to derive new keys.
	KeyRing KeyRing

	// Chain is our access to the current main chain.
	//
	// TODO(roasbeef): can make a slimmer version of
	Chain tapgarden.ChainBridge

	// SupplySyncer is used to insert supply commitments into the remote
	// universe server.
	SupplySyncer SupplySyncer

	// DaemonAdapters is a set of adapters that allow the state machine to
	// interact with external daemons whilst processing internal events.
	DaemonAdapters DaemonAdapters

	// StateLog is the main state log that is used to track the state of the
	// state machine. This is used to persist the state of the state machine
	// across restarts.
	StateLog StateMachineStore

	// ChainParams is the chain parameters for the chain that we're
	// operating on.
	ChainParams chaincfg.Params

	// IgnoreCheckerCache is used to invalidate the ignore cache when a new
	// supply commitment is created.
	IgnoreCheckerCache IgnoreCheckerCache
}

// Manager is a manager for multiple supply commitment state
// machines, one for each asset group. It is responsible for starting and
// stopping the state machines, as well as forwarding sending events to them.
type Manager struct {
	// cfg is the configuration for the multi state machine manager.
	cfg ManagerCfg

	// smCache is a cache that maps asset group public keys to their
	// supply commitment state machines.
	smCache *stateMachineCache

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard

	startOnce sync.Once
	stopOnce  sync.Once
}

// NewManager creates a new multi state machine manager.
func NewManager(cfg ManagerCfg) *Manager {
	return &Manager{
		cfg: cfg,
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start starts the multi state machine manager.
func (m *Manager) Start() error {
	m.startOnce.Do(func() {
		// Initialize the state machine cache.
		m.smCache = newStateMachineCache()
	})

	return nil
}

// Stop stops the multi state machine manager, which in turn stops all asset
// group key specific supply commitment state machines.
func (m *Manager) Stop() error {
	m.stopOnce.Do(func() {
		// Cancel the state machine context to signal all state machines
		// to stop.
		close(m.Quit)

		// Stop all state machines.
		m.smCache.StopAll()
	})

	return nil
}

// ensureSupplyCommitSupport verifies that the asset group for the given
// asset specifier supports supply commitments, and that this node can generate
// supply commitments for it.
func (m *Manager) ensureSupplyCommitSupport(ctx context.Context,
	metaReveal proof.MetaReveal) error {

	// If the universe commitment flag is not set on the asset metadata,
	// then the asset group does not support supply commitments.
	if !metaReveal.UniverseCommitments {
		return fmt.Errorf("asset group metadata universe " +
			"commitments flag indicates that asset does not " +
			"support supply commitments")
	}

	// If a delegation key is not present, then the asset group does not
	// support supply commitments.
	if metaReveal.DelegationKey.IsNone() {
		return fmt.Errorf("asset group metadata does not " +
			"specify delegation key, which is required for " +
			"supply commitments")
	}

	// Extract supply commitment delegation pub key from the asset metadata.
	delegationPubKey, err := metaReveal.DelegationKey.UnwrapOrErr(
		fmt.Errorf("delegation key not found for given asset"),
	)
	if err != nil {
		return err
	}

	// Fetch the delegation key locator. We need to ensure that the
	// delegation key is owned by this node, so that we can generate
	// supply commitments (ignore tuples) for this asset group.
	_, err = m.cfg.AssetLookup.FetchInternalKeyLocator(
		ctx, &delegationPubKey,
	)
	switch {
	case errors.Is(err, address.ErrInternalKeyNotFound):
		return fmt.Errorf("delegation key locator not found; " +
			"only delegation key owners can ignore asset " +
			"outpoints for this asset group")
	case err != nil:
		return fmt.Errorf("failed to fetch delegation key locator: %w",
			err)
	}

	return nil
}

// fetchStateMachine retrieves a state machine from the cache or creates a
// new one if it doesn't exist. If a new state machine is created, it is also
// started.
func (m *Manager) fetchStateMachine(
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
	//
	// Before we can create a state machine, we need to ensure that the
	// asset group supports supply commitments. If it doesn't, then we
	// return an error.
	ctx, cancel := m.WithCtxQuitNoTimeout()
	defer cancel()

	metaReveal, err := fetchLatestAssetMetadata(
		ctx, m.cfg.AssetLookup, assetSpec,
	)
	if err != nil {
		return nil, fmt.Errorf("faild to fetch asset meta: %w", err)
	}

	err = m.ensureSupplyCommitSupport(ctx, metaReveal)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure supply commit "+
			"support for asset: %w", err)
	}

	env := &Environment{
		AssetSpec:          assetSpec,
		TreeView:           m.cfg.TreeView,
		Commitments:        m.cfg.Commitments,
		Wallet:             m.cfg.Wallet,
		AssetLookup:        m.cfg.AssetLookup,
		KeyRing:            m.cfg.KeyRing,
		Chain:              m.cfg.Chain,
		SupplySyncer:       m.cfg.SupplySyncer,
		StateLog:           m.cfg.StateLog,
		CommitConfTarget:   DefaultCommitConfTarget,
		ChainParams:        m.cfg.ChainParams,
		IgnoreCheckerCache: m.cfg.IgnoreCheckerCache,
	}

	// Before we start the state machine, we'll need to fetch the current
	// state from disk, to see if we need to emit any new events.
	initialState, _, err := m.cfg.StateLog.FetchState(ctx, assetSpec)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch current state: %w", err)
	}

	// Create a new error reporter for the state machine.
	errorReporter := NewErrorReporter(assetSpec)

	fsmCfg := protofsm.StateMachineCfg[Event, *Environment]{
		ErrorReporter: &errorReporter,
		InitialState:  initialState,
		Env:           env,
		Daemon:        m.cfg.DaemonAdapters,
	}
	newSm := protofsm.NewStateMachine[Event, *Environment](fsmCfg)

	// Ensure that the state machine is running. We use the manager's
	// context guard to derive a sub context which will be cancelled when
	// the manager is stopped.
	smCtx, _ := m.WithCtxQuitNoTimeout()
	newSm.Start(smCtx)

	// If specific initial states are provided, we send the corresponding
	// events to the state machine to ensure it begins ticking as expected.
	switch initialState.(type) {
	// Once we write the commitment transaction to disk in CommitTxSign,
	// then on restart, we'll be in the broadcast state. From this point,
	// we'll trigger the broadcast event so we can resume the state machine.
	case *CommitBroadcastState:
		newSm.SendEvent(ctx, &BroadcastEvent{})

	// Once we get a confirmation, then we'll transition to the
	// CommitFinalizeState. If we crashed right after that, then
	// we'll also send the finalize event so we can apply
	// everything, and transition back to the normal default state.
	case *CommitFinalizeState:
		newSm.SendEvent(ctx, &FinalizeEvent{})
	}

	m.smCache.Set(*groupKey, &newSm)

	return &newSm, nil
}

// SendEvent sends an event to the state machine associated with the given asset
// specifier. If a state machine for the asset group does not exist, it will be
// created and started.
func (m *Manager) SendEvent(ctx context.Context,
	assetSpec asset.Specifier, event Event) error {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return fmt.Errorf("unable to get or create state machine: %w",
			err)
	}

	sm.SendEvent(ctx, event)
	return nil
}

// SendEventSync sends an event to the state machine and waits for it to be
// processed and written to disk. This method provides synchronous confirmation
// that the event has been durably persisted. If the event doesn't support
// synchronous processing (i.e., it's not a SupplyUpdateEvent), this method will
// return an error.
func (m *Manager) SendEventSync(ctx context.Context, assetSpec asset.Specifier,
	event SyncSupplyUpdateEvent) error {

	// Only SupplyUpdateEvents can be processed synchronously.
	supplyEvent, ok := event.(SupplyUpdateEvent)
	if !ok {
		return fmt.Errorf("event type %T does not support "+
			"synchronous processing", event)
	}

	// We'll use this channel to signal when the event has been processed.
	done := make(chan error, 1)

	// As the event has already been created, we'll set the done channel
	// directly.
	switch e := supplyEvent.(type) {
	case *NewMintEvent:
		e.Done = done
	case *NewBurnEvent:
		e.Done = done
	case *NewIgnoreEvent:
		e.Done = done
	default:
		return fmt.Errorf("unexpected supply update event type: %T",
			supplyEvent)
	}

	// Send the event to the state machine, the pause and wait until it
	// signals that the event has been fully processed.
	if err := m.SendEvent(ctx, assetSpec, supplyEvent); err != nil {
		return err
	}
	return event.WaitForDone(ctx)
}

// SendMintEvent sends a mint event to the supply commitment state machine.
//
// NOTE: This implements the tapgarden.MintSupplyCommitter interface.
func (m *Manager) SendMintEvent(ctx context.Context, assetSpec asset.Specifier,
	leafKey universe.UniqueLeafKey, issuanceProof universe.Leaf,
	mintBlockHeight uint32) error {

	mintEvent := &NewMintEvent{
		LeafKey:       leafKey,
		IssuanceProof: issuanceProof,
		MintHeight:    mintBlockHeight,
	}

	return m.SendEventSync(ctx, assetSpec, mintEvent)
}

// SendBurnEvent sends a burn event to the supply commitment state machine.
//
// NOTE: This implements the tapfreighter.BurnSupplyCommitter interface.
func (m *Manager) SendBurnEvent(ctx context.Context, assetSpec asset.Specifier,
	burnLeaf universe.BurnLeaf) error {

	burnEvent := &NewBurnEvent{
		BurnLeaf: burnLeaf,
	}

	return m.SendEventSync(ctx, assetSpec, burnEvent)
}

// StartSupplyPublishFlow triggers the state machine to build and publish
// a new supply commitment if pending supply tree updates exist.
func (m *Manager) StartSupplyPublishFlow(ctx context.Context,
	assetSpec asset.Specifier) error {

	sm, err := m.fetchStateMachine(assetSpec)
	if err != nil {
		return fmt.Errorf("unable to get or create state machine: %w",
			err)
	}

	sm.SendEvent(ctx, &CommitTickEvent{})
	return nil
}

// CanHandle determines if the state machine associated with the given asset
// specifier can handle the given message. If a state machine for the asset
// group does not exist, it will be created and started.
func (m *Manager) CanHandle(assetSpec asset.Specifier,
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
func (m *Manager) Name(
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
func (m *Manager) SendMessage(ctx context.Context,
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
func (m *Manager) CurrentState(assetSpec asset.Specifier) (
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
func (m *Manager) RegisterStateEvents(
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
func (m *Manager) RemoveStateSub(assetSpec asset.Specifier,
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
func (m *Manager) FetchCommitment(ctx context.Context,
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

	subtrees, err := m.cfg.TreeView.FetchSubTrees(
		ctx, assetSpec, fn.None[uint32](),
	).Unpack()
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

// FetchSupplyLeavesByHeight returns the set of supply leaves for the given
// asset specifier within the specified height range.
func (m *Manager) FetchSupplyLeavesByHeight(
	ctx context.Context, assetSpec asset.Specifier, startHeight,
	endHeight uint32) (SupplyLeaves, error) {

	var zero SupplyLeaves

	resp, err := m.cfg.TreeView.FetchSupplyLeavesByHeight(
		ctx, assetSpec, startHeight, endHeight,
	).Unpack()
	if err != nil {
		return zero, fmt.Errorf("unable to fetch supply leaves: %w",
			err)
	}

	return resp, nil
}

// FetchSubTrees returns all the sub trees for the given asset specifier.
func (m *Manager) FetchSubTrees(ctx context.Context,
	assetSpec asset.Specifier,
	blockHeightEnd fn.Option[uint32]) (SupplyTrees, error) {

	var zero SupplyTrees

	subtrees, err := m.cfg.TreeView.FetchSubTrees(
		ctx, assetSpec, blockHeightEnd,
	).Unpack()
	if err != nil {
		return zero, fmt.Errorf("unable to fetch sub trees: %w", err)
	}

	return subtrees, nil
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

// ErrorReporter is an asset specific error reporter that can be used to
// report errors that occur during the operation of the asset group supply
// commitment state machine.
type ErrorReporter struct {
	// assetSpec is the asset specifier that identifies the asset group.
	assetSpec asset.Specifier
}

// NewErrorReporter creates a new ErrorReporter for the given asset specifier
// state machine.
func NewErrorReporter(assetSpec asset.Specifier) ErrorReporter {
	return ErrorReporter{
		assetSpec: assetSpec,
	}
}

// ReportError reports an error that occurred during the operation of the
// asset group supply commitment state machine.
func (r *ErrorReporter) ReportError(err error) {
	log.Errorf("supply commit state machine (asset_spec=%s): %v",
		r.assetSpec.String(), err)
}
