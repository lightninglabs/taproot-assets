package supplyverifier

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightningnetwork/lnd/msgmux"
	"github.com/lightningnetwork/lnd/protofsm"
)

const (
	// DefaultTimeout is the context guard default timeout.
	DefaultTimeout = 30 * time.Second

	// DefaultSpendSyncDelay is the default delay to wait after a spend
	// notification is received before starting the sync of the
	// corresponding supply commitment. The delay allows the peer node to
	// submit the new commitment to the universe server and for it to be
	// available for retrieval
	DefaultSpendSyncDelay = 5 * time.Second
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

// IssuanceSubscriptions allows verifier state machines to subscribe to
// asset group issuance events.
type IssuanceSubscriptions interface {
	// RegisterSubscriber registers an event receiver to receive future
	// issuance events.
	RegisterSubscriber(receiver *fn.EventReceiver[fn.Event],
		deliverExisting bool, _ bool) error

	// RemoveSubscriber removes the given subscriber and also stops it from
	// processing events.
	RemoveSubscriber(subscriber *fn.EventReceiver[fn.Event]) error
}

// ManagerCfg is the configuration for the
// Manager. It contains all the dependencies needed to
// manage multiple supply verifier state machines, one for each asset group.
type ManagerCfg struct {
	// Chain is our access to the current main chain.
	Chain tapgarden.ChainBridge

	// AssetLookup is used to look up asset information such as asset groups
	// and asset metadata.
	AssetLookup supplycommit.AssetLookup

	// Lnd is a collection of useful LND clients.
	Lnd *lndclient.LndServices

	// SupplyCommitView allows us to look up supply commitments and
	// pre-commitments.
	SupplyCommitView SupplyCommitView

	// SupplyTreeView is used to fetch supply leaves by height.
	SupplyTreeView SupplyTreeView

	// SupplySyncer is used to retrieve supply leaves from a universe and
	// persist them to the local database.
	SupplySyncer SupplySyncer

	// GroupFetcher is used to fetch asset group information.
	GroupFetcher tapgarden.GroupFetcher

	// IssuanceSubscriptions registers verifier state machines to receive
	// new asset group issuance event notifications.
	IssuanceSubscriptions IssuanceSubscriptions

	// DaemonAdapters is a set of adapters that allow the state machine to
	// interact with external daemons whilst processing internal events.
	DaemonAdapters DaemonAdapters

	// ErrChan is the channel that is used to send errors to the caller.
	ErrChan chan<- error

	// DisableChainWatch, when true, prevents the supply verifier from
	// starting state machines to watch on-chain outputs for spends. This
	// option is intended for universe servers, where supply verification
	// should only occur for commitments submitted by peers, not via
	// on-chain spend detection.
	DisableChainWatch bool
}

// Validate validates the ManagerCfg.
func (m *ManagerCfg) Validate() error {
	if m.Chain == nil {
		return fmt.Errorf("chain is required")
	}

	if m.AssetLookup == nil {
		return fmt.Errorf("asset lookup is required")
	}

	if m.Lnd == nil {
		return fmt.Errorf("lnd is required")
	}

	if m.SupplyCommitView == nil {
		return fmt.Errorf("supply commit view is required")
	}

	if m.SupplyTreeView == nil {
		return fmt.Errorf("supply tree view is required")
	}

	if m.GroupFetcher == nil {
		return fmt.Errorf("group fetcher is required")
	}

	if m.IssuanceSubscriptions == nil {
		return fmt.Errorf("issuance subscriptions is required")
	}

	if m.DaemonAdapters == nil {
		return fmt.Errorf("daemon adapters is required")
	}

	return nil
}

// Manager is a manager for multiple supply verifier state machines, one for
// each asset group. It is responsible for starting and stopping the state
// machines, as well as forwarding events to them.
type Manager struct {
	// cfg is the configuration for the multi state machine manager.
	cfg ManagerCfg

	// smCache is a cache that maps asset group public keys to their
	// supply verifier state machines.
	smCache *stateMachineCache

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard

	startOnce sync.Once
	stopOnce  sync.Once
}

// NewManager creates a new multi state machine manager.
func NewManager(cfg ManagerCfg) (*Manager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &Manager{
		cfg: cfg,
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}, nil
}

// InitStateMachines initializes state machines for all asset groups that
// support supply commitments. If a state machine for an asset group already
// exists, it will be skipped.
func (m *Manager) InitStateMachines() error {
	ctx, cancel := m.WithCtxQuitNoTimeout()
	defer cancel()

	log.Infof("Initializing supply verifier state machines")

	// First, get all assets with group keys that could potentially be
	// involved in supply commitments. The Manager will filter these
	// based on delegation key ownership and other criteria.
	assetGroupKeys, err := m.cfg.AssetLookup.FetchSupplyCommitAssets(
		ctx, false,
	)
	if err != nil {
		return fmt.Errorf("unable to fetch supply commit assets: %w",
			err)
	}

	log.Debugf("Found %d potential asset groups for supply verification",
		len(assetGroupKeys))

	for idx := range assetGroupKeys {
		groupKey := assetGroupKeys[idx]

		// Create asset specifier from group key.
		assetSpec := asset.NewSpecifierFromGroupKey(groupKey)

		// Check to ensure state machine for asset group does not
		// already exist.
		_, ok := m.smCache.Get(groupKey)
		if ok {
			log.Tracef("State machine already exists for "+
				"asset group: %x",
				groupKey.SerializeCompressed())
			continue
		}

		// Create and start a new state machine for the asset group.
		newSm, err := m.startAssetSM(ctx, assetSpec)
		if err != nil {
			return fmt.Errorf("unable to start state machine for "+
				"asset group (asset=%s): %w",
				assetSpec.String(), err)
		}

		m.smCache.Set(groupKey, newSm)
	}

	return nil
}

// Start starts the multi state machine manager.
func (m *Manager) Start() error {
	var startErr error

	m.startOnce.Do(func() {
		log.Infof("Starting supply verifier manager")

		// Initialize the state machine cache unconditionally to prevent
		// potential nil pointer dereferences, even if it ends up
		// unused.
		m.smCache = newStateMachineCache()

		// If chain watching is disabled, return early. We won't start
		// any state machines in this mode.
		if m.cfg.DisableChainWatch {
			log.Infof("Supply verifier chain watch disabled, " +
				"skip state machine initialization")
			return
		}

		// Initialize state machines for each asset group that supports
		// supply commitments.
		err := m.InitStateMachines()
		if err != nil {
			startErr = fmt.Errorf("unable to initialize "+
				"state machines: %v", err)
			return
		}

		log.Debugf("Starting universe syncer event monitor")

		// Start a goroutine to handle universe syncer issuance events.
		m.ContextGuard.Goroutine(
			m.MonitorUniSyncEvents, func(err error) {
				log.Errorf("MonitorUniIssuanceSyncEvents: %v",
					err)
			},
		)

		log.Infof("Supply verifier manager started successfully")
	})
	if startErr != nil {
		return fmt.Errorf("unable to start manager: %w", startErr)
	}

	return nil
}

// handleUniSyncEvent handles a single universe syncer event. If the event is an
// issuance event for an asset group that supports supply commitments, it will
// ensure that a state machine for the asset group exists, creating and
// starting it if necessary.
func (m *Manager) handleUniSyncEvent(event fn.Event) error {
	// Disregard event if it is not of type
	// universe.SyncDiffEvent.
	syncDiffEvent, ok := event.(*universe.SyncDiffEvent)
	if !ok {
		return nil
	}

	// If the sync diff is not a new issuance, we disregard it.
	universeID := syncDiffEvent.SyncDiff.NewUniverseRoot.ID
	if universeID.ProofType != universe.ProofTypeIssuance {
		return nil
	}

	// If the asset is not a group key asset, we
	// disregard it.
	if universeID.GroupKey == nil {
		return nil
	}

	// If there are no new leaf proofs, we disregard the sync event.
	if len(syncDiffEvent.SyncDiff.NewLeafProofs) == 0 {
		return nil
	}

	log.Tracef("Processing universe sync event for group key: %x, "+
		"new_leaf_proofs=%d", universeID.GroupKey.SerializeCompressed(),
		len(syncDiffEvent.SyncDiff.NewLeafProofs))

	// Get genesis asset ID from the first synced leaf and formulate an
	// asset specifier.
	//
	// TODO(ffranr): Revisit this. We select any asset ID to aid in metdata
	//  retrieval, but we should be able to do this with just the group key.
	//  However, QueryAssetGroupByGroupKey currently fails for the asset
	//  group.
	assetID := syncDiffEvent.SyncDiff.NewLeafProofs[0].Genesis.ID()

	assetSpec := asset.NewSpecifierOptionalGroupPubKey(
		assetID, universeID.GroupKey,
	)

	// Check that the asset group supports supply
	// commitments.
	ctx, cancelCtx := m.WithCtxQuitNoTimeout()
	isSupported, err := supplycommit.IsSupplySupported(
		ctx, m.cfg.AssetLookup, assetSpec, false,
	)
	if err != nil {
		return fmt.Errorf("failed to check supply support: %w", err)
	}
	cancelCtx()

	if !isSupported {
		log.Tracef("Asset does not support supply commitments: %s",
			assetSpec.String())
		return nil
	}

	log.Debugf("Ensure supply verifier state machine for asset "+
		"group due to universe syncer issuance event (asset=%s)",
		assetSpec.String())

	// Fetch the state machine for the asset group, creating and starting it
	// if it doesn't exist.
	_, err = m.fetchStateMachine(assetSpec)
	if err != nil {
		return fmt.Errorf("unable to get or create state machine: %w",
			err)
	}

	return nil
}

// MonitorUniSyncEvents registers an event receiver to receive universe
// syncer issuance events.
//
// NOTE: This method must be run as a goroutine.
func (m *Manager) MonitorUniSyncEvents() error {
	// Register an event receiver to receive universe syncer events. These
	// events relate to asset issuance proofs.
	eventReceiver := fn.NewEventReceiver[fn.Event](
		fn.DefaultQueueSize,
	)
	err := m.cfg.IssuanceSubscriptions.RegisterSubscriber(
		eventReceiver, false, true,
	)
	if err != nil {
		return fmt.Errorf("unable to register universe syncer "+
			"issuance event subscriber: %w", err)
	}

	// Ensure we remove the subscriber when we exit.
	defer func() {
		err := m.cfg.IssuanceSubscriptions.RemoveSubscriber(
			eventReceiver,
		)
		if err != nil {
			log.Errorf("unable to remove universe syncer "+
				"issuance event subscriber: %v", err)
		}
	}()

	for {
		select {
		case <-m.Quit:
			return nil

		case event := <-eventReceiver.NewItemCreated.ChanOut():
			err := m.handleUniSyncEvent(event)
			if err != nil {
				return fmt.Errorf("unable to handle "+
					"universe issuance sync event: %w", err)
			}
		}
	}
}

// Stop stops the multi state machine manager, which in turn stops all asset
// group key specific supply verifier state machines.
func (m *Manager) Stop() error {
	m.stopOnce.Do(func() {
		log.Infof("Stopping supply verifier manager")

		// Cancel the state machine context to signal all state machines
		// to stop.
		close(m.Quit)

		// Stop all state machines.
		m.smCache.StopAll()

		log.Infof("Supply verifier manager stopped")
	})

	return nil
}

// startAssetSM creates and starts a new supply commitment state machine for the
// given asset specifier. If DisableChainWatch is true, an error is returned.
func (m *Manager) startAssetSM(ctx context.Context,
	assetSpec asset.Specifier) (*StateMachine, error) {

	// If chain watching is disabled, return an error.
	if m.cfg.DisableChainWatch {
		log.Debugf("Supply verifier chain watch disabled, not "+
			"starting state machine (asset=%s)", assetSpec.String())
		return nil, fmt.Errorf("supply verifier chain watch is " +
			"disabled")
	}

	log.Infof("Starting supply verifier state machine (asset=%s)",
		assetSpec.String())

	// If the state machine is not found, create a new one.
	env := &Environment{
		AssetSpec:        assetSpec,
		AssetLog:         NewAssetLogger(assetSpec.String()),
		Chain:            m.cfg.Chain,
		SupplyCommitView: m.cfg.SupplyCommitView,
		SupplyTreeView:   m.cfg.SupplyTreeView,
		AssetLookup:      m.cfg.AssetLookup,
		Lnd:              m.cfg.Lnd,
		GroupFetcher:     m.cfg.GroupFetcher,
		SupplySyncer:     m.cfg.SupplySyncer,
		SpendSyncDelay:   DefaultSpendSyncDelay,
		ErrChan:          m.cfg.ErrChan,
		QuitChan:         m.Quit,
	}

	// Create a new error reporter for the state machine.
	errorReporter := NewErrorReporter(assetSpec)

	fsmCfg := protofsm.StateMachineCfg[Event, *Environment]{
		ErrorReporter: &errorReporter,
		InitialState:  &InitState{},
		Env:           env,
		Daemon:        m.cfg.DaemonAdapters,
	}
	newSm := protofsm.NewStateMachine[Event, *Environment](fsmCfg)

	// Ensure that the state machine is running. We use the manager's
	// context guard to derive a sub context which will be cancelled when
	// the manager is stopped.
	smCtx, _ := m.WithCtxQuitNoTimeout()
	newSm.Start(smCtx)

	// Assert that the state machine is running. Start should block until
	// the state machine is running.
	if !newSm.IsRunning() {
		return nil, fmt.Errorf("state machine unexpectadly not running")
	}

	// For supply verifier, we always start with an InitEvent to begin
	// the verification process.
	newSm.SendEvent(ctx, &InitEvent{})

	return &newSm, nil
}

// fetchStateMachine retrieves a state machine from the cache or creates a
// new one if it doesn't exist. If a new state machine is created, it is also
// started. If DisableChainWatch is true, an error is returned.
func (m *Manager) fetchStateMachine(assetSpec asset.Specifier) (*StateMachine,
	error) {

	// If chain watching is disabled, return an error.
	if m.cfg.DisableChainWatch {
		log.Debugf("Supply verifier chain watch disabled, not "+
			"fetching state machine (asset=%s)", assetSpec.String())
		return nil, fmt.Errorf("supply verifier chain watch is " +
			"disabled")
	}

	groupKey, err := assetSpec.UnwrapGroupKeyOrErr()
	if err != nil {
		return nil, fmt.Errorf("asset specifier missing group key: %w",
			err)
	}

	// Check if the state machine for the asset group already exists in the
	// cache.
	sm, ok := m.smCache.Get(*groupKey)
	if ok {
		// If the state machine is found and is running, return it.
		if sm.IsRunning() {
			return sm, nil
		}

		// If the state machine exists but is not running, replace it in
		// the cache with a new running instance.
	}

	log.Debugf("Creating new supply verifier state machine for "+
		"group: %x", groupKey.SerializeCompressed())

	ctx, cancel := m.WithCtxQuitNoTimeout()
	defer cancel()

	// Check that the asset group supports supply commitments and that
	// this node does not create supply commitments for the asset group
	// (i.e. it does not own the delegation key). We don't want to run
	// a verifier state machine for an asset group supply commitment
	// that we issue ourselves.
	err = supplycommit.CheckSupplyCommitSupport(
		ctx, m.cfg.AssetLookup, assetSpec, false,
	)
	if err != nil {
		return nil, fmt.Errorf("asset group is not suitable for "+
			"supply verifier state machine: %w", err)
	}

	newSm, err := m.startAssetSM(ctx, assetSpec)
	if err != nil {
		return nil, fmt.Errorf("unable to start state machine: %w", err)
	}

	m.smCache.Set(*groupKey, newSm)

	return newSm, nil
}

// InsertSupplyCommit stores a verified supply commitment for the given asset
// group in the node's local database.
func (m *Manager) InsertSupplyCommit(ctx context.Context,
	assetSpec asset.Specifier, commitment supplycommit.RootCommitment,
	leaves supplycommit.SupplyLeaves) error {

	log.Infof("Inserting supply commitment for asset: %s, "+
		"commitment_outpoint=%s", assetSpec.String(),
		commitment.CommitPoint().String())

	// First, we verify the supply commitment to ensure it is valid and
	// consistent with the given supply leaves.
	verifier, err := NewVerifier(
		VerifierCfg{
			AssetSpec:        assetSpec,
			ChainBridge:      m.cfg.Chain,
			AssetLookup:      m.cfg.AssetLookup,
			Lnd:              m.cfg.Lnd,
			GroupFetcher:     m.cfg.GroupFetcher,
			SupplyCommitView: m.cfg.SupplyCommitView,
			SupplyTreeView:   m.cfg.SupplyTreeView,
		},
	)
	if err != nil {
		return fmt.Errorf("unable to create supply verifier: %w", err)
	}

	err = verifier.VerifyCommit(ctx, assetSpec, commitment, leaves)
	if err != nil {
		return fmt.Errorf("supply commitment verification failed: %w",
			err)
	}

	return m.cfg.SupplyCommitView.InsertSupplyCommit(
		ctx, assetSpec, commitment, leaves,
	)
}

// SupplyCommitSnapshot packages the on-chain state of a supply commitment at a
// specific block height: the root commitment, the supply tree,
// the subtrees at that height, the new leaves since the previous commitment,
// and the chain proof that links the leaves to the root.
//
// TODO(guggero): Replace call sites that pass three separate params with
// this struct.
type SupplyCommitSnapshot struct {
	// Commitment is the root supply commitment that commits to all supply
	// leaves up to the block height recorded in CommitmentBlock.
	Commitment supplycommit.RootCommitment

	// SupplyTree is the upper supply tree as of CommitmentBlock.
	SupplyTree mssmt.Tree

	// Subtrees are the supply subtrees as of CommitmentBlock.
	Subtrees supplycommit.SupplyTrees

	// Leaves are the supply leaves added after the previous commitment's
	// block height (exclusive) and up to this commitment's block height
	// (inclusive).
	Leaves supplycommit.SupplyLeaves
}

// LocatorType is an enum that indicates the type of locator used to identify
// a supply commitment in the database.
type LocatorType uint8

const (
	// LocatorTypeOutpoint indicates that the locator type is the outpoint
	// of a supply commitment transaction output.
	LocatorTypeOutpoint LocatorType = 0

	// LocatorTypeSpentOutpoint indicates that the locator type is the
	// outpoint spent by a supply commitment transaction.
	LocatorTypeSpentOutpoint LocatorType = 1

	// LocatorTypeVeryFirst indicates that the locator type is the very
	// first supply commitment transaction output for an asset group.
	LocatorTypeVeryFirst LocatorType = 2
)

// CommitLocator is used to locate a supply commitment in the database based on
// its on-chain characteristics.
type CommitLocator struct {
	// LocatorType indicates the type of locator used to identify the
	// supply commitment.
	LocatorType LocatorType

	// Outpoint is the outpoint used to locate a supply commitment.
	// Depending on the LocatorType, this may be the outpoint created by a
	// supply commitment, the outpoint spent by a supply commitment, or an
	// empty outpoint for the very first supply commitment of an asset
	// group.
	Outpoint wire.OutPoint
}

// BlockHeightRange represents a range of block heights, inclusive of both
// start and end.
type BlockHeightRange struct {
	// Start is the starting block height of the range.
	Start uint32

	// End is the ending block height of the range.
	End uint32
}

// fetchCommitmentBlockRange returns the block height range for fetching supply
// leaves for the given commitment.
//
// The range starts from the block height of the previous commitment
// (exclusive) to the block height of the given commitment (inclusive). If
// there is no previous commitment, the range starts from block height zero.
func (m *Manager) fetchCommitmentBlockRange(ctx context.Context,
	assetSpec asset.Specifier,
	commitment supplycommit.RootCommitment) (BlockHeightRange, error) {

	var (
		zero BlockHeightRange
		view = m.cfg.SupplyCommitView
	)

	commitmentBlock, err := commitment.CommitmentBlock.UnwrapOrErr(
		supplycommit.ErrNoBlockInfo,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch commitment block: %w",
			err)
	}

	// Determine the block height range for fetching supply leaves.
	//
	// If there is no preceding commitment, the block height range starts
	// from zero.
	if commitment.SpentCommitment.IsNone() {
		heightRange := BlockHeightRange{
			Start: 0,
			End:   commitmentBlock.Height,
		}

		return heightRange, nil
	}

	// Otherwise, we need to fetch the previous commitment to determine
	// the starting block height.
	prevCommitmentOutPoint, err := commitment.SpentCommitment.UnwrapOrErr(
		fmt.Errorf("supply commitment unexpectedly has no spent " +
			"outpoint"),
	)
	if err != nil {
		return zero, err
	}

	spentCommitment, err := view.FetchCommitmentByOutpoint(
		ctx, assetSpec, prevCommitmentOutPoint,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch commitment by "+
			"outpoint: %w", err)
	}

	spentCommitmentBlock, err := spentCommitment.CommitmentBlock.
		UnwrapOrErr(supplycommit.ErrNoBlockInfo)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch spent commitment "+
			"block: %w", err)
	}

	return BlockHeightRange{
		Start: spentCommitmentBlock.Height,
		End:   commitmentBlock.Height,
	}, nil
}

// FetchCommitment fetches the commitment with the given locator from the local
// database view.
func (m *Manager) FetchCommitment(ctx context.Context,
	assetSpec asset.Specifier, locator CommitLocator) (SupplyCommitSnapshot,
	error) {

	var (
		zero SupplyCommitSnapshot
		err  error

		view       = m.cfg.SupplyCommitView
		commitment *supplycommit.RootCommitment
	)
	switch locator.LocatorType {
	case LocatorTypeOutpoint:
		commitment, err = view.FetchCommitmentByOutpoint(
			ctx, assetSpec, locator.Outpoint,
		)
		if err != nil {
			return zero, fmt.Errorf("unable to fetch commitment "+
				"by outpoint: %w", err)
		}

	case LocatorTypeSpentOutpoint:
		commitment, err = view.FetchCommitmentBySpentOutpoint(
			ctx, assetSpec, locator.Outpoint,
		)
		if err != nil {
			return zero, fmt.Errorf("unable to fetch commitment "+
				"by spent outpoint: %w", err)
		}

	case LocatorTypeVeryFirst:
		commitment, err = view.FetchStartingCommitment(ctx, assetSpec)
		if err != nil {
			return zero, fmt.Errorf("unable to fetch starting "+
				"commitment: %w", err)
		}

	default:
		return zero, fmt.Errorf("unknown supply commit locator "+
			"type: %d", locator.LocatorType)
	}

	// Fetch block height range for fetching supply leaves.
	blockHeightRange, err := m.fetchCommitmentBlockRange(
		ctx, assetSpec, *commitment,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch block height "+
			"range: %w", err)
	}

	leaves, err := m.cfg.SupplyTreeView.FetchSupplyLeavesByHeight(
		ctx, assetSpec, blockHeightRange.Start, blockHeightRange.End,
	).Unpack()
	if err != nil {
		return zero, fmt.Errorf("unable to fetch supply leaves for "+
			"asset specifier %s: %w", assetSpec.String(), err)
	}

	// Fetch supply subtrees at block height.
	subtrees, err := m.cfg.SupplyTreeView.FetchSubTrees(
		ctx, assetSpec, fn.Some(blockHeightRange.End),
	).Unpack()
	if err != nil {
		return zero, fmt.Errorf("unable to fetch supply subtrees for "+
			"asset specifier %s: %w", assetSpec.String(), err)
	}

	// Formulate supply tree at correct height from subtrees.
	bareSupplyTree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())
	supplyTree, err := supplycommit.UpdateRootSupplyTree(
		ctx, bareSupplyTree, subtrees,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to formulate supply tree "+
			"for asset specifier %s: %w", assetSpec.String(), err)
	}

	// Sanity check that the derived upper supply tree root matches the
	// commitment.
	expectedSupplyRoot, err := supplyTree.Root(ctx)
	if err != nil {
		return zero, fmt.Errorf("unable to fetch upper supply tree "+
			"root for asset specifier %s: %w",
			assetSpec.String(), err)
	}

	expectedRootHash := expectedSupplyRoot.NodeHash()
	actualRootHash := commitment.SupplyRoot.NodeHash()
	if expectedRootHash != actualRootHash {
		return zero, fmt.Errorf("supply root mismatch for asset "+
			"specifier %s: expected %s, got %s",
			assetSpec.String(), expectedRootHash, actualRootHash)
	}

	return SupplyCommitSnapshot{
		Commitment: *commitment,
		SupplyTree: supplyTree,
		Subtrees:   subtrees,
		Leaves:     leaves,
	}, nil
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
func (m *Manager) Name(assetSpec asset.Specifier) (string, error) {
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

// stateMachineCache is a thread-safe cache mapping an asset group's public key
// to its supply verifier state machine.
type stateMachineCache struct {
	// mu is a mutex that is used to synchronize access to the cache.
	mu sync.RWMutex

	// cache is a map of serialized asset group public keys to their
	// supply verifier state machines.
	cache map[asset.SerializedKey]*StateMachine
}

// newStateMachineCache creates a new supply verifier state machine cache.
func newStateMachineCache() *stateMachineCache {
	return &stateMachineCache{
		cache: make(map[asset.SerializedKey]*StateMachine),
	}
}

// StopAll stops all state machines in the cache.
func (c *stateMachineCache) StopAll() {
	if c == nil {
		return
	}

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

// Count returns the number of state machines in the cache.
func (c *stateMachineCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.cache)
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
// verifier state machine.
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
// asset group supply verifier state machine.
func (r *ErrorReporter) ReportError(err error) {
	log.Errorf("supply verifier state machine (asset_spec=%s): %v",
		r.assetSpec.String(), err)
}
