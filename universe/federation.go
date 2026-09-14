package universe

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
)

const (
	// DefaultTimeout is the default timeout we use for RPC and database
	// operations.
	DefaultTimeout = 30 * time.Second

	// DefaultSyncAuditInterval is the default period between the forced
	// enumeration syncs that audit the delta sync fast path. One
	// enumeration sync per server per day bounds any divergence the
	// delta path cannot observe.
	DefaultSyncAuditInterval = 24 * time.Hour
)

// FederationConfig is a config that the FederationEnvoy will use to
// synchronize new updates between the current set of federated Universe nodes.
type FederationConfig struct {
	// FederationDB is used for CRUD operations related to federation sync
	// config and tracked servers.
	FederationDB FederationDB

	// UniverseSyncer is used to synchronize with the federation
	// periodically.
	UniverseSyncer Syncer

	// NewRemoteRegistrar is a function that returns a new register instance
	// to the target remote Universe. This'll be used to optimistically push
	// out new updates to Universe servers.
	NewRemoteRegistrar func(ServerAddr) (Registrar, error)

	// LocalRegistrar is the local register. This'll be used to add new
	// leaves (minting events) to our local server before pushing them out
	// to the federation.
	LocalRegistrar BatchRegistrar

	// SyncInterval is the period that we'll use to synchronize with the
	// set of Universe servers.
	SyncInterval time.Duration

	// DisableDeltaSync forces the envoy to use full enumeration sync
	// even against servers that support cursor-based delta sync. This
	// is a kill switch for the delta sync mechanism.
	DisableDeltaSync bool

	// SyncAuditInterval is the longest the envoy will rely on
	// cursor-based delta sync against a server before forcing a full
	// enumeration sync as an audit. The audit bounds the divergence the
	// delta path cannot see: quiet-universe drift, export config
	// changes on the remote, and journal replacements the rewind check
	// was never shown. A zero value applies DefaultSyncAuditInterval.
	SyncAuditInterval time.Duration

	// ErrChan is the main error channel the custodian will report back
	// critical errors to the main server.
	ErrChan chan<- error

	// StaticFederationMembers is a set of static federation members
	// that'll be added on start up, and used to sync and push out proofs
	// with.
	StaticFederationMembers []string

	// ServerChecker is a function that can be used to check if a server is
	// operational and not the local daemon.
	ServerChecker func(ServerAddr) error
}

// FederationEnvoy is used to manage synchronization between the set of
// federated Universe servers. It handles the periodic sync between universe
// servers, and can also be used to push out new locally created proofs to the
// federation.
type FederationEnvoy struct {
	cfg FederationConfig

	*fn.ContextGuard

	startOnce sync.Once

	stopOnce sync.Once

	// pushWake wakes the dedicated federation pusher. Durable work lives in
	// the federation proof sync log, so the channel only carries a wakeup.
	pushWake chan struct{}

	// lastEnumSync tracks, per server host, when a full enumeration
	// sync last completed (or when the server was first seen), driving
	// the periodic enumeration audit.
	lastEnumSync map[string]time.Time

	// lastEnumSyncMtx guards lastEnumSync; servers sync in parallel.
	lastEnumSyncMtx sync.Mutex
}

// A compile-time check to ensure that FederationEnvoy meets the
// address.AssetSyncer interface.
var _ address.AssetSyncer = (*FederationEnvoy)(nil)

// NewFederationEnvoy creates a new federation envoy from the passed config.
func NewFederationEnvoy(cfg FederationConfig) *FederationEnvoy {
	return &FederationEnvoy{
		cfg:          cfg,
		pushWake:     make(chan struct{}, 1),
		lastEnumSync: make(map[string]time.Time),
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start launches all goroutines needed to interact with the envoy.
func (f *FederationEnvoy) Start() error {
	f.startOnce.Do(func() {
		log.Infof("Starting FederationEnvoy")

		// Before we start the main goroutine, we'll add the set of
		// static Universe servers.
		addrs := f.cfg.StaticFederationMembers
		serverAddrs := fn.Map(addrs, NewServerAddrFromStr)

		serverAddrs = fn.Filter(serverAddrs, func(a ServerAddr) bool {
			// Before we add the server as a federation member, we
			// check that we can actually connect to it and that it
			// isn't ourselves.
			if err := f.cfg.ServerChecker(a); err != nil {
				log.Warnf("Not adding server to federation: %v",
					err)

				return false
			}

			return true
		})

		err := f.AddServer(serverAddrs...)
		if err != nil {
			log.Warnf("Unable to add universe "+
				"servers: %v", err)
		}

		f.Wg.Add(2)

		go f.syncer()
		go f.pusher()

		// Replay any durable pending pushes left by a previous run.
		f.signalPusher()
	})

	return nil
}

// Close frees up any ephemeral resources allocated by the envoy.
func (f *FederationEnvoy) Close() error {
	return nil
}

// Stop stops all active goroutines.
func (f *FederationEnvoy) Stop() error {
	f.stopOnce.Do(func() {
		log.Infof("Stopping FederationEnvoy")

		close(f.Quit)

		f.Wg.Wait()

		log.Infof("Stopped FederationEnvoy")
	})

	return nil
}

// enumerationAuditDue reports whether the periodic enumeration audit
// should replace delta sync for the given server this round. The first
// call for a server starts its audit clock rather than forcing an
// immediate audit: a fresh envoy has no delta history to audit yet.
func (f *FederationEnvoy) enumerationAuditDue(host string) bool {
	interval := f.cfg.SyncAuditInterval
	if interval == 0 {
		interval = DefaultSyncAuditInterval
	}

	f.lastEnumSyncMtx.Lock()
	defer f.lastEnumSyncMtx.Unlock()

	last, ok := f.lastEnumSync[host]
	if !ok {
		f.lastEnumSync[host] = time.Now()
		return false
	}

	return time.Since(last) >= interval
}

// markEnumSync records a completed enumeration sync against the given
// server, resetting its audit clock.
func (f *FederationEnvoy) markEnumSync(host string) {
	f.lastEnumSyncMtx.Lock()
	defer f.lastEnumSyncMtx.Unlock()

	f.lastEnumSync[host] = time.Now()
}

// syncServerState attempts to sync Universe state with the target server.
// If the sync is successful (even if no diff is generated), then a new sync
// event will be logged. Cursor-based delta sync is attempted first when
// available; full enumeration sync remains the fallback for servers that
// don't support it (and the always-correct path on any delta failure), as
// well as the periodic audit that bounds any divergence the delta path
// cannot see.
func (f *FederationEnvoy) syncServerState(ctx context.Context,
	addr ServerAddr, syncConfigs SyncConfigs) error {

	log.Infof("Syncing Universe state with server=%s", addr.HostStr())

	auditDue := f.enumerationAuditDue(addr.HostStr())
	if auditDue {
		log.Infof("Enumeration sync audit due for server=%v",
			addr.HostStr())
	}

	var pendingReset fn.Option[uint64]

	deltaSyncer, canDelta := f.cfg.UniverseSyncer.(DeltaSyncer)
	if canDelta && !f.cfg.DisableDeltaSync && !auditDue {
		done, diffSize, reset, err := f.tryDeltaSync(
			ctx, deltaSyncer, addr, syncConfigs,
		)
		if err != nil {
			// The delta path is an optimization: on failure we
			// log and let the enumeration path below have a go.
			log.Warnf("Delta sync with server=%v failed, "+
				"falling back to enumeration sync: %v",
				addr.HostStr(), err)
		}
		if done {
			if diffSize > 0 {
				f.logSyncEvent(addr, diffSize)
			}

			return nil
		}

		pendingReset = reset
	}

	// Attempt to sync with the remote Universe server, if this errors then
	// we'll bail out early as something wrong happened.
	diff, err := f.cfg.UniverseSyncer.SyncUniverse(
		ctx, addr, SyncFull, syncConfigs,
	)
	if err != nil {
		return err
	}

	f.markEnumSync(addr.HostStr())

	// The enumeration pass delivered everything a cursor reset would
	// otherwise skip, so the reset is now sound to make durable. A
	// failure here leaves the cursor where it was: the next round
	// re-detects the rewind and retries.
	err = fn.MapOptionZ(pendingReset, func(tail uint64) error {
		return f.cfg.FederationDB.UpsertSyncCursor(ctx, addr, tail)
	})
	if err != nil {
		return fmt.Errorf("unable to reset sync cursor: %w", err)
	}

	if len(diff) == 0 {
		return nil
	}

	f.logSyncEvent(addr, len(diff))

	return nil
}

// tryDeltaSync runs a cursor-based delta sync against the target server,
// persisting the advanced cursor on success. It reports done=false when
// the remote doesn't support delta sync, signaling the caller to use the
// enumeration path instead.
//
// A detected journal rewind is reported rather than acted on: the
// returned option carries the cursor value to reset to, which the caller
// must only make durable once the enumeration pass it falls through to
// has completed successfully.
func (f *FederationEnvoy) tryDeltaSync(ctx context.Context,
	deltaSyncer DeltaSyncer, addr ServerAddr,
	syncConfigs SyncConfigs) (bool, int, fn.Option[uint64], error) {

	cursor, err := f.cfg.FederationDB.FetchSyncCursor(ctx, addr)
	if err != nil {
		return false, 0, fn.None[uint64](), fmt.Errorf("unable to "+
			"fetch sync cursor: %w", err)
	}

	res, err := deltaSyncer.SyncUniverseDelta(
		ctx, addr, cursor, syncConfigs,
	)
	var rewindErr *ErrJournalRewind
	switch {
	// The remote predates delta sync; the enumeration path takes over.
	case errors.Is(err, ErrDeltaUnsupported):
		log.Debugf("Server=%v does not support delta sync",
			addr.HostStr())
		return false, 0, fn.None[uint64](), nil

	// The journal our cursor pointed into no longer exists in that
	// form. Hand the caller the tail to reset to and let the
	// enumeration path reconcile: for a merely rewound journal the
	// entries at or below the tail are an append-only prefix we have
	// already consumed, and for a replaced instance the enumeration
	// pass delivers everything the reset would otherwise skip. That
	// makes the reset sound only once the pass has run, so the caller
	// commits it, not us.
	case errors.As(err, &rewindErr):
		log.Warnf("Delta sync cursor %d beyond journal tail %d "+
			"for server=%v; running enumeration sync before "+
			"resetting cursor", rewindErr.Cursor, rewindErr.Tail,
			addr.HostStr())

		return false, 0, fn.Some(rewindErr.Tail), nil

	case err != nil:
		return false, 0, fn.None[uint64](), err
	}

	// A successful run means every universe the delta touched has been
	// verified as converged, so the cursor may be persisted.
	if res.NewCursor != cursor {
		err := f.cfg.FederationDB.UpsertSyncCursor(
			ctx, addr, res.NewCursor,
		)
		if err != nil {
			return false, 0, fn.None[uint64](), fmt.Errorf(
				"unable to persist sync cursor: %w", err,
			)
		}
	}

	log.Infof("Delta sync with server=%v complete: cursor %d -> %d, "+
		"diff_size=%d", addr.HostStr(), cursor, res.NewCursor,
		len(res.Diffs))

	return true, len(res.Diffs), fn.None[uint64](), nil
}

// logSyncEvent records a successful sync with the given server in the
// background.
func (f *FederationEnvoy) logSyncEvent(addr ServerAddr, diffSize int) {
	log.Infof("Synced new Universe leaves from server=%v, diff_size=%v",
		spew.Sdump(addr), diffSize)

	// Log a new sync event in the background now that we know we were able
	// to contract the remote server.
	f.Wg.Add(1)
	go func() {
		defer f.Wg.Done()

		ctx, cancel := f.WithCtxQuit()
		defer cancel()

		err := f.cfg.FederationDB.LogNewSyncs(ctx, addr)
		if err != nil {
			log.Warnf("unable to log new sync: %v", err)
		}
	}()
}

// pushProofToServer attempts to push out a new proof to the target server.
func (f *FederationEnvoy) pushProofToServer(ctx context.Context,
	uniID Identifier, key LeafKey, leaf *Leaf, addr ServerAddr) error {

	remoteUniverseServer, err := f.cfg.NewRemoteRegistrar(addr)
	if err != nil {
		return fmt.Errorf("cannot push proof unable to connect "+
			"to remote server(%v): %w", addr.HostStr(), err)
	}

	// In the default wiring NewRemoteRegistrar hands back a wrapper
	// over a pool-owned *grpc.ClientConn, so this Close is a no-op
	// and the conn outlives the call. The defer still belongs here
	// for any alternative wiring (tests, CLI) that hands back a
	// non-pooled, single-use registrar.
	defer remoteUniverseServer.Close()

	_, err = remoteUniverseServer.UpsertProofLeaf(
		ctx, uniID, key, leaf,
	)
	if err != nil {
		return fmt.Errorf("cannot push proof to remote "+
			"server(%v): %w", addr.HostStr(), err)
	}

	return nil
}

// pushProofToServerLogged attempts to push out a new proof to the target
// server, and logs the sync attempt.
func (f *FederationEnvoy) pushProofToServerLogged(ctx context.Context,
	uniID Identifier, key LeafKey, leaf *Leaf, addr ServerAddr) error {

	// Ensure that we have a pending sync log entry for this
	// leaf and server pair. This will allow us to handle all
	// pending syncs in the event of a restart or at a different
	// point in the envoy.
	_, err := f.cfg.FederationDB.UpsertFederationProofSyncLog(
		ctx, uniID, key, addr, SyncDirectionPush,
		ProofSyncStatusPending, true,
	)
	if err != nil {
		return fmt.Errorf("unable to log proof sync as pending: %w",
			err)
	}

	// Push the proof to the remote server.
	err = f.pushProofToServer(ctx, uniID, key, leaf, addr)
	if err != nil {
		return fmt.Errorf("cannot push proof to remote server(%v): %w",
			addr.HostStr(), err)
	}

	// We did not encounter an error in our proof push
	// attempt. Log the proof sync attempt as complete.
	_, err = f.cfg.FederationDB.UpsertFederationProofSyncLog(
		ctx, uniID, key, addr, SyncDirectionPush,
		ProofSyncStatusComplete, false,
	)
	if err != nil {
		return fmt.Errorf("unable to log proof sync attempt: %w", err)
	}

	return nil
}

// pushProofToFederation attempts to push out a new proof to the current
// federation in parallel.
func (f *FederationEnvoy) pushProofToFederation(ctx context.Context,
	uniID Identifier, key LeafKey, leaf *Leaf, fedServers []ServerAddr,
	logProofSync bool) {

	log.Infof("Pushing proof to %v federation members, proof_key=%v",
		len(fedServers), spew.Sdump(key))

	// To push a new proof out, we'll attempt to dial to the remote
	// registrar, then will attempt to push the new proof directly to the
	// register.
	pushNewProof := func(ctx context.Context, addr ServerAddr) error {
		// If we are logging proof sync attempts, we will use the
		// logged version of the push function.
		if logProofSync {
			err := f.pushProofToServerLogged(
				ctx, uniID, key, leaf, addr,
			)
			if err != nil {
				log.Warnf("Cannot push proof via logged "+
					"server push: %v", err)
			}

			return nil
		}

		// If we are not logging proof sync attempts, we will use the
		// non-logged version of the push function.
		err := f.pushProofToServer(ctx, uniID, key, leaf, addr)
		if err != nil {
			log.Warnf("Cannot push proof: %v", err)
		}

		return nil
	}

	// To conclude, we'll attempt to push the new proof to all the universe
	// servers in parallel.
	err := fn.ParSlice(ctx, fedServers, pushNewProof)
	if err != nil {
		// TODO(roasbeef): retry in the background until successful?
		log.Errorf("unable to push proof to federation: %v", err)
		return
	}
}

// syncer is the main goroutine that's responsible for periodic federation
// synchronization. Remote proof pushes run in the dedicated pusher goroutine.
//
// NOTE: This function MUST be run as a goroutine.
func (f *FederationEnvoy) syncer() {
	defer f.Wg.Done()

	// TODO(roasbeef): trigger new sync on start up?

	syncTicker := time.NewTicker(f.cfg.SyncInterval)
	defer syncTicker.Stop()

	for {
		select {
		// Handle a new sync tick event.
		case <-syncTicker.C:
			log.Debug("Federation envoy handling new tick event")
			err := f.handleTickEvent()
			if err != nil {
				// Warn, but don't exit the syncer. The syncer
				// should continue to run and attempt handle
				// more events.
				log.Warnf("Unable to handle tick event: %v",
					err)
			}

		case <-f.Quit:
			return
		}
	}
}

// handleTickEvent is called each time the sync ticker fires. It will attempt
// to synchronize state with all the active universe servers in the federation.
func (f *FederationEnvoy) handleTickEvent() error {
	// Error propagation is handled in tryFetchServers, we only need to exit
	// here.
	fedServers, err := f.tryFetchServers()
	if err != nil {
		return fmt.Errorf("unable to fetch set of universe servers: "+
			"%w", err)
	}

	log.Infof("Synchronizing with %v federation members", len(fedServers))
	err = f.SyncServers(fedServers)
	if err != nil {
		return fmt.Errorf("unable to sync with federation server: %w",
			err)
	}

	// Pending federation pushes are retried by the dedicated pusher rather
	// than on this serial sync loop.
	f.signalPusher()

	return nil
}

// UpsertProofLeaf upserts a proof leaf within the target universe tree. This
// can be used to first push out a new update to the local registrar,
// ultimately queuing it to also be sent to the set of active universe servers.
//
// NOTE: This is part of the universe.Registrar interface.
func (f *FederationEnvoy) UpsertProofLeaf(ctx context.Context, id Identifier,
	key LeafKey, leaf *Leaf) (*Proof, error) {

	newProof, err := f.cfg.LocalRegistrar.UpsertProofLeaf(
		ctx, id, key, leaf,
	)
	var pendingErr error
	switch {
	case errors.Is(err, ErrMultiversePending):
		pendingErr = err
		log.Warnf("Proof stored with multiverse update pending, "+
			"proceeding with federation push (id=%v): %v",
			id.StringForLog(), err)

	case err != nil:
		return nil, fmt.Errorf("unable to insert proof into local "+
			"universe: %w", err)
	}

	item := &Item{
		ID:           id,
		Key:          key,
		Leaf:         leaf,
		LogProofSync: id.ProofType == ProofTypeIssuance,
	}
	if err := f.queueProofPushes(ctx, []*Item{item}); err != nil {
		if pendingErr != nil {
			log.Warnf("Unable to queue federation push after "+
				"multiverse-pending upsert: %v", err)
			return nil, pendingErr
		}

		return nil, err
	}

	if pendingErr != nil {
		return nil, pendingErr
	}

	return newProof, nil
}

// UpsertProofLeafBatch inserts a batch of proof leaves within the target
// universe tree. We assume the proofs within the batch have already been
// checked that they don't yet exist in the local database.
//
// NOTE: This is part of the universe.BatchRegistrar interface.
func (f *FederationEnvoy) UpsertProofLeafBatch(ctx context.Context,
	items []*Item) error {

	err := f.cfg.LocalRegistrar.UpsertProofLeafBatch(ctx, items)
	var pendingErr error
	switch {
	case errors.Is(err, ErrMultiversePending):
		pendingErr = err
		log.Warnf("Proof batch stored with multiverse updates "+
			"pending, proceeding with federation push "+
			"(num_leaves=%d): %v", len(items), err)

	case err != nil:
		return fmt.Errorf("unable to insert proof batch into local "+
			"universe: %w", err)
	}

	if err := f.queueProofPushes(ctx, items); err != nil {
		if pendingErr != nil {
			log.Warnf("Unable to queue federation push after "+
				"multiverse-pending batch upsert: %v", err)
			return pendingErr
		}

		return err
	}

	return pendingErr
}

// AddServer adds a new set of servers to the federation, then immediately
// performs a new background sync.
func (f *FederationEnvoy) AddServer(addrs ...ServerAddr) error {
	ctx, cancel := f.WithCtxQuit()
	defer cancel()

	log.Infof("Adding new Universe server to Federation, addrs=%v",
		spew.Sdump(addrs))

	if err := f.cfg.FederationDB.AddServers(ctx, addrs...); err != nil {
		return err
	}

	return f.SyncServers(addrs)
}

// QuerySyncConfigs returns the current sync configs for the federation.
func (f *FederationEnvoy) QuerySyncConfigs(
	ctx context.Context) (*SyncConfigs, error) {

	// Obtain the general and universe specific federation sync configs.
	queryFedSyncConfigs := f.cfg.FederationDB.QueryFederationSyncConfigs
	globalConfigs, uniSyncConfigs, err := queryFedSyncConfigs(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to query federation sync "+
			"config(s): %w", err)
	}

	return &SyncConfigs{
		GlobalSyncConfigs: globalConfigs,
		UniSyncConfigs:    uniSyncConfigs,
	}, nil
}

func (f *FederationEnvoy) SyncServers(serverAddrs []ServerAddr) error {
	// Sync servers in parallel without context timeout.
	ctx, cancel := f.WithCtxQuitNoTimeout()
	defer cancel()

	// Obtain the general and universe specific federation sync configs.
	syncConfigs, err := f.QuerySyncConfigs(ctx)
	if err != nil {
		return err
	}

	syncServer := func(ctx context.Context, serverAddr ServerAddr) error {
		err := f.syncServerState(ctx, serverAddr, *syncConfigs)
		if err != nil {
			log.WarnS(ctx, "Error syncing with universe", err,
				"server", serverAddr.HostStr())
		}
		return nil
	}

	err = fn.ParSlice(ctx, serverAddrs, syncServer)
	if err != nil {
		log.Warnf("unable to sync with server: %w", err)
	}

	return nil
}

// SetConfigSyncAllAssets sets the global (default) sync config to sync all
// assets.
func (f *FederationEnvoy) SetConfigSyncAllAssets() error {
	ctx, cancel := f.WithCtxQuit()
	defer cancel()

	globalSyncConfigs := []*FedGlobalSyncConfig{
		{
			ProofType:       ProofTypeIssuance,
			AllowSyncInsert: true,
			AllowSyncExport: true,
		},
		{
			ProofType:       ProofTypeTransfer,
			AllowSyncInsert: true,
			AllowSyncExport: true,
		},
	}

	return f.cfg.FederationDB.UpsertFederationSyncConfig(
		ctx, globalSyncConfigs, nil,
	)
}

// tryFetchServers attempts to fetch the set of universe servers in the
// federation.
func (f *FederationEnvoy) tryFetchServers() ([]ServerAddr, error) {
	ctx, cancel := f.WithCtxQuit()

	fedServers, err := f.cfg.FederationDB.UniverseServers(
		ctx,
	)
	if err != nil {
		log.Warnf("unable to fetch set of universe servers: %v", err)
	}
	cancel()

	return fedServers, nil
}

// SyncAssetInfo queries the universes in our federation for genesis and asset
// group information about the given asset.
func (f *FederationEnvoy) SyncAssetInfo(ctx context.Context,
	specifier asset.Specifier) error {

	uniID := Identifier{
		ProofType: ProofTypeIssuance,
	}

	// One of asset ID or group key must be set, but not both.
	if specifier.HasId() == specifier.HasGroupPubKey() {
		return fmt.Errorf("must set either asset ID or group key for " +
			"asset sync")
	}

	specifier.WhenId(func(id asset.ID) {
		uniID.AssetID = id
	})
	specifier.WhenGroupPubKey(func(groupKey btcec.PublicKey) {
		uniID.GroupKey = &groupKey
	})

	// Fetch the set of universe servers in our federation.
	fedServers, err := f.tryFetchServers()
	if err != nil {
		return err
	}

	assetConfig := FedUniSyncConfig{
		UniverseID:      uniID,
		AllowSyncInsert: true,
		AllowSyncExport: false,
	}
	fullConfig := SyncConfigs{
		UniSyncConfigs: []*FedUniSyncConfig{&assetConfig},
	}

	// We'll sync with Universe servers in parallel and collect the diffs
	// from any successful syncs. There can only be one diff per server, as
	// we're only syncing one universe root.
	returnedSyncDiffs := make(chan AssetSyncDiff, len(fedServers))

	// To fetch information about the asset, we only need to sync with the
	// remote universe. Asset group import and verification is handled as
	// part of the universe sync.
	syncFromUni := func(ctxs context.Context, addr ServerAddr) error {
		syncDiff, err := f.cfg.UniverseSyncer.SyncUniverse(
			ctxs, addr, SyncIssuance, fullConfig,
		)

		// Sync failures are expected from Universe servers that do not
		// have a relevant universe root.
		if err != nil {
			log.Warnf("Asset lookup failed: id=%v, "+
				"remote_server=%v: %v", uniID.String(),
				addr.HostStr(), err)

			// We don't want to abort syncing here, as this might
			// just be one server in our list and returning an error
			// would cause us to stop trying the other servers.
			// lint:ignore nilerr failure is expected and logged.
			return nil
		}

		// There should only be one sync diff since we're only syncing
		// one universe root.
		if syncDiff != nil {
			if len(syncDiff) != 1 {
				log.Warnf("Unexpected number of sync diffs "+
					"when looking up asset: num_diffs=%d, "+
					"id=%v, remote_server=%v",
					len(syncDiff), uniID.String(),
					addr.HostStr())

				// We don't want to abort syncing here, as this
				// might just be one server in our list and
				// returning an error would cause us to stop
				// trying the other servers.
				return nil
			}

			returnedSyncDiffs <- syncDiff[0]
		}

		return nil
	}

	// Sync with the federation Universe servers in parallel.
	err = fn.ParSlice(ctx, fedServers, syncFromUni)
	if err != nil {
		// We should never receive a non-nil error from the sync above.
		log.Errorf("unable to perform asset lookup with federation: "+
			"%v", err)
		return err
	}

	syncDiffs := fn.Collect(returnedSyncDiffs)
	log.Infof("Synced new Universe leaves for asset %v, diff_size=%v",
		uniID.String(), len(syncDiffs))

	if len(syncDiffs) == 0 {
		return fmt.Errorf("asset lookup failed for asset: %v",
			uniID.String())
	}

	return nil
}

// EnableAssetSync updates the sync config for the given asset to that we sync
// future issuance proofs.
func (f *FederationEnvoy) EnableAssetSync(ctx context.Context,
	groupInfo *asset.AssetGroup) error {

	// Construct the universe config to match the given asset.
	uniID := FedUniSyncConfig{
		UniverseID: Identifier{
			ProofType: ProofTypeIssuance,
			GroupKey:  &groupInfo.GroupKey.GroupPubKey,
		},
		AllowSyncInsert: true,
		AllowSyncExport: true,
	}

	// We know there is no existing config for this asset, so we don't need
	// to read an existing config before upserting the config above.
	return f.cfg.FederationDB.UpsertFederationSyncConfig(
		ctx, nil, []*FedUniSyncConfig{&uniID},
	)
}

// SyncConfigs is a set of configs that are used to control which universes to
// synchronize with the federation.
type SyncConfigs struct {
	// GlobalSyncConfigs are the global proof type specific configs.
	GlobalSyncConfigs []*FedGlobalSyncConfig

	// UniSyncConfigs are the universe specific configs.
	UniSyncConfigs []*FedUniSyncConfig
}

// IsSyncInsertEnabled returns true if the given universe is configured to allow
// insert (into this server) synchronization with the federation.
func (s *SyncConfigs) IsSyncInsertEnabled(id Identifier) bool {
	// Check for universe specific config. This takes precedence over the
	// global config.
	for _, cfg := range s.UniSyncConfigs {
		if cfg.UniverseID.IsEqual(id) {
			return cfg.AllowSyncInsert
		}
	}

	// Check for global config.
	for _, cfg := range s.GlobalSyncConfigs {
		if cfg.ProofType == id.ProofType {
			return cfg.AllowSyncInsert
		}
	}

	return false
}

// IsSyncExportEnabled returns true if the given universe is configured to allow
// export (from this server) synchronization with the federation.
func (s *SyncConfigs) IsSyncExportEnabled(id Identifier) bool {
	// Check for universe specific config. This takes precedence over the
	// global config.
	for _, cfg := range s.UniSyncConfigs {
		if cfg.UniverseID.IsEqual(id) {
			return cfg.AllowSyncExport
		}
	}

	// Check for global config.
	for _, cfg := range s.GlobalSyncConfigs {
		if cfg.ProofType == id.ProofType {
			return cfg.AllowSyncExport
		}
	}

	return false
}
