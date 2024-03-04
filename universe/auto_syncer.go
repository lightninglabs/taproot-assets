package universe

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
)

const (
	// DefaultTimeout is the default timeout we use for RPC and database
	// operations.
	DefaultTimeout = 30 * time.Second
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

// FederationPushReq is used to push out new updates to all or some members of
// the federation.
type FederationPushReq struct {
	// ID identifies the Universe tree to push this new update out to.
	ID Identifier

	// Key is the leaf key in the Universe that the new leaf should be
	// added to.
	Key LeafKey

	// Leaf is the new leaf to add.
	Leaf *Leaf

	// resp is a channel that will be sent the asset issuance/transfer
	// proof and corresponding universe/multiverse inclusion proofs if the
	// federation proof push was successful.
	resp chan *Proof

	// LogProofSync is a boolean that indicates, if true, that the proof
	// leaf sync attempt should be logged and actively managed to ensure
	// that the federation push procedure is repeated in the event of a
	// failure.
	LogProofSync bool

	err chan error
}

// FederationProofBatchPushReq is used to push out a batch of universe proof
// leaves to all or some members of the federation.
type FederationProofBatchPushReq struct {
	Batch []*Item

	resp chan struct{}
	err  chan error
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

	// pushRequests is a channel that will be sent new requests to push out
	// proof leaves to the federation.
	pushRequests chan *FederationPushReq

	// batchPushRequests is a channel that will be sent new requests to push
	// out batch proof leaves to the federation.
	batchPushRequests chan *FederationProofBatchPushReq
}

// A compile-time check to ensure that FederationEnvoy meets the
// address.AssetSyncer interface.
var _ address.AssetSyncer = (*FederationEnvoy)(nil)

// NewFederationEnvoy creates a new federation envoy from the passed config.
func NewFederationEnvoy(cfg FederationConfig) *FederationEnvoy {
	return &FederationEnvoy{
		cfg:               cfg,
		pushRequests:      make(chan *FederationPushReq),
		batchPushRequests: make(chan *FederationProofBatchPushReq),
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
		// On restart, we'll get an error for universe servers already
		// inserted in our DB, since we can't store duplicates.
		// We can safely ignore that error.
		if err != nil && !errors.Is(err, ErrDuplicateUniverse) {
			log.Warnf("Unable to add universe servers: %v", err)
		}

		f.Wg.Add(1)

		go f.syncer()
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

// syncServerState attempts to sync Universe state with the target server.
// If the sync is successful (even if no diff is generated), then a new sync
// event will be logged.
func (f *FederationEnvoy) syncServerState(ctx context.Context,
	addr ServerAddr, syncConfigs SyncConfigs) error {

	log.Infof("Syncing Universe state with server=%v", spew.Sdump(addr))

	// Attempt to sync with the remote Universe server, if this errors then
	// we'll bail out early as something wrong happened.
	diff, err := f.cfg.UniverseSyncer.SyncUniverse(
		ctx, addr, SyncFull, syncConfigs,
	)
	if err != nil {
		return err
	}

	if len(diff) == 0 {
		return nil
	}

	// If we synced anything from the server, then we'll log that here.
	log.Infof("Synced new Universe leaves from server=%v, diff_size=%v",
		spew.Sdump(addr), len(diff))

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

	return nil
}

// pushProofToServer attempts to push out a new proof to the target server.
func (f *FederationEnvoy) pushProofToServer(ctx context.Context,
	uniID Identifier, key LeafKey, leaf *Leaf, addr ServerAddr) error {

	remoteUniverseServer, err := f.cfg.NewRemoteRegistrar(addr)
	if err != nil {
		return fmt.Errorf("cannot push proof unable to connect "+
			"to remote server(%v): %w", addr.HostStr(), err)
	}

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

// filterProofSyncPending filters out servers that have already been synced
// with for the given leaf.
func (f *FederationEnvoy) filterProofSyncPending(fedServers []ServerAddr,
	uniID Identifier, key LeafKey) ([]ServerAddr, error) {

	// If there are no servers to filter, then we'll return early. This
	// saves from querying the database unnecessarily.
	if len(fedServers) == 0 {
		return nil, nil
	}

	ctx, cancel := f.WithCtxQuit()
	defer cancel()

	// Select all sync push complete log entries for the given universe
	// leaf. If there are any servers which are sync complete within this
	// log set, we will filter them out of our target server set.
	logs, err := f.cfg.FederationDB.QueryFederationProofSyncLog(
		ctx, uniID, key, SyncDirectionPush,
		ProofSyncStatusComplete,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to query federation sync log: %w",
			err)
	}

	// Construct a map of servers that have already been synced with for the
	// given leaf.
	syncedServers := make(map[string]struct{})
	for idx := range logs {
		logEntry := logs[idx]
		syncedServers[logEntry.ServerAddr.HostStr()] = struct{}{}
	}

	// Filter out servers that we've already pushed to.
	filteredFedServers := fn.Filter(fedServers, func(a ServerAddr) bool {
		// Filter out servers that have a log entry with sync status
		// complete.
		if _, ok := syncedServers[a.HostStr()]; ok {
			return false
		}

		// By this point we haven't found logs corresponding to the
		// given server, we will therefore return true and include the
		// server as a sync target for the given leaf.
		return true
	})

	return filteredFedServers, nil
}

// syncer is the main goroutine that's responsible for interacting with the
// federation envoy. It also accepts incoming requests to push out new updates
// to the federation.
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

		// Handle a new push request.
		case pushReq := <-f.pushRequests:
			log.Debug("Federation envoy handling push request")
			err := f.handlePushRequest(pushReq)
			if err != nil {
				// Warn, but don't exit the syncer. The syncer
				// should continue to run and attempt handle
				// more events.
				log.Warnf("Unable to handle push request: %v",
					err)
			}

		// Handle a new batch push request.
		case pushReq := <-f.batchPushRequests:
			log.Debug("Federation envoy handling batch push " +
				"request")
			err := f.handleBatchPushRequest(pushReq)
			if err != nil {
				// Warn, but don't exit the event handler
				// routine.
				log.Warnf("Unable to handle batch push "+
					"request: %v", err)
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

	// After we've synced with the federation, we'll attempt to push out any
	// pending proofs that we haven't yet completed.
	ctx, cancel := f.WithCtxQuitNoTimeout()
	defer cancel()

	syncDirection := SyncDirectionPush
	db := f.cfg.FederationDB

	logEntries, err := db.FetchPendingProofsSyncLog(
		ctx, &syncDirection,
	)
	if err != nil {
		return fmt.Errorf("unable to query pending push sync log: %w",
			err)
	}

	if len(logEntries) > 0 {
		log.Debugf("Handling pending proof sync log entries "+
			"(entries_count=%d)", len(logEntries))
	}

	// TODO(ffranr): Take account of any new servers that have been added
	//  since the last time we populated the log for a given proof leaf.
	//  Pending proof sync log entries are only relevant for the set of
	//  servers that existed at the time the log entry was created. If a new
	//  server is added, then we should create a new log entry for the new
	//  server.

	// We'll use a timeout that's slightly less than the sync interval to
	// help avoid ticking into a new sync event before the previous event
	// has finished.
	syncContextTimeout := f.cfg.SyncInterval - 1*time.Second
	if syncContextTimeout < 0 {
		// If the sync interval is less than a second, then we'll use
		// the sync interval as the timeout.
		syncContextTimeout = f.cfg.SyncInterval
	}

	for idx := range logEntries {
		entry := logEntries[idx]

		servers := []ServerAddr{
			entry.ServerAddr,
		}

		ctxPush, cancelPush := f.CtxBlockingCustomTimeout(
			syncContextTimeout,
		)
		f.pushProofToFederation(
			ctxPush, entry.UniID, entry.LeafKey, &entry.Leaf,
			servers, true,
		)
		cancelPush()
	}

	return nil
}

// handlePushRequest is called each time a new push request is received. It will
// perform an asynchronous registration with the local Universe registrar, then
// push the proof leaf out in an async manner to the federation members.
func (f *FederationEnvoy) handlePushRequest(pushReq *FederationPushReq) error {
	if pushReq == nil {
		return fmt.Errorf("nil push request")
	}

	// First, we'll attempt to registrar the proof leaf with the local
	// registrar server.
	ctx, cancel := f.WithCtxQuit()
	defer cancel()
	newProof, err := f.cfg.LocalRegistrar.UpsertProofLeaf(
		ctx, pushReq.ID, pushReq.Key, pushReq.Leaf,
	)
	if err != nil {
		err = fmt.Errorf("unable to insert proof into local "+
			"universe: %w", err)
		pushReq.err <- err
		return err
	}

	// Now that we know we were able to register the proof, we'll return
	// back to the caller, and push the new proof out to the federation in
	// the background.
	pushReq.resp <- newProof

	// Fetch all universe servers in our federation.
	fedServers, err := f.tryFetchServers()
	if err != nil {
		err = fmt.Errorf("unable to fetch federation servers: %w", err)
		pushReq.err <- err
		return err
	}

	if len(fedServers) == 0 {
		log.Warnf("could not find any federation servers")
		return nil
	}

	if pushReq.LogProofSync {
		// We are attempting to sync using the logged proof sync
		// procedure. We will therefore narrow down the set of target
		// servers based on the sync log. Only servers that are not yet
		// push sync complete will be targeted.
		fedServers, err = f.filterProofSyncPending(
			fedServers, pushReq.ID, pushReq.Key,
		)
		if err != nil {
			err = fmt.Errorf("failed to filter federation "+
				"servers: %w", err)
			pushReq.err <- err
			return err
		}
	}

	// With the response sent above, we'll push this out to all the Universe
	// servers in the background.
	ctx, cancel = f.WithCtxQuitNoTimeout()
	defer cancel()
	f.pushProofToFederation(
		ctx, pushReq.ID, pushReq.Key, pushReq.Leaf, fedServers,
		pushReq.LogProofSync,
	)

	return nil
}

// handleBatchPushRequest is called each time a new batch push request is
// received. It will perform an asynchronous registration with the local
// Universe registrar, then push each leaf from the batch out in an async manner
// to the federation members.
func (f *FederationEnvoy) handleBatchPushRequest(
	pushReq *FederationProofBatchPushReq) error {

	if pushReq == nil {
		return fmt.Errorf("nil batch push request")
	}

	ctx, cancel := f.WithCtxQuitNoTimeout()
	defer cancel()

	// First, we'll attempt to registrar the proof leaf with the local
	// registrar server.
	err := f.cfg.LocalRegistrar.UpsertProofLeafBatch(ctx, pushReq.Batch)
	if err != nil {
		err = fmt.Errorf("unable to insert proof batch into local "+
			"universe: %w", err)
		pushReq.err <- err
		return err
	}

	// Now that we know we were able to register the proof, we'll return
	// back to the caller.
	pushReq.resp <- struct{}{}

	// Fetch all universe servers in our federation.
	fedServers, err := f.tryFetchServers()
	if err != nil {
		err = fmt.Errorf("unable to fetch federation servers: %w", err)
		pushReq.err <- err
		return err
	}

	if len(fedServers) == 0 {
		log.Warnf("could not find any federation servers")
		return nil
	}

	// With the response sent above, we'll push this out to all the Universe
	// servers in the background.
	for idx := range pushReq.Batch {
		item := pushReq.Batch[idx]

		f.pushProofToFederation(
			ctx, item.ID, item.Key, item.Leaf, fedServers,
			item.LogProofSync,
		)
	}

	return nil
}

// UpsertProofLeaf upserts a proof leaf within the target universe tree. This
// can be used to first push out a new update to the local registrar,
// ultimately queuing it to also be sent to the set of active universe servers.
//
// NOTE: This is part of the universe.Registrar interface.
func (f *FederationEnvoy) UpsertProofLeaf(_ context.Context, id Identifier,
	key LeafKey, leaf *Leaf) (*Proof, error) {

	// If we're attempting to push an issuance proof, then we'll ensure
	// that we track the sync attempt to ensure that we retry in the event
	// of a failure.
	logProofSync := id.ProofType == ProofTypeIssuance

	pushReq := &FederationPushReq{
		ID:           id,
		Key:          key,
		Leaf:         leaf,
		LogProofSync: logProofSync,
		resp:         make(chan *Proof, 1),
		err:          make(chan error, 1),
	}

	if !fn.SendOrQuit(f.pushRequests, pushReq, f.Quit) {
		return nil, fmt.Errorf("unable to push new proof event")
	}

	return fn.RecvResp(pushReq.resp, pushReq.err, f.Quit)
}

// UpsertProofLeafBatch inserts a batch of proof leaves within the target
// universe tree. We assume the proofs within the batch have already been
// checked that they don't yet exist in the local database.
//
// NOTE: This is part of the universe.BatchRegistrar interface.
func (f *FederationEnvoy) UpsertProofLeafBatch(_ context.Context,
	items []*Item) error {

	pushReq := &FederationProofBatchPushReq{
		Batch: items,
		resp:  make(chan struct{}, 1),
		err:   make(chan error, 1),
	}

	if !fn.SendOrQuit(f.batchPushRequests, pushReq, f.Quit) {
		return fmt.Errorf("unable to push new proof event batch")
	}

	_, err := fn.RecvResp(pushReq.resp, pushReq.err, f.Quit)
	return err
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
			log.Warnf("encountered an error whilst syncing with "+
				"server=%v: %v", spew.Sdump(serverAddr), err)
		}
		return nil
	}

	err = fn.ParSlice(ctx, serverAddrs, syncServer)
	if err != nil {
		log.Warnf("unable to sync with server: %w", err)
	}

	return nil
}

// SetAllowPublicAccess sets the global sync config to allow public access
// for proof insert and export across all universes.
func (f *FederationEnvoy) SetAllowPublicAccess() error {
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
// group information about the given asset ID.
func (f *FederationEnvoy) SyncAssetInfo(ctx context.Context,
	assetID *asset.ID) error {

	if assetID == nil {
		return fmt.Errorf("no asset ID provided")
	}

	// Fetch the set of universe servers in our federation.
	fedServers, err := f.tryFetchServers()
	if err != nil {
		return err
	}

	assetConfig := FedUniSyncConfig{
		UniverseID: Identifier{
			AssetID:   *assetID,
			ProofType: ProofTypeIssuance,
		},
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
			log.Debugf("asset lookup for %v failed with remote"+
				"server: %v", assetID.String(), addr.HostStr())
			//lint:ignore nilerr failure is expected and logged
			return nil
		}

		// There should only be one sync diff since we're only syncing
		// one universe root.
		if syncDiff != nil {
			if len(syncDiff) != 1 {
				log.Debugf("unexpected number of sync diffs: "+
					"%v", len(syncDiff))
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
		assetID.String(), len(syncDiffs))

	// TODO(jhb): Log successful syncs?
	if len(syncDiffs) == 0 {
		return fmt.Errorf("asset lookup failed for asset: %v",
			assetID.String())
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
		if cfg.UniverseID == id {
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
		if cfg.UniverseID == id {
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
