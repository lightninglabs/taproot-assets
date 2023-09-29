package universe

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
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

	resp chan *Proof
	err  chan error
}

// FederationIssuanceBatchPushReq is used to push out a batch of new issuance
// events to all or some members of the federation.
type FederationIssuanceBatchPushReq struct {
	IssuanceBatch []*IssuanceItem

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

	pushRequests chan *FederationPushReq

	batchPushRequests chan *FederationIssuanceBatchPushReq
}

// NewFederationEnvoy creates a new federation envoy from the passed config.
func NewFederationEnvoy(cfg FederationConfig) *FederationEnvoy {
	return &FederationEnvoy{
		cfg:               cfg,
		pushRequests:      make(chan *FederationPushReq),
		batchPushRequests: make(chan *FederationIssuanceBatchPushReq),
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
		serverAddrs := fn.Map(addrs, func(a string) ServerAddr {
			return NewServerAddrFromStr(a)
		})

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

// reportErr sends a new error result back to the main error channel.
func (f *FederationEnvoy) reportErr(err error) {
	log.Errorf(err.Error())

	select {
	case f.cfg.ErrChan <- err:
	case <-f.Quit:
	}
}

// syncUniverseState attempts to sync Universe state with the target server.
// If the sync is successful (even if no diff is generated), then a new sync
// event will be logged.
func (f *FederationEnvoy) syncUniverseState(ctx context.Context,
	addr ServerAddr) error {

	log.Infof("Syncing Universe state with server=%v", spew.Sdump(addr))

	// Attempt to sync with the remote Universe server, if this errors then
	// we'll bail out early as something wrong happened.
	diff, err := f.cfg.UniverseSyncer.SyncUniverse(
		ctx, addr, SyncIssuance,
	)
	if err != nil {
		return err
	}

	if len(diff) == 0 {
		return nil
	}

	// If we synced anything from the server, then we'll log that here.
	log.Infof("Synced new Universe leaves from server=%v, diff=%v",
		spew.Sdump(addr), spew.Sdump(diff))

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

// pushProofToFederation attempts to push out a new proof to the current
// federation in parallel.
func (f *FederationEnvoy) pushProofToFederation(uniID Identifier, key LeafKey,
	leaf *Leaf) {

	ctx, cancel := f.WithCtxQuit()
	defer cancel()

	fedServers, err := f.cfg.FederationDB.UniverseServers(
		ctx,
	)
	if err != nil {
		err := fmt.Errorf("unable to fetch set of universe "+
			"servers: %v", err)
		f.reportErr(err)
		return
	}

	if len(fedServers) == 0 {
		return
	}

	log.Infof("Pushing new proof to %v federation members, proof_key=%v",
		len(fedServers), spew.Sdump(key))

	ctx, cancel = f.WithCtxQuitNoTimeout()
	defer cancel()

	// To push a new proof out, we'll attempt to dial to the remote
	// registrar, then will attempt to push the new proof directly to the
	// register.
	pushNewProof := func(ctx context.Context, addr ServerAddr) error {
		remoteUniverseServer, err := f.cfg.NewRemoteRegistrar(addr)
		if err != nil {
			log.Warnf("cannot push proof unable to connect "+
				"to remote server(%v): %v", addr.HostStr(),
				err)
			return nil
		}

		_, err = remoteUniverseServer.RegisterIssuance(
			ctx, uniID, key, leaf,
		)
		if err != nil {
			log.Warnf("cannot push proof to remote "+
				"server(%v): %v", addr.HostStr(), err)
		}
		return nil
	}

	// To conclude, we'll attempt to push the new proof to all the universe
	// servers in parallel.
	err = fn.ParSlice(ctx, fedServers, pushNewProof)
	if err != nil {
		// TODO(roasbeef): retry in the background until successful?
		log.Errorf("unable to push proof to federation: %v", err)
		return
	}
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
		// A new sync event has just been triggered, so we'll attempt
		// to synchronize state with all the active universe servers in
		// the federation.
		case <-syncTicker.C:
			ctx, cancel := f.WithCtxQuit()

			fedServers, err := f.cfg.FederationDB.UniverseServers(
				ctx,
			)
			if err != nil {
				cancel()

				err := fmt.Errorf("unable to fetch set of "+
					"universe servers: %v", err)
				f.reportErr(err)
				return
			}
			cancel()

			log.Infof("Synchronizing with %v federation members",
				len(fedServers))
			err = f.SyncServers(fedServers)
			if err != nil {
				log.Warnf("unable to sync with federation "+
					"server: %v", err)
				continue
			}

		// A new push request has just arrived. We'll perform a
		// asynchronous registration with the local Universe registrar,
		// then push it out in an async manner to the federation
		// members.
		case pushReq := <-f.pushRequests:
			ctx, cancel := f.WithCtxQuit()

			// First, we'll attempt to registrar the issuance with
			// the local registrar server.
			newProof, err := f.cfg.LocalRegistrar.RegisterIssuance(
				ctx, pushReq.ID, pushReq.Key, pushReq.Leaf,
			)
			cancel()
			if err != nil {
				err := fmt.Errorf("unable to insert proof "+
					"into local universe: %w", err)

				log.Warnf(err.Error())

				pushReq.err <- err
				continue
			}

			// Now that we know we were able to register the proof,
			// we'll return back to the caller, and push the new
			// proof out to the federation in the background.
			pushReq.resp <- newProof

			// With the response sent above, we'll push this out to
			// all the Universe servers in the background.
			go f.pushProofToFederation(
				pushReq.ID, pushReq.Key, pushReq.Leaf,
			)

		case pushReq := <-f.batchPushRequests:
			ctx, cancel := f.WithCtxQuitNoTimeout()

			// First, we'll attempt to registrar the issuance with
			// the local registrar server.
			err := f.cfg.LocalRegistrar.RegisterNewIssuanceBatch(
				ctx, pushReq.IssuanceBatch,
			)
			cancel()
			if err != nil {
				err := fmt.Errorf("unable to insert proof "+
					"batch into local universe: %w", err)

				log.Warnf(err.Error())

				pushReq.err <- err
				continue
			}

			// Now that we know we were able to register the proof,
			// we'll return back to the caller.
			pushReq.resp <- struct{}{}

			// With the response sent above, we'll push this out to
			// all the Universe servers in the background.
			go func() {
				for idx := range pushReq.IssuanceBatch {
					item := pushReq.IssuanceBatch[idx]
					f.pushProofToFederation(
						item.ID, item.Key, item.Leaf,
					)
				}
			}()

		case <-f.Quit:
			return
		}
	}
}

// RegisterIssuance inserts a new minting leaf within the target universe tree
// (based on the ID), stored at the base key. This can be used to first push
// out a new update to the local registrar, ultimately queuing it to also be
// sent to the set of active universe servers.
//
// NOTE: This is part of the universe.Registrar interface.
func (f *FederationEnvoy) RegisterIssuance(_ context.Context, id Identifier,
	key LeafKey, leaf *Leaf) (*Proof, error) {

	pushReq := &FederationPushReq{
		ID:   id,
		Key:  key,
		Leaf: leaf,
		resp: make(chan *Proof, 1),
		err:  make(chan error, 1),
	}

	if !fn.SendOrQuit(f.pushRequests, pushReq, f.Quit) {
		return nil, fmt.Errorf("unable to push new proof event")
	}

	return fn.RecvResp(pushReq.resp, pushReq.err, f.Quit)
}

// RegisterNewIssuanceBatch inserts a batch of new minting leaves within the
// target universe tree (based on the ID), stored at the base key(s). We assume
// the proofs within the batch have already been checked that they don't yet
// exist in the local database.
//
// NOTE: This is part of the universe.BatchRegistrar interface.
func (f *FederationEnvoy) RegisterNewIssuanceBatch(_ context.Context,
	items []*IssuanceItem) error {

	pushReq := &FederationIssuanceBatchPushReq{
		IssuanceBatch: items,
		resp:          make(chan struct{}, 1),
		err:           make(chan error, 1),
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

func (f *FederationEnvoy) SyncServers(serverAddrs []ServerAddr) error {
	// Sync servers in parallel without context timeout.
	ctx, cancel := f.WithCtxQuitNoTimeout()
	defer cancel()

	err := fn.ParSlice(ctx, serverAddrs, f.syncUniverseState)
	if err != nil {
		log.Warnf("unable to sync with server: %w", err)
	}

	return nil
}
