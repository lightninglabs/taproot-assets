package universe

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taro/chanutils"
)

const (
	// DefaultTimeout is the default timeout we use for RPC and database
	// operations.
	DefaultTimeout = 30 * time.Second
)

// FederationConfig is a config that the FederationEnvoy will used to
// synchronize new updates between the current set of federated Universe nodes.
type FederationConfig struct {
	// FederationDB is used for CRUD operations related to the current set
	// of servers in the federation.
	FederationDB FederationLog

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
	LocalRegistrar Registrar

	// SyncInterval is the period that we'll use to synchronize with the
	// set of Universe servers.
	SyncInterval time.Duration

	// ErrChan is the main error channel the custodian will report back
	// critical errors to the main server.
	ErrChan chan<- error
}

// FederationPushReq is used to push out new updates to all or some members of
// the federation.
type FederationPushReq struct {
	// ID identifies the Universe tree to push this new update out to.
	ID Identifier

	// Key is the leaf key in the Universe that the new leaf should be
	// added to.
	Key BaseKey

	// Leaf is the new leaf to add.
	Leaf *MintingLeaf

	resp chan *IssuanceProof
	err  chan error
}

// FederationEnvoy is used to manage synchronization between the set of
// federated Universe servers. It handles the periodic sync between universe
// servers, and can also be used to push out new locally created proofs to the
// federation.
type FederationEnvoy struct {
	cfg FederationConfig

	*chanutils.ContextGuard

	startOnce sync.Once

	stopOnce sync.Once

	pushRequests chan *FederationPushReq
}

// NewFederationEnvoy creates a new federation envoy from the passed config.
func NewFederationEnvoy(cfg FederationConfig) *FederationEnvoy {
	return &FederationEnvoy{
		cfg:          cfg,
		pushRequests: make(chan *FederationPushReq),
		ContextGuard: &chanutils.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start launches all goroutines needed to interact with the envoy.
func (f *FederationEnvoy) Start() error {
	f.startOnce.Do(func() {
		log.Infof("Starting FederationEnvoy")

		f.Wg.Add(1)

		go f.syncer()
	})

	return nil
}

// Stop stop all active goroutines.
func (f *FederationEnvoy) Stop() error {
	f.stopOnce.Do(func() {
		log.Infof("Stopping FederationEnvoy")

		close(f.Quit)

		f.Wg.Wait()

		log.Infof("Stopped FederationEnvoy")
	})

	return nil
}

// reportErr sends a new error result back to the main error channle.
func (f *FederationEnvoy) reportErr(err error) {
	log.Errorf(err.Error())

	select {
	case f.cfg.ErrChan <- err:
	case <-f.Quit:
	}
}

// syncUniverseState attempts to sync Universe state with the targets server.
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
func (f *FederationEnvoy) pushProofToFederation(uniID Identifier,
	newProof *IssuanceProof) {

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
		len(fedServers), spew.Sdump(newProof.MintingKey))

	ctx, cancel = f.WithCtxQuitNoTimeout()
	defer cancel()

	// To push a new proof out, we'll attempt to dial to the remote
	// registrar, then will attempt to push the new proof directly to the
	// register.
	pushNewProof := func(ctx context.Context, addr ServerAddr) error {
		remoteUniverseServer, err := f.cfg.NewRemoteRegistrar(addr)
		if err != nil {
			return fmt.Errorf("unable to connect to remote "+
				"server(%v): %v", addr.HostStr(), err)
		}

		_, err = remoteUniverseServer.RegisterIssuance(
			ctx, uniID, newProof.MintingKey, newProof.Leaf,
		)
		return err
	}

	// To conclude, we'll attempt to push the new proof to all the universe
	// servers in parallel.
	err = chanutils.ParSlice(ctx, fedServers, pushNewProof)
	if err != nil {
		// TODO(roasbeef): retry in the background until successful?
		log.Errorf("unable to push proof to federation: %w", err)
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

			ctx, cancel = f.WithCtxQuitNoTimeout()

			// Sync the set of servers in parallel, waiting until
			// the syncs are finished to proceed.
			err = chanutils.ParSlice(
				ctx, fedServers, f.syncUniverseState,
			)
			if err != nil {
				cancel()

				log.Warnf("unable to sync with universe "+
					"server: %v", err)
				continue
			}

			cancel()

		// A new push request has just arrived. We'll perform a
		// asynchronous registration with the local Universe registrar,
		// then push it out in an async manner to the federation
		// members.
		case pushReq := <-f.pushRequests:
			ctx, cancel := f.WithCtxQuit()
			defer cancel()

			// First, we'll attempt to registrar the issuance with
			// the local registrar server.
			newProof, err := f.cfg.LocalRegistrar.RegisterIssuance(
				ctx, pushReq.ID, pushReq.Key, pushReq.Leaf,
			)
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
			go f.pushProofToFederation(pushReq.ID, newProof)

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
func (f *FederationEnvoy) RegisterIssuance(ctx context.Context, id Identifier,
	key BaseKey, leaf *MintingLeaf) (*IssuanceProof, error) {

	pushReq := &FederationPushReq{
		ID:   id,
		Key:  key,
		Leaf: leaf,
		resp: make(chan *IssuanceProof, 1),
		err:  make(chan error, 1),
	}

	if !chanutils.SendOrQuit(f.pushRequests, pushReq, f.Quit) {
		return nil, fmt.Errorf("unable to push new proof event")
	}

	return chanutils.RecvResp(pushReq.resp, pushReq.err, f.Quit)
}

// AddServers adds a new set of servers to the federation, then immediately
// performs a new background sync.
func (f *FederationEnvoy) AddServer(addrs ...ServerAddr) error {
	ctx, cancel := f.WithCtxQuit()
	defer cancel()

	log.Infof("Adding new Universe server to Federation, addrs=%v",
		spew.Sdump(addrs))

	if err := f.cfg.FederationDB.AddServers(ctx, addrs...); err != nil {
		return err
	}

	f.Wg.Add(1)
	go func() {
		defer f.Wg.Done()

		ctx, cancel = f.WithCtxQuitNoTimeout()
		defer cancel()

		err := chanutils.ParSlice(ctx, addrs, f.syncUniverseState)
		if err != nil {
			log.Warnf("unable to sync universe state: %w", err)
		}
	}()

	return nil
}
