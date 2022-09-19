package tarogarden

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightningnetwork/lnd/ticker"
)

// GardenKit holds the set of shared fundamental interfaces all sub-systems of
// the tarogarden need to function.
type GardenKit struct {
	// Wallet is an active on chain wallet for the target chain.
	Wallet WalletAnchor

	// ChainBridge provides access to the chain for confirmation
	// notification, and other block related actions.
	ChainBridge ChainBridge

	// Log stores the current state of any active batch, throughout the
	// various states the planter will progress it through.
	Log MintingStore

	// KeyRing is used for obtaining internal keys for the anchor
	// transaction, as well as script keys for each asset and family keys
	// for assets created that permit ongoing emission.
	KeyRing KeyRing

	// GenSigner is used to generate signatures for the key family tweaked
	// by the genesis point when creating assets that permit on going
	// emission.
	GenSigner asset.GenesisSigner
}

// PlanterConfig is the main config for the ChainPlanter.
type PlanterConfig struct {
	GardenKit

	// BatchTicker is used to notify the planter than it should assemble
	// all asset requests into a new batch.
	BatchTicker ticker.Ticker

	// ErrChan is the main error channel the planter will report back
	// critical errors to the main server.
	ErrChan chan<- error

	// TODO(roasbeef): something notification related?
}

// BatchKey is a type alias for a serialized public key.
type BatchKey = asset.SerializedKey

type stateRequest interface {
	Resolve(any)
	Error(error)
	Type() reqType
}

type stateReq[T any] struct {
	resp    chan T
	err     chan error
	reqType reqType
}

func (s *stateReq[T]) Resolve(resp any) {
	s.resp <- resp.(T)
}

func (s *stateReq[T]) Error(err error) {
	s.err <- err
}

func (s *stateReq[T]) Type() reqType {
	return s.reqType
}

type reqType uint8

const (
	reqTypePendingBatch = iota
	reqTypeNumActiveBatches
)

// ChainPlanter is responsible for accepting new incoming requests to create
// taro assets. The planter will periodically batch those requests into a new
// minting batch, which is handed off to a caretaker. While batches are
// progressing through maturity the planter will be responsible for sending
// notifications back to the relevant caller.
type ChainPlanter struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg PlanterConfig

	// seedlingReqs is used to accept new asset issuance requests.
	seedlingReqs chan *Seedling

	// pendingBatch is the current pending, non-frozen batch. Only one of
	// these will exist at any given time.
	pendingBatch *MintingBatch

	// caretakers maps a batch key (which is used as the internal key for
	// the transaction that mints the assets) to the caretaker that will
	// progress the batch through the final phases.
	caretakers map[BatchKey]*BatchCaretaker

	// completionSignals is a channel used to allow the caretakers to
	// signal that the batch is fully final, allowing garbage collection of
	// any relevant resources.
	completionSignals chan BatchKey

	// stateReqs is the channel that any outside requests for the state of
	// the planter will come across.
	stateReqs chan stateRequest

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*chanutils.ContextGuard
}

// NewChainPlanter creates a new ChainPlanter instance given the passed config.
func NewChainPlanter(cfg PlanterConfig) *ChainPlanter {
	return &ChainPlanter{
		cfg:               cfg,
		caretakers:        make(map[BatchKey]*BatchCaretaker),
		completionSignals: make(chan BatchKey),
		seedlingReqs:      make(chan *Seedling),
		stateReqs:         make(chan stateRequest),
		ContextGuard: &chanutils.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// newCaretakerForBatch creates a new BatchCaretaker for a given batch and
// inserts it into the caretaker map.
func (c *ChainPlanter) newCaretakerForBatch(batch *MintingBatch) *BatchCaretaker {
	batchKey := asset.ToSerialized(batch.BatchKey.PubKey)
	caretaker := NewBatchCaretaker(&BatchCaretakerConfig{
		Batch:     batch,
		GardenKit: c.cfg.GardenKit,
		SignalCompletion: func() {
			c.completionSignals <- batchKey
		},
		ErrChan: c.cfg.ErrChan,
	})
	c.caretakers[batchKey] = caretaker

	return caretaker
}

// Start starts the ChainPlanter and any goroutines it needs to carry out its
// duty.
func (c *ChainPlanter) Start() error {
	var startErr error
	c.startOnce.Do(func() {
		log.Infof("Starting ChainPlanter")

		// First, we'll read out any minting batches that aren't yet
		// fully finalized (minting transaction well confirmed on
		// chain). This includes batches that were still pending before
		// our last restart, so were never frozen in the first place.
		// The caretaker will handle progressing the batch to the
		// frozen state, and beyond.
		//
		// TODO(roasbeef): instead do RBF here? so only a single
		// pending batch at at time? but would end up changing
		// assetIDs.
		ctx, cancel := c.WithCtxQuit()
		defer cancel()
		nonFinalBatches, err := c.cfg.Log.FetchNonFinalBatches(ctx)
		if err != nil {
			startErr = err
			return
		}

		log.Infof("Retrieved %v non-finalized batches from DB",
			len(nonFinalBatches))

		// Now for each of these non-final batches, we'll make a new
		// caretaker which'll handle progressing each batch to
		// completion.
		for _, batch := range nonFinalBatches {
			log.Infof("Launching ChainCaretaker(%x)",
				batch.BatchKey.PubKey.SerializeCompressed())

			caretaker := c.newCaretakerForBatch(batch)
			if err := caretaker.Start(); err != nil {
				startErr = err
				return
			}
		}

		// With all the caretakers for each minting batch launched,
		// we'll start up the main gardener goroutine so we can accept
		// new minting requests.
		c.Wg.Add(1)
		go c.gardener()
	})

	return startErr
}

// Stop signals the ChainPlanter to halt all operations gracefully.
func (c *ChainPlanter) Stop() error {
	var stopErr error
	c.stopOnce.Do(func() {
		log.Infof("Stopping ChainPlanter")

		close(c.Quit)
		c.Wg.Wait()
	})

	return stopErr
}

// stopCaretakers attempts to gracefully stop all the active caretakers.
func (c *ChainPlanter) stopCaretakers() {
	for batchKey, caretaker := range c.caretakers {
		log.Debugf("Stopping ChainCaretaker(%x)", batchKey[:])

		if err := caretaker.Stop(); err != nil {
			// TODO(roasbeef): continue and stop the rest
			// of them?
			log.Warnf("Unable to stop ChainCaretaker(%x)", batchKey[:])
			return
		}
	}
}

// freezeMintingBatch freezes a target minting batch which means that no new
// assets can be added to the batch.
func freezeMintingBatch(ctx context.Context, pLog MintingStore,
	batch *MintingBatch) error {

	batchKey := batch.BatchKey.PubKey

	log.Infof("Freezing MintingBatch(key=%x, num_assets=%v",
		batchKey.SerializeCompressed(), len(batch.Seedlings))

	// In order to freeze a batch, we need to update the state of the batch
	// to BatchStateFinalized, meaning that no other changes can happen.
	//
	// TODO(roasbeef): assert not in some other state first?
	return pLog.UpdateBatchState(
		ctx, batchKey, BatchStateFrozen,
	)
}

// gardener is responsible for collecting new potential taro asset
// seeds/seedlings into a batch to ultimately be anchored in a genesis output
// creating the assets from seedlings into sprouts, and eventually fully grown
// assets.
func (c *ChainPlanter) gardener() {
	defer c.Wg.Done()

	// When this exits due to the quit signal, we also want to stop all the
	// active caretakers as well.
	defer c.stopCaretakers()

	log.Infof("Gardner for ChainPlanter now active!")

	// TODO(roasbeef): use top level ticker.Force instead?
	batchTicker := make(chan time.Time, 1)

	c.Wg.Add(1)
	go func() {
		defer c.Wg.Done()

		// Forward any ticks from the main ticker into this channel.
		// This lets us trigger manual ticks, but also make sure we're
		// grabbing the real set of ticks.
		select {
		case tick := <-c.cfg.BatchTicker.Ticks():

			select {
			case batchTicker <- tick:
			case <-c.Quit:
				return
			}

		case <-c.Quit:
			return
		}
	}()

	for {
		select {
		case <-batchTicker:
			// No pending batch, so we can just continue back to
			// the top of the loop.
			if c.pendingBatch == nil {
				log.Debugf("No batches pending...doing nothing")
				continue
			}

			// Prep the new care taker that'll be launched assuming
			// the call below to freeze the batch succeeds.
			caretaker := c.newCaretakerForBatch(c.pendingBatch)

			// At this point, we have a non-empty batch, so we'll
			// first finalize it on disk. This means no further
			// seedlings can be added to this batch.
			ctx, cancel := c.WithCtxQuit()
			err := freezeMintingBatch(ctx, c.cfg.Log, c.pendingBatch)
			cancel()
			if err != nil {
				c.cfg.ErrChan <- fmt.Errorf("unable to freeze "+
					"minting batch: %w", err)
				continue
			}

			// Now that the batch has been frozen, we'll launch a
			// new caretaker state machine for the batch that'll
			// drive all the seedlings do adulthood.
			if err := caretaker.Start(); err != nil {
				c.cfg.ErrChan <- fmt.Errorf("unable to start "+
					"new caretaker: %w", err)
				continue
			}

			// Now that we have a caretaker launched for this
			// batch, we'll set the pending batch to nil
			c.pendingBatch = nil

		// A request for new asset issuance just arrived, add this to
		// the pending batch and acknowledge the receipt back to the
		// caller.
		case req := <-c.seedlingReqs:
			// After some basic validation, prepare the asset
			// seedling (soon to be a sprout) by committing it to
			// disk as part of the latest batch.
			ctx, cancel := c.WithCtxQuit()
			batchNow, err := c.prepTaroSeedling(ctx, req)
			cancel()
			if err != nil {
				// Something went wrong, so then an error
				// update back to the caller.
				req.updates <- SeedlingUpdate{
					Error: err,
				}
				continue
			}

			log.Infof("Request for new seedling: %v", req)

			// Otherwise if we've got to this point then we can
			// return a response back to the caller that the
			// seedling has been added to the next batch.
			//
			// TODO(roasbeef): extend the ticker by a certain
			// portion?
			req.updates <- SeedlingUpdate{
				BatchKey: c.pendingBatch.BatchKey.PubKey,
				NewState: MintingStateSeed,
			}

			// If at this point the last request we processed
			// necessitates a new batch, then we'll force a ticker
			// instance, which'll prompt the finalization of the
			// current batch.
			if batchNow {
				log.Infof("Forcing new batch for %v", req)
				batchTicker <- time.Time{}
			}

		// A caretaker has finished processing their batch to full Taro
		// asset maturity. We'll clean up our local state, and signal
		// that it can exit.
		//
		// TODO(roasbeef): also need a channel to send out additional
		// notifications?
		case batchKey := <-c.completionSignals:
			caretaker, ok := c.caretakers[batchKey]
			if !ok {
				log.Warnf("unknown caretaker: %x", batchKey[:])
				continue
			}

			log.Infof("ChainCaretaker(%x) has finished", batchKey[:])

			if err := caretaker.Stop(); err != nil {
				log.Warnf("unable to stop care taker: %v", err)
			}

			delete(c.caretakers, batchKey)

			// TODO(roasbeef): send completion signal?

		// A new request just came along to query our internal state.
		case req := <-c.stateReqs:
			switch req.Type() {
			case reqTypePendingBatch:
				req.Resolve(c.pendingBatch)
			case reqTypeNumActiveBatches:
				req.Resolve(len(c.caretakers))
			}

		case <-c.Quit:
			return
		}
	}
}

// PendingBatch returns the current pending batch. If there's no pending batch,
// then an error is returned.
func (c *ChainPlanter) PendingBatch() (*MintingBatch, error) {
	req := &stateReq[*MintingBatch]{
		resp:    make(chan *MintingBatch, 1),
		err:     make(chan error, 1),
		reqType: reqTypePendingBatch,
	}

	if !chanutils.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, nil
}

// NumActiveBatches returns the total number of active batches that have an
// outstanding caretaker assigned.
func (c *ChainPlanter) NumActiveBatches() (int, error) {
	req := &stateReq[int]{
		resp:    make(chan int, 1),
		err:     make(chan error, 1),
		reqType: reqTypeNumActiveBatches,
	}

	if !chanutils.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return 0, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, nil
}

// prepTaroSeedling performs some basic validation for the TaroSeedling, then
// either adds it to an existing pending batch or creates a new batch for it. A
// bool indicating if a new batch should immediately be created is returned.
func (c *ChainPlanter) prepTaroSeedling(ctx context.Context,
	req *Seedling) (bool, error) {

	// First, we'll perform some basic validation for the seedling.
	if err := req.validateFields(); err != nil {
		return false, err
	}

	// Now that we know the field are valid, we'll check to see if a batch
	// already exists.
	switch {
	// No batch, so we'll create a new one with only this seedling as part
	// of the batch.
	case c.pendingBatch == nil:
		log.Infof("Creating new MintingBatch w/ %v", req)

		// To create a new batch we'll first need to grab a new
		// internal key, which'll be used in the output we create, and
		// also will serve as the primary identifier for a batch.
		newInternalKey, err := c.cfg.KeyRing.DeriveNextKey(
			ctx, TaroKeyFamily,
		)
		if err != nil {
			return false, err
		}

		// Create a new batch and commit it to disk so we can pick up
		// where we left off upon restart.
		newBatch := &MintingBatch{
			CreationTime: time.Now(),
			BatchState:   BatchStatePending,
			BatchKey:     newInternalKey,
			Seedlings: map[string]*Seedling{
				req.AssetName: req,
			},
		}
		ctx, cancel := c.WithCtxQuit()
		defer cancel()
		err = c.cfg.Log.CommitMintingBatch(ctx, newBatch)
		if err != nil {
			return false, err
		}

		c.pendingBatch = newBatch

	// A batch already exists, so we'll add this seedling to the batch,
	// committing it to disk fully before we move on.
	case c.pendingBatch != nil:
		log.Infof("Adding %v to existing MintingBatch", req)

		// First attempt to add the seedling to our pending batch, if
		// this name is already taken (in the batch), then an error
		// will be returned.
		//
		// TODO(roasbeef): unique constraint below? will trigger on the
		// name?
		if err := c.pendingBatch.addSeedling(req); err != nil {
			return false, err
		}

		// Now that we know the seedling is ok, we'll write it to disk.
		ctx, cancel := c.WithCtxQuit()
		defer cancel()
		err := c.cfg.Log.AddSeedlingsToBatch(
			ctx, c.pendingBatch.BatchKey.PubKey, req,
		)
		if err != nil {
			return false, err
		}
	}

	// Now that we have the batch committed to disk, we'll return back to
	// the caller if we should finalize the batch immediately or not based
	// on its preference.
	return req.NoBatch, nil
}

// QueueNewSeedling attempts to queue a new seedling request (the intent for
// New asset creation or on going issuance) to the ChainPlanter. A channel is
// returned where future updates will be sent over. If an error is returned no
// issuance operation was possible.
//
// NOTE: This is part of the Planter interface.
func (c *ChainPlanter) QueueNewSeedling(req *Seedling) (SeedlingUpdates, error) {
	req.updates = make(SeedlingUpdates, 1)

	// Attempt to send the new request, or exit if the quit channel
	// triggered first.
	if !chanutils.SendOrQuit(c.seedlingReqs, req, c.Quit) {
		return nil, fmt.Errorf("planter shutting down")
	}

	return req.updates, nil
}

// CancelSeedling attempts to cancel the creation of a new asset identified by
// its name. If the seedling has already progressed to a point where the
// genesis PSBT has been broadcasted, an error is returned.
//
// NOTE: This is part of the Planter interface.
func (c *ChainPlanter) CancelSeedling() error {
	// TODO(roasbeef): actually needed?
	return nil
}

// A compile-time assertion to make sure that ChainPlanter implements the
// taronursery.Planter interface.
var _ Planter = (*ChainPlanter)(nil)
