package tapgarden

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/ticker"
	"golang.org/x/exp/maps"
)

// GardenKit holds the set of shared fundamental interfaces all sub-systems of
// the tapgarden need to function.
type GardenKit struct {
	// Wallet is an active on chain wallet for the target chain.
	Wallet WalletAnchor

	// ChainBridge provides access to the chain for confirmation
	// notification, and other block related actions.
	ChainBridge ChainBridge

	// Log stores the current state of any active batch, throughout the
	// various states the planter will progress it through.
	Log MintingStore

	// TreeStore provides access to optional tapscript trees used with
	// script keys, minting output keys, and group keys.
	TreeStore asset.TapscriptTreeManager

	// KeyRing is used for obtaining internal keys for the anchor
	// transaction, as well as script keys for each asset and group keys
	// for assets created that permit ongoing emission.
	KeyRing KeyRing

	// GenSigner is used to generate signatures for the key group tweaked
	// by the genesis point when creating assets that permit on going
	// emission.
	GenSigner asset.GenesisSigner

	// GenTxBuilder is used to create virtual transactions for the group
	// witness generation process.
	GenTxBuilder asset.GenesisTxBuilder

	// TxValidator is used to validate group witnesses when creating assets
	// that support reissuance.
	TxValidator tapscript.TxValidator

	// ProofFiles stores the set of flat proof files.
	ProofFiles proof.Archiver

	// Universe is used to register new asset issuance with a local/remote
	// base universe instance.
	Universe universe.BatchRegistrar

	// ProofWatcher is used to watch new proofs for their anchor transaction
	// to be confirmed safely with a minimum number of confirmations.
	ProofWatcher proof.Watcher

	// UniversePushBatchSize is the number of minted items to push to the
	// local universe in a single batch.
	UniversePushBatchSize int
}

// PlanterConfig is the main config for the ChainPlanter.
type PlanterConfig struct {
	GardenKit

	// BatchTicker is used to notify the planter than it should assemble
	// all asset requests into a new batch.
	BatchTicker *ticker.Force

	// ProofUpdates is the storage backend for updated proofs.
	ProofUpdates proof.Archiver

	// ErrChan is the main error channel the planter will report back
	// critical errors to the main server.
	ErrChan chan<- error

	// TODO(roasbeef): something notification related?
}

// BatchKey is a type alias for a serialized public key.
type BatchKey = asset.SerializedKey

// CancelResp is the response from a caretaker attempting to cancel a batch.
type CancelResp struct {
	cancelAttempted bool
	err             error
}

type stateRequest interface {
	Resolve(any)
	Error(error)
	Return(any, error)
	Type() reqType
	Param() any
}

type stateReq[T any] struct {
	resp    chan T
	err     chan error
	reqType reqType
}

func newStateReq[T any](req reqType) *stateReq[T] {
	return &stateReq[T]{
		resp:    make(chan T, 1),
		err:     make(chan error, 1),
		reqType: req,
	}
}

type stateParamReq[T, S any] struct {
	stateReq[T]

	param S
}

// FinalizeParams are the options available to change how a batch is finalized,
// and how the genesis TX is constructed.
type FinalizeParams struct {
	FeeRate        fn.Option[chainfee.SatPerKWeight]
	SiblingTapTree fn.Option[asset.TapscriptTreeNodes]
}

// FundParams are the options available to change how a batch is funded, and how
// the genesis TX is constructed.
type FundParams struct {
	FeeRate        fn.Option[chainfee.SatPerKWeight]
	SiblingTapTree fn.Option[asset.TapscriptTreeNodes]
	// TODO(jhb): follow-up PR: accept a PSBT here
}

// groupSeal specifies the group witness for a seedling in a funded batch.
type groupSeal struct {
	GroupMember  asset.ID
	GroupWitness []wire.TxWitness
}

// SealParams change how asset groups in a minting batch are created.
type SealParams struct {
	GroupWitnesses []groupSeal
	// TODO(jhb): follow-up PR: accept a witness for the genesis point here
	// to enable script-path spends
}

func newStateParamReq[T, S any](req reqType, param S) *stateParamReq[T, S] {
	return &stateParamReq[T, S]{
		stateReq: *newStateReq[T](req),
		param:    param,
	}
}

func (s *stateReq[T]) Resolve(resp any) {
	s.resp <- resp.(T)
	close(s.err)
}

func (s *stateReq[T]) Error(err error) {
	s.err <- err
	close(s.resp)
}

func (s *stateReq[T]) Return(resp any, err error) {
	s.resp <- resp.(T)
	s.err <- err
}

func (s *stateReq[T]) Type() reqType {
	return s.reqType
}

func (s *stateReq[T]) Param() any {
	return nil
}

func (s *stateParamReq[T, S]) Param() any {
	return s.param
}

func typedParam[T any](req stateRequest) (*T, error) {
	if param, ok := req.Param().(T); ok {
		return &param, nil
	}

	return nil, fmt.Errorf("invalid type")
}

type reqType uint8

const (
	reqTypePendingBatch = iota
	reqTypeNumActiveBatches
	reqTypeListBatches
	reqTypeFinalizeBatch
	reqTypeCancelBatch
	reqTypeFundBatch
	reqTypeSealBatch
)

// ChainPlanter is responsible for accepting new incoming requests to create
// taproot assets. The planter will periodically batch those requests into a new
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
	*fn.ContextGuard
}

// NewChainPlanter creates a new ChainPlanter instance given the passed config.
func NewChainPlanter(cfg PlanterConfig) *ChainPlanter {
	return &ChainPlanter{
		cfg:               cfg,
		caretakers:        make(map[BatchKey]*BatchCaretaker),
		completionSignals: make(chan BatchKey),
		seedlingReqs:      make(chan *Seedling),
		stateReqs:         make(chan stateRequest),
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// newCaretakerForBatch creates a new BatchCaretaker for a given batch and
// inserts it into the caretaker map.
func (c *ChainPlanter) newCaretakerForBatch(batch *MintingBatch,
	feeRate *chainfee.SatPerKWeight) *BatchCaretaker {

	batchKey := asset.ToSerialized(batch.BatchKey.PubKey)
	batchConfig := &BatchCaretakerConfig{
		Batch:                 batch,
		GardenKit:             c.cfg.GardenKit,
		BroadcastCompleteChan: make(chan struct{}, 1),
		BroadcastErrChan:      make(chan error, 1),
		SignalCompletion: func() {
			c.completionSignals <- batchKey
		},
		CancelReqChan:       make(chan struct{}, 1),
		CancelRespChan:      make(chan CancelResp, 1),
		UpdateMintingProofs: c.updateMintingProofs,
		ErrChan:             c.cfg.ErrChan,
	}
	if feeRate != nil {
		batchConfig.BatchFeeRate = feeRate
	}

	caretaker := NewBatchCaretaker(batchConfig)
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
		// pending batch at a time? but would end up changing assetIDs.
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
		// completion. We'll skip batches that were cancelled.
		for _, batch := range nonFinalBatches {
			batchState := batch.State()

			if batchState == BatchStateSeedlingCancelled ||
				batchState == BatchStateSproutCancelled {

				continue
			}

			log.Infof("Launching ChainCaretaker(%x)",
				batch.BatchKey.PubKey.SerializeCompressed())

			// For batches before the actual assets have been
			// committed, we'll need to populate this field
			// manually.
			if batch.AssetMetas == nil {
				batch.AssetMetas = make(AssetMetas)
			}

			// TODO(jhb): Log manual fee rates?
			caretaker := c.newCaretakerForBatch(batch, nil)
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
			log.Warnf("Unable to stop ChainCaretaker(%x)",
				batchKey[:])
			return
		}
	}
}

// newBatch creates a new minting batch, which includes deriving a new internal
// key. The batch is not written to disk nor set as the pending batch.
func (c *ChainPlanter) newBatch() (*MintingBatch, error) {
	ctx, cancel := c.WithCtxQuit()
	defer cancel()

	// To create a new batch we'll first need to grab a new internal key,
	// which will be used in the output we create, and also will serve as
	// the primary identifier for a batch.
	log.Infof("Creating new MintingBatch")
	newInternalKey, err := c.cfg.KeyRing.DeriveNextKey(
		ctx, asset.TaprootAssetsKeyFamily,
	)
	if err != nil {
		return nil, err
	}

	currentHeight, err := c.cfg.ChainBridge.CurrentHeight(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get current height: %w", err)
	}

	// Create the new batch.
	newBatch := &MintingBatch{
		CreationTime: time.Now(),
		HeightHint:   currentHeight,
		BatchKey:     newInternalKey,
		Seedlings:    make(map[string]*Seedling),
		AssetMetas:   make(AssetMetas),
	}
	newBatch.UpdateState(BatchStatePending)
	return newBatch, nil
}

// fundGenesisPsbt generates a PSBT packet we'll use to create an asset.  In
// order to be able to create an asset, we need an initial genesis outpoint. To
// obtain this we'll ask the wallet to fund a PSBT template for GenesisAmtSats
// (all outputs need to hold some BTC to not be dust), and with a dummy script.
// We need to use a dummy script as we can't know the actual script key since
// that's dependent on the genesis outpoint.
func (c *ChainPlanter) fundGenesisPsbt(ctx context.Context,
	batchKey asset.SerializedKey,
	manualFeeRate *chainfee.SatPerKWeight) (*tapsend.FundedPsbt, error) {

	log.Infof("Attempting to fund batch: %x", batchKey)

	// Construct a 1-output TX as a template for our genesis TX, which the
	// backing wallet will fund.
	txTemplate := wire.NewMsgTx(2)
	txTemplate.AddTxOut(tapsend.CreateDummyOutput())
	genesisPkt, err := psbt.NewFromUnsignedTx(txTemplate)
	if err != nil {
		return nil, fmt.Errorf("unable to make psbt packet: %w", err)
	}

	log.Infof("creating skeleton PSBT for batch: %x", batchKey)
	log.Tracef("PSBT: %v", spew.Sdump(genesisPkt))

	var feeRate chainfee.SatPerKWeight
	switch {
	// If a fee rate was manually assigned for this batch, use that instead
	// of a fee rate estimate.
	case manualFeeRate != nil:
		feeRate = *manualFeeRate
		log.Infof("using manual fee rate for batch: %x, %s, %d sat/vB",
			batchKey[:], feeRate.String(),
			feeRate.FeePerKVByte()/1000)

	default:
		feeRate, err = c.cfg.ChainBridge.EstimateFee(
			ctx, GenesisConfTarget,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to estimate fee: %w",
				err)
		}

		log.Infof("estimated fee rate for batch: %x, %s",
			batchKey[:], feeRate.FeePerKVByte().String())
	}

	fundedGenesisPkt, err := c.cfg.Wallet.FundPsbt(
		ctx, genesisPkt, 1, feeRate,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fund psbt: %w", err)
	}

	log.Infof("Funded GenesisPacket for batch: %x", batchKey)
	log.Tracef("GenesisPacket: %v", spew.Sdump(fundedGenesisPkt))

	return fundedGenesisPkt, nil
}

// freezeMintingBatch freezes a target minting batch which means that no new
// assets can be added to the batch.
func freezeMintingBatch(ctx context.Context, batchStore MintingStore,
	batch *MintingBatch) error {

	batchKey := batch.BatchKey.PubKey

	log.Infof("Freezing MintingBatch(key=%x, num_assets=%v)",
		batchKey.SerializeCompressed(), len(batch.Seedlings))

	// In order to freeze a batch, we need to update the state of the batch
	// to BatchStateFrozen, meaning that no other changes can happen.
	//
	// TODO(roasbeef): assert not in some other state first?
	return batchStore.UpdateBatchState(
		ctx, batchKey, BatchStateFrozen,
	)
}

// ListBatches returns the single batch specified by the batch key, or the set
// of batches not yet finalized on disk.
func listBatches(ctx context.Context, batchStore MintingStore,
	batchKey *btcec.PublicKey) ([]*MintingBatch, error) {

	if batchKey == nil {
		return batchStore.FetchAllBatches(ctx)
	}

	batch, err := batchStore.FetchMintingBatch(ctx, batchKey)
	if err != nil {
		return nil, err
	}

	return []*MintingBatch{batch}, nil
}

// canCancelBatch returns a batch key if the planter is in a state where a batch
// can be cancelled. This does not account for the state of a caretaker that
// may be managing a batch.
func (c *ChainPlanter) canCancelBatch() (*btcec.PublicKey, error) {
	caretakerCount := len(c.caretakers)

	switch caretakerCount {
	case 0:
		// If there are no caretakers, the only batch we could cancel
		// would be the current pending batch.
		if c.pendingBatch == nil {
			return nil, fmt.Errorf("no pending batch")
		}

		return c.pendingBatch.BatchKey.PubKey, nil
	case 1:
		// TODO(jhb): Update once we support multiple batches.
		// If there is exactly one caretaker, our pending batch should
		// be empty. Otherwise, the batch to cancel is ambiguous.
		if c.pendingBatch != nil {
			return nil, fmt.Errorf("multiple batches not supported")
		}

		batchKeys := maps.Keys(c.caretakers)
		batchKey, err := btcec.ParsePubKey(batchKeys[0][:])
		if err != nil {
			return nil, fmt.Errorf("bad caretaker key: %w", err)
		}

		return batchKey, nil
	default:
	}

	// TODO(jhb): Update once we support multiple batches.
	return nil, fmt.Errorf("multiple caretakers not supported")
}

// cancelMintingBatch attempts to cancel a target minting batch. This can fail
// if the batch is managed by a caretaker and has already been broadcast.
func (c *ChainPlanter) cancelMintingBatch(ctx context.Context,
	batchKey *btcec.PublicKey) error {

	// The target batch may have already been assigned a caretaker. If so,
	// we need to signal to the caretaker to cancel the batch.
	batchKeySerialized := asset.ToSerialized(batchKey)
	caretaker, ok := c.caretakers[batchKeySerialized]
	if ok {
		log.Infof("Cancelling MintingBatch(key=%x, num_assets=%v)",
			batchKeySerialized, len(caretaker.cfg.Batch.Seedlings))

		caretaker.cfg.CancelReqChan <- struct{}{}

		// Wait for the caretaker to reply to the cancellation request.
		// If the request succeeded, the caretaker will update the
		// batch state on disk.
		select {
		case cancelResp := <-caretaker.cfg.CancelRespChan:
			// If the caretaker returned a batch state, then batch
			// cancellation was possible and attempted. This means
			// that the caretaker is shut down and the planter
			// must delete it.
			if cancelResp.cancelAttempted {
				delete(c.caretakers, batchKeySerialized)
			}

			return cancelResp.err

		case <-c.Quit:
			return nil
		}
	}

	log.Infof("Cancelling MintingBatch(key=%x, num_assets=%v)",
		batchKeySerialized, len(c.pendingBatch.Seedlings))

	// If the target batch was not assigned a caretaker, we only need to
	// update the batch state on disk to cancel it.
	err := c.cfg.Log.UpdateBatchState(
		ctx, batchKey, BatchStateSeedlingCancelled,
	)
	if err != nil {
		return fmt.Errorf("unable to cancel minting batch: %w", err)
	}

	return nil
}

// gardener is responsible for collecting new potential taproot asset
// seeds/seedlings into a batch to ultimately be anchored in a genesis output
// creating the assets from seedlings into sprouts, and eventually fully grown
// assets.
func (c *ChainPlanter) gardener() {
	defer c.Wg.Done()

	// When this exits due to the quit signal, we also want to stop all the
	// active caretakers as well.
	defer c.stopCaretakers()

	log.Infof("Gardener for ChainPlanter now active!")

	for {
		select {
		case <-c.cfg.BatchTicker.Ticks():
			// There is no pending batch, so we can just abort.
			if c.pendingBatch == nil {
				log.Debugf("No batches pending...doing nothing")
				continue
			}

			defaultFeeRate := fn.None[chainfee.SatPerKWeight]()
			emptyTapSibling := fn.None[asset.TapscriptTreeNodes]()

			defaultFinalizeParams := FinalizeParams{
				FeeRate:        defaultFeeRate,
				SiblingTapTree: emptyTapSibling,
			}
			_, err := c.finalizeBatch(defaultFinalizeParams)
			if err != nil {
				c.cfg.ErrChan <- fmt.Errorf("unable to freeze "+
					"minting batch: %w", err)
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
			err := c.prepAssetSeedling(ctx, req)
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
				PendingBatch: c.pendingBatch,
				NewState:     MintingStateSeed,
			}

		// A caretaker has finished processing their batch to full
		// Taproot Asset maturity. We'll clean up our local state, and
		// signal that it can exit.
		//
		// TODO(roasbeef): also need a channel to send out additional
		// notifications?
		case batchKey := <-c.completionSignals:
			caretaker, ok := c.caretakers[batchKey]
			if !ok {
				log.Warnf("Unknown caretaker: %x", batchKey[:])
				continue
			}

			log.Infof("ChainCaretaker(%x) has finished", batchKey[:])

			if err := caretaker.Stop(); err != nil {
				log.Warnf("Unable to stop caretaker: %v", err)
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

			case reqTypeListBatches:
				batchKey, err := typedParam[*btcec.PublicKey](req)
				if err != nil {
					req.Error(fmt.Errorf("bad batch key: "+
						"%w", err))
					break
				}

				ctx, cancel := c.WithCtxQuit()
				batches, err := listBatches(
					ctx, c.cfg.Log, *batchKey,
				)
				cancel()
				if err != nil {
					req.Error(err)
					break
				}

				req.Resolve(batches)

			case reqTypeFundBatch:
				log.Infof("Funding batch")

				fundReqParams, err :=
					typedParam[FundParams](req)
				if err != nil {
					req.Error(fmt.Errorf("bad fund "+
						"params: %w", err))
					break
				}

				ctx, cancel := c.WithCtxQuit()
				err = c.fundBatch(ctx, *fundReqParams)
				cancel()
				if err != nil {
					req.Error(fmt.Errorf("unable to fund "+
						"minting batch: %w", err))
					break
				}

			// TODO(jhb): follow-up PR: Implement SealBatch command
			case reqTypeSealBatch:

			case reqTypeFinalizeBatch:
				if c.pendingBatch == nil {
					req.Error(fmt.Errorf("no pending batch"))
					break
				}

				batchKey := c.pendingBatch.BatchKey.PubKey
				batchKeySerial := asset.ToSerialized(batchKey)
				log.Infof("Finalizing batch %x", batchKeySerial)

				finalizeReqParams, err :=
					typedParam[FinalizeParams](req)
				if err != nil {
					req.Error(fmt.Errorf("bad finalize "+
						"params: %w", err))
					break
				}

				caretaker, err := c.finalizeBatch(
					*finalizeReqParams,
				)
				if err != nil {
					freezeErr := fmt.Errorf("unable to "+
						"freeze minting batch: %w", err)
					c.cfg.ErrChan <- freezeErr
					req.Error(freezeErr)
					break
				}

				// We now wait for the caretaker to either
				// broadcast the batch or fail to do so.
				select {
				case <-caretaker.cfg.BroadcastCompleteChan:
					req.Resolve(caretaker.cfg.Batch)

				case err := <-caretaker.cfg.BroadcastErrChan:
					req.Error(err)
					// Unrecoverable error, stop caretaker
					// directly. The pending batch will not
					// be saved.
					stopErr := caretaker.Stop()
					if stopErr != nil {
						log.Warnf("Unable to stop "+
							"caretaker "+
							"gracefully: %v", err)
					}

					delete(c.caretakers, batchKeySerial)

				case <-c.Quit:
					return
				}

				// Now that we have a caretaker launched for
				// this batch and broadcast its minting
				// transaction, we can remove the pending batch.
				c.pendingBatch = nil

			case reqTypeCancelBatch:
				batchKey, err := c.canCancelBatch()
				if err != nil {
					req.Error(err)
					break
				}

				// Attempt to cancel the current batch, and then
				// clear the pending batch in the planter.
				ctx, cancel := c.WithCtxQuit()
				err = c.cancelMintingBatch(ctx, batchKey)
				cancel()
				c.pendingBatch = nil

				// Always return the key of the batch we tried
				// to cancel.
				req.Return(batchKey, err)
			}

		case <-c.Quit:
			return
		}
	}
}

// If funding fails should we delete the batch?
func (c *ChainPlanter) fundBatch(ctx context.Context, params FundParams) error {
	var (
		feeRate  *chainfee.SatPerKWeight
		rootHash *chainhash.Hash
		err      error
	)

	// If a tapscript tree was specified for this batch, we'll store it on
	// disk. The caretaker we start for this batch will use it when deriving
	// the final Taproot output key.
	params.FeeRate.WhenSome(func(fr chainfee.SatPerKWeight) {
		feeRate = &fr
	})
	params.SiblingTapTree.WhenSome(func(tn asset.TapscriptTreeNodes) {
		rootHash, err = c.cfg.TreeStore.
			StoreTapscriptTree(ctx, tn)
	})

	if err != nil {
		return fmt.Errorf("unable to store tapscript tree for minting "+
			"batch: %w", err)
	}

	// Update the batch by adding the sibling root hash and genesis TX.
	updateBatch := func(batch *MintingBatch) error {
		// Add the batch sibling root hash if present.
		if rootHash != nil {
			batch.tapSibling = rootHash
		}

		// Fund the batch with the specified fee rate.
		batchKey := asset.ToSerialized(batch.BatchKey.PubKey)
		batchTX, err := c.fundGenesisPsbt(ctx, batchKey, feeRate)
		if err != nil {
			return fmt.Errorf("unable to fund minting PSBT for "+
				"batch: %x %w", batchKey[:], err)
		}

		batch.GenesisPacket = batchTX

		return nil
	}

	switch {
	// If we don't have a batch, we'll create an empty batch before funding
	// and writing to disk.
	case c.pendingBatch == nil:
		newBatch, err := c.newBatch()
		if err != nil {
			return fmt.Errorf("unable to create new batch: %w", err)
		}

		err = updateBatch(newBatch)
		if err != nil {
			return err
		}

		// Now that we're done populating parts of the batch, write it
		// to disk.
		err = c.cfg.Log.CommitMintingBatch(ctx, newBatch)
		if err != nil {
			return err
		}

		c.pendingBatch = newBatch

	// If we already have a batch, we need to attach the optional sibling
	// root hash and fund the batch.
	case c.pendingBatch != nil:
		err = updateBatch(c.pendingBatch)
		if err != nil {
			return err
		}

		// Write the associated sibling root hash and TX to disk.
		if c.pendingBatch.tapSibling != nil {
			err = c.cfg.Log.CommitBatchTapSibling(
				ctx, c.pendingBatch.BatchKey.PubKey, rootHash,
			)
			if err != nil {
				return fmt.Errorf("unable to commit tapscript "+
					"sibling for minting batch %w", err)
			}
		}

		err = c.cfg.Log.CommitBatchTx(
			ctx, c.pendingBatch.BatchKey.PubKey,
			c.pendingBatch.GenesisPacket,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *ChainPlanter) sealBatch(params SealParams) error {
	return nil
}

// finalizeBatch creates a new caretaker for the batch and starts it.
func (c *ChainPlanter) finalizeBatch(params FinalizeParams) (*BatchCaretaker,
	error) {

	var (
		feeRate *chainfee.SatPerKWeight
		err     error
	)

	// Process the finalize parameters.
	params.FeeRate.WhenSome(func(fr chainfee.SatPerKWeight) {
		feeRate = &fr
	})

	ctx, cancel := c.WithCtxQuit()
	defer cancel()

	params.SiblingTapTree.WhenSome(func(tn asset.TapscriptTreeNodes) {
		_, err = c.cfg.TreeStore.
			StoreTapscriptTree(ctx, tn)
	})

	if err != nil {
		return nil, fmt.Errorf("unable to store tapscript tree for "+
			"minting batch: %w", err)
	}
	// At this point, we have a non-empty batch, so we'll first finalize it
	// on disk. This means no further seedlings can be added to this batch.
	err = freezeMintingBatch(ctx, c.cfg.Log, c.pendingBatch)
	if err != nil {
		return nil, err
	}

	// If the batch already has a funded TX, we can skip funding the batch.
	if c.pendingBatch.GenesisPacket == nil {
		fundParams := FundParams(params)

		// Fund the batch before starting the caretaker. If funding
		// fails, we can't start a caretaker for the batch, so we'll
		// clear the pending batch. The batch will exist on disk for
		// the user to recreate it if necessary.
		err = c.fundBatch(ctx, fundParams)
		if err != nil {
			c.pendingBatch = nil
			return nil, err
		}
	}

	// TODO(jhb): move batch sibling handling entirely to fundBatch, remove
	// logic around sibling storage
	// TODO(jhb): check for batch sealing

	// Now that the batch has been frozen on disk, we can update the batch
	// state to frozen before launching a new caretaker state machine for
	// the batch that'll drive all the seedlings do adulthood.
	c.pendingBatch.UpdateState(BatchStateFrozen)
	caretaker := c.newCaretakerForBatch(c.pendingBatch, feeRate)
	if err := caretaker.Start(); err != nil {
		return nil, fmt.Errorf("unable to start new caretaker: %w", err)
	}

	return caretaker, nil
}

// PendingBatch returns the current pending batch. If there's no pending batch,
// then an error is returned.
func (c *ChainPlanter) PendingBatch() (*MintingBatch, error) {
	req := newStateReq[*MintingBatch](reqTypePendingBatch)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, nil
}

// NumActiveBatches returns the total number of active batches that have an
// outstanding caretaker assigned.
func (c *ChainPlanter) NumActiveBatches() (int, error) {
	req := newStateReq[int](reqTypeNumActiveBatches)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return 0, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, nil
}

// ListBatches returns the single batch specified by the batch key, or the set
// of batches not yet finalized on disk.
func (c *ChainPlanter) ListBatches(batchKey *btcec.PublicKey) ([]*MintingBatch,
	error) {

	req := newStateParamReq[[]*MintingBatch](reqTypeListBatches, batchKey)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, <-req.err
}

// FundBatch sends a signal to the planter to fund the current batch, or create
// a funded batch.
func (c *ChainPlanter) FundBatch(params FundParams) (*MintingBatch, error) {
	req := newStateParamReq[*MintingBatch](reqTypeFundBatch, params)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, <-req.err
}

// SealBatch attempts to seal the current batch, by providing or deriving all
// witnesses necessary to create the final genesis TX.
func (c *ChainPlanter) SealBatch(params SealParams) (*MintingBatch, error) {
	req := newStateParamReq[*MintingBatch](reqTypeSealBatch, params)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, <-req.err
}

// FinalizeBatch sends a signal to the planter to finalize the current batch.
func (c *ChainPlanter) FinalizeBatch(params FinalizeParams) (*MintingBatch,
	error) {

	req := newStateParamReq[*MintingBatch](reqTypeFinalizeBatch, params)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, <-req.err
}

// CancelBatch sends a signal to the planter to cancel the current batch.
func (c *ChainPlanter) CancelBatch() (*btcec.PublicKey, error) {
	req := newStateReq[*btcec.PublicKey](reqTypeCancelBatch)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, <-req.err
}

// prepAssetSeedling performs some basic validation for the Seedling, then
// either adds it to an existing pending batch or creates a new batch for it. A
// bool indicating if a new batch should immediately be created is returned.
func (c *ChainPlanter) prepAssetSeedling(ctx context.Context,
	req *Seedling) error {

	// First, we'll perform some basic validation for the seedling.
	if err := req.validateFields(); err != nil {
		return err
	}

	// If emission is enabled and a group key is specified, we need to
	// make sure the asset types match and that we can sign with that key.
	if req.HasGroupKey() {
		groupInfo, err := c.cfg.Log.FetchGroupByGroupKey(
			ctx, &req.GroupInfo.GroupPubKey,
		)
		if err != nil {
			groupKeyBytes := req.GroupInfo.GroupPubKey.
				SerializeCompressed()
			return fmt.Errorf("group key %x not found: %w",
				groupKeyBytes, err,
			)
		}

		if err := req.validateGroupKey(*groupInfo); err != nil {
			return err
		}

		req.GroupInfo = groupInfo
	}

	// If a group anchor is specified, we need to ensure that the anchor
	// seedling is already in the batch and has emission enabled.
	if req.GroupAnchor != nil {
		if c.pendingBatch == nil {
			return fmt.Errorf("batch empty, group anchor %v "+
				"invalid", *req.GroupAnchor)
		}

		err := c.pendingBatch.validateGroupAnchor(req)
		if err != nil {
			return err
		}
	}

	if c.pendingBatch != nil {
		if _, ok := c.pendingBatch.Seedlings[req.AssetName]; ok {
			return fmt.Errorf("asset with name %v already in batch",
				req.AssetName)
		}
	}

	// Now that we've validated the seedling, we can derive a script key to
	// be used for this asset.
	scriptKey, err := c.cfg.KeyRing.DeriveNextKey(
		ctx, asset.TaprootAssetsKeyFamily,
	)
	if err != nil {
		return fmt.Errorf("unable to obtain script key for seedling: "+
			"%s %w", req.AssetName, err)
	}

	// Default to BIP86 for the script key tweaking method.
	req.ScriptKey = fn.Ptr(asset.NewScriptKeyBip86(scriptKey))

	// For group anchors, derive an internal key for the future group key.
	if req.EnableEmission {
		groupInternalKey, err := c.cfg.KeyRing.DeriveNextKey(
			ctx, asset.TaprootAssetsKeyFamily,
		)
		if err != nil {
			return fmt.Errorf("unable to obtain internal key for "+
				"group key for seedling: %s %w", req.AssetName,
				err)
		}

		req.GroupInternalKey = &groupInternalKey
	}

	// Now that we know the field are valid, we'll check to see if a batch
	// already exists.
	switch {
	// No batch, so we'll create a new one with only this seedling as part
	// of the batch.
	case c.pendingBatch == nil:
		newBatch, err := c.newBatch()
		if err != nil {
			return err
		}

		log.Infof("Adding %v to new MintingBatch", req)

		newBatch.Seedlings[req.AssetName] = req

		ctx, cancel := c.WithCtxQuit()
		defer cancel()
		err = c.cfg.Log.CommitMintingBatch(ctx, newBatch)
		if err != nil {
			return err
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
			return err
		}

		// Now that we know the seedling is ok, we'll write it to disk.
		ctx, cancel := c.WithCtxQuit()
		defer cancel()
		err := c.cfg.Log.AddSeedlingsToBatch(
			ctx, c.pendingBatch.BatchKey.PubKey, req,
		)
		if err != nil {
			return err
		}
	}

	// Now that we have the batch committed to disk, we'll return back to
	// the caller if we should finalize the batch immediately or not based
	// on its preference.
	return nil
}

// updateMintingProofs is called by the re-org watcher when it detects a re-org
// and has updated the minting proofs. This cannot be done by the caretaker
// itself, because its job is already done at the point that a re-org can happen
// (the batch is finalized after a single confirmation).
func (c *ChainPlanter) updateMintingProofs(proofs []*proof.Proof) error {
	ctx, cancel := c.WithCtxQuitNoTimeout()
	defer cancel()

	headerVerifier := GenHeaderVerifier(ctx, c.cfg.ChainBridge)
	groupVerifier := GenGroupVerifier(ctx, c.cfg.Log)
	for idx := range proofs {
		p := proofs[idx]

		err := proof.ReplaceProofInBlob(
			ctx, p, c.cfg.ProofUpdates, headerVerifier,
			proof.DefaultMerkleVerifier, groupVerifier,
		)
		if err != nil {
			return fmt.Errorf("unable to update minted proofs: %w",
				err)
		}

		// The universe ID serves to identify the universe root we want
		// to update this asset in. This is either the assetID or the
		// group key.
		uniID := universe.Identifier{
			AssetID: p.Asset.ID(),
		}
		if p.Asset.GroupKey != nil {
			uniID.GroupKey = &p.Asset.GroupKey.GroupPubKey
		}

		log.Debugf("Updating issuance proof for asset with universe, "+
			"key=%v", spew.Sdump(uniID))

		// The base key is the set of bytes that keys into the universe,
		// this'll be the outpoint where it was created at and the
		// script key for that asset.
		leafKey := universe.LeafKey{
			OutPoint: wire.OutPoint{
				Hash:  p.AnchorTx.TxHash(),
				Index: p.InclusionProof.OutputIndex,
			},
			ScriptKey: &p.Asset.ScriptKey,
		}

		// The universe leaf stores the raw proof, so we'll encode it
		// here now.
		var proofBuf bytes.Buffer
		if err := p.Encode(&proofBuf); err != nil {
			return fmt.Errorf("unable to encode proof: %w", err)
		}

		// With both of those assembled, we can now update issuance
		// which takes the amount and proof of the minting event.
		uniGen := universe.GenesisWithGroup{
			Genesis: p.Asset.Genesis,
		}
		if p.Asset.GroupKey != nil {
			uniGen.GroupKey = p.Asset.GroupKey
		}
		mintingLeaf := &universe.Leaf{
			GenesisWithGroup: uniGen,
			RawProof:         proofBuf.Bytes(),
			Amt:              p.Asset.Amount,
			Asset:            &p.Asset,
		}
		_, err = c.cfg.Universe.UpsertProofLeaf(
			ctx, uniID, leafKey, mintingLeaf,
		)
		if err != nil {
			return fmt.Errorf("unable to update issuance: %w", err)
		}
	}

	return nil
}

// QueueNewSeedling attempts to queue a new seedling request (the intent for
// New asset creation or ongoing issuance) to the ChainPlanter. A channel is
// returned where future updates will be sent over. If an error is returned no
// issuance operation was possible.
//
// NOTE: This is part of the Planter interface.
func (c *ChainPlanter) QueueNewSeedling(req *Seedling) (SeedlingUpdates, error) {
	req.updates = make(SeedlingUpdates, 1)

	// Attempt to send the new request, or exit if the quit channel
	// triggered first.
	if !fn.SendOrQuit(c.seedlingReqs, req, c.Quit) {
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
// tapgarden.Planter interface.
var _ Planter = (*ChainPlanter)(nil)
