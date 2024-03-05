package tapgarden

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/neutrino/cache/lru"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"
)

var (
	// ErrGroupKeyUnknown is an error returned if an asset has a group key
	// attached that has not been previously verified.
	ErrGroupKeyUnknown = errors.New("group key not known")

	// ErrGenesisNotGroupAnchor is an error returned if an asset has a group
	// key attached, and the asset is not the anchor asset for the group.
	// This is true for any asset created via reissuance.
	ErrGenesisNotGroupAnchor = errors.New("genesis not group anchor")
)

const (
	// GenesisAmtSats is the amount of sats we'll use to anchor created
	// assets within. This value just needs to be greater than dust, as for
	// now, we assume that the tapd client manages asset bearing UTXOs
	// distinctly from normal UTXOs.
	GenesisAmtSats = btcutil.Amount(1_000)

	// GenesisConfTarget is the confirmation target we'll use to query for
	// a fee estimate.
	GenesisConfTarget = 6

	// DefaultTimeout is the default timeout we use for RPC and database
	// operations.
	DefaultTimeout = 30 * time.Second
)

// BatchCaretakerConfig houses all the items that the BatchCaretaker needs to
// carry out its duties.
type BatchCaretakerConfig struct {
	// Batch is the minting batch that this caretaker is responsible for?
	Batch *MintingBatch

	// BatchFeeRate is an optional manually-set feerate specified when
	// finalizing a batch.
	BatchFeeRate *chainfee.SatPerKWeight

	GardenKit

	// BroadcastCompleteChan is used to signal back to the caller that the
	// batch has been broadcast and is now waiting for confirmation. Either
	// this channel _or_ BroadcastErrChan is sent on, never both.
	BroadcastCompleteChan chan struct{}

	// BroadcastErrChan is used to signal back to the caller that while
	// attempting to proceed the batch to the state of broadcasting the
	// batch transaction, an error occurred. Either this channel _or_
	// BroadcastCompleteChan is sent on, never both.
	BroadcastErrChan chan error

	// SignalCompletion is used to signal back to the BatchPlanter that
	// their batch has been finalized.
	SignalCompletion func()

	// CancelChan is used by the BatchPlanter to signal that the caretaker
	// should stop advancing the batch.
	CancelReqChan chan struct{}

	// CancelRespChan is used by the BatchCaretaker to report the result of
	// attempted batch cancellation to the planter.
	CancelRespChan chan CancelResp

	// UpdateMintingProofs is used to update the minting proofs in the
	// database in case of a re-org. This cannot be done by the caretaker
	// itself, because its job is already done at the point that a re-org
	// can happen (the batch is finalized after a single confirmation).
	UpdateMintingProofs func([]*proof.Proof) error

	// ErrChan is the main error channel the caretaker will report back
	// critical errors to the main server.
	ErrChan chan<- error
}

// BatchCaretaker is the caretaker for a MintingBatch. It'll handle validating
// the batch, creating a transaction that mints all items in the batch, and
// waiting for enough confirmations for the batch to be considered finalized.
type BatchCaretaker struct {
	startOnce sync.Once
	stopOnce  sync.Once

	batchKey BatchKey

	cfg *BatchCaretakerConfig

	// confEvent is used to deliver a confirmation event to the caretaker.
	confEvent chan *chainntnfs.TxConfirmation

	// confInfo is used to store a delivered confirmation event.
	confInfo *chainntnfs.TxConfirmation

	// anchorOutputIndex is the index in the anchor output that commits to
	// the Taproot Asset commitment.
	anchorOutputIndex uint32

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewBatchCaretaker creates a new Taproot Asset caretaker based on the passed
// config.
//
// TODO(roasbeef): rename to Cultivator?
func NewBatchCaretaker(cfg *BatchCaretakerConfig) *BatchCaretaker {
	return &BatchCaretaker{
		batchKey:  asset.ToSerialized(cfg.Batch.BatchKey.PubKey),
		cfg:       cfg,
		confEvent: make(chan *chainntnfs.TxConfirmation, 1),
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start attempts to start a new batch caretaker.
func (b *BatchCaretaker) Start() error {
	var startErr error
	b.startOnce.Do(func() {
		b.Wg.Add(1)
		go b.assetCultivator()
	})
	return startErr
}

// Stop signals for a batch caretaker to gracefully exit.
func (b *BatchCaretaker) Stop() error {
	var stopErr error
	b.stopOnce.Do(func() {
		log.Infof("BatchCaretaker(%x): Stopping", b.batchKey[:])

		close(b.Quit)
		b.Wg.Wait()
	})

	return stopErr
}

// Cancel signals for a batch caretaker to stop advancing a batch. A batch can
// only be cancelled if it has not reached BatchStateBroadcast yet. If
// cancellation succeeds, we forward the batch state after cancellation. If the
// batch could not be cancelled, the planter will handle caretaker shutdown and
// batch state.
func (b *BatchCaretaker) Cancel() error {
	ctx, cancel := b.WithCtxQuit()
	defer cancel()

	batchKey := b.batchKey[:]
	batchState := b.cfg.Batch.State()
	var cancelResp CancelResp

	// This function can only be called before the caretaker state stepping
	// function, so the batch state read is the next state that has not yet
	// been executed. Seedlings are converted to asset sprouts in the Frozen
	// state, and broadcast in the Broadast state.
	log.Debugf("BatchCaretaker(%x): Trying to cancel", batchKey)
	switch batchState {
	// In the pending state, the batch seedlings have not sprouted yet.
	case BatchStatePending, BatchStateFrozen:
		err := b.cfg.Log.UpdateBatchState(
			ctx, b.cfg.Batch.BatchKey.PubKey,
			BatchStateSeedlingCancelled,
		)
		if err != nil {
			err = fmt.Errorf("BatchCaretaker(%x), batch state(%v), "+
				"cancel failed: %w", batchKey, batchState, err)
		}

		cancelResp = CancelResp{true, err}

	case BatchStateCommitted:
		err := b.cfg.Log.UpdateBatchState(
			ctx, b.cfg.Batch.BatchKey.PubKey,
			BatchStateSproutCancelled,
		)
		if err != nil {
			err = fmt.Errorf("BatchCaretaker(%x), batch state(%v), "+
				"cancel failed: %w", batchKey, batchState, err)
		}

		cancelResp = CancelResp{true, err}

	default:
		err := fmt.Errorf("BatchCaretaker(%x), batch not cancellable",
			b.cfg.Batch.BatchKey.PubKey.SerializeCompressed())
		cancelResp = CancelResp{false, err}
	}

	b.cfg.CancelRespChan <- cancelResp

	// If the batch was cancellable, the final write of the cancelled batch
	// may still have failed. That error will be handled by the planter. At
	// this point, the caretaker should shut down gracefully if cancellation
	// was attempted.
	if cancelResp.cancelAttempted {
		log.Infof("BatchCaretaker(%x), attempted batch cancellation, "+
			"shutting down", b.batchKey[:])

		return nil
	}

	// If the cancellation failed, that error will be handled by the
	// planter.
	return fmt.Errorf("BatchCaretaker(%x) cancellation failed",
		b.batchKey[:])
}

// advanceStateUntil attempts to advance the internal state machine until the
// target state has been reached.
func (b *BatchCaretaker) advanceStateUntil(currentState,
	targetState BatchState) (BatchState, error) {

	log.Infof("BatchCaretaker(%x), advancing from state=%v to state=%v",
		b.batchKey[:], currentState, targetState)

	var terminalState bool
	for !terminalState {
		// Before we attempt a state transition, make sure that we
		// aren't trying to shut down or cancel the batch.
		select {
		case <-b.Quit:
			return 0, fmt.Errorf("BatchCaretaker(%x), shutting "+
				"down", b.batchKey[:])

		// If the batch was cancellable, the finalState of the cancel
		// response will be non-nil. If the cancellation failed, that
		// error will be handled by the planter. At this point, the
		// caretaker should always shut down gracefully.
		case <-b.cfg.CancelReqChan:
			cancelErr := b.Cancel()
			if cancelErr == nil {
				return 0, fmt.Errorf("BatchCaretaker(%x), "+
					"attempted batch cancellation, "+
					"shutting down", b.batchKey[:])
			}

			log.Info(cancelErr)

		default:
		}

		nextState, err := b.stateStep(currentState)
		if err != nil {
			return 0, fmt.Errorf("unable to advance state "+
				"machine: %w", err)
		}

		// We've reached a terminal state once the next state is our
		// current state (state machine loops back to the current
		// state).
		terminalState = nextState == currentState

		currentState = nextState

		b.cfg.Batch.UpdateState(currentState)
	}

	return currentState, nil
}

// assetCultivator is the main goroutine for the BatchCaretaker struct. This
// goroutines handles progressing a batch all the way up to the point of
// broadcast. Once the batch has been broadcast, we'll register for a
// confirmation to progress the batch to the final terminal state.
func (b *BatchCaretaker) assetCultivator() {
	defer b.Wg.Done()

	currentBatchState := b.cfg.Batch.State()
	// If the batch is already marked as confirmed, then we just need to
	// advance it one more level to be finalized.
	if currentBatchState == BatchStateConfirmed {
		log.Infof("MintingBatch(%x): already confirmed!", b.batchKey[:])

		_, err := b.advanceStateUntil(
			BatchStateFinalized, BatchStateFinalized,
		)
		if err != nil {
			log.Error(err)
			return
		}

		b.cfg.SignalCompletion()
		return
	}

	// Our task as a cultivator is pretty simple: we advance our state
	// machine up until the minting transaction is broadcaster or we fail
	// for some reason. If we can broadcast, then we'll await a
	// confirmation notification, which'll let us advance to the final
	// state.
	_, err := b.advanceStateUntil(
		currentBatchState, BatchStateBroadcast,
	)
	if err != nil {
		log.Errorf("Unable to advance state machine: %v", err)
		b.cfg.BroadcastErrChan <- err
		return
	}

	// We've now broadcast the minting transaction, so we can inform the
	// caller that the synchronous part is over, and we're now entering the
	// long-running, asynchronous part.
	b.cfg.BroadcastCompleteChan <- struct{}{}

	// TODO(roasbeef): proper restart logic?

	// At this point, we've advanced all the way to broadcasting the
	// minting transaction, so we'll wait until we need to exit, or we get
	// the confirmation notification.
	//
	// TODO(roasbeef): eventually should attempt to RBF if needed?
	for {
		select {
		// We've received the confirmation notification, so we can
		// advance our state machine through the final two phases.
		case confInfo := <-b.confEvent:
			log.Infof("MintingBatch(%x): confirmed at block("+
				"hash=%v, height=%v)", b.batchKey[:],
				confInfo.BlockHash, confInfo.BlockHeight)

			b.confInfo = confInfo
			b.cfg.Batch.UpdateState(BatchStateConfirmed)
			currentBatchState = b.cfg.Batch.State()

			// TODO(roasbeef): use a "trigger" here instead?
			_, err = b.advanceStateUntil(
				currentBatchState, BatchStateFinalized,
			)
			if err != nil {
				log.Error(err)
				return
			}

			// At this point we've advanced to the final state,
			// which means we have a set of fully grown Taproot
			// assets! We'll report back to the planter out final
			// state, then exit.
			b.cfg.SignalCompletion()
			return

		case <-b.cfg.CancelReqChan:
			cancelErr := b.Cancel()
			if cancelErr == nil {
				return
			}

			log.Error(cancelErr)

		case <-b.Quit:
			return
		}
	}
}

// fundGenesisPsbt generates a PSBT packet we'll use to create an asset.  In
// order to be able to create an asset, we need an initial genesis outpoint. To
// obtain this we'll ask the wallet to fund a PSBT template for GenesisAmtSats
// (all outputs need to hold some BTC to not be dust), and with a dummy script.
// We need to use a dummy script as we can't know the actual script key since
// that's dependent on the genesis outpoint.
func (b *BatchCaretaker) fundGenesisPsbt(
	ctx context.Context) (*tapsend.FundedPsbt, error) {

	log.Infof("BatchCaretaker(%x): attempting to fund GenesisPacket",
		b.batchKey[:])

	txTemplate := wire.NewMsgTx(2)
	txTemplate.AddTxOut(tapsend.CreateDummyOutput())
	genesisPkt, err := psbt.NewFromUnsignedTx(txTemplate)
	if err != nil {
		return nil, fmt.Errorf("unable to make psbt packet: %w", err)
	}

	log.Infof("BatchCaretaker(%x): creating skeleton PSBT", b.batchKey[:])
	log.Tracef("PSBT: %v", spew.Sdump(genesisPkt))

	var feeRate chainfee.SatPerKWeight
	switch {
	// If a fee rate was manually assigned for this batch, use that instead
	// of a fee rate estimate.
	case b.cfg.BatchFeeRate != nil:
		feeRate = *b.cfg.BatchFeeRate
		log.Infof("BatchCaretaker(%x): using manual fee rate: %s, %d "+
			"sat/vB", b.batchKey[:], feeRate.String(),
			feeRate.FeePerKVByte()/1000)

	default:
		feeRate, err = b.cfg.ChainBridge.EstimateFee(
			ctx, GenesisConfTarget,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to estimate fee: %w",
				err)
		}

		log.Infof("BatchCaretaker(%x): estimated fee rate: %s",
			b.batchKey[:], feeRate.FeePerKVByte().String())
	}

	fundedGenesisPkt, err := b.cfg.Wallet.FundPsbt(
		ctx, genesisPkt, 1, feeRate,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fund psbt: %w", err)
	}

	log.Infof("BatchCaretaker(%x): funded GenesisPacket", b.batchKey[:])
	log.Tracef("GenesisPacket: %v", spew.Sdump(fundedGenesisPkt))

	return fundedGenesisPkt, nil
}

// extractGenesisOutpoint extracts the genesis point (the first output from the
// genesis transaction).
func extractGenesisOutpoint(tx *wire.MsgTx) wire.OutPoint {
	return tx.TxIn[0].PreviousOutPoint
}

// seedlingsToAssetSprouts maps a set of seedlings in the internal batch into a
// set of sprouts: Assets that aren't yet fully linked to broadcast genesis
// transaction.
func (b *BatchCaretaker) seedlingsToAssetSprouts(ctx context.Context,
	genesisPoint wire.OutPoint,
	assetOutputIndex uint32) (*commitment.TapCommitment, error) {

	log.Infof("BatchCaretaker(%x): mapping %v seedlings to asset sprouts, "+
		"with genesis_point=%v", b.batchKey[:],
		len(b.cfg.Batch.Seedlings), genesisPoint)

	newAssets := make([]*asset.Asset, 0, len(b.cfg.Batch.Seedlings))

	// Seedlings that anchor a group may be referenced by other seedlings,
	// and therefore need to be mapped to sprouts first so that we derive
	// the initial tweaked group key early.
	orderedSeedlings := SortSeedlings(maps.Values(b.cfg.Batch.Seedlings))
	newGroups := make(map[string]*asset.AssetGroup, len(orderedSeedlings))

	for _, seedlingName := range orderedSeedlings {
		seedling := b.cfg.Batch.Seedlings[seedlingName]

		assetGen := asset.Genesis{
			FirstPrevOut: genesisPoint,
			Tag:          seedling.AssetName,
			OutputIndex:  assetOutputIndex,
			Type:         seedling.AssetType,
		}

		// If the seedling has a meta data reveal set, then we'll bind
		// that by including the hash of the meta data in the asset
		// genesis.
		if seedling.Meta != nil {
			assetGen.MetaHash = seedling.Meta.MetaHash()
		}

		scriptKey, err := b.cfg.KeyRing.DeriveNextKey(
			ctx, asset.TaprootAssetsKeyFamily,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to obtain script "+
				"key: %w", err)
		}
		tweakedScriptKey := asset.NewScriptKeyBip86(scriptKey)

		var (
			amount         uint64
			groupInfo      *asset.AssetGroup
			protoAsset     *asset.Asset
			sproutGroupKey *asset.GroupKey
		)

		// Determine the amount for the actual asset.
		switch seedling.AssetType {
		case asset.Normal:
			amount = seedling.Amount
		case asset.Collectible:
			amount = 1
		}

		// If the seedling has a group key specified,
		// that group key was validated earlier. We need to
		// sign the new genesis with that group key.
		if seedling.HasGroupKey() {
			groupInfo = seedling.GroupInfo
		}

		// If the seedling has a group anchor specified, that anchor
		// was validated earlier and the corresponding group has already
		// been created. We need to look up the group key and sign
		// the asset genesis with that key.
		if seedling.GroupAnchor != nil {
			groupInfo = newGroups[*seedling.GroupAnchor]
		}

		// If a group witness needs to be produced, then we will need a
		// partially filled asset as part of the signing process.
		if groupInfo != nil || seedling.EnableEmission {
			protoAsset, err = asset.New(
				assetGen, amount, 0, 0, tweakedScriptKey, nil,
				asset.WithAssetVersion(seedling.AssetVersion),
			)
			if err != nil {
				return nil, fmt.Errorf("unable to create "+
					"asset for group key signing: %w", err)
			}
		}

		if groupInfo != nil {
			groupReq, err := asset.NewGroupKeyRequest(
				groupInfo.GroupKey.RawKey, *groupInfo.Genesis,
				protoAsset, nil,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to request "+
					"asset group membership: %w", err)
			}

			sproutGroupKey, err = asset.DeriveGroupKey(
				b.cfg.GenSigner, b.cfg.GenTxBuilder, *groupReq,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to tweak group "+
					"key: %w", err)
			}
		}

		// If emission is enabled without a group key specified,
		// then we'll need to generate another public key,
		// then use that to derive the key group signature
		// along with the tweaked key group.
		if seedling.EnableEmission {
			rawGroupKey, err := b.cfg.KeyRing.DeriveNextKey(
				ctx, asset.TaprootAssetsKeyFamily,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to derive "+
					"group key: %w", err)
			}

			groupReq, err := asset.NewGroupKeyRequest(
				rawGroupKey, assetGen, protoAsset, nil,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to request "+
					"asset group creation: %w", err)
			}

			sproutGroupKey, err = asset.DeriveGroupKey(
				b.cfg.GenSigner, b.cfg.GenTxBuilder, *groupReq,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to tweak group "+
					"key: %w", err)
			}

			newGroups[seedlingName] = &asset.AssetGroup{
				Genesis:  &assetGen,
				GroupKey: sproutGroupKey,
			}
		}

		// With the necessary keys components assembled, we'll create
		// the actual asset now.
		newAsset, err := asset.New(
			assetGen, amount, 0, 0, tweakedScriptKey,
			sproutGroupKey,
			asset.WithAssetVersion(seedling.AssetVersion),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create new asset: %w",
				err)
		}

		// Verify the group witness if present.
		if sproutGroupKey != nil {
			err := b.cfg.TxValidator.Execute(newAsset, nil, nil)
			if err != nil {
				return nil, fmt.Errorf("unable to verify "+
					"asset group witness: %w", err)
			}
		}

		newAssets = append(newAssets, newAsset)
	}

	// Now that we have all our assets created, we'll make a new
	// Taproot asset commitment, which commits to all the assets we
	// created above in a new root.
	return commitment.FromAssets(newAssets...)
}

// stateStep attempts to transition the state machine from one state to
// another. Two states are terminal: the broadcast state, and the finalized
// state.
func (b *BatchCaretaker) stateStep(currentState BatchState) (BatchState, error) {
	// TODO(roasbeef): will also handle finalizing a batch if incomplete
	// and go done w/ it?
	switch currentState {
	// If we have a batch that's still in the pending state, then the first
	// thing we need to do is finalize it.
	case BatchStatePending:
		// Finalize the batch, then move the batch state to frozen.
		ctx, cancel := b.WithCtxQuit()
		defer cancel()
		err := freezeMintingBatch(ctx, b.cfg.Log, b.cfg.Batch)
		if err != nil {
			return 0, err
		}

		log.Infof("BatchCaretaker(%x): transition states: %v -> %v",
			b.batchKey, BatchStatePending, BatchStateFrozen)

		return BatchStateFrozen, nil

	// In the frozen state, we know all the assets to create in this next
	// batch, so we'll use the batch key as the internal key for the
	// genesis transaction that'll create the batch.
	case BatchStateFrozen:
		// First, we'll fund a PSBT packet with enough coins allocated
		// as inputs to be able to create our genesis output for the
		// asset and also pay for fees.
		//
		// TODO(roasbeef): need to invalidate asset creation if on
		// restart leases are gone
		ctx, cancel := b.WithCtxQuitNoTimeout()
		defer cancel()
		genesisTxPkt, err := b.fundGenesisPsbt(ctx)
		if err != nil {
			return 0, err
		}

		genesisPoint := extractGenesisOutpoint(
			genesisTxPkt.Pkt.UnsignedTx,
		)

		// If the change output is first, then our commitment is second,
		// and vice versa.
		b.anchorOutputIndex = 0
		if genesisTxPkt.ChangeOutputIndex == 0 {
			b.anchorOutputIndex = 1
		}

		// First, we'll turn all the seedlings into actual taproot assets.
		tapCommitment, err := b.seedlingsToAssetSprouts(
			ctx, genesisPoint, b.anchorOutputIndex,
		)
		if err != nil {
			return 0, fmt.Errorf("unable to map seedlings to "+
				"sprouts: %w", err)
		}

		b.cfg.Batch.RootAssetCommitment = tapCommitment

		// Fetch the optional Tapscript sibling for this batch, and
		// convert it to a TapscriptPreimage.
		var batchSibling *commitment.TapscriptPreimage
		if b.cfg.Batch.tapSibling != nil {
			tapSibling, err := b.cfg.TreeStore.LoadTapscriptTree(
				ctx, *b.cfg.Batch.tapSibling,
			)
			if err != nil {
				return 0, err
			}

			batchSibling, err = commitment.
				NewPreimageFromTapscriptTreeNodes(*tapSibling)
			if err != nil {
				return 0, err
			}
		}

		// With the commitment Taproot Asset root SMT constructed, we'll
		// map that into the tapscript root we'll insert into the
		// genesis transaction.
		genesisScript, err := b.cfg.Batch.genesisScript(batchSibling)
		if err != nil {
			return 0, fmt.Errorf("unable to create genesis "+
				"script: %w", err)
		}

		genesisTxPkt.Pkt.UnsignedTx.TxOut[b.anchorOutputIndex].PkScript = genesisScript

		log.Infof("BatchCaretaker(%x): committing sprouts to disk",
			b.batchKey[:])

		// With all our commitments created, we'll commit them to disk,
		// replacing the existing seedlings we had created for each of
		// these assets.
		err = b.cfg.Log.AddSproutsToBatch(
			ctx, b.cfg.Batch.BatchKey.PubKey,
			genesisTxPkt, b.cfg.Batch.RootAssetCommitment,
		)
		if err != nil {
			return 0, fmt.Errorf("unable to commit batch: %w", err)
		}

		b.cfg.Batch.GenesisPacket = genesisTxPkt

		// Now that we know the script key for all the assets, we'll
		// populate the asset metas map as we need that to create the
		// asset proofs. On restart, we'll get these in the batch
		// pre-populated.
		for _, newAsset := range tapCommitment.CommittedAssets() {
			seedling, ok := b.cfg.Batch.Seedlings[newAsset.Tag]
			if !ok {
				continue
			}

			scriptKey := asset.ToSerialized(
				newAsset.ScriptKey.PubKey,
			)
			b.cfg.Batch.AssetMetas[scriptKey] = seedling.Meta
		}

		log.Infof("BatchCaretaker(%x): transition states: %v -> %v",
			b.batchKey, BatchStateFrozen, BatchStateCommitted)

		return BatchStateCommitted, nil

	// In this state, all the assets have been committed to disk along with
	// the genesis transaction which will create those assets on chain.
	// We'll have the backing wallet sign the transaction, then import the
	// resulting key into the wallet so it tracks the balance.
	case BatchStateCommitted:
		log.Infof("BatchCaretaker(%x): finalizing GenesisPacket",
			b.batchKey[:])

		// First, we'll have the wallet sign the PSBT is created, which
		// was then modified.
		//
		// TODO(roasbeef): only execute if finalized? or missing sig
		ctx, cancel := b.WithCtxQuit()
		defer cancel()
		signedPkt, err := b.cfg.Wallet.SignAndFinalizePsbt(
			ctx, b.cfg.Batch.GenesisPacket.Pkt,
		)
		if err != nil {
			return 0, fmt.Errorf("unable to sign psbt: %w", err)
		}

		// Final TX sanity check.
		signedTx, err := psbt.Extract(signedPkt)
		if err != nil {
			return 0, fmt.Errorf("unable to extract psbt: %w", err)
		}

		err = blockchain.CheckTransactionSanity(btcutil.NewTx(signedTx))
		if err != nil {
			return 0, fmt.Errorf("genesis TX failed final checks: "+
				"%w", err)
		}

		b.cfg.Batch.GenesisPacket.Pkt = signedPkt

		// Populate how much this tx paid in on-chain fees.
		chainFees, err := signedPkt.GetTxFee()
		if err != nil {
			return 0, fmt.Errorf("unable to get on-chain fees "+
				"for psbt: %w", err)
		}
		b.cfg.Batch.GenesisPacket.ChainFees = int64(chainFees)

		log.Infof("BatchCaretaker(%x): GenesisPacket finalized "+
			"(absolute_fee_sats: %d)", b.batchKey[:], chainFees)
		log.Tracef("GenesisPacket: %v", spew.Sdump(signedPkt))

		// At this point we have a fully signed PSBT packet which'll
		// create our set of assets once mined. We'll write this to
		// disk, then import the public key into the wallet. The sibling
		// here can always be nil as we'll fetch the output key computed
		// previously in BatchStateFrozen.
		//
		// TODO(roasbeef): re-run during the broadcast phase to ensure
		// it's fully imported?
		mintingOutputKey, merkleRoot, err := b.cfg.Batch.
			MintingOutputKey(nil)
		if err != nil {
			return 0, err
		}

		// To spend this output in the future, we must also commit the
		// Taproot Asset commitment root and batch tapscript sibling.
		tapCommitmentRoot := b.cfg.Batch.RootAssetCommitment.
			TapscriptRoot(nil)

		// Fetch the optional Tapscript sibling for this batch, and
		// encode it to bytes.
		var siblingBytes []byte
		if b.cfg.Batch.tapSibling != nil {
			tapSibling, err := b.cfg.TreeStore.LoadTapscriptTree(
				ctx, *b.cfg.Batch.tapSibling,
			)
			if err != nil {
				return 0, err
			}

			batchSibling, err := commitment.
				NewPreimageFromTapscriptTreeNodes(*tapSibling)
			if err != nil {
				return 0, err
			}

			siblingBytes, _, err = commitment.
				MaybeEncodeTapscriptPreimage(batchSibling)
			if err != nil {
				return 0, err
			}
		}

		err = b.cfg.Log.CommitSignedGenesisTx(
			ctx, b.cfg.Batch.BatchKey.PubKey,
			b.cfg.Batch.GenesisPacket, b.anchorOutputIndex,
			merkleRoot, tapCommitmentRoot[:], siblingBytes,
		)
		if err != nil {
			return 0, fmt.Errorf("unable to commit genesis "+
				"tx: %w", err)
		}

		// With the genesis transaction committed to disk, we'll also
		// import this public key into the backing wallet, so it
		// recognizes the de minimis amt sats under out control.
		//
		// TODO(roasbeef): should be idempotent along w/ all other
		// operations above
		ctx, cancel = b.WithCtxQuit()
		defer cancel()
		_, err = b.cfg.Wallet.ImportTaprootOutput(ctx, mintingOutputKey)
		switch {
		case err == nil:
			break

		// On restart, we'll get an error that the output has already
		// been added to the wallet, so we'll catch this now and move
		// along if so.
		case strings.Contains(err.Error(), "already exists"):
			break

		default:
			return 0, fmt.Errorf("unable to import key: %w", err)
		}

		log.Infof("BatchCaretaker(%x): transition states: %v -> %v",
			b.batchKey, BatchStateCommitted, BatchStateBroadcast)

		return BatchStateBroadcast, nil

	// In this case the genesis transaction has already been rebroadcast.
	// So we'll attempt to re-broadcast it, then wait for enough
	// confirmations to pass.
	case BatchStateBroadcast:
		// First, we'll re-extract the final signed minting transaction
		// which once broadcast and confirmed will mark the creation of
		// our assets.
		signedTx, err := psbt.Extract(b.cfg.Batch.GenesisPacket.Pkt)
		if err != nil {
			return 0, fmt.Errorf("unable to extract final "+
				"signed tx: %w", err)
		}

		log.Infof("BatchCaretaker(%x): extracted finalized GenesisTx",
			b.batchKey[:])
		log.Tracef("GenesisTx: %v", spew.Sdump(signedTx))

		// With the final transaction extracted, we'll broadcast the
		// transaction, then request a confirmation notification.
		ctx, cancel := b.WithCtxQuit()
		defer cancel()
		err = b.cfg.ChainBridge.PublishTransaction(ctx, signedTx)
		if err != nil {
			return 0, fmt.Errorf("unable to publish "+
				"transaction: %w", err)
		}

		// Now we'll wait for a confirmation as we reach our terminal
		// state that requires an on-chain event to shift from. We make
		// sure to request that the block is included as well, since we
		// need this to construct the proof files for each of the
		// assets later.
		//
		// TODO(roasbeef): eventually want to be able to RBF the bump
		heightHint := b.cfg.Batch.HeightHint
		txHash := signedTx.TxHash()
		confCtx, confCancel := b.WithCtxQuitNoTimeout()
		confNtfn, errChan, err := b.cfg.ChainBridge.RegisterConfirmationsNtfn(
			confCtx, &txHash, signedTx.TxOut[0].PkScript, 1,
			heightHint, true, nil,
		)
		if err != nil {
			return 0, fmt.Errorf("unable to register for "+
				"minting tx conf: %w", err)
		}

		// Launch a goroutine that'll notify us when the transaction
		// confirms.
		//
		// TODO(roasbeef): make blocking here?
		b.Wg.Add(1)
		go func() {
			defer confCancel()
			defer b.Wg.Done()

			var (
				confEvent *chainntnfs.TxConfirmation
				confRecv  bool
			)

			for !confRecv {
				select {
				case confEvent = <-confNtfn.Confirmed:
					confRecv = true

				case err := <-errChan:
					confErr := fmt.Errorf("error getting "+
						"confirmation: %w", err)
					log.Info(confErr)
					b.cfg.ErrChan <- confErr

					return

				case <-confCtx.Done():
					log.Debugf("Skipping TX confirmation, " +
						"context done")
					confRecv = true

				case <-b.cfg.CancelReqChan:
					cancelErr := b.Cancel()
					if cancelErr == nil {
						return
					}

					// Cancellation failed, continue to wait
					// for transaction confirmation.
					log.Info(cancelErr)

				case <-b.Quit:
					log.Debugf("Skipping TX confirmation, " +
						"exiting")
					return
				}
			}

			if confEvent == nil {
				confErr := fmt.Errorf("got empty " +
					"confirmation event in batch")
				log.Info(confErr)
				b.cfg.ErrChan <- confErr

				return
			}

			if confEvent.Tx != nil {
				log.Debugf("Got chain confirmation: %v",
					confEvent.Tx.TxHash())
			}

			for {
				select {
				case b.confEvent <- confEvent:
					return

				case <-confCtx.Done():
					log.Debugf("Skipping TX confirmation, " +
						"context done")
					return

				case <-b.cfg.CancelReqChan:
					cancelErr := b.Cancel()
					if cancelErr == nil {
						return
					}

					// Cancellation failed, continue to try
					// and send the confirmation event.
					log.Info(cancelErr)

				case <-b.Quit:
					log.Debugf("Skipping TX confirmation, " +
						"exiting")
					return
				}
			}
		}()

		log.Infof("BatchCaretaker(%x): transition states: %v -> %v",
			b.batchKey, BatchStateBroadcast, BatchStateBroadcast)

		return BatchStateBroadcast, nil

	// In this state, we know that the minting transaction has confirmed on
	// chain, so we'll need to commit the exact confirmation location to the
	// log.
	case BatchStateConfirmed:
		confInfo := b.confInfo
		ctx, cancel := b.WithCtxQuitNoTimeout()
		defer cancel()

		headerVerifier := GenHeaderVerifier(ctx, b.cfg.ChainBridge)
		merkleVerifier := proof.DefaultMerkleVerifier
		groupVerifier := GenGroupVerifier(ctx, b.cfg.Log)
		groupAnchorVerifier := GenGroupAnchorVerifier(ctx, b.cfg.Log)

		// Fetch the optional tapscript sibling for this batch, which
		// is needed to construct valid inclusion proofs.
		var batchSibling *commitment.TapscriptPreimage
		if b.cfg.Batch.tapSibling != nil {
			tapSibling, err := b.cfg.TreeStore.LoadTapscriptTree(
				ctx, *b.cfg.Batch.tapSibling,
			)
			if err != nil {
				return 0, err
			}

			batchSibling, err = commitment.
				NewPreimageFromTapscriptTreeNodes(*tapSibling)
			if err != nil {
				return 0, err
			}
		}

		// Now that the minting transaction has been confirmed, we'll
		// need to create the series of proof file blobs for each of
		// the assets. In case the lnd wallet creates a P2TR change
		// output we need to create an exclusion proof for it (and for
		// all other P2TR outputs, we just assume BIP-0086 here).
		batchCommitment := b.cfg.Batch.RootAssetCommitment
		baseProof := &proof.MintParams{
			BaseProofParams: proof.BaseProofParams{
				Block:            confInfo.Block,
				BlockHeight:      confInfo.BlockHeight,
				Tx:               confInfo.Tx,
				TxIndex:          int(confInfo.TxIndex),
				OutputIndex:      int(b.anchorOutputIndex),
				InternalKey:      b.cfg.Batch.BatchKey.PubKey,
				TapscriptSibling: batchSibling,
				TaprootAssetRoot: batchCommitment,
			},
			GenesisPoint: extractGenesisOutpoint(
				b.cfg.Batch.GenesisPacket.Pkt.UnsignedTx,
			),
		}
		err := proof.AddExclusionProofs(
			&baseProof.BaseProofParams,
			b.cfg.Batch.GenesisPacket.Pkt, func(idx uint32) bool {
				return idx == b.anchorOutputIndex
			},
		)
		if err != nil {
			return 0, fmt.Errorf("unable to add exclusion proofs: "+
				"%w", err)
		}

		mintingProofs, err := proof.NewMintingBlobs(
			baseProof, headerVerifier, merkleVerifier,
			groupVerifier, groupAnchorVerifier,
			proof.WithAssetMetaReveals(b.cfg.Batch.AssetMetas),
			proof.WithSiblingPreimage(batchSibling),
		)
		if err != nil {
			return 0, fmt.Errorf("unable to construct minting "+
				"proofs: %w", err)
		}

		var (
			committedAssets   = batchCommitment.CommittedAssets()
			numAssets         = len(committedAssets)
			mintingProofBlobs = make(proof.AssetBlobs, numAssets)
			universeItems     chan *universe.Item
			mintTxHash        = confInfo.Tx.TxHash()
			proofMutex        sync.Mutex
			batchSyncEG       errgroup.Group
		)

		// If we have a universe configured, we'll batch stream the
		// issuance items to it. We start this as a goroutine/err group
		// now, so we can already start streaming while the proofs are
		// still being stored to the local proof store.
		if b.cfg.Universe != nil {
			universeItems = make(
				chan *universe.Item, numAssets,
			)

			// We use an error group to simply the error handling of
			// a goroutine.
			batchSyncEG.Go(func() error {
				return b.batchStreamUniverseItems(
					ctx, universeItems, numAssets,
				)
			})
		}

		// Before we write any assets from the batch, we need to sort
		// the assets so that we insert group anchors before
		// reissunces. This is required for any possible reissuances
		// to be verified correctly when updating our local Universe.
		anchorAssets, nonAnchorAssets, err := SortAssets(
			committedAssets, groupAnchorVerifier,
		)
		if err != nil {
			return 0, fmt.Errorf("could not sort assets: %w", err)
		}

		// Before we confirm the batch, we'll also update the on disk
		// file system as well.
		//
		// TODO(roasbeef): rely on the upsert here instead
		updateAssetProofs := func(ctx context.Context,
			newAsset *asset.Asset) error {

			scriptPubKey := newAsset.ScriptKey.PubKey
			scriptKey := asset.ToSerialized(scriptPubKey)

			mintingProof := mintingProofs[scriptKey]

			proofBlob, uniProof, err := b.storeMintingProof(
				ctx, newAsset, mintingProof, mintTxHash,
				headerVerifier, merkleVerifier, groupVerifier,
			)
			if err != nil {
				return fmt.Errorf("unable to store "+
					"proof: %w", err)
			}

			proofMutex.Lock()
			mintingProofBlobs[scriptKey] = proofBlob
			proofMutex.Unlock()

			if uniProof != nil {
				universeItems <- uniProof
			}

			return nil
		}

		err = fn.ParSlice(ctx, anchorAssets, updateAssetProofs)
		if err != nil {
			return 0, fmt.Errorf("unable to update asset proofs: "+
				"%w", err)
		}

		err = fn.ParSlice(ctx, nonAnchorAssets, updateAssetProofs)
		if err != nil {
			return 0, fmt.Errorf("unable to update asset proofs: "+
				"%w", err)
		}

		// The local proof store inserts are now completed, but we also
		// need to wait for the batch sync to complete before we can
		// confirm the batch.
		if b.cfg.Universe != nil {
			close(universeItems)

			err = batchSyncEG.Wait()
			if err != nil {
				return 0, fmt.Errorf("unable to batch sync "+
					"universe: %w", err)
			}
		}

		err = b.cfg.Log.MarkBatchConfirmed(
			ctx, b.cfg.Batch.BatchKey.PubKey, confInfo.BlockHash,
			confInfo.BlockHeight, confInfo.TxIndex,
			mintingProofBlobs,
		)
		if err != nil {
			return 0, fmt.Errorf("unable to confirm batch: %w", err)
		}

		// Now that we've confirmed the batch, we'll hand over the
		// proofs to the re-org watcher.
		if err := b.cfg.ProofWatcher.WatchProofs(
			maps.Values(mintingProofs), b.cfg.UpdateMintingProofs,
		); err != nil {
			return 0, fmt.Errorf("error watching proof: %w", err)
		}

		log.Infof("BatchCaretaker(%x): transition states: %v -> %v",
			b.batchKey, BatchStateConfirmed, BatchStateFinalized)

		return BatchStateFinalized, nil

	// This is a terminal state, in this state we have nothing left to do,
	// so we just go back to batch finalized.
	case BatchStateFinalized:
		log.Infof("BatchCaretaker(%x): transition states: %v -> %v",
			b.batchKey, BatchStateFinalized, BatchStateFinalized)

		// TODO(roasbeef): confirmed should just be the final state?
		ctx, cancel := b.WithCtxQuit()
		defer cancel()
		err := b.cfg.Log.UpdateBatchState(
			ctx, b.cfg.Batch.BatchKey.PubKey, BatchStateFinalized,
		)
		return BatchStateFinalized, err

	default:
		return 0, fmt.Errorf("unknown state: %v", currentState)
	}
}

// storeMintingProof stores the minting proof for a new asset in the proof
// store. If a universe is configured, it also returns the issuance item that
// can be used to register the asset with the universe.
func (b *BatchCaretaker) storeMintingProof(ctx context.Context,
	a *asset.Asset, mintingProof *proof.Proof, mintTxHash chainhash.Hash,
	headerVerifier proof.HeaderVerifier, merkleVerifier proof.MerkleVerifier,
	groupVerifier proof.GroupVerifier) (proof.Blob, *universe.Item,
	error) {

	assetID := a.ID()
	blob, err := proof.EncodeAsProofFile(mintingProof)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to encode proof file: %w",
			err)
	}

	fullProof := &proof.AnnotatedProof{
		Locator: proof.Locator{
			AssetID:   &assetID,
			ScriptKey: *a.ScriptKey.PubKey,
			OutPoint:  fn.Ptr(mintingProof.OutPoint()),
		},
		Blob: blob,
	}

	err = b.cfg.ProofFiles.ImportProofs(
		ctx, headerVerifier, merkleVerifier, groupVerifier, false,
		fullProof,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to insert proofs: %w", err)
	}

	// Before we continue with the next item, we'll also register the
	// issuance of the new asset with our local base universe. We skip this
	// step if there is no universe configured.
	if b.cfg.Universe == nil {
		return blob, nil, nil
	}

	// The universe ID serves to identifier the universe root we want to add
	// this asset to. This is either the assetID or the group key.
	uniID := universe.Identifier{
		AssetID: assetID,
	}

	groupKey := a.GroupKey
	if groupKey != nil {
		uniID.GroupKey = &groupKey.GroupPubKey
	}

	log.Debugf("Preparing asset for registration with universe, key=%v",
		spew.Sdump(uniID))

	// The base key is the set of bytes that keys into the universe, this'll
	// be the outpoint where it was created at and the script key for that
	// asset.
	leafKey := universe.LeafKey{
		OutPoint: wire.OutPoint{
			Hash:  mintTxHash,
			Index: b.anchorOutputIndex,
		},
		ScriptKey: &a.ScriptKey,
	}

	var proofBuf bytes.Buffer
	if err = mintingProof.Encode(&proofBuf); err != nil {
		return nil, nil, fmt.Errorf("unable to encode proof: %w", err)
	}

	// With both of those assembled, we can now register issuance which
	// takes the amount and proof of the minting event.
	uniGen := universe.GenesisWithGroup{
		Genesis: a.Genesis,
	}
	if groupKey != nil {
		uniGen.GroupKey = groupKey
	}
	mintingLeaf := &universe.Leaf{
		GenesisWithGroup: uniGen,

		// The universe tree store only the asset state transition and
		// not also the proof file checksum (as the root is effectively
		// a checksum), so we'll use just the state transition.
		RawProof: proofBuf.Bytes(),
		Amt:      a.Amount,
		Asset:    a,
	}

	return blob, &universe.Item{
		ID:   uniID,
		Key:  leafKey,
		Leaf: mintingLeaf,

		// We set this to true to indicate that we would like the syncer
		// to log and reattempt (in the event of a failure) to push sync
		// this proof leaf.
		LogProofSync: true,
	}, nil
}

// batchStreamUniverseItems streams the issuance items for a batch to the
// universe.
func (b *BatchCaretaker) batchStreamUniverseItems(ctx context.Context,
	universeItems chan *universe.Item, numTotal int) error {

	var (
		numItems int
		uni      = b.cfg.Universe
	)
	err := fn.CollectBatch(
		ctx, universeItems, b.cfg.UniversePushBatchSize,
		func(ctx context.Context,
			batch []*universe.Item) error {

			numItems += len(batch)
			log.Infof("Inserting %d new leaves (%d of %d) into "+
				"local universe", len(batch), numItems,
				numTotal)

			err := uni.UpsertProofLeafBatch(ctx, batch)
			if err != nil {
				return fmt.Errorf("unable to register "+
					"issuance batch: %w", err)
			}

			log.Infof("Inserted %d new leaves (%d of %d) into "+
				"local universe", len(batch), numItems,
				numTotal)

			return nil
		},
	)
	if err != nil {
		return fmt.Errorf("unable to register issuance proofs: %w", err)
	}

	return nil
}

// SortSeedlings sorts the seedling names such that all seedlings that will be
// a group anchor are first.
func SortSeedlings(seedlings []*Seedling) []string {
	var normalSeedlings []string
	allSeedlings := make([]string, 0, len(seedlings))

	for _, seedling := range seedlings {
		if seedling.EnableEmission {
			allSeedlings = append(allSeedlings, seedling.AssetName)
			continue
		}

		normalSeedlings = append(normalSeedlings, seedling.AssetName)
	}

	allSeedlings = append(allSeedlings, normalSeedlings...)
	return allSeedlings
}

// SortAssets sorts the batch assets such that assets that are group anchors are
// partitioned from all other assets.
func SortAssets(fullAssets []*asset.Asset,
	anchorVerifier proof.GroupAnchorVerifier) ([]*asset.Asset,
	[]*asset.Asset, error) {

	var anchorAssets, nonAnchorAssets []*asset.Asset
	for ind := range fullAssets {
		fullAsset := fullAssets[ind]

		switch {
		case fullAsset.GroupKey != nil:
			err := anchorVerifier(
				&fullAsset.Genesis,
				fullAsset.GroupKey,
			)

			switch {
			case err == nil:
				anchorAssets = append(anchorAssets, fullAsset)

			case errors.Is(err, ErrGenesisNotGroupAnchor) ||
				errors.Is(err, ErrGroupKeyUnknown):

				nonAnchorAssets = append(
					nonAnchorAssets, fullAsset,
				)

			default:
				return nil, nil, err
			}
		default:
			nonAnchorAssets = append(nonAnchorAssets, fullAsset)
		}
	}

	return anchorAssets, nonAnchorAssets, nil
}

// GenHeaderVerifier generates a block header on-chain verification callback
// function given a chain bridge.
func GenHeaderVerifier(ctx context.Context,
	chainBridge ChainBridge) func(wire.BlockHeader, uint32) error {

	return func(header wire.BlockHeader, height uint32) error {
		err := chainBridge.VerifyBlock(ctx, header, height)
		return err
	}
}

// assetGroupCacheSize is the size of the cache for group keys.
const assetGroupCacheSize = 10000

// emptyVal is a simple type def around struct{} to use as a dummy value in in
// the cache.
type emptyVal struct{}

// singleCacheValue is a dummy value that can be used to add an element to the
// cache. This should be used when the cache just needs to worry aobut the
// total number of elements, and not also the size (in bytes) of the elements.
type singleCacheValue[T any] struct {
	val T
}

// Size determines how big this entry would be in the cache.
func (s singleCacheValue[T]) Size() (uint64, error) {
	return 1, nil
}

// newSingleValue creates a new single cache value.
func newSingleValue[T any](v T) singleCacheValue[T] {
	return singleCacheValue[T]{
		val: v,
	}
}

// emptyCacheVal is a type def for an empty cache value. In this case the cache
// is used more as a set.
type emptyCacheVal = singleCacheValue[emptyVal]

// GenGroupVerifier generates a group key verification callback function given a
// DB handle.
func GenGroupVerifier(ctx context.Context,
	mintingStore MintingStore) func(*btcec.PublicKey) error {

	// Cache known group keys that were previously fetched.
	assetGroups := lru.NewCache[asset.SerializedKey, emptyCacheVal](
		assetGroupCacheSize,
	)

	return func(groupKey *btcec.PublicKey) error {
		if groupKey == nil {
			return fmt.Errorf("cannot verify empty group key")
		}

		assetGroupKey := asset.ToSerialized(groupKey)
		_, err := assetGroups.Get(assetGroupKey)
		if err == nil {
			return nil
		}

		// This query will err if no stored group has a matching
		// tweaked group key.
		_, err = mintingStore.FetchGroupByGroupKey(ctx, groupKey)
		if err != nil {
			return fmt.Errorf("%x: group verifier: %s: %w",
				assetGroupKey[:], err.Error(),
				ErrGroupKeyUnknown)
		}

		_, _ = assetGroups.Put(assetGroupKey, emptyCacheVal{})

		return nil
	}
}

// GenGroupAnchorVerifier generates a caching group anchor verification
// callback function given a DB handle.
func GenGroupAnchorVerifier(ctx context.Context,
	mintingStore MintingStore) func(*asset.Genesis, *asset.GroupKey) error {

	// Cache anchors for groups that were previously fetched.
	groupAnchors := lru.NewCache[
		asset.SerializedKey, singleCacheValue[*asset.Genesis],
	](
		assetGroupCacheSize,
	)

	return func(gen *asset.Genesis, groupKey *asset.GroupKey) error {
		assetGroupKey := asset.ToSerialized(&groupKey.GroupPubKey)
		groupAnchor, err := groupAnchors.Get(assetGroupKey)
		if err != nil {
			storedGroup, err := mintingStore.FetchGroupByGroupKey(
				ctx, &groupKey.GroupPubKey,
			)
			if err != nil {
				return fmt.Errorf("%x: group anchor verifier: "+
					"%w", assetGroupKey[:],
					ErrGroupKeyUnknown)
			}

			groupAnchor = newSingleValue(storedGroup.Genesis)

			_, _ = groupAnchors.Put(assetGroupKey, groupAnchor)
		}

		if gen.ID() != groupAnchor.val.ID() {
			return ErrGenesisNotGroupAnchor
		}

		return nil
	}
}

// GenRawGroupAnchorVerifier generates a group anchor verification callback
// function. This anchor verifier recomputes the tweaked group key with the
// passed genesis and compares that key to the given group key. This verifier
// is only used in the caretaker, before any asset groups are stored in the DB.
func GenRawGroupAnchorVerifier(ctx context.Context) func(*asset.Genesis,
	*asset.GroupKey) error {

	// Cache group anchors we already verified.
	groupAnchors := lru.NewCache[
		asset.SerializedKey, singleCacheValue[*asset.Genesis]](
		assetGroupCacheSize,
	)

	return func(gen *asset.Genesis, groupKey *asset.GroupKey) error {
		assetGroupKey := asset.ToSerialized(&groupKey.GroupPubKey)
		groupAnchor, err := groupAnchors.Get(assetGroupKey)
		if err != nil {
			// TODO(jhb): add tapscript root support
			singleTweak := gen.ID()
			tweakedGroupKey, err := asset.GroupPubKey(
				groupKey.RawKey.PubKey, singleTweak[:], nil,
			)
			if err != nil {
				return err
			}

			computedGroupKey := asset.ToSerialized(tweakedGroupKey)
			if computedGroupKey != assetGroupKey {
				return ErrGenesisNotGroupAnchor
			}

			groupAnchor = newSingleValue(gen)

			_, _ = groupAnchors.Put(assetGroupKey, groupAnchor)

			return nil
		}

		if gen.ID() != groupAnchor.val.ID() {
			return ErrGenesisNotGroupAnchor
		}

		return nil
	}
}
