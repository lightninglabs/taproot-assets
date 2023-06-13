package tapgarden

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/keychain"
	"golang.org/x/exp/maps"
)

var (
	// GenesisDummyScript is a dummy script that we'll use to fund the
	// initial PSBT packet that'll create initial set of assets. It's the
	// same size as a encoded P2TR output.
	GenesisDummyScript [34]byte

	// DummyGenesisTxOut is the dummy TxOut we'll place in the PSBt funding
	// request to make sure we leave enough room for change and fees.
	DummyGenesisTxOut = wire.TxOut{
		PkScript: GenesisDummyScript[:],
		Value:    int64(GenesisAmtSats),
	}
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

	GardenKit

	// SignalCompletion is used to signal back to the BatchPlanter that
	// their batch has been finalized.
	SignalCompletion func()

	// CancelChan is used by the BatchPlanter to signal that the caretaker
	// should stop advancing the batch.
	CancelReqChan chan struct{}

	// CancelRespChan is used by the BatchCaretaker to report the result of
	// attempted batch cancellation to the planter.
	CancelRespChan chan CancelResp

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
		close(b.Quit)
		b.Wg.Wait()
	})

	return stopErr
}

// Cancel signals for a batch caretaker to stop advancing a batch if possible.
// A batch can only be cancelled if it has not reached BatchStateBroadcast yet.
func (b *BatchCaretaker) Cancel() CancelResp {
	ctx, cancel := b.WithCtxQuit()
	defer cancel()

	batchKey := b.cfg.Batch.BatchKey.PubKey.SerializeCompressed()
	batchState := b.cfg.Batch.State()
	// This function can only be called before the caretaker state stepping
	// function, so the batch state read is the next state that has not yet
	// been executed. Seedlings are converted to asset sprouts in the Frozen
	// state, and broadcast in the Broadast state.
	switch batchState {
	// In the pending state, the batch seedlings have not sprouted yet.
	case BatchStatePending, BatchStateFrozen:
		finalBatchState := BatchStateSeedlingCancelled
		err := b.cfg.Log.UpdateBatchState(
			ctx, b.cfg.Batch.BatchKey.PubKey,
			finalBatchState,
		)
		if err != nil {
			err = fmt.Errorf("BatchCaretaker(%x), batch state(%v), "+
				"cancel failed: %w", batchKey, batchState, err)
		}

		return CancelResp{&finalBatchState, err}

	case BatchStateCommitted:
		finalBatchState := BatchStateSproutCancelled
		err := b.cfg.Log.UpdateBatchState(
			ctx, b.cfg.Batch.BatchKey.PubKey,
			finalBatchState,
		)
		if err != nil {
			err = fmt.Errorf("BatchCaretaker(%x), batch state(%v), "+
				"cancel failed: %w", batchKey, batchState, err)
		}

		return CancelResp{&finalBatchState, err}

	default:
		err := fmt.Errorf("BatchCaretaker(%x), batch not cancellable",
			b.cfg.Batch.BatchKey.PubKey.SerializeCompressed())
		return CancelResp{nil, err}
	}
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

		case <-b.cfg.CancelReqChan:
			cancelResp := b.Cancel()
			b.cfg.CancelRespChan <- cancelResp

			// TODO(jhb): Use concrete error types for caretaker
			// shutdown cases
			// If the batch was cancellable, the finalState of the
			// cancel response will be non-nil. If the cancellation
			// failed, that error will be handled by the planter.
			// At this point, the caretaker should always shut down
			// gracefully.
			if cancelResp.finalState != nil {
				return 0, fmt.Errorf("BatchCaretaker(%x), "+
					"attempted batch cancellation, "+
					"shutting down", b.batchKey[:])
			}
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
		log.Errorf("unable to advance state machine: %v", err)
		return
	}

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
			b.cfg.CancelRespChan <- b.Cancel()

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
func (b *BatchCaretaker) fundGenesisPsbt(ctx context.Context) (*FundedPsbt, error) {
	log.Infof("BatchCaretaker(%x): attempting to fund GenesisPacket",
		b.batchKey[:])

	txTemplate := wire.NewMsgTx(2)
	txTemplate.AddTxOut(&DummyGenesisTxOut)
	genesisPkt, err := psbt.NewFromUnsignedTx(txTemplate)
	if err != nil {
		return nil, fmt.Errorf("unable to make psbt packet: %w", err)
	}

	log.Infof("BatchCaretaker(%x): creating skeleton PSBT", b.batchKey[:])
	log.Tracef("PSBT: %v", spew.Sdump(genesisPkt))

	feeRate, err := b.cfg.ChainBridge.EstimateFee(
		ctx, GenesisConfTarget,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to estimate fee: %w", err)
	}

	fundedGenesisPkt, err := b.cfg.Wallet.FundPsbt(
		ctx, genesisPkt, 1, feeRate,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to fund psbt: %w", err)
	}

	log.Infof("BatchCaretaker(%x): funded GenesisPacket", b.batchKey[:])
	log.Tracef("GenesisPacket: %v", spew.Sdump(fundedGenesisPkt))

	return &fundedGenesisPkt, nil
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

	newAssets := make([]*asset.Asset, len(b.cfg.Batch.Seedlings))
	batchSize := len(b.cfg.Batch.Seedlings)
	threadCount := runtime.NumCPU()
	scriptKeyDescs := make(chan keychain.KeyDescriptor, 10*threadCount)
	scriptKeys := make(chan asset.ScriptKey, 10*threadCount)
	errChan := make(chan error, threadCount)
	metaChan := make(chan *proof.MetaReveal)
	metaHashChan := make(chan [32]byte)
	makeKeyChan := make(chan struct{}, threadCount)
	var wg sync.WaitGroup

	// Derive a new script key if a signal is sent on a channel. If key
	// derivation fails, send out the error. The main sprout creation loop
	// will propogate that error and exit.
	newScriptKey := func(errChan chan<- error) {
		for range makeKeyChan {
			scriptKeyDesc, err := b.cfg.KeyRing.DeriveNextKey(
				ctx, asset.TaprootAssetsKeyFamily,
			)
			if err != nil {
				errChan <- fmt.Errorf("unable to obtain"+
					"script key: %w", err)
				return
			}

			select {
			case scriptKeyDescs <- scriptKeyDesc:
			default:
			}
		}
	}

	// Create script keys from new script key descriptors.
	newBip86ScriptKey := func() {
		for desc := range scriptKeyDescs {
			scriptKey := asset.NewScriptKeyBip86(desc)
			scriptKeys <- scriptKey
		}
	}

	// Hash metadata for seedlings and forward the metadata hash.
	newMetaHash := func() {
		for meta := range metaChan {
			metaHash := meta.MetaHash()
			metaHashChan <- metaHash
		}
	}

	// Start a pipeline to derive new script keys and metadata hashes in
	// parallel. The signal to derive new keys is sent from this goroutine,
	// and that signal can be closed before the main sprout creation loop
	// is done reading keys. The channels for the other goroutines are
	// closed after the main sprout creation loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < threadCount; i++ {
			go newScriptKey(errChan)
			go newBip86ScriptKey()
			go newMetaHash()
		}
		for batchSize > 0 {
			makeKeyChan <- struct{}{}
			batchSize -= 1
		}
		close(makeKeyChan)
	}()

	// Seedlings that anchor a group may be referenced by other seedlings,
	// and therefore need to be mapped to sprouts first so that we derive
	// the initial tweaked group key early.
	orederedSeedlings := SortSeedlings(maps.Values(b.cfg.Batch.Seedlings))
	newGroups := make(map[string]*asset.AssetGroup, len(orederedSeedlings))

	for ind, seedlingName := range orederedSeedlings {
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
			metaChan <- seedling.Meta
		}

		var (
			err            error
			scriptKey      asset.ScriptKey
			groupInfo      *asset.AssetGroup
			sproutGroupKey *asset.GroupKey
		)

		select {
		case err = <-errChan:
			return nil, err
		case scriptKey = <-scriptKeys:
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

		// Set the metahash field before possibly deriving a group key.
		if seedling.Meta != nil {
			assetGen.MetaHash = <-metaHashChan
		}

		if groupInfo != nil {
			sproutGroupKey, err = asset.DeriveGroupKey(
				b.cfg.GenSigner, groupInfo.GroupKey.RawKey,
				*groupInfo.Genesis, &assetGen,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to"+
					"tweak group key: %w", err)
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
				return nil, fmt.Errorf("unable to"+
					"derive group key: %w", err)
			}
			sproutGroupKey, err = asset.DeriveGroupKey(
				b.cfg.GenSigner, rawGroupKey,
				assetGen, nil,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to"+
					"tweak group key: %w", err)
			}

			newGroups[seedlingName] = &asset.AssetGroup{
				Genesis:  &assetGen,
				GroupKey: sproutGroupKey,
			}
		}

		// With the necessary keys components assembled, we'll create
		// the actual asset now.
		var amount uint64
		switch seedling.AssetType {
		case asset.Normal:
			amount = seedling.Amount
		case asset.Collectible:
			amount = 1
		}

		newAsset, err := asset.New(
			assetGen, amount, 0, 0, scriptKey, sproutGroupKey,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create new asset: %w",
				err)
		}

		newAssets[ind] = newAsset
	}

	close(scriptKeyDescs)
	close(scriptKeys)
	close(metaChan)
	wg.Wait()

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
				"sprouts: %v", err)
		}

		b.cfg.Batch.RootAssetCommitment = tapCommitment

		// With the commitment Taproot Asset root SMT constructed, we'll
		// map that into the tapscript root we'll insert into the
		// genesis transaction.
		genesisScript, err := b.cfg.Batch.genesisScript()
		if err != nil {
			return 0, fmt.Errorf("unable to create genesis "+
				"script: %v", err)
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
		b.cfg.Batch.GenesisPacket.Pkt = signedPkt

		// Populate how much this tx paid in on-chain fees.
		chainFees, err := GetTxFee(signedPkt)
		if err != nil {
			return 0, fmt.Errorf("unable to get on-chain fees "+
				"for psbt: %w", err)
		}
		b.cfg.Batch.GenesisPacket.ChainFees = chainFees

		log.Infof("BatchCaretaker(%x): GenesisPacket finalized",
			b.batchKey[:])
		log.Tracef("GenesisPacket: %v", spew.Sdump(signedPkt))

		// At this point we have a fully signed PSBT packet which'll
		// create our set of assets once mined. We'll write this to
		// disk, then import the public key into the wallet.
		//
		// TODO(roasbeef): re-run during the broadcast phase to ensure
		// it's fully imported?
		mintingOutputKey, tapRoot, err := b.cfg.Batch.MintingOutputKey()
		if err != nil {
			return 0, err
		}
		err = b.cfg.Log.CommitSignedGenesisTx(
			ctx, b.cfg.Batch.BatchKey.PubKey,
			b.cfg.Batch.GenesisPacket, b.anchorOutputIndex,
			tapRoot,
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

		case err != nil:
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
			heightHint, true,
		)
		if err != nil {
			return 0, fmt.Errorf("unable to register for "+
				"minting tx conf: %v", err)
		}

		// Launch a goroutine that'll notify us when the transaction
		// confirms.
		//
		// TODO(roasbeef): make blocking here?
		b.Wg.Add(1)
		go func() {
			defer confCancel()
			defer b.Wg.Done()

			var confEvent *chainntnfs.TxConfirmation
			select {
			case confEvent = <-confNtfn.Confirmed:
				log.Debugf("Got chain confirmation: %v",
					confEvent.Tx.TxHash())

			case err := <-errChan:
				b.cfg.ErrChan <- fmt.Errorf("error getting "+
					"confirmation: %w", err)
				return

			case <-confCtx.Done():
				log.Debugf("Skipping TX confirmation, context " +
					"done")

			case <-b.cfg.CancelReqChan:
				b.cfg.CancelRespChan <- b.Cancel()

			case <-b.Quit:
				log.Debugf("Skipping TX confirmation, exiting")
				return
			}

			if confEvent == nil {
				b.cfg.ErrChan <- fmt.Errorf("got empty " +
					"confirmation event in batch")
				return
			}

			select {
			case b.confEvent <- confEvent:

			case <-confCtx.Done():
				log.Debugf("Skipping TX confirmation, context " +
					"done")

			case <-b.cfg.CancelReqChan:
				b.cfg.CancelRespChan <- b.Cancel()

			case <-b.Quit:
				log.Debugf("Skipping TX confirmation, exiting")
				return
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

		headerVerifier := GenCachingHeaderVerifier(
			ctx, b.cfg.ChainBridge,
		)

		// Now that the minting transaction has been confirmed, we'll
		// need to create the series of proof file blobs for each of
		// the assets. In case the lnd wallet creates a P2TR change
		// output we need to create an exclusion proof for it (and for
		// all other P2TR outputs, we just assume BIP-0086 here).
		baseProof := &proof.MintParams{
			BaseProofParams: proof.BaseProofParams{
				Block:            confInfo.Block,
				Tx:               confInfo.Tx,
				TxIndex:          int(confInfo.TxIndex),
				OutputIndex:      int(b.anchorOutputIndex),
				InternalKey:      b.cfg.Batch.BatchKey.PubKey,
				TaprootAssetRoot: b.cfg.Batch.RootAssetCommitment,
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
			baseProof, headerVerifier,
			proof.WithAssetMetaReveals(b.cfg.Batch.AssetMetas),
		)
		if err != nil {
			return 0, fmt.Errorf("unable to construct minting "+
				"proofs: %w", err)
		}

		// Before we confirm the batch, we'll also update the on disk
		// file system as well.
		//
		// TODO(roasbeef): rely on the upsert here instead
		for _, newAsset := range b.cfg.Batch.RootAssetCommitment.CommittedAssets() {
			assetID := newAsset.ID()
			scriptPubKey := newAsset.ScriptKey.PubKey
			scriptKey := asset.ToSerialized(scriptPubKey)

			mintingProof := mintingProofs[scriptKey]

			err := b.cfg.ProofFiles.ImportProofs(
				ctx, headerVerifier, &proof.AnnotatedProof{
					Locator: proof.Locator{
						AssetID:   &assetID,
						ScriptKey: *scriptPubKey,
					},
					Blob: mintingProof,
				},
			)
			if err != nil {
				return 0, fmt.Errorf("unable to insert "+
					"proofs: %w", err)
			}

			// Before we mark the batch as confirmed below, we'll
			// also register the issuance of the new asset with our
			// local base universe.
			//
			// TODO(roasbeef): can combine with minting proof
			// creation above?
			if b.cfg.Universe != nil {
				// The universe ID serves to identifier the
				// universe root we want to add this asset to.
				// This is either the assetID or the group key.
				uniID := universe.Identifier{
					AssetID: assetID,
				}

				groupKey := newAsset.GroupKey
				if groupKey != nil {
					uniID.GroupKey = &groupKey.GroupPubKey
				}

				log.Debugf("Registering asset with "+
					"universe, key=%v", spew.Sdump(uniID))

				// The base key is the set of bytes that keys
				// into the universe, this'll be the outpoint.
				// where it was created at and the script key
				// for that asset.
				baseKey := universe.BaseKey{
					MintingOutpoint: wire.OutPoint{
						Hash:  confInfo.Tx.TxHash(),
						Index: b.anchorOutputIndex,
					},
					ScriptKey: &newAsset.ScriptKey,
				}

				// The universe tree store the only the asset
				// state transition and not also the proof file
				// checksum (as the root is effectively a
				// checksum), so we'll re-encode just the state
				// transition.
				//
				// TODO(roasbeef): this path ends up doing
				// waaay too many proof encode round trips
				var proofFile proof.File
				err := proofFile.Decode(
					bytes.NewReader(mintingProof),
				)
				if err != nil {
					return 0, fmt.Errorf("unable to decode "+
						"proof: %w", err)
				}

				var proofBuf bytes.Buffer
				issuanceProof, err := proofFile.LastProof()
				if err != nil {
					return 0, err
				}
				err = issuanceProof.Encode(&proofBuf)
				if err != nil {
					return 0, err
				}

				// With both of those assembled, we can now
				// register issuance which takes the amount and
				// proof of the minting event.
				uniGen := universe.GenesisWithGroup{
					Genesis: newAsset.Genesis,
				}
				if groupKey != nil {
					uniGen.GroupKey = groupKey
				}
				mintingLeaf := &universe.MintingLeaf{
					GenesisWithGroup: uniGen,
					GenesisProof:     proofBuf.Bytes(),
					Amt:              newAsset.Amount,
				}
				_, err = b.cfg.Universe.RegisterIssuance(
					ctx, uniID, baseKey, mintingLeaf,
				)
				if err != nil {
					return 0, fmt.Errorf("unable to "+
						"register issuance: %v", err)
				}
			}
		}

		err = b.cfg.Log.MarkBatchConfirmed(
			ctx, b.cfg.Batch.BatchKey.PubKey, confInfo.BlockHash,
			confInfo.BlockHeight, confInfo.TxIndex, mintingProofs,
		)
		if err != nil {
			return 0, fmt.Errorf("unable to confirm batch: %w", err)
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

// GetTxFee returns the value of the on-chain fees paid by a finalized PSBT.
func GetTxFee(pkt *psbt.Packet) (int64, error) {
	inputValue, err := psbt.SumUtxoInputValues(pkt)
	if err != nil {
		return 0, fmt.Errorf("unable to sum input values: %v", err)
	}

	outputValue := int64(0)
	for _, out := range pkt.UnsignedTx.TxOut {
		outputValue += out.Value
	}

	return inputValue - outputValue, nil
}

// GenHeaderVerifier generates a block header on-chain verification callback
// function given a chain bridge.
func GenHeaderVerifier(ctx context.Context,
	chainBridge ChainBridge) func(header wire.BlockHeader) error {

	return func(blockHeader wire.BlockHeader) error {
		_, err := chainBridge.GetBlock(
			ctx, blockHeader.BlockHash(),
		)
		return err
	}
}

// GenCachingHeaderVerifier generate a block header on-chain verification
// callback that caches the first block hash verified with the chain bridge,
// and checks for equality with the cached block hash on future calls.
// This is only safe to use for proof generation after asset minting where all
// proofs share an anchor transaction.
func GenCachingHeaderVerifier(ctx context.Context,
	chainBridge ChainBridge) func(header wire.BlockHeader) error {

	return func(blockHeader wire.BlockHeader) error {
		var staticBlockHash chainhash.Hash
		if staticBlockHash.IsEqual(&chainhash.Hash{}) {
			staticBlockHash = blockHeader.BlockHash()
			_, err := chainBridge.GetBlock(
				ctx, staticBlockHash,
			)
			return err
		}

		// Skip the RPC call if the block header is the same as the
		// first used block header.
		if blockHeader.BlockHash() == staticBlockHash {
			return nil
		}

		return fmt.Errorf("passed block hash %x does not match cached"+
			"%x", blockHeader.BlockHash().String(),
			staticBlockHash.String())
	}
}
