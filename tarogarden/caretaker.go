package tarogarden

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightningnetwork/lnd/chainntnfs"
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
	// now, we assume that the taro client manages asset bearing UTXOs
	// distinctly from normal UTXOs.
	GenesisAmtSats = btcutil.Amount(1_000)

	// GenesisConfTarget is the confirmation target we'll use to query for
	// a fee estimate.
	GenesisConfTarget = 6

	// DefaultTimeout is the default timeout we use for RPC and database
	// operations.
	DefaultTimeout = 30 * time.Minute
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
	// the Taro commitment.
	anchorOutputIndex uint32

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*chanutils.ContextGuard
}

// NewBatchCaretaker creates a new taro caretaker based on the passed config.
//
// TODO(roasbeef): rename to Cultivator?
func NewBatchCaretaker(cfg *BatchCaretakerConfig) *BatchCaretaker {
	return &BatchCaretaker{
		batchKey:  NewBatchKey(cfg.Batch.BatchKey.PubKey),
		cfg:       cfg,
		confEvent: make(chan *chainntnfs.TxConfirmation, 1),
		ContextGuard: &chanutils.ContextGuard{
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
		go b.taroCultivator()
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

// advanceStateUntil attempts to advance the internal state machine until the
// target state has been reached.
func (b *BatchCaretaker) advanceStateUntil(currentState,
	targetState BatchState) (BatchState, error) {

	log.Infof("BatchCaretaker(%x), advancing from state=%v to state=%v",
		b.batchKey[:], currentState, targetState)

	var terminalState bool
	for !terminalState {
		// Before we attempt a state transition, make sure that we
		// aren't trying to shut down.
		select {
		case <-b.Quit:
			return 0, fmt.Errorf("BatchCaretaker(%x), shutting "+
				"down", b.batchKey[:])

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

		b.cfg.Batch.BatchState = currentState
	}

	return currentState, nil
}

// taroCultivator is the main goroutine for the BatchCaretaker struct. This
// goroutines handles progressing a batch all the way up to the point of
// broadcast. Once the batch has been broadcast, we'll register for a
// confirmation to progress the batch to the final terminal state.
func (b *BatchCaretaker) taroCultivator() {
	defer b.Wg.Done()

	// If the batch is already marked as confirmed, then we just need to
	// advance it one more level to be finalized.
	if b.cfg.Batch.BatchState == BatchStateConfirmed {
		log.Infof("MintingBatch(%x): already confirmed!", b.batchKey[:])

		_, err := b.advanceStateUntil(
			BatchStateFinalized, BatchStateFinalized,
		)
		if err != nil {
			log.Error(err)
			return
		}

		b.cfg.SignalCompletion()
	}

	// Our task as a cultivator is pretty simple: we advance our state
	// machine up until the minting transaction is broadcaster or we fail
	// for some reason. If we can broadcast, then we'll await a
	// confirmation notification, which'll let us advance to the final
	// state.
	_, err := b.advanceStateUntil(
		b.cfg.Batch.BatchState, BatchStateBroadcast,
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
			b.cfg.Batch.BatchState = BatchStateConfirmed

			// TODO(roasbeef): use a "trigger" here instead?
			_, err = b.advanceStateUntil(
				b.cfg.Batch.BatchState, BatchStateFinalized,
			)
			if err != nil {
				log.Error(err)
				return
			}

			// At this point we've advanced to the final state,
			// which means we have a set of fully grown Taro
			// assets! We'll report back to the planter out final
			// state, then exit.
			b.cfg.SignalCompletion()
			return

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

	log.Infof("BatchCaretaker(%x): creating skeleton PSBT: %v",
		b.batchKey[:], spew.Sdump(genesisPkt))

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

	log.Infof("BatchCaretaker(%x): funded GenesisPacket obtained: %v",
		b.batchKey[:], spew.Sdump(fundedGenesisPkt))

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
	taroOutputIndex uint32) ([]*commitment.AssetCommitment, error) {

	log.Infof("BatchCaretaker(%x): mapping %v seedlings to asset sprouts, "+
		"with genesis_point=%v", b.batchKey[:], len(b.cfg.Batch.Seedlings),
		genesisPoint)

	assetRoots := make(
		[]*commitment.AssetCommitment, 0, len(b.cfg.Batch.Seedlings),
	)
	for _, seedling := range b.cfg.Batch.Seedlings {
		assetGen := asset.Genesis{
			FirstPrevOut: genesisPoint,
			Tag:          seedling.AssetName,
			Metadata:     seedling.Metadata,
			OutputIndex:  taroOutputIndex,
			Type:         seedling.AssetType,
		}

		scriptKey, err := b.cfg.KeyRing.DeriveNextKey(
			ctx, TaroKeyFamily,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to obtain script "+
				"key: %w", err)
		}

		var familyKey *asset.FamilyKey
		// If emission is enabled, then we'll need to generate another
		// public key, then use that to derive the key family signature
		// along with the tweaked key family.
		if seedling.EnableEmission {
			rawFamilyKey, err := b.cfg.KeyRing.DeriveNextKey(
				ctx, TaroKeyFamily,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to derive "+
					"family key: %v", err)
			}
			familyKey, err = asset.DeriveFamilyKey(
				b.cfg.GenSigner, rawFamilyKey, assetGen,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to tweak	family "+
					"key: %v", err)
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
			assetGen, amount, 0, 0,
			asset.NewScriptKeyBIP0086(scriptKey), familyKey,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create new asset: %v",
				err)
		}

		// Finally make a new asset commitment (the inner SMT tree) for
		// this newly created asset.
		assetRoot, err := commitment.NewAssetCommitment(
			newAsset,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to make new asset "+
				"commitment: %w", err)
		}

		assetRoots = append(assetRoots, assetRoot)
	}

	return assetRoots, nil
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
		ctx, cancel := b.WithCtxQuit()
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

		// First, we'll turn all the seedlings into actual taro assets.
		assetRoots, err := b.seedlingsToAssetSprouts(
			ctx, genesisPoint, uint32(b.anchorOutputIndex),
		)
		if err != nil {
			return 0, fmt.Errorf("unable to map seedlings to "+
				"sprouts: %v", err)
		}

		// Now that we have all our assets created, we'll make a new
		// Taro asset commitment, which commits to all the assets we
		// created above in a new root.
		taroCommitment, err := commitment.NewTaroCommitment(
			assetRoots...,
		)
		if err != nil {
			return 0, err
		}

		b.cfg.Batch.RootAssetCommitment = taroCommitment

		// With the commitment Taro root SMT constructed, we'll map
		// that into the tapscript root we'll insert into the genesis
		// transaction.
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

		log.Infof("BatchCaretaker(%x): GenesisPacket finalized: %v",
			b.batchKey[:], spew.Sdump(signedPkt))

		// At this point we have a fully signed PSBT packet which'll
		// create our set of assets once mined. We'll write this to
		// disk, then import the public key into the wallet.
		//
		// TODO(roasbeef): re-run during the broadcast phase to ensure
		// it's fully imported?
		mintingOutputKey, taroRoot, err := b.cfg.Batch.MintingOutputKey()
		if err != nil {
			return 0, err
		}
		err = b.cfg.Log.CommitSignedGenesisTx(
			ctx, b.cfg.Batch.BatchKey.PubKey,
			b.cfg.Batch.GenesisPacket, b.anchorOutputIndex,
			taroRoot,
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
		err = b.cfg.Wallet.ImportPubKey(ctx, mintingOutputKey)
		if err != nil {
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

		log.Infof("BatchCaretaker(%x): extracted finalized GenesisTx: %v",
			b.batchKey[:], spew.Sdump(signedTx))

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
		currentHeight, err := b.cfg.ChainBridge.CurrentHeight(ctx)
		if err != nil {
			return 0, fmt.Errorf("unable to get current "+
				"height: %v", err)
		}
		txHash := signedTx.TxHash()
		confCtx, confCancel := b.WithCtxQuitNoTimeout()
		confNtfn, errChan, err := b.cfg.ChainBridge.RegisterConfirmationsNtfn(
			confCtx, &txHash, signedTx.TxOut[0].PkScript, 1,
			currentHeight, true,
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
		ctx, cancel := b.WithCtxQuit()
		defer cancel()

		// Now that the minting transaction has been confirmed, we'll
		// need to create the series of proof file blobs for each of
		// the assets.
		mintingProofs, err := proof.NewMintingBlobs(&proof.MintParams{
			Block:       confInfo.Block,
			Tx:          confInfo.Tx,
			TxIndex:     int(confInfo.TxIndex),
			OutputIndex: int(b.anchorOutputIndex),
			InternalKey: b.cfg.Batch.BatchKey.PubKey,
			GenesisPoint: extractGenesisOutpoint(
				b.cfg.Batch.GenesisPacket.Pkt.UnsignedTx,
			),
			TaroRoot: b.cfg.Batch.RootAssetCommitment,
		})
		if err != nil {
			return 0, fmt.Errorf("unable to construct minting "+
				"proofs: %v", err)
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
