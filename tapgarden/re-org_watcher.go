package tapgarden

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

// proofRegistration is a struct that holds all proofs that need to be watched
// for re-orgs and a callback that will be called if a re-org happened.
type proofRegistration struct {
	proofs []*proof.Proof

	anchorTx wire.MsgTx

	blockHash chainhash.Hash

	blockHeight int32

	updateCb proof.UpdateCallback
}

// anchorTxNotification is a struct that holds all proof watch subscriptions for
// a single anchor transaction. It is possible to have different callbacks for
// different proofs within the same anchor transaction.
type anchorTxNotification struct {
	proofsRegistrations []*proofRegistration

	cancel context.CancelFunc
}

// numProofs returns the total number of proofs that are being watched for this
// anchor transaction.
func (a *anchorTxNotification) numProofs() int {
	return fn.Reduce(
		a.proofsRegistrations,
		func(agg int, reg *proofRegistration) int {
			return agg + len(reg.proofs)
		},
	)
}

// firstRegistration returns the first proof registration that is being watched
// for this anchor transaction.
func (a *anchorTxNotification) firstRegistration() *proofRegistration {
	return a.proofsRegistrations[0]
}

// ReOrgWatcherConfig houses all the items that the re-org watcher needs to
// carry out its duties.
type ReOrgWatcherConfig struct {
	// ChainBridge is the main interface for interacting with the chain
	// backend.
	ChainBridge ChainBridge

	// GroupVerifier is used to verify the validity of the group key for an
	// asset.
	GroupVerifier proof.GroupVerifier

	// ProofArchive is the storage backend for proofs to which we store
	// updated proofs.
	ProofArchive proof.Archiver

	// NonBuriedAssetFetcher is a function that returns all assets that are
	// not yet sufficiently deep buried.
	NonBuriedAssetFetcher func(ctx context.Context,
		minHeight int32) ([]*asset.ChainAsset, error)

	// SafeDepth is the number of confirmations we require before we
	// consider a transaction to be safely buried in the chain.
	SafeDepth int32

	// ErrChan is the main error channel the watcher will report back
	// critical errors to the main server.
	ErrChan chan<- error
}

// ReOrgWatcher is responsible for watching initially confirmed transactions
// until they reach a safe confirmation depth. If a re-org happens, it will
// update the proof and store it in the proof archive.
type ReOrgWatcher struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *ReOrgWatcherConfig

	bestHeight atomic.Int32

	incomingProofs chan *proofRegistration
	incomingConfs  chan *chainntnfs.TxConfirmation

	// pendingProofs is a list of all proofs that are currently being
	// watched for re-orgs, keyed by their anchor transaction hash.
	pendingProofs map[chainhash.Hash]*anchorTxNotification

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewReOrgWatcher creates a new re-org watcher based on the passed config.
func NewReOrgWatcher(cfg *ReOrgWatcherConfig) *ReOrgWatcher {
	return &ReOrgWatcher{
		cfg:            cfg,
		incomingProofs: make(chan *proofRegistration),
		incomingConfs:  make(chan *chainntnfs.TxConfirmation),
		pendingProofs:  make(map[chainhash.Hash]*anchorTxNotification),
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start attempts to start a new re-org watcher.
func (w *ReOrgWatcher) Start() error {
	var startErr error
	w.startOnce.Do(func() {
		log.Info("Starting re-org watcher")

		// Start the main event handler loop that will process new
		// proofs and watch their anchor transactions until they reach
		// a safe confirmation depth.
		w.Wg.Add(1)
		go w.watchTransactions()

		// Now that we have started the watcher, we can load all assets
		// that are not yet sufficiently deep buried and watch their
		// anchor transactions for re-orgs.
		ctx, cancel := w.WithCtxQuitNoTimeout()
		defer cancel()

		currentHeight, err := w.cfg.ChainBridge.CurrentHeight(ctx)
		if err != nil {
			startErr = fmt.Errorf("unable to get current "+
				"block height: %w", err)
			return
		}

		assets, err := w.cfg.NonBuriedAssetFetcher(
			ctx, int32(currentHeight)-w.cfg.SafeDepth,
		)
		if err != nil {
			startErr = fmt.Errorf("unable to fetch non-buried "+
				"assets: %w", err)
			return
		}

		for idx := range assets {
			locator := proof.Locator{
				AssetID:   fn.Ptr(assets[idx].ID()),
				ScriptKey: *assets[idx].ScriptKey.PubKey,
				OutPoint:  &assets[idx].AnchorOutpoint,
			}
			blob, err := w.cfg.ProofArchive.FetchProof(ctx, locator)
			if err != nil {
				startErr = fmt.Errorf("unable to fetch proof "+
					"for asset_id=%v, script_key=%x, "+
					"outpoint=%v: %w", assets[idx].ID(),
					locator.ScriptKey.SerializeCompressed(),
					locator.OutPoint, err)
				return
			}

			f := &proof.File{}
			err = f.Decode(bytes.NewReader(blob))
			if err != nil {
				startErr = fmt.Errorf("unable to decode "+
					"proof: %w", err)
				return
			}

			err = w.MaybeWatch(f, w.DefaultUpdateCallback())
			if err != nil {
				startErr = fmt.Errorf("unable to watch proof "+
					"for asset %v: %w", assets[idx].ID(),
					err)
				return
			}
		}
	})
	return startErr
}

// Stop signals for a re-org watcher to gracefully exit.
func (w *ReOrgWatcher) Stop() error {
	var stopErr error
	w.stopOnce.Do(func() {
		log.Info("Stopping re-org watcher")

		close(w.Quit)
		w.Wg.Wait()
	})

	return stopErr
}

// waitForConf waits for the anchor transaction of the given proofs to reach a
// safe confirmation depth.
func (w *ReOrgWatcher) waitForConf(ctx context.Context, txHash chainhash.Hash,
	newProofs *proofRegistration) error {

	// Do we already have a confirmation watcher for this transaction? Then
	// we don't need to add another one.
	existingNtfn, ok := w.pendingProofs[txHash]
	if ok {
		existingNtfn.proofsRegistrations = append(
			existingNtfn.proofsRegistrations, newProofs,
		)

		return nil
	}

	reOrgChan := make(chan struct{}, 1)
	ctxc, cancel := context.WithCancel(ctx)

	// We only register for a single confirmation, which we expect to come
	// in immediately, since we're only given the proof after one conf.
	// But we keep the registration open, so we will get notified again if
	// there is a re-org.
	confEvent, errChan, err := w.cfg.ChainBridge.RegisterConfirmationsNtfn(
		ctxc, &txHash, newProofs.anchorTx.TxOut[0].PkScript, 1,
		uint32(newProofs.blockHeight), true, reOrgChan,
	)
	if err != nil {
		cancel()
		return fmt.Errorf("unable to register for conf ntfn: %w", err)
	}

	// Now that we have created the confirmation watcher, we can add the
	// new proofs to the pending proofs map.
	w.pendingProofs[txHash] = &anchorTxNotification{
		proofsRegistrations: []*proofRegistration{newProofs},
		cancel:              cancel,
	}

	w.Wg.Add(1)
	go func() {
		defer confEvent.Cancel()
		defer w.Wg.Done()
		defer cancel()

		for {
			select {
			// If the transaction was confirmed normally, we don't
			// need to do anything and can stop watching it.
			case conf, ok := <-confEvent.Confirmed:
				if !ok {
					return
				}

				select {
				case w.incomingConfs <- conf:
				case <-w.Quit:
				}

			// If the transaction was re-organized out, we need to
			// update the proof and store it in the proof archive.
			case <-reOrgChan:
				log.Infof("Anchor TX %v was re-organized out "+
					"of the chain, will update proof "+
					"with next confirmation", txHash)

				// We continue to watch the transaction until
				// it reaches a safe confirmation depth. We
				// basically only use this signal to log the
				// message above. We expect another confirmation
				// to come in once the transaction is included
				// in a new block in the re-organized chain.

			case err := <-errChan:
				if !fn.IsCanceled(err) {
					w.reportErr(fmt.Errorf("error while "+
						"waiting for conf: %w", err))
					return
				}

			case <-ctx.Done():
				if !fn.IsCanceled(ctx.Err()) {
					log.Warnf("Stopping to watch TX %v "+
						"due to context error: %v",
						txHash, ctx.Err())
				}

				return

			case <-w.Quit:
				log.Debugf("Stopping to watch TX %v, re-org "+
					"watcher shutting down", txHash)
				return
			}
		}
	}()

	return nil
}

// updateProofs updates the given proofs with the new block and merkle proof and
// then informs the caller about the update.
func (w *ReOrgWatcher) updateProofs(proofNtfn *anchorTxNotification,
	conf *chainntnfs.TxConfirmation) error {

	// All proofs in the registration should have the same anchor tx, so we
	// can just create a single merkle proof for all of them.
	merkleProof, err := proof.NewTxMerkleProof(
		conf.Block.Transactions, int(conf.TxIndex),
	)
	if err != nil {
		return fmt.Errorf("unable to create merkle proof: %w", err)
	}

	for idxR := range proofNtfn.proofsRegistrations {
		r := proofNtfn.proofsRegistrations[idxR]
		for idxP := range r.proofs {
			p := r.proofs[idxP]

			// We can now update the proof with the new block.
			p.BlockHeight = conf.BlockHeight
			p.BlockHeader = conf.Block.Header
			p.TxMerkleProof = *merkleProof
		}

		if err := r.updateCb(r.proofs); err != nil {
			err := fmt.Errorf("unable to update proof after "+
				"re-org: %w", err)
			log.Error(err.Error())
			return err
		}
	}

	return nil
}

// watchTransactions processes new proofs given to the watcher and watches their
// anchor transactions until they reach a safe confirmation depth.
func (w *ReOrgWatcher) watchTransactions() {
	defer w.Wg.Done()

	runCtx, cancel := w.WithCtxQuitNoTimeout()
	defer cancel()

	newBlockChan, blockErr, err := w.cfg.ChainBridge.RegisterBlockEpochNtfn(
		runCtx,
	)
	if err != nil {
		w.reportErr(fmt.Errorf("unable to register for block "+
			"epoch notifications: %w", err))
		return
	}

	for {
		select {
		case newProofs := <-w.incomingProofs:
			txHash := newProofs.anchorTx.TxHash()
			log.Infof("Watching new proof anchor TX %v for %d "+
				"assets until it reaches %d confirmations",
				txHash, len(newProofs.proofs), w.cfg.SafeDepth)

			err := w.waitForConf(runCtx, txHash, newProofs)
			if err != nil {
				w.reportErr(err)
				return
			}

		case conf := <-w.incomingConfs:
			txHash := conf.Tx.TxHash()
			txNtfn, ok := w.pendingProofs[txHash]
			if !ok {
				// This shouldn't happen in the normal flow, as
				// lnd makes sure that we only receive confs for
				// transactions we subscribed. But it's possible
				// to get here in an edge case where we just
				// started up and a new block comes in at the
				// same time as we receive the confirmation for
				// the TX. Then we might remove the TX from the
				// map of watched TXs and then receive the conf
				// for it.
				log.Debugf("Received confirmation for anchor "+
					"TX we're (no longer?) watching: %v",
					txHash)
				continue
			}

			// If the transaction was confirmed normally, we don't
			// need to do anything and can stop watching it.
			log.Debugf("Anchor TX %v was confirmed at height %d "+
				"(block_hash=%v), checking if %d proof(s) "+
				"need to be updated", txHash, conf.BlockHeight,
				conf.BlockHash, txNtfn.numProofs())

			// We should never accept an empty proof slice to watch,
			// but we add this check just to prevent panics in case
			// we use the watcher incorrectly somewhere.
			if txNtfn.numProofs() == 0 {
				w.reportErr(fmt.Errorf("received confirmation "+
					"for anchor TX %v with empty proof "+
					"slice", txHash))
				return
			}

			// Let's make sure we got a new block hash. If not,
			// something is weird and would indicate lnd is
			// misbehaving.
			if conf.BlockHash == nil {
				w.reportErr(fmt.Errorf("received confirmation "+
					"for anchor TX %v with nil block hash",
					txHash))
				return
			}
			confHash := *conf.BlockHash

			// Do we actually have a different block than the one
			// we already have in the proof? If not, we can just
			// ignore this confirmation (this should not happen in
			// normal circumstances and would be an indication of
			// the chain backend being misconfigured).
			firstReg := txNtfn.firstRegistration()
			if firstReg.blockHash == confHash {
				log.Debugf("Anchor TX %v was already "+
					"confirmed in block %v, ignoring "+
					"confirmation for block %v", txHash,
					conf.BlockHeight, conf.BlockHash)
				continue
			}

			// We can now update the proofs with the new block and
			// inform the caller if necessary.
			err = w.updateProofs(txNtfn, conf)
			if err != nil {
				w.reportErr(fmt.Errorf("error updating "+
					"proofs: %w", err))
				return
			}

		case newBlock := <-newBlockChan:
			log.Infof("New block at height %d", newBlock)
			w.bestHeight.Store(newBlock)

			for txid := range w.pendingProofs {
				proofNtfn := w.pendingProofs[txid]
				firstReg := proofNtfn.firstRegistration()
				confs := newBlock - firstReg.blockHeight

				if confs >= w.cfg.SafeDepth {
					log.Infof("Anchor TX %v reached %d "+
						"confirmations, removing it "+
						"from the re-org watcher",
						txid, confs)

					// Stop watching the anchor transaction.
					proofNtfn.cancel()

					delete(w.pendingProofs, txid)
				}
			}

		case err := <-blockErr:
			w.reportErr(fmt.Errorf("unable to receive new block "+
				"notifications: %w", err))
			return

		case <-w.Quit:
			return
		}
	}
}

// WatchProofs adds new proofs to the re-org watcher for their anchor
// transaction to be watched until it reaches a safe confirmation depth.
func (w *ReOrgWatcher) WatchProofs(newProofs []*proof.Proof,
	onProofUpdate proof.UpdateCallback) error {

	if len(newProofs) == 0 {
		return fmt.Errorf("cannot watch empty proof slice")
	}

	// Check that all proofs have the same anchor transaction, block height
	// and hash.
	anchorTx := newProofs[0].AnchorTx
	blockHeight := newProofs[0].BlockHeight
	blockHash := newProofs[0].BlockHeader.BlockHash()
	for i := 1; i < len(newProofs); i++ {
		if newProofs[i].AnchorTx.TxHash() != anchorTx.TxHash() {
			return fmt.Errorf("all proofs must have the same " +
				"anchor transaction")
		}
		if newProofs[i].BlockHeight != blockHeight {
			return fmt.Errorf("all proofs must have the same " +
				"block height")
		}
		if newProofs[i].BlockHeader.BlockHash() != blockHash {
			return fmt.Errorf("all proofs must have the same " +
				"block hash")
		}
	}

	select {
	case w.incomingProofs <- &proofRegistration{
		proofs:      newProofs,
		anchorTx:    anchorTx,
		blockHash:   blockHash,
		blockHeight: int32(blockHeight),
		updateCb:    onProofUpdate,
	}:
	case <-w.Quit:
		return fmt.Errorf("re-org watcher was stopped")
	}

	return nil
}

// MaybeWatch inspects the given proof file for any proofs that are not
// yet buried sufficiently deep and adds them to the re-org watcher.
func (w *ReOrgWatcher) MaybeWatch(file *proof.File,
	onProofUpdate proof.UpdateCallback) error {

	// We walk backward through the file and start watching all proofs that
	// are not yet sufficiently buried.
	for i := file.NumProofs() - 1; i >= 0; i-- {
		p, err := file.ProofAt(uint32(i))
		if err != nil {
			return fmt.Errorf("error fetching proof: %w", err)
		}

		// If a proof is not yet sufficiently buried, let's watch it
		// too. We submit the proof as a single element slice since the
		// watcher expects only proofs to be grouped that are committed
		// in the same anchor transaction.
		if w.ShouldWatch(p) {
			err := w.WatchProofs([]*proof.Proof{p}, onProofUpdate)
			if err != nil {
				return fmt.Errorf("error watching proof: %w",
					err)
			}

			continue
		}

		// We're going through the file in reverse order, so once we
		// find a proof that is buried sufficiently, all proofs before
		// that will be as well, so we can stop.
		return nil
	}

	return nil
}

// ShouldWatch returns true if the proof is for a block that is not yet
// sufficiently deep to be considered safe.
func (w *ReOrgWatcher) ShouldWatch(p *proof.Proof) bool {
	return (w.bestHeight.Load() - int32(p.BlockHeight)) < w.cfg.SafeDepth
}

// DefaultUpdateCallback is the default implementation for the update callback
// that is called when a proof is updated. This implementation will replace the
// old proof in the proof archiver (multi-archive) with the new one.
func (w *ReOrgWatcher) DefaultUpdateCallback() proof.UpdateCallback {
	return func(proofs []*proof.Proof) error {
		// Let's not be interrupted by a shutdown.
		ctxt, cancel := w.CtxBlocking()
		defer cancel()

		headerVerifier := GenHeaderVerifier(ctxt, w.cfg.ChainBridge)
		for idx := range proofs {
			err := proof.ReplaceProofInBlob(
				ctxt, proofs[idx], w.cfg.ProofArchive,
				headerVerifier, proof.DefaultMerkleVerifier,
				w.cfg.GroupVerifier,
			)
			if err != nil {
				return fmt.Errorf("unable to update proofs: %w",
					err)
			}
		}

		return nil
	}
}

// reportErr reports an error to the main server.
func (w *ReOrgWatcher) reportErr(err error) {
	select {
	case w.cfg.ErrChan <- err:
	case <-w.Quit:
	}
}
