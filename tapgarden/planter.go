package tapgarden

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"golang.org/x/exp/maps"
)

// GardenKit holds the set of shared fundamental interfaces all sub-systems of
// the tapgarden need to function.
type GardenKit struct {
	// Wallet is an active on chain wallet for the target chain.
	Wallet tapnode.WalletAnchor

	// ChainBridge provides access to the chain for confirmation
	// notification, and other block related actions.
	ChainBridge tapnode.ChainBridge

	// BatchStore persists the lifecycle of minting batches. Both the
	// planter and the cultivators it spawns drive batches through their
	// states by writing to this store.
	BatchStore BatchStore

	// MintingRefs exposes read-only lookups for the reference data
	// (script keys, asset metas, group keys, delegation keys) that
	// the planter consults when validating seedlings and that the
	// cultivator consults when verifying proofs via GenGroupVerifier
	// and GenGroupAnchorVerifier.
	MintingRefs MintingRefReader

	// TreeStore provides access to optional tapscript trees used with
	// script keys, minting output keys, and group keys.
	TreeStore asset.TapscriptTreeManager

	// KeyRing is used for obtaining internal keys for the anchor
	// transaction, as well as script keys for each asset and group keys
	// for assets created that permit ongoing emission.
	KeyRing tapnode.KeyRing

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

	// MintProofPublisher ships freshly-minted (or re-organized) proofs
	// to a downstream distributor (e.g. a local/remote universe). If
	// nil, no proofs are published; the cultivator's local archival
	// path is unaffected.
	MintProofPublisher MintProofPublisher

	// ProofWatcher is used to watch new proofs for their anchor transaction
	// to be confirmed safely with a minimum number of confirmations.
	ProofWatcher proof.Watcher

	// IgnoreChecker is an optional function that can be used to check if
	// a proof should be ignored.
	IgnoreChecker lfn.Option[proof.IgnoreChecker]

	// GenesisTxAugmenter is an optional hook that lets an external
	// substance (e.g. supply commitment) participate in batch
	// minting without tapgarden having to know what that
	// substance is doing. When unset, all augmenter call sites
	// degrade to NoOpAugmenter and minting proceeds without any
	// extra outputs, validation, or post-confirmation events.
	GenesisTxAugmenter GenesisTxAugmenter
}

// PlanterConfig is the main config for the ChainPlanter.
type PlanterConfig struct {
	GardenKit

	// ChainParams defines the chain parameters for the target blockchain
	// network. It specifies whether the network is Bitcoin mainnet or
	// testnet.
	ChainParams address.ChainParams

	// ProofUpdates is the storage backend for updated proofs.
	ProofUpdates proof.Archiver

	// ErrChan is the main error channel the planter will report back
	// critical errors to the main server.
	ErrChan chan<- error

	// TODO(roasbeef): something notification related?
}

// BatchKey is a type alias for a serialized public key.
type BatchKey = asset.SerializedKey

// CancelResp is the response from a cultivator attempting to cancel a batch.
type CancelResp struct {
	cancelAttempted bool
	err             error
}

// cancelReq is a cancellation request sent from the planter to a
// cultivator. Each request carries its own response channel, so the
// cultivator's reply is causally bound to this specific call and cannot
// be confused with the reply to any other in-flight or future
// cancellation. The previous protocol used two shared channels per
// cultivator (CancelReqChan + CancelRespChan), which was only correct
// because the gardener serialized all cancel calls -- a discipline,
// not a property the protocol itself guaranteed.
type cancelReq struct {
	// resp is the unique reply channel for this request. The
	// cultivator writes the result here exactly once. Buffer size 1
	// so the cultivator never blocks if the planter has already
	// given up (e.g. on c.Quit).
	resp chan<- CancelResp
}

// stateReq is a request executed inside the gardener loop. The
// closure captures its own response channel and any parameters; the
// loop simply invokes it. This replaces the prior stateRequest
// interface + stateReq[T] / stateParamReq[T,S] generics + reqType
// enum + dispatch switch. Closures preserve the per-call binding
// between request and response without any runtime type assertions.
type stateReq func()

// stateResult is what a stateReq closure writes back to its caller.
// One buffered channel of stateResult[T] per call replaces the prior
// (resp, err) channel pair.
type stateResult[T any] struct {
	val T
	err error
}

// stateOk constructs a successful stateResult[T] with the given
// value.
func stateOk[T any](v T) stateResult[T] {
	return stateResult[T]{val: v}
}

// stateErr constructs a failing stateResult[T] with the given
// error.
func stateErr[T any](err error) stateResult[T] {
	return stateResult[T]{err: err}
}

// ListBatchesParams are the options available to specify which minting batches
// are listed, and how verbose the listing should be.
type ListBatchesParams struct {
	BatchKey *btcec.PublicKey
	Verbose  bool
}

// PendingAssetGroup is the group key request and virtual TX necessary to
// produce an asset group witness for a seedling. The joining principle is
// "a request together with the virtual tx that fulfils it."
type PendingAssetGroup struct {
	// KeyRequest is the request to create the asset group.
	KeyRequest asset.GroupKeyRequest

	// VirtualTx is the virtual tx that fulfils the KeyRequest.
	VirtualTx asset.GroupVirtualTx
}

// PSBT returns a PSBT packet that can be used to create a group witness for the
// asset group.
func (p *PendingAssetGroup) PSBT(
	params chaincfg.Params) (*psbt.Packet, error) {

	// Generate PSBT equivalent of the group virtual tx.
	packet, err := psbt.NewFromUnsignedTx(&p.VirtualTx.Tx)
	if err != nil {
		return nil, fmt.Errorf("error producing group virtual PSBT "+
			"from tx: %w", err)
	}

	vIn := &packet.Inputs[0]
	vIn.WitnessUtxo = &p.VirtualTx.PrevOut
	vIn.TaprootMerkleRoot = p.KeyRequest.TapscriptRoot
	vIn.TaprootInternalKey = schnorr.SerializePubKey(
		p.KeyRequest.RawKey.PubKey,
	)

	switch {
	case p.KeyRequest.ExternalKey.IsSome():
		externalKey := p.KeyRequest.ExternalKey.UnwrapToPtr()
		pubKey, err := externalKey.PubKey()
		if err != nil {
			return nil, fmt.Errorf("error deriving public key "+
				"from external key: %w", err)
		}

		bip32Main := &psbt.Bip32Derivation{
			PubKey:               pubKey.SerializeCompressed(),
			MasterKeyFingerprint: externalKey.MasterFingerprint,
			Bip32Path:            externalKey.DerivationPath,
		}
		trBip32Main := &psbt.TaprootBip32Derivation{
			XOnlyPubKey:          bip32Main.PubKey[1:],
			MasterKeyFingerprint: externalKey.MasterFingerprint,
			Bip32Path:            externalKey.DerivationPath,
			LeafHashes:           make([][]byte, 0),
		}

		xPub := externalKey.XPub
		xPubPath := externalKey.DerivationPath[:xPub.Depth()]
		packet.XPubs = append(packet.XPubs, psbt.XPub{
			ExtendedKey:          psbt.EncodeExtendedKey(&xPub),
			MasterKeyFingerprint: externalKey.MasterFingerprint,
			Bip32Path:            xPubPath,
		})

		vIn.Bip32Derivation = []*psbt.Bip32Derivation{
			bip32Main,
		}
		vIn.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
			trBip32Main,
		}

		// TODO(guggero): Make this switch dependent on the non-spend
		// leaf version, once we allow the user to configure that.
		if true {
			assetID := p.KeyRequest.AnchorGen.ID()
			numsXPub, numsKey, err := asset.TweakedNumsKey(assetID)
			if err != nil {
				return nil, fmt.Errorf("error deriving nums "+
					"key: %w", err)
			}

			// For the fake/NUMS key, we use a specific static
			// fingerprint, which will allow us to identify it in
			// the HWI library in order to construct the correct
			// miniscript policy for this type of spend.
			numsFP := asset.PedersenXPubMasterKeyFingerprint
			numsKeyBytes := numsKey.SerializeCompressed()
			bip32Nums := &psbt.Bip32Derivation{
				PubKey:               numsKeyBytes,
				MasterKeyFingerprint: numsFP,
				// We use the same derivation path as for the
				// "real" key, but it doesn't really matter,
				// since it's a fake key anyway.
				Bip32Path: externalKey.DerivationPath,
			}
			trBip32Nums := &psbt.TaprootBip32Derivation{
				XOnlyPubKey:          numsKeyBytes[1:],
				MasterKeyFingerprint: numsFP,
				// We use the same derivation path as for the
				// "real" key, but it doesn't really matter,
				// since it's a fake key anyway.
				Bip32Path:  externalKey.DerivationPath,
				LeafHashes: make([][]byte, 0),
			}

			vIn.Bip32Derivation = append(
				vIn.Bip32Derivation, bip32Nums,
			)
			vIn.TaprootBip32Derivation = append(
				vIn.TaprootBip32Derivation, trBip32Nums,
			)

			numsXPub, err = numsXPub.CloneWithVersion(
				params.HDPublicKeyID[:],
			)
			if err != nil {
				return nil, fmt.Errorf("error cloning nums "+
					"key: %w", err)
			}
			packet.XPubs = append(packet.XPubs, psbt.XPub{
				ExtendedKey: psbt.EncodeExtendedKey(
					numsXPub,
				),
				MasterKeyFingerprint: numsFP,
				Bip32Path:            xPubPath,
			})
		}

	default:
		bip32, trBip32 := tappsbt.Bip32DerivationFromKeyDesc(
			p.KeyRequest.RawKey, params.HDCoinType,
		)
		vIn.Bip32Derivation = []*psbt.Bip32Derivation{bip32}
		vIn.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
			trBip32,
		}
	}

	return packet, nil
}

// UnsealedSeedling is a previously submitted seedling and its associated
// PendingAssetGroup, which can be used to produce an asset group witness.
type UnsealedSeedling struct {
	*Seedling
	*PendingAssetGroup
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
}

// PendingGroupWitness specifies the asset group witness for an asset seedling
// in an unsealed minting batch.
type PendingGroupWitness struct {
	GenID   asset.ID
	Witness wire.TxWitness
}

// SealParams change how asset groups in a minting batch are created.
type SealParams struct {
	GroupWitnesses []PendingGroupWitness

	// SignedGroupVirtualPsbts are the signed group virtual PSBTs that
	// will be used to create the group witness for the asset group.
	SignedGroupVirtualPsbts []psbt.Packet
}

// ChainPlanter is responsible for accepting new incoming requests to create
// taproot assets. The planter will periodically batch those requests into a new
// minting batch, which is handed off to a cultivator. While batches are
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

	// cultivators maps a batch key (which is used as the internal key for
	// the transaction that mints the assets) to the cultivator that will
	// progress the batch through the final phases.
	cultivators map[BatchKey]*Cultivator

	// completionSignals is a channel used to allow the cultivators to
	// signal that the batch is fully final, allowing garbage collection of
	// any relevant resources.
	completionSignals chan BatchKey

	// stateReqs is the channel that any outside requests for the state of
	// the planter will come across. Each request is a closure that runs
	// inside the gardener loop with full access to ChainPlanter state.
	stateReqs chan stateReq

	// subscribers is a map of components that want to be notified on new
	// events, keyed by their subscription ID.
	subscribers map[uint64]*fn.EventReceiver[fn.Event]

	// subscriberMtx guards the subscribers map.
	subscriberMtx sync.Mutex

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewChainPlanter creates a new ChainPlanter instance given the passed config.
func NewChainPlanter(cfg PlanterConfig) *ChainPlanter {
	return &ChainPlanter{
		cfg:               cfg,
		cultivators:        make(map[BatchKey]*Cultivator),
		completionSignals: make(chan BatchKey),
		seedlingReqs:      make(chan *Seedling),
		stateReqs:         make(chan stateReq),
		subscribers:       make(map[uint64]*fn.EventReceiver[fn.Event]),
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// augmenter returns the GenesisTxAugmenter configured on the
// planter's GardenKit, or a no-op augmenter when none was wired.
// Call sites can invoke augmenter methods without nil-checking.
func (c *ChainPlanter) augmenter() GenesisTxAugmenter {
	if c.cfg.GenesisTxAugmenter == nil {
		return NoOpAugmenter{}
	}
	return c.cfg.GenesisTxAugmenter
}

// newCultivatorForBatch creates a new Cultivator for a given batch and
// inserts it into the cultivator map.
func (c *ChainPlanter) newCultivatorForBatch(batch *MintingBatch,
	feeRate *chainfee.SatPerKWeight) *Cultivator {

	batchKey := asset.ToSerialized(batch.BatchKey.PubKey)
	batchConfig := &CultivatorConfig{
		Batch:                 batch,
		GardenKit:             &c.cfg.GardenKit,
		BroadcastCompleteChan: make(chan struct{}, 1),
		BroadcastErrChan:      make(chan error, 1),
		// SignalCompletion is invoked from the cultivator goroutine
		// just before it returns. The gardener reads
		// c.completionSignals from its main select; if Stop has
		// already closed c.Quit, the gardener is no longer in that
		// select and the unbuffered send would block forever,
		// hanging cultivator.Stop's Wg.Wait inside stopCultivators.
		// Selecting on c.Quit makes the send abandonable, which is
		// safe: on shutdown the planter does not need the
		// completion notification (it is stopping the cultivator
		// anyway).
		SignalCompletion: func() {
			select {
			case c.completionSignals <- batchKey:
			case <-c.Quit:
			}
		},
		CancelReqChan:       make(chan cancelReq, 1),
		UpdateMintingProofs: c.updateMintingProofs,
		PublishMintEvent:    c.publishSubscriberEvent,
		ErrChan:             c.cfg.ErrChan,
	}
	if feeRate != nil {
		batchConfig.BatchFeeRate = feeRate
	}

	cultivator := NewCultivator(batchConfig)
	c.cultivators[batchKey] = cultivator

	return cultivator
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
		// The cultivator will handle progressing the batch to the
		// frozen state, and beyond.
		//
		// TODO(roasbeef): instead do RBF here? so only a single
		// pending batch at a time? but would end up changing assetIDs.
		ctx, cancel := c.WithCtxQuit()
		defer cancel()
		nonFinalBatches, err := c.cfg.BatchStore.FetchNonFinalBatches(ctx)
		if err != nil {
			startErr = err
			return
		}

		log.Infof("Retrieved %v non-finalized batches from DB",
			len(nonFinalBatches))

		// Enforce the singleton invariant: at most one batch may
		// be in BatchStatePending or BatchStateFrozen at a time.
		// The DB constraint added in migration 000060 should
		// already make this impossible, but a legacy DB that was
		// migrated post-population, or a manually-modified row,
		// could still violate it. Surfacing the error here gives
		// the operator a human-readable diagnostic instead of an
		// opaque SQL one later.
		if err := checkSingletonInvariant(nonFinalBatches); err != nil {
			startErr = err
			return
		}

		// Now for each of these non-final batches, we'll make a new
		// cultivator which'll handle progressing each batch to
		// completion. We'll skip batches that were cancelled.
		for _, batch := range nonFinalBatches {
			batchState := batch.State()
			batchKey := batch.BatchKey.PubKey.SerializeCompressed()

			if batchState == BatchStateSeedlingCancelled ||
				batchState == BatchStateSproutCancelled {

				continue
			}

			// For batches before the actual assets have been
			// committed, we'll need to populate this field
			// manually.
			if batch.AssetMetas == nil {
				batch.AssetMetas = make(AssetMetas)
			}

			// If batch funding or sealing fail during startup, the
			// batch will be marked as cancelled. The batch can
			// still be displayed by the planter, and can be
			// resubmitted manually.
			cancelBatch := func() {
				log.Warnf("Marking batch as cancelled (%x)",
					batchKey)
				err := c.cfg.BatchStore.UpdateBatchState(
					ctx, batch,
					BatchStateSeedlingCancelled,
				)

				// If updating the batch state fails, the batch
				// will still be skipped on this startup; we can
				// continue without passing the error further.
				if err != nil {
					log.Warnf("Unable to cancel batch (%x)",
						batchKey)
				}
			}

			// TODO(jhb): Log manual fee rates?
			// If the batch was still pending, or if batch
			// finalization was interrupted, it may need to be
			// funded or sealed before being assigned a cultivator.
			// A batch that was already properly frozen at this
			// point should not be modified before being assigned a
			// cultivator.
			if batchState == BatchStatePending ||
				batchState == BatchStateFrozen {

				var (
					fundErr error
					sealErr error
				)

				if !batch.IsFunded() {
					log.Infof("Funding non-finalized "+
						"batch from DB (%x)", batchKey)
					fundErr = c.applyFundingToBatch(
						ctx, FundParams{}, batch,
					)
				}

				if fundErr != nil {
					log.Warnf("Failed to fund batch from "+
						"DB (%x): %s",
						batchKey, fundErr.Error())
					cancelBatch()
					continue
				}

				log.Infof("Sealing non-finalized batch from "+
					"DB (%x)", batchKey)
				sealedBatch, sealErr := c.sealBatch(
					ctx, SealParams{}, batch,
				)
				if sealErr != nil {
					if !errors.Is(
						sealErr, ErrBatchAlreadySealed,
					) {

						log.Warnf("Failed to seal "+
							"batch from DB (%x): "+
							"%s", batchKey,
							sealErr.Error())
						cancelBatch()
						continue
					}
				}

				// If the sealBatch call returned a sealed
				// batch, update the pending batch accordingly.
				if sealedBatch != nil {
					batch = sealedBatch
				}

				// Any pending batch that was funded and sealed
				// can now be set as frozen. We are already not
				// able to add new seedlings to the batch. The
				// store call below moves both the on-disk row
				// and the in-memory mirror atomically; if it
				// fails, neither has moved.
				err := c.cfg.BatchStore.UpdateBatchState(
					ctx, batch, BatchStateFrozen,
				)
				if err != nil {
					log.Warnf("Failed to update batch "+
						"state to frozen (%x): %s",
						batchKey, err.Error())
					cancelBatch()
					continue
				}
			}

			log.Infof("Launching Cultivator(%x)", batchKey)
			cultivator := c.newCultivatorForBatch(batch, nil)
			if err := cultivator.Start(); err != nil {
				startErr = err
				return
			}
		}

		// With all the cultivators for each minting batch launched,
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

		// Remove all subscribers.
		c.subscriberMtx.Lock()
		defer c.subscriberMtx.Unlock()

		for _, subscriber := range c.subscribers {
			subscriber.Stop()
			delete(c.subscribers, subscriber.ID())
		}
	})

	return stopErr
}

// stopCultivators attempts to gracefully stop all the active cultivators.
func (c *ChainPlanter) stopCultivators() {
	for batchKey, cultivator := range c.cultivators {
		log.Debugf("Stopping Cultivator(%x)", batchKey[:])

		if err := cultivator.Stop(); err != nil {
			// TODO(roasbeef): continue and stop the rest
			// of them?
			log.Warnf("Unable to stop Cultivator(%x)",
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
	// The batch is private to this caller until CommitMintingBatch
	// succeeds, so setting the in-memory state directly here does not
	// open a two-truth window: the next DB call is the first to publish
	// the row, with state=Pending.
	newBatch.setState(BatchStatePending)
	return newBatch, nil
}

// unfundedAnchorPsbt creates an unfunded PSBT packet for the minting anchor
// transaction.
func unfundedAnchorPsbt(preCommitmentTxOut fn.Option[wire.TxOut]) (psbt.Packet,
	error) {

	var zero psbt.Packet

	// Construct a template transaction for our minting anchor transaction.
	txTemplate := wire.NewMsgTx(2)

	// Add one output to anchor all assets which are being minted.
	txTemplate.AddTxOut(tapsend.CreateDummyOutput())

	// If universe commitments are enabled, we add an output to the
	// transaction which will be used as the pre-commitment output.
	// This output is spent by the universe commitment transaction.
	preCommitmentTxOut.WhenSome(func(txOut wire.TxOut) {
		txTemplate.AddTxOut(&txOut)
	})

	// Formulate the PSBT packet from the template transaction.
	genesisPkt, err := psbt.NewFromUnsignedTx(txTemplate)
	if err != nil {
		return zero, fmt.Errorf("unable to make psbt packet: %w", err)
	}

	return *genesisPkt, nil
}

// AnchorTxOutputIndexes specifies the output indexes of the batch mint anchor
// transaction.
type AnchorTxOutputIndexes struct {
	// AssetAnchorOutIdx is the index of the asset anchor output in the
	// transaction.
	AssetAnchorOutIdx uint32

	// ChangeOutIdx is the index of the change output in the transaction.
	ChangeOutIdx uint32
}

// anchorTxOutputIndexes scans the funded anchor PSBT for the asset
// anchor output and the wallet-provided change output. Any
// additional outputs (e.g. those contributed by the
// GenesisTxAugmenter) are located by the augmenter itself.
func anchorTxOutputIndexes(
	fundedPsbt tapsend.FundedPsbt) (AnchorTxOutputIndexes, error) {

	var (
		zero AnchorTxOutputIndexes

		assetAnchorOutIdxOpt fn.Option[uint32]
	)

	expectedAssetAnchorOutput := tapsend.CreateDummyOutput()
	expectedAssetAnchorPkScript := expectedAssetAnchorOutput.PkScript

	for idx := range fundedPsbt.Pkt.UnsignedTx.TxOut {
		if int32(idx) == fundedPsbt.ChangeOutputIndex {
			continue
		}
		txOut := fundedPsbt.Pkt.UnsignedTx.TxOut[idx]
		if bytes.Equal(txOut.PkScript, expectedAssetAnchorPkScript) {
			assetAnchorOutIdxOpt = fn.Some(uint32(idx))
			break
		}
	}

	assetAnchorOutIdx, err := assetAnchorOutIdxOpt.UnwrapOrErr(
		fmt.Errorf("asset anchor output index not found"),
	)
	if err != nil {
		return zero, err
	}

	return AnchorTxOutputIndexes{
		AssetAnchorOutIdx: assetAnchorOutIdx,
		ChangeOutIdx:      uint32(fundedPsbt.ChangeOutputIndex),
	}, nil
}

// anchorTxFeeRate computes the fee rate for the anchor transaction. If a fee
// rate is manually assigned for the batch, it is used. Otherwise, the fee rate
// is estimated based on the current network conditions.
func (c *ChainPlanter) anchorTxFeeRate(ctx context.Context,
	manualFeeRateOpt fn.Option[chainfee.SatPerKWeight]) (
	chainfee.SatPerKWeight, error) {

	var zero chainfee.SatPerKWeight

	// First, we'll fetch the minimum relay fee for the target chain.
	// We'll use this to ensure that the fee rate we use meets the
	// minimum requirements.
	minRelayFee, err := c.cfg.Wallet.MinRelayFee(ctx)
	if err != nil {
		return zero, fmt.Errorf("unable to obtain min relay fee: %w",
			err)
	}

	// If provided and valid, use the manual fee rate.
	if manualFeeRateOpt.IsSome() {
		manualFeeRate, err := manualFeeRateOpt.UnwrapOrErr(
			fmt.Errorf("code error: no manual fee rate"),
		)
		if err != nil {
			return zero, err
		}

		log.Debug("Manual fee rate specified for batch anchor tx: %s",
			manualFeeRate.String())

		// Ensure that the manual fee rate is above the minimum relay
		// fee.
		if manualFeeRate < minRelayFee {
			return zero, fmt.Errorf("manual fee rate less than "+
				"min relay fee: (manual_fee_rate=%s, "+
				"min_relay_fee=%s)", manualFeeRate.String(),
				minRelayFee.String())
		}

		return manualFeeRate, nil
	}

	log.Debug("No manual fee rate specified for batch, " +
		"querying chain backend for fee rate")

	// We'll ask the chain backend to estimate a fee rate that should get
	// the batch anchor tx into the next block.
	chainFeeRate, err := c.cfg.ChainBridge.EstimateFee(
		ctx, GenesisConfTarget,
	)
	if err != nil {
		return zero, fmt.Errorf("failed to call chain backend for "+
			"fee estimate: %w", err)
	}

	log.Debugf("Chain backend returned fee rate: %s", chainFeeRate.String())

	// If the chain backend provided fee rate is less than the minimum relay
	// fee, we'll use the min relay fee instead.
	if chainFeeRate < minRelayFee {
		log.Debugf("Chain backend provided fee rate less than min "+
			"relay fee, using min relay fee "+
			"(chain_backend_fee_rate=%s, min_relay_fee=%s)",
			chainFeeRate.String(), minRelayFee.String())
		return minRelayFee, nil
	}

	// Otherwise, we'll use the fee rate as provided by the chain
	// backend.
	log.Debugf("Using fee rate from chain backend: %s",
		chainFeeRate.String())
	return chainFeeRate, nil
}

// WalletFundPsbt is a function that funds a PSBT packet.
type WalletFundPsbt = func(ctx context.Context,
	anchorPkt psbt.Packet) (tapsend.FundedPsbt, error)

// fundGenesisPsbt generates a PSBT packet we'll use to create an asset.  In
// order to be able to create an asset, we need an initial genesis outpoint. To
// obtain this we'll ask the wallet to fund a PSBT template for GenesisAmtSats
// (all outputs need to hold some BTC to not be dust), and with a dummy script.
// We need to use a dummy script as we can't know the actual script key since
// that's dependent on the genesis outpoint.
func fundGenesisPsbt(ctx context.Context, _ address.ChainParams,
	pendingBatch *MintingBatch, walletFundPsbt WalletFundPsbt,
	augmenter GenesisTxAugmenter) (FundedMintAnchorPsbt, error) {

	var zero FundedMintAnchorPsbt

	if augmenter == nil {
		augmenter = NoOpAugmenter{}
	}

	// Ask the augmenter for any extra outputs to splice into
	// the unfunded anchor PSBT (e.g. the pre-commitment output
	// for the supply-commit substance). The augmenter returns
	// nil/empty when it has nothing to contribute, in which
	// case the genesis tx carries only the asset anchor output
	// (plus a wallet-managed change output).
	extraOuts, err := augmenter.ExtraOutputs(ctx, pendingBatch)
	if err != nil {
		return zero, fmt.Errorf("augmenter ExtraOutputs: %w", err)
	}

	// The legacy funding helper accepted a single fn.Option for
	// the pre-commitment output. The augmenter generalizes that
	// to a list, but in practice only zero or one extra output
	// is contributed today; route accordingly.
	var preCommitmentTxOut fn.Option[wire.TxOut]
	switch len(extraOuts) {
	case 0:
		// no-op
	case 1:
		preCommitmentTxOut = fn.Some(extraOuts[0])
	default:
		return zero, fmt.Errorf("augmenter returned %d extra "+
			"outputs; only zero or one is supported",
			len(extraOuts))
	}

	// Construct an unfunded anchor PSBT which will eventually become a
	// funded minting anchor transaction.
	genesisPkt, err := unfundedAnchorPsbt(preCommitmentTxOut)
	if err != nil {
		return zero, fmt.Errorf("unable to create anchor template tx: "+
			"%w", err)
	}
	log.Tracef("Unfunded batch anchor PSBT: %v", spew.Sdump(genesisPkt))

	fundedGenesisPkt, err := walletFundPsbt(ctx, genesisPkt)
	if err != nil {
		return zero, fmt.Errorf("unable to fund psbt: %w", err)
	}

	// Sanity check the funded PSBT.
	if fundedGenesisPkt.ChangeOutputIndex == -1 {
		return zero, fmt.Errorf("undefined change output index in " +
			"funded anchor transaction")
	}

	log.Tracef("GenesisPacket: %v", spew.Sdump(fundedGenesisPkt))

	// Classify anchor transaction output indexes. Tapgarden only
	// tracks the asset anchor and change output indexes; the
	// augmenter (if any) tracks its own outputs internally.
	anchorOutIndexes, err := anchorTxOutputIndexes(fundedGenesisPkt)
	if err != nil {
		return zero, fmt.Errorf("unable to determine output indexes: "+
			"%w", err)
	}

	// Let the augmenter locate its own outputs in the funded
	// PSBT and stamp any required metadata (BIP32 derivation
	// for the pre-commitment output).
	if err := augmenter.PostFund(
		ctx, pendingBatch, &fundedGenesisPkt,
	); err != nil {
		return zero, fmt.Errorf("augmenter PostFund: %w", err)
	}

	// Build the FundedMintAnchorPsbt. The augmenter is the
	// source of truth for any extra outputs and their
	// persistence payloads via BindData.
	fundedMintAnchorPsbt, err := NewFundedMintAnchorPsbt(
		fundedGenesisPkt, anchorOutIndexes,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to create funded minting "+
			"anchor PSBT: %w", err)
	}

	return fundedMintAnchorPsbt, nil
}

// filterSeedlingsWithGroup separates a set of seedlings into two sets based on
// their relation to an asset group, which has not been constructed yet.
func filterSeedlingsWithGroup(
	seedlings map[string]*Seedling) (map[string]*Seedling,
	map[string]*Seedling) {

	withGroup := make(map[string]*Seedling)
	withoutGroup := make(map[string]*Seedling)
	fn.ForEachMapItem(seedlings, func(name string, seedling *Seedling) {
		switch {
		case seedling.GroupInfo != nil || seedling.GroupAnchor != nil ||
			seedling.EnableEmission:

			withGroup[name] = seedling

		default:
			withoutGroup[name] = seedling
		}
	})

	return withGroup, withoutGroup
}

// buildGroupReqs creates group key requests and asset group genesis TXs for
// seedlings that are part of a funded batch.
func buildGroupReqs(genesisPoint wire.OutPoint, assetOutputIndex uint32,
	genBuilder asset.GenesisTxBuilder,
	groupSeedlings map[string]*Seedling) ([]asset.GroupKeyRequest,
	[]asset.GroupVirtualTx, error) {

	// Seedlings that anchor a group may be referenced by other seedlings,
	// and therefore need to be mapped to sprouts first so that we derive
	// the initial tweaked group key early.
	orderedSeedlings := SortSeedlings(maps.Values(groupSeedlings))
	newGroups := make(map[string]*asset.AssetGroup)
	groupReqs := make([]asset.GroupKeyRequest, 0, len(orderedSeedlings))
	genTXs := make([]asset.GroupVirtualTx, 0, len(orderedSeedlings))

	for _, seedlingName := range orderedSeedlings {
		seedling := groupSeedlings[seedlingName]
		assetGen := seedling.Genesis(genesisPoint, assetOutputIndex)

		// If the seedling has a meta data reveal set, then we'll bind
		// that by including the hash of the meta data in the asset
		// genesis.
		if seedling.Meta != nil {
			assetGen.MetaHash = seedling.Meta.MetaHash()
		}

		var (
			amount uint64

			// groupInfo represents the group key and genesis data
			// for the asset group. This is populated if the
			// seedling specifies a group key or if it specifies
			// a group anchor and the corresponding group already
			// exists.
			groupInfo *asset.AssetGroup

			protoAsset *asset.Asset
			err        error
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
				assetGen, amount, 0, 0, seedling.ScriptKey,
				nil,
				asset.WithAssetVersion(seedling.AssetVersion),
			)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to create "+
					"asset for group key signing: %w", err)
			}
		}

		// If groupInfo is specified, a group key already exists for the
		// seedling. This key will be used to create a placeholder group
		// key request, which will then be used to generate a group
		// virtual transaction.
		if groupInfo != nil {
			groupReq, err := asset.NewGroupKeyRequest(
				groupInfo.GroupKey.RawKey, seedling.ExternalKey,
				*groupInfo.Genesis, protoAsset,
				groupInfo.GroupKey.TapscriptRoot,
				groupInfo.GroupKey.CustomTapscriptRoot,
			)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to "+
					"request asset group membership: %w",
					err)
			}

			genTx, err := groupReq.BuildGroupVirtualTx(
				genBuilder,
			)
			if err != nil {
				return nil, nil, err
			}

			groupReqs = append(groupReqs, *groupReq)
			genTXs = append(genTXs, *genTx)

			// TODO(ffranr): Should we continue to the next seedling
			//  at this point? The group key request and virtual
			//  transaction have been created.
		}

		// If emission isn't enabled, we don't have to do anything else
		// for this seedling.
		if !seedling.EnableEmission {
			continue
		}

		// If emission is enabled, an internal key for the group should
		// already be specified. Use that to derive the key group
		// signature along with the tweaked key group.
		if seedling.GroupInternalKey == nil &&
			seedling.ExternalKey.IsNone() {

			return nil, nil, fmt.Errorf("unable to " +
				"derive group key, both internal and " +
				"external keys are unspecified")
		}

		// If seedling.GroupTapscriptRoot is specified and the
		// seedling includes an external key, we must use group
		// key V1. As a result, seedling.GroupTapscriptRoot will
		// be treated as a custom tapscript subtree root, which
		// we will graft into the group key's tapscript tree. We
		// will proceed with this now.
		var (
			tsRoot         = seedling.GroupTapscriptRoot
			customRootHash fn.Option[chainhash.Hash]
		)
		if seedling.ExternalKey.IsSome() {
			// If seedling.GroupTapscriptRoot is specified,
			// set it to the custom root hash. Then we will
			// calculate a new tapscript root hash which
			// includes the custom root as a grafted
			// subtree.
			if len(tsRoot) > 0 {
				r, err := chainhash.NewHash(tsRoot)
				if err != nil {
					return nil, nil, err
				}

				customRootHash = fn.Some(*r)
			}

			// Construct an asset group tapscript tree,
			// incorporating the optional custom subtree
			// through grafting.
			//
			// At this point, we are constructing the group
			// tapscript tree root whether the
			// customRootHash is defined.
			tapscriptTree, _, err := asset.NewGroupKeyTapscriptRoot(
				// TODO(guggero): Make this configurable in the
				// future.
				asset.PedersenVersion, assetGen.ID(),
				customRootHash,
			)
			if err != nil {
				return nil, nil, err
			}

			// Update the group tapscript tree root hash to
			// the new root hash. If customRootHash is
			// defined, the new root hash incorporates it as
			// a subtree.
			tsRoot = fn.ByteSlice(tapscriptTree.Root())
		}

		// The group internal key should be set at this point.
		//
		// If an external key is present, the internal key
		// should be a public key derived from the external
		// key.
		if seedling.GroupInternalKey == nil {
			return nil, nil, fmt.Errorf("internal key is " +
				"missing for seedling")
		}

		groupReq, err := asset.NewGroupKeyRequest(
			*seedling.GroupInternalKey,
			seedling.ExternalKey, assetGen,
			protoAsset, tsRoot, customRootHash,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to "+
				"request asset group creation: %w", err)
		}

		genTx, err := groupReq.BuildGroupVirtualTx(
			genBuilder,
		)
		if err != nil {
			return nil, nil, err
		}

		groupReqs = append(groupReqs, *groupReq)
		genTXs = append(genTXs, *genTx)

		newGroupKey := &asset.GroupKey{
			Version:             groupReq.Version,
			RawKey:              *seedling.GroupInternalKey,
			TapscriptRoot:       seedling.GroupTapscriptRoot,
			CustomTapscriptRoot: customRootHash,
		}

		newGroups[seedlingName] = &asset.AssetGroup{
			Genesis:  &assetGen,
			GroupKey: newGroupKey,
		}
	}

	return groupReqs, genTXs, nil
}

// freezeMintingBatch freezes a target minting batch which means that no new
// assets can be added to the batch.
func freezeMintingBatch(ctx context.Context, batchStore BatchStore,
	batch *MintingBatch) error {

	batchKey := batch.BatchKey.PubKey

	log.Infof("Freezing MintingBatch(key=%x, num_assets=%v)",
		batchKey.SerializeCompressed(), len(batch.Seedlings))

	// In order to freeze a batch, we need to update the state of the batch
	// to BatchStateFrozen, meaning that no other changes can happen.
	//
	// TODO(roasbeef): assert not in some other state first?
	return batchStore.UpdateBatchState(
		ctx, batch, BatchStateFrozen,
	)
}

// checkSingletonInvariant verifies that at most one batch in the
// supplied slice is in a pre-broadcast state (BatchStatePending or
// BatchStateFrozen). The invariant is enforced at the DB layer by
// the partial unique index added in migration 000060; this Go-level
// check exists as defense in depth and to produce a human-readable
// diagnostic naming the offending batch keys, since a raw SQL
// constraint error from a downstream insert is harder to act on.
//
// The check is called from ChainPlanter.Start() after
// FetchNonFinalBatches. If it fails, startup is aborted so the
// operator can investigate rather than letting the daemon run with
// ambiguous "which batch is current?" semantics.
func checkSingletonInvariant(batches []*MintingBatch) error {
	var preBroadcastKeys []string
	for _, batch := range batches {
		switch batch.State() {
		case BatchStatePending, BatchStateFrozen:
			preBroadcastKeys = append(
				preBroadcastKeys,
				hex.EncodeToString(
					batch.BatchKey.PubKey.
						SerializeCompressed(),
				),
			)
		}
	}

	if len(preBroadcastKeys) <= 1 {
		return nil
	}

	return fmt.Errorf("singleton pre-broadcast batch invariant "+
		"violated: found %d batches in BatchStatePending or "+
		"BatchStateFrozen (keys: %v); at most one is permitted. "+
		"Resolve by running `tapd --repair.cancel-duplicate-batches` "+
		"to cancel all but the most recent, then restart",
		len(preBroadcastKeys), preBroadcastKeys)
}

// filterFinalizedBatches separates a set of batches into two sets based on
// their batch state.
func filterFinalizedBatches(batches []*MintingBatch) ([]*MintingBatch,
	[]*MintingBatch) {

	finalized := []*MintingBatch{}
	nonFinalized := []*MintingBatch{}

	fn.ForEach(batches, func(batch *MintingBatch) {
		switch batch.State() {
		case BatchStateFinalized:
			finalized = append(finalized, batch)
		default:
			nonFinalized = append(nonFinalized, batch)
		}
	})

	return finalized, nonFinalized
}

// fetchFinalizedBatch fetches the assets of a batch in their genesis state,
// given a batch populated with seedlings.
func fetchFinalizedBatch(ctx context.Context, refs MintingRefReader,
	archiver proof.Archiver, batch *MintingBatch) (*MintingBatch, error) {

	genesisPkt := batch.GenesisPacket

	if genesisPkt == nil {
		return nil, fmt.Errorf("batch is missing anchor tx packet")
	}

	// Collect genesis TX information from the batch to build the proof
	// locators.
	anchorOutputIndex := genesisPkt.AssetAnchorOutIdx

	genOutpoint, err := genesisPkt.GenesisOutpoint().UnwrapOrErr(
		ErrFundedAnchorPsbtMissingOutpoint,
	)
	if err != nil {
		return nil, err
	}

	signedTx, err := psbt.Extract(batch.GenesisPacket.Pkt)
	if err != nil {
		return nil, err
	}

	genScript := signedTx.TxOut[anchorOutputIndex].PkScript
	anchorOutpoint := wire.OutPoint{
		Hash:  signedTx.TxHash(),
		Index: anchorOutputIndex,
	}

	batchAssets := make([]*asset.Asset, 0, len(batch.Seedlings))
	assetMetas := make(AssetMetas)
	for _, seedling := range batch.Seedlings {
		gen := seedling.Genesis(genOutpoint, anchorOutputIndex)
		issuanceProof, err := archiver.FetchIssuanceProof(
			ctx, gen.ID(), anchorOutpoint,
		)
		if err != nil {
			return nil, err
		}

		proofFile, err := issuanceProof.AsFile()
		if err != nil {
			return nil, err
		}

		if proofFile.NumProofs() != 1 {
			return nil, fmt.Errorf("expected single proof for " +
				"issuance proof")
		}

		rawProof, err := proofFile.RawLastProof()
		if err != nil {
			return nil, err
		}

		// Decode the sprouted asset from the issuance proof.
		var sproutedAsset asset.Asset
		assetRecord := proof.AssetLeafRecord(&sproutedAsset)
		err = proof.SparseDecode(bytes.NewReader(rawProof), assetRecord)
		if err != nil {
			return nil, fmt.Errorf("unable to decode issuance "+
				"proof: %w", err)
		}

		if !sproutedAsset.IsGenesisAsset() {
			return nil, fmt.Errorf("decoded asset is not a " +
				"genesis asset")
		}

		// Populate the key info for the script key and group key.
		if sproutedAsset.ScriptKey.PubKey == nil {
			return nil, fmt.Errorf("decoded asset is missing " +
				"script key")
		}

		tweakedScriptKey, err := refs.FetchScriptKeyByTweakedKey(
			ctx, sproutedAsset.ScriptKey.PubKey,
		)
		if err != nil {
			return nil, err
		}

		sproutedAsset.ScriptKey.TweakedScriptKey = tweakedScriptKey
		if sproutedAsset.GroupKey != nil {
			assetGroup, err := refs.FetchGroupByGroupKey(
				ctx, &sproutedAsset.GroupKey.GroupPubKey,
			)
			if err != nil {
				return nil, err
			}

			sproutedAsset.GroupKey = assetGroup.GroupKey
		}

		batchAssets = append(batchAssets, &sproutedAsset)
		scriptKey := asset.ToSerialized(sproutedAsset.ScriptKey.PubKey)
		assetMetas[scriptKey] = seedling.Meta
	}

	// Verify that we can reconstruct the genesis output script used in the
	// anchor TX.
	batchSibling := batch.TapSibling()
	var tapSibling *chainhash.Hash
	if len(batchSibling) != 0 {
		var err error
		tapSibling, err = chainhash.NewHash(batchSibling)
		if err != nil {
			return nil, err
		}
	}

	tapCommitment, err := VerifyOutputScript(
		batch.BatchKey.PubKey, tapSibling, genScript, batchAssets,
	)

	if err != nil {
		return nil, err
	}

	// With the batch assets validated, construct the populated finalized
	// batch.
	batch.Seedlings = nil
	finalizedBatch := batch.Copy()
	finalizedBatch.RootAssetCommitment = tapCommitment
	finalizedBatch.AssetMetas = assetMetas

	return finalizedBatch, nil
}

// ListBatches returns the single batch specified by the batch key, or the set
// of batches not yet finalized on disk.
func listBatches(ctx context.Context, batchStore BatchStore,
	refs MintingRefReader, archiver proof.Archiver,
	genBuilder asset.GenesisTxBuilder,
	params ListBatchesParams) ([]*VerboseBatch, error) {

	var (
		batches []*MintingBatch
		err     error
	)

	switch {
	case params.BatchKey == nil:
		batches, err = batchStore.FetchAllBatches(ctx)
	default:
		var batch *MintingBatch
		batch, err = batchStore.FetchMintingBatch(ctx, params.BatchKey)
		batches = []*MintingBatch{batch}
	}
	if err != nil {
		return nil, err
	}

	var (
		finalBatches, nonFinalBatches = filterFinalizedBatches(batches)
		sortedBatches                 []*MintingBatch
	)

	switch {
	case len(finalBatches) == 0:
		sortedBatches = batches

	// For finalized batches, we need to fetch the assets from the proof
	// archiver, not the DB.
	default:
		finalizedBatches := make([]*MintingBatch, 0, len(finalBatches))
		for _, batch := range finalBatches {
			finalizedBatch, err := fetchFinalizedBatch(
				ctx, refs, archiver, batch,
			)
			if err != nil {
				return nil, err
			}

			finalizedBatches = append(
				finalizedBatches, finalizedBatch,
			)
		}

		// Re-sort the batches by creation time for consistent display.
		allBatches := append(nonFinalBatches, finalizedBatches...)
		slices.SortFunc(allBatches, func(a, b *MintingBatch) int {
			return a.CreationTime.Compare(b.CreationTime)
		})

		sortedBatches = allBatches
	}

	// Return the batches without any extra asset group info.
	if !params.Verbose {
		batches := fn.Map(
			sortedBatches,
			func(b *MintingBatch) *VerboseBatch {
				return &VerboseBatch{
					MintingBatch:      b,
					UnsealedSeedlings: nil,
				}
			},
		)

		return batches, nil
	}

	// Formulate verbose batches from the sorted batches.
	verboseBatches := make([]*VerboseBatch, 0, len(sortedBatches))

	for idx := range sortedBatches {
		currentBatch := sortedBatches[idx]

		// The batch must be pending, funded, and have seedlings for us
		// to show pending asset group information.
		switch {
		case currentBatch.State() != BatchStatePending:
			continue
		case !currentBatch.IsFunded():
			// The batch isn't funded yet, so we can't display any
			// pending asset group information. Funding is required
			// because the anchor transaction outpoint is needed to
			// formulate pending asset group key requests.
			continue
		case len(currentBatch.Seedlings) == 0:
			continue
		default:
		}

		verboseBatch, err := newVerboseBatch(currentBatch, genBuilder)
		if err != nil {
			return nil, err
		}

		verboseBatches = append(verboseBatches, verboseBatch)
	}

	return verboseBatches, nil
}

// newVerboseBatch constructs a new verbose batch from a given minting batch.
// The verbose batch includes extra information about the asset group, if any.
func newVerboseBatch(currentBatch *MintingBatch,
	genBuilder asset.GenesisTxBuilder) (*VerboseBatch, error) {

	verboseBatch := &VerboseBatch{
		MintingBatch: currentBatch.Copy(),
	}

	// Filter the batch seedlings to only consider those that will become
	// grouped assets. If there are no such seedlings, then there is no
	// extra information to add.
	groupSeedlings, _ := filterSeedlingsWithGroup(
		currentBatch.Seedlings,
	)
	if len(groupSeedlings) == 0 {
		return verboseBatch, nil
	}

	// Before we can build the group key requests for each seedling, we must
	// fetch the genesis point and anchor index for the batch.
	anchorOutputIndex := currentBatch.GenesisPacket.AssetAnchorOutIdx

	genesisPkt := currentBatch.GenesisPacket
	genesisPoint, err := genesisPkt.GenesisOutpoint().UnwrapOrErr(
		ErrFundedAnchorPsbtMissingOutpoint,
	)
	if err != nil {
		return nil, err
	}

	// Construct the group key requests and group virtual TXs for each
	// seedling. With these we can verify provided asset group witnesses, or
	// attempt to derive asset group witnesses if needed.
	groupReqs, genTXs, err := buildGroupReqs(
		genesisPoint, anchorOutputIndex, genBuilder, groupSeedlings,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to build group requests: %w",
			err)
	}

	if len(groupReqs) != len(genTXs) {
		return nil, fmt.Errorf("mismatched number of group requests " +
			"and virtual TXs")
	}

	// Copy existing seedlings into the unsealed seedling map; we'll clear
	// the batch seedlings after adding group information.
	verboseBatch.UnsealedSeedlings = make(
		map[string]*UnsealedSeedling,
		len(currentBatch.Seedlings),
	)
	for k, v := range currentBatch.Seedlings {
		verboseBatch.UnsealedSeedlings[k] = &UnsealedSeedling{
			Seedling:          v,
			PendingAssetGroup: nil,
		}
	}

	// Match each group key request and group virtual TX with the
	// corresponding seedling.
	for i := 0; i < len(groupReqs); i++ {
		seedlingName := groupReqs[i].NewAsset.Genesis.Tag
		seedling, ok := verboseBatch.
			UnsealedSeedlings[seedlingName]
		if !ok {
			return nil, fmt.Errorf("unable to find seedling with "+
				"tag matching asset group: %s", seedlingName)
		}

		seedling.PendingAssetGroup = &PendingAssetGroup{
			KeyRequest: groupReqs[i],
			VirtualTx:  genTXs[i],
		}
	}

	// Clear the original batch seedlings so each asset is only represented
	// once.
	verboseBatch.Seedlings = nil

	return verboseBatch, nil
}

// canCancelBatch returns a batch key if the planter is in a state where a batch
// can be cancelled. This does not account for the state of a cultivator that
// may be managing a batch.
func (c *ChainPlanter) canCancelBatch() (*btcec.PublicKey, error) {
	cultivatorCount := len(c.cultivators)

	switch cultivatorCount {
	case 0:
		// If there are no cultivators, the only batch we could cancel
		// would be the current pending batch.
		if c.pendingBatch == nil {
			return nil, fmt.Errorf("no pending batch")
		}

		return c.pendingBatch.BatchKey.PubKey, nil
	case 1:
		// If there is exactly one cultivator, our pending batch
		// must be empty for the cancel target to be
		// unambiguous. Both can coexist legitimately: the
		// cultivator may be handling a post-broadcast batch
		// (Committed/Broadcast/Confirmed) while a fresh
		// Pending/Frozen batch has begun in c.pendingBatch. The
		// singleton constraint added in migration 000060 only
		// applies to {Pending, Frozen}, so this case is real,
		// not unreachable.
		if c.pendingBatch != nil {
			return nil, fmt.Errorf("cancellation ambiguous: " +
				"pending batch and an active cultivator " +
				"coexist; cancel-by-batch-key not " +
				"implemented")
		}

		batchKeys := maps.Keys(c.cultivators)
		batchKey, err := btcec.ParsePubKey(batchKeys[0][:])
		if err != nil {
			return nil, fmt.Errorf("bad cultivator key: %w", err)
		}

		return batchKey, nil
	default:
	}

	// Multiple cultivators can coexist when several post-broadcast
	// batches are awaiting confirmation in parallel. The singleton
	// constraint added in migration 000060 does not forbid this; it
	// only constrains {Pending, Frozen}.
	return nil, fmt.Errorf("cancellation ambiguous: %d active "+
		"cultivators; cancel-by-batch-key not implemented",
		cultivatorCount)
}

// cancelMintingBatch attempts to cancel a target minting batch. This can fail
// if the batch is managed by a cultivator and has already been broadcast.
func (c *ChainPlanter) cancelMintingBatch(ctx context.Context,
	batchKey *btcec.PublicKey) error {

	// The target batch may have already been assigned a cultivator. If so,
	// we need to signal to the cultivator to cancel the batch.
	batchKeySerialized := asset.ToSerialized(batchKey)
	cultivator, ok := c.cultivators[batchKeySerialized]
	if ok {
		log.Infof("Cancelling MintingBatch(key=%x, num_assets=%v)",
			batchKeySerialized, len(cultivator.cfg.Batch.Seedlings))

		// Per-call reply channel: the cultivator writes the result
		// of this specific request here. Buffer size 1 so the
		// cultivator never blocks if we abandon the wait via c.Quit.
		respCh := make(chan CancelResp, 1)
		cultivator.cfg.CancelReqChan <- cancelReq{resp: respCh}

		// Wait for the cultivator to reply to the cancellation request.
		// If the request succeeded, the cultivator will update the
		// batch state on disk.
		select {
		case cancelResp := <-respCh:
			// If the cultivator returned a batch state, then batch
			// cancellation was possible and attempted. This means
			// that the cultivator is shut down and the planter
			// must delete it.
			if cancelResp.cancelAttempted {
				delete(c.cultivators, batchKeySerialized)
			}

			return cancelResp.err

		case <-c.Quit:
			return nil
		}
	}

	log.Infof("Cancelling MintingBatch(key=%x, num_assets=%v)",
		batchKeySerialized, len(c.pendingBatch.Seedlings))

	// If the target batch was not assigned a cultivator, the only
	// non-cancelled batch in play is c.pendingBatch (canCancelBatch
	// guarantees this). Update the batch state on disk and in memory in
	// a single atomic call.
	err := c.cfg.BatchStore.UpdateBatchState(
		ctx, c.pendingBatch, BatchStateSeedlingCancelled,
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
	// active cultivators as well.
	defer c.stopCultivators()

	log.Infof("Gardener for ChainPlanter now active!")

	for {
		select {
		// A request for new asset issuance just arrived, add this to
		// the pending batch and acknowledge the receipt back to the
		// caller.
		case req := <-c.seedlingReqs:
			// After some basic validation, prepare the asset
			// seedling (soon to be a sprout) by committing it to
			// disk as part of the latest batch.
			//
			// This method will also include the seedling in any
			// existing pending batch or create a new pending batch
			// if necessary.
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

			// Copy the pending batch to prevent potential
			// concurrent read/write issues.
			var batchCopy *MintingBatch
			if c.pendingBatch != nil {
				batchCopy = c.pendingBatch.Copy()
			}
			req.updates <- SeedlingUpdate{
				PendingBatch: batchCopy,
			}

		// A cultivator has finished processing their batch to full
		// Taproot Asset maturity. We'll clean up our local state, and
		// signal that it can exit.
		//
		// TODO(roasbeef): also need a channel to send out additional
		// notifications?
		case batchKey := <-c.completionSignals:
			cultivator, ok := c.cultivators[batchKey]
			if !ok {
				log.Warnf("Unknown cultivator: %x", batchKey[:])
				continue
			}

			log.Infof("Cultivator(%x) has finished", batchKey[:])

			if err := cultivator.Stop(); err != nil {
				log.Warnf("Unable to stop cultivator: %v", err)
			}

			delete(c.cultivators, batchKey)

			// TODO(roasbeef): send completion signal?

		// A new request just came along to query or mutate our
		// internal state. Each request is a closure that already
		// carries its own response channel and parameters; we
		// simply invoke it in this goroutine.
		case req := <-c.stateReqs:
			req()

		case <-c.Quit:
			return
		}
	}
}

// fundingPrep stores a tapscript-sibling root hash (already persisted
// to the tree store) and a closure that computes a funded mint anchor
// PSBT for a given batch without mutating it. Both fields are
// populated by prepareFunding and consumed by createFundedBatch /
// applyFundingToBatch.
type fundingPrep struct {
	// rootHash is the persisted root hash of the optional tapscript
	// sibling supplied via FundParams. nil if no sibling was given.
	rootHash *chainhash.Hash

	// computeFunding builds the funded genesis PSBT for a batch
	// without mutating it. Callers must apply the result only after
	// all persistence has succeeded, so a failure leaves the batch
	// unchanged.
	computeFunding func(batch *MintingBatch) (*FundedMintAnchorPsbt,
		error)
}

// prepareFunding stores the optional tapscript sibling and constructs
// the funding-computation closure shared by createFundedBatch and
// applyFundingToBatch.
func (c *ChainPlanter) prepareFunding(ctx context.Context,
	params FundParams) (fundingPrep, error) {

	var (
		zero     fundingPrep
		rootHash *chainhash.Hash
		err      error
	)

	// If a tapscript tree was specified for this batch, we'll store
	// it on disk. The cultivator we start for this batch will use it
	// when deriving the final Taproot output key.
	params.SiblingTapTree.WhenSome(func(tn asset.TapscriptTreeNodes) {
		rootHash, err = c.cfg.TreeStore.StoreTapscriptTree(ctx, tn)
	})
	if err != nil {
		return zero, fmt.Errorf("unable to store tapscript tree "+
			"for minting batch: %w", err)
	}

	computeFunding := func(batch *MintingBatch) (
		*FundedMintAnchorPsbt, error) {

		feeRate, err := c.anchorTxFeeRate(ctx, params.FeeRate)
		if err != nil {
			return nil, fmt.Errorf("unable to determine anchor "+
				"TX fee rate: %w", err)
		}

		batchKey := asset.ToSerialized(batch.BatchKey.PubKey)

		// walletFundPsbt is a closure that will be used to fund
		// the batch with the specified fee rate.
		walletFundPsbt := func(ctx context.Context,
			anchorPkt psbt.Packet) (tapsend.FundedPsbt, error) {

			var zero tapsend.FundedPsbt

			fundedPkt, err := c.cfg.Wallet.FundPsbt(
				ctx, &anchorPkt, 1, feeRate, -1,
			)
			if err != nil {
				return zero, err
			}

			return *fundedPkt, nil
		}

		log.Infof("Attempting to fund batch: %x", batchKey)
		mintAnchorTx, err := fundGenesisPsbt(
			ctx, c.cfg.ChainParams, batch, walletFundPsbt,
			c.augmenter(),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fund minting PSBT "+
				"for batch: %x %w", batchKey[:], err)
		}

		log.Infof("Funded GenesisPacket for batch: %x", batchKey)
		return &mintAnchorTx, nil
	}

	return fundingPrep{
		rootHash:       rootHash,
		computeFunding: computeFunding,
	}, nil
}

// createFundedBatch derives a fresh minting batch, computes its
// funding, and persists the funded batch to disk as a single new row.
// On any failure no new batch is committed and no in-memory state is
// touched; the caller may try again. The returned batch is ready to
// be installed as c.pendingBatch by the caller.
//
// NOTE: This is the create half of what used to be a single fundBatch
// function with two purposes. The split exists so that "create a new
// funded batch" cannot be silently dispatched into "update an
// existing batch's funding" (or vice-versa) by callers passing a
// stale or wrong reference -- the bug shape behind #2136.
func (c *ChainPlanter) createFundedBatch(ctx context.Context,
	params FundParams) (*MintingBatch, error) {

	prep, err := c.prepareFunding(ctx, params)
	if err != nil {
		return nil, err
	}

	newBatch, err := c.newBatch()
	if err != nil {
		return nil, fmt.Errorf("unable to create new batch: %w", err)
	}

	mintAnchorTx, err := prep.computeFunding(newBatch)
	if err != nil {
		return nil, err
	}

	// Apply the funding to the local batch and commit. If the
	// commit fails, newBatch is discarded and the caller's planter
	// state is never assigned.
	newBatch.GenesisPacket = mintAnchorTx
	if prep.rootHash != nil {
		newBatch.tapSibling = prep.rootHash
	}

	// The augmenter is the source of truth for the persistence
	// payload (formerly read off
	// newBatch.GenesisPacket.PreCommitmentOutput); it derives
	// the row from the batch's current state.
	preCommit, err := c.augmenter().BindData(ctx, newBatch)
	if err != nil {
		return nil, fmt.Errorf("augmenter BindData: %w", err)
	}
	err = c.cfg.BatchStore.CommitMintingBatch(ctx, newBatch, preCommit)
	if err != nil {
		return nil, err
	}

	return newBatch, nil
}

// applyFundingToBatch computes funding for an existing on-disk batch,
// persists the funding atomically (sibling + genesis TX in one DB
// transaction), and only then mirrors the funding into the in-memory
// batch. On any failure neither disk nor memory is mutated.
//
// NOTE: This is the update half of the former fundBatch. It must
// never be called with a batch that has not yet been written to disk
// -- use createFundedBatch for that case.
func (c *ChainPlanter) applyFundingToBatch(ctx context.Context,
	params FundParams, batch *MintingBatch) error {

	if batch == nil {
		return fmt.Errorf("applyFundingToBatch requires non-nil " +
			"batch; use createFundedBatch to create a new one")
	}

	prep, err := c.prepareFunding(ctx, params)
	if err != nil {
		return err
	}

	mintAnchorTx, err := prep.computeFunding(batch)
	if err != nil {
		return err
	}

	// The augmenter is consulted for the persistence payload --
	// it scans the freshly-funded PSBT for its own output and
	// returns the typed row. Currently
	// applyFundingToBatch is called before the batch's
	// GenesisPacket has been mirrored back into the in-memory
	// batch, so we attach mintAnchorTx temporarily so the
	// augmenter can read the funded PSBT off it.
	stagingBatch := *batch
	stagingBatch.GenesisPacket = mintAnchorTx
	preCommit, err := c.augmenter().BindData(ctx, &stagingBatch)
	if err != nil {
		return fmt.Errorf("augmenter BindData: %w", err)
	}

	// Persist the sibling, genesis TX, and (when present) the
	// supply-pre-commit row atomically. Combining the writes in a
	// single transaction ensures a partial failure cannot leave
	// the batch with one persisted and the others absent.
	err = c.cfg.BatchStore.CommitBatchFunding(
		ctx, batch.BatchKey.PubKey, prep.rootHash, *mintAnchorTx,
		preCommit,
	)
	if err != nil {
		return fmt.Errorf("unable to commit batch funding: %w", err)
	}

	// All persistence succeeded; mirror the funding into memory.
	batch.GenesisPacket = mintAnchorTx
	if prep.rootHash != nil {
		batch.tapSibling = prep.rootHash
	}

	return nil
}

// fundPendingBatch funds c.pendingBatch, creating it first if it does
// not yet exist. This is the convenience wrapper used by the
// gardener's fund-batch request handler and by finalizeBatch; both
// have the same "I want the pending batch funded, regardless of
// whether it exists yet" semantics. c.pendingBatch is updated only on
// success of the create path; the update path mutates the existing
// batch in place via applyFundingToBatch.
func (c *ChainPlanter) fundPendingBatch(ctx context.Context,
	params FundParams) error {

	if c.pendingBatch == nil {
		newBatch, err := c.createFundedBatch(ctx, params)
		if err != nil {
			return err
		}

		c.pendingBatch = newBatch
		return nil
	}

	return c.applyFundingToBatch(ctx, params, c.pendingBatch)
}

// matchPsbtToGroupReq attempts to match a signed group virtual PSBT to a
// corresponding group key request.
func matchPsbtToGroupReq(psbt psbt.Packet,
	groupReqs []asset.GroupKeyRequest) (fn.Option[asset.GroupKeyRequest],
	error) {

	// Sanity check PSBT.
	if len(psbt.Inputs) != 1 {
		return fn.None[asset.GroupKeyRequest](), fmt.Errorf(
			"PSBT must have a single input")
	}

	psbtInPrevOut := psbt.UnsignedTx.TxIn[0].PreviousOutPoint

	// Match the signed PSBT to the corresponding group request.
	for idxReq := range groupReqs {
		req := groupReqs[idxReq]

		// Formulate the group virtual TX for the group key request so
		// we can extract the previous output.
		tx, err := req.BuildGroupVirtualTx(
			&tapscript.GroupTxBuilder{},
		)
		if err != nil {
			return fn.None[asset.GroupKeyRequest](), err
		}

		// Sanity check that the group virtual TX.
		if len(tx.Tx.TxIn) != 1 {
			return fn.None[asset.GroupKeyRequest](), fmt.Errorf(
				"group virtual TX must have a single input")
		}
		vTxInPrevOut := tx.Tx.TxIn[0].PreviousOutPoint

		// If the previous output of the signed PSBT matches the
		// previous output of the group virtual TX, we have a match.
		if vTxInPrevOut.Hash == psbtInPrevOut.Hash {
			return fn.Some(req), nil
		}
	}

	return fn.None[asset.GroupKeyRequest](), nil
}

// sealBatch will verify that each grouped asset in the pending batch has an
// asset group witness, and will attempt to create asset group witnesses when
// possible if they are not provided. After all asset group witnesses have been
// validated, they are saved to disk to be used by the cultivator during batch
// finalization.
func (c *ChainPlanter) sealBatch(ctx context.Context, params SealParams,
	workingBatch *MintingBatch) (*MintingBatch, error) {

	// A batch should exist with 1+ seedlings and be funded before being
	// sealed.
	if !workingBatch.HasSeedlings() {
		return nil, fmt.Errorf("no seedlings in batch")
	}

	if !workingBatch.IsFunded() {
		return nil, fmt.Errorf("batch is not funded")
	}

	// Filter the batch seedlings to only consider those that will become
	// grouped assets. If there are no such seedlings, then there is nothing
	// to seal and no action is needed.
	groupSeedlings, _ := filterSeedlingsWithGroup(workingBatch.Seedlings)
	if len(groupSeedlings) == 0 {
		return workingBatch, nil
	}

	// Before we can build the group key requests for each seedling, we must
	// fetch the genesis point and anchor index for the batch.
	workingGenesisPkt := workingBatch.GenesisPacket
	anchorOutputIndex := workingGenesisPkt.AssetAnchorOutIdx

	genesisPoint, err := workingGenesisPkt.GenesisOutpoint().UnwrapOrErr(
		ErrFundedAnchorPsbtMissingOutpoint,
	)
	if err != nil {
		return nil, err
	}

	// Check if the batch is already sealed by picking a random grouped
	// seedling and trying to fetch the full asset group.
	var singleSeedling []*Seedling
	for _, seedling := range groupSeedlings {
		singleSeedling = append(singleSeedling, seedling)
		break
	}

	// If the batch was previously sealed, each grouped seedling will have
	// its asset genesis already stored on disk.
	existingGroups, err := c.cfg.BatchStore.FetchSeedlingGroups(
		ctx, genesisPoint, anchorOutputIndex, singleSeedling,
	)

	switch {
	case len(existingGroups) != 0:
		return nil, ErrBatchAlreadySealed
	case err != nil:
		// The only expected error is for a missing asset genesis.
		if !errors.Is(err, ErrNoGenesis) {
			return nil, err
		}
	}

	// Construct the group key requests and group virtual TXs for each
	// seedling. With these we can verify provided asset group witnesses,
	// or attempt to derive asset group witnesses if needed.
	groupReqs, genTXs, err := buildGroupReqs(
		genesisPoint, anchorOutputIndex, c.cfg.GenTxBuilder,
		groupSeedlings,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to build group requests: "+
			"%w", err)
	}
	if len(groupReqs) != len(genTXs) {
		return nil, fmt.Errorf("mismatched number of group requests " +
			"and virtual TXs")
	}

	// Each provided group witness must have a corresponding seedling in the
	// current batch.
	seedlingAssetIDs := fn.NewSet(fn.Map(
		groupReqs, func(req asset.GroupKeyRequest) asset.ID {
			return req.NewAsset.ID()
		})...,
	)

	externalWitnesses := make(map[asset.ID]PendingGroupWitness)
	for _, wit := range params.GroupWitnesses {
		if !seedlingAssetIDs.Contains(wit.GenID) {
			return nil, fmt.Errorf("witness has no matching "+
				"seedling: %v", wit)
		}

		externalWitnesses[wit.GenID] = wit
	}

	// Extract witnesses from signed group virtual PSBTs.
	for idxPsbt := range params.SignedGroupVirtualPsbts {
		psbtPacket := params.SignedGroupVirtualPsbts[idxPsbt]

		// Match the signed PSBT to the corresponding group request.
		groupReqMatch, err := matchPsbtToGroupReq(
			psbtPacket, groupReqs,
		)
		if err != nil {
			return nil, fmt.Errorf("encountered error while "+
				"matching signed PSBT to group request: %w",
				err)
		}

		// Ensure that a matching group key reveal has been found.
		if groupReqMatch.IsNone() {
			return nil, fmt.Errorf("failed to find matching " +
				"group key request for signed group virtual " +
				"PSBT")
		}

		// Ensure that an external witness has not already been
		// specified for the given genesis asset ID.
		genesisAssetID := fn.MapOptionZ(
			groupReqMatch,
			func(req asset.GroupKeyRequest) asset.ID {
				return req.NewAsset.ID()
			},
		)

		if _, ok := externalWitnesses[genesisAssetID]; ok {
			return nil, fmt.Errorf("signed PSBT is a duplicate "+
				"witness for asset ID: %v", genesisAssetID)
		}

		// Finalize the signed PSBT.
		err = psbt.MaybeFinalizeAll(&psbtPacket)
		if err != nil {
			return nil, fmt.Errorf("unable to finalize signed "+
				"PSBT for asset ID: %v, %w", genesisAssetID,
				err)
		}

		// Extract the signed transaction from the PSBT.
		tx, err := psbt.Extract(&psbtPacket)
		if err != nil {
			return nil, fmt.Errorf("unable to extract signed "+
				"PSBT for asset ID: %v, %w", genesisAssetID,
				err)
		}

		if len(tx.TxIn) != 1 {
			return nil, fmt.Errorf("expected exactly 1 input in "+
				"signed PSBT for asset ID: %v", genesisAssetID)
		}

		// Add the witness to the set of external witnesses.
		externalWitnesses[genesisAssetID] = PendingGroupWitness{
			GenID:   genesisAssetID,
			Witness: tx.TxIn[0].Witness,
		}
	}

	// Formulate new asset groups from the group key requests.
	newAssetGroups := make([]*asset.AssetGroup, 0, len(groupReqs))
	for i := 0; i < len(groupReqs); i++ {
		var (
			genTX      = genTXs[i]
			groupReq   = groupReqs[i]
			protoAsset = groupReq.NewAsset
			groupKey   *asset.GroupKey
			err        error
		)

		// Check for an externally-provided asset group witness before
		// trying to derive a witness.
		reqAssetID := protoAsset.ID()
		groupWitness, ok := externalWitnesses[reqAssetID]
		switch {
		case ok:
			// Set the provided witness; it will be validated below.
			subtreeRoot := groupReq.CustomTapscriptRoot
			groupKey = &asset.GroupKey{
				Version:             groupReq.Version,
				RawKey:              groupReq.RawKey,
				GroupPubKey:         genTX.TweakedKey,
				TapscriptRoot:       groupReq.TapscriptRoot,
				CustomTapscriptRoot: subtreeRoot,
				Witness:             groupWitness.Witness,
			}

		default:
			// Derive the asset group witness.
			groupKey, err = asset.DeriveGroupKey(
				c.cfg.GenSigner, genTX, groupReq, nil,
			)
			if err != nil {
				return nil, err
			}
		}
		// Recreate the asset with the populated group key and validate
		// the asset group witness.
		groupedAsset, err := asset.New(
			protoAsset.Genesis, protoAsset.Amount,
			protoAsset.LockTime, protoAsset.RelativeLockTime,
			protoAsset.ScriptKey, groupKey,
			asset.WithAssetVersion(protoAsset.Version),
		)
		if err != nil {
			return nil, err
		}

		// Validate the asset with the Taproot Assets VM. Lock times in
		// the group key scripts are checked against the current block
		// height. And CSV (relative lock times) don't make sense in
		// the context of a group key script (since there's no input to
		// verify against), so those will fail anyway. So we don't
		// provide a proof as context to the chain lookup, which will
		// definitely cause any CSV checks to fail.
		noProofLookup := c.cfg.ChainBridge.GenFileChainLookup(nil)
		err = c.cfg.TxValidator.Execute(
			groupedAsset, nil, nil, noProofLookup,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to verify asset group "+
				"witness: %s, %w", reqAssetID.String(), err)
		}

		newGroup := &asset.AssetGroup{
			Genesis:  &protoAsset.Genesis,
			GroupKey: groupKey,
		}

		newAssetGroups = append(newAssetGroups, newGroup)
	}

	// Assign each newly created asset group to its corresponding seedling.
	batchWithGroupInfo := workingBatch.Copy()
	for _, group := range newAssetGroups {
		assetName := group.Genesis.Tag
		batchWithGroupInfo.Seedlings[assetName].GroupInfo = group
	}

	// The supply-commit augmenter rediscovers the group-key
	// metadata directly from the (now group-keyed) seedlings
	// when it constructs the persistence payload below; no
	// separate "stamp the group key onto PreCommitmentOutput"
	// step is needed.

	// With all the asset group witnesses validated, we can now
	// save them to disk effectively sealing the batch. The
	// augmenter recomputes its persistence payload off the
	// batch's current state -- by seal time the group key has
	// typically been derived, so the row will be refreshed
	// with it.
	sealPreCommit, err := c.augmenter().BindData(ctx, batchWithGroupInfo)
	if err != nil {
		return nil, fmt.Errorf("augmenter BindData: %w", err)
	}
	err = c.cfg.BatchStore.SealBatch(
		ctx, batchWithGroupInfo, newAssetGroups, sealPreCommit,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to write seedling groups: "+
			"%w", err)
	}

	return batchWithGroupInfo, nil
}

// finalizeBatch creates a new cultivator for the batch and starts it.
func (c *ChainPlanter) finalizeBatch(params FinalizeParams) (*Cultivator,
	error) {

	var (
		feeRate *chainfee.SatPerKWeight
		err     error
	)

	// Before modifying the pending batch, check if the batch was already
	// funded. If so, reject any provided parameters, as they would conflict
	// with those previously used for batch funding.
	haveParams := params.FeeRate.IsSome() || params.SiblingTapTree.IsSome()
	if haveParams && c.pendingBatch.IsFunded() {
		return nil, fmt.Errorf("cannot provide finalize parameters " +
			"if batch already funded")
	}

	// Process the finalize parameters.
	feeRate = params.FeeRate.UnwrapToPtr()

	ctx, cancel := c.WithCtxQuit()
	defer cancel()

	params.SiblingTapTree.WhenSome(func(tn asset.TapscriptTreeNodes) {
		_, err = c.cfg.TreeStore.StoreTapscriptTree(ctx, tn)
	})

	if err != nil {
		return nil, fmt.Errorf("unable to store tapscript tree for "+
			"minting batch: %w", err)
	}
	// Fund the batch if it hasn't been funded yet. If funding
	// fails, the batch stays pending so the user can retry.
	//
	// finalizeBatch is only reached when c.pendingBatch is
	// non-nil (the gardener short-circuits with an error
	// otherwise), so the "create" path of fundPendingBatch is
	// not exercised here; calling fundPendingBatch keeps the
	// dispatch in one place rather than re-checking pending-ness
	// here.
	if !c.pendingBatch.IsFunded() {
		err = c.fundPendingBatch(ctx, FundParams(params))
		if err != nil {
			return nil, err
		}
	}

	// If the batch needs to be sealed, we'll use the default
	// behavior for generating asset group witnesses. Any custom
	// behavior requires calling SealBatch() explicitly, before
	// batch finalization.
	sealedBatch, err := c.sealBatch(
		ctx, SealParams{}, c.pendingBatch,
	)
	if err != nil {
		if !errors.Is(err, ErrBatchAlreadySealed) {
			return nil, err
		}
	}

	// If seal batch executed successfully, and returned a
	// sealed batch, then we can update the pending batch.
	if err == nil && sealedBatch != nil {
		c.pendingBatch = sealedBatch
	}

	// Now that funding and sealing have succeeded, freeze the
	// batch on disk and in memory. This means no further
	// seedlings can be added to this batch. freezeMintingBatch
	// updates both the on-disk row and the in-memory state in a
	// single atomic step via the BatchStore.
	err = freezeMintingBatch(ctx, c.cfg.BatchStore, c.pendingBatch)
	if err != nil {
		return nil, err
	}
	cultivator := c.newCultivatorForBatch(c.pendingBatch, feeRate)
	if err := cultivator.Start(); err != nil {
		return nil, fmt.Errorf("unable to start new cultivator: %w", err)
	}

	return cultivator, nil
}

// dispatchStateReq sends a closure to the gardener loop and waits
// for its typed result. The closure runs inside the loop's
// goroutine with full access to ChainPlanter state. Returns a
// shutdown error if the planter quits before the request can be
// sent or its response received.
func dispatchStateReq[T any](c *ChainPlanter,
	handler func(out chan<- stateResult[T])) (T, error) {

	var zero T
	out := make(chan stateResult[T], 1)
	req := stateReq(func() { handler(out) })

	if !fn.SendOrQuit(c.stateReqs, req, c.Quit) {
		return zero, fmt.Errorf("chain planter shutting down")
	}

	select {
	case r := <-out:
		return r.val, r.err
	case <-c.Quit:
		return zero, fmt.Errorf("chain planter shutting down")
	}
}

// PendingBatch returns the current pending batch, or nil if no batch is
// pending.
func (c *ChainPlanter) PendingBatch() (*MintingBatch, error) {
	return dispatchStateReq(
		c, func(out chan<- stateResult[*MintingBatch]) {
			// Resolve a copy of the state to prevent potential
			// concurrent read/write issues.
			if c.pendingBatch == nil {
				out <- stateOk[*MintingBatch](nil)
				return
			}
			out <- stateOk(c.pendingBatch.Copy())
		},
	)
}

// NumActiveBatches returns the total number of active batches that have an
// outstanding cultivator assigned.
func (c *ChainPlanter) NumActiveBatches() (int, error) {
	return dispatchStateReq(c, func(out chan<- stateResult[int]) {
		out <- stateOk(len(c.cultivators))
	})
}

// ListBatches returns the single batch specified by the batch key, or the set
// of batches not yet finalized on disk.
func (c *ChainPlanter) ListBatches(params ListBatchesParams) ([]*VerboseBatch,
	error) {

	return dispatchStateReq(
		c, func(out chan<- stateResult[[]*VerboseBatch]) {
			ctx, cancel := c.WithCtxQuit()
			batches, err := listBatches(
				ctx, c.cfg.BatchStore, c.cfg.MintingRefs,
				c.cfg.ProofFiles, c.cfg.GenTxBuilder, params,
			)
			cancel()
			if err != nil {
				out <- stateErr[[]*VerboseBatch](err)
				return
			}
			out <- stateOk(batches)
		},
	)
}

// FundBatch sends a signal to the planter to fund the current batch, or create
// a funded batch.
func (c *ChainPlanter) FundBatch(params FundParams) (*VerboseBatch, error) {
	return dispatchStateReq(
		c, func(out chan<- stateResult[*VerboseBatch]) {
			if c.pendingBatch != nil &&
				c.pendingBatch.IsFunded() {

				out <- stateErr[*VerboseBatch](fmt.Errorf(
					"batch already funded",
				))
				return
			}

			ctx, cancel := c.WithCtxQuit()
			err := c.fundPendingBatch(ctx, params)
			cancel()
			if err != nil {
				out <- stateErr[*VerboseBatch](fmt.Errorf(
					"unable to fund minting batch: %w",
					err,
				))
				return
			}

			verboseBatch, err := newVerboseBatch(
				c.pendingBatch, c.cfg.GenTxBuilder,
			)
			if err != nil {
				out <- stateErr[*VerboseBatch](err)
				return
			}

			out <- stateOk(verboseBatch)
		},
	)
}

// SealBatch attempts to seal the current batch, by providing or deriving all
// witnesses necessary to create the final genesis TX.
func (c *ChainPlanter) SealBatch(params SealParams) (*MintingBatch, error) {
	return dispatchStateReq(
		c, func(out chan<- stateResult[*MintingBatch]) {
			if c.pendingBatch == nil {
				out <- stateErr[*MintingBatch](fmt.Errorf(
					"no pending batch",
				))
				return
			}

			ctx, cancel := c.WithCtxQuit()
			sealedBatch, err := c.sealBatch(
				ctx, params, c.pendingBatch,
			)
			cancel()
			if err != nil {
				out <- stateErr[*MintingBatch](fmt.Errorf(
					"unable to seal minting batch: %w",
					err,
				))
				return
			}

			if sealedBatch != nil {
				c.pendingBatch = sealedBatch
			}

			// Resolve a copy of the state to prevent potential
			// concurrent read/write issues.
			if c.pendingBatch == nil {
				out <- stateOk[*MintingBatch](nil)
				return
			}
			out <- stateOk(c.pendingBatch.Copy())
		},
	)
}

// FinalizeBatch sends a signal to the planter to finalize the current batch.
func (c *ChainPlanter) FinalizeBatch(params FinalizeParams) (*MintingBatch,
	error) {

	return dispatchStateReq(
		c, func(out chan<- stateResult[*MintingBatch]) {
			if c.pendingBatch == nil {
				out <- stateErr[*MintingBatch](fmt.Errorf(
					"no pending batch",
				))
				return
			}

			batchKey := c.pendingBatch.BatchKey.PubKey
			batchKeySerial := asset.ToSerialized(batchKey)
			log.Infof("Finalizing batch %x", batchKeySerial)

			cultivator, err := c.finalizeBatch(params)
			if err != nil {
				freezeErr := fmt.Errorf("unable to finalize "+
					"minting batch: %w", err)
				log.Warnf(freezeErr.Error())
				out <- stateErr[*MintingBatch](freezeErr)
				return
			}

			// Wait for the cultivator to either broadcast the
			// batch or fail to do so.
			select {
			case <-cultivator.cfg.BroadcastCompleteChan:
				// Snapshot the cultivator's live batch before
				// handing it to the caller. The cultivator
				// goroutine continues to mutate
				// Batch.GenesisPacket and
				// Batch.RootAssetCommitment after this point
				// (Broadcast -> Confirmed -> Finalized);
				// returning the live pointer would race
				// those writes against any read the caller
				// does.
				out <- stateOk(cultivator.cfg.Batch.Copy())

			case err := <-cultivator.cfg.BroadcastErrChan:
				out <- stateErr[*MintingBatch](err)

				// Unrecoverable error, stop cultivator
				// directly. The pending batch will not be
				// saved.
				stopErr := cultivator.Stop()
				if stopErr != nil {
					log.Warnf("Unable to stop cultivator "+
						"gracefully: %v", err)
				}

				delete(c.cultivators, batchKeySerial)

				// Cancel the failed batch on disk so it does
				// not stay wedged in a pre-broadcast state,
				// where the singleton invariant added in
				// migration 000060 would block any
				// subsequent batch from being created. We
				// use the same cancel-state rule as
				// cultivator.Cancel(): Pending or Frozen →
				// SeedlingCancelled (no sprouts yet);
				// Committed → SproutCancelled (sprouts
				// already on disk).
				cancelState := BatchStateSeedlingCancelled
				if c.pendingBatch.State() ==
					BatchStateCommitted {

					cancelState = BatchStateSproutCancelled
				}

				cancelCtx, cancelCtxCancel := c.WithCtxQuit()
				cancelErr := c.cfg.BatchStore.UpdateBatchState(
					cancelCtx, c.pendingBatch, cancelState,
				)
				cancelCtxCancel()
				if cancelErr != nil {
					log.Warnf("Unable to cancel failed "+
						"batch (%x): %v",
						batchKeySerial[:], cancelErr)
				}

			case <-c.Quit:
				return
			}

			// Now that we have a cultivator launched for this
			// batch and broadcast its minting transaction, we
			// can remove the pending batch.
			c.pendingBatch = nil
		},
	)
}

// CancelBatch sends a signal to the planter to cancel the current batch.
func (c *ChainPlanter) CancelBatch() (*btcec.PublicKey, error) {
	return dispatchStateReq(
		c, func(out chan<- stateResult[*btcec.PublicKey]) {
			batchKey, err := c.canCancelBatch()
			if err != nil {
				out <- stateErr[*btcec.PublicKey](err)
				return
			}

			// Attempt to cancel the current batch, and then
			// clear the pending batch in the planter.
			ctx, cancel := c.WithCtxQuit()
			err = c.cancelMintingBatch(ctx, batchKey)
			cancel()
			c.pendingBatch = nil

			// Always return the key of the batch we tried to
			// cancel.
			out <- stateResult[*btcec.PublicKey]{
				val: batchKey,
				err: err,
			}
		},
	)
}

// prepAssetSeedling performs some basic validation for the Seedling, then
// either adds it to an existing pending batch or creates a new batch for it.
func (c *ChainPlanter) prepAssetSeedling(ctx context.Context,
	req *Seedling) error {

	// Let the configured augmenter populate any augmenter-managed
	// fields on the seedling (e.g. a delegation key for
	// supply-commit-flagged seedlings). When no augmenter is
	// active the call is a no-op.
	if err := c.augmenter().PrepareSeedling(
		ctx, c.pendingBatch, req,
	); err != nil {
		return err
	}

	// Set seedling asset metadata fields.
	req.Meta.UniverseCommitments = req.SupplyCommitments

	// If a delegation key is set in the seedling, set it in the metadata.
	if req.DelegationKey.IsSome() {
		keyDesc, err := req.DelegationKey.UnwrapOrErr(
			fmt.Errorf("delegation key is not set"),
		)
		if err != nil {
			return err
		}

		if keyDesc.PubKey == nil {
			return fmt.Errorf("delegation key has no public key")
		}

		req.Meta.DelegationKey = fn.Some(*keyDesc.PubKey)
	}

	// We will perform basic validation on the seedling, including metadata
	// validation.
	if err := req.validateFields(); err != nil {
		return err
	}

	// The seedling name must be unique within the pending batch.
	if c.pendingBatch != nil {
		if _, ok := c.pendingBatch.Seedlings[req.AssetName]; ok {
			return fmt.Errorf("asset with name %v already in batch",
				req.AssetName)
		}
	}

	// If emission is enabled and a group key is specified, we need to
	// make sure the asset types match and that we can sign with that key.
	if req.HasGroupKey() {
		groupKeyBytes := req.GroupInfo.GroupPubKey.
			SerializeCompressed()
		groupInfo, err := c.cfg.MintingRefs.FetchGroupByGroupKey(
			ctx, &req.GroupInfo.GroupPubKey,
		)
		if err != nil {
			return fmt.Errorf("group key %x not found: %w",
				groupKeyBytes, err,
			)
		}

		anchorMeta, err := c.cfg.MintingRefs.FetchAssetMeta(
			ctx, groupInfo.Genesis.ID(),
		)
		if err != nil {
			return fmt.Errorf("group anchor genesis %x not found: "+
				"%w", groupKeyBytes, err,
			)
		}

		err = req.validateGroupKey(*groupInfo, anchorMeta)
		if err != nil {
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

		err := c.pendingBatch.ValidateGroupAnchor(req)
		if err != nil {
			return err
		}
	}

	// If a group internal key or tapscript root is specified, emission must
	// also be enabled.
	if !req.EnableEmission {
		// For re-issuing grouped assets or regular (non-grouped)
		// assets, the group internal key shouldn't be set. It is,
		// however, set for re-issuance with an external key, because
		// the internal group key is the key we compare the external key
		// against.
		if req.GroupInternalKey != nil && req.ExternalKey.IsNone() {
			return fmt.Errorf("cannot specify group internal key " +
				"without creating a new grouped asset")
		}

		if req.GroupTapscriptRoot != nil {
			return fmt.Errorf("cannot specify group tapscript " +
				"root without creating a new grouped asset")
		}
	}

	// For group anchors, derive an internal key for the future group key if
	// none was provided.
	if req.EnableEmission && req.GroupInternalKey == nil {
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

	// Now that we've validated the seedling, we can derive a script key to
	// be used for this asset, if an external script key was not provided.
	if req.ScriptKey.PubKey == nil {
		scriptKey, err := c.cfg.KeyRing.DeriveNextKey(
			ctx, asset.TaprootAssetsKeyFamily,
		)
		if err != nil {
			return fmt.Errorf("unable to obtain script key for "+
				"seedling: %s %w", req.AssetName, err)
		}

		// Default to BIP86 for the script key tweaking method.
		req.ScriptKey = asset.NewScriptKeyBip86(scriptKey)
	}

	// Now that we know the seedling is valid, we'll check to see if a batch
	// already exists.
	switch {
	// No batch, so we'll create a new one with only this seedling as part
	// of the batch.
	case c.pendingBatch == nil:
		newBatch, err := c.newBatch()
		if err != nil {
			return err
		}

		log.Infof("Attempting to add a seedling to a new batch "+
			"(seedling=%v)", req)

		// Let the augmenter run its intake gate against the
		// fresh (empty) batch. It enforces invariants like
		// "first seedling sets the SupplyCommitments flag" and
		// "delegation key must be set if SupplyCommitments
		// is on."
		err = c.augmenter().ValidateSeedling(newBatch, *req)
		if err != nil {
			return fmt.Errorf("failed to add seedling to batch: %w",
				err)
		}

		// Stage the seedling on the local newBatch and persist
		// the whole batch atomically via CommitMintingBatch. The
		// planter's pendingBatch is assigned only after the DB
		// write succeeds; on any failure newBatch is discarded
		// and the planter state is unchanged.
		err = newBatch.AddSeedling(*req)
		if err != nil {
			return fmt.Errorf("failed to add seedling to batch: %w",
				err)
		}

		ctx, cancel := c.WithCtxQuit()
		defer cancel()
		err = c.cfg.BatchStore.CommitMintingBatch(
			ctx, newBatch, fn.None[PreCommitBindData](),
		)
		if err != nil {
			return err
		}

		c.pendingBatch = newBatch

	// A batch already exists, so we'll add this seedling to the batch,
	// committing it to disk fully before we move on.
	case c.pendingBatch != nil:
		log.Infof("Attempting to add a seedling to batch (seedling=%v)",
			req)

		// Let the augmenter run its intake gate before the
		// batch's own validation. Splitting validation in two
		// keeps augmenter-owned invariants in the augmenter and
		// batch-owned invariants on MintingBatch.
		err := c.augmenter().ValidateSeedling(c.pendingBatch, *req)
		if err != nil {
			return fmt.Errorf("failed to add seedling to batch: %w",
				err)
		}

		// Validate first without mutating the in-memory batch,
		// then persist, then mirror the seedling into memory.
		// This ordering ensures the in-memory batch never
		// advances unless the DB write succeeded: a failed
		// AddSeedlingsToBatch leaves both disk and memory at
		// their prior state.
		err = c.pendingBatch.validateSeedling(*req)
		if err != nil {
			return fmt.Errorf("failed to add seedling to batch: %w",
				err)
		}

		ctx, cancel := c.WithCtxQuit()
		defer cancel()
		err = c.cfg.BatchStore.AddSeedlingsToBatch(
			ctx, c.pendingBatch.BatchKey.PubKey, req,
		)
		if err != nil {
			return err
		}

		c.pendingBatch.commitSeedling(*req)
	}

	// Now that we have the batch committed to disk, we'll return back to
	// the caller if we should finalize the batch immediately or not based
	// on its preference.
	return nil
}

// updateMintingProofs is called by the re-org watcher when it detects a re-org
// and has updated the minting proofs. This cannot be done by the cultivator
// itself, because its job is already done at the point that a re-org can happen
// (the batch is finalized after a single confirmation).
func (c *ChainPlanter) updateMintingProofs(proofs []*proof.Proof) error {
	ctx, cancel := c.WithCtxQuitNoTimeout()
	defer cancel()

	// This is a bit of a hacky part. If we have a chain of transactions
	// that were re-organized, we can't verify the whole chain until all of
	// the transactions were confirmed and all proofs were updated with the
	// new blocks and merkle roots. So we'll skip the verification here
	// since we don't know if the whole chain has been updated yet (the
	// confirmations might come in out of order).
	// TODO(guggero): Find a better way to do this.
	vCtx := c.verifierCtx(ctx)
	vCtx.HeaderVerifier = func(wire.BlockHeader, uint32) error {
		return nil
	}

	for idx := range proofs {
		p := proofs[idx]

		existingProofs, err := c.cfg.ProofUpdates.FetchProofs(
			ctx, p.Asset.ID(),
		)
		if err != nil {
			return fmt.Errorf("unable to fetch proofs: %w", err)
		}

		updatedProofs, err := proof.ReplaceProofInFiles(
			p, existingProofs,
		)
		if err != nil {
			return fmt.Errorf("unable to update minted proofs: %w",
				err)
		}

		if len(updatedProofs) > 0 {
			err = c.cfg.ProofUpdates.ImportProofs(
				ctx, vCtx, true, updatedProofs...,
			)
			if err != nil {
				return fmt.Errorf("unable to import updated "+
					"minted proofs: %w", err)
			}
		}
	}

	if c.cfg.MintProofPublisher == nil {
		return nil
	}

	if err := c.cfg.MintProofPublisher.PublishMintProofUpdates(
		ctx, proofs,
	); err != nil {
		return fmt.Errorf("unable to publish minting proof "+
			"updates: %w", err)
	}

	return nil
}

// QueueNewSeedling attempts to queue a new seedling request (the intent for
// New asset creation or ongoing issuance) to the ChainPlanter. A channel is
// returned where future updates will be sent over. If an error is returned no
// issuance operation was possible.
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
func (c *ChainPlanter) CancelSeedling() error {
	// TODO(roasbeef): actually needed?
	return nil
}

// RegisterSubscriber adds a new subscriber to the set of subscribers that will
// be notified of any new events that are broadcast.
func (c *ChainPlanter) RegisterSubscriber(
	receiver *fn.EventReceiver[fn.Event], _, _ bool) error {

	c.subscriberMtx.Lock()
	defer c.subscriberMtx.Unlock()

	c.subscribers[receiver.ID()] = receiver

	return nil
}

// RemoveSubscriber removes a subscriber from the set of subscribers that will
// be notified of any new events that are broadcast.
func (c *ChainPlanter) RemoveSubscriber(
	subscriber *fn.EventReceiver[fn.Event]) error {

	c.subscriberMtx.Lock()
	defer c.subscriberMtx.Unlock()

	_, ok := c.subscribers[subscriber.ID()]
	if !ok {
		return fmt.Errorf("subscriber with ID %d not found",
			subscriber.ID())
	}

	subscriber.Stop()
	delete(c.subscribers, subscriber.ID())

	return nil
}

// publishSubscriberEvent publishes an event to all subscribers.
func (c *ChainPlanter) publishSubscriberEvent(event fn.Event) {
	// Lock the subscriber mutex to ensure that we don't modify the
	// subscriber map while we're iterating over it.
	c.subscriberMtx.Lock()
	defer c.subscriberMtx.Unlock()

	for _, sub := range c.subscribers {
		sub.NewItemCreated.ChanIn() <- event
	}
}

// verifierCtx returns a verifier context that can be used to verify proofs.
func (c *ChainPlanter) verifierCtx(ctx context.Context) proof.VerifierCtx {
	headerVerifier := tapnode.GenHeaderVerifier(ctx, c.cfg.ChainBridge)
	merkleVerifier := proof.DefaultMerkleVerifier
	groupVerifier := tapnode.GenGroupVerifier(ctx, c.cfg.MintingRefs)

	return proof.VerifierCtx{
		HeaderVerifier: headerVerifier,
		MerkleVerifier: merkleVerifier,
		GroupVerifier:  groupVerifier,
		ChainLookupGen: c.cfg.ChainBridge,
		IgnoreChecker:  c.cfg.IgnoreChecker,
	}
}

// A compile-time assertion to make sure ChainPlanter satisfies the
// fn.EventPublisher interface.
var _ fn.EventPublisher[fn.Event, bool] = (*ChainPlanter)(nil)

// FundedMintAnchorPsbt is a struct that contains a funded minting anchor
// transaction PSBT.
type FundedMintAnchorPsbt struct {
	// FundedPsbt is the PSBT packet that has been funded by the wallet.
	tapsend.FundedPsbt

	// AssetAnchorOutIdx is the index of the asset anchor output in the
	// transaction.
	AssetAnchorOutIdx uint32
}

// NewFundedMintAnchorPsbt creates a new funded minting anchor PSBT package from
// a funded PSBT.
func NewFundedMintAnchorPsbt(fundedPsbt tapsend.FundedPsbt,
	anchorOutIndexes AnchorTxOutputIndexes) (FundedMintAnchorPsbt, error) {

	return FundedMintAnchorPsbt{
		FundedPsbt:        fundedPsbt,
		AssetAnchorOutIdx: anchorOutIndexes.AssetAnchorOutIdx,
	}, nil
}

// GenesisOutpoint returns the genesis outpoint of the mint anchor PSBT, which
// is the first input in the genesis transaction.
func (f *FundedMintAnchorPsbt) GenesisOutpoint() fn.Option[wire.OutPoint] {
	var zero fn.Option[wire.OutPoint]

	if f.Pkt == nil {
		return zero
	}

	if f.Pkt.UnsignedTx == nil {
		return zero
	}

	if len(f.Pkt.UnsignedTx.TxIn) == 0 {
		return zero
	}

	return fn.Some(f.Pkt.UnsignedTx.TxIn[0].PreviousOutPoint)
}

// Copy returns a deep copy of FundedMintAnchorPsbt. The contained
// psbt.Packet is cloned via a serialize/parse round-trip so every nested
// PInput/POutput/Unknown -- each of which carries its own slice and map
// substructure -- is duplicated. LockedUTXOs holds wire.OutPoint values
// (no pointer reachability) so fn.CopySlice is a true deep copy there.
//
// If the round-trip fails (the underlying packet is malformed) we panic,
// since tapgarden only ever holds packets it constructed itself via the
// wallet's funding flow.
func (f *FundedMintAnchorPsbt) Copy() *FundedMintAnchorPsbt {
	newMintAnchorPsbt := &FundedMintAnchorPsbt{
		FundedPsbt: tapsend.FundedPsbt{
			ChangeOutputIndex: f.ChangeOutputIndex,
			ChainFees:         f.ChainFees,
			LockedUTXOs:       fn.CopySlice(f.LockedUTXOs),
		},
		AssetAnchorOutIdx: f.AssetAnchorOutIdx,
	}

	if f.Pkt != nil {
		// Real-world packets always carry an UnsignedTx (the psbt
		// package's Serialize requires it). Surface the impossible
		// case explicitly rather than letting Serialize panic with
		// a less-actionable nil-pointer dereference.
		if f.Pkt.UnsignedTx == nil {
			panic("FundedMintAnchorPsbt.Copy: Pkt has nil " +
				"UnsignedTx; not a valid psbt")
		}

		var buf bytes.Buffer
		if err := f.Pkt.Serialize(&buf); err != nil {
			panic(fmt.Errorf("FundedMintAnchorPsbt.Copy: "+
				"serializing packet failed: %w", err))
		}

		pktCopy, err := psbt.NewFromRawBytes(
			bytes.NewReader(buf.Bytes()), false,
		)
		if err != nil {
			panic(fmt.Errorf("FundedMintAnchorPsbt.Copy: parsing "+
				"round-tripped packet failed: %w", err))
		}
		newMintAnchorPsbt.Pkt = pktCopy
	}

	return newMintAnchorPsbt
}

