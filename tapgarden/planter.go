package tapgarden

import (
	"bytes"
	"context"
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
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/universe"
	lfn "github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
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

// ListBatchesParams are the options available to specify which minting batches
// are listed, and how verbose the listing should be.
type ListBatchesParams struct {
	BatchKey *btcec.PublicKey
	Verbose  bool
}

// PendingAssetGroup is the group key request and virtual TX necessary to
// produce an asset group witness for a seedling.
type PendingAssetGroup struct {
	asset.GroupKeyRequest
	asset.GroupVirtualTx
}

// PSBT returns a PSBT packet that can be used to create a group witness for the
// asset group.
func (p *PendingAssetGroup) PSBT(
	params chaincfg.Params) (*psbt.Packet, error) {

	// Generate PSBT equivalent of the group virtual tx.
	packet, err := psbt.NewFromUnsignedTx(&p.GroupVirtualTx.Tx)
	if err != nil {
		return nil, fmt.Errorf("error producing group virtual PSBT "+
			"from tx: %w", err)
	}

	vIn := &packet.Inputs[0]
	vIn.WitnessUtxo = &p.GroupVirtualTx.PrevOut
	vIn.TaprootMerkleRoot = p.GroupKeyRequest.TapscriptRoot
	vIn.TaprootInternalKey = schnorr.SerializePubKey(
		p.GroupKeyRequest.RawKey.PubKey,
	)

	switch {
	case p.GroupKeyRequest.ExternalKey.IsSome():
		externalKey := p.GroupKeyRequest.ExternalKey.UnwrapToPtr()
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
			assetID := p.AnchorGen.ID()
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
			p.GroupKeyRequest.RawKey, params.HDCoinType,
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
		caretakers:        make(map[BatchKey]*BatchCaretaker),
		completionSignals: make(chan BatchKey),
		seedlingReqs:      make(chan *Seedling),
		stateReqs:         make(chan stateRequest),
		subscribers:       make(map[uint64]*fn.EventReceiver[fn.Event]),
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
		PublishMintEvent:    c.publishSubscriberEvent,
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
				err := c.cfg.Log.UpdateBatchState(
					ctx, batch.BatchKey.PubKey,
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
			// funded or sealed before being assigned a caretaker.
			// A batch that was already properly frozen at this
			// point should not be modified before being assigned a
			// caretaker.
			if batchState == BatchStatePending ||
				batchState == BatchStateFrozen {

				var (
					fundErr error
					sealErr error
				)

				if !batch.IsFunded() {
					log.Infof("Funding non-finalized "+
						"batch from DB (%x)", batchKey)
					fundErr = c.fundBatch(
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
				_, sealErr = c.sealBatch(
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

				// Any pending batch that was funded and sealed
				// can now be set as frozen. We are already not
				// able to add new seedlings to the batch.
				batch.UpdateState(BatchStateFrozen)
			}

			log.Infof("Launching ChainCaretaker(%x)", batchKey)
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

// preCommitmentOutput creates the pre-commitment output for a batch that uses
// universe commitments.
func preCommitmentOutput(pendingBatch *MintingBatch) (PreCommitmentOutput,
	error) {

	var zero PreCommitmentOutput

	// Ensure that a pending batch is provided.
	if pendingBatch == nil {
		return zero, fmt.Errorf("no pending batch provided when " +
			"creating pre-commitment output")
	}

	// Ensure that the universe commitments feature is enabled for the
	// batch.
	if !pendingBatch.UniverseCommitments {
		return zero, fmt.Errorf("code error: universe commitments " +
			"should be enabled before calling " +
			"preCommitmentOutput")
	}

	// Ensure that the batch has at least one seedling.
	if len(pendingBatch.Seedlings) == 0 {
		return zero, fmt.Errorf("uni commitment enabled for funded " +
			"batch but no seedlings in batch")
	}

	// Retrieve batch anchor seedling.
	var groupAnchorSeedling *Seedling
	for _, seedling := range pendingBatch.Seedlings {
		if seedling.GroupAnchor == nil {
			groupAnchorSeedling = seedling
			break
		}

		groupAnchorSeedling =
			pendingBatch.Seedlings[*seedling.GroupAnchor]
		break
	}

	// Ensure that the group anchor seedling is found.
	if groupAnchorSeedling == nil {
		return zero, fmt.Errorf("no group anchor seedling found")
	}

	// Extract delegated key from the group anchor seedling.
	delegationKey, err := groupAnchorSeedling.DelegationKey.UnwrapOrErr(
		fmt.Errorf("no delegation key found in seedling"),
	)
	if err != nil {
		return zero, err
	}

	// Extract group pub key from group anchor seedling.
	if groupAnchorSeedling.GroupInfo == nil {
		return zero, fmt.Errorf("no group info found in seedling")
	}
	groupPubKey := groupAnchorSeedling.GroupInfo.GroupPubKey

	// Use a placeholder output index for the pre-commitment output. This
	// will be revised after funding.
	var placeholderOutIdx uint32 = 0

	// Formulate the pre-commitment output bundle.
	preCommitOut := NewPreCommitmentOutput(
		placeholderOutIdx, *delegationKey.PubKey, groupPubKey,
	)
	return preCommitOut, nil
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

	// PreCommitOutIdx is the index of the pre-commitment output in the
	// transaction. This field is only set if universe commitments are
	// enabled for the batch.
	PreCommitOutIdx fn.Option[uint32]
}

// anchorTxOutputIndexes specifies the output indexes of the anchor transaction.
func anchorTxOutputIndexes(fundedPsbt tapsend.FundedPsbt,
	preCommitmentTxOut fn.Option[wire.TxOut]) (AnchorTxOutputIndexes,
	error) {

	var (
		zero AnchorTxOutputIndexes

		// assetAnchorOutIdxOpt will contain the index of the asset
		// anchor output in the transaction.
		assetAnchorOutIdxOpt fn.Option[uint32]

		// preCommitOutIdx will contain the index of the pre-commitment
		// output in the transaction. This field is only
		// set if universe commitments are enabled for the batch.
		preCommitOutIdx fn.Option[uint32]
	)

	// Formulate the expected asset anchor output that we will use to
	// identify the asset anchor output in the transaction.
	expectedAssetAnchorOutput := tapsend.CreateDummyOutput()
	expectedAssetAnchorPkScript := expectedAssetAnchorOutput.PkScript

	// Inspect each output in the transaction to determine the output
	// indexes.
	for idx := range fundedPsbt.Pkt.UnsignedTx.TxOut {
		// Skip the change output based on its index.
		if int32(idx) == fundedPsbt.ChangeOutputIndex {
			continue
		}

		// We will inspect the output script pubkey to determine whether
		// it is the asset anchor output or the pre-commitment output.
		txOut := fundedPsbt.Pkt.UnsignedTx.TxOut[idx]

		// If the output script pubkey matches the expected asset anchor
		// output script pubkey, we have found the asset anchor output.
		if bytes.Equal(txOut.PkScript, expectedAssetAnchorPkScript) {
			assetAnchorOutIdxOpt = fn.Some(uint32(idx))
			continue
		}

		// If universe commitments are enabled, we will inspect the
		// output script pubkey to determine whether it is the
		// pre-commitment output.
		preCommitmentTxOut.WhenSome(
			func(preCommitTxOut wire.TxOut) {
				// If the output script pubkey matches the
				// pre-commitment output script pubkey, we have
				// found the pre-commitment output.
				outputMatch := bytes.Equal(
					txOut.PkScript, preCommitTxOut.PkScript,
				)
				if outputMatch {
					preCommitOutIdx = fn.Some(uint32(idx))
				}
			},
		)
	}

	// Unpack the asset anchor output index. Return an error if the output
	// index is not found.
	assetAnchorOutIdx, err := assetAnchorOutIdxOpt.UnwrapOrErr(
		fmt.Errorf("asset anchor output index not found"),
	)
	if err != nil {
		return zero, err
	}

	// If the pre-commitment output is expected, but not found, we return an
	// error.
	if preCommitmentTxOut.IsSome() && !preCommitOutIdx.IsSome() {
		return zero, fmt.Errorf("pre-commitment output index not found")
	}

	return AnchorTxOutputIndexes{
		AssetAnchorOutIdx: assetAnchorOutIdx,
		ChangeOutIdx:      uint32(fundedPsbt.ChangeOutputIndex),
		PreCommitOutIdx:   preCommitOutIdx,
	}, nil
}

// anchorTxFeeRate computes the fee rate for the anchor transaction. If a fee
// rate is manually assigned for the batch, it is used. Otherwise, the fee rate
// is estimated based on the current network conditions.
func (c *ChainPlanter) anchorTxFeeRate(ctx context.Context,
	manualFeeRate *chainfee.SatPerKWeight) (chainfee.SatPerKWeight, error) {

	// Compute the anchor transaction fee rate.
	var feeRate chainfee.SatPerKWeight
	switch {
	// If a fee rate was manually assigned for this batch, use that instead
	// of a fee rate estimate.
	case manualFeeRate != nil:
		feeRate = *manualFeeRate
		log.Infof("using manual fee rate for batch: %s, %d sat/vB",
			feeRate.String(),
			feeRate.FeePerKVByte()/1000)

	default:
		feeRate, err := c.cfg.ChainBridge.EstimateFee(
			ctx, GenesisConfTarget,
		)
		if err != nil {
			return 0, fmt.Errorf("unable to estimate fee: %w",
				err)
		}

		log.Infof("estimated fee rate for batch: %s",
			feeRate.FeePerKVByte().String())
	}

	minRelayFee, err := c.cfg.Wallet.MinRelayFee(ctx)
	if err != nil {
		return 0, fmt.Errorf("unable to obtain minrelayfee: %w", err)
	}

	// If the fee rate is below the minimum relay fee, we'll
	// bump it up.
	if feeRate < minRelayFee {
		switch {
		// If a fee rate was manually assigned for this batch, we err
		// out, otherwise we silently bump the feerate.
		case manualFeeRate != nil:
			// This case should already have been handled by the
			// `checkFeeRateSanity` of `rpcserver.go`. We check here
			// again to be safe.
			return 0, fmt.Errorf("feerate does not meet "+
				"minrelayfee: (fee_rate=%s, minrelayfee=%s)",
				feeRate.String(), minRelayFee.String())
		default:
			log.Infof("Bump fee rate for batch to meet "+
				"minrelayfee from %s to %s",
				feeRate.String(), minRelayFee.String())
			feeRate = minRelayFee
		}
	}

	return feeRate, nil
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
func fundGenesisPsbt(ctx context.Context, pendingBatch *MintingBatch,
	walletFundPsbt WalletFundPsbt) (FundedMintAnchorPsbt, error) {

	var zero FundedMintAnchorPsbt

	// If universe commitments are enabled, we formulate a pre-commitment
	// output. This output is spent by the universe commitment transaction.
	var preCommitmentOut fn.Option[PreCommitmentOutput]
	if pendingBatch != nil && pendingBatch.UniverseCommitments {
		out, err := preCommitmentOutput(pendingBatch)
		if err != nil {
			return zero, fmt.Errorf("unable to create "+
				"pre-commitment output: %w", err)
		}

		preCommitmentOut = fn.Some(out)
	}

	// Derive wire.TxOut from the pre-commitment output, if available.
	var preCommitmentTxOut fn.Option[wire.TxOut]
	if preCommitmentOut.IsSome() {
		txOut, err := fn.MapOptionZ(
			preCommitmentOut,
			func(p PreCommitmentOutput) lfn.Result[wire.TxOut] {
				txOut, err := p.TxOut()
				return lfn.NewResult(txOut, err)
			},
		).Unpack()
		if err != nil {
			return zero, err
		}

		preCommitmentTxOut = fn.Some(txOut)
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

	// Classify anchor transaction output indexes.
	anchorOutIndexes, err := anchorTxOutputIndexes(
		fundedGenesisPkt, preCommitmentTxOut,
	)
	if err != nil {
		return zero, fmt.Errorf("unable to determine output indexes: "+
			"%w", err)
	}

	// Sanity check that the pre-commitment output index was found if
	// expected.
	if preCommitmentOut.IsSome() &&
		anchorOutIndexes.PreCommitOutIdx.IsNone() {

		return zero, fmt.Errorf("pre-commitment output index not found")
	}

	// If pre-commitment output is some, assign the output index to the
	// pre-commitment output.
	if preCommitmentOut.IsSome() {
		// Ensure that a pre-commitment output index is found.
		outIdx, err := anchorOutIndexes.PreCommitOutIdx.UnwrapOrErr(
			fmt.Errorf("pre-commitment output index not found"),
		)
		if err != nil {
			return zero, err
		}

		// Assign output index to the pre-commitment output.
		preCommitmentOut = fn.MapOption(
			func(out PreCommitmentOutput) PreCommitmentOutput {
				out.OutIdx = outIdx
				return out
			},
		)(preCommitmentOut)
	}

	// Formulate a funded minting anchor PSBT from the funded PSBT.
	fundedMintAnchorPsbt, err := NewFundedMintAnchorPsbt(
		fundedGenesisPkt, anchorOutIndexes, preCommitmentOut,
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
func fetchFinalizedBatch(ctx context.Context, batchStore MintingStore,
	archiver proof.Archiver, batch *MintingBatch) (*MintingBatch, error) {

	if batch.GenesisPacket == nil {
		return nil, fmt.Errorf("batch is missing anchor tx packet")
	}

	// Collect genesis TX information from the batch to build the proof
	// locators.
	anchorOutputIndex := batch.GenesisPacket.AssetAnchorOutIdx

	signedTx, err := psbt.Extract(batch.GenesisPacket.Pkt)
	if err != nil {
		return nil, err
	}

	genOutpoint := extractGenesisOutpoint(signedTx)
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

		tweakedScriptKey, err := batchStore.FetchScriptKeyByTweakedKey(
			ctx, sproutedAsset.ScriptKey.PubKey,
		)
		if err != nil {
			return nil, err
		}

		sproutedAsset.ScriptKey.TweakedScriptKey = tweakedScriptKey
		if sproutedAsset.GroupKey != nil {
			assetGroup, err := batchStore.FetchGroupByGroupKey(
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
func listBatches(ctx context.Context, batchStore MintingStore,
	archiver proof.Archiver, genBuilder asset.GenesisTxBuilder,
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
				ctx, batchStore, archiver, batch,
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
	verboseBatches := make([]*VerboseBatch, len(sortedBatches))

	for idx := range sortedBatches {
		currentBatch := sortedBatches[idx]

		// The batch must be pending, funded, and have seedlings for us
		// to show pending asset group information.
		switch {
		case currentBatch.State() != BatchStatePending:
			continue
		case !currentBatch.IsFunded():
			continue
		case len(currentBatch.Seedlings) == 0:
			continue
		default:
		}

		verboseBatch, err := newVerboseBatch(currentBatch, genBuilder)
		if err != nil {
			return nil, err
		}

		verboseBatches[idx] = verboseBatch
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

	genesisPoint := extractGenesisOutpoint(
		currentBatch.GenesisPacket.Pkt.UnsignedTx,
	)

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
			GroupKeyRequest: groupReqs[i],
			GroupVirtualTx:  genTXs[i],
		}
	}

	// Clear the original batch seedlings so each asset is only represented
	// once.
	verboseBatch.Seedlings = nil

	return verboseBatch, nil
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
				listBatchesParams, err :=
					typedParam[ListBatchesParams](req)
				if err != nil {
					req.Error(fmt.Errorf("bad list batch "+
						"params: %w", err))
					break
				}

				ctx, cancel := c.WithCtxQuit()
				batches, err := listBatches(
					ctx, c.cfg.Log, c.cfg.ProofFiles,
					c.cfg.GenTxBuilder, *listBatchesParams,
				)
				cancel()
				if err != nil {
					req.Error(err)
					break
				}

				req.Resolve(batches)

			case reqTypeFundBatch:
				if c.pendingBatch != nil &&
					c.pendingBatch.IsFunded() {

					req.Error(fmt.Errorf("batch already " +
						"funded"))
					break
				}

				fundReqParams, err :=
					typedParam[FundParams](req)
				if err != nil {
					req.Error(fmt.Errorf("bad fund "+
						"params: %w", err))
					break
				}

				ctx, cancel := c.WithCtxQuit()
				err = c.fundBatch(
					ctx, *fundReqParams, c.pendingBatch,
				)
				cancel()
				if err != nil {
					req.Error(fmt.Errorf("unable to fund "+
						"minting batch: %w", err))
					break
				}

				// Formulate a verbose batch to return to the
				// caller.
				verboseBatch, err := newVerboseBatch(
					c.pendingBatch, c.cfg.GenTxBuilder,
				)
				if err != nil {
					req.Error(err)
					break
				}

				req.Resolve(&FundBatchResp{
					Batch: verboseBatch,
				})

			case reqTypeSealBatch:
				if c.pendingBatch == nil {
					req.Error(fmt.Errorf("no pending " +
						"batch"))
					break
				}

				sealReqParams, err :=
					typedParam[SealParams](req)
				if err != nil {
					req.Error(fmt.Errorf("bad seal "+
						"params: %w", err))
					break
				}

				ctx, cancel := c.WithCtxQuit()
				sealedBatch, err := c.sealBatch(
					ctx, *sealReqParams, c.pendingBatch,
				)
				cancel()
				if err != nil {
					req.Error(fmt.Errorf("unable to seal "+
						"minting batch: %w", err))
					break
				}

				req.Resolve(sealedBatch)

			case reqTypeFinalizeBatch:
				if c.pendingBatch == nil {
					req.Error(fmt.Errorf("no pending " +
						"batch"))
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
						"finalize minting batch: %w",
						err)
					log.Warnf(freezeErr.Error())
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

// fundBatch attempts to fund a minting batch and create a funded genesis PSBT.
// This PSBT is a template that the caretaker will modify when finalizing the
// batch. If a feerate or tapscript sibling are provided, those will be used
// when funding the batch. If no pending batch exists, a batch will be created
// with the funded genesis PSBT. After funding, the pending batch will be
// saved to disk and updated in memory.
func (c *ChainPlanter) fundBatch(ctx context.Context, params FundParams,
	workingBatch *MintingBatch) error {

	var (
		manualFeeRate *chainfee.SatPerKWeight
		rootHash      *chainhash.Hash
		err           error
	)

	// If a tapscript tree was specified for this batch, we'll store it on
	// disk. The caretaker we start for this batch will use it when deriving
	// the final Taproot output key.
	manualFeeRate = params.FeeRate.UnwrapToPtr()
	params.SiblingTapTree.WhenSome(func(tn asset.TapscriptTreeNodes) {
		rootHash, err = c.cfg.TreeStore.StoreTapscriptTree(ctx, tn)
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
		feeRate, err := c.anchorTxFeeRate(ctx, manualFeeRate)
		if err != nil {
			return fmt.Errorf("unable to determine anchor TX "+
				"fee rate: %w", err)
		}

		batchKey := asset.ToSerialized(batch.BatchKey.PubKey)

		// walletFundPsbt is a closure that will be used to fund the
		// batch with the specified fee rate.
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
			ctx, c.pendingBatch, walletFundPsbt,
		)
		if err != nil {
			return fmt.Errorf("unable to fund minting PSBT for "+
				"batch: %x %w", batchKey[:], err)
		}

		log.Infof("Funded GenesisPacket for batch: %x", batchKey)
		batch.GenesisPacket = &mintAnchorTx

		return nil
	}

	// If we don't have a batch, we'll create an empty batch before funding
	// and writing to disk.
	if workingBatch == nil {
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
		return nil
	}

	// If we already have a batch, we need to attach the optional sibling
	// root hash and fund the batch.
	err = updateBatch(workingBatch)
	if err != nil {
		return err
	}

	// Write the associated sibling root hash and TX to disk.
	if workingBatch.tapSibling != nil {
		err = c.cfg.Log.CommitBatchTapSibling(
			ctx, workingBatch.BatchKey.PubKey, rootHash,
		)
		if err != nil {
			return fmt.Errorf("unable to commit tapscript "+
				"sibling for minting batch %w", err)
		}
	}

	err = c.cfg.Log.CommitBatchTx(
		ctx, workingBatch.BatchKey.PubKey, *workingBatch.GenesisPacket,
	)
	if err != nil {
		return err
	}

	return nil
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
		tx, err := groupReqs[0].BuildGroupVirtualTx(
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
// validated, they are saved to disk to be used by the caretaker during batch
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
	anchorOutputIndex := workingBatch.GenesisPacket.AssetAnchorOutIdx

	genesisPoint := extractGenesisOutpoint(
		workingBatch.GenesisPacket.Pkt.UnsignedTx,
	)

	// Check if the batch is already sealed by picking a random grouped
	// seedling and trying to fetch the full asset group.
	var singleSeedling []*Seedling
	for _, seedling := range groupSeedlings {
		singleSeedling = append(singleSeedling, seedling)
		break
	}

	// If the batch was previously sealed, each grouped seedling will have
	// its asset genesis already stored on disk.
	existingGroups, err := c.cfg.Log.FetchSeedlingGroups(
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

	assetGroups := make([]*asset.AssetGroup, 0, len(groupReqs))
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

		assetGroups = append(assetGroups, newGroup)
	}

	// With all the asset group witnesses validated, we can now save them
	// to disk.
	err = c.cfg.Log.AddSeedlingGroups(ctx, genesisPoint, assetGroups)
	if err != nil {
		return nil, fmt.Errorf("unable to write seedling groups: "+
			"%w", err)
	}

	// Populate the group info for each seedling, to display to the caller.
	batchWithGroupInfo := workingBatch.Copy()
	for _, group := range assetGroups {
		assetName := group.Genesis.Tag
		batchWithGroupInfo.Seedlings[assetName].GroupInfo = group
	}

	return batchWithGroupInfo, nil
}

// finalizeBatch creates a new caretaker for the batch and starts it.
func (c *ChainPlanter) finalizeBatch(params FinalizeParams) (*BatchCaretaker,
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
	// At this point, we have a non-empty batch, so we'll first finalize it
	// on disk. This means no further seedlings can be added to this batch.
	err = freezeMintingBatch(ctx, c.cfg.Log, c.pendingBatch)
	if err != nil {
		return nil, err
	}

	// If the batch already has a funded TX, we can skip funding the batch.
	if !c.pendingBatch.IsFunded() {
		// Fund the batch before starting the caretaker. If funding
		// fails, we can't start a caretaker for the batch, so we'll
		// clear the pending batch. The batch will exist on disk for
		// the user to recreate it if necessary.
		// TODO(jhb): Don't clear pending batch here
		err = c.fundBatch(ctx, FundParams(params), c.pendingBatch)
		if err != nil {
			c.pendingBatch = nil
			return nil, err
		}
	}

	// If the batch needs to be sealed, we'll use the default behavior for
	// generating asset group witnesses. Any custom behavior requires
	// calling SealBatch() explicitly, before batch finalization.
	_, err = c.sealBatch(ctx, SealParams{}, c.pendingBatch)
	if err != nil {
		if !errors.Is(err, ErrBatchAlreadySealed) {
			return nil, err
		}
	}

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

// PendingBatch returns the current pending batch, or nil if no batch is
// pending.
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
func (c *ChainPlanter) ListBatches(params ListBatchesParams) ([]*VerboseBatch,
	error) {

	req := newStateParamReq[[]*VerboseBatch](reqTypeListBatches, params)

	if !fn.SendOrQuit[stateRequest](c.stateReqs, req, c.Quit) {
		return nil, fmt.Errorf("chain planter shutting down")
	}

	return <-req.resp, <-req.err
}

// FundBatch sends a signal to the planter to fund the current batch, or create
// a funded batch.
func (c *ChainPlanter) FundBatch(params FundParams) (*FundBatchResp, error) {
	req := newStateParamReq[*FundBatchResp](reqTypeFundBatch, params)

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

// prepSeedlingDelegationKey finalizes the seedling delegation key.
func (c *ChainPlanter) prepSeedlingDelegationKey(ctx context.Context,
	req *Seedling) error {

	// If the universe commitments feature is disabled for this seedling,
	// we can skip any further delegation key considerations.
	if !req.UniverseCommitments {
		return nil
	}

	// At this point, we know that the universe commitments feature is
	// enabled for the seedling. If a group anchor seedling is specified
	// we will use its delegation key.
	if req.GroupAnchor != nil {
		// Retrieve the group anchor seedling from the pending batch.
		anchorSeedlingName := *req.GroupAnchor

		anchor, ok := c.pendingBatch.Seedlings[anchorSeedlingName]
		if anchor == nil || !ok {
			return fmt.Errorf("group anchor seedling not present "+
				"in batch (anchor_seedling_name=%s)",
				anchorSeedlingName)
		}

		if anchor.DelegationKey.IsNone() {
			return fmt.Errorf("group anchor seedling has no "+
				"delegation key (anchor_seedling_name=%s)",
				anchorSeedlingName)
		}

		// Set the delegation key for the seedling to the delegation key
		// of the group anchor seedling.
		req.DelegationKey = anchor.DelegationKey

		// Return early, no further seedling prep required for universe
		// commitments feature.
		return nil
	}

	// On the other hand, if we're handling the group anchor seedling, we
	// and the delegation key is unset, we must generate a new one.
	if req.EnableEmission && req.GroupAnchor == nil {
		newKey, err := c.cfg.KeyRing.DeriveNextKey(
			ctx, asset.TaprootAssetsKeyFamily,
		)
		if err != nil {
			return fmt.Errorf("unable to derive pre-commitment "+
				"output key: %w", err)
		}

		req.DelegationKey = fn.Some(newKey)
	}

	return nil
}

// prepAssetSeedling performs some basic validation for the Seedling, then
// either adds it to an existing pending batch or creates a new batch for it.
func (c *ChainPlanter) prepAssetSeedling(ctx context.Context,
	req *Seedling) error {

	// Finalise the seedling delegation key.
	err := c.prepSeedlingDelegationKey(ctx, req)
	if err != nil {
		return err
	}

	// Set seedling asset metadata fields.
	req.Meta.UniverseCommitments = req.UniverseCommitments

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
		groupInfo, err := c.cfg.Log.FetchGroupByGroupKey(
			ctx, &req.GroupInfo.GroupPubKey,
		)
		if err != nil {
			return fmt.Errorf("group key %x not found: %w",
				groupKeyBytes, err,
			)
		}

		anchorMeta, err := c.cfg.Log.FetchAssetMeta(
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

		err := c.pendingBatch.validateGroupAnchor(req)
		if err != nil {
			return err
		}
	}

	// If a group internal key or tapscript root is specified, emission must
	// also be enabled.
	if !req.EnableEmission {
		if req.GroupInternalKey != nil {
			return fmt.Errorf("cannot specify group internal key " +
				"without enabling emission")
		}

		if req.GroupTapscriptRoot != nil {
			return fmt.Errorf("cannot specify group tapscript " +
				"root without enabling emission")
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

		c.pendingBatch = newBatch

		log.Infof("Attempting to add a seedling to a new batch "+
			"(seedling=%v)", req)

		err = c.pendingBatch.AddSeedling(*req)
		if err != nil {
			return fmt.Errorf("failed to add seedling to batch: %w",
				err)
		}

		ctx, cancel := c.WithCtxQuit()
		defer cancel()
		err = c.cfg.Log.CommitMintingBatch(ctx, c.pendingBatch)
		if err != nil {
			return err
		}

	// A batch already exists, so we'll add this seedling to the batch,
	// committing it to disk fully before we move on.
	case c.pendingBatch != nil:
		log.Infof("Attempting to add a seedling to batch (seedling=%v)",
			req)

		err := c.pendingBatch.AddSeedling(*req)
		if err != nil {
			return fmt.Errorf("failed to add seedling to batch: %w",
				err)
		}

		// Now that we know the seedling is ok, we'll write it to disk.
		ctx, cancel := c.WithCtxQuit()
		defer cancel()
		err = c.cfg.Log.AddSeedlingsToBatch(
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
			c.cfg.ChainBridge,
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

// A compile-time assertion to make sure that ChainPlanter implements the
// tapgarden.Planter interface.
var _ Planter = (*ChainPlanter)(nil)

// A compile-time assertion to make sure BatchCaretaker satisfies the
// fn.EventPublisher interface.
var _ fn.EventPublisher[fn.Event, bool] = (*ChainPlanter)(nil)

// PreCommitmentOutput provides metadata related to the pre-commitment output
// of a mint anchor transaction. This output serves as an intermediate step
// before being spent by the universe commitment transaction.
type PreCommitmentOutput struct {
	// OutIdx specifies the index of the pre-commitment output within the
	// batch mint anchor transaction.
	OutIdx uint32

	// InternalKey is the Taproot internal public key associated with the
	// pre-commitment output.
	InternalKey btcec.PublicKey

	// GroupPubKey is the asset group public key associated with this
	// pre-commitment output.
	GroupPubKey btcec.PublicKey
}

// NewPreCommitmentOutput creates a new PreCommitmentOutput instance.
func NewPreCommitmentOutput(outIdx uint32, internalKey,
	groupPubKey btcec.PublicKey) PreCommitmentOutput {

	return PreCommitmentOutput{
		OutIdx:      outIdx,
		InternalKey: internalKey,
		GroupPubKey: groupPubKey,
	}
}

// TxOut returns the pre-commitment output as a wire.TxOut instance.
func (p *PreCommitmentOutput) TxOut() (wire.TxOut, error) {
	var zero wire.TxOut

	// Formulate a taproot output key from the taproot internal key.
	taprootOutputKey := txscript.ComputeTaprootKeyNoScript(&p.InternalKey)

	// Create a new pay-to-taproot pk script from the taproot output key.
	pkScript, err := txscript.PayToTaprootScript(taprootOutputKey)
	if err != nil {
		return zero, fmt.Errorf("unable to create pre-commitment "+
			"output pk script: %w", err)
	}

	// Return the minting anchor transaction pre-commitment output.
	return wire.TxOut{
		Value:    int64(tapsend.DummyAmtSats),
		PkScript: pkScript,
	}, nil
}

// FundedMintAnchorPsbt is a struct that contains a funded minting anchor
// transaction PSBT.
type FundedMintAnchorPsbt struct {
	// FundedPsbt is the PSBT packet that has been funded by the wallet.
	tapsend.FundedPsbt

	// AssetAnchorOutIdx is the index of the asset anchor output in the
	// transaction.
	AssetAnchorOutIdx uint32

	// PreCommitmentOutput contains metadata describing the pre-commitment
	// output.
	//
	// This field is set only if the pre-commitment output exists in the
	// transaction. The pre-commitment output is later spent by the universe
	// commitment transaction.
	PreCommitmentOutput fn.Option[PreCommitmentOutput]
}

// NewFundedMintAnchorPsbt creates a new funded minting anchor PSBT package from
// a funded PSBT.
func NewFundedMintAnchorPsbt(
	fundedPsbt tapsend.FundedPsbt, anchorOutIndexes AnchorTxOutputIndexes,
	preCommitOut fn.Option[PreCommitmentOutput]) (FundedMintAnchorPsbt,
	error) {

	var zero FundedMintAnchorPsbt

	// Sanity check pre-commitment output arguments.
	if anchorOutIndexes.PreCommitOutIdx.IsSome() != preCommitOut.IsSome() {
		return zero, fmt.Errorf("pre-commitment output index and " +
			"pre-commitment output must be both set or both unset")
	}

	return FundedMintAnchorPsbt{
		FundedPsbt:          fundedPsbt,
		AssetAnchorOutIdx:   anchorOutIndexes.AssetAnchorOutIdx,
		PreCommitmentOutput: preCommitOut,
	}, nil
}

// Copy creates a deep copy of FundedMintAnchorPsbt.
func (f *FundedMintAnchorPsbt) Copy() *FundedMintAnchorPsbt {
	newMintAnchorPsbt := &FundedMintAnchorPsbt{
		FundedPsbt: tapsend.FundedPsbt{
			ChangeOutputIndex: f.ChangeOutputIndex,
			ChainFees:         f.ChainFees,
			LockedUTXOs:       fn.CopySlice(f.LockedUTXOs),
		},
		AssetAnchorOutIdx:   f.AssetAnchorOutIdx,
		PreCommitmentOutput: f.PreCommitmentOutput,
	}

	if f.Pkt != nil {
		newMintAnchorPsbt.Pkt = &psbt.Packet{
			UnsignedTx: f.Pkt.UnsignedTx.Copy(),
			Inputs:     fn.CopySlice(f.Pkt.Inputs),
			Outputs:    fn.CopySlice(f.Pkt.Outputs),
			Unknowns:   fn.CopySlice(f.Pkt.Unknowns),
		}
	}

	return newMintAnchorPsbt
}
