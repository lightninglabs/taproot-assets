package tarofreighter

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

// ChainPorterConfig is the main config for the chain porter.
type ChainPorterConfig struct {
	// CoinSelector is the interface used to select input coins (assets)
	// for the transfer.
	CoinSelector CommitmentSelector

	// Signer implements the Taro level signing we need to sign a virtual
	// transaction.
	Signer Signer

	// TxValidator allows us to validate each Taro virtual transaction we
	// create.
	TxValidator taroscript.TxValidator

	// ExportLog is used to log information about pending parcels to disk.
	ExportLog ExportLog

	// ChainBridge is our bridge to the chain we operate on.
	ChainBridge ChainBridge

	// Wallet is used to fund+sign PSBTs for the transfer transaction.
	Wallet WalletAnchor

	// KeyRing is used to generate new keys throughout the transfer
	// process.
	KeyRing KeyRing

	// ChainParams is the chain params of the chain we operate on.
	ChainParams *address.ChainParams

	// AssetProofs is used to write the proof files on disk for the
	// receiver during a transfer.
	//
	// TODO(roasbeef): replace with proof.Courier in the future/
	AssetProofs proof.Archiver

	// ProofCourier is used to optionally deliver the final proof to the
	// user using an asynchronous transport mechanism.
	ProofCourier proof.Courier[address.Taro]

	// ErrChan is the main error channel the custodian will report back
	// critical errors to the main server.
	ErrChan chan<- error
}

// ChainPorter is the main sub-system of the tarofreighter package. The porter
// is responsible for transferring your bags (assets). This porter is
// responsible for taking incoming delivery requests (parcels) and generating a
// final transfer transaction along with all the proofs needed to complete the
// transfer.
type ChainPorter struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *ChainPorterConfig

	exportReqs chan *AssetParcel

	// subscribers is a map of components that want to be notified on new
	// events, keyed by their subscription ID.
	subscribers map[uint64]*chanutils.EventReceiver[chanutils.Event]

	// subscriberMtx guards the subscribers map and access to the
	// subscriptionID.
	subscriberMtx sync.Mutex

	*chanutils.ContextGuard
}

// NewChainPorter creates a new instance of the ChainPorter given a valid
// config.
func NewChainPorter(cfg *ChainPorterConfig) *ChainPorter {
	subscribers := make(
		map[uint64]*chanutils.EventReceiver[chanutils.Event],
	)
	return &ChainPorter{
		cfg:         cfg,
		exportReqs:  make(chan *AssetParcel),
		subscribers: subscribers,
		ContextGuard: &chanutils.ContextGuard{
			DefaultTimeout: tarogarden.DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start kicks off the chain porter and any goroutines it needs to carry out
// its duty.
func (p *ChainPorter) Start() error {
	var startErr error
	p.startOnce.Do(func() {
		log.Infof("Starting ChainPorter")

		// Before we re-launch the main goroutine, we'll make sure to
		// restart any other incomplete sends that may or may not have
		// had the transaction broadcaster.
		ctx, cancel := p.WithCtxQuit()
		defer cancel()
		pendingParcels, err := p.cfg.ExportLog.PendingParcels(ctx)
		if err != nil {
			startErr = err
			return
		}

		log.Infof("Resuming delivery of %v pending asset parcels",
			len(pendingParcels))

		// Now that we have the set of pending sends, we'll make a new
		// goroutine that'll drive the state machine till the broadcast
		// point (which we might be repeating), and final terminal
		// state.
		for _, parcel := range pendingParcels {
			p.Wg.Add(1)
			go p.resumePendingParcel(parcel)
		}

		p.Wg.Add(1)
		go p.taroPorter()
	})

	return startErr
}

// Stop signals that the chain porter should gracefully stop.
func (p *ChainPorter) Stop() error {
	var stopErr error
	p.stopOnce.Do(func() {
		close(p.Quit)
		p.Wg.Wait()

		// Remove all subscribers.
		for _, sub := range p.subscribers {
			err := p.RemoveSubscriber(sub)
			if err != nil {
				stopErr = err
				break
			}
		}
	})

	return stopErr
}

// RequestShipment is the main external entry point to the porter. This request
// a new transfer take place.
func (p *ChainPorter) RequestShipment(req *AssetParcel) (*PendingParcel, error) {
	req.errChan = make(chan error, 1)
	req.respChan = make(chan *PendingParcel, 1)

	log.Infof("New asset shipment request to addr: %v", spew.Sdump(req))

	if !chanutils.SendOrQuit(p.exportReqs, req, p.Quit) {
		return nil, fmt.Errorf("ChainPorter shutting down")
	}

	select {
	case err := <-req.errChan:
		return nil, err

	case resp := <-req.respChan:
		return resp, nil

	case <-p.Quit:
		return nil, fmt.Errorf("ChainPorter shutting down")
	}
}

// resumePendingParcel attempts to resume a pending parcel. A pending parcel
// has already had its transfer transaction broadcast. In this state, we'll
// rebroadcast and then wait for the transfer to confirm.
//
// TODO(roasbeef): consolidate w/ below? or adopt similar arch as ChainPlanter
//   - could move final conf into the state machien itself
func (p *ChainPorter) resumePendingParcel(pkg *OutboundParcelDelta) {
	defer p.Wg.Done()

	log.Infof("Attempting to resume delivery to anchor_point=%v",
		pkg.NewAnchorPoint)

	// To resume the state machine, we'll make a skeleton of a sendPackage,
	// basically just what we need to drive the state machine to further
	// completion.
	restartSendPkg := sendPackage{
		OutboundPkg: pkg,
		SendState:   SendStateBroadcast,
	}

	err := p.advanceState(&restartSendPkg)
	if err != nil {
		// TODO(roasbef): no req to send the error back to here
		log.Warnf("unable to advance state machine: %v", err)
		return
	}
}

// taroPorter is the main goroutine of the ChainPorter. This takes in incoming
// requests, and attempt to complete a transfer. A response is sent back to the
// caller if a transfer can be completed. Otherwise, an error is returned.
func (p *ChainPorter) taroPorter() {
	defer p.Wg.Done()

	for {
		select {
		case req := <-p.exportReqs:
			log.Infof("Received to send request to: %x:%x",
				req.Dest.ID(),
				req.Dest.ScriptKey.SerializeCompressed())

			// Initialize a package with the destination address.
			sendPkg := sendPackage{
				ReqAssetTransfer: req,
			}

			// Advance the state machine for this package as far as
			// possible.
			err := p.advanceState(&sendPkg)
			if err != nil {
				log.Warnf("unable to advance state machine: %v", err)
				req.errChan <- err
				continue
			}

		case <-p.Quit:
			return
		}
	}
}

// waitForTransferTxConf waits for the confirmation of the final transaction
// within the delta. Once confirmed, the parcel will be marked as delivered on
// chain, with the goroutine cleaning up its state.
func (p *ChainPorter) waitForTransferTxConf(pkg *sendPackage) error {
	outboundPkg := pkg.OutboundPkg

	txHash := outboundPkg.AnchorTx.TxHash()
	log.Infof("Waiting for confirmation of transfer_txid=%v", txHash)

	confCtx, confCancel := p.WithCtxQuitNoTimeout()
	confNtfn, errChan, err := p.cfg.ChainBridge.RegisterConfirmationsNtfn(
		confCtx, &txHash, outboundPkg.AnchorTx.TxOut[0].PkScript, 1,
		outboundPkg.AnchorTxHeightHint, true,
	)
	if err != nil {
		return fmt.Errorf("unable to register for package tx conf: %w",
			err)
	}

	// Launch a goroutine that'll notify us when the transaction confirms.
	defer confCancel()

	var confEvent *chainntnfs.TxConfirmation
	select {
	case confEvent = <-confNtfn.Confirmed:
		log.Debugf("Got chain confirmation: %v", confEvent.Tx.TxHash())
		pkg.TransferTxConfEvent = confEvent
		pkg.SendState = SendStateStoreProofs

	case err := <-errChan:
		return fmt.Errorf("error whilst waiting for package tx "+
			"confirmation: %w", err)

	case <-confCtx.Done():
		log.Debugf("Skipping TX confirmation, context done")

	case <-p.Quit:
		log.Debugf("Skipping TX confirmation, exiting")
		return nil
	}

	if confEvent == nil {
		return fmt.Errorf("got empty package tx confirmation event in " +
			"batch")
	}

	return nil
}

// storeProofs writes the updated sender and receiver proof files to the proof
// archive.
func (p *ChainPorter) storeProofs(pkg *sendPackage) error {
	// Now we'll enter the final phase of the send process, where we'll
	// write the receiver's proof file to disk.
	//
	// First, we'll fetch the sender's current proof file.
	ctx, cancel := p.CtxBlocking()
	defer cancel()

	var (
		outboundPkg     = pkg.OutboundPkg
		spendDeltas     = outboundPkg.AssetSpendDeltas
		outboundAssetID = spendDeltas[0].WitnessData[0].PrevID.ID
		locator         = proof.Locator{
			AssetID:   &outboundAssetID,
			ScriptKey: spendDeltas[0].OldScriptKey,
		}
		confEvent = pkg.TransferTxConfEvent
	)

	senderFullProofBytes, err := p.cfg.AssetProofs.FetchProof(ctx, locator)
	if err != nil {
		return fmt.Errorf("error fetching proof: %w", err)
	}
	senderProof := proof.NewEmptyFile(proof.V0)
	err = senderProof.Decode(bytes.NewReader(senderFullProofBytes))
	if err != nil {
		return fmt.Errorf("error decoding proof: %w", err)
	}

	// Now that we have the sender's proof file, we'll decode the new
	// suffix we want to add so we can append it to the sender's file.
	var senderProofSuffix proof.Proof
	err = senderProofSuffix.Decode(
		bytes.NewReader(spendDeltas[0].SenderAssetProof),
	)
	if err != nil {
		return fmt.Errorf("error decoding proof suffix: %w", err)
	}
	err = senderProofSuffix.UpdateTransitionProof(&proof.BaseProofParams{
		Block:   confEvent.Block,
		Tx:      confEvent.Tx,
		TxIndex: int(confEvent.TxIndex),
	})
	if err != nil {
		return fmt.Errorf("error updating sender transition proof: "+
			"%w", err)
	}

	// With the proof suffix updated, we can append the proof, then encode
	// it to get the final sender proof.
	var updatedSenderProof bytes.Buffer
	if err := senderProof.AppendProof(senderProofSuffix); err != nil {
		return fmt.Errorf("error appending sender proof: %w", err)
	}
	if err := senderProof.Encode(&updatedSenderProof); err != nil {
		return fmt.Errorf("error encoding sender proof: %w", err)
	}
	newSenderProof := &proof.AnnotatedProof{
		Locator: proof.Locator{
			AssetID:   &outboundAssetID,
			ScriptKey: *senderProofSuffix.Asset.ScriptKey.PubKey,
		},
		Blob: updatedSenderProof.Bytes(),
	}

	// As a final step, we'll do the same for the receiver's proof as well.
	var receiverProofSuffix proof.Proof
	err = receiverProofSuffix.Decode(
		bytes.NewReader(spendDeltas[0].ReceiverAssetProof),
	)
	if err != nil {
		return fmt.Errorf("error decoding receiver proof: %w", err)
	}
	err = receiverProofSuffix.UpdateTransitionProof(&proof.BaseProofParams{
		Block:   confEvent.Block,
		Tx:      confEvent.Tx,
		TxIndex: int(confEvent.TxIndex),
	})
	if err != nil {
		return fmt.Errorf("error updating receiver transition proof: "+
			"%w", err)
	}

	log.Infof("Importing receiver proof into local Proof Archive")

	// Now we'll write out the final receiver proof to the on disk proof
	// archive.
	var updatedReceiverProof bytes.Buffer
	if err := senderProof.ReplaceLastProof(receiverProofSuffix); err != nil {
		return fmt.Errorf("error replacing receiver proof: %w", err)
	}
	if err := senderProof.Encode(&updatedReceiverProof); err != nil {
		return fmt.Errorf("error encoding receiver proof: %w", err)
	}
	receiverProof := &proof.AnnotatedProof{
		Locator: proof.Locator{
			AssetID:   &outboundAssetID,
			ScriptKey: *receiverProofSuffix.Asset.ScriptKey.PubKey,
		},
		Blob: updatedReceiverProof.Bytes(),
	}

	// Use callback to verify that block header exists on chain.
	headerVerifier := tarogarden.GenHeaderVerifier(ctx, p.cfg.ChainBridge)

	// Import sender proof and receiver proof into proof archive.
	err = p.cfg.AssetProofs.ImportProofs(
		ctx, headerVerifier, receiverProof, newSenderProof,
	)
	if err != nil {
		return fmt.Errorf("error importing proof: %w", err)
	}

	log.Debugf("Updated proofs for sender and receiver (new_len=%d)",
		senderProof.NumProofs())

	pkg.SendState = SendStateReceiverProofTransfer
	return nil
}

// transferReceiverProof retrieves the sender and receiver proofs from the
// archive and then transfers the receiver's proof to the receiver. Upon
// successful transfer, the asset parcel delivery is marked as complete.
func (p *ChainPorter) transferReceiverProof(pkg *sendPackage) error {
	ctx, cancel := p.CtxBlocking()
	defer cancel()

	// Retrieve sender proof from proof archive.
	assetId := pkg.OutboundPkg.AssetSpendDeltas[0].WitnessData[0].PrevID.ID
	senderProofBlob, err := p.cfg.AssetProofs.FetchProof(
		ctx, proof.Locator{
			AssetID:   &assetId,
			ScriptKey: *pkg.SenderScriptKey.PubKey,
		},
	)
	if err != nil {
		return fmt.Errorf("error fetching sender proof: %w", err)
	}

	// Retrieve receiver proof from proof archive.
	locator := proof.Locator{
		AssetID:   &assetId,
		ScriptKey: pkg.ReqAssetTransfer.Dest.ScriptKey,
	}
	receiverProofBlob, err := p.cfg.AssetProofs.FetchProof(ctx, locator)
	if err != nil {
		return fmt.Errorf("error fetching receiver proof: %w", err)
	}
	receiverProof := &proof.AnnotatedProof{
		Locator: locator,
		Blob:    receiverProofBlob,
	}

	// If we have a proof courier instance active, then we'll launch a new
	// goroutine to deliver the proof to the receiver.
	//
	// TODO(roasbeef): move earlier?
	if p.cfg.ProofCourier != nil {
		// TODO(roasbeef): should actually also serialize the
		// addr of the remote party here
		ctx, cancel := p.WithCtxQuitNoTimeout()
		defer cancel()

		err := p.cfg.ProofCourier.DeliverProof(
			ctx, *pkg.ReqAssetTransfer.Dest, receiverProof,
		)

		// If the proof courier returned a backoff error, then
		// we'll just return nil here so that we can retry
		// later.
		var backoffExecErr *proof.BackoffExecError
		if errors.As(err, &backoffExecErr) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("error delivering proof: %w", err)
		}
	}

	log.Infof("Marking parcel (txid=%v) as confirmed!",
		pkg.OutboundPkg.AnchorTx.TxHash())

	// At this point we have the confirmation signal, so we can mark the
	// parcel delivery as completed in the database.
	err = p.cfg.ExportLog.ConfirmParcelDelivery(ctx, &AssetConfirmEvent{
		AnchorPoint:      pkg.OutboundPkg.NewAnchorPoint,
		BlockHash:        *pkg.TransferTxConfEvent.BlockHash,
		BlockHeight:      int32(pkg.TransferTxConfEvent.BlockHeight),
		TxIndex:          int32(pkg.TransferTxConfEvent.TxIndex),
		FinalSenderProof: senderProofBlob,
	})
	if err != nil {
		return fmt.Errorf("unable to log parcel delivery "+
			"confirmation: %w", err)
	}

	pkg.SendState = SendStateComplete
	return nil
}

// advanceState advances the state machine.
func (p *ChainPorter) advanceState(pkg *sendPackage) error {
	// Continue state transitions whilst state complete has not yet
	// been reached.
	for pkg.SendState < SendStateComplete {
		log.Infof("ChainPorter executing state: %v",
			pkg.SendState)

		// Before we attempt a state transition, make sure that
		// we aren't trying to shut down.
		select {
		case <-p.Quit:
			return nil

		default:
		}

		updatedPkg, err := p.stateStep(*pkg)
		if err != nil {
			p.cfg.ErrChan <- err
			log.Errorf("Error evaluating state (%v): %v",
				pkg.SendState, err)
			return err
		}

		pkg = updatedPkg
	}

	return nil
}

// createDummyOutput creates a new Bitcoin transaction output that is later
// used to embed a Taro commitment.
func createDummyOutput() *wire.TxOut {
	// The dummy PkScript is the same size as an encoded P2TR output.
	newOutput := wire.TxOut{
		Value:    int64(taroscript.DummyAmtSats),
		PkScript: make([]byte, 34),
	}
	return &newOutput
}

// adjustFundedPsbt takes a funded PSBT which may have used BIP 69 sorting, and
// creates a new one with outputs shuffled such that the change output is the
// last output.
func adjustFundedPsbt(pkt *tarogarden.FundedPsbt, anchorInputValue int64) {
	// If there is no change there's nothing we need to do.
	changeIndex := pkt.ChangeOutputIndex
	if changeIndex == -1 {
		return
	}

	// Store the script and value of the change output.
	maxOutputIndex := len(pkt.Pkt.UnsignedTx.TxOut) - 1
	changeOutput := pkt.Pkt.UnsignedTx.TxOut[changeIndex]

	// Overwrite the existing change output, and restore in at the
	// highest-index output.
	pkt.Pkt.UnsignedTx.TxOut[changeIndex] = createDummyOutput()
	pkt.Pkt.UnsignedTx.TxOut[maxOutputIndex].PkScript = changeOutput.PkScript
	pkt.Pkt.UnsignedTx.TxOut[maxOutputIndex].Value = changeOutput.Value

	// Since we're adding the input of the anchor output of our prior asset
	// later, we need to add this value here, so we don't lose the amount
	// to fees.
	pkt.Pkt.UnsignedTx.TxOut[maxOutputIndex].Value += anchorInputValue

	// If the change output already is the last output, we don't need to
	// overwrite anything in the PSBT outputs.
	if changeIndex == int32(maxOutputIndex) {
		return
	}

	// We also need to re-assign the PSBT level output information.
	changeOutputInfo := pkt.Pkt.Outputs[changeIndex]
	pkt.Pkt.Outputs[maxOutputIndex] = psbt.POutput{
		RedeemScript:           changeOutputInfo.RedeemScript,
		WitnessScript:          changeOutputInfo.WitnessScript,
		Bip32Derivation:        changeOutputInfo.Bip32Derivation,
		TaprootInternalKey:     changeOutputInfo.TaprootInternalKey,
		TaprootTapTree:         changeOutputInfo.TaprootTapTree,
		TaprootBip32Derivation: changeOutputInfo.TaprootBip32Derivation,
	}
	pkt.Pkt.Outputs[changeIndex] = psbt.POutput{}
	pkt.ChangeOutputIndex = int32(maxOutputIndex)
}

// stateStep attempts to step through the state machine to complete a Taro
// transfer.
func (p *ChainPorter) stateStep(currentPkg sendPackage) (*sendPackage, error) {
	// Notify subscribers that the state machine is about to execute a
	// state.
	stateEvent := NewExecuteSendStateEvent(currentPkg.SendState)
	p.publishSubscriberEvent(stateEvent)

	switch currentPkg.SendState {
	// In this initial state, we'll set up some initial state we need to
	// carry out the send flow.
	case SendStateInitializing:
		// As a sanity check, make sure the chain params are properly
		// specified.
		if p.cfg.ChainParams == nil {
			return nil, fmt.Errorf("network for send unspecified")
		}

		currentPkg.SendDelta = &taroscript.SpendDelta{
			InputAssets: make(commitment.InputSet),
		}

		currentPkg.SendState = SendStateCommitmentSelect

		return &currentPkg, nil

	// At this point we have the initial package information populated, so
	// we'll perform coin selection to see if the send request is even
	// possible at all.
	case SendStateCommitmentSelect:
		ctx, cancel := p.WithCtxQuitNoTimeout()
		defer cancel()

		// We need to find a commitment that has enough assets to
		// satisfy this send request. We'll map the address to a set of
		// constraints, so we can use that to do Taro asset coin
		// selection.
		//
		// TODO(roasbeef): send logic assumes just one input (no
		// merges) so we pass in the amount here to ensure we have
		// enough to send
		assetID := currentPkg.ReqAssetTransfer.Dest.ID()
		constraints := CommitmentConstraints{
			GroupKey: currentPkg.ReqAssetTransfer.Dest.GroupKey,
			AssetID:  &assetID,
			MinAmt:   currentPkg.ReqAssetTransfer.Dest.Amount,
		}
		eligibleCommitments, err := p.cfg.CoinSelector.SelectCommitment(
			ctx, constraints,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to complete coin "+
				"selection: %w", err)
		}

		taroAddr := currentPkg.ReqAssetTransfer.Dest
		log.Infof("Selected %v possible asset inputs for send to %x",
			len(eligibleCommitments),
			taroAddr.ScriptKey.SerializeCompressed())

		// We'll take just the first commitment here as we need enough
		// to complete the send w/o merging inputs.
		assetInput := eligibleCommitments[0]

		// If the key found for the input UTXO is not from the Taro
		// keyfamily, something has gone wrong with the DB.
		if assetInput.InternalKey.Family != asset.TaroKeyFamily {
			return nil, fmt.Errorf("invalid internal key family "+
				"for selected input: %v %v",
				assetInput.InternalKey.Family,
				assetInput.InternalKey.Index,
			)
		}

		// At this point, we have a valid "coin" to spend in the
		// commitment, so we'll update the relevant information in the
		// send package.
		//
		// TODO(roasbeef): still need to add family key to PrevID.
		currentPkg.InputAssetPrevID = asset.PrevID{
			OutPoint: assetInput.AnchorPoint,
			ID:       assetInput.Asset.ID(),
			ScriptKey: asset.ToSerialized(
				assetInput.Asset.ScriptKey.PubKey,
			),
		}
		currentPkg.InputAsset = assetInput

		currentPkg.SendState = SendStateValidatedInput

		return &currentPkg, nil

	// Now that we have our set of inputs selected, we'll validate them to
	// make sure that they're enough to satisfy our send request.
	case SendStateValidatedInput:
		ctx, cancel := p.WithCtxQuitNoTimeout()
		defer cancel()

		// We'll validate the selected input and commitment. From this
		// we'll gain the asset that we'll use as an input and info
		// w.r.t if we need to use an unspendable zero-value root.
		inputAsset, fullValue, err := taroscript.IsValidInput(
			currentPkg.InputAsset.Commitment,
			*currentPkg.ReqAssetTransfer.Dest,
			*currentPkg.InputAsset.Asset.ScriptKey.PubKey,
			*p.cfg.ChainParams,
		)
		if err != nil {
			return nil, err
		}

		currentPkg.SendDelta.InputAssets[currentPkg.InputAssetPrevID] = inputAsset

		// Before we can prepare output assets for our send, we need to
		// generate a new internal key and script key. The script key
		// is needed for asset change, and the internal key will anchor
		// the send itself.
		//
		// TODO(jhb): ScriptKey derivation instructions should be
		// specified in the AssetParcel
		currentPkg.SenderNewInternalKey, err = p.cfg.KeyRing.DeriveNextKey(
			ctx, asset.TaroKeyFamily,
		)
		if err != nil {
			return nil, err
		}

		// If we are sending the full value of the input asset, or
		// sending a collectible, we will need to create a split with
		// unspendable change.
		if fullValue {
			currentPkg.SenderScriptKey = asset.NUMSScriptKey
		} else {
			senderScriptKey, err := p.cfg.KeyRing.DeriveNextKey(
				ctx, asset.TaroKeyFamily,
			)
			if err != nil {
				return nil, err
			}

			// We'll assume BIP 86 everywhere, and use the tweaked key from
			// here on out.
			currentPkg.SenderScriptKey = asset.NewScriptKeyBIP0086(
				senderScriptKey,
			)
		}

		currentPkg.SendState = SendStatePreparedSplit

		return &currentPkg, nil

	// At this point, we know a split is required in order to complete the
	// send, so we'll make a split with our root change output and the rest
	// of the created outputs.
	case SendStatePreparedSplit:
		preparedSpend, err := taroscript.PrepareAssetSplitSpend(
			*currentPkg.ReqAssetTransfer.Dest,
			currentPkg.InputAssetPrevID,
			*currentPkg.SenderScriptKey.PubKey,
			*currentPkg.SendDelta,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create split "+
				"commit: %w", err)
		}

		currentPkg.SendDelta = preparedSpend

		currentPkg.SendState = SendStateSigned

		return &currentPkg, nil

	// At this point, we have everything we need to sign our _virtual_
	// transaction on the Taro layer.
	case SendStateSigned:
		addr := currentPkg.ReqAssetTransfer.Dest
		log.Infof("Generating Taro witnesses for send to: %x",
			addr.ScriptKey.SerializeCompressed())

		// Now we'll use the signer to sign all the inputs for the new
		// taro leaves. The witness data for each input will be
		// assigned for us.
		completedSpend, err := taroscript.CompleteAssetSpend(
			*currentPkg.InputAsset.Asset.ScriptKey.RawKey.PubKey,
			*currentPkg.SendDelta, p.cfg.Signer, p.cfg.TxValidator,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to generate taro "+
				"witness data: %w", err)
		}

		currentPkg.SendDelta = completedSpend

		currentPkg.SendState = SendStateCommitmentsUpdated

		return &currentPkg, nil

	// With our new asset (our change output) fully signed, we'll now
	// generate the top-level Taro commitments for the sender and the
	// receiver.
	case SendStateCommitmentsUpdated:
		spendCommitments, err := taroscript.CreateSpendCommitments(
			currentPkg.InputAsset.Commitment,
			currentPkg.InputAssetPrevID, *currentPkg.SendDelta,
			*currentPkg.ReqAssetTransfer.Dest,
			*currentPkg.SenderScriptKey.PubKey,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create new output "+
				"commitments: %w", err)
		}

		addr := currentPkg.ReqAssetTransfer.Dest
		log.Infof("Constructing new Taro commitments for send to: %x",
			addr.ScriptKey.SerializeCompressed())

		currentPkg.NewOutputCommitments = spendCommitments

		// Otherwise, we can go straight to stamping things as we have
		// them w/ the PSBT.
		currentPkg.SendState = SendStatePsbtFund

		return &currentPkg, nil

	// With all the internal Taro signing taken care of, we can now make
	// our initial skeleton PSBT packet to send off to the wallet for
	// funding.
	case SendStatePsbtFund:
		ctx, cancel := p.WithCtxQuitNoTimeout()
		defer cancel()

		// Construct our template PSBT to commits to the set of dummy
		// locators we use to make fee estimation work.
		sendPacket, err := taroscript.CreateTemplatePsbt(
			currentPkg.SendDelta.Locators,
		)
		if err != nil {
			return nil, err
		}

		// Submit the template PSBT to the wallet for funding.
		//
		// TODO(roasbeef): unlock the input UTXOs of things fail
		feeRate, err := p.cfg.ChainBridge.EstimateFee(
			ctx, taroscript.SendConfTarget,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to estimate fee: %w", err)
		}
		fundedSendPacket, err := p.cfg.Wallet.FundPsbt(
			ctx, sendPacket, 1, feeRate,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fund psbt: %w", err)
		}

		// TODO(roasbeef): also want to log the total fee to disk for
		// accounting, etc.

		// Move the change output to the highest-index output, so that
		// we don't overwrite it when embedding our Taro commitments.
		//
		// TODO(jhb): Do we need richer handling for the change output?
		// We could reassign the change value to our Taro change output
		// and remove the change output entirely.
		adjustFundedPsbt(
			&fundedSendPacket,
			int64(currentPkg.InputAsset.AnchorOutputValue),
		)

		log.Infof("Received funded PSBT packet: %v",
			spew.Sdump(fundedSendPacket.Pkt))

		// We keep the original funded PSBT with all the wallet's output
		// information on the change output preserved but continue the
		// signing process with a copy to avoid clearing the info on
		// finalization.
		currentPkg.FundedPkt = &fundedSendPacket
		currentPkg.SendPkt, err = copyPsbt(fundedSendPacket.Pkt)
		if err != nil {
			return nil, fmt.Errorf("error copying funded PSBT: %w",
				err)
		}

		currentPkg.TargetFeeRate = feeRate

		currentPkg.SendState = SendStatePsbtSign

		return &currentPkg, nil

	// SendStatePsbtSign in this state we'll create the final PSBT packet,
	// to submit to the wallet to sign its set of inputs.
	case SendStatePsbtSign:
		// First, we'll update the PSBT packets to insert the _real_
		// outputs we need to commit to the asset transfer.
		err := taroscript.CreateSpendOutputs(
			*currentPkg.ReqAssetTransfer.Dest,
			currentPkg.SendDelta.Locators,
			*currentPkg.SenderNewInternalKey.PubKey,
			*currentPkg.SenderScriptKey.PubKey,
			currentPkg.NewOutputCommitments, currentPkg.SendPkt,
		)
		if err != nil {
			return &currentPkg, err
		}

		// Now that all the real outputs are in the PSBT, we'll also
		// add our anchor input as well, since the wallet can sign for
		// it itself.
		err = currentPkg.addAnchorPsbtInput()
		if err != nil {
			return &currentPkg, err
		}

		ctx, cancel := p.WithCtxQuitNoTimeout()
		defer cancel()

		// With all the input and output information in the packet, we
		// can now ask lnd to sign it, and then extract the final
		// version ourselves.
		signedPsbt, err := p.cfg.Wallet.SignPsbt(
			ctx, currentPkg.SendPkt,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to sign psbt: %w", err)
		}

		log.Debugf("Got signed PSBT: %s", spew.Sdump(signedPsbt))

		err = psbt.MaybeFinalizeAll(signedPsbt)
		if err != nil {
			return nil, fmt.Errorf("unable to finalize psbt: %w", err)
		}

		currentPkg.SendPkt = signedPsbt

		currentPkg.SendState = SendStateLogCommit

		return &currentPkg, nil

	// At this state, we have a final PSBT transaction which is fully
	// signed. We'll write this to disk (the point of no return), then
	// broadcast this to the network.
	case SendStateLogCommit:
		// Extract the final packet from the PSBT transaction (has all
		// sigs included).
		var err error
		currentPkg.TransferTx, err = psbt.Extract(currentPkg.SendPkt)
		if err != nil {
			return nil, err
		}

		// Now we'll grab our new commitment, and also the output index
		// to populate the log entry below.
		senderCommitKey := asset.AssetCommitmentKey(
			currentPkg.InputAssetPrevID.ID,
			currentPkg.SenderScriptKey.PubKey,
			currentPkg.InputAsset.Asset.GroupKey == nil,
		)
		newSenderCommitment := currentPkg.NewOutputCommitments[senderCommitKey]
		anchorOutputIndex := currentPkg.SendDelta.Locators[senderCommitKey].OutputIndex

		var tapscriptSibling *chainhash.Hash
		if currentPkg.InputAsset.TapscriptSibling != nil {
			h, err := chainhash.NewHash(
				currentPkg.InputAsset.TapscriptSibling,
			)
			if err != nil {
				return nil, err
			}

			tapscriptSibling = h
		}

		taroRoot := newSenderCommitment.TapscriptRoot(
			tapscriptSibling,
		)

		spendProofs, err := currentPkg.createProofs()
		if err != nil {
			return nil, err
		}

		// Before we write to disk, we'll make the incomplete proofs
		// for the sender and the receiver.
		senderAssetProof := spendProofs[asset.ToSerialized(
			currentPkg.SenderScriptKey.PubKey,
		)]
		var senderProofBuf bytes.Buffer
		if err := senderAssetProof.Encode(&senderProofBuf); err != nil {
			return nil, err
		}

		receiverAssetProof := spendProofs[asset.ToSerialized(
			&currentPkg.ReqAssetTransfer.Dest.ScriptKey,
		)]
		var receiverProofBuf bytes.Buffer
		if err := receiverAssetProof.Encode(&receiverProofBuf); err != nil {
			return nil, err
		}

		chainFees, err := tarogarden.GetTxFee(currentPkg.SendPkt)
		if err != nil {
			return nil, fmt.Errorf("unable to get on-chain fees "+
				"for psbt: %w", err)
		}

		// Before we can broadcast, we want to find out the current height to
		// pass as a height hint.
		ctx, cancel := p.WithCtxQuit()
		defer cancel()
		currentHeight, err := p.cfg.ChainBridge.CurrentHeight(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to get current "+
				"height: %v", err)
		}

		// Before we broadcast, we'll write to disk that we have a
		// pending outbound parcel. If we crash before this point,
		// we'll start all over. Otherwise, we'll come back to this
		// state to re-do the process.
		//
		// TODO(roasbeef); need to update proof file information,
		// ideally the db doesn't do this directly
		newAsset := currentPkg.SendDelta.NewAsset
		currentPkg.OutboundPkg = &OutboundParcelDelta{
			OldAnchorPoint: currentPkg.InputAssetPrevID.OutPoint,
			NewAnchorPoint: wire.OutPoint{
				Hash:  currentPkg.TransferTx.TxHash(),
				Index: anchorOutputIndex,
			},
			NewInternalKey:     currentPkg.SenderNewInternalKey,
			TaroRoot:           taroRoot[:],
			AnchorTx:           currentPkg.TransferTx,
			AnchorTxHeightHint: currentHeight,
			AssetSpendDeltas: []AssetSpendDelta{
				{
					OldScriptKey:        *currentPkg.InputAsset.Asset.ScriptKey.PubKey,
					NewAmt:              newAsset.Amount,
					NewScriptKey:        currentPkg.SenderScriptKey,
					WitnessData:         newAsset.PrevWitnesses,
					SplitCommitmentRoot: newAsset.SplitCommitmentRoot,
					SenderAssetProof:    senderProofBuf.Bytes(),
					ReceiverAssetProof:  receiverProofBuf.Bytes(),
				},
			},
			TapscriptSibling: currentPkg.InputAsset.TapscriptSibling,
			// TODO(bhandras): use clock.Clock instead.
			TransferTime: time.Now(),
			ChainFees:    chainFees,
		}

		// Don't allow shutdown while we're attempting to store proofs.
		ctx, cancel = p.CtxBlocking()
		defer cancel()

		log.Infof("Committing pending parcel to disk")

		err = p.cfg.ExportLog.LogPendingParcel(
			ctx, currentPkg.OutboundPkg,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to write send pkg to "+
				"disk: %v", err)
		}

		// We've logged the state transition to disk, so now we can
		// move onto the broadcast phase.
		currentPkg.SendState = SendStateBroadcast

		return &currentPkg, nil

	// In this state we broadcast the transaction to the network, then
	// launch a goroutine to notify us on confirmation.
	case SendStateBroadcast:
		ctx, cancel := p.WithCtxQuitNoTimeout()
		defer cancel()

		// We'll need to extract the output public key from the tx out
		// that does the send. We'll use this shortly below as a step
		// before broadcast.
		//
		// TODO(roasbeef): cache before?
		anchorIndex := currentPkg.OutboundPkg.NewAnchorPoint.Index
		anchorOutput := currentPkg.OutboundPkg.AnchorTx.TxOut[anchorIndex]
		_, witProgram, err := txscript.ExtractWitnessProgramInfo(
			anchorOutput.PkScript,
		)
		if err != nil {
			return nil, err
		}
		anchorOutputKey, err := schnorr.ParsePubKey(witProgram)
		if err != nil {
			return nil, err
		}

		// Before we broadcast the transaction to the network, we'll
		// import the new anchor output into the wallet so it watches
		// it for spends and also takes account of the BTC we used in
		// the transfer.
		_, err = p.cfg.Wallet.ImportTaprootOutput(ctx, anchorOutputKey)
		switch {
		case err == nil:
			break

		// On restart, we'll get an error that the output has already
		// been added to the wallet, so we'll catch this now and move
		// along if so.
		case strings.Contains(err.Error(), "already exists"):
			break

		case err != nil:
			return nil, err
		}

		log.Infof("Broadcasting new transfer tx, taro_anchor_output=%v",
			spew.Sdump(anchorOutput))

		// With the public key imported, we can now broadcast to the
		// network.
		err = p.cfg.ChainBridge.PublishTransaction(
			ctx, currentPkg.OutboundPkg.AnchorTx,
		)
		if err != nil {
			return nil, err
		}

		// With the transaction broadcast, we'll deliver a
		// notification via the transaction broadcast response channel.
		currentPkg.deliverTxBroadcastResp()

		// Set send state to the next state to evaluate.
		currentPkg.SendState = SendStateWaitTxConf
		return &currentPkg, nil

	// At this point, transaction broadcast is complete. We go on to wait
	// for the transfer transaction to confirm on-chain.
	case SendStateWaitTxConf:
		err := p.waitForTransferTxConf(&currentPkg)
		return &currentPkg, err

	// At this point, the transfer transaction is confirmed on-chain. We go
	// on to store the sender and receiver proofs in the proof archive.
	case SendStateStoreProofs:
		err := p.storeProofs(&currentPkg)
		return &currentPkg, err

	// At this point, the transfer transaction is confirmed on-chain. We go
	// on to store the sender and receiver proofs in the proof archive.
	case SendStateReceiverProofTransfer:
		err := p.transferReceiverProof(&currentPkg)
		return &currentPkg, err

	default:
		return &currentPkg, fmt.Errorf("unknown state: %v",
			currentPkg.SendState)
	}
}

// RegisterSubscriber adds a new subscriber to the set of subscribers that will
// be notified of any new events that are broadcast.
//
// TODO(ffranr): Add support for delivering existing events to new subscribers.
func (p *ChainPorter) RegisterSubscriber(
	receiver *chanutils.EventReceiver[chanutils.Event],
	deliverExisting bool, deliverFrom bool) error {

	p.subscriberMtx.Lock()
	defer p.subscriberMtx.Unlock()

	p.subscribers[receiver.ID()] = receiver

	// If we have a proof courier, we'll also update its subscribers.
	if p.cfg.ProofCourier != nil {
		p.cfg.ProofCourier.SetSubscribers(p.subscribers)
	}

	return nil
}

// RemoveSubscriber removes a subscriber from the set of subscribers that will
// be notified of any new events that are broadcast.
func (p *ChainPorter) RemoveSubscriber(
	subscriber *chanutils.EventReceiver[chanutils.Event]) error {

	p.subscriberMtx.Lock()
	defer p.subscriberMtx.Unlock()

	_, ok := p.subscribers[subscriber.ID()]
	if !ok {
		return fmt.Errorf("subscriber with ID %d not found",
			subscriber.ID())
	}

	subscriber.Stop()
	delete(p.subscribers, subscriber.ID())

	// If we have a proof courier, we'll also update its subscribers.
	if p.cfg.ProofCourier != nil {
		p.cfg.ProofCourier.SetSubscribers(p.subscribers)
	}

	return nil
}

// publishSubscriberEvent publishes an event to all subscribers.
func (p *ChainPorter) publishSubscriberEvent(event chanutils.Event) {
	// Lock the subscriber mutex to ensure that we don't modify the
	// subscriber map while we're iterating over it.
	p.subscriberMtx.Lock()
	defer p.subscriberMtx.Unlock()

	for _, sub := range p.subscribers {
		sub.NewItemCreated.ChanIn() <- event
	}
}

// A compile-time assertion to make sure ChainPorter satisfies the
// chanutils.EventPublisher interface.
var _ chanutils.EventPublisher[chanutils.Event, bool] = (*ChainPorter)(nil)

// ExecuteSendStateEvent is an event which is sent to the ChainPorter's event
// subscribers before a state is executed.
type ExecuteSendStateEvent struct {
	// timestamp is the time the event was created.
	timestamp time.Time

	// SendState is the state that is about to be executed.
	SendState SendState
}

// Timestamp returns the timestamp of the event.
func (e *ExecuteSendStateEvent) Timestamp() time.Time {
	return e.timestamp
}

// NewExecuteSendStateEvent creates a new ExecuteSendStateEvent.
func NewExecuteSendStateEvent(state SendState) *ExecuteSendStateEvent {
	return &ExecuteSendStateEvent{
		timestamp: time.Now().UTC(),
		SendState: state,
	}
}

// copyPsbt creates a deep copy of a PSBT packet by serializing and
// de-serializing it.
func copyPsbt(pkg *psbt.Packet) (*psbt.Packet, error) {
	var buf bytes.Buffer
	if err := pkg.Serialize(&buf); err != nil {
		return nil, err
	}

	return psbt.NewFromRawBytes(&buf, false)
}
