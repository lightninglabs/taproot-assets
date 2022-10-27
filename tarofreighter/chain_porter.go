package tarofreighter

import (
	"bytes"
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

	*chanutils.ContextGuard
}

// NewChainPorter creates a new instance of the ChainPorter given a valid
// config.
func NewChainPorter(cfg *ChainPorterConfig) *ChainPorter {
	return &ChainPorter{
		cfg:        cfg,
		exportReqs: make(chan *AssetParcel),
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
	_, err := p.advanceStateUntil(
		&restartSendPkg, SendStateBroadcast,
	)
	if err != nil {
		// TODO(roasbef): no req to send the error back to here
		log.Warnf("unable to advance state machine: %v", err)
		return
	}

	// Now that the transfer tx has (maybe) been rebroadcast, we'll now
	// trigger to wait for the final package information.
	p.waitForPkgConfirmation(pkg)
}

// taroPorter is the main goroutine of the ChainPorter. This takes in incoming
// requests, and attempt to complete a transfer. A response is sent back to the
// caller if a transfer can be completed. Otherwise an error is returned.
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
				ReceiverAddr: req.Dest,
			}

			// Advance the state machine for this package until we
			// reach the state that we broadcast the transaction
			// that completes the transfer.
			advancedPkg, err := p.advanceStateUntil(
				&sendPkg, SendStateBroadcast,
			)
			if err != nil {
				log.Warnf("unable to advance state machine: %v", err)
				req.errChan <- err
				continue
			}

			// With the transaction broadcast, we'll deliver a
			// a response back to the original caller.
			advancedPkg.deliverResponse(req.respChan)

			// Now that we broadcast the transaction, we'll
			// create a goroutine that'll wait for the confirmation
			// then update everything on disk.
			p.Wg.Add(1)
			go p.waitForPkgConfirmation(advancedPkg.OutboundPkg)

		case <-p.Quit:
			return
		}
	}
}

// waitForPkgConfirmation waits for the confirmation of the final transaction
// within the delta. Once confirmed, the parcel will be marked as delivered on
// chain, with the goroutine cleaning up its state.
func (p *ChainPorter) waitForPkgConfirmation(pkg *OutboundParcelDelta) {
	defer p.Wg.Done()

	mkErr := func(format string, args ...interface{}) error {
		logFormat := strings.ReplaceAll(format, "%w", "%v")
		log.Errorf("Error waiting for package confirmation: "+
			logFormat, args...)
		return fmt.Errorf(format, args...)
	}

	txHash := pkg.AnchorTx.TxHash()

	log.Infof("Waiting for confirmation of transfer_txid=%v", txHash)

	// Before we can broadcast, we want to find out the current height to
	// pass as a height hint.
	ctx, cancel := p.WithCtxQuit()
	defer cancel()
	currentHeight, err := p.cfg.ChainBridge.CurrentHeight(ctx)
	if err != nil {
		p.cfg.ErrChan <- mkErr("unable to get current height: %v", err)
		return
	}

	confCtx, confCancel := p.WithCtxQuitNoTimeout()
	confNtfn, errChan, err := p.cfg.ChainBridge.RegisterConfirmationsNtfn(
		confCtx, &txHash, pkg.AnchorTx.TxOut[0].PkScript, 1,
		currentHeight, true,
	)
	if err != nil {
		p.cfg.ErrChan <- mkErr("unable to register for tx conf: %v",
			err)
		return
	}

	// Launch a goroutine that'll notify us when the transaction confirms.
	defer confCancel()

	var confEvent *chainntnfs.TxConfirmation
	select {
	case confEvent = <-confNtfn.Confirmed:
		log.Debugf("Got chain confirmation: %v", confEvent.Tx.TxHash())

	case err := <-errChan:
		p.cfg.ErrChan <- mkErr("error getting confirmation: %w", err)
		return

	case <-confCtx.Done():
		log.Debugf("Skipping TX confirmation, context done")

	case <-p.Quit:
		log.Debugf("Skipping TX confirmation, exiting")
		return
	}

	if confEvent == nil {
		p.cfg.ErrChan <- mkErr("got empty confirmation event in batch")
		return
	}

	// Now we'll enter the final phase of the send process, where we'll
	// write the receiver's proof file to disk.
	//
	// First, we'll fetch the sender's current proof file.
	ctx, cancel = p.CtxBlocking()
	defer cancel()
	senderFullProofBytes, err := p.cfg.AssetProofs.FetchProof(ctx, proof.Locator{
		AssetID:   &pkg.AssetSpendDeltas[0].WitnessData[0].PrevID.ID,
		ScriptKey: pkg.AssetSpendDeltas[0].OldScriptKey,
	})
	if err != nil {
		p.cfg.ErrChan <- mkErr("error fetching proof: %v", err)
		return
	}
	senderProof := proof.NewEmptyFile(proof.V0)
	err = senderProof.Decode(bytes.NewReader(senderFullProofBytes))
	if err != nil {
		p.cfg.ErrChan <- mkErr("error decoding proof: %v", err)
		return
	}

	// Now that we have the sender's proof file, we'll decode the new
	// suffix we want to add so we can append it to the sender's file.
	var senderProofSuffix proof.Proof
	err = senderProofSuffix.Decode(
		bytes.NewReader(pkg.AssetSpendDeltas[0].SenderAssetProof),
	)
	if err != nil {
		p.cfg.ErrChan <- mkErr("error decoding proof suffix: %v", err)
		return
	}
	err = senderProofSuffix.UpdateTransitionProof(&proof.BaseProofParams{
		Block:   confEvent.Block,
		Tx:      confEvent.Tx,
		TxIndex: int(confEvent.TxIndex),
	})
	if err != nil {
		p.cfg.ErrChan <- mkErr("error updating sender transition "+
			"proof: %v", err)
		return
	}

	// With the proof suffix updated, we can append the proof, then encode
	// it to get the final sender proof.
	var updatedSenderProof bytes.Buffer
	if err := senderProof.AppendProof(senderProofSuffix); err != nil {
		p.cfg.ErrChan <- mkErr("error appending sender proof: %v", err)
		return
	}
	if err := senderProof.Encode(&updatedSenderProof); err != nil {
		p.cfg.ErrChan <- mkErr("error encoding sender proof: %v", err)
		return
	}
	newSenderProof := &proof.AnnotatedProof{
		Locator: proof.Locator{
			AssetID:   &pkg.AssetSpendDeltas[0].WitnessData[0].PrevID.ID,
			ScriptKey: *senderProofSuffix.Asset.ScriptKey.PubKey,
		},
		Blob: updatedSenderProof.Bytes(),
	}

	// As a final step, we'll do the same for the receiver's proof as well.
	var receiverProofSuffix proof.Proof
	err = receiverProofSuffix.Decode(
		bytes.NewReader(pkg.AssetSpendDeltas[0].ReceiverAssetProof),
	)
	if err != nil {
		p.cfg.ErrChan <- mkErr("error decoding receiver proof: %v", err)
		return
	}
	err = receiverProofSuffix.UpdateTransitionProof(&proof.BaseProofParams{
		Block:   confEvent.Block,
		Tx:      confEvent.Tx,
		TxIndex: int(confEvent.TxIndex),
	})
	if err != nil {
		p.cfg.ErrChan <- mkErr("error updating receiver transition "+
			"proof: %v", err)
		return
	}

	log.Infof("Importing receiver proof into local Proof Archive")

	// Now we'll write out the final receiver proof to the on disk proof
	// archive.
	var updatedReceiverProof bytes.Buffer
	if err := senderProof.ReplaceLastProof(receiverProofSuffix); err != nil {
		p.cfg.ErrChan <- mkErr("error replacing receiver proof: %v", err)
		return
	}
	if err := senderProof.Encode(&updatedReceiverProof); err != nil {
		p.cfg.ErrChan <- mkErr("error encoding receiver proof: %v", err)
		return
	}
	receiverProof := &proof.AnnotatedProof{
		Locator: proof.Locator{
			AssetID:   &pkg.AssetSpendDeltas[0].WitnessData[0].PrevID.ID,
			ScriptKey: *receiverProofSuffix.Asset.ScriptKey.PubKey,
		},
		Blob: updatedReceiverProof.Bytes(),
	}
	err = p.cfg.AssetProofs.ImportProofs(
		ctx, receiverProof, newSenderProof,
	)
	if err != nil {
		p.cfg.ErrChan <- mkErr("error importing proof: %v", err)
		return
	}

	log.Debugf("Updated proofs for sender and receiver (new_len=%d)",
		senderProof.NumProofs())

	// If we have a proof courier instance active, then we'll launch a new
	// goroutine to deliver the proof to the receiver.
	//
	// TODO(roasbeef): move earlier?
	if p.cfg.ProofCourier != nil {
		p.Wg.Add(1)
		go func() {
			defer p.Wg.Done()

			// TODO(roasbeef): should actually also serialize the
			// addr of the remote party here
			addr := address.Taro{
				Genesis:   receiverProofSuffix.Asset.Genesis,
				ScriptKey: receiverProof.ScriptKey,
				Amount:    receiverProofSuffix.Asset.Amount,
			}
			ctx, cancel := p.WithCtxQuitNoTimeout()
			defer cancel()
			err := p.cfg.ProofCourier.DeliverProof(
				ctx, addr, receiverProof,
			)
			if err != nil {
				log.Errorf("unable to deliver proof: %v", err)
			}
		}()
	}

	log.Infof("Marking parcel (txid=%v) as confirmed!", txHash)

	// At this point we have the confirmation signal, so we can mark the
	// parcel delivery as completed in the database.
	err = p.cfg.ExportLog.ConfirmParcelDelivery(ctx, &AssetConfirmEvent{
		AnchorPoint:      pkg.NewAnchorPoint,
		BlockHash:        *confEvent.BlockHash,
		BlockHeight:      int32(confEvent.BlockHeight),
		TxIndex:          int32(confEvent.TxIndex),
		FinalSenderProof: updatedSenderProof.Bytes(),
	})
	if err != nil {
		p.cfg.ErrChan <- mkErr("unable to log tx conf: %w", err)
		return
	}

	return
}

// advanceStateUntil will advance the state machine until the next state is the
// target state.
func (p *ChainPorter) advanceStateUntil(currentPkg *sendPackage,
	targetState SendState) (*sendPackage, error) {

	log.Infof("ChainPorter advancing from state=%v to state=%v",
		currentPkg.SendState, targetState)

	currentState := currentPkg.SendState

	var terminalState bool
	for !terminalState {
		// Before we attempt a state transition, make sure that we
		// aren't trying to shut down.
		select {
		case <-p.Quit:
			return nil, fmt.Errorf("porter shutting down")

		default:
		}

		updatedPkg, err := p.stateStep(*currentPkg)
		if err != nil {
			return nil, err
		}

		// We've reached a terminal state once the next state is our
		// current state (state machine loops back to the current
		// state).
		terminalState = updatedPkg.SendState == currentState

		currentState = updatedPkg.SendState

		currentPkg = updatedPkg
	}

	return currentPkg, nil
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

// adjustFundedPsbt takes a PSBT which may have used BIP 69 sorting, and
// creates a new one with outputs shuffled such that the change output is the
// last output.
func adjustFundedPsbt(pkt *psbt.Packet, changeIndex uint32,
	anchorInputValue int64) {
	// Store the script and value of the change output.
	changeOutput := pkt.UnsignedTx.TxOut[changeIndex]
	changeAmtSats := changeOutput.Value
	changeScript := changeOutput.PkScript

	// Overwrite the existing change output, and restore in at the
	// highest-index output.
	maxOutputIndex := len(pkt.UnsignedTx.TxOut) - 1
	pkt.UnsignedTx.TxOut[changeIndex] = createDummyOutput()
	pkt.UnsignedTx.TxOut[maxOutputIndex].PkScript = changeScript
	pkt.UnsignedTx.TxOut[maxOutputIndex].Value = changeAmtSats

	// Since we're adding the input of the anchor output of our prior asset
	// later, we need to add this value here, so we don't lose the amount
	// to fees.
	pkt.UnsignedTx.TxOut[maxOutputIndex].Value += anchorInputValue
}

// stateStep attempts to step through the state machine to complete a Taro
// transfer.
func (p *ChainPorter) stateStep(currentPkg sendPackage) (*sendPackage, error) {
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
		assetID := currentPkg.ReceiverAddr.ID()
		constraints := CommitmentConstraints{
			FamilyKey: currentPkg.ReceiverAddr.FamilyKey,
			AssetID:   &assetID,
			MinAmt:    currentPkg.ReceiverAddr.Amount,
		}
		elgigibleCommitments, err := p.cfg.CoinSelector.SelectCommitment(
			ctx, constraints,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to complete coin "+
				"selection: %w", err)
		}

		log.Infof("Selected %v possible asset inputs for send to %x",
			len(elgigibleCommitments),
			currentPkg.ReceiverAddr.ScriptKey.SerializeCompressed())

		// We'll take just the first commitment here as we need enough
		// to complete the send w/o merging inputs.
		assetInput := elgigibleCommitments[0]

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
		// w.r.t if we need to split or not.
		inputAsset, needsSplit, err := taroscript.IsValidInput(
			currentPkg.InputAsset.Commitment, *currentPkg.ReceiverAddr,
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
			ctx, tarogarden.TaroKeyFamily,
		)
		if err != nil {
			return nil, err
		}

		// If we are sending the full value of the input asset, we will
		// need to create a split with unspendable change.
		if inputAsset.Type == asset.Normal && !needsSplit {
			currentPkg.SenderScriptKey = asset.NUMSScriptKey
		} else {
			senderScriptKey, err := p.cfg.KeyRing.DeriveNextKey(
				ctx, tarogarden.TaroKeyFamily,
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

		// If we need to split (addr amount < input amount), then we'll
		// transition to prepare the set of splits. If not,then we can
		// assume the splits are unnecessary.
		//
		// TODO(roasbeef): always need to split anyway see:
		// https://github.com/lightninglabs/taro/issues/121
		if inputAsset.Type == asset.Normal {
			currentPkg.SendState = SendStatePreparedSplit
		} else {
			currentPkg.SendState = SendStatePreparedComplete
		}

		return &currentPkg, nil

	// At this point, we know a split is required in order to complete the
	// send, so we'll make a split with our root change output and the rest
	// of the created outputs.
	case SendStatePreparedSplit:
		preparedSpend, err := taroscript.PrepareAssetSplitSpend(
			*currentPkg.ReceiverAddr, currentPkg.InputAssetPrevID,
			*currentPkg.SenderScriptKey.PubKey, *currentPkg.SendDelta,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create split "+
				"commit: %w", err)
		}

		currentPkg.SendDelta = preparedSpend

		currentPkg.SendState = SendStateSigned

		return &currentPkg, nil

	// Alternatively, we'll enter this state when we know we don't actually
	// need a split at all. In this case, we fully consume an input asset,
	// so the asset created is the same asset w/ the new script key in
	// place.
	case SendStatePreparedComplete:
		preparedSpend := taroscript.PrepareAssetCompleteSpend(
			*currentPkg.ReceiverAddr, currentPkg.InputAssetPrevID,
			*currentPkg.SendDelta,
		)
		currentPkg.SendDelta = preparedSpend

		currentPkg.SendState = SendStateSigned

		return &currentPkg, nil

	// At this point, we have everything we need to sign our _virtual_
	// transaction on the Taro layer.
	case SendStateSigned:
		log.Infof("Generating Taro witnesses for send to: %x",
			currentPkg.ReceiverAddr.ScriptKey.SerializeCompressed())

		// Now we'll use the signer to sign all the inputs for the new
		// taro leaves. The witness data for each input will be
		// assigned for us.
		completedSpend, err := taroscript.CompleteAssetSpend(
			*currentPkg.InputAsset.Asset.ScriptKey.RawKey.PubKey,
			currentPkg.InputAssetPrevID, *currentPkg.SendDelta,
			p.cfg.Signer, p.cfg.TxValidator,
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
			*currentPkg.ReceiverAddr,
			*currentPkg.SenderScriptKey.PubKey,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create new output "+
				"commitments: %w", err)
		}

		log.Infof("Constructing new Taro commitments for send to: %x",
			currentPkg.ReceiverAddr.ScriptKey.SerializeCompressed())

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
			fundedSendPacket.Pkt, fundedSendPacket.ChangeOutputIndex,
			int64(currentPkg.InputAsset.AnchorOutputValue),
		)

		log.Infof("Received funded PSBT packet: %v",
			spew.Sdump(fundedSendPacket.Pkt))

		currentPkg.SendPkt = fundedSendPacket.Pkt
		currentPkg.TargetFeeRate = feeRate

		currentPkg.SendState = SendStatePsbtSign

		return &currentPkg, nil

	// SendStatePsbtSign in this state we'll create the final PSBT packet,
	// to submit to the wallet to sign its set of inputs.
	case SendStatePsbtSign:
		// First, we'll update the PSBT packets to insert the _real_
		// outputs we need to commit to the asset transfer.
		err := taroscript.CreateSpendOutputs(
			*currentPkg.ReceiverAddr, currentPkg.SendDelta.Locators,
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
		signedPsbt, err := p.cfg.Wallet.SignPsbt(ctx, currentPkg.SendPkt)
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
			currentPkg.InputAsset.Asset.FamilyKey == nil,
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
			&currentPkg.ReceiverAddr.ScriptKey,
		)]
		var receiverProofBuf bytes.Buffer
		if err := receiverAssetProof.Encode(&receiverProofBuf); err != nil {
			return nil, err
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
			NewInternalKey: currentPkg.SenderNewInternalKey,
			TaroRoot:       taroRoot[:],
			AnchorTx:       currentPkg.TransferTx,
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
		}

		// Don't allow shutdown while we're attempting to store proofs.
		ctx, cancel := p.CtxBlocking()
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

	// In this terminal state, we'll broadcast the transaction to the
	// network, then launch a goroutine to notify us on confirmation.
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

		// We'll remain in the broadcast state to hit our termination
		// condition. The next transition will be triggered manually
		// once the transaction confirms.
		currentPkg.SendState = SendStateBroadcast

		return &currentPkg, nil

	// In this terminal state, we're waiting for the tx to confirm.
	case SendStateWaitingConf:
		return &currentPkg, nil

	default:
		return &currentPkg, fmt.Errorf("unknown state: %v",
			currentPkg.SendState)
	}
}
