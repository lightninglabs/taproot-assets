package tarofreighter

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightninglabs/taro/taropsbt"
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

	// AssetWallet is the asset-level wallet that we'll use to fund+sign
	// virtual transactions.
	AssetWallet Wallet

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

	exportReqs chan Parcel

	// subscribers is a map of components that want to be notified on new
	// events, keyed by their subscription ID.
	subscribers map[uint64]*chanutils.EventReceiver[Event]

	// subscriberMtx guards the subscribers map and access to the
	// subscriptionID.
	subscriberMtx sync.Mutex

	*chanutils.ContextGuard
}

// NewChainPorter creates a new instance of the ChainPorter given a valid
// config.
func NewChainPorter(cfg *ChainPorterConfig) *ChainPorter {
	return &ChainPorter{
		cfg:         cfg,
		exportReqs:  make(chan Parcel),
		subscribers: make(map[uint64]*chanutils.EventReceiver[Event]),
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
func (p *ChainPorter) RequestShipment(req Parcel) (*PendingParcel, error) {
	if !chanutils.SendOrQuit(p.exportReqs, req, p.Quit) {
		return nil, fmt.Errorf("ChainPorter shutting down")
	}

	select {
	case err := <-req.kit().errChan:
		return nil, err

	case resp := <-req.kit().respChan:
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
//   - could move final conf into the state machine itself
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
			// The request either has a destination address we want
			// to send to, or a send package is already initialized.
			sendPkg := req.pkg()

			// Advance the state machine for this package until we
			// reach the state that we broadcast the transaction
			// that completes the transfer.
			advancedPkg, err := p.advanceStateUntil(
				sendPkg, SendStateBroadcast,
			)
			if err != nil {
				log.Warnf("unable to advance state machine: %v",
					err)
				req.kit().errChan <- err
				continue
			}

			// With the transaction broadcast, we'll deliver
			// a response back to the original caller.
			advancedPkg.deliverResponse(req.kit().respChan)

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

	confCtx, confCancel := p.WithCtxQuitNoTimeout()
	confNtfn, errChan, err := p.cfg.ChainBridge.RegisterConfirmationsNtfn(
		confCtx, &txHash, pkg.AnchorTx.TxOut[0].PkScript, 1,
		pkg.AnchorTxHeightHint, true,
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
	ctx, cancel := p.CtxBlocking()
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

	// Use callback to verify that block header exists on chain.
	headerVerifier := tarogarden.GenHeaderVerifier(ctx, p.cfg.ChainBridge)
	err = p.cfg.AssetProofs.ImportProofs(
		ctx, headerVerifier, receiverProof, newSenderProof,
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

// stateStep attempts to step through the state machine to complete a Taro
// transfer.
func (p *ChainPorter) stateStep(currentPkg sendPackage) (*sendPackage, error) {
	// Notify subscribers that the state machine is about to execute a
	// state.
	stateEvent := NewExecuteSendStateEvent(currentPkg.SendState)
	p.publishSubscriberEvent(stateEvent)

	switch currentPkg.SendState {
	// At this point we have the initial package information populated, so
	// we'll perform coin selection to see if the send request is even
	// possible at all.
	case SendStateVirtualCommitmentSelect:
		ctx, cancel := p.WithCtxQuitNoTimeout()
		defer cancel()

		packet, inputCommitment, err := p.cfg.AssetWallet.FundAddressSend(
			ctx, *currentPkg.ReceiverAddr,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fund address send: "+
				"%w", err)
		}

		currentPkg.VirtualPacket = packet
		currentPkg.InputCommitment = inputCommitment

		currentPkg.SendState = SendStateVirtualSign

		return &currentPkg, nil

	// At this point, we have everything we need to sign our _virtual_
	// transaction on the Taro layer.
	case SendStateVirtualSign:
		vPacket := currentPkg.VirtualPacket
		receiverScriptKey := vPacket.Outputs[1].ScriptKey.PubKey
		log.Infof("Generating Taro witnesses for send to: %x",
			receiverScriptKey.SerializeCompressed())

		// Now we'll use the signer to sign all the inputs for the new
		// taro leaves. The witness data for each input will be
		// assigned for us.
		err := p.cfg.AssetWallet.SignVirtualPacket(vPacket)
		if err != nil {
			return nil, fmt.Errorf("unable to sign and commit "+
				"virtual packet: %w", err)
		}

		currentPkg.SendState = SendStateAnchorSign

		return &currentPkg, nil

	// With all the internal Taro signing taken care of, we can now make
	// our initial skeleton PSBT packet to send off to the wallet for
	// funding and signing.
	case SendStateAnchorSign:
		ctx, cancel := p.WithCtxQuitNoTimeout()
		defer cancel()

		// Submit the template PSBT to the wallet for funding.
		//
		// TODO(roasbeef): unlock the input UTXOs of things fail
		feeRate, err := p.cfg.ChainBridge.EstimateFee(
			ctx, taroscript.SendConfTarget,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to estimate fee: %w",
				err)
		}

		vPacket := currentPkg.VirtualPacket
		receiverScriptKey := vPacket.Outputs[1].ScriptKey.PubKey
		log.Infof("Constructing new Taro commitments for send to: %x",
			receiverScriptKey.SerializeCompressed())

		wallet := p.cfg.AssetWallet
		anchorTx, err := wallet.AnchorVirtualTransactions(
			ctx, feeRate, []*commitment.TaroCommitment{
				currentPkg.InputCommitment,
			}, []*taropsbt.VPacket{vPacket},
		)
		if err != nil {
			return nil, fmt.Errorf("unable to anchor virtual "+
				"transactions: %w", err)
		}

		// We keep the original funded PSBT with all the wallet's output
		// information on the change output preserved but continue the
		// signing process with a copy to avoid clearing the info on
		// finalization.
		currentPkg.AnchorTx = anchorTx

		currentPkg.SendState = SendStateLogCommit

		return &currentPkg, nil

	// At this state, we have a final PSBT transaction which is fully
	// signed. We'll write this to disk (the point of no return), then
	// broadcast this to the network.
	case SendStateLogCommit:
		// Now we'll grab our new commitment, and also the output index
		// to populate the log entry below.
		input := currentPkg.VirtualPacket.Inputs[0]
		senderOut := currentPkg.VirtualPacket.Outputs[0]
		anchorOutputIndex := senderOut.AnchorOutputIndex
		outputCommitments := currentPkg.AnchorTx.OutputCommitments
		newSenderCommitment := outputCommitments[anchorOutputIndex]

		var tapscriptSibling *chainhash.Hash
		if len(input.Anchor.TapscriptSibling) > 0 {
			h, err := chainhash.NewHash(
				input.Anchor.TapscriptSibling,
			)
			if err != nil {
				return nil, err
			}

			tapscriptSibling = h
		}

		taroRoot := newSenderCommitment.TapscriptRoot(tapscriptSibling)

		senderProof, receiverProof, err := currentPkg.createProofs()
		if err != nil {
			return nil, err
		}

		// Before we write to disk, we'll make the incomplete proofs
		// for the sender and the receiver.
		var senderProofBuf bytes.Buffer
		if err := senderProof.Encode(&senderProofBuf); err != nil {
			return nil, err
		}

		var receiverProofBuf bytes.Buffer
		if err := receiverProof.Encode(&receiverProofBuf); err != nil {
			return nil, err
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
		vIn := currentPkg.VirtualPacket.Inputs[0]
		inputAsset := vIn.Asset()
		newAsset := senderOut.Asset

		newInternalKeyDesc, err := senderOut.AnchorKeyToDesc()
		if err != nil {
			return nil, fmt.Errorf("unable to get anchor key "+
				"desc: %w", err)
		}

		currentPkg.OutboundPkg = &OutboundParcelDelta{
			OldAnchorPoint: vIn.PrevID.OutPoint,
			NewAnchorPoint: wire.OutPoint{
				Hash:  currentPkg.AnchorTx.FinalTx.TxHash(),
				Index: anchorOutputIndex,
			},
			NewInternalKey:     newInternalKeyDesc,
			TaroRoot:           taroRoot[:],
			AnchorTx:           currentPkg.AnchorTx.FinalTx,
			AnchorTxHeightHint: currentHeight,
			AssetSpendDeltas: []AssetSpendDelta{{
				OldScriptKey:        *inputAsset.ScriptKey.PubKey,
				NewAmt:              newAsset.Amount,
				NewScriptKey:        senderOut.ScriptKey,
				WitnessData:         newAsset.PrevWitnesses,
				SplitCommitmentRoot: newAsset.SplitCommitmentRoot,
				SenderAssetProof:    senderProofBuf.Bytes(),
				ReceiverAssetProof:  receiverProofBuf.Bytes(),
			}},
			TapscriptSibling: vIn.Anchor.TapscriptSibling,
			// TODO(bhandras): use clock.Clock instead.
			TransferTime: time.Now(),
			ChainFees:    currentPkg.AnchorTx.ChainFees,
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

// RegisterSubscriber adds a new subscriber to the set of subscribers that will
// be notified of any new events that are broadcast.
//
// TODO(ffranr): Add support for delivering existing events to new subscribers.
func (p *ChainPorter) RegisterSubscriber(
	receiver *chanutils.EventReceiver[Event],
	deliverExisting bool, deliverFrom bool) error {

	p.subscriberMtx.Lock()
	defer p.subscriberMtx.Unlock()

	p.subscribers[receiver.ID()] = receiver

	return nil
}

// RemoveSubscriber removes a subscriber from the set of subscribers that will
// be notified of any new events that are broadcast.
func (p *ChainPorter) RemoveSubscriber(
	subscriber *chanutils.EventReceiver[Event]) error {

	p.subscriberMtx.Lock()
	defer p.subscriberMtx.Unlock()

	_, ok := p.subscribers[subscriber.ID()]
	if !ok {
		return fmt.Errorf("subscriber with ID %d not found",
			subscriber.ID())
	}

	subscriber.Stop()
	delete(p.subscribers, subscriber.ID())

	return nil
}

// publishSubscriberEvent publishes an event to all subscribers.
func (p *ChainPorter) publishSubscriberEvent(event Event) {
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
var _ chanutils.EventPublisher[Event, bool] = (*ChainPorter)(nil)

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
