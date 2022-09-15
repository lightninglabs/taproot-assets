package tarofreighter

import (
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightningnetwork/lnd/chainntnfs"
)

// Config for an instance of the ChainPorter
type ChainPorterConfig struct {
	// CoinSelector...
	CoinSelector CommitmentSelector

	// Signer...
	Signer Signer

	// TxValidator...
	TxValidator taroscript.TxValidator

	// ExportLog...
	ExportLog ExportLog

	// ChainBridge...
	ChainBridge ChainBridge

	// Wallet...
	Wallet WalletAnchor

	// KeyRing...
	KeyRing KeyRing

	// ChainParams...
	ChainParams *address.ChainParams
}

// ChainPorter...
type ChainPorter struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *ChainPorterConfig

	exportReqs chan *AssetParcel

	*chanutils.ContextGuard
}

// NewChainPorter...
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

// Start...
func (p *ChainPorter) Start() error {
	var startErr error
	p.startOnce.Do(func() {
		// TODO(roasbeef): need to rebroadcast pending parcels

		p.Wg.Add(1)
		go p.taroPorter()
	})

	return startErr
}

// Stop...
func (p *ChainPorter) Stop() error {
	var stopErr error
	p.stopOnce.Do(func() {
		close(p.Quit)
		p.Wg.Wait()
	})

	return stopErr
}

// RequestShipment...
func (p *ChainPorter) RequestShipment(req *AssetParcel) (*PendingParcel, error) {
	req.errChan = make(chan error, 1)
	req.respChan = make(chan *PendingParcel, 1)

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

// main state machine goroutine; advance state, wait for TX confirmation
func (p *ChainPorter) taroPorter() {
	defer p.Wg.Done()

	for {
		select {
		case req := <-p.exportReqs:
			// Initialize a package with the destination address.
			sendPkg := sendPackage{
				ReceiverAddr: req.Dest,
			}

			// Advance the state machine for this package until we
			// reach the state that we broadcast the transaction
			// that completes the transfer.
			err := p.advanceStateUntil(&sendPkg, SendStateWaitingConf)
			if err != nil {
				log.Warnf("unable to advance state machine: %v", err)
				req.errChan <- err
				continue
			}

			// Now that we broadcaster the transaction, we'll
			// create a goroutine that'll wait for the confirmation
			// then update everything on disk.
			go p.waitForPkgConfirmation(&sendPkg, req)

		case <-p.Quit:
			return
		}
	}

}

// waitForPkgConfirmation waits for the confirmation of the final transaction
// within the delta. Once confirmed, the parcel will be marked as delivered on
// chain, with the goroutine cleaning up its state.
func (p *ChainPorter) waitForPkgConfirmation(pkg *sendPackage,
	req *AssetParcel) {

	defer p.Wg.Done()

	ctx, cancel := p.WithCtxQuit()
	defer cancel()

	// Before we can broadcast, we want to find out the current height to
	// pass as a height hint.
	currentHeight, err := p.cfg.ChainBridge.CurrentHeight(ctx)
	if err != nil {
		err := fmt.Errorf("unable to get current height: %v", err)
		log.Error(err)

		req.errChan <- err
		return
	}

	txHash := pkg.TransferTx.TxHash()
	confCtx, confCancel := p.WithCtxQuit()
	confNtfn, errChan, err := p.cfg.ChainBridge.RegisterConfirmationsNtfn(
		confCtx, &txHash, pkg.TransferTx.TxOut[0].PkScript, 1,
		currentHeight, true,
	)
	if err != nil {
		err := fmt.Errorf("unable to register for tx conf: %v", err)
		log.Error(err)

		req.errChan <- err
		return
	}

	// Launch a goroutine that'll notify us when the transaction confirms.
	defer confCancel()

	var confEvent *chainntnfs.TxConfirmation
	select {
	case confEvent = <-confNtfn.Confirmed:
		log.Debugf("Got chain confirmation: %v",
			confEvent.Tx.TxHash())

	case err := <-errChan:
		req.errChan <- fmt.Errorf("error getting "+
			"confirmation: %w", err)
		return

	case <-confCtx.Done():
		log.Debugf("Skipping TX confirmation, context " +
			"done")

	case <-p.Quit:
		log.Debugf("Skipping TX confirmation, exiting")
		return
	}

	if confEvent == nil {
		req.errChan <- fmt.Errorf("got empty confirmation event in " +
			"batch")
		return
	}

	// At this point we have the confirmation signal, so we can mark the
	// parcel delivery as completed in the database.
	err = p.cfg.ExportLog.ConfirmParcelDelivery(ctx, &AssetConfirmEvent{
		AnchorPoint: pkg.OutboundPkg.NewAnchorPoint,
		BlockHash:   *confEvent.BlockHash,
		BlockHeight: int32(confEvent.BlockHeight),
		TxIndex:     int32(confEvent.TxIndex),
	})
	if err != nil {
		err := fmt.Errorf("unable to log tx conf: %w", err)
		log.Error(err)

		req.errChan <- err
	}

	oldRoot := pkg.InputAsset.Commitment.TapscriptRoot(nil)

	req.respChan <- &PendingParcel{
		NewAnchorPoint: pkg.OutboundPkg.NewAnchorPoint,
		TransferTx:     pkg.TransferTx,
		OldTaroRoot:    oldRoot[:],
		NewTaroRoot:    pkg.OutboundPkg.TaroRoot,
		AssetInputs: []AssetInput{
			{
				PrevID: pkg.InputAssetPrevID,
				Amount: btcutil.Amount(
					pkg.InputAsset.Asset.Amount,
				),
			},
		},
		AssetOutputs: []AssetOutput{
			{
				AssetInput: AssetInput{
					PrevID: asset.PrevID{
						OutPoint:  pkg.OutboundPkg.NewAnchorPoint,
						ID:        pkg.ReceiverAddr.ID,
						ScriptKey: asset.ToSerialized(pkg.SenderScriptKey),
					},
					Amount: btcutil.Amount(
						pkg.OutboundPkg.AssetSpendDeltas[0].NewAmt,
					),
				},
			},
			{
				AssetInput: AssetInput{
					PrevID: asset.PrevID{
						OutPoint: pkg.OutboundPkg.NewAnchorPoint,
						ID:       pkg.ReceiverAddr.ID,
						ScriptKey: asset.ToSerialized(
							&pkg.ReceiverAddr.ScriptKey,
						),
					},
					Amount: btcutil.Amount(
						pkg.ReceiverAddr.Amount,
					),
				},
			},
		},
		TotalFees: 0,
	}

	return

}

// advanceStateUntil...
func (p *ChainPorter) advanceStateUntil(currentPkg *sendPackage,
	targetState SendState) error {

	log.Infof("ChainPorter advancing from state=%v to state=%v",
		currentPkg.SendState, targetState)

	var terminalState bool
	for !terminalState {
		// Before we attempt a state transition, make sure that we
		// aren't trying to shut down.
		select {
		case <-p.Quit:
			return fmt.Errorf("Porter shutting down")

		default:
		}

		updatedPkg, err := p.stateStep(*currentPkg)
		if err != nil {
			return fmt.Errorf("unable to advance "+
				"state machine: %w", err)
		}

		// We've reached a terminal state once the next state is our
		// current state (state machine loops back to the current
		// state).
		terminalState = updatedPkg.SendState == targetState

		currentPkg = updatedPkg
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

// adjustFundedPsbt...
//
// Move the change output on a funded psbt
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
	//
	// TODO(roasbeef): double check this, also fix fee estimation generally
	// here
	pkt.UnsignedTx.TxOut[maxOutputIndex].Value += anchorInputValue
}

// stateStep...
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
		ctx, cancel := p.WithCtxQuit()
		defer cancel()

		// We need to find a commitment that has enough assets to
		// satisfy this send request. We'll map the address to a set of
		// constraints, so we can use that to do Taro asset coin
		// selection.
		//
		// TODO(roasbeef): send logic assumes just one input (no
		// merges) so we pass in the amount here to ensure we have
		// enough to send
		constraints := CommitmentConstraints{
			FamilyKey: currentPkg.ReceiverAddr.FamilyKey,
			AssetID:   &currentPkg.ReceiverAddr.ID,
			MinAmt:    currentPkg.ReceiverAddr.Amount,
		}
		elgigibleCommitments, err := p.cfg.CoinSelector.SelectCommitment(
			ctx, constraints,
		)
		if err != nil {
			return nil, err
		}

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
		ctx, cancel := p.WithCtxQuit()
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
		currentPkg.SenderScriptKeyDesc, err = p.cfg.KeyRing.DeriveNextKey(
			ctx, tarogarden.TaroKeyFamily,
		)
		if err != nil {
			return nil, err
		}

		// We'll assume BIP 86 everywhere, and use the tweaked key from
		// here on out.
		currentPkg.SenderScriptKey = txscript.ComputeTaprootKeyNoScript(
			currentPkg.SenderScriptKeyDesc.PubKey,
		)

		// If we need to split (addr amount < input amount), then we'll
		// transition to prepare the set of splits. If not,then we can
		// assume the splits are unnecessary.
		//
		// TODO(roasbeef): always need to split anyway see:
		// https://github.com/lightninglabs/taro/issues/121
		currentPkg.NeedsSplit = needsSplit
		if needsSplit {
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
			*currentPkg.SenderScriptKey, *currentPkg.SendDelta,
		)
		if err != nil {
			return nil, err
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
		// Now we'll use the signer to sign all the inputs for the new
		// taro leaves. The witness data for each input will be
		// assigned for us.
		completedSpend, err := taroscript.CompleteAssetSpend(
			*currentPkg.InputAsset.InternalKey.PubKey,
			currentPkg.InputAssetPrevID, *currentPkg.SendDelta,
			p.cfg.Signer, p.cfg.TxValidator,
		)
		if err != nil {
			return nil, err
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
			*currentPkg.ReceiverAddr, *currentPkg.SenderScriptKey,
		)
		if err != nil {
			return nil, err
		}

		currentPkg.NewOutputCommitments = spendCommitments

		// Otherwise, we can go straight to stamping things as we have
		// them w/ the PSBT.
		currentPkg.SendState = SendStatePsbtFund

		return &currentPkg, nil

	// With all the internal Taro signing taken care of, we can now make
	// our initial skeleton PSBT packet to send off to the wallet for
	// funding.
	case SendStatePsbtFund:
		ctx, cancel := p.WithCtxQuit()
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
		// accosting, etc.

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

		currentPkg.SendPkt = fundedSendPacket.Pkt

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
			*currentPkg.SenderScriptKey, currentPkg.NewOutputCommitments,
			currentPkg.SendPkt,
		)
		if err != nil {
			return &currentPkg, err
		}

		// Now that all the real outputs are in the PSBT, we'll also
		// add our anchor input as well, since the wallet can sign for
		// it itself.
		currentPkg.addAnchorPsbtInput()

		ctx, cancel := p.WithCtxQuit()
		defer cancel()

		// With all the input and output information in the packet, we
		// can now ask lnd to sign it, and also give us the final
		// version.
		currentPkg.SendPkt, err = p.cfg.Wallet.SignAndFinalizePsbt(
			ctx, currentPkg.SendPkt,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to sign psbt: %w", err)
		}

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
			currentPkg.InputAssetPrevID.ID, currentPkg.SenderScriptKey,
			currentPkg.InputAsset.Asset.FamilyKey == nil,
		)
		newSenderCommitment := currentPkg.NewOutputCommitments[senderCommitKey]
		anchorOutputIndex := currentPkg.SendDelta.Locators[senderCommitKey].OutputIndex

		ctx, cancel := p.WithCtxQuit()
		defer cancel()

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

		// Before we broadcast, we'll write to disk that we have a
		// pending outbound parcel. If we crash before this point,
		// we'll start all over. Otherwise, we'll come back to this
		// state to re-do the process.
		//
		// TODO(roasbeef); need to update proof file information,
		// ideally the db doesn't do this directly
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
					OldScriptKey: *currentPkg.InputAsset.Asset.ScriptKey.PubKey,
					NewAmt:       currentPkg.SendDelta.NewAsset.Amount,
					NewScriptKey: currentPkg.SenderScriptKeyDesc,
				},
			},
			TapscriptSibling: currentPkg.InputAsset.TapscriptSibling,
		}
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
		ctx, cancel := p.WithCtxQuit()
		defer cancel()

		// We'll need to extract the output public key from the tx out
		// that does the send. We'll use this shortly below as a step
		// before broadcast.
		//
		// TODO(roasbeef): cache before?
		anchorIndex := currentPkg.OutboundPkg.NewAnchorPoint.Index
		anchorOutput := currentPkg.TransferTx.TxOut[anchorIndex]
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
		err = p.cfg.Wallet.ImportTaprootOutput(ctx, anchorOutputKey)
		if err != nil {
			return nil, err
		}

		// With the public key imported, we can now broadcast to the
		// network.
		err = p.cfg.ChainBridge.PublishTransaction(
			ctx, currentPkg.TransferTx,
		)
		if err != nil {
			return nil, err
		}

		// At this point, we enter the terminal state of tx broadcast.
		// This state can be repeated as it should be idempotent.
		currentPkg.SendState = SendStateWaitingConf

		return &currentPkg, nil

	// In this terminal state, we're waiting for the tx to confirm.
	case SendStateWaitingConf:
		return &currentPkg, nil

	default:
		return &currentPkg, fmt.Errorf("unknown state: %v",
			currentPkg.SendState)
	}
}
