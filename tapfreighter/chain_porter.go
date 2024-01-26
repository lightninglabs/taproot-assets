package tapfreighter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// ChainPorterConfig is the main config for the chain porter.
type ChainPorterConfig struct {
	// Signer implements the Taproot Asset level signing we need to sign a
	// virtual transaction.
	Signer Signer

	// TxValidator allows us to validate each Taproot Asset virtual
	// transaction we create.
	TxValidator tapscript.TxValidator

	// ExportLog is used to log information about pending parcels to disk.
	ExportLog ExportLog

	// ChainBridge is our bridge to the chain we operate on.
	ChainBridge ChainBridge

	// GroupVerifier is used to verify the validity of the group key for a
	// genesis proof.
	GroupVerifier proof.GroupVerifier

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

	// ProofCourierCfg is a general config applicable to all proof courier
	// service handles.
	ProofCourierCfg *proof.CourierCfg

	// ProofWatcher is used to watch new proofs for their anchor transaction
	// to be confirmed safely with a minimum number of confirmations.
	ProofWatcher proof.Watcher

	// ErrChan is the main error channel the custodian will report back
	// critical errors to the main server.
	ErrChan chan<- error
}

// ChainPorter is the main sub-system of the tapfreighter package. The porter
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
	subscribers map[uint64]*fn.EventReceiver[fn.Event]

	// subscriberMtx guards the subscribers map.
	subscriberMtx sync.Mutex

	*fn.ContextGuard
}

// NewChainPorter creates a new instance of the ChainPorter given a valid
// config.
func NewChainPorter(cfg *ChainPorterConfig) *ChainPorter {
	subscribers := make(
		map[uint64]*fn.EventReceiver[fn.Event],
	)
	return &ChainPorter{
		cfg:         cfg,
		exportReqs:  make(chan Parcel),
		subscribers: subscribers,
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: tapgarden.DefaultTimeout,
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

		// Start the main chain porter goroutine.
		p.Wg.Add(1)
		go p.assetsPorter()

		// Identify any pending parcels that need to be resumed and add
		// them to the exportReqs channel so they can be processed by
		// the main porter goroutine.
		ctx, cancel := p.WithCtxQuit()
		defer cancel()
		outboundParcels, err := p.cfg.ExportLog.PendingParcels(ctx)
		if err != nil {
			startErr = err
			return
		}

		// We resume delivery using the normal parcel delivery mechanism
		// by converting the outbound parcels into pending parcels.
		for idx := range outboundParcels {
			outboundParcel := outboundParcels[idx]
			log.Infof("Attempting to resume delivery for "+
				"anchor_txid=%v",
				outboundParcel.AnchorTx.TxHash().String())

			// At this point the asset porter should be running.
			// It should therefore pick up the pending parcels from
			// the channel and attempt to deliver them.
			p.exportReqs <- NewPendingParcel(outboundParcel)
		}
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
func (p *ChainPorter) RequestShipment(req Parcel) (*OutboundParcel, error) {
	// Perform validation on the parcel before we continue. This is a good
	// point to perform validation because it is at the external entry point
	// to the porter. We will therefore catch invalid parcels before locking
	// coins or broadcasting.
	err := req.Validate()
	if err != nil {
		return nil, fmt.Errorf("failed to validate parcel: %w", err)
	}

	if !fn.SendOrQuit(p.exportReqs, req, p.Quit) {
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

// assetsPorter is the main goroutine of the ChainPorter. This takes in incoming
// requests, and attempt to complete a transfer. A response is sent back to the
// caller if a transfer can be completed. Otherwise, an error is returned.
func (p *ChainPorter) assetsPorter() {
	defer p.Wg.Done()

	for {
		select {
		case req := <-p.exportReqs:
			// The request either has a destination address we want
			// to send to, or a send package is already initialized.
			sendPkg := req.pkg()

			// Advance the state machine for this package as far as
			// possible in its own goroutine. The status will be
			// reported through the different channels of the send
			// package.
			go p.advanceState(sendPkg, req.kit())

		case <-p.Quit:
			return
		}
	}
}

// advanceState advances the state machine.
//
// NOTE: This method MUST be called as a goroutine.
func (p *ChainPorter) advanceState(pkg *sendPackage, kit *parcelKit) {
	// Continue state transitions whilst state complete has not yet
	// been reached.
	for pkg.SendState < SendStateComplete {
		log.Infof("ChainPorter executing state: %v",
			pkg.SendState)

		// Before we attempt a state transition, make sure that
		// we aren't trying to shut down.
		select {
		case <-p.Quit:
			return

		default:
		}

		updatedPkg, err := p.stateStep(*pkg)
		if err != nil {
			kit.errChan <- err
			log.Errorf("Error evaluating state (%v): %v",
				pkg.SendState, err)
			return
		}

		pkg = updatedPkg
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
		outboundPkg.AnchorTxHeightHint, true, nil,
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
		return fmt.Errorf("got empty package tx confirmation event " +
			"in batch")
	}

	return nil
}

// storeProofs writes the updated sender and receiver proof files to the proof
// archive.
func (p *ChainPorter) storeProofs(sendPkg *sendPackage) error {
	// Now we'll enter the final phase of the send process, where we'll
	// write the receiver's proof file to disk.
	//
	// First, we'll fetch the sender's current proof file.
	ctx, cancel := p.CtxBlocking()
	defer cancel()

	parcel := sendPkg.OutboundPkg
	confEvent := sendPkg.TransferTxConfEvent

	// Use callback to verify that block header exists on chain.
	headerVerifier := tapgarden.GenHeaderVerifier(ctx, p.cfg.ChainBridge)

	// Generate updated passive asset proof files.
	passiveAssetProofFiles := make(
		[]*proof.AnnotatedProof, 0, len(sendPkg.PassiveAssets),
	)
	passiveAssetRawProofs := make(
		[]*proof.Proof, 0, len(sendPkg.PassiveAssets),
	)
	for _, passiveAsset := range sendPkg.PassiveAssets {
		newAnnotatedProofFile, rawProof, err := p.updateAssetProofFile(
			ctx, passiveAsset.GenesisID,
			passiveAsset.ScriptKey.PubKey, confEvent,
			passiveAsset.NewProof,
		)
		if err != nil {
			return fmt.Errorf("failed to generate an updated "+
				"proof file for passive asset: %w", err)
		}

		passiveAssetProofFiles = append(
			passiveAssetProofFiles, newAnnotatedProofFile,
		)
		passiveAssetRawProofs = append(passiveAssetRawProofs, rawProof)
	}

	log.Infof("Importing %d passive asset proofs into local Proof "+
		"Archive", len(passiveAssetProofFiles))
	err := p.cfg.AssetProofs.ImportProofs(
		ctx, headerVerifier, p.cfg.GroupVerifier, false,
		passiveAssetProofFiles...,
	)
	if err != nil {
		return fmt.Errorf("error importing passive proof: %w", err)
	}

	// The proof is created after a single confirmation. To make sure we
	// notice if the anchor transaction is re-organized out of the chain, we
	// give the proof to the re-org watcher and replace the updated proof in
	// the local proof archive if a re-org happens.
	if len(passiveAssetRawProofs) > 0 {
		if err := p.cfg.ProofWatcher.WatchProofs(
			passiveAssetRawProofs,
			p.cfg.ProofWatcher.DefaultUpdateCallback(),
		); err != nil {
			return fmt.Errorf("error watching proof: %w", err)
		}
	}

	// If there are no active inputs/outputs (only passive assets), don't
	// create any proofs. This would be the case for externally anchored
	// assets, such as in a Pool account, where the anchor UTXO is spent or
	// re-created but the actual asset remains unchanged.
	if len(parcel.Inputs) == 0 {
		log.Debugf("Not updating proofs as there are no active " +
			"transfers")

		sendPkg.SendState = SendStateReceiverProofTransfer
		return nil
	}

	sendPkg.FinalProofs = make(
		map[asset.SerializedKey]*proof.AnnotatedProof,
		len(parcel.Outputs),
	)
	firstInput := parcel.Inputs[0]
	for idx := range parcel.Outputs {
		out := parcel.Outputs[idx]

		// For outputs without assets (=anchor for passive assets), we
		// don't need to store explicit proofs, they were created and
		// imported above.
		if out.Type == tappsbt.TypePassiveAssetsOnly {
			continue
		}

		// First, we'll decode the outputs' proof suffix.
		var proofSuffix proof.Proof
		err := proofSuffix.Decode(bytes.NewReader(out.ProofSuffix))
		if err != nil {
			return fmt.Errorf("error decoding proof suffix %d: %w",
				idx, err)
		}

		// The suffix doesn't contain any information about the
		// confirmed block yet, so we'll add that now.
		err = proofSuffix.UpdateTransitionProof(&proof.BaseProofParams{
			Block:       confEvent.Block,
			BlockHeight: confEvent.BlockHeight,
			Tx:          confEvent.Tx,
			TxIndex:     int(confEvent.TxIndex),
		})
		if err != nil {
			return fmt.Errorf("error updating transition proof "+
				"%d: %w", idx, err)
		}

		// The suffix is complete, so we need to fetch the input proof
		// in order to append the suffix to it.
		inputProofFile, err := p.fetchInputProof(ctx, firstInput)
		if err != nil {
			return fmt.Errorf("error fetching input proof: %w", err)
		}

		// Are there more inputs? Then this is a merge, and we need to
		// add those additional files to the suffix as well.
		for idx := 1; idx < len(parcel.Inputs); idx++ {
			additionalInputProofFile, err := p.fetchInputProof(
				ctx, parcel.Inputs[idx],
			)
			if err != nil {
				return fmt.Errorf("error fetching input "+
					"proof %d: %w", idx, err)
			}

			proofSuffix.AdditionalInputs = append(
				proofSuffix.AdditionalInputs,
				*additionalInputProofFile,
			)
		}

		// With the proof suffix updated, we can append the proof, then
		// encode it to get the final proof file.
		var outputProofBuf bytes.Buffer
		if err := inputProofFile.AppendProof(proofSuffix); err != nil {
			return fmt.Errorf("error appending proof: %w", err)
		}
		if err := inputProofFile.Encode(&outputProofBuf); err != nil {
			return fmt.Errorf("error encoding proof: %w", err)
		}

		// Now we just need to identify the new proof correctly before
		// adding it to the proof archive.
		outputProofLocator := proof.Locator{
			AssetID:   &firstInput.ID,
			ScriptKey: *out.ScriptKey.PubKey,
			OutPoint:  &firstInput.OutPoint,
		}
		outputProof := &proof.AnnotatedProof{
			Locator: outputProofLocator,
			Blob:    outputProofBuf.Bytes(),
		}
		serializedScriptKey := asset.ToSerialized(out.ScriptKey.PubKey)
		sendPkg.FinalProofs[serializedScriptKey] = outputProof

		// Import proof into proof archive.
		log.Infof("Importing proof for output %d into local Proof "+
			"Archive", idx)
		err = p.cfg.AssetProofs.ImportProofs(
			ctx, headerVerifier, p.cfg.GroupVerifier, false,
			outputProof,
		)
		if err != nil {
			return fmt.Errorf("error importing proof: %w", err)
		}

		log.Debugf("Updated proofs for output %d (new_len=%d)",
			idx, inputProofFile.NumProofs())

		// The proof is created after a single confirmation. To make
		// sure we notice if the anchor transaction is re-organized out
		// of the chain, we give the proof to the re-org watcher and
		// replace the updated proof in the local proof archive if a
		// re-org happens. We only watch change output proofs, as we
		// won't keep an asset record of outbound transfers. But the
		// receiver will also watch for re-orgs, so no re-send of the
		// proof is necessary anyway.
		if out.ScriptKey.TweakedScriptKey != nil && out.ScriptKeyLocal {
			err := p.cfg.ProofWatcher.WatchProofs(
				[]*proof.Proof{&proofSuffix},
				p.cfg.ProofWatcher.DefaultUpdateCallback(),
			)
			if err != nil {
				return fmt.Errorf("error watching proof: %w",
					err)
			}
		}
	}

	sendPkg.SendState = SendStateReceiverProofTransfer
	return nil
}

// fetchInputProof fetches a proof for the given input from the proof archive.
func (p *ChainPorter) fetchInputProof(ctx context.Context,
	input TransferInput) (*proof.File, error) {

	scriptKey, err := btcec.ParsePubKey(input.ScriptKey[:])
	if err != nil {
		return nil, fmt.Errorf("error parsing script key: %w", err)
	}
	inputProofLocator := proof.Locator{
		AssetID:   &input.ID,
		ScriptKey: *scriptKey,
	}
	inputProofBytes, err := p.cfg.AssetProofs.FetchProof(
		ctx, inputProofLocator,
	)
	if err != nil {
		return nil, fmt.Errorf("error fetching input proof: %w", err)
	}
	inputProofFile := proof.NewEmptyFile(proof.V0)
	err = inputProofFile.Decode(bytes.NewReader(inputProofBytes))
	if err != nil {
		return nil, fmt.Errorf("error decoding input proof: %w", err)
	}

	return inputProofFile, nil
}

// updateAssetProofFile retrieves and updates the proof file for the given asset
// ID and script key with the new proof.
func (p *ChainPorter) updateAssetProofFile(ctx context.Context, assetID asset.ID,
	scriptKeyPub *btcec.PublicKey, confEvent *chainntnfs.TxConfirmation,
	newProof *proof.Proof) (*proof.AnnotatedProof, *proof.Proof, error) {

	// Retrieve current proof file.
	locator := proof.Locator{
		AssetID:   &assetID,
		ScriptKey: *scriptKeyPub,
	}
	currentProofFileBlob, err := p.cfg.AssetProofs.FetchProof(ctx, locator)
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching proof: %w", err)
	}
	currentProofFile := proof.NewEmptyFile(proof.V0)
	err = currentProofFile.Decode(bytes.NewReader(currentProofFileBlob))
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding proof file: %w",
			err)
	}

	// Now that we have the current proof file, we'll update the new proof
	// with chain tx confirmation data and then append it to the proof file.
	err = newProof.UpdateTransitionProof(&proof.BaseProofParams{
		Block:       confEvent.Block,
		BlockHeight: confEvent.BlockHeight,
		Tx:          confEvent.Tx,
		TxIndex:     int(confEvent.TxIndex),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error updating new proof with "+
			"chain transaction confirmation data: %w", err)
	}

	// With the new proof updated, we can append the proof to the
	// current proof file.
	if err := currentProofFile.AppendProof(*newProof); err != nil {
		return nil, nil, fmt.Errorf("error appending proof suffix: %w",
			err)
	}
	var newProofFileBuffer bytes.Buffer
	if err := currentProofFile.Encode(&newProofFileBuffer); err != nil {
		return nil, nil, fmt.Errorf("error encoding proof file: %w",
			err)
	}
	newAnnotatedProofFile := &proof.AnnotatedProof{
		Locator: proof.Locator{
			AssetID:   &assetID,
			ScriptKey: *newProof.Asset.ScriptKey.PubKey,
		},
		Blob: newProofFileBuffer.Bytes(),
	}

	return newAnnotatedProofFile, newProof, nil
}

// transferReceiverProof retrieves the sender and receiver proofs from the
// archive and then transfers the receiver's proof to the receiver. Upon
// successful transfer, the asset parcel delivery is marked as complete.
func (p *ChainPorter) transferReceiverProof(pkg *sendPackage) error {
	ctx, cancel := p.WithCtxQuitNoTimeout()
	defer cancel()

	deliver := func(ctx context.Context, out TransferOutput) error {
		key := out.ScriptKey.PubKey

		// If this is an output that is going to our own node/wallet,
		// we don't need to transfer the proof.
		if out.ScriptKey.TweakedScriptKey != nil && out.ScriptKeyLocal {
			log.Debugf("Not transferring proof for local output "+
				"script key %x", key.SerializeCompressed())
			return nil
		}

		// Un-spendable means this is a tombstone output resulting from
		// a split.
		unSpendable, err := out.ScriptKey.IsUnSpendable()
		if err != nil {
			return fmt.Errorf("error checking if script key is "+
				"unspendable: %w", err)
		}
		if unSpendable {
			log.Debugf("Not transferring proof for un-spendable "+
				"output script key %x",
				key.SerializeCompressed())
			return nil
		}

		// Burns are also always kept local and not sent to any
		// receiver.
		if len(out.WitnessData) > 0 && asset.IsBurnKey(
			out.ScriptKey.PubKey, out.WitnessData[0],
		) {

			log.Debugf("Not transferring proof for burn script "+
				"key %x", key.SerializeCompressed())
			return nil
		}

		// We just look for the full proof in the list of final proofs
		// by matching the content of the proof suffix.
		var receiverProof *proof.AnnotatedProof
		for idx := range pkg.FinalProofs {
			finalFile := pkg.FinalProofs[idx]
			if finalFile.ScriptKey.IsEqual(out.ScriptKey.PubKey) {
				receiverProof = finalFile
				break
			}
		}
		if receiverProof == nil {
			return fmt.Errorf("no proof found for output with "+
				"script key %x", key.SerializeCompressed())
		}

		log.Debugf("Attempting to deliver proof for script key %x",
			key.SerializeCompressed())

		proofCourierAddr, err := proof.ParseCourierAddrString(
			string(out.ProofCourierAddr),
		)
		if err != nil {
			return fmt.Errorf("failed to parse proof courier "+
				"address: %w", err)
		}

		// Initiate proof courier service handle from the proof
		// courier address found in the Tap address.
		recipient := proof.Recipient{
			ScriptKey: key,
			AssetID:   *receiverProof.AssetID,
			Amount:    out.Amount,
		}
		courier, err := proofCourierAddr.NewCourier(
			ctx, p.cfg.ProofCourierCfg, recipient,
		)
		if err != nil {
			return fmt.Errorf("unable to initiate proof courier "+
				"service handle: %w", err)
		}

		defer courier.Close()

		// Update courier events subscribers before attempting to
		// deliver proof.
		p.subscriberMtx.Lock()
		courier.SetSubscribers(p.subscribers)
		p.subscriberMtx.Unlock()

		// Deliver proof to proof courier service.
		err = courier.DeliverProof(ctx, receiverProof)
		if err != nil {
			return fmt.Errorf("failed to deliver proof via "+
				"courier service: %w", err)
		}

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

		return nil
	}

	// If we have a proof courier instance active, then we'll launch several
	// goroutines to deliver the proof(s) to the receiver(s).
	if p.cfg.ProofCourierCfg != nil {
		ctx, cancel := p.WithCtxQuitNoTimeout()
		defer cancel()

		err := fn.ParSlice(ctx, pkg.OutboundPkg.Outputs, deliver)
		if err != nil {
			return fmt.Errorf("error delivering proof(s): %w", err)
		}
	}

	log.Infof("Marking parcel (txid=%v) as confirmed!",
		pkg.OutboundPkg.AnchorTx.TxHash())

	// Load passive asset proof files from archive.
	passiveAssetProofFiles := map[[32]byte]proof.Blob{}
	for idx := range pkg.OutboundPkg.PassiveAssets {
		passiveAsset := pkg.OutboundPkg.PassiveAssets[idx]
		proofLocator := proof.Locator{
			AssetID:   &passiveAsset.GenesisID,
			ScriptKey: *passiveAsset.ScriptKey.PubKey,
		}
		proofFileBlob, err := p.cfg.AssetProofs.FetchProof(
			ctx, proofLocator,
		)
		if err != nil {
			return fmt.Errorf("error fetching passive asset "+
				"proof file: %w", err)
		}

		// Hash proof locator.
		hash, err := proofLocator.Hash()
		if err != nil {
			return fmt.Errorf("error hashing proof locator: %w",
				err)
		}

		passiveAssetProofFiles[hash] = proofFileBlob
	}

	// At this point we have the confirmation signal, so we can mark the
	// parcel delivery as completed in the database.
	err := p.cfg.ExportLog.ConfirmParcelDelivery(ctx, &AssetConfirmEvent{
		AnchorTXID:             pkg.OutboundPkg.AnchorTx.TxHash(),
		BlockHash:              *pkg.TransferTxConfEvent.BlockHash,
		BlockHeight:            int32(pkg.TransferTxConfEvent.BlockHeight),
		TxIndex:                int32(pkg.TransferTxConfEvent.TxIndex),
		FinalProofs:            pkg.FinalProofs,
		PassiveAssetProofFiles: passiveAssetProofFiles,
	})
	if err != nil {
		return fmt.Errorf("unable to log parcel delivery "+
			"confirmation: %w", err)
	}

	pkg.SendState = SendStateComplete
	return nil
}

// importLocalAddresses imports the addresses for outputs that go to ourselves,
// from the given outbound parcel.
func (p *ChainPorter) importLocalAddresses(ctx context.Context,
	parcel *OutboundParcel) error {

	// We'll need to extract the output public key from the tx out that does
	// the send. We'll use this shortly below as a step before broadcast.
	for idx := range parcel.Outputs {
		out := &parcel.Outputs[idx]

		// Skip non-local outputs, those are going to a receiver outside
		// of this daemon.
		if !out.ScriptKeyLocal {
			continue
		}

		anchorOutputIndex := out.Anchor.OutPoint.Index
		anchorOutput := parcel.AnchorTx.TxOut[anchorOutputIndex]
		_, witProgram, err := txscript.ExtractWitnessProgramInfo(
			anchorOutput.PkScript,
		)
		if err != nil {
			return err
		}
		anchorOutputKey, err := schnorr.ParsePubKey(witProgram)
		if err != nil {
			return err
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

		default:
			return err
		}
	}

	return nil
}

// createDummyOutput creates a new Bitcoin transaction output that is later
// used to embed a Taproot Asset commitment.
func createDummyOutput() *wire.TxOut {
	// The dummy PkScript is the same size as an encoded P2TR output.
	newOutput := wire.TxOut{
		Value:    int64(tapscript.DummyAmtSats),
		PkScript: make([]byte, 34),
	}
	return &newOutput
}

// stateStep attempts to step through the state machine to complete a Taproot
// Asset transfer.
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

		// We know that the porter is only initialized with this state
		// for a send to an address parcel. If not, something was called
		// incorrectly.
		addrParcel, ok := currentPkg.Parcel.(*AddressParcel)
		if !ok {
			return nil, fmt.Errorf("unable to cast parcel to " +
				"address parcel")
		}
		fundSendRes, outputIdxToAddr, err :=
			p.cfg.AssetWallet.FundAddressSend(
				ctx, addrParcel.destAddrs...,
			)
		if err != nil {
			return nil, fmt.Errorf("unable to fund address send: "+
				"%w", err)
		}

		currentPkg.VirtualPacket = fundSendRes.VPacket
		currentPkg.InputCommitments = fundSendRes.InputCommitments
		currentPkg.OutputIdxToAddr = outputIdxToAddr

		currentPkg.SendState = SendStateVirtualSign

		return &currentPkg, nil

	// At this point, we have everything we need to sign our _virtual_
	// transaction on the Taproot Asset layer.
	case SendStateVirtualSign:
		vPacket := currentPkg.VirtualPacket
		receiverScriptKey := vPacket.Outputs[1].ScriptKey.PubKey
		log.Infof("Generating Taproot Asset witnesses for send to: %x",
			receiverScriptKey.SerializeCompressed())

		// Now we'll use the signer to sign all the inputs for the new
		// Taproot Asset leaves. The witness data for each input will be
		// assigned for us.
		_, err := p.cfg.AssetWallet.SignVirtualPacket(vPacket)
		if err != nil {
			return nil, fmt.Errorf("unable to sign and commit "+
				"virtual packet: %w", err)
		}

		currentPkg.SendState = SendStateAnchorSign

		return &currentPkg, nil

	// With all the internal Taproot Asset signing taken care of, we can now
	// make our initial skeleton PSBT packet to send off to the wallet for
	// funding and signing.
	case SendStateAnchorSign:
		ctx, cancel := p.WithCtxQuitNoTimeout()
		defer cancel()

		// Submit the template PSBT to the wallet for funding.
		//
		// TODO(roasbeef): unlock the input UTXOs of things fail
		var (
			feeRate chainfee.SatPerKWeight
			err     error
		)

		// First, use a manual fee rate if specified by the parcel.
		// TODO(jhb): Support PSBT flow / PreSignedParcels
		addrParcel, ok := currentPkg.Parcel.(*AddressParcel)
		switch {
		case ok && addrParcel.transferFeeRate != nil:
			feeRate = *addrParcel.transferFeeRate
			log.Infof("sending with manual fee rate")

		default:
			feeRate, err = p.cfg.ChainBridge.EstimateFee(
				ctx, tapscript.SendConfTarget,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to estimate "+
					"fee: %w", err)
			}
		}

		readableFeeRate := feeRate.FeePerKVByte().String()
		log.Infof("sending with fee rate: %v", readableFeeRate)

		vPacket := currentPkg.VirtualPacket
		firstRecipient, err := vPacket.FirstNonSplitRootOutput()
		if err != nil {
			return nil, fmt.Errorf("unable to get first "+
				"interactive output: %w", err)
		}
		receiverScriptKey := firstRecipient.ScriptKey.PubKey
		log.Infof("Constructing new Taproot Asset commitments for "+
			"send to: %x", receiverScriptKey.SerializeCompressed())

		// Gather passive assets virtual packets and sign them.
		wallet := p.cfg.AssetWallet

		currentPkg.PassiveAssets, err = wallet.SignPassiveAssets(
			vPacket, currentPkg.InputCommitments,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to sign passive "+
				"assets: %w", err)
		}

		var passiveVPackets []*tappsbt.VPacket
		for _, passiveAsset := range currentPkg.PassiveAssets {
			passiveVPackets = append(
				passiveVPackets, passiveAsset.VPacket,
			)
		}

		anchorTx, err := wallet.AnchorVirtualTransactions(
			ctx, &AnchorVTxnsParams{
				FeeRate:            feeRate,
				VPkts:              []*tappsbt.VPacket{vPacket},
				InputCommitments:   currentPkg.InputCommitments,
				PassiveAssetsVPkts: passiveVPackets,
			},
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
		// Before we can broadcast, we want to find out the current
		// height to pass as a height hint.
		ctx, cancel := p.WithCtxQuit()
		defer cancel()
		currentHeight, err := p.cfg.ChainBridge.CurrentHeight(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to get current height: "+
				"%v", err)
		}

		// We need to prepare the parcel for storage.
		parcel, err := currentPkg.prepareForStorage(currentHeight)
		if err != nil {
			return nil, fmt.Errorf("unable to prepare parcel for "+
				"storage: %w", err)
		}
		currentPkg.OutboundPkg = parcel

		// We now need to find out if this is a transfer to ourselves
		// (e.g. a change output) or an outbound transfer. A key being
		// local means the lnd node connected to this daemon knows how
		// to derive the key.
		for idx := range parcel.Outputs {
			out := &parcel.Outputs[idx]
			key := out.ScriptKey
			if key.TweakedScriptKey != nil &&
				p.cfg.KeyRing.IsLocalKey(ctx, key.RawKey) {

				out.ScriptKeyLocal = true
			}
		}

		// Don't allow shutdown while we're attempting to store proofs.
		ctx, cancel = p.CtxBlocking()
		defer cancel()

		log.Infof("Committing pending parcel to disk")

		err = p.cfg.ExportLog.LogPendingParcel(
			ctx, parcel, defaultWalletLeaseIdentifier,
			time.Now().Add(defaultBroadcastCoinLeaseDuration),
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

		err := p.importLocalAddresses(ctx, currentPkg.OutboundPkg)
		if err != nil {
			return nil, fmt.Errorf("unable to import local "+
				"addresses: %w", err)
		}

		log.Infof("Broadcasting new transfer tx, txid=%v",
			currentPkg.OutboundPkg.AnchorTx.TxHash())

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

	// At this point, the transfer transaction is confirmed on-chain, and
	// we've stored the sender and receiver proofs in the proof archive.
	// We'll now attempt to transfer the receiver proof to the receiver.
	case SendStateReceiverProofTransfer:
		// We'll set the package state to complete early here so the
		// main loop breaks out. We'll continue to attempt proof
		// deliver in the background.
		currentPkg.SendState = SendStateComplete

		p.Wg.Add(1)
		go func() {
			defer p.Wg.Done()

			err := p.transferReceiverProof(&currentPkg)
			if err != nil {
				log.Errorf("unable to transfer receiver "+
					"proof: %v", err)
			}
		}()

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
	receiver *fn.EventReceiver[fn.Event],
	deliverExisting bool, deliverFrom bool) error {

	p.subscriberMtx.Lock()
	defer p.subscriberMtx.Unlock()

	p.subscribers[receiver.ID()] = receiver

	return nil
}

// RemoveSubscriber removes a subscriber from the set of subscribers that will
// be notified of any new events that are broadcast.
func (p *ChainPorter) RemoveSubscriber(
	subscriber *fn.EventReceiver[fn.Event]) error {

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
func (p *ChainPorter) publishSubscriberEvent(event fn.Event) {
	// Lock the subscriber mutex to ensure that we don't modify the
	// subscriber map while we're iterating over it.
	p.subscriberMtx.Lock()
	defer p.subscriberMtx.Unlock()

	for _, sub := range p.subscribers {
		sub.NewItemCreated.ChanIn() <- event
	}
}

// A compile-time assertion to make sure ChainPorter satisfies the
// fn.EventPublisher interface.
var _ fn.EventPublisher[fn.Event, bool] = (*ChainPorter)(nil)

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
