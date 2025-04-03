package tapfreighter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// ProofImporter is used to import proofs into the local proof archive after we
// complete a trransfer.
type ProofImporter interface {
	// ImportProofs attempts to store fully populated proofs on disk. The
	// previous outpoint of the first state transition will be used as the
	// Genesis point. The final resting place of the asset will be used as
	// the script key itself. If replace is specified, we expect a proof to
	// already be present, and we just update (replace) it with the new
	// proof.
	ImportProofs(ctx context.Context, vCtx proof.VerifierCtx,
		replace bool, proofs ...*proof.AnnotatedProof) error
}

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

	ProofWriter ProofImporter

	// ProofReader is used to fetch input proofs.
	ProofReader proof.Exporter

	// ProofCourierDispatcher is the dispatcher that is used to create new
	// proof courier handles for sending proofs based on the protocol of
	// a proof courier address.
	ProofCourierDispatcher proof.CourierDispatch

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

	// outboundParcels is a channel that carries outbound parcels that need
	// to be processed by the main porter goroutine.
	outboundParcels chan Parcel

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
		cfg:             cfg,
		outboundParcels: make(chan Parcel),
		subscribers:     subscribers,
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
		go p.mainEventLoop()

		startErr = p.resumePendingParcels()
	})

	return startErr
}

// resumePendingParcels attempts to resume delivery for any pending parcels that
// were previously interrupted. This is done by querying the export log for any
// pending parcels and adding them to the outboundParcels channel so they can be
// processed by the main porter goroutine.
func (p *ChainPorter) resumePendingParcels() error {
	ctx, cancel := p.WithCtxQuit()
	defer cancel()

	outboundParcels, err := p.cfg.ExportLog.PendingParcels(ctx)
	if err != nil {
		return err
	}

	// Return early if there are no pending parcels to resume.
	if len(outboundParcels) == 0 {
		log.Info("No pending parcels to resume")
		return nil
	}

	log.Infof("Attempting to resume asset transfer for %d parcels",
		len(outboundParcels))

	// We resume delivery using the normal parcel delivery mechanism by
	// converting the outbound parcels into pending parcels.
	for idx := range outboundParcels {
		outboundParcel := outboundParcels[idx]

		pendingParcel := NewPendingParcel(outboundParcel)
		reportPendingParcel(*pendingParcel)

		// At this point the asset porter should be running. It should
		// therefore pick up the pending parcels from the channel and
		// attempt to deliver them.
		p.outboundParcels <- pendingParcel
	}

	return nil
}

// reportPendingParcel logs information about a pending parcel.
func reportPendingParcel(pendingParcel PendingParcel) {
	outboundParcel := pendingParcel.pkg().OutboundPkg

	// Formulate a log entry for each proof delivery pending transfer output
	// for the pending parcel.
	var outputLogStrings []string

	for idx := range outboundParcel.Outputs {
		transferOut := outboundParcel.Outputs[idx]

		// Process only the proof outputs that are pending delivery.
		// Skip outputs with proofs that don't need to be delivered to a
		// peer (none) or those with proofs already delivered
		// (some true).
		if transferOut.ProofDeliveryComplete.UnwrapOr(true) {
			continue
		}

		// Construct a log string for the transfer output.
		skBytes := transferOut.ScriptKey.PubKey.SerializeCompressed()
		proofCourierAddr := string(
			transferOut.ProofCourierAddr,
		)

		outputLog := fmt.Sprintf(
			"transfer_output_idx=%d, script_key=%x, "+
				"proof_courier_addr=%s",
			idx, skBytes, proofCourierAddr,
		)
		outputLogStrings = append(
			outputLogStrings, outputLog,
		)
	}

	log.Infof("Encountered pending parcel "+
		"(anchor_txid=%v, count_undelivered_proofs=%d)",
		outboundParcel.AnchorTx.TxHash().String(),
		len(outputLogStrings))

	// If there are any outputs with pending delivery proofs, we'll log
	// them here.
	if len(outputLogStrings) > 0 {
		perOutputLog := strings.Join(outputLogStrings, "\n")

		log.Debugf("Transfer output(s) with delivery pending "+
			"proofs:\n%v", perOutputLog)
	}
}

// Stop signals that the chain porter should gracefully stop.
func (p *ChainPorter) Stop() error {
	var stopErr error
	p.stopOnce.Do(func() {
		close(p.Quit)
		p.Wg.Wait()

		// Remove all subscribers.
		p.subscriberMtx.Lock()
		defer p.subscriberMtx.Unlock()

		for _, subscriber := range p.subscribers {
			subscriber.Stop()
			delete(p.subscribers, subscriber.ID())
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

	if !fn.SendOrQuit(p.outboundParcels, req, p.Quit) {
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

// QueryParcels returns the set of confirmed or unconfirmed parcels. If the
// anchor tx hash is Some, then a query for an parcel with the matching anchor
// hash will be made.
func (p *ChainPorter) QueryParcels(ctx context.Context,
	anchorTxHash fn.Option[chainhash.Hash],
	pending bool) ([]*OutboundParcel, error) {

	return p.cfg.ExportLog.QueryParcels(
		ctx, anchorTxHash.UnwrapToPtr(), pending,
	)
}

// mainEventLoop is the main goroutine of the ChainPorter. This takes a parcel
// requests, and attempt to complete a transfer. A response is sent back to the
// caller if a transfer can be completed. Otherwise, an error is returned.
func (p *ChainPorter) mainEventLoop() {
	defer p.Wg.Done()

	for {
		select {
		case outboundParcel := <-p.outboundParcels:
			// The outbound parcel either has a destination address
			// we want to send to, or a send package is already
			// initialized.
			sendPkg := outboundParcel.pkg()

			// Advance the state machine for this package as far as
			// possible in its own goroutine. The status will be
			// reported through the different channels of the send
			// package.
			go p.advanceState(sendPkg, outboundParcel.kit())

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

		stateToExecute := pkg.SendState
		updatedPkg, err := p.stateStep(*pkg)
		if err != nil {
			kit.errChan <- err
			log.Errorf("Error evaluating state (%v): %v",
				pkg.SendState, err)

			p.publishSubscriberEvent(newAssetSendErrorEvent(
				err, stateToExecute, *pkg,
			))

			return
		}

		// Notify subscribers that the state machine has executed a
		// state successfully. The only state that happens in a
		// goroutine outside the state machine is sending the proof to
		// the receiver using the proof courier service. That goroutine
		// will notify the subscribers itself, so we skip it here.
		if pkg.SendState < SendStateComplete {
			p.publishSubscriberEvent(newAssetSendEvent(
				stateToExecute, *updatedPkg,
			))
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

		// If the anchoring tx block hash is given, we'll also store it
		// in the outbound package.
		pkg.OutboundPkg.AnchorTxBlockHash = fn.MaybeSome(
			confEvent.BlockHash,
		)
		pkg.OutboundPkg.AnchorTxBlockHeight = confEvent.BlockHeight

		pkg.SendState = SendStateStorePostAnchorTxConf

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
	passiveAssetProofSuffixes := make(
		[]*proof.Proof, 0, len(sendPkg.PassiveAssets),
	)
	for idx := range sendPkg.PassiveAssets {
		passiveOut := sendPkg.PassiveAssets[idx].Outputs[0]

		inputs := fn.Map(
			sendPkg.PassiveAssets[idx].Inputs,
			func(in *tappsbt.VInput) asset.PrevID {
				return in.PrevID
			},
		)

		newAnnotatedProofFile, err := p.updateAssetProofFile(
			ctx, inputs, passiveOut.ProofSuffix,
			passiveOut.Asset.ScriptKey, confEvent,
		)
		if err != nil {
			return fmt.Errorf("failed to generate an updated "+
				"proof file for passive asset: %w", err)
		}

		passiveAssetProofFiles = append(
			passiveAssetProofFiles, newAnnotatedProofFile,
		)
		passiveAssetProofSuffixes = append(
			passiveAssetProofSuffixes, passiveOut.ProofSuffix,
		)
	}

	vCtx := proof.VerifierCtx{
		HeaderVerifier: headerVerifier,
		MerkleVerifier: proof.DefaultMerkleVerifier,
		GroupVerifier:  p.cfg.GroupVerifier,
		ChainLookupGen: p.cfg.ChainBridge,
	}

	log.Infof("Importing %d passive asset proofs into local Proof "+
		"Archive", len(passiveAssetProofFiles))
	err := p.cfg.ProofWriter.ImportProofs(
		ctx, vCtx, false, passiveAssetProofFiles...,
	)
	if err != nil {
		return fmt.Errorf("error importing passive proof: %w", err)
	}

	// The proof is created after a single confirmation. To make sure we
	// notice if the anchor transaction is re-organized out of the chain, we
	// give the proof to the re-org watcher and replace the updated proof in
	// the local proof archive if a re-org happens.
	if len(passiveAssetProofSuffixes) > 0 {
		if err := p.cfg.ProofWatcher.WatchProofs(
			passiveAssetProofSuffixes,
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

		sendPkg.SendState = SendStateTransferProofs
		return nil
	}

	sendPkg.FinalProofs = make(
		map[OutputIdentifier]*proof.AnnotatedProof,
		len(parcel.Outputs),
	)
	for idx := range parcel.Outputs {
		out := parcel.Outputs[idx]

		parsedSuffix := &proof.Proof{}
		err := parsedSuffix.Decode(bytes.NewReader(out.ProofSuffix))
		if err != nil {
			return fmt.Errorf("error decoding proof suffix %d: %w",
				idx, err)
		}

		var inputsForAsset []asset.PrevID
		for _, in := range parcel.Inputs {
			witnesses := parsedSuffix.Asset.Witnesses()
			for _, witness := range witnesses {
				if witness.PrevID != nil &&
					in.PrevID == *witness.PrevID {

					inputsForAsset = append(
						inputsForAsset, in.PrevID,
					)
				}
			}
		}
		outputProof, err := p.updateAssetProofFile(
			ctx, inputsForAsset, parsedSuffix, out.ScriptKey,
			confEvent,
		)
		if err != nil {
			return fmt.Errorf("failed to generate an updated "+
				"proof file for output %d: %w", idx, err)
		}

		outKey, err := out.UniqueKey()
		if err != nil {
			return fmt.Errorf("error generating unique key for "+
				"output %d: %w", idx, err)
		}
		sendPkg.FinalProofs[outKey] = outputProof

		vCtx := proof.VerifierCtx{
			HeaderVerifier: headerVerifier,
			MerkleVerifier: proof.DefaultMerkleVerifier,
			GroupVerifier:  p.cfg.GroupVerifier,
			ChainLookupGen: p.cfg.ChainBridge,
		}

		// Before we import the proof into the proof archive, we'll
		// validate it.
		verifier := &proof.BaseVerifier{}
		_, err = verifier.Verify(
			ctx, bytes.NewReader(outputProof.Blob), vCtx,
		)
		if err != nil {
			return fmt.Errorf("error verifying proof: %w", err)
		}

		// Import proof into proof archive.
		log.Infof("Importing proof for output %d into local Proof "+
			"Archive", idx)
		err = p.cfg.ProofWriter.ImportProofs(
			ctx, vCtx, false, outputProof,
		)
		if err != nil {
			return fmt.Errorf("error importing proof: %w", err)
		}

		log.Debugf("Updated proofs for output %d", idx)

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
				[]*proof.Proof{parsedSuffix},
				p.cfg.ProofWatcher.DefaultUpdateCallback(),
			)
			if err != nil {
				return fmt.Errorf("error watching proof: %w",
					err)
			}
		}
	}

	sendPkg.SendState = SendStateTransferProofs
	return nil
}

// storePackageAnchorTxConf logs the on-chain confirmation of the transfer
// anchor transaction for the given package.
func (p *ChainPorter) storePackageAnchorTxConf(pkg *sendPackage) error {
	ctx, cancel := p.WithCtxQuitNoTimeout()
	defer cancel()

	// Load passive asset proof files from archive.
	passiveAssetProofFiles := map[asset.ID][]*proof.AnnotatedProof{}
	for idx := range pkg.OutboundPkg.PassiveAssets {
		passivePkt := pkg.OutboundPkg.PassiveAssets[idx]
		passiveOut := passivePkt.Outputs[0]

		proofLocator := proof.Locator{
			AssetID:   fn.Ptr(passiveOut.Asset.ID()),
			ScriptKey: *passiveOut.ScriptKey.PubKey,
			OutPoint:  fn.Ptr(passiveOut.ProofSuffix.OutPoint()),
		}
		proofFileBlob, err := p.cfg.ProofReader.FetchProof(
			ctx, proofLocator,
		)
		if err != nil {
			return fmt.Errorf("error fetching passive asset "+
				"proof file: %w", err)
		}

		passiveAssetProofFiles[passiveOut.Asset.ID()] = append(
			passiveAssetProofFiles[passiveOut.Asset.ID()],
			&proof.AnnotatedProof{
				Locator: proofLocator,
				Blob:    proofFileBlob,
			},
		)
	}

	// Now we scan through the VPacket for any burns.
	var burns []*AssetBurn

	for _, v := range pkg.VirtualPackets {
		for _, o := range v.Outputs {
			if !o.Asset.IsBurn() {
				continue
			}

			assetID := o.Asset.ID()

			// We prepare the burn and add it to the list.
			b := &AssetBurn{
				AssetID:    assetID[:],
				Amount:     o.Amount,
				AnchorTxid: pkg.OutboundPkg.AnchorTx.TxHash(),
				Note:       pkg.Note,
			}

			if o.Asset.GroupKey != nil {
				groupKey := o.Asset.GroupKey.GroupPubKey
				b.GroupKey = groupKey.SerializeCompressed()
			}

			burns = append(burns, b)
		}
	}

	// At this point we have the confirmation signal, so we can mark the
	// parcel delivery as completed in the database.
	anchorTXID := pkg.OutboundPkg.AnchorTx.TxHash()
	anchorTxBlockHeight := int32(pkg.TransferTxConfEvent.BlockHeight)
	err := p.cfg.ExportLog.LogAnchorTxConfirm(ctx, &AssetConfirmEvent{
		AnchorTXID:             anchorTXID,
		BlockHash:              *pkg.TransferTxConfEvent.BlockHash,
		BlockHeight:            anchorTxBlockHeight,
		TxIndex:                int32(pkg.TransferTxConfEvent.TxIndex),
		FinalProofs:            pkg.FinalProofs,
		PassiveAssetProofFiles: passiveAssetProofFiles,
	}, burns)
	if err != nil {
		return fmt.Errorf("unable to log parcel delivery "+
			"confirmation: %w", err)
	}

	return nil
}

// fetchInputProof fetches a proof for the given input from the proof archive.
func (p *ChainPorter) fetchInputProof(ctx context.Context,
	input asset.PrevID) (*proof.File, error) {

	scriptKey, err := btcec.ParsePubKey(input.ScriptKey[:])
	if err != nil {
		return nil, fmt.Errorf("error parsing script key: %w", err)
	}
	inputProofLocator := proof.Locator{
		AssetID:   &input.ID,
		ScriptKey: *scriptKey,
		OutPoint:  &input.OutPoint,
	}
	inputProofBytes, err := p.cfg.ProofReader.FetchProof(
		ctx, inputProofLocator,
	)
	if err != nil {
		return nil, fmt.Errorf("error fetching input proof -- "+
			"locator=%v: %w", spew.Sdump(inputProofLocator), err)
	}
	inputProofFile := proof.NewEmptyFile(proof.V0)
	err = inputProofFile.Decode(bytes.NewReader(inputProofBytes))
	if err != nil {
		return nil, fmt.Errorf("error decoding input proof: %w", err)
	}

	return inputProofFile, nil
}

// updateAssetProofFile retrieves and updates the proof file for the given
// virtual packet output.
func (p *ChainPorter) updateAssetProofFile(ctx context.Context,
	inputs []asset.PrevID, proofSuffix *proof.Proof,
	newScriptKey asset.ScriptKey,
	confEvent *chainntnfs.TxConfirmation) (*proof.AnnotatedProof, error) {

	// The suffix doesn't contain any information about the confirmed block
	// yet, so we'll add that now.
	err := proofSuffix.UpdateTransitionProof(&proof.BaseProofParams{
		Block:       confEvent.Block,
		BlockHeight: confEvent.BlockHeight,
		Tx:          confEvent.Tx,
		TxIndex:     int(confEvent.TxIndex),
	})
	if err != nil {
		return nil, fmt.Errorf("error updating transition proof: %w",
			err)
	}

	// The suffix is complete, so we need to fetch the input proof in order
	// to append the suffix to it.
	firstInput := inputs[0]
	inputProofFile, err := p.fetchInputProof(ctx, firstInput)
	if err != nil {
		return nil, fmt.Errorf("error fetching input proof: %w", err)
	}

	// Are there more inputs? Then this is a merge, and we need to add those
	// additional files to the suffix as well.
	for idx := 1; idx < len(inputs); idx++ {
		additionalInputProofFile, err := p.fetchInputProof(
			ctx, inputs[idx],
		)
		if err != nil {
			return nil, fmt.Errorf("error fetching additional "+
				"input proof %d: %w", idx, err)
		}

		proofSuffix.AdditionalInputs = append(
			proofSuffix.AdditionalInputs, *additionalInputProofFile,
		)
	}

	// With the proof suffix updated, we can append the proof, then encode
	// it to get the final proof file.
	if err := inputProofFile.AppendProof(*proofSuffix); err != nil {
		return nil, fmt.Errorf("error appending proof: %w", err)
	}
	var outputProofBuf bytes.Buffer
	if err := inputProofFile.Encode(&outputProofBuf); err != nil {
		return nil, fmt.Errorf("error encoding proof: %w", err)
	}

	// Now we just need to identify the new proof correctly before adding it
	// to the proof archive.
	outputProofLocator := proof.Locator{
		AssetID:   &firstInput.ID,
		ScriptKey: *newScriptKey.PubKey,
		OutPoint:  fn.Ptr(proofSuffix.OutPoint()),
	}

	return &proof.AnnotatedProof{
		Locator: outputProofLocator,
		Blob:    outputProofBuf.Bytes(),
	}, nil
}

// reportProofTransfers logs a summary of the transfer outputs that require
// proof delivery and those that do not.
func reportProofTransfers(notDeliveringOutputs []TransferOutput,
	pendingDeliveryOutputs []TransferOutput) {

	log.Debugf("Count of transfer output(s) by proof delivery status: "+
		"(count_delivery_not_applicable=%d, count_pending_delivery=%d)",
		len(notDeliveringOutputs), len(pendingDeliveryOutputs))

	// Report the transfer outputs that do not require proof delivery.
	if len(notDeliveringOutputs) > 0 {
		logEntries := make([]string, 0, len(notDeliveringOutputs))
		for idx := range notDeliveringOutputs {
			out := notDeliveringOutputs[idx]
			key := out.ScriptKey.PubKey

			entry := fmt.Sprintf("transfer_output_position=%d, "+
				"proof_delivery_status=%v, "+
				"script_key=%x", out.Position,
				out.ProofDeliveryComplete,
				key.SerializeCompressed())
			logEntries = append(logEntries, entry)
		}

		entriesJoin := strings.Join(logEntries, "\n")
		log.Debugf("Transfer outputs that do not require proof "+
			"delivery:\n%v", entriesJoin)
	}

	// Report the transfer outputs that require proof delivery.
	if len(pendingDeliveryOutputs) > 0 {
		logEntries := make([]string, 0, len(pendingDeliveryOutputs))
		for idx := range pendingDeliveryOutputs {
			out := pendingDeliveryOutputs[idx]
			key := out.ScriptKey.PubKey

			entry := fmt.Sprintf("transfer_output_position=%d, "+
				"proof_delivery_status=%v, "+
				"proof_courier_addr=%s, "+
				"script_key=%x", out.Position,
				out.ProofDeliveryComplete, out.ProofCourierAddr,
				key.SerializeCompressed())
			logEntries = append(logEntries, entry)
		}

		entriesJoin := strings.Join(logEntries, "\n")
		log.Debugf("Transfer outputs that require proof delivery:\n%v",
			entriesJoin)
	}
}

// transferReceiverProof retrieves the sender and receiver proofs from the
// archive and then transfers the receiver's proof to the receiver. Upon
// successful transfer, the asset parcel delivery is marked as complete.
func (p *ChainPorter) transferReceiverProof(pkg *sendPackage) error {
	ctx, cancel := p.WithCtxQuitNoTimeout()
	defer cancel()

	// Classify transfer outputs into those that require proof delivery and
	// those that do not.
	var (
		notDeliveringOutputs   []TransferOutput
		pendingDeliveryOutputs []TransferOutput
	)
	for idx := range pkg.OutboundPkg.Outputs {
		out := pkg.OutboundPkg.Outputs[idx]

		// We'll first check to see if the proof should be delivered.
		shouldDeliverProof, err := out.ShouldDeliverProof()
		if err != nil {
			return fmt.Errorf("error determining if proof should "+
				"be delivered: %w", err)
		}

		if !shouldDeliverProof {
			notDeliveringOutputs = append(notDeliveringOutputs, out)
			continue
		}

		pendingDeliveryOutputs = append(pendingDeliveryOutputs, out)
	}

	// Log a summary of the transfer outputs that require proof delivery and
	// those that do not.
	reportProofTransfers(notDeliveringOutputs, pendingDeliveryOutputs)

	// incompleteDelivery is set to true if any proof delivery attempts fail
	// and exceed the maximum backoff limit.
	incompleteDelivery := false

	deliver := func(ctx context.Context, out TransferOutput) error {
		scriptKey := out.ScriptKey.PubKey
		scriptKeyBytes := scriptKey.SerializeCompressed()
		outKey, err := out.UniqueKey()
		if err != nil {
			return fmt.Errorf("error generating unique key for "+
				"output: %w", err)
		}

		receiverProof, ok := pkg.FinalProofs[outKey]
		if !ok {
			return fmt.Errorf("no proof found for output with "+
				"script key %x", scriptKeyBytes)
		}

		log.Debugf("Attempting to deliver proof (script_key=%x, "+
			"asset_id=%x, proof_courier_addr=%s)",
			scriptKeyBytes, receiverProof.AssetID[:],
			out.ProofCourierAddr)

		proofCourierAddr, err := proof.ParseCourierAddress(
			string(out.ProofCourierAddr),
		)
		if err != nil {
			return fmt.Errorf("failed to parse proof courier "+
				"address: %w", err)
		}

		// Initiate proof courier service handle from the proof
		// courier address found in the Tap address.
		courier, err := p.cfg.ProofCourierDispatcher.NewCourier(
			ctx, proofCourierAddr, true,
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
		recipient := proof.Recipient{
			ScriptKey: scriptKey,
			AssetID:   *receiverProof.AssetID,
			Amount:    out.Amount,
		}
		err = courier.DeliverProof(ctx, recipient, receiverProof)

		// If the proof courier returned a backoff error, then
		// we'll just return nil here so that we can retry
		// later.
		var backoffExecErr *proof.BackoffExecError
		if errors.As(err, &backoffExecErr) {
			log.Debugf("Exceeded backoff limit for proof delivery "+
				"(script_key=%x, proof_courier_addr=%s)",
				scriptKey.SerializeCompressed(),
				out.ProofCourierAddr)

			// Set the incomplete delivery flag to true so that we
			// can retry the proof transfer state later.
			incompleteDelivery = true
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to deliver proof via "+
				"courier service: %w", err)
		}

		// The proof has been successfully delivered to the receiver.
		// Now, we will update our transfer log to reflect this.
		err = p.cfg.ExportLog.ConfirmProofDelivery(
			ctx, out.Anchor.OutPoint, out.Position,
		)
		if err != nil {
			return fmt.Errorf("unable to log proof delivery "+
				"confirmation: %w", err)
		}

		log.Infof("Transfer output proof delivery complete "+
			"(anchor_txid=%v, output_position=%d)",
			pkg.OutboundPkg.AnchorTx.TxHash(), out.Position)

		return nil
	}

	// If we have a non-interactive proof, then we'll launch several
	// goroutines to deliver the proof(s) to the receiver(s).
	instanceErrors, err := fn.ParSliceErrCollect(
		ctx, pendingDeliveryOutputs, deliver,
	)
	if err != nil {
		return fmt.Errorf("error delivering proof(s): %w", err)
	}

	// If there were any errors during the proof delivery process, we'll
	// log them all here.
	for idx := range instanceErrors {
		output := pkg.OutboundPkg.Outputs[idx]
		instanceErr := instanceErrors[idx]

		scriptPubKey := output.ScriptKey.PubKey.SerializeCompressed()
		anchorOutpoint := output.Anchor.OutPoint.String()
		courierAddr := string(output.ProofCourierAddr)

		log.Errorf("Error delivering transfer output proof "+
			"(anchor_outpoint=%s, script_pub_key=%x, "+
			"position=%d, proof_courier_addr=%s, "+
			"proof_delivery_status=%v): %v",
			anchorOutpoint, scriptPubKey, output.Position,
			courierAddr, output.ProofDeliveryComplete,
			instanceErr)
	}

	// Return the first error encountered during the proof delivery process,
	// if any.
	var firstErr error
	fn.PeekMap(instanceErrors).WhenSome(func(kv fn.KV[int, error]) {
		firstErr = kv.Value
	})

	if firstErr != nil {
		return firstErr
	}

	// If the delivery is incomplete, we'll return early so that we can
	// retry proof transfer later.
	if incompleteDelivery {
		log.Debugf("Proof delivery incomplete, will retry executing "+
			"the proof transfer state (transfer_anchor_tx_hash=%v)",
			pkg.OutboundPkg.AnchorTx.TxHash())

		// Return here before setting the transfer to complete.
		return nil
	}

	// At this point, the transfer is fully finalised and successful:
	// - The anchoring transaction has been confirmed on-chain.
	// - The proof(s) have been delivered to the receiver(s).
	// - The database has been updated to reflect the successful transfer.
	log.Infof("Parcel transfer is fully complete (anchor_txid=%v)",
		pkg.OutboundPkg.AnchorTx.TxHash())

	// Send out the final notification that the transfer is complete.
	p.publishSubscriberEvent(newAssetSendEvent(SendStateComplete, *pkg))

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

// pingCourier attempts to establish a connection to the given proof courier
// address. If the connection is successful, the courier is closed and the
// function returns nil. If the connection fails, an error is returned.
// This function is blocking.
func (p *ChainPorter) pingCourier(ctx context.Context, addr url.URL) error {
	log.Debugf("Attempting to ping proof courier (addr=%s)", addr.String())

	// Connect to the proof courier service with an eager (non-lazy)
	// connection attempt, blocking until the connection either succeeds,
	// fails, or times out.
	courier, err := p.cfg.ProofCourierDispatcher.NewCourier(
		ctx, &addr, false,
	)
	if err != nil {
		return fmt.Errorf("unable to initiate proof courier "+
			"service handle (addr=%s): %w", addr.String(), err)
	}

	return courier.Close()
}

// pingProofCouriers performs a blocking connectivity check for each applicable
// proof courier.
func (p *ChainPorter) pingProofCouriers(proofCourierAddrs []url.URL) error {
	// Construct minimal set of unique proof couriers to ping.
	var couriers []url.URL

	for idx := range proofCourierAddrs {
		addr := proofCourierAddrs[idx]

		// Check if the address is a duplicate (already in the list of
		// couriers).
		for i := range couriers {
			if addr.String() == couriers[i].String() {
				// Skip duplicate addresses.
				continue
			}
		}

		couriers = append(couriers, addr)
	}

	// Ping each proof courier in parallel to ensure they are reachable.
	ctx, cancel := p.WithCtxQuit()
	defer cancel()
	instanceErrors, err := fn.ParSliceErrCollect(
		ctx, couriers, p.pingCourier,
	)
	if err != nil {
		return fmt.Errorf("failed execute proof courier(s) parallel "+
			"ping: %w", err)
	}

	// If any errors occurred while pinging proof couriers, log them all
	// here.
	for idx := range instanceErrors {
		addr := couriers[idx]
		instanceErr := instanceErrors[idx]

		log.Errorf("Failed to pinging proof courier (addr=%s): %v",
			addr.String(), instanceErr)
	}

	// If any errors occurred while pinging proof couriers, return an error.
	if len(instanceErrors) > 0 {
		return fmt.Errorf("failed to ping proof courier(s) "+
			"(error_count=%d)", len(instanceErrors))
	}

	return nil
}

// prelimCheckAddrParcel performs preliminary validation on the given address
// parcel. These early checks run before any coin locking or transaction
// broadcasting occurs.
func (p *ChainPorter) prelimCheckAddrParcel(addrParcel AddressParcel) error {
	// Currently, the only preliminary check is to ensure that the proof
	// couriers are reachable. If the skip flag is set, we skip this
	// check and exit early.
	if addrParcel.skipProofCourierPingCheck {
		log.Debugf("Flag skipProofCourierPingCheck activated. " +
			"Skipping check. ")
		return nil
	}

	// Ping the proof couriers to verify that they are reachable.
	// This early check ensures a proof can be reliably delivered
	// to the counterparty before broadcasting a transaction or
	// locking local funds.
	var proofCourierAddrs []url.URL
	for idx := range addrParcel.destAddrs {
		tapAddr := addrParcel.destAddrs[idx]

		proofCourierAddrs = append(
			proofCourierAddrs, tapAddr.ProofCourierAddr,
		)
	}

	err := p.pingProofCouriers(proofCourierAddrs)
	if err != nil {
		return fmt.Errorf("failed proof courier(s) connection "+
			"check: %w", err)
	}

	return nil
}

// stateStep attempts to step through the state machine to complete a Taproot
// Asset transfer.
func (p *ChainPorter) stateStep(currentPkg sendPackage) (*sendPackage, error) {
	switch currentPkg.SendState {
	// The initial state entered when the state machine begins processing a
	// new address parcel. In this state, basic validation is performed,
	// such as verifying connectivity to any required proof courier service.
	case SendStateStartHandleAddrParcel:
		// Ensure that the parcel is a valid address parcel.
		addrParcel, ok := currentPkg.Parcel.(*AddressParcel)
		if !ok {
			return nil, fmt.Errorf("unable to cast parcel to " +
				"address parcel")
		}

		err := p.prelimCheckAddrParcel(*addrParcel)
		if err != nil {
			return nil, fmt.Errorf("failed to perform prelim "+
				"checks on address parcel: %w", err)
		}

		currentPkg.SendState = SendStateVirtualCommitmentSelect
		return &currentPkg, nil

	// Perform coin selection for the address parcel.
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
		fundSendRes, err := p.cfg.AssetWallet.FundAddressSend(
			ctx, fn.Some(asset.ScriptKeyBip86), nil,
			addrParcel.destAddrs...,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fund address send: "+
				"%w", err)
		}

		currentPkg.VirtualPackets = fundSendRes.VPackets
		currentPkg.InputCommitments = fundSendRes.InputCommitments

		currentPkg.SendState = SendStateVirtualSign

		return &currentPkg, nil

	// At this point, we have everything we need to sign our _virtual_
	// transaction on the Taproot Asset layer.
	case SendStateVirtualSign:
		ctx, cancel := p.WithCtxQuitNoTimeout()
		defer cancel()

		vPackets := currentPkg.VirtualPackets
		err := tapsend.ValidateVPacketVersions(vPackets)
		if err != nil {
			p.unlockInputs(ctx, &currentPkg)

			return nil, err
		}

		// Now we'll use the signer to sign all the inputs for the new
		// Taproot Asset leaves. The witness data for each input will be
		// assigned for us.
		for idx := range vPackets {
			vPkt := vPackets[idx]

			logPacket(vPkt, "Generating Taproot Asset witnesses")

			_, err := p.cfg.AssetWallet.SignVirtualPacket(vPkt)
			if err != nil {
				p.unlockInputs(ctx, &currentPkg)

				return nil, fmt.Errorf("unable to sign and "+
					"commit virtual packet: %w", err)
			}
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
		var (
			feeRate chainfee.SatPerKWeight
			err     error
		)

		// First, use a manual fee rate if specified by the parcel.
		addrParcel, ok := currentPkg.Parcel.(*AddressParcel)
		switch {
		case ok && addrParcel.transferFeeRate != nil:
			feeRate = *addrParcel.transferFeeRate
			log.Infof("sending with manual fee rate")

		default:
			feeRate, err = p.cfg.ChainBridge.EstimateFee(
				ctx, tapsend.SendConfTarget,
			)
			if err != nil {
				p.unlockInputs(ctx, &currentPkg)

				return nil, fmt.Errorf("unable to estimate "+
					"fee: %w", err)
			}

			log.Infof("estimated fee rate for parcel:, %s",
				feeRate.FeePerKVByte().String())
		}

		minRelayFee, err := p.cfg.Wallet.MinRelayFee(ctx)
		if err != nil {
			p.unlockInputs(ctx, &currentPkg)

			return nil, fmt.Errorf("unable to obtain "+
				"minimum relay fee: %w", err)
		}

		// If the fee rate is below the minimum relay fee, we'll
		// bump it up.
		if feeRate < minRelayFee {
			switch {
			// If a fee rate was manually assigned for this parcel,
			// we err out, otherwise we silently bump the feerate.
			case addrParcel.transferFeeRate != nil:
				// This case should already have been handled by
				// the `checkFeeRateSanity` of `rpcserver.go`.
				// We check here again to be safe.
				p.unlockInputs(ctx, &currentPkg)

				return nil, fmt.Errorf("feerate does not "+
					"meet minrelayfee: (fee_rate=%s, "+
					"minrelayfee=%s)", feeRate.String(),
					minRelayFee.String())
			default:
				log.Infof("bump fee rate for parcel to meet "+
					"minrelayfee from %s to %s",
					feeRate.FeePerKVByte().String(),
					minRelayFee.FeePerKVByte().String())
				feeRate = minRelayFee
			}
		}

		readableFeeRate := feeRate.FeePerKVByte().String()
		log.Infof("Sending with fee rate: %v", readableFeeRate)

		for idx := range currentPkg.VirtualPackets {
			vPkt := currentPkg.VirtualPackets[idx]

			logPacket(vPkt, "Constructing new Taproot Asset "+
				"commitments")
		}

		// Gather passive assets virtual packets and sign them.
		wallet := p.cfg.AssetWallet

		currentPkg.PassiveAssets, err = wallet.CreatePassiveAssets(
			ctx, currentPkg.VirtualPackets,
			currentPkg.InputCommitments,
		)
		if err != nil {
			p.unlockInputs(ctx, &currentPkg)

			return nil, fmt.Errorf("unable to create passive "+
				"assets: %w", err)
		}

		log.Debugf("Signing %d passive assets",
			len(currentPkg.PassiveAssets))

		err = wallet.SignPassiveAssets(currentPkg.PassiveAssets)
		if err != nil {
			p.unlockInputs(ctx, &currentPkg)

			return nil, fmt.Errorf("unable to sign passive "+
				"assets: %w", err)
		}

		anchorTx, err := wallet.AnchorVirtualTransactions(
			ctx, &AnchorVTxnsParams{
				FeeRate:        feeRate,
				ActivePackets:  currentPkg.VirtualPackets,
				PassivePackets: currentPkg.PassiveAssets,
			},
		)
		if err != nil {
			p.unlockInputs(ctx, &currentPkg)

			return nil, fmt.Errorf("unable to anchor virtual "+
				"transactions: %w", err)
		}

		// We keep the original funded PSBT with all the wallet's output
		// information on the change output preserved but continue the
		// signing process with a copy to avoid clearing the info on
		// finalization.
		currentPkg.AnchorTx = anchorTx

		// For the final validation, we need to also supply the assets
		// that were committed to the input tree but pruned because they
		// were burns or tombstones.
		prunedAssets := make(map[wire.OutPoint][]*asset.Asset)
		for prevID := range currentPkg.InputCommitments {
			c := currentPkg.InputCommitments[prevID]
			prunedAssets[prevID.OutPoint] = append(
				prunedAssets[prevID.OutPoint],
				tapsend.ExtractUnSpendable(c)...,
			)
		}

		// Make sure everything is ready for the finalization.
		err = currentPkg.validateReadyForPublish(prunedAssets)
		if err != nil {
			p.unlockInputs(ctx, &currentPkg)

			return nil, fmt.Errorf("unable to validate send "+
				"package: %w", err)
		}

		currentPkg.SendState = SendStateStorePreBroadcast

		return &currentPkg, nil

	// In this state, the parcel state is stored before the fully signed
	// transaction is broadcast to the mempool.
	case SendStateStorePreBroadcast:
		// We won't broadcast in this state, but in preparation for
		// broadcasting, we will find out the current height to use as
		// a height hint.
		ctx, cancel := p.WithCtxQuit()
		defer cancel()
		currentHeight, err := p.cfg.ChainBridge.CurrentHeight(ctx)
		if err != nil {
			p.unlockInputs(ctx, &currentPkg)

			return nil, fmt.Errorf("unable to get current height: "+
				"%w", err)
		}

		// We now need to find out if this is a transfer to ourselves
		// (e.g. a change output) or an outbound transfer. A key being
		// local means the lnd node connected to this daemon knows how
		// to derive the key.
		isLocalKey := func(key asset.ScriptKey) bool {
			return key.TweakedScriptKey != nil &&
				p.cfg.KeyRing.IsLocalKey(ctx, key.RawKey)
		}

		// We need to prepare the parcel for storage.
		parcel, err := ConvertToTransfer(
			currentHeight, currentPkg.VirtualPackets,
			currentPkg.AnchorTx, currentPkg.PassiveAssets,
			isLocalKey, currentPkg.Label,
		)
		if err != nil {
			p.unlockInputs(ctx, &currentPkg)

			return nil, fmt.Errorf("unable to prepare parcel for "+
				"storage: %w", err)
		}
		currentPkg.OutboundPkg = parcel

		// Don't allow shutdown while we're attempting to store proofs.
		ctx, cancel = p.CtxBlocking()
		defer cancel()

		log.Infof("Committing pending parcel to disk")

		// Write the parcel to disk as a pending parcel. This step also
		// records the transfer details (e.g., reference to the anchor
		// transaction ID, transfer outputs and inputs) to the database.
		err = p.cfg.ExportLog.LogPendingParcel(
			ctx, parcel, defaultWalletLeaseIdentifier,
			time.Now().Add(defaultBroadcastCoinLeaseDuration),
		)
		if err != nil {
			p.unlockInputs(ctx, &currentPkg)

			return nil, fmt.Errorf("unable to write send pkg to "+
				"disk: %w", err)
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
			p.unlockInputs(ctx, &currentPkg)

			return nil, fmt.Errorf("unable to import local "+
				"addresses: %w", err)
		}

		txHash := currentPkg.OutboundPkg.AnchorTx.TxHash()
		log.Infof("Broadcasting new transfer tx, txid=%v", txHash)

		// With the public key imported, we can now broadcast to the
		// network.
		err = p.cfg.ChainBridge.PublishTransaction(
			ctx, currentPkg.OutboundPkg.AnchorTx, TransferTxLabel,
		)
		switch {
		case errors.Is(err, lnwallet.ErrDoubleSpend):
			// A double spend error means the transaction will never
			// make it into the mempool or chain, so we'll never be
			// able to confirm it. At this point we should probably
			// put the transfer in a failed state and not re-try on
			// next startup... But since we don't have that state
			// yet, we just return an error here. But what we can do
			// is release any fee sponsoring inputs we selected from
			// lnd's wallet to avoid locking up balance.
			//
			// TODO(guggero): Put this transfer into a failed state
			// and don't retry on next startup.
			p.unlockInputs(ctx, &currentPkg)

			return nil, fmt.Errorf("unable to broadcast "+
				"transaction %v: %w", txHash, err)

		case err != nil:
			return nil, fmt.Errorf("unable to broadcast "+
				"transaction %v: %w", txHash, err)
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

	// The transfer transaction is now confirmed on-chain. We'll update the
	// package state on disk to reflect this. This step frees up the change
	// outputs so that they can be used in future transactions.
	case SendStateStorePostAnchorTxConf:
		err := p.storeProofs(&currentPkg)
		if err != nil {
			return nil, fmt.Errorf("unable to store proofs: %w",
				err)
		}

		// We'll now update the parcel state in storage to reflect that
		// the transfer anchoring tx is confirmed on-chain.
		err = p.storePackageAnchorTxConf(&currentPkg)
		if err != nil {
			return nil, fmt.Errorf("storing transfer anchor tx "+
				"on-chain confirmation: %w", err)
		}

		return &currentPkg, nil

	// At this point, the transfer transaction is confirmed on-chain, and
	// we've stored the sender and receiver proofs in the proof archive.
	// We'll now attempt to transfer one or more proofs to the receiver(s).
	case SendStateTransferProofs:
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

				p.publishSubscriberEvent(newAssetSendErrorEvent(
					err, SendStateTransferProofs,
					currentPkg,
				))
			}
		}()

		return &currentPkg, nil

	default:
		return &currentPkg, fmt.Errorf("unknown state: %v",
			currentPkg.SendState)
	}
}

// unlockInputs unlocks the inputs that were locked for the given package.
func (p *ChainPorter) unlockInputs(ctx context.Context, pkg *sendPackage) {
	// Impossible state, but catch it anyway.
	if pkg == nil {
		return
	}

	// If we haven't even attempted to broadcast yet, we're still in a state
	// where we give feedback to the user synchronously, as we haven't
	// created an on-chain transaction that we need to await confirmation.
	// We also haven't written the transfer to disk yet, so we can just
	// release/unlock the _asset_ level UTXOs so the user can try again. We
	// sanity-check that we have known input commitments to unlock, since
	// that might not always be the case (for example if another party
	// contributes inputs).
	if pkg.SendState < SendStateStorePreBroadcast &&
		len(pkg.InputCommitments) > 0 {

		for prevID := range pkg.InputCommitments {
			log.Debugf("Unlocking input %v", prevID.OutPoint)

			err := p.cfg.AssetWallet.ReleaseCoins(
				ctx, prevID.OutPoint,
			)
			if err != nil {
				log.Warnf("Unable to unlock input %v: %v",
					prevID.OutPoint, err)
			}
		}
	}

	// If we're in another state, the anchor transaction has been created,
	// and we can't simply unlock the asset level inputs. This will likely
	// require manual intervention.
	if pkg.AnchorTx == nil || pkg.AnchorTx.FundedPsbt == nil {
		return
	}

	// We need to unlock any _BTC_ level inputs we locked for the anchor
	// transaction.
	for _, op := range pkg.AnchorTx.FundedPsbt.LockedUTXOs {
		err := p.cfg.Wallet.UnlockInput(ctx, op)
		if err != nil {
			log.Warnf("Unable to unlock input %v: %v", op, err)
		}
	}
}

// logPacket logs the virtual packet to the debug log.
func logPacket(vPkt *tappsbt.VPacket, action string) {
	firstRecipient, err := vPkt.FirstNonSplitRootOutput()
	if err != nil {
		// Fall back to the first output if there is no split output
		// (probably a full-value send).
		firstRecipient = vPkt.Outputs[0]
	}

	receiverScriptKey := firstRecipient.ScriptKey.PubKey
	log.Infof("%s for send to: %x", action,
		receiverScriptKey.SerializeCompressed())
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

// detectUnSpendableKeys checks if the script key in the virtual output is a
// burn or tombstone key and sets the appropriate type on the output script key.
func detectUnSpendableKeys(vOut *tappsbt.VOutput) {
	setScriptKeyType := func(vOut *tappsbt.VOutput,
		scriptKeyType asset.ScriptKeyType) {

		if vOut.Asset.ScriptKey.TweakedScriptKey == nil {
			vOut.Asset.ScriptKey.TweakedScriptKey = new(
				asset.TweakedScriptKey,
			)
			vOut.Asset.ScriptKey.RawKey.PubKey =
				vOut.Asset.ScriptKey.PubKey
		}
		if vOut.ScriptKey.TweakedScriptKey == nil {
			vOut.ScriptKey.TweakedScriptKey = new(
				asset.TweakedScriptKey,
			)
			vOut.ScriptKey.RawKey.PubKey = vOut.ScriptKey.PubKey
		}

		vOut.Asset.ScriptKey.Type = scriptKeyType
		vOut.ScriptKey.Type = scriptKeyType
	}

	if vOut.Asset == nil {
		return
	}

	witness := vOut.Asset.PrevWitnesses
	scriptKey := vOut.ScriptKey
	if len(witness) > 0 && asset.IsBurnKey(scriptKey.PubKey, witness[0]) {
		setScriptKeyType(vOut, asset.ScriptKeyBurn)
	}

	unSpendable, _ := scriptKey.IsUnSpendable()
	if unSpendable {
		setScriptKeyType(vOut, asset.ScriptKeyTombstone)
	}
}

// A compile-time assertion to make sure ChainPorter satisfies the
// fn.EventPublisher interface.
var _ fn.EventPublisher[fn.Event, bool] = (*ChainPorter)(nil)

// AssetSendEvent is an event which is sent to the ChainPorter's event
// subscribers after a state was executed.
type AssetSendEvent struct {
	// timestamp is the time the event was created.
	timestamp time.Time

	// SendState is the state that was just executed successfully, unless
	// Error below is set, then it means executing this state failed.
	SendState SendState

	// Error is an optional error, indicating that something went wrong
	// during the execution of the SendState above.
	Error error

	// Parcel is the parcel that is being sent.
	Parcel Parcel

	// TransferLabel is the label that was set for the transfer.
	TransferLabel string

	// VirtualPackets is the list of virtual packets that describes the
	// "active" parts of the asset transfer.
	VirtualPackets []*tappsbt.VPacket

	// PassivePackets is the list of virtual packets that describes the
	// "passive" parts of the asset transfer.
	PassivePackets []*tappsbt.VPacket

	// AnchorTx is the BTC level anchor transaction with all its information
	// as it was used when funding/signing it.
	AnchorTx *tapsend.AnchorTransaction

	// Transfer is the on-disk level information that tracks the pending
	// transfer.
	Transfer *OutboundParcel
}

// Timestamp returns the timestamp of the event.
func (e *AssetSendEvent) Timestamp() time.Time {
	return e.timestamp
}

// newAssetSendEvent creates a new AssetSendEvent from the given send package
// and executed state.
func newAssetSendEvent(executedState SendState,
	pkg sendPackage) *AssetSendEvent {

	newSendEvent := &AssetSendEvent{
		timestamp: time.Now().UTC(),
		SendState: executedState,
		// The parcel remains static throughout the state machine, so we
		// don't need to copy it, there can be no data race.
		Parcel:         pkg.Parcel,
		TransferLabel:  pkg.Label,
		VirtualPackets: fn.CopyAll(pkg.VirtualPackets),
		PassivePackets: fn.CopyAll(pkg.PassiveAssets),
	}

	if pkg.AnchorTx != nil {
		newSendEvent.AnchorTx = pkg.AnchorTx.Copy()
	}

	if pkg.OutboundPkg != nil {
		newSendEvent.Transfer = pkg.OutboundPkg.Copy()
	}

	return newSendEvent
}

// newAssetSendErrorEvent creates a new AssetSendEvent with an error.
func newAssetSendErrorEvent(err error, executedState SendState,
	pkg sendPackage) *AssetSendEvent {

	return &AssetSendEvent{
		timestamp:      time.Now().UTC(),
		SendState:      executedState,
		Error:          err,
		Parcel:         pkg.Parcel,
		TransferLabel:  pkg.Label,
		VirtualPackets: pkg.VirtualPackets,
		PassivePackets: pkg.PassiveAssets,
		AnchorTx:       pkg.AnchorTx,
		Transfer:       pkg.OutboundPkg,
	}
}
