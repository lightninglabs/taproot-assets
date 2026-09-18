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
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/universe"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

const (
	// DefaultSendFragmentExpiryDelta is the default number of blocks that
	// we expect a send fragment to be valid for after its claimed outpoint
	// has been spent. This is roughly equivalent to 90 days.
	DefaultSendFragmentExpiryDelta = 12_960
)

// VerifiedProofImporter is used to import verified proofs into the local proof
// archive after we complete a transfer.
type VerifiedProofImporter interface {
	// ImportVerifiedProofs stores verified proofs without re-validating
	// them. If replace is specified, we expect a proof to already be
	// present, and we just update (replace) it with the new proof.
	ImportVerifiedProofs(ctx context.Context, replace bool,
		proofs ...proof.VerifiedAnnotatedProof) error
}

// BurnSupplyCommitter is used by the chain porter to update the on-chain supply
// commitment when burns 1st party burns are confirmed.
type BurnSupplyCommitter interface {
	// SendBurnEvent sends a burn event to the supply commitment state
	// machine.
	SendBurnEvent(ctx context.Context, assetSpec asset.Specifier,
		burnLeaf universe.BurnLeaf) error
}

// ChainPorterConfig is the main config for the chain porter.
type ChainPorterConfig struct {
	// ChainParams are the chain parameters for the chain porter.
	ChainParams address.ChainParams

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

	ProofWriter VerifiedProofImporter

	// ProofReader is used to fetch input proofs.
	ProofReader proof.Exporter

	// ProofCourierDispatcher is the dispatcher that is used to create new
	// proof courier handles for sending proofs based on the protocol of
	// a proof courier address.
	ProofCourierDispatcher proof.CourierDispatch

	// AnchoringWatcher is the re-org watcher the porter registers its
	// transfers with as speculative anchorings. When set, the porter
	// stakes and converges transfer state through the watcher's
	// registry instead of subscribing to confirmations itself.
	//
	// NOTE: this is an interface field; a disabled watcher must be
	// wired as an explicit interface nil, never as a nil concrete
	// pointer.
	AnchoringWatcher tapreorg.Registrar

	// AnchoringLog is the transaction-scoped persistence surface the
	// porter site drives from its watcher handlers.
	AnchoringLog AnchoringLog

	// AnchoringThreshold is the confirmation depth at which the
	// porter considers a transfer act-confirmed (buried).
	AnchoringThreshold uint32

	// IgnoreChecker is an optional function that can be used to check if
	// a proof should be ignored.
	IgnoreChecker lfn.Option[proof.IgnoreChecker]

	// ErrChan is the main error channel the custodian will report back
	// critical errors to the main server.
	ErrChan chan<- error

	// BurnSupplyCommitter is used to track supply changes (burns) and
	// create periodic on-chain supply commitments.
	BurnCommitter BurnSupplyCommitter

	// DelegationKeyChecker is used to verify that we control the delegation
	// key for a given asset, which is required for creating supply
	// commitments.
	DelegationKeyChecker address.DelegationKeyChecker
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

	// waiters tracks parcels waiting on anchoring outcomes, nudged
	// by the re-org watcher's delivery listener.
	waiters *tapreorg.DeliveryWaiters

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
		waiters:         tapreorg.NewDeliveryWaiters(),
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
	for pkg.SendState <= SendStateComplete {
		log.Infof("ChainPorter executing state: %v (label=%s)",
			pkg.SendState, pkg.Label)

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
		// state successfully.
		p.publishSubscriberEvent(newAssetSendEvent(
			stateToExecute, *updatedPkg,
		))

		// Exit the loop once the state machine has executed its final
		// state.
		if pkg.SendState == SendStateComplete {
			log.Infof("ChainPorter completed state machine for "+
				"parcel (anchor_txid=%v)",
				updatedPkg.OutboundPkg.AnchorTx.TxHash())

			return
		}

		pkg = updatedPkg
	}
}

// sendBurnSupplyCommitEvents sends supply commitment events for all burned
// assets to track them in the supply commitment state machine.
func (p *ChainPorter) sendBurnSupplyCommitEvents(ctx context.Context,
	burns []*AssetBurn) error {

	// If no supply commit manager is configured, skip this step.
	if p.cfg.BurnCommitter == nil {
		return nil
	}

	// If no delegation key checker is configured, skip this step. We need
	// it to figure out if this is an asset we created or not.
	if p.cfg.DelegationKeyChecker == nil {
		return nil
	}

	delChecker := p.cfg.DelegationKeyChecker

	// We'll use a filter predicate to filter out the burns that we didn't
	// do ourselves, i.e., those that don't have a delegation key.
	burnsWithDelegation := fn.Filter(burns, func(burn *AssetBurn) bool {
		var assetID asset.ID
		copy(assetID[:], burn.AssetID)

		// If the asset doesn't have a group, then this will return
		// false.
		hasDelegationKey, err := delChecker.HasDelegationKey(
			ctx, assetID,
		)
		if err != nil {
			log.Debugf("Error checking delegation key for "+
				"asset %x: %v", assetID, err)
			return false
		}

		if !hasDelegationKey {
			log.Debugf("Skipping supply commit burn event "+
				"for asset %x: delegation key not controlled "+
				"locally",
				assetID)
		}

		return hasDelegationKey
	})

	for _, burn := range burnsWithDelegation {
		var assetID asset.ID
		copy(assetID[:], burn.AssetID)

		groupKeyBytes := burn.GroupKey
		groupKey, err := btcec.ParsePubKey(groupKeyBytes)
		if err != nil {
			return fmt.Errorf("unable to parse group key: %w", err)
		}

		assetSpec := asset.NewSpecifierOptionalGroupPubKey(
			assetID, groupKey,
		)

		burnLeaf := universe.BurnLeaf{
			UniverseKey: universe.AssetLeafKey{
				BaseLeafKey: universe.BaseLeafKey{
					ScriptKey: burn.ScriptKey,
					OutPoint:  burn.OutPoint,
				},
				AssetID: assetID,
			},
			BurnProof: burn.Proof,
		}

		err = p.cfg.BurnCommitter.SendBurnEvent(
			ctx, assetSpec, burnLeaf,
		)
		if err != nil {
			return fmt.Errorf("unable to send burn event for "+
				"asset %x: %w", assetID, err)
		}

		log.Infof("Sent supply commit burn event for asset %v",
			assetID)
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

		// Is there a send fragment manifest for this output that we
		// need to send first?
		var sendManifest *proof.SendManifest
		if len(pkg.SendManifests) > 0 {
			anchorOutputIndex := out.Anchor.OutPoint.Index
			sendManifest = pkg.SendManifests[anchorOutputIndex]
		}

		log.Debugf("Attempting to deliver proof (script_key=%x, "+
			"asset_id=%x, proof_courier_addr=%s, has_manifest=%v)",
			scriptKeyBytes, receiverProof.AssetID[:],
			out.ProofCourierAddr, sendManifest != nil)

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
		err = courier.DeliverProof(
			ctx, recipient, receiverProof, sendManifest,
		)

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

		isImportable := out.IsLocal() || out.IsTombstone() ||
			out.IsBurn()

		// Determine if the output should be imported into the wallet.
		if !isImportable {
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

		log.Infof("Importing anchor output key for output %d "+
			"(isTombstone=%v, isBurn=%v): outpoint=%v, key=%x",
			idx, out.IsTombstone(), out.IsBurn(),
			out.Anchor.OutPoint,
			anchorOutputKey.SerializeCompressed())

		// Before we broadcast the transaction to the network, we'll
		// import the new anchor output into the wallet so it watches
		// it for spends and also takes account of the BTC we used in
		// the transfer.
		_, err = p.cfg.Wallet.ImportTaprootOutput(ctx, anchorOutputKey)
		if err != nil {
			// On restart, we'll get an error that the output has
			// already been added to the wallet, so we'll catch this
			// now and move along if so.
			if strings.Contains(err.Error(), "already exists") {
				log.Tracef("Anchor output key already exists "+
					"(outpoint=%v): %w",
					out.Anchor.OutPoint, err)
				continue
			}

			return fmt.Errorf("unable to import anchor output "+
				"key: %w", err)
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

// verifyVPacketsPreBroadcast performs verification checks on the given virtual
// packets before the anchor transaction is broadcast.
func (p *ChainPorter) verifyVPacketsPreBroadcast(ctx context.Context,
	packets []*tappsbt.VPacket) error {

	headerVerifier := tapnode.GenHeaderVerifier(ctx, p.cfg.ChainBridge)
	vCtx := proof.VerifierCtx{
		HeaderVerifier: headerVerifier,
		MerkleVerifier: proof.DefaultMerkleVerifier,
		GroupVerifier:  p.cfg.GroupVerifier,
		ChainLookupGen: p.cfg.ChainBridge,
		IgnoreChecker:  p.cfg.IgnoreChecker,
	}

	verifier := &proof.BaseVerifier{}

	for pktIdx := range packets {
		vPkt := packets[pktIdx]

		err := p.verifyPacketInputProofs(ctx, *vPkt)
		if err != nil {
			return fmt.Errorf("verify packet input proofs "+
				"(vpkt_idx=%d): %w", pktIdx, err)
		}

		err = verifySplitCommitmentWitnesses(*vPkt)
		if err != nil {
			return fmt.Errorf("verify split commitment "+
				"witnesses (vpkt_idx=%d): %w", pktIdx, err)
		}

		// Partially verify the packet's output proofs.
		for outIdx := range vPkt.Outputs {
			err := p.verifyOutputProofPreBroadcast(
				ctx, vCtx, verifier, vPkt, pktIdx, outIdx,
			)
			if err != nil {
				return fmt.Errorf("verify output proofs "+
					"(vpkt_idx=%d): %w", pktIdx, err)
			}
		}
	}

	return nil
}

// verifyOutputProofPreBroadcast verifies a single packet output proof by
// assembling a full proof file and skipping chain and time lock verification
// for the final proof, since the anchor transaction is not yet confirmed.
func (p *ChainPorter) verifyOutputProofPreBroadcast(ctx context.Context,
	vCtx proof.VerifierCtx, verifier proof.Verifier,
	vPkt *tappsbt.VPacket, pktIdx, outIdx int) error {

	vOut := vPkt.Outputs[outIdx]
	if vOut.ProofSuffix == nil {
		return fmt.Errorf("output proof suffix is nil "+
			"(vpkt_idx=%d, output_idx=%d)",
			pktIdx, outIdx)
	}

	if vOut.Asset == nil {
		return fmt.Errorf("output asset is nil "+
			"(vpkt_idx=%d, output_idx=%d)",
			pktIdx, outIdx)
	}

	witnesses := vOut.Asset.Witnesses()
	witnessPrevIDs := make(
		map[asset.PrevID]struct{}, len(witnesses),
	)
	for _, witness := range witnesses {
		if witness.PrevID == nil {
			continue
		}

		witnessPrevIDs[*witness.PrevID] = struct{}{}
	}

	inputsForAsset := make(
		[]asset.PrevID, 0, len(vPkt.Inputs),
	)
	for _, in := range vPkt.Inputs {
		if _, ok := witnessPrevIDs[in.PrevID]; ok {
			inputsForAsset = append(
				inputsForAsset, in.PrevID,
			)
		}
	}
	if len(inputsForAsset) == 0 {
		return fmt.Errorf("no inputs matched output "+
			"witnesses (vpkt_idx=%d, "+
			"output_idx=%d)", pktIdx, outIdx)
	}

	inputProofFiles := make(
		map[asset.PrevID]*proof.File, len(inputsForAsset),
	)
	for idx := range inputsForAsset {
		prevID := inputsForAsset[idx]
		inputProofFile, err := p.fetchInputProof(ctx, prevID)
		if err != nil {
			return fmt.Errorf("error fetching input proof %d "+
				"(vpkt_idx=%d, "+
				"output_idx=%d): %w", idx,
				pktIdx, outIdx, err)
		}
		inputProofFiles[prevID] = inputProofFile
	}

	_, err := proof.VerifyProofSuffix(
		ctx, vOut.ProofSuffix, inputProofFiles, verifier, vCtx,
	)
	if err != nil {
		return fmt.Errorf("output proof verification "+
			"failed (vpkt_idx=%d, "+
			"output_idx=%d): %w", pktIdx,
			outIdx, err)
	}

	return nil
}

// verifyPacketInputProofs ensures that each virtual packet's inputs reference
// a valid Taproot Asset commitment before the package is broadcast.
func (p *ChainPorter) verifyPacketInputProofs(ctx context.Context,
	vPkt tappsbt.VPacket) error {

	headerVerifier := tapnode.GenHeaderVerifier(ctx, p.cfg.ChainBridge)
	vCtx := proof.VerifierCtx{
		HeaderVerifier: headerVerifier,
		MerkleVerifier: proof.DefaultMerkleVerifier,
		GroupVerifier:  p.cfg.GroupVerifier,
		ChainLookupGen: p.cfg.ChainBridge,
		IgnoreChecker:  p.cfg.IgnoreChecker,
	}

	for inputIdx := range vPkt.Inputs {
		assetProof := vPkt.Inputs[inputIdx].Proof
		if assetProof == nil {
			return fmt.Errorf("packet input proof is nil "+
				"(input_idx=%d)", inputIdx)
		}

		_, err := assetProof.VerifyProofIntegrity(ctx, vCtx)
		if err != nil {
			return fmt.Errorf("unable to verify "+
				"inclusion proof for packet input "+
				"(input_idx=%d): %w", inputIdx, err)
		}
	}

	return nil
}

// verifySplitCommitmentWitnesses ensures split leaf outputs embed a split root
// that actually carries a witness. Split leaves intentionally keep their own
// TxWitness empty and rely on the embedded root witness for validation.
func verifySplitCommitmentWitnesses(vPkt tappsbt.VPacket) error {
	for outIdx := range vPkt.Outputs {
		vOut := vPkt.Outputs[outIdx]

		if vOut.Asset == nil ||
			!vOut.Asset.HasSplitCommitmentWitness() {

			continue
		}

		splitCommitment := vOut.Asset.PrevWitnesses[0].SplitCommitment
		if splitCommitment == nil {
			return fmt.Errorf("output missing split commitment "+
				"(output_idx=%d)", outIdx)
		}

		root := &splitCommitment.RootAsset
		if len(root.PrevWitnesses) == 0 {
			return fmt.Errorf("output split root has no prev "+
				"witnesses (output_idx=%d)", outIdx)
		}

		hasWitness := fn.Any(
			root.PrevWitnesses, func(wit asset.Witness) bool {
				return len(wit.TxWitness) > 0
			},
		)
		if !hasWitness {
			return fmt.Errorf("output split root witness empty "+
				"(output_idx=%d)", outIdx)
		}
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
		wallet := p.cfg.AssetWallet
		fundSendRes, err := wallet.FundAddressSend(
			ctx, fn.Some(asset.ScriptKeyBip86), nil,
			addrParcel.destAddrs...,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to fund address send: "+
				"%w", err)
		}

		currentPkg.VirtualPackets = fundSendRes.VPackets
		currentPkg.InputCommitments = fundSendRes.InputCommitments
		currentPkg.ZeroValueInputs = fundSendRes.ZeroValueInputs

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

			_, err := p.cfg.AssetWallet.SignVirtualPacket(ctx, vPkt)
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

		err = wallet.SignPassiveAssets(ctx, currentPkg.PassiveAssets)
		if err != nil {
			p.unlockInputs(ctx, &currentPkg)

			return nil, fmt.Errorf("unable to sign passive "+
				"assets: %w", err)
		}

		anchorTx, err := wallet.AnchorVirtualTransactions(
			ctx, &AnchorVTxnsParams{
				FeeRate:         feeRate,
				ActivePackets:   currentPkg.VirtualPackets,
				PassivePackets:  currentPkg.PassiveAssets,
				ZeroValueInputs: currentPkg.ZeroValueInputs,
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

		currentPkg.SendState = SendStateVerifyPreBroadcast
		return &currentPkg, nil

	// Run final pre-broadcast checks on the package.
	case SendStateVerifyPreBroadcast:
		ctx, cancel := p.WithCtxQuitNoTimeout()
		defer cancel()

		totalVPacketsCount :=
			len(currentPkg.VirtualPackets) +
				len(currentPkg.PassiveAssets)
		allPackets := make([]*tappsbt.VPacket, 0, totalVPacketsCount)
		allPackets = append(allPackets, currentPkg.VirtualPackets...)
		allPackets = append(allPackets, currentPkg.PassiveAssets...)

		err := p.verifyVPacketsPreBroadcast(ctx, allPackets)
		if err != nil {
			p.unlockInputs(ctx, &currentPkg)

			return nil, fmt.Errorf("verifying vPackets: %w", err)
		}

		currentPkg.SendState = SendStateStorePreBroadcast
		return &currentPkg, nil

	// In this state, the parcel state is stored before the fully signed
	// transaction is broadcast to the mempool.
	case SendStateStorePreBroadcast:
		// We won't broadcast in this state, but in preparation for
		// broadcasting, we will find out the current height to use as
		// a height hint. If the parcel provides its own height hint,
		// we'll use that instead.
		ctx, cancel := p.WithCtxQuit()
		defer cancel()

		parcelHint := currentPkg.Parcel.HeightHint()
		parcelHint.WhenSome(func(h uint32) {
			log.Debugf("Using parcel-provided height hint: %d", h)
		})
		heightHint, err := parcelHint.UnwrapOrFuncErr(
			func() (uint32, error) {
				return p.cfg.ChainBridge.CurrentHeight(ctx)
			},
		)
		if err != nil {
			p.unlockInputs(ctx, &currentPkg)

			return nil, fmt.Errorf("unable to get current "+
				"height: %w", err)
		}

		// We now need to find out if this is a transfer to ourselves
		// (e.g. a change output) or an outbound transfer. A key being
		// local means the lnd node connected to this daemon knows how
		// to derive the key.
		isLocalKey := func(key asset.ScriptKey) (bool, error) {
			// To make sure we have the correct internal key with
			// the family and index set, we attempt to fetch it
			// from the database. If it exists, then we know we
			// stored it with the correct information.
			dbKey, err := p.cfg.AssetWallet.FetchScriptKey(
				ctx, key.PubKey,
			)
			switch {
			// If this isn't an output that goes to us, we won't
			// find it, which is okay. Only for other database
			// errors do we return the error.
			case err != nil &&
				!errors.Is(err, address.ErrScriptKeyNotFound):

				return false, fmt.Errorf("error fetching "+
					"script key: %w", err)

			// We did find the key, so we can check if it's a local
			// key with the key ring.
			case err == nil:
				return p.cfg.KeyRing.IsLocalKey(
					ctx, dbKey.RawKey,
				), nil
			}

			// As a fallback, in case only the internal key was
			// declared, we can check if the key is local by
			// using the info we have, with a potential for a false
			// negative if the key family and index isn't set at
			// this point. But if it isn't set, then we didn't
			// import/declare the key before, so it's very likely
			// not ours anyway.
			return key.TweakedScriptKey != nil &&
				p.cfg.KeyRing.IsLocalKey(ctx, key.RawKey), nil
		}

		// We need to prepare the parcel for storage.
		parcel, err := ConvertToTransfer(
			heightHint, currentPkg.VirtualPackets,
			currentPkg.AnchorTx, currentPkg.PassiveAssets,
			currentPkg.ZeroValueInputs, isLocalKey,
			currentPkg.Label, currentPkg.SkipAnchorTxBroadcast,
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
		// This will also extend the leases for both asset inputs and
		// zero-value UTXOs to prevent them from being used elsewhere.
		//
		// The same write commits atomically with the transfer's
		// registration as a speculative anchoring: there is no
		// instant at which the stake exists without the watcher
		// knowing it.
		var anchoringID tapreorg.AnchoringID
		anchoringID, err = p.registerParcelAnchoring(ctx, &currentPkg)
		if err == nil {
			currentPkg.AnchoringID = anchoringID
		}
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

		// If the skip flag is set, another system (the lnd sweeper
		// for force-close sweeps, the channel arbitrator or peer flow
		// for commitment and cooperative close transactions, or an
		// external packager) owns broadcast and rebroadcast of this
		// transaction. We only record and watch it.
		if currentPkg.OutboundPkg.SkipAnchorTxBroadcast {
			log.Infof("Skip anchor broadcast flag set; not "+
				"publishing txid=%v, transitioning to "+
				"WaitTxConf state",
				currentPkg.OutboundPkg.AnchorTx.TxHash())
			currentPkg.SendState = SendStateWaitTxConf

			return &currentPkg, nil
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

		// Set send state to the next state to evaluate.
		currentPkg.SendState = SendStateWaitTxConf
		return &currentPkg, nil

	// At this point, transaction broadcast is complete. We go on to wait
	// for the transfer transaction to confirm on-chain.
	case SendStateWaitTxConf:
		// The state machine now transitions to waiting for the transfer
		// transaction to be confirmed on-chain. Before entering this
		// state, we return the outbound package response to unblock the
		// caller's send request.
		currentPkg.deliverOutboundPkgResp()

		// The re-org watcher is the sole sensor: we wait for the
		// registry's delivered phase rather than subscribing to
		// confirmations ourselves.
		ctx, cancel := p.WithCtxQuitNoTimeout()
		defer cancel()

		outcome, err := p.waitForAnchoringOutcome(ctx, &currentPkg)
		if err != nil {
			return nil, err
		}
		if outcome.abandoned {
			return nil, fmt.Errorf("transfer %v abandoned: its "+
				"anchor inputs were claimed by a buried "+
				"conflicting transaction",
				currentPkg.OutboundPkg.AnchorTx.TxHash())
		}

		currentPkg.ConfWitness = outcome.witness

		// Send-event subscribers read the anchor block context off
		// the outbound package.
		currentPkg.OutboundPkg.AnchorTxBlockHash = fn.Some(
			outcome.witness.W.BlockHash(),
		)
		currentPkg.OutboundPkg.AnchorTxBlockHeight =
			outcome.witness.W.Height()

		currentPkg.SendState = SendStateStorePostAnchorTxConf

		return &currentPkg, nil

	// The transfer transaction is now confirmed on-chain. We'll update the
	// package state on disk to reflect this. This step frees up the change
	// outputs so that they can be used in future transactions.
	case SendStateStorePostAnchorTxConf:
		// Before we store the proofs, we need to create the send
		// fragment manifests for any address v2 sends.
		manifests, err := createSendManifests(
			&p.cfg.ChainParams, currentPkg.OutboundPkg,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to create send "+
				"fragments: %w", err)
		}

		log.Infof("Created %d send fragment manifests for transfer",
			len(manifests))
		currentPkg.SendManifests = manifests

		// The watcher's delivery already applied the confirmation to
		// the database (atomically with the registry advance); what
		// remains here is mirroring the final proof files into the
		// archive for couriers and archive readers. Burn
		// supply-commit events are act-gated and dispatched from the
		// site's Buried handler via the outbox — never here.
		ctx, cancel := p.CtxBlocking()
		defer cancel()

		err = enrichSendManifests(&currentPkg, currentPkg.ConfWitness)
		if err != nil {
			return nil, fmt.Errorf("unable to enrich send "+
				"manifests: %w", err)
		}

		err = p.importConfirmedProofFiles(
			ctx, &currentPkg, currentPkg.ConfWitness,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to import proof "+
				"files: %w", err)
		}

		currentPkg.SendState = SendStateTransferProofs

		return &currentPkg, nil

	// At this point, the transfer transaction is confirmed on-chain, and
	// we've stored the sender and receiver proofs in the proof archive.
	// We'll now attempt to transfer one or more proofs to the receiver(s).
	case SendStateTransferProofs:
		err := p.transferReceiverProof(&currentPkg)
		if err != nil {
			return nil, fmt.Errorf("unable to transfer receiver "+
				"proof: %w", err)
		}

		currentPkg.SendState = SendStateComplete
		return &currentPkg, nil

	case SendStateComplete:
		// At this point, the transfer is fully finalised and
		// successful:
		// - The anchoring transaction has been confirmed on-chain.
		// - The proof(s) have been delivered to the receiver(s).
		// - The database has been updated to reflect the successful
		//   transfer.
		log.Infof("Parcel transfer is fully complete (anchor_txid=%v)",
			currentPkg.OutboundPkg.AnchorTx.TxHash())

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
	// Also unlock any zero-value UTXOs that were leased for this package.
	if pkg.SendState < SendStateStorePreBroadcast {
		// Gather all outpoints to unlock in a single array.
		var outpoints []wire.OutPoint

		// Add input commitment outpoints
		for prevID := range pkg.InputCommitments {
			log.Debugf("Unlocking input %v", prevID.OutPoint)
			outpoints = append(outpoints, prevID.OutPoint)
		}

		// Add zero-value inputs.
		zeroValueOutpoints := fn.Map(
			pkg.ZeroValueInputs,
			func(z *ZeroValueInput) wire.OutPoint {
				return z.OutPoint
			},
		)
		outpoints = append(outpoints, zeroValueOutpoints...)

		// Release all coins in a single call.
		if len(outpoints) > 0 {
			err := p.cfg.AssetWallet.ReleaseCoins(
				ctx, outpoints...,
			)
			if err != nil {
				log.Warnf("Unable to unlock inputs: %v", err)
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

	// NextSendState is the next state that will be executed.
	NextSendState SendState

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
		timestamp:     time.Now().UTC(),
		SendState:     executedState,
		NextSendState: pkg.SendState,
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
		NextSendState:  pkg.SendState,
		Error:          err,
		Parcel:         pkg.Parcel,
		TransferLabel:  pkg.Label,
		VirtualPackets: pkg.VirtualPackets,
		PassivePackets: pkg.PassiveAssets,
		AnchorTx:       pkg.AnchorTx,
		Transfer:       pkg.OutboundPkg,
	}
}

// NewHistoricalAssetSendEvent creates an AssetSendEvent from a completed
// transfer parcel for historical event replay. This is used when replaying
// events from the database.
func NewHistoricalAssetSendEvent(parcel *OutboundParcel,
	timestamp time.Time) *AssetSendEvent {

	return &AssetSendEvent{
		timestamp:     timestamp,
		SendState:     SendStateComplete,
		NextSendState: SendStateComplete,
		Error:         nil,
		// We don't have the original Parcel for historical events.
		Parcel:        nil,
		TransferLabel: parcel.Label,
		Transfer:      parcel,
		// For historical events, we don't have access to the virtual
		// packets, so these will be empty. This is a limitation of
		// historical replay.
		VirtualPackets: nil,
		PassivePackets: nil,
		AnchorTx: &tapsend.AnchorTransaction{
			FinalTx:   parcel.AnchorTx,
			ChainFees: parcel.ChainFees,
		},
	}
}
