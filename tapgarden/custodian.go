package tapgarden

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/lnrpc"
)

// CustodianConfig houses all the items that the Custodian needs to carry out
// its duties.
type CustodianConfig struct {
	// ChainParams are the Taproot Asset specific chain parameters.
	ChainParams *address.ChainParams

	// WalletAnchor is the main interface for interacting with the on-chain
	// wallet.
	WalletAnchor WalletAnchor

	// ChainBridge is the main interface for interacting with the chain
	// backend.
	ChainBridge ChainBridge

	// AddrBook is the storage backend for addresses.
	AddrBook *address.Book

	// ProofArchive is the storage backend for proofs to which we store new
	// incoming proofs.
	ProofArchive proof.NotifyArchiver

	// ProofNotifier is the storage backend for proofs from which we are
	// notified about new proofs. This can be the same as the ProofArchive
	// above but can also be different (for example if we should _store_ the
	// proofs to a multi archiver but only be notified about new proofs
	// being available in the relational database).
	ProofNotifier proof.NotifyArchiver

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

// Custodian is responsible for taking custody of an asset that is transferred
// to us on-chain. It watches the chain for incoming transfers defined by
// Taproot Asset addresses and then takes full custody of the transferred assets
// by collecting and validating their provenance proofs.
type Custodian struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *CustodianConfig

	// addrSubscription is the subscription queue through which we receive
	// events about new addresses being created (and we also receive all
	// previously existing addresses on startup).
	addrSubscription *fn.EventReceiver[*address.AddrWithKeyInfo]

	// proofSubscription is the subscription queue through which we receive
	// events about new proofs being imported.
	proofSubscription *fn.EventReceiver[proof.Blob]

	// events is a map of all transaction outpoints and their ongoing
	// address events of inbound assets.
	events map[wire.OutPoint]*address.Event

	// ContextGuard provides a wait group and main quit channel that can be
	// used to create guarded contexts.
	*fn.ContextGuard
}

// NewCustodian creates a new Taproot Asset custodian based on the passed
// config.
func NewCustodian(cfg *CustodianConfig) *Custodian {
	addrSub := fn.NewEventReceiver[*address.AddrWithKeyInfo](
		fn.DefaultQueueSize,
	)
	proofSub := fn.NewEventReceiver[proof.Blob](fn.DefaultQueueSize)
	return &Custodian{
		cfg:               cfg,
		addrSubscription:  addrSub,
		proofSubscription: proofSub,
		events:            make(map[wire.OutPoint]*address.Event),
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// Start attempts to start a new custodian.
func (c *Custodian) Start() error {
	var startErr error
	c.startOnce.Do(func() {
		log.Info("Starting asset custodian")

		// Start the main event handler loop that will process new
		// addresses being added and new incoming on-chain transactions.
		c.Wg.Add(1)
		go c.watchInboundAssets()

		// We instruct the address book to also deliver all existing
		// addresses that haven't been added to the internal wallet for
		// tracking on chain yet.
		err := c.cfg.AddrBook.RegisterSubscriber(
			c.addrSubscription, true, address.QueryParams{
				UnmanagedOnly: true,
			},
		)
		if err != nil {
			startErr = err
			return
		}

		// We want all new proofs to be delivered to us for inspection.
		err = c.cfg.ProofNotifier.RegisterSubscriber(
			c.proofSubscription, false, nil,
		)
		if err != nil {
			startErr = err
			return
		}
	})
	return startErr
}

// Stop signals for a custodian to gracefully exit.
func (c *Custodian) Stop() error {
	var stopErr error
	c.stopOnce.Do(func() {
		close(c.Quit)
		c.Wg.Wait()

		err := c.cfg.AddrBook.RemoveSubscriber(c.addrSubscription)
		if err != nil {
			stopErr = err
		}

		err = c.cfg.ProofNotifier.RemoveSubscriber(c.proofSubscription)
		if err != nil {
			stopErr = err
		}
	})

	return stopErr
}

// watchInboundAssets processes new Taproot Asset addresses being created and
// new transactions being received and attempts to match the two things into
// inbound asset events.
func (c *Custodian) watchInboundAssets() {
	defer c.Wg.Done()

	reportErr := func(err error) {
		select {
		case c.cfg.ErrChan <- err:
		case <-c.Quit:
		}
	}

	// We first start the transaction subscription, so we don't miss any new
	// transactions that come in while we still process the existing ones.
	log.Debugf("Subscribing to new on-chain transactions")
	ctxStream, cancel := c.WithCtxQuitNoTimeout()
	defer cancel()
	newTxChan, txErrChan, err := c.cfg.WalletAnchor.SubscribeTransactions(
		ctxStream,
	)
	if err != nil {
		reportErr(err)
		return
	}

	// Fetch all pending events that we wish to process.
	log.Infof("Loading pending inbound asset events")
	ctxt, cancel := c.WithCtxQuit()
	events, err := c.cfg.AddrBook.GetPendingEvents(ctxt)
	cancel()
	if err != nil {
		reportErr(err)
		return
	}

	// From the events we already know, we can now find out the last height
	// we detected an event at.
	log.Infof("Resuming %d pending inbound asset events", len(events))
	var lastDetectHeight uint32
	for idx := range events {
		event := events[idx]
		if event.ConfirmationHeight > lastDetectHeight {
			lastDetectHeight = event.ConfirmationHeight
		}

		c.events[event.Outpoint] = event

		// Maybe a proof was delivered while we were shutting down or
		// starting up, let's check now.
		err = c.checkProofAvailable(event)
		if err != nil {
			reportErr(err)
			return
		}
	}

	// Read all on-chain transactions and make sure they are mapped to an
	// address event in the database.
	log.Infof("Loading wallet transactions starting at block height %d",
		lastDetectHeight)
	ctxt, cancel = c.WithCtxQuit()
	walletTxns, err := c.cfg.WalletAnchor.ListTransactions(
		ctxt, int32(lastDetectHeight), -1,
		waddrmgr.ImportedAddrAccountName,
	)
	cancel()
	if err != nil {
		reportErr(err)
		return
	}

	// Keep a cache of all events that are currently ongoing.
	log.Infof("Checking %d wallet transactions for inbound assets, this "+
		"might take a while", len(walletTxns))
	for idx := range walletTxns {
		err := c.inspectWalletTx(&walletTxns[idx])
		if err != nil {
			reportErr(err)
			return
		}
	}

	log.Infof("Starting main custodian event loop")
	for {
		var err error
		select {
		case newAddr := <-c.addrSubscription.NewItemCreated.ChanOut():
			err = c.importAddrToWallet(newAddr)

		case tx := <-newTxChan:
			err = c.inspectWalletTx(&tx)

		case newProof := <-c.proofSubscription.NewItemCreated.ChanOut():
			log.Tracef("New proof received from notifier")
			err = c.mapProofToEvent(newProof)

		case err = <-txErrChan:
			break

		case <-c.Quit:
			return
		}

		if err != nil {
			// We'll report the error to the main daemon, but only
			// if this isn't a context cancel.
			if fn.IsCanceled(err) {
				return
			}

			log.Errorf("Aborting main custodian event loop: %v",
				err)

			reportErr(err)
			return
		}
	}
}

// inspectWalletTx looks at the outputs of a transaction belonging to the wallet
// and decides whether a new event should be created for it.
func (c *Custodian) inspectWalletTx(walletTx *lndclient.Transaction) error {
	// Skip transactions that don't send to a Taproot address that
	// is recognized by our wallet.
	if !hasWalletTaprootOutput(walletTx) {
		return nil
	}

	// There is at least one Taproot output going to our wallet in that TX,
	// let's now find out which one.
	txHash := walletTx.Tx.TxHash()
	log.Debugf("Inspecting tx %s for Taproot Asset address outputs",
		txHash.String())
	for idx, out := range walletTx.OutputDetails {
		if !isWalletTaprootOutput(out) {
			continue
		}

		// Do we already have an event for this output?
		op := wire.OutPoint{Hash: txHash, Index: uint32(idx)}
		event, ok := c.events[op]
		if ok {
			// Was this event previously unconfirmed, and we have
			// received a conf now? Let's bump the state then.
			if event.ConfirmationHeight == 0 &&
				walletTx.Confirmations > 0 {

				var err error
				ctxt, cancel := c.CtxBlocking()
				event, err = c.cfg.AddrBook.GetOrCreateEvent(
					ctxt,
					address.StatusTransactionConfirmed,
					event.Addr, walletTx, uint32(idx),
				)
				cancel()
				if err != nil {
					return fmt.Errorf("error updating "+
						"event: %w", err)
				}

				c.events[op] = event
			}

			continue
		}

		// This is a new output, let's find out if it's for an address
		// of ours.
		addr, err := c.mapToTapAddr(walletTx, uint32(idx), op)
		if err != nil {
			return err
		}

		// We are not interested in the outpoint if we don't know of a
		// pre-stored address associated with it.
		if addr == nil {
			continue
		}

		// TODO(ffranr): This proof courier disabled check should be
		//  removed. It was implemented because some integration test do
		//  not setup and use a proof courier.
		if c.cfg.ProofCourierCfg == nil {
			continue
		}

		// Now that we've seen this output on chain, we'll launch a
		// goroutine to use the ProofCourier to import the proof into
		// our local DB.
		c.Wg.Add(1)
		go func() {
			defer c.Wg.Done()

			ctx, cancel := c.WithCtxQuitNoTimeout()
			defer cancel()

			assetID := addr.AssetID

			log.Debugf("Waiting to receive proof for script key %x",
				addr.ScriptKey.SerializeCompressed())

			// Initiate proof courier service handle from the proof
			// courier address found in the Tap address.
			recipient := proof.Recipient{
				ScriptKey: &addr.ScriptKey,
				AssetID:   assetID,
				Amount:    addr.Amount,
			}
			courier, err := proof.NewCourier(
				ctx, addr.ProofCourierAddr,
				c.cfg.ProofCourierCfg, recipient,
			)
			if err != nil {
				log.Errorf("unable to initiate proof courier "+
					"service handle: %v", err)
				return
			}

			// Attempt to receive proof via proof courier service.
			loc := proof.Locator{
				AssetID:   &assetID,
				ScriptKey: addr.ScriptKey,
				OutPoint:  &op,
			}
			addrProof, err := courier.ReceiveProof(ctx, loc)
			if err != nil {
				log.Errorf("unable to recv proof: %v", err)
				return
			}

			log.Debugf("Received proof for: script_key=%x, "+
				"asset_id=%x",
				addr.ScriptKey.SerializeCompressed(),
				assetID[:])

			ctx, cancel = c.CtxBlocking()
			defer cancel()

			headerVerifier := GenHeaderVerifier(
				ctx, c.cfg.ChainBridge,
			)
			err = c.cfg.ProofArchive.ImportProofs(
				ctx, headerVerifier, false, addrProof,
			)
			if err != nil {
				log.Errorf("unable to import proofs: %v", err)
				return
			}
		}()
	}

	return nil
}

// mapToTapAddr attempts to match a transaction output to a Taproot Asset
// address. If a matching address is found, an event is created for it. If an
// event already exists, it is updated with the current transaction information.
func (c *Custodian) mapToTapAddr(walletTx *lndclient.Transaction,
	outputIdx uint32, op wire.OutPoint) (*address.Tap, error) {

	taprootKey, err := proof.ExtractTaprootKey(walletTx.Tx, outputIdx)
	if err != nil {
		return nil, fmt.Errorf("error extracting taproot key: %w", err)
	}

	ctxt, cancel := c.WithCtxQuit()
	addr, err := c.cfg.AddrBook.AddrByTaprootOutput(ctxt, taprootKey)
	cancel()
	switch {
	// There is no Taproot Asset address that expects an asset for the given
	// on-chain output. This probably wasn't a Taproot Asset transaction at
	// all then.
	case errors.Is(err, address.ErrNoAddr):
		return nil, nil

	case err != nil:
		return nil, fmt.Errorf("error querying addresses by Taproot "+
			"Asset key: %w", err)
	}

	addrStr, err := addr.EncodeAddress()
	if err != nil {
		return nil, fmt.Errorf("unable to encode address: %v", err)
	}

	// Make sure we have an event registered for the transaction, since it
	// is now clear that it is an incoming asset that is being received with
	// a Taproot Asset address.
	log.Infof("Found inbound asset transfer (asset_id=%x) for Taproot "+
		"Asset address %s in %s", addr.AssetID[:], addrStr, op.String())
	status := address.StatusTransactionDetected
	if walletTx.Confirmations > 0 {
		status = address.StatusTransactionConfirmed
	}

	// Block here, a shutdown can wait on this operation.
	ctxt, cancel = c.CtxBlocking()
	event, err := c.cfg.AddrBook.GetOrCreateEvent(
		ctxt, status, addr, walletTx, outputIdx,
	)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("error creating event: %w", err)
	}

	// Let's update our cache of ongoing events.
	c.events[op] = event

	return addr.Tap, nil
}

// importAddrToWallet imports the given Taproot Asset address into the
// lnd-internal btcwallet instance by tracking the on-chain Taproot output key
// the assets must be sent to in order to be received.
func (c *Custodian) importAddrToWallet(addr *address.AddrWithKeyInfo) error {
	addrStr, err := addr.EncodeAddress()
	if err != nil {
		return fmt.Errorf("unable to encode address: %w", err)
	}

	// Let's not be interrupted by a shutdown.
	ctxt, cancel := c.CtxBlocking()
	defer cancel()

	p2trAddr, err := c.cfg.WalletAnchor.ImportTaprootOutput(
		ctxt, &addr.TaprootOutputKey,
	)
	switch {
	case err == nil:
		log.Warnf("Taproot addr %v was already added to "+
			"wallet before, skipping", p2trAddr.String())

	// On restart, we'll get an error that the output has already
	// been added to the wallet, so we'll catch this now and move
	// along if so.
	case strings.Contains(err.Error(), "already exists"):

	case err != nil:
		return err
	}

	log.Infof("Imported Taproot Asset address %v into wallet, watching "+
		"p2tr address %v on chain", addrStr, p2trAddr.String())

	return c.cfg.AddrBook.SetAddrManaged(ctxt, addr, time.Now())
}

// checkProofAvailable checks the proof storage if a proof for the given event
// is already available. If it is, and it checks out, the event is updated.
func (c *Custodian) checkProofAvailable(event *address.Event) error {
	ctxt, cancel := c.WithCtxQuit()
	defer cancel()

	// We check if the local proof is already available. We check the same
	// source that would notify us and not the proof archive (which might
	// be a multi archiver that includes file based storage) to make sure
	// the proof is available in the relational database. If the proof is
	// not in the DB, we can't update the event.
	blob, err := c.cfg.ProofNotifier.FetchProof(ctxt, proof.Locator{
		AssetID:   fn.Ptr(event.Addr.AssetID),
		GroupKey:  event.Addr.GroupKey,
		ScriptKey: event.Addr.ScriptKey,
	})
	switch {
	case errors.Is(err, proof.ErrProofNotFound):
		return nil

	case err != nil:
		return fmt.Errorf("error fetching proof for event: %w", err)
	}

	file := proof.NewEmptyFile(proof.V0)
	if err := file.Decode(bytes.NewReader(blob)); err != nil {
		return fmt.Errorf("error decoding proof file: %w", err)
	}

	// Exit early on empty proof (shouldn't happen outside of test cases).
	if file.IsEmpty() {
		return fmt.Errorf("archive contained empty proof file: %w", err)
	}

	lastProof, err := file.LastProof()
	if err != nil {
		return fmt.Errorf("error fetching last proof: %w", err)
	}

	// The proof might be an old state, let's make sure it matches our event
	// before marking the inbound asset transfer as complete.
	if AddrMatchesAsset(event.Addr, &lastProof.Asset) {
		return c.setReceiveCompleted(event, lastProof, file)
	}

	return nil
}

// mapProofToEvent inspects a new proof and attempts to match it to an existing
// and pending address event. If a proof successfully matches the desired state
// of the address, that completes the inbound transfer of an asset.
func (c *Custodian) mapProofToEvent(p proof.Blob) error {
	file := proof.NewEmptyFile(proof.V0)
	if err := file.Decode(bytes.NewReader(p)); err != nil {
		return fmt.Errorf("error decoding proof file: %w", err)
	}

	// Exit early on empty proof (shouldn't happen outside of test cases).
	if file.IsEmpty() {
		log.Warnf("Received empty proof file!")
		return nil
	}

	// We got the proof from the multi archiver, which verifies it before
	// giving it to us. So we don't have to verify them again and can
	// directly look at the last state.
	lastProof, err := file.LastProof()
	if err != nil {
		return fmt.Errorf("error fetching last proof: %w", err)
	}
	log.Infof("Received new proof file, version=%d, num_proofs=%d",
		file.Version, file.NumProofs())

	// Check if any of our in-flight events match the last proof's state.
	for _, event := range c.events {
		if AddrMatchesAsset(event.Addr, &lastProof.Asset) &&
			event.Outpoint == lastProof.OutPoint() {

			// Importing a proof already creates the asset in the
			// database. Therefore, all we need to do is update the
			// state of the address event to mark it as completed
			// successfully.
			err = c.setReceiveCompleted(event, lastProof, file)
			if err != nil {
				return fmt.Errorf("error updating event: %w",
					err)
			}

			delete(c.events, event.Outpoint)
		}
	}

	return nil
}

// setReceiveCompleted updates the address event in the database to mark it as
// completed successfully and to link it to the proof we received.
func (c *Custodian) setReceiveCompleted(event *address.Event,
	lastProof *proof.Proof, proofFile *proof.File) error {

	// The proof is created after a single confirmation. To make sure we
	// notice if the anchor transaction is re-organized out of the chain, we
	// give all the not-yet-sufficiently-buried proofs in the received proof
	// file to the re-org watcher and replace the updated proof in the local
	// proof archive if a re-org happens. The sender will do the same, so no
	// re-send of the proof is necessary.
	err := c.cfg.ProofWatcher.MaybeWatch(
		proofFile, c.cfg.ProofWatcher.DefaultUpdateCallback(),
	)
	if err != nil {
		return fmt.Errorf("error watching received proof: %w", err)
	}

	// Let's not be interrupted by a shutdown.
	ctxt, cancel := c.CtxBlocking()
	defer cancel()

	anchorPoint := wire.OutPoint{
		Hash:  lastProof.AnchorTx.TxHash(),
		Index: lastProof.InclusionProof.OutputIndex,
	}

	return c.cfg.AddrBook.CompleteEvent(
		ctxt, event, address.StatusCompleted, anchorPoint,
	)
}

// hasWalletTaprootOutput returns true if one of the outputs of the given
// transaction is recognized by the wallet as belonging to us and is a Taproot
// output.
func hasWalletTaprootOutput(tx *lndclient.Transaction) bool {
	if tx == nil || len(tx.OutputDetails) == 0 {
		return false
	}

	for _, out := range tx.OutputDetails {
		if isWalletTaprootOutput(out) {
			return true
		}
	}

	return false
}

// isWalletTaprootOutput returns true if the given output is recognized by the
// wallet as belonging to us and is a Taproot output.
func isWalletTaprootOutput(out *lnrpc.OutputDetail) bool {
	const p2trType = lnrpc.OutputScriptType_SCRIPT_TYPE_WITNESS_V1_TAPROOT
	return out.IsOurAddress && out.OutputType == p2trType
}

// AddrMatchesAsset returns true if the given asset state (ID, group key,
// script key) matches the state represented in the address.
func AddrMatchesAsset(addr *address.AddrWithKeyInfo, a *asset.Asset) bool {
	groupKeyBothNil := (addr.GroupKey == nil) && (a.GroupKey == nil)
	groupKeyNoneNil := (addr.GroupKey != nil) && (a.GroupKey != nil)

	// If one of the group keys is not nil while the other one is, then we
	// can already exit here as we know things won't match up further.
	if !groupKeyBothNil && !groupKeyNoneNil {
		return false
	}

	groupKeyEqual := groupKeyBothNil ||
		addr.GroupKey.IsEqual(&a.GroupKey.GroupPubKey)

	return addr.AssetID == a.ID() && groupKeyEqual &&
		addr.ScriptKey.IsEqual(a.ScriptKey.PubKey)
}
