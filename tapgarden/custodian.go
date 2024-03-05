package tapgarden

import (
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

// AssetReceiveCompleteEvent is an event that is sent to a subscriber once the
// asset receive process has finished for a given address and outpoint.
type AssetReceiveCompleteEvent struct {
	// timestamp is the time the event was created.
	timestamp time.Time

	// Address is the address associated with the asset that was received.
	Address address.Tap

	// OutPoint is the outpoint of the transaction that was used to receive
	// the asset.
	OutPoint wire.OutPoint
}

// Timestamp returns the timestamp of the event.
func (e *AssetReceiveCompleteEvent) Timestamp() time.Time {
	return e.timestamp
}

// NewAssetRecvCompleteEvent creates a new AssetReceiveCompleteEvent.
func NewAssetRecvCompleteEvent(addr address.Tap,
	outpoint wire.OutPoint) *AssetReceiveCompleteEvent {

	return &AssetReceiveCompleteEvent{
		timestamp: time.Now().UTC(),
		Address:   addr,
		OutPoint:  outpoint,
	}
}

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

	// GroupVerifier is used to verify the validity of the group key for an
	// asset.
	GroupVerifier proof.GroupVerifier

	// AddrBook is the storage backend for addresses.
	AddrBook *address.Book

	// ProofArchive is the storage backend for proofs to which we store new
	// incoming proofs.
	ProofArchive proof.Archiver

	// ProofNotifier is the storage backend for proofs from which we are
	// notified about new proofs. This can be the same as the ProofArchive
	// above but can also be different (for example if we should _store_ the
	// proofs to a multi archiver but only be notified about new proofs
	// being available in the relational database).
	ProofNotifier proof.NotifyArchiver

	// ProofCourierDispatcher is the dispatcher that is used to create new
	// proof courier handles for receiving proofs based on the protocol of
	// a proof courier address.
	ProofCourierDispatcher proof.CourierDispatch

	// ProofRetrievalDelay is the time duration the custodian waits having
	// identified an asset transfer on-chain and before retrieving the
	// corresponding proof via the proof courier service.
	ProofRetrievalDelay time.Duration

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

	// statusEventsSubs is a map of subscribers that want to be notified on
	// new status events, keyed by their subscription ID.
	statusEventsSubs map[uint64]*fn.EventReceiver[fn.Event]

	// statusEventsSubsMtx guards the general status events subscribers map.
	statusEventsSubsMtx sync.Mutex

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
	statusEventsSubs := make(map[uint64]*fn.EventReceiver[fn.Event])
	return &Custodian{
		cfg:               cfg,
		addrSubscription:  addrSub,
		proofSubscription: proofSub,
		statusEventsSubs:  statusEventsSubs,
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

		// Remove all status event subscribers.
		for _, sub := range c.statusEventsSubs {
			err := c.RemoveSubscriber(sub)
			if err != nil {
				stopErr = err
				break
			}
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
		available, err := c.checkProofAvailable(event)
		if err != nil {
			reportErr(err)
			return
		}

		// If we did find a proof, we did import it now and can remove
		// the event from our cache.
		if available {
			delete(c.events, event.Outpoint)

			continue
		}

		// If this event is not yet confirmed, we don't yet expect a
		// proof to be delivered. We'll wait for the confirmation to
		// come in, and then we'll launch a goroutine to use the
		// ProofCourier to import the proof into our local DB.
		if event.ConfirmationHeight == 0 {
			continue
		}

		// If we didn't find a proof, we'll launch a goroutine to use
		// the ProofCourier to import the proof into our local DB.
		c.Wg.Add(1)
		go func() {
			defer c.Wg.Done()

			recErr := c.receiveProof(event.Addr.Tap, event.Outpoint)
			if recErr != nil {
				reportErr(recErr)
			}
		}()
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

				// Now that we've seen this output confirm on
				// chain, we'll launch a goroutine to use the
				// ProofCourier to import the proof into our
				// local DB.
				c.Wg.Add(1)
				go func() {
					defer c.Wg.Done()

					recErr := c.receiveProof(
						event.Addr.Tap, op,
					)
					if recErr != nil {
						log.Errorf("Unable to receive "+
							"proof: %v", recErr)
					}
				}()
			}

			continue
		}

		// This is a new output, let's find out if it's for an address
		// of ours. This step also creates a new event for the address
		// if it doesn't exist yet.
		addr, err := c.mapToTapAddr(walletTx, uint32(idx), op)
		if err != nil {
			return err
		}

		// We are not interested in the outpoint if we don't know of a
		// pre-stored address associated with it.
		if addr == nil {
			continue
		}

		// We now need to wait for a confirmation, since proofs will
		// be delivered once the anchor transaction is confirmed. If
		// we skip it now, we'll receive another notification once the
		// transaction is confirmed.
		if walletTx.Confirmations == 0 {
			continue
		}

		// Now that we've seen this output confirm on chain, we'll
		// launch a goroutine to use the ProofCourier to import the
		// proof into our local DB.
		c.Wg.Add(1)
		go func() {
			defer c.Wg.Done()

			recErr := c.receiveProof(addr, op)
			if recErr != nil {
				log.Errorf("Unable to receive proof: %v",
					recErr)
			}
		}()
	}

	return nil
}

// receiveProof attempts to receive a proof for the given address and outpoint
// via the proof courier service.
func (c *Custodian) receiveProof(addr *address.Tap, op wire.OutPoint) error {
	ctx, cancel := c.WithCtxQuitNoTimeout()
	defer cancel()

	assetID := addr.AssetID

	scriptKeyBytes := addr.ScriptKey.SerializeCompressed()
	log.Debugf("Waiting to receive proof for script key %x", scriptKeyBytes)

	// Initiate proof courier service handle from the proof courier address
	// found in the Tap address.
	recipient := proof.Recipient{
		ScriptKey: &addr.ScriptKey,
		AssetID:   assetID,
		Amount:    addr.Amount,
	}
	courier, err := c.cfg.ProofCourierDispatcher.NewCourier(
		&addr.ProofCourierAddr, recipient,
	)
	if err != nil {
		return fmt.Errorf("unable to initiate proof courier service "+
			"handle: %w", err)
	}

	// Update courier handle events subscribers before attempting to
	// retrieve proof.
	c.statusEventsSubsMtx.Lock()
	courier.SetSubscribers(c.statusEventsSubs)
	c.statusEventsSubsMtx.Unlock()

	// Sleep to give the sender an opportunity to transfer the proof to the
	// proof courier service. Without this delay our first attempt at
	// retrieving the proof will very likely fail. We should expect
	// retrieval success before this delay.
	select {
	case <-time.After(c.cfg.ProofRetrievalDelay):
	case <-ctx.Done():
		return nil
	}

	// Attempt to receive proof via proof courier service.
	loc := proof.Locator{
		AssetID:   &assetID,
		GroupKey:  addr.GroupKey,
		ScriptKey: addr.ScriptKey,
		OutPoint:  &op,
	}
	addrProof, err := courier.ReceiveProof(ctx, loc)
	if err != nil {
		return fmt.Errorf("unable to receive proof using courier: %w",
			err)
	}

	log.Debugf("Received proof for: script_key=%x, asset_id=%x",
		scriptKeyBytes, assetID[:])

	ctx, cancel = c.CtxBlocking()
	defer cancel()

	headerVerifier := GenHeaderVerifier(ctx, c.cfg.ChainBridge)
	err = c.cfg.ProofArchive.ImportProofs(
		ctx, headerVerifier, proof.DefaultMerkleVerifier,
		c.cfg.GroupVerifier, false, addrProof,
	)
	if err != nil {
		return fmt.Errorf("unable to import proofs script_key=%x, "+
			"asset_id=%x: %w", scriptKeyBytes, assetID[:], err)
	}

	// The proof is now verified and in our local archive. We will now
	// finalize handling the proof like we would with any other newly
	// received proof.
	c.proofSubscription.NewItemCreated.ChanIn() <- addrProof.Blob

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
		return nil, fmt.Errorf("unable to encode address: %w", err)
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

	default:
		return err
	}

	log.Infof("Imported Taproot Asset address %v into wallet", addrStr)
	if p2trAddr != nil {
		log.Infof("Watching p2tr address %v on chain", p2trAddr)
	}

	return c.cfg.AddrBook.SetAddrManaged(ctxt, addr, time.Now())
}

// checkProofAvailable checks the proof storage if a proof for the given event
// is already available. If it is, and it checks out, the event is updated.
func (c *Custodian) checkProofAvailable(event *address.Event) (bool, error) {
	ctxt, cancel := c.WithCtxQuit()
	defer cancel()

	// We check if the local proof is already available. We check the same
	// source that would notify us and not the proof archive (which might
	// be a multi archiver that includes file based storage) to make sure
	// the proof is available in the relational database. If the proof is
	// not in the DB, we can't update the event.
	locator := proof.Locator{
		AssetID:   fn.Ptr(event.Addr.AssetID),
		GroupKey:  event.Addr.GroupKey,
		ScriptKey: event.Addr.ScriptKey,
		OutPoint:  &event.Outpoint,
	}
	blob, err := c.cfg.ProofNotifier.FetchProof(ctxt, locator)
	switch {
	case errors.Is(err, proof.ErrProofNotFound):
		return false, nil

	case err != nil:
		return false, fmt.Errorf("error fetching proof for event: %w",
			err)
	}

	// At this point, we expect the proof to be a full file, containing the
	// whole provenance chain (as required by implementers of the
	// proof.NotifyArchiver.FetchProof() method). So if we don't we can't
	// continue.
	if !blob.IsFile() {
		return false, fmt.Errorf("expected proof to be a full file, " +
			"but got something else")
	}

	// In case we missed a notification from the local universe and didn't
	// previously import the proof (for example because we were shutting
	// down), we could be in a situation where the local database doesn't
	// have the proof yet. So we make sure to import it now.
	err = c.assertProofInLocalArchive(&proof.AnnotatedProof{
		Locator: locator,
		Blob:    blob,
	})
	if err != nil {
		return false, fmt.Errorf("error asserting proof in local "+
			"archive: %w", err)
	}

	file, err := blob.AsFile()
	if err != nil {
		return false, fmt.Errorf("error extracting proof file: %w", err)
	}

	// Exit early on empty proof (shouldn't happen outside of test cases).
	if file.IsEmpty() {
		return false, fmt.Errorf("archive contained empty proof file")
	}

	lastProof, err := file.LastProof()
	if err != nil {
		return false, fmt.Errorf("error fetching last proof: %w", err)
	}

	// The proof might be an old state, let's make sure it matches our event
	// before marking the inbound asset transfer as complete.
	if AddrMatchesAsset(event.Addr, &lastProof.Asset) {
		return true, c.setReceiveCompleted(event, lastProof, file)
	}

	return false, nil
}

// mapProofToEvent inspects a new proof and attempts to match it to an existing
// and pending address event. If a proof successfully matches the desired state
// of the address, that completes the inbound transfer of an asset.
func (c *Custodian) mapProofToEvent(p proof.Blob) error {
	// We arrive here if we are notified about a new proof. The notification
	// interface allows that proof to be a single transition proof. So if
	// we don't have a full file yet, we need to fetch it now. The
	// proof.NotifyArchiver.FetchProof() method will return the full file as
	// per its Godoc.
	var (
		proofBlob = p
		lastProof *proof.Proof
		err       error
	)
	if !p.IsFile() {
		log.Debugf("Received single proof, inspecting if matches event")
		lastProof, err = p.AsSingleProof()
		if err != nil {
			return fmt.Errorf("error decoding proof: %w", err)
		}

		// Before we go ahead and fetch the full file, let's make sure
		// we are actually interested in this proof. We need to do this
		// because we receive all transfer proofs inserted into the
		// local universe here. So they could just be from a proof sync
		// run and not actually be for an address we are interested in.
		haveMatchingEvents := fn.AnyMapItem(
			c.events, func(e *address.Event) bool {
				return EventMatchesProof(e, lastProof)
			},
		)
		if !haveMatchingEvents {
			log.Debugf("Proof doesn't match any events, skipping.")
			return nil
		}

		ctxt, cancel := c.WithCtxQuit()
		defer cancel()

		loc := proof.Locator{
			AssetID:   fn.Ptr(lastProof.Asset.ID()),
			ScriptKey: *lastProof.Asset.ScriptKey.PubKey,
			OutPoint:  fn.Ptr(lastProof.OutPoint()),
		}
		if lastProof.Asset.GroupKey != nil {
			loc.GroupKey = &lastProof.Asset.GroupKey.GroupPubKey
		}

		log.Debugf("Received single proof, fetching full file")
		proofBlob, err = c.cfg.ProofNotifier.FetchProof(ctxt, loc)
		if err != nil {
			return fmt.Errorf("error fetching full proof file for "+
				"event: %w", err)
		}

		// Do we already have this proof in our main archive? This
		// should only be false if we got the notification from our
		// local universe instead of the local proof archive (which the
		// couriers use). This is mainly an optimization to make sure we
		// don't unnecessarily overwrite the proofs in our main archive.
		err := c.assertProofInLocalArchive(&proof.AnnotatedProof{
			Locator: loc,
			Blob:    proofBlob,
		})
		if err != nil {
			return fmt.Errorf("error asserting proof in local "+
				"archive: %w", err)
		}
	}

	// Now we can be sure we have a file.
	file, err := proofBlob.AsFile()
	if err != nil {
		return fmt.Errorf("error extracting proof file: %w", err)
	}

	// Exit early on empty proof (shouldn't happen outside of test cases).
	if file.IsEmpty() {
		log.Warnf("Received empty proof file!")
		return nil
	}

	// We got the proof from the multi archiver, which verifies it before
	// giving it to us. So we don't have to verify them again and can
	// directly look at the last state. We can skip extracting the last
	// proof if we started out with a single proof in the first place, which
	// we already parsed above.
	if lastProof == nil {
		lastProof, err = file.LastProof()
		if err != nil {
			return fmt.Errorf("error fetching last proof: %w", err)
		}
	}
	log.Infof("Received new proof file for asset ID %s, version=%d,"+
		"num_proofs=%d", lastProof.Asset.ID().String(), file.Version,
		file.NumProofs())

	// Check if any of our in-flight events match the last proof's state.
	for _, event := range c.events {
		if EventMatchesProof(event, lastProof) {
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

// assertProofInLocalArchive checks if the proof is already in the local proof
// archive. If it isn't, it is imported now.
func (c *Custodian) assertProofInLocalArchive(p *proof.AnnotatedProof) error {
	ctxt, cancel := c.WithCtxQuit()
	defer cancel()

	haveProof, err := c.cfg.ProofArchive.HasProof(ctxt, p.Locator)
	if err != nil {
		return fmt.Errorf("error checking if proof is available: %w",
			err)
	}

	// We don't have the proof yet, or not in all backends, so we
	// need to import it now.
	if !haveProof {
		headerVerifier := GenHeaderVerifier(ctxt, c.cfg.ChainBridge)
		err = c.cfg.ProofArchive.ImportProofs(
			ctxt, headerVerifier, proof.DefaultMerkleVerifier,
			c.cfg.GroupVerifier, false, p,
		)
		if err != nil {
			return fmt.Errorf("error importing proof file into "+
				"main archive: %w", err)
		}
	}

	return nil
}

// setReceiveCompleted updates the address event in the database to mark it as
// completed successfully and to link it to the proof we received.
func (c *Custodian) setReceiveCompleted(event *address.Event,
	lastProof *proof.Proof, proofFile *proof.File) error {

	// At this point the "receive" process is complete. We will now notify
	// all status event subscribers.
	receiveCompleteEvent := NewAssetRecvCompleteEvent(
		*event.Addr.Tap, event.Outpoint,
	)
	err := c.publishSubscriberStatusEvent(receiveCompleteEvent)
	if err != nil {
		log.Errorf("Unable publish status event: %v", err)
	}

	// The proof is created after a single confirmation. To make sure we
	// notice if the anchor transaction is re-organized out of the chain, we
	// give all the not-yet-sufficiently-buried proofs in the received proof
	// file to the re-org watcher and replace the updated proof in the local
	// proof archive if a re-org happens. The sender will do the same, so no
	// re-send of the proof is necessary.
	err = c.cfg.ProofWatcher.MaybeWatch(
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

// RegisterSubscriber adds a new subscriber to the set of subscribers that will
// be notified of any new status update events.
//
// TODO(ffranr): Add support for delivering existing events to new subscribers.
func (c *Custodian) RegisterSubscriber(receiver *fn.EventReceiver[fn.Event],
	deliverExisting bool, deliverFrom bool) error {

	c.statusEventsSubsMtx.Lock()
	defer c.statusEventsSubsMtx.Unlock()

	c.statusEventsSubs[receiver.ID()] = receiver

	return nil
}

// publishSubscriberStatusEvent publishes an event to all status events
// subscribers.
func (c *Custodian) publishSubscriberStatusEvent(event fn.Event) error {
	// Lock the subscriber mutex to ensure that we don't modify the
	// subscriber map while we're iterating over it.
	c.statusEventsSubsMtx.Lock()
	defer c.statusEventsSubsMtx.Unlock()

	for _, sub := range c.statusEventsSubs {
		if !fn.SendOrQuit(sub.NewItemCreated.ChanIn(), event, c.Quit) {
			return fmt.Errorf("custodian shutting down")
		}
	}

	return nil
}

// RemoveSubscriber removes a subscriber from the set of status event
// subscribers.
func (c *Custodian) RemoveSubscriber(
	subscriber *fn.EventReceiver[fn.Event]) error {

	c.statusEventsSubsMtx.Lock()
	defer c.statusEventsSubsMtx.Unlock()

	_, ok := c.statusEventsSubs[subscriber.ID()]
	if !ok {
		return fmt.Errorf("status event subscriber with ID %d not "+
			"found", subscriber.ID())
	}

	subscriber.Stop()
	delete(c.statusEventsSubs, subscriber.ID())

	return nil
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

// EventMatchesProof returns true if the given event matches the given proof.
func EventMatchesProof(event *address.Event, p *proof.Proof) bool {
	return AddrMatchesAsset(event.Addr, &p.Asset) &&
		event.Outpoint == p.OutPoint()
}
