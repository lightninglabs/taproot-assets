package backup

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/lnencrypt"
)

const (
	// DefaultDebounce is the default amount of time the Updater waits
	// after the first wallet change notification before it reconciles
	// and rewrites the backup file. A single on-chain confirmation can
	// emit many proof notifications (active outputs, change, passive
	// assets), so coalescing them avoids one rewrite per notification.
	DefaultDebounce = time.Second

	// DefaultRetryInterval is the default amount of time the Updater waits
	// before retrying after a reconcile that failed or could not back up
	// every asset.
	DefaultRetryInterval = 30 * time.Second

	// startupTimeout bounds the key derivation and initial reconcile that
	// happen synchronously in Start.
	startupTimeout = 2 * time.Minute

	// shutdownSyncTimeout bounds the final reconcile that happens in Stop.
	shutdownSyncTimeout = 30 * time.Second
)

var (
	// ErrUpdaterNotActive is returned when a manual sync is requested
	// while the Updater is not running.
	ErrUpdaterNotActive = errors.New("backup updater is not active")
)

// AssetFetcher returns the current set of wallet assets that should be part
// of the backup. Filtering of unconfirmed assets is done by the Updater.
type AssetFetcher func(ctx context.Context) ([]*asset.ChainAsset, error)

// ProofNotifier is the event publisher the Updater subscribes to in order to
// learn about received, transferred and re-anchored assets. Every new or
// replaced asset proof in the local asset store is published on it.
type ProofNotifier = fn.EventPublisher[proof.Blob, []*proof.Locator]

// MintNotifier is the event publisher the Updater subscribes to in order to
// learn about minted assets. Minting stores the proof file before it writes
// the confirmed asset, so the proof notification alone would race the
// database write. Mint events are published after every batch state change,
// including the final one after the database write.
type MintNotifier = fn.EventPublisher[fn.Event, bool]

// UpdaterConfig holds the dependencies of the Updater.
type UpdaterConfig struct {
	// FetchAssets returns the current set of unspent wallet assets.
	FetchAssets AssetFetcher

	// ProofArchive is used to fetch the proof file of each asset.
	ProofArchive proof.Exporter

	// KeyLookup is used to resolve anchor internal key locators.
	KeyLookup KeyLocatorLookup

	// ProofNotifier publishes proof import events that signal wallet
	// state changes.
	ProofNotifier ProofNotifier

	// MintNotifier publishes minting batch state changes. Optional.
	MintNotifier MintNotifier

	// KeyDeriver derives the backup encryption key from the lnd wallet.
	KeyDeriver KeyDeriver

	// Swapper persists the packed backup.
	Swapper Swapper

	// Debounce is how long to wait after the first change notification
	// before reconciling. Zero selects DefaultDebounce.
	Debounce time.Duration

	// RetryInterval is how long to wait before retrying a failed
	// reconcile. Zero selects DefaultRetryInterval.
	RetryInterval time.Duration
}

// entryKey uniquely identifies an asset leaf within the backup.
type entryKey struct {
	assetID   asset.ID
	scriptKey asset.SerializedKey
	outpoint  wire.OutPoint
}

// bytes returns a fixed layout serialization of the key that is used for
// deterministic ordering of the backup entries.
func (k entryKey) bytes() []byte {
	var buf bytes.Buffer
	buf.Write(k.assetID[:])
	buf.Write(k.scriptKey[:])
	buf.Write(k.outpoint.Hash[:])

	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], k.outpoint.Index)
	buf.Write(idx[:])

	return buf.Bytes()
}

// keyForChainAsset returns the entry key for a chain asset.
func keyForChainAsset(a *asset.ChainAsset) entryKey {
	return entryKey{
		assetID:   a.ID(),
		scriptKey: asset.ToSerialized(a.ScriptKey.PubKey),
		outpoint:  a.AnchorOutpoint,
	}
}

// keyForBackup returns the entry key for a backup entry. The boolean is false
// if the entry is missing the fields needed to identify it.
func keyForBackup(ab *AssetBackup) (entryKey, bool) {
	if ab == nil || ab.Asset == nil || ab.Asset.ScriptKey.PubKey == nil {
		return entryKey{}, false
	}

	return entryKey{
		assetID:   ab.Asset.ID(),
		scriptKey: asset.ToSerialized(ab.Asset.ScriptKey.PubKey),
		outpoint:  ab.AnchorOutpoint,
	}, true
}

// trackedEntry is an in-memory backup entry together with the anchor block
// hash it was built from, so a re-org that re-anchors the same leaf in a
// different block is detected and the entry rebuilt.
type trackedEntry struct {
	backup    *AssetBackup
	blockHash chainhash.Hash
}

// syncRequest is a request to reconcile immediately and report the result.
type syncRequest struct {
	errChan chan error
}

// Updater keeps an encrypted asset wallet backup file on disk in sync with the
// wallet state. It mirrors lnd's chanbackup.SubSwapper: it holds the current
// set of backup entries in memory, subscribes to wallet change notifications,
// and on every change reconciles the in-memory set against the database and
// atomically rewrites the file. Entries found on disk that the database does
// not know about are retained, entries for spent leaves are removed.
type Updater struct {
	startOnce sync.Once
	stopOnce  sync.Once

	cfg *UpdaterConfig

	encrypter lnencrypt.EncrypterDecrypter

	receiver     *fn.EventReceiver[proof.Blob]
	mintReceiver *fn.EventReceiver[fn.Event]

	// entries is the in-memory backup state. It is only accessed from
	// Start (before the main loop runs) and from the main loop itself.
	entries map[entryKey]trackedEntry

	// pendingRemovals holds the keys of leaves that were removed from the
	// in-memory state but whose removal has not yet been persisted. They
	// are dropped from the disk union on the next successful write.
	pendingRemovals map[entryKey]struct{}

	// dirty is true if the in-memory state has changes that have not been
	// persisted yet. It is cleared by a successful write only, so a failed
	// write is retried even if no further change happens.
	dirty bool

	syncReqs chan syncRequest

	isActive atomic.Bool

	ctx    context.Context //nolint:containedctx
	cancel context.CancelFunc

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewUpdater creates a new Updater from the given config.
func NewUpdater(cfg *UpdaterConfig) (*Updater, error) {
	switch {
	case cfg == nil:
		return nil, fmt.Errorf("updater config is nil")
	case cfg.FetchAssets == nil:
		return nil, fmt.Errorf("updater requires an asset fetcher")
	case cfg.ProofArchive == nil:
		return nil, fmt.Errorf("updater requires a proof archive")
	case cfg.ProofNotifier == nil:
		return nil, fmt.Errorf("updater requires a proof notifier")
	case cfg.KeyDeriver == nil:
		return nil, fmt.Errorf("updater requires a key deriver")
	case cfg.Swapper == nil:
		return nil, fmt.Errorf("updater requires a swapper")
	}

	if cfg.Debounce <= 0 {
		cfg.Debounce = DefaultDebounce
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = DefaultRetryInterval
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Updater{
		cfg:             cfg,
		entries:         make(map[entryKey]trackedEntry),
		pendingRemovals: make(map[entryKey]struct{}),
		syncReqs:        make(chan syncRequest),
		ctx:             ctx,
		cancel:          cancel,
		quit:            make(chan struct{}),
	}, nil
}

// Start derives the encryption key, checks that any existing backup file can
// be read with it, subscribes to wallet changes and starts the background
// loop, which immediately reconciles the file against the database. An
// existing backup file that cannot be decrypted with the wallet's key is a
// fatal error, since it most likely belongs to a different seed.
func (u *Updater) Start() error {
	var startErr error
	u.startOnce.Do(func() {
		log.Infof("Starting asset wallet backup file updater")

		ctx, cancel := context.WithTimeout(u.ctx, startupTimeout)
		defer cancel()

		encrypter, err := NewKeyRingEncrypter(ctx, u.cfg.KeyDeriver)
		if err != nil {
			startErr = err
			return
		}
		u.encrypter = encrypter

		// Make sure we can read what is already there before we
		// commit to rewriting it.
		if _, err := u.readDisk(); err != nil {
			startErr = err
			return
		}

		// Subscribe before the initial reconcile so no change that
		// lands in between is missed.
		u.receiver = fn.NewEventReceiver[proof.Blob](
			fn.DefaultQueueSize,
		)
		err = u.cfg.ProofNotifier.RegisterSubscriber(
			u.receiver, false, nil,
		)
		if err != nil {
			u.receiver = nil
			startErr = fmt.Errorf("unable to subscribe to proof "+
				"events: %w", err)
			return
		}

		if u.cfg.MintNotifier != nil {
			u.mintReceiver = fn.NewEventReceiver[fn.Event](
				fn.DefaultQueueSize,
			)
			err = u.cfg.MintNotifier.RegisterSubscriber(
				u.mintReceiver, false, false,
			)
			if err != nil {
				u.unsubscribe()
				u.mintReceiver = nil
				startErr = fmt.Errorf("unable to subscribe to "+
					"mint events: %w", err)
				return
			}
		}

		u.isActive.Store(true)

		u.wg.Add(1)
		go u.mainLoop()
	})

	return startErr
}

// Stop performs a final reconcile so the file reflects the latest wallet
// state, then shuts the background loop down.
func (u *Updater) Stop() error {
	u.stopOnce.Do(func() {
		log.Infof("Stopping asset wallet backup file updater")

		if u.isActive.Load() {
			ctx, cancel := context.WithTimeout(
				context.Background(), shutdownSyncTimeout,
			)
			err := u.Sync(ctx)
			cancel()
			if err != nil {
				log.Warnf("Final backup file sync failed: %v",
					err)
			}
		}

		u.isActive.Store(false)
		u.cancel()
		close(u.quit)
		u.wg.Wait()

		u.unsubscribe()
	})

	return nil
}

// unsubscribe removes the change subscriptions that were registered in Start.
func (u *Updater) unsubscribe() {
	if u.receiver != nil {
		err := u.cfg.ProofNotifier.RemoveSubscriber(u.receiver)
		if err != nil {
			log.Warnf("Unable to remove proof subscriber: %v", err)
		}
		u.receiver = nil
	}

	if u.mintReceiver != nil {
		err := u.cfg.MintNotifier.RemoveSubscriber(u.mintReceiver)
		if err != nil {
			log.Warnf("Unable to remove mint subscriber: %v", err)
		}
		u.mintReceiver = nil
	}
}

// Sync forces an immediate reconcile and blocks until the file has been
// rewritten or the context expires. An error is returned if the write failed
// or if any asset could not be backed up.
func (u *Updater) Sync(ctx context.Context) error {
	if !u.isActive.Load() {
		return ErrUpdaterNotActive
	}

	req := syncRequest{errChan: make(chan error, 1)}

	select {
	case u.syncReqs <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-u.quit:
		return ErrUpdaterNotActive
	}

	select {
	case err := <-req.errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-u.quit:
		return ErrUpdaterNotActive
	}
}

// mainLoop writes the initial state, then waits for change notifications,
// debounces them and reconciles.
func (u *Updater) mainLoop() {
	defer u.wg.Done()

	var (
		timer   *time.Timer
		timerCh <-chan time.Time
	)
	arm := func(d time.Duration) {
		if timer != nil {
			timer.Stop()
		}
		timer = time.NewTimer(d)
		timerCh = timer.C
	}
	disarm := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = nil
		timerCh = nil
	}
	defer disarm()

	// handleResult logs the outcome of a reconcile and arms the retry
	// timer if anything is left to do.
	handleResult := func(failed int, err error) {
		switch {
		case err != nil:
			log.Errorf("Unable to update backup file: %v, "+
				"retrying in %v", err, u.cfg.RetryInterval)
			arm(u.cfg.RetryInterval)

		case failed > 0:
			log.Warnf("%d asset(s) could not be backed up, "+
				"retrying in %v", failed, u.cfg.RetryInterval)
			arm(u.cfg.RetryInterval)
		}
	}

	// The initial write always happens, so the file reflects the database
	// state even if nothing changes for a long time after startup.
	handleResult(u.reconcile(u.ctx, true))

	// Only arm the debounce timer for the first notification of a burst,
	// later ones fold into it.
	onChange := func() {
		if timerCh == nil {
			arm(u.cfg.Debounce)
		}
	}

	// A nil channel blocks forever, which is what we want when there is
	// no mint notifier.
	var mintEvents <-chan fn.Event
	if u.mintReceiver != nil {
		mintEvents = u.mintReceiver.NewItemCreated.ChanOut()
	}

	for {
		select {
		case <-u.receiver.NewItemCreated.ChanOut():
			onChange()

		case <-mintEvents:
			onChange()

		case <-timerCh:
			disarm()
			handleResult(u.reconcile(u.ctx, false))

		case req := <-u.syncReqs:
			disarm()

			failed, err := u.reconcile(u.ctx, false)
			if err == nil && failed > 0 {
				err = fmt.Errorf("%d asset(s) could not be "+
					"backed up", failed)
			}
			if err != nil {
				arm(u.cfg.RetryInterval)
			}
			req.errChan <- err

		case <-u.quit:
			return
		}
	}
}

// reconcile fetches the current wallet state, updates the in-memory entry set
// and, if anything changed (or force is set), rewrites the backup file. It
// returns the number of assets that could not be turned into backup entries;
// those are retried on the next reconcile. The error is only non-nil for
// failures that affect the whole file.
func (u *Updater) reconcile(ctx context.Context, force bool) (int, error) {
	assets, err := u.cfg.FetchAssets(ctx)
	if err != nil {
		return 0, fmt.Errorf("unable to fetch assets: %w", err)
	}

	current := make(map[entryKey]*asset.ChainAsset, len(assets))
	for _, a := range assets {
		if a == nil || a.Asset == nil || a.ScriptKey.PubKey == nil {
			continue
		}

		// Unconfirmed leaves have no anchor block yet, they enter
		// the backup once their anchor transaction confirms.
		if a.AnchorBlockHeight == 0 {
			continue
		}

		current[keyForChainAsset(a)] = a
	}

	// Leaves that are no longer part of the unspent set were spent, drop
	// them from memory and remember to drop them from disk too.
	numRemoved := 0
	for key := range u.entries {
		if _, ok := current[key]; ok {
			continue
		}

		delete(u.entries, key)
		u.pendingRemovals[key] = struct{}{}
		numRemoved++
	}

	// New leaves, and leaves whose anchor block changed because of a
	// re-org, need a fresh backup entry built from their proof.
	var numAdded, numFailed int
	for key, chainAsset := range current {
		existing, ok := u.entries[key]
		if ok && existing.blockHash == chainAsset.AnchorBlockHash {
			continue
		}

		backups, _, err := CollectBackups(
			ctx, ExportModeCompact,
			[]*asset.ChainAsset{chainAsset}, u.cfg.ProofArchive,
			u.cfg.KeyLookup, nil,
		)
		if err != nil || len(backups) != 1 {
			log.Warnf("Unable to build backup entry for asset "+
				"%x at %v: %v", key.assetID[:], key.outpoint,
				err)
			numFailed++
			continue
		}

		u.entries[key] = trackedEntry{
			backup:    backups[0],
			blockHash: chainAsset.AnchorBlockHash,
		}
		delete(u.pendingRemovals, key)
		numAdded++
	}

	u.dirty = u.dirty || force || numAdded > 0 ||
		len(u.pendingRemovals) > 0
	if !u.dirty {
		return numFailed, nil
	}

	log.Infof("Updating backup file: %d wallet entries (%d added, %d "+
		"removed, %d failed)", len(u.entries), numAdded, numRemoved,
		numFailed)

	if err := u.updateFile(); err != nil {
		return numFailed, err
	}

	return numFailed, nil
}

// updateFile merges what is currently on disk with the in-memory state (the
// in-memory state wins on conflicts), drops pending removals, and atomically
// swaps the encrypted result into place.
func (u *Updater) updateFile() error {
	combined := make(map[entryKey]*AssetBackup)

	diskBackup, err := u.readDisk()
	if err != nil {
		return err
	}
	if diskBackup != nil {
		for _, ab := range diskBackup.Assets {
			key, ok := keyForBackup(ab)
			if !ok {
				continue
			}
			combined[key] = ab
		}
	}

	for key, entry := range u.entries {
		combined[key] = entry.backup
	}
	for key := range u.pendingRemovals {
		delete(combined, key)
	}

	keys := make([]entryKey, 0, len(combined))
	for key := range combined {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b entryKey) int {
		return bytes.Compare(a.bytes(), b.bytes())
	})

	walletBackup := &WalletBackup{
		Version: BackupVersionStripped,
		Assets:  make([]*AssetBackup, 0, len(keys)),
	}
	for _, key := range keys {
		walletBackup.Assets = append(walletBackup.Assets, combined[key])
	}

	plaintext, err := EncodeWalletBackup(walletBackup)
	if err != nil {
		return fmt.Errorf("unable to encode backup: %w", err)
	}

	packed, err := EncryptBackup(u.encrypter, plaintext)
	if err != nil {
		return err
	}

	if err := u.cfg.Swapper.UpdateAndSwap(packed); err != nil {
		return fmt.Errorf("unable to swap backup file: %w", err)
	}

	// The in-memory state is now reflected on disk.
	u.pendingRemovals = make(map[entryKey]struct{})
	u.dirty = false

	log.Infof("Wrote backup file with %d entries (%d bytes)", len(keys),
		len(packed))

	return nil
}

// readDisk reads and decodes the currently persisted backup. It returns nil
// if nothing is persisted yet. Both encrypted and plaintext files are
// accepted, so a plaintext export placed at the backup path is picked up and
// re-written encrypted on the next update.
func (u *Updater) readDisk() (*WalletBackup, error) {
	packed, err := u.cfg.Swapper.Extract()
	switch {
	case errors.Is(err, ErrNoBackupFile):
		return nil, nil

	case err != nil:
		return nil, fmt.Errorf("unable to read existing backup "+
			"file: %w", err)
	}

	plaintext := packed
	if IsEncryptedBackup(packed) {
		plaintext, err = DecryptBackup(u.encrypter, packed)
		if err != nil {
			return nil, fmt.Errorf("existing backup file cannot "+
				"be decrypted with the wallet key: %w", err)
		}
	}

	walletBackup, err := DecodeWalletBackup(plaintext)
	if err != nil {
		return nil, fmt.Errorf("existing backup file cannot be "+
			"decoded: %w", err)
	}

	return walletBackup, nil
}
