package backup

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

const (
	// testDebounce is the debounce used in tests, short enough to keep
	// the tests fast but long enough to observe coalescing.
	testDebounce = 50 * time.Millisecond

	// testRetry is the retry interval used in tests.
	testRetry = 100 * time.Millisecond

	// testTimeout is how long tests wait for an expected write.
	testTimeout = 5 * time.Second

	// testQuiet is how long tests wait to assert that no write happens.
	testQuiet = 6 * testDebounce
)

// mockSwapper is an in-memory Swapper that records every write and can be
// told to fail.
type mockSwapper struct {
	mu     sync.Mutex
	data   []byte
	fail   bool
	writes chan []byte
}

func newMockSwapper() *mockSwapper {
	return &mockSwapper{writes: make(chan []byte, 100)}
}

func (m *mockSwapper) UpdateAndSwap(packed []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.fail {
		return errors.New("disk full")
	}

	m.data = append([]byte{}, packed...)
	m.writes <- m.data

	return nil
}

func (m *mockSwapper) Extract() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.data == nil {
		return nil, ErrNoBackupFile
	}

	return append([]byte{}, m.data...), nil
}

func (m *mockSwapper) setFail(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.fail = fail
}

func (m *mockSwapper) seed(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data = data
}

// mockNotifier is a ProofNotifier that hands out the registered receiver so
// tests can push notifications.
type mockNotifier struct {
	mu          sync.Mutex
	receiver    *fn.EventReceiver[proof.Blob]
	registerErr error
	removed     bool
}

func (m *mockNotifier) RegisterSubscriber(
	receiver *fn.EventReceiver[proof.Blob], _ bool,
	_ []*proof.Locator) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.registerErr != nil {
		return m.registerErr
	}
	m.receiver = receiver

	return nil
}

func (m *mockNotifier) RemoveSubscriber(
	receiver *fn.EventReceiver[proof.Blob]) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.receiver != receiver {
		return errors.New("unknown subscriber")
	}
	m.removed = true
	m.receiver.Stop()

	return nil
}

func (m *mockNotifier) notify(t *testing.T) {
	m.mu.Lock()
	receiver := m.receiver
	m.mu.Unlock()

	require.NotNil(t, receiver)
	receiver.NewItemCreated.ChanIn() <- proof.Blob("irrelevant")
}

// mockMintNotifier is an EventNotifier that hands out the registered receiver
// so tests can push events.
type mockMintNotifier struct {
	mu          sync.Mutex
	receiver    *fn.EventReceiver[fn.Event]
	registerErr error
	removed     bool
}

func (m *mockMintNotifier) RegisterSubscriber(
	receiver *fn.EventReceiver[fn.Event], _, _ bool) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.registerErr != nil {
		return m.registerErr
	}
	m.receiver = receiver

	return nil
}

func (m *mockMintNotifier) RemoveSubscriber(
	receiver *fn.EventReceiver[fn.Event]) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.receiver != receiver {
		return errors.New("unknown subscriber")
	}
	m.removed = true
	m.receiver.Stop()

	return nil
}

// mintEvent is a minimal fn.Event.
type mintEvent struct{}

func (mintEvent) Timestamp() time.Time {
	return time.Now()
}

func (m *mockMintNotifier) notify(t *testing.T) {
	m.mu.Lock()
	receiver := m.receiver
	m.mu.Unlock()

	require.NotNil(t, receiver)
	receiver.NewItemCreated.ChanIn() <- mintEvent{}
}

// mockKeyLookup resolves every internal key to a fixed locator.
type mockKeyLookup struct {
	err error
}

func (m *mockKeyLookup) FetchInternalKeyLocator(_ context.Context,
	_ *btcec.PublicKey) (keychain.KeyLocator, error) {

	if m.err != nil {
		return keychain.KeyLocator{}, m.err
	}

	return keychain.KeyLocator{Family: 212, Index: 7}, nil
}

// assetSource is a mutable in-memory stand-in for the asset database.
type assetSource struct {
	mu     sync.Mutex
	assets map[entryKey]*asset.ChainAsset
	err    error
}

func newAssetSource() *assetSource {
	return &assetSource{assets: make(map[entryKey]*asset.ChainAsset)}
}

func (s *assetSource) fetch(_ context.Context) ([]*asset.ChainAsset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return nil, s.err
	}

	assets := make([]*asset.ChainAsset, 0, len(s.assets))
	for _, a := range s.assets {
		assets = append(assets, a)
	}

	return assets, nil
}

func (s *assetSource) add(a *asset.ChainAsset) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.assets[keyForChainAsset(a)] = a
}

func (s *assetSource) remove(a *asset.ChainAsset) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.assets, keyForChainAsset(a))
}

// testChainAsset is a chain asset together with the proof file it was built
// from.
type testChainAsset struct {
	*asset.ChainAsset
	proofBlob proof.Blob
}

// newTestChainAsset builds a confirmed chain asset backed by a valid proof
// file and, unless skipArchive is set, stores the proof in the archive under
// the locator the Updater will use.
func newTestChainAsset(t *testing.T, archive *proof.MockProofArchive,
	skipArchive bool) *testChainAsset {

	proofBlob, block, height := makeTestProofFile(t)

	f, err := proof.Blob(proofBlob).AsFile()
	require.NoError(t, err)
	p, err := f.LastProof()
	require.NoError(t, err)

	chainAsset := &asset.ChainAsset{
		Asset:             &p.Asset,
		AnchorTx:          &p.AnchorTx,
		AnchorBlockHash:   block.BlockHash(),
		AnchorBlockHeight: height,
		AnchorOutpoint:    p.OutPoint(),
		AnchorInternalKey: p.InclusionProof.InternalKey,
	}

	tca := &testChainAsset{ChainAsset: chainAsset, proofBlob: proofBlob}
	if !skipArchive {
		tca.storeProof(t, archive)
	}

	return tca
}

func (a *testChainAsset) storeProof(t *testing.T,
	archive *proof.MockProofArchive) {

	assetID := a.ID()
	err := archive.ImportProofs(
		context.Background(), proof.VerifierCtx{}, false,
		&proof.AnnotatedProof{
			Locator: proof.Locator{
				AssetID:   &assetID,
				ScriptKey: *a.ScriptKey.PubKey,
				OutPoint:  &a.AnchorOutpoint,
			},
			Blob: a.proofBlob,
		},
	)
	require.NoError(t, err)
}

func (a *testChainAsset) key() entryKey {
	return keyForChainAsset(a.ChainAsset)
}

// updaterHarness wires an Updater to all mocks.
type updaterHarness struct {
	t        *testing.T
	updater  *Updater
	source   *assetSource
	archive  *proof.MockProofArchive
	notifier *mockNotifier
	minter   *mockMintNotifier
	porter   *mockMintNotifier
	swapper  *mockSwapper
	deriver  *mockKeyDeriver
	lookup   *mockKeyLookup
}

func newUpdaterHarness(t *testing.T) *updaterHarness {
	h := &updaterHarness{
		t:        t,
		source:   newAssetSource(),
		archive:  proof.NewMockProofArchive(),
		notifier: &mockNotifier{},
		minter:   &mockMintNotifier{},
		porter:   &mockMintNotifier{},
		swapper:  newMockSwapper(),
		deriver:  newMockKeyDeriver(t),
		lookup:   &mockKeyLookup{},
	}

	updater, err := NewUpdater(h.config())
	require.NoError(t, err)
	h.updater = updater

	return h
}

func (h *updaterHarness) config() *UpdaterConfig {
	return &UpdaterConfig{
		FetchAssets:   h.source.fetch,
		ProofArchive:  h.archive,
		KeyLookup:     h.lookup,
		ProofNotifier: h.notifier,
		EventNotifiers: []EventNotifier{
			h.minter, h.porter,
		},
		KeyDeriver:    h.deriver,
		Swapper:       h.swapper,
		Debounce:      testDebounce,
		RetryInterval: testRetry,
	}
}

func (h *updaterHarness) newAsset() *testChainAsset {
	return newTestChainAsset(h.t, h.archive, false)
}

func (h *updaterHarness) start() {
	require.NoError(h.t, h.updater.Start())
	h.t.Cleanup(func() {
		require.NoError(h.t, h.updater.Stop())
	})
}

// waitWrite blocks until the swapper records a write and returns the decoded
// backup.
func (h *updaterHarness) waitWrite() *WalletBackup {
	select {
	case packed := <-h.swapper.writes:
		return h.decode(packed)

	case <-time.After(testTimeout):
		h.t.Fatalf("timeout waiting for backup file write")
		return nil
	}
}

// assertNoWrite asserts that no write happens within the quiet period.
func (h *updaterHarness) assertNoWrite() {
	select {
	case <-h.swapper.writes:
		h.t.Fatalf("unexpected backup file write")

	case <-time.After(testQuiet):
	}
}

// decode decrypts and decodes a packed backup with the harness key.
func (h *updaterHarness) decode(packed []byte) *WalletBackup {
	require.True(h.t, IsEncryptedBackup(packed))

	plaintext, err := DecryptBackup(
		newTestEncrypter(h.t, h.deriver), packed,
	)
	require.NoError(h.t, err)

	wb, err := DecodeWalletBackup(plaintext)
	require.NoError(h.t, err)

	return wb
}

// onDisk returns the decoded backup currently held by the swapper.
func (h *updaterHarness) onDisk() *WalletBackup {
	packed, err := h.swapper.Extract()
	require.NoError(h.t, err)

	return h.decode(packed)
}

// keys returns the set of entry keys in a backup.
func keys(t *testing.T, wb *WalletBackup) map[entryKey]*AssetBackup {
	result := make(map[entryKey]*AssetBackup, len(wb.Assets))
	for _, ab := range wb.Assets {
		key, ok := keyForBackup(ab)
		require.True(t, ok)
		result[key] = ab
	}

	return result
}

// assertEntries asserts that the backup holds exactly the given assets.
func assertEntries(t *testing.T, wb *WalletBackup, assets ...*testChainAsset) {
	got := keys(t, wb)
	require.Len(t, got, len(assets))
	for _, a := range assets {
		require.Contains(t, got, a.key())
	}
}

// encodePlain encodes a plaintext backup holding the given assets as raw v1
// entries.
func encodePlain(t *testing.T, assets ...*testChainAsset) []byte {
	wb := &WalletBackup{Version: BackupVersionOriginal}
	for _, a := range assets {
		wb.Assets = append(wb.Assets, &AssetBackup{
			Asset:             a.Asset,
			AnchorOutpoint:    a.AnchorOutpoint,
			AnchorBlockHeight: a.AnchorBlockHeight,
			ProofFileBlob:     a.proofBlob,
		})
	}

	data, err := EncodeWalletBackup(wb)
	require.NoError(t, err)

	return data
}

// TestNewUpdaterValidation asserts that every dependency is required and that
// zero durations fall back to the defaults.
func TestNewUpdaterValidation(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)

	_, err := NewUpdater(nil)
	require.ErrorContains(t, err, "nil")

	mutations := map[string]func(*UpdaterConfig){
		"asset fetcher": func(c *UpdaterConfig) {
			c.FetchAssets = nil
		},
		"proof archive": func(c *UpdaterConfig) {
			c.ProofArchive = nil
		},
		"proof notifier": func(c *UpdaterConfig) {
			c.ProofNotifier = nil
		},
		"key deriver": func(c *UpdaterConfig) {
			c.KeyDeriver = nil
		},
		"swapper": func(c *UpdaterConfig) {
			c.Swapper = nil
		},
	}
	for name, mutate := range mutations {
		cfg := h.config()
		mutate(cfg)

		_, err := NewUpdater(cfg)
		require.ErrorContains(t, err, name)
	}

	cfg := h.config()
	cfg.Debounce = 0
	cfg.RetryInterval = -1
	u, err := NewUpdater(cfg)
	require.NoError(t, err)
	require.Equal(t, DefaultDebounce, u.cfg.Debounce)
	require.Equal(t, DefaultRetryInterval, u.cfg.RetryInterval)
}

// TestUpdaterInitialWrite asserts that Start writes the full confirmed wallet
// state as an encrypted compact backup.
func TestUpdaterInitialWrite(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)
	a1, a2 := h.newAsset(), h.newAsset()
	h.source.add(a1.ChainAsset)
	h.source.add(a2.ChainAsset)

	// An unconfirmed leaf must be left out.
	pending := h.newAsset()
	pending.AnchorBlockHeight = 0
	h.source.add(pending.ChainAsset)

	h.start()

	wb := h.waitWrite()
	require.Equal(t, BackupVersionStripped, wb.Version)
	assertEntries(t, wb, a1, a2)

	for _, ab := range wb.Assets {
		// Compact entries carry a stripped proof and hints only.
		require.Empty(t, ab.ProofFileBlob)
		require.NotEmpty(t, ab.StrippedProofFileBlob)
		require.NotEmpty(t, ab.RehydrationHintsBlob)

		require.NotEmpty(t, ab.AnchorOutputPkScript)
		require.NotNil(t, ab.AnchorInternalKeyInfo)
		require.Equal(t, keychain.KeyLocator{Family: 212, Index: 7},
			ab.AnchorInternalKeyInfo.KeyLocator)
	}

	// The starting state is written exactly once.
	h.assertNoWrite()

	// Once the pending leaf confirms it is picked up.
	pending.AnchorBlockHeight = 101
	h.source.add(pending.ChainAsset)
	h.notifier.notify(t)

	assertEntries(t, h.waitWrite(), a1, a2, pending)
}

// TestUpdaterAddAndRemove drives a receive and a spend through the notifier
// and asserts the file follows.
func TestUpdaterAddAndRemove(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)
	a1 := h.newAsset()
	h.source.add(a1.ChainAsset)
	h.start()
	assertEntries(t, h.waitWrite(), a1)

	// Receive.
	a2 := h.newAsset()
	h.source.add(a2.ChainAsset)
	h.notifier.notify(t)
	assertEntries(t, h.waitWrite(), a1, a2)

	// Mint: signalled through the mint notifier instead.
	a3 := h.newAsset()
	h.source.add(a3.ChainAsset)
	h.minter.notify(t)
	assertEntries(t, h.waitWrite(), a1, a2, a3)

	// Full value send without change: no proof is imported locally, only
	// the send state machine reports it.
	h.source.remove(a3.ChainAsset)
	h.porter.notify(t)
	assertEntries(t, h.waitWrite(), a1, a2)

	// Spend a1: the leaf leaves the unspent set.
	h.source.remove(a1.ChainAsset)
	h.notifier.notify(t)
	assertEntries(t, h.waitWrite(), a2)

	// A notification that changes nothing does not rewrite the file.
	h.notifier.notify(t)
	h.assertNoWrite()

	// Spend the last one, the file is rewritten empty rather than left
	// stale.
	h.source.remove(a2.ChainAsset)
	h.notifier.notify(t)
	assertEntries(t, h.waitWrite())
}

// TestUpdaterDebounce asserts that a burst of notifications results in a
// single rewrite.
func TestUpdaterDebounce(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)
	h.start()
	h.waitWrite()

	a := h.newAsset()
	h.source.add(a.ChainAsset)
	for i := 0; i < 20; i++ {
		h.notifier.notify(t)
	}

	assertEntries(t, h.waitWrite(), a)
	h.assertNoWrite()
}

// TestUpdaterDiskOnlyEntriesRetained asserts that entries found on disk that
// the database does not know about survive rewrites, and that spends of known
// leaves still get removed.
func TestUpdaterDiskOnlyEntriesRetained(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)

	// Seed the disk with an encrypted backup holding a foreign leaf.
	foreign := h.newAsset()
	packed, err := EncryptBackup(
		newTestEncrypter(t, h.deriver), encodePlain(t, foreign),
	)
	require.NoError(t, err)
	h.swapper.seed(packed)

	local := h.newAsset()
	h.source.add(local.ChainAsset)
	h.start()

	assertEntries(t, h.waitWrite(), foreign, local)

	h.source.remove(local.ChainAsset)
	h.notifier.notify(t)
	assertEntries(t, h.waitWrite(), foreign)
}

// TestUpdaterPlaintextFileAdopted asserts that a plaintext export placed at
// the backup path is merged and rewritten encrypted.
func TestUpdaterPlaintextFileAdopted(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)
	seeded := h.newAsset()
	h.swapper.seed(encodePlain(t, seeded))

	local := h.newAsset()
	h.source.add(local.ChainAsset)
	h.start()

	wb := h.waitWrite()
	assertEntries(t, wb, seeded, local)

	// The seeded raw entry is carried over as is.
	require.NotEmpty(t, keys(t, wb)[seeded.key()].ProofFileBlob)

	packed, err := h.swapper.Extract()
	require.NoError(t, err)
	require.True(t, IsEncryptedBackup(packed))
}

// TestUpdaterMemoryWinsAndReorg asserts that the in-memory entry replaces the
// disk entry for the same leaf, and that a re-org changing the anchor block
// rebuilds the entry.
func TestUpdaterMemoryWinsAndReorg(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)

	// Seed disk with a raw entry for the same leaf the DB knows.
	a := h.newAsset()
	h.swapper.seed(encodePlain(t, a))
	h.source.add(a.ChainAsset)
	h.start()

	wb := h.waitWrite()
	assertEntries(t, wb, a)
	entry := keys(t, wb)[a.key()]
	require.Empty(t, entry.ProofFileBlob, "disk entry should be replaced")
	require.NotEmpty(t, entry.StrippedProofFileBlob)
	require.Equal(t, a.AnchorBlockHeight, entry.AnchorBlockHeight)

	// Same leaf, but now anchored in a different block.
	reorged := *a.ChainAsset
	reorged.AnchorBlockHash = chainhash.Hash{0xaa}
	reorged.AnchorBlockHeight = a.AnchorBlockHeight + 1
	h.source.add(&reorged)
	h.notifier.notify(t)

	wb = h.waitWrite()
	assertEntries(t, wb, a)
	require.Equal(t, reorged.AnchorBlockHeight,
		keys(t, wb)[a.key()].AnchorBlockHeight)
}

// TestUpdaterSwapFailureRetried asserts that a failed write is retried and
// that removals are not lost across the failure.
func TestUpdaterSwapFailureRetried(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)
	a1, a2 := h.newAsset(), h.newAsset()
	h.source.add(a1.ChainAsset)
	h.source.add(a2.ChainAsset)
	h.start()
	assertEntries(t, h.waitWrite(), a1, a2)

	// Disk goes bad, a1 is spent and a3 arrives.
	h.swapper.setFail(true)
	a3 := h.newAsset()
	h.source.remove(a1.ChainAsset)
	h.source.add(a3.ChainAsset)
	h.notifier.notify(t)
	h.assertNoWrite()

	// The file on disk is untouched.
	assertEntries(t, h.onDisk(), a1, a2)

	// Disk recovers, the retry applies both the add and the removal.
	h.swapper.setFail(false)
	assertEntries(t, h.waitWrite(), a2, a3)
}

// TestUpdaterProofFetchFailureRetried asserts that a leaf whose proof cannot
// be fetched is skipped and picked up on a later retry.
func TestUpdaterProofFetchFailureRetried(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)
	a1 := h.newAsset()
	h.source.add(a1.ChainAsset)

	// a2 is in the DB but its proof is missing from the archive.
	a2 := newTestChainAsset(t, h.archive, true)
	h.source.add(a2.ChainAsset)

	h.start()
	assertEntries(t, h.waitWrite(), a1)

	// Sync reports the failure explicitly.
	err := h.updater.Sync(context.Background())
	require.ErrorContains(t, err, "1 asset(s) could not be backed up")

	// The proof shows up, the retry picks it up.
	a2.storeProof(t, h.archive)
	assertEntries(t, h.waitWrite(), a1, a2)
}

// TestUpdaterFetchAssetsFailure asserts that a database error does not touch
// the file and is retried.
func TestUpdaterFetchAssetsFailure(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)
	a1 := h.newAsset()
	h.source.add(a1.ChainAsset)
	h.start()
	assertEntries(t, h.waitWrite(), a1)

	h.source.mu.Lock()
	h.source.err = errors.New("db locked")
	h.source.mu.Unlock()

	a2 := h.newAsset()
	h.source.add(a2.ChainAsset)
	h.notifier.notify(t)
	h.assertNoWrite()

	err := h.updater.Sync(context.Background())
	require.ErrorContains(t, err, "db locked")

	h.source.mu.Lock()
	h.source.err = nil
	h.source.mu.Unlock()

	assertEntries(t, h.waitWrite(), a1, a2)
}

// TestUpdaterStartFailures covers the fatal startup conditions.
func TestUpdaterStartFailures(t *testing.T) {
	t.Parallel()

	t.Run("undecryptable file", func(t *testing.T) {
		h := newUpdaterHarness(t)

		other := newTestEncrypter(t, newMockKeyDeriver(t))
		packed, err := EncryptBackup(other, encodePlain(t))
		require.NoError(t, err)
		h.swapper.seed(packed)

		err = h.updater.Start()
		require.ErrorContains(t, err, "cannot be decrypted")
		require.False(t, h.updater.isActive.Load())

		// We never subscribed, and Stop is still safe to call.
		require.Nil(t, h.updater.receiver)
		require.NoError(t, h.updater.Stop())
	})

	t.Run("garbage file", func(t *testing.T) {
		h := newUpdaterHarness(t)
		h.swapper.seed([]byte("definitely not a backup"))

		err := h.updater.Start()
		require.ErrorContains(t, err, "cannot be decoded")
	})

	t.Run("key derivation fails", func(t *testing.T) {
		h := newUpdaterHarness(t)
		h.deriver.err = errors.New("lnd down")

		require.ErrorContains(t, h.updater.Start(), "lnd down")
	})

	t.Run("subscribe fails", func(t *testing.T) {
		h := newUpdaterHarness(t)
		h.notifier.registerErr = errors.New("no subscriptions")

		require.ErrorContains(t, h.updater.Start(),
			"no subscriptions")
	})

	t.Run("subscribe fails leaves no receiver", func(t *testing.T) {
		h := newUpdaterHarness(t)
		h.notifier.registerErr = errors.New("no subscriptions")

		require.Error(t, h.updater.Start())
		require.Nil(t, h.updater.receiver)
		require.Empty(t, h.updater.eventReceivers)
		require.NoError(t, h.updater.Stop())
	})

	t.Run("event subscribe fails", func(t *testing.T) {
		h := newUpdaterHarness(t)
		h.porter.registerErr = errors.New("no send events")

		require.ErrorContains(t, h.updater.Start(), "no send events")

		// The subscriptions that did succeed are rolled back.
		require.True(t, h.notifier.removed)
		require.True(t, h.minter.removed)
		require.Nil(t, h.updater.receiver)
		require.Empty(t, h.updater.eventReceivers)
		require.NoError(t, h.updater.Stop())
	})
}

// TestUpdaterWithoutEventNotifiers asserts the event notifiers are optional.
func TestUpdaterWithoutEventNotifiers(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)
	cfg := h.config()
	cfg.EventNotifiers = nil
	u, err := NewUpdater(cfg)
	require.NoError(t, err)
	h.updater = u

	a := h.newAsset()
	h.source.add(a.ChainAsset)
	h.start()
	assertEntries(t, h.waitWrite(), a)

	h.source.remove(a.ChainAsset)
	h.notifier.notify(t)
	assertEntries(t, h.waitWrite())
}

// TestUpdaterStartupTransientFailuresRetried asserts that database and disk
// failures during the initial write do not fail startup and are retried.
func TestUpdaterStartupTransientFailuresRetried(t *testing.T) {
	t.Parallel()

	t.Run("database fails", func(t *testing.T) {
		h := newUpdaterHarness(t)
		a := h.newAsset()
		h.source.add(a.ChainAsset)
		h.source.err = errors.New("db locked")

		h.start()
		h.assertNoWrite()

		h.source.mu.Lock()
		h.source.err = nil
		h.source.mu.Unlock()

		assertEntries(t, h.waitWrite(), a)
	})

	t.Run("swap fails", func(t *testing.T) {
		h := newUpdaterHarness(t)
		a := h.newAsset()
		h.source.add(a.ChainAsset)
		h.swapper.setFail(true)

		h.start()
		h.assertNoWrite()

		h.swapper.setFail(false)
		assertEntries(t, h.waitWrite(), a)
	})
}

// TestUpdaterStartupProofFailureNotFatal asserts that a single leaf without a
// proof does not prevent startup and gets retried.
func TestUpdaterStartupProofFailureNotFatal(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)
	a1 := h.newAsset()
	a2 := newTestChainAsset(t, h.archive, true)
	h.source.add(a1.ChainAsset)
	h.source.add(a2.ChainAsset)

	h.start()
	assertEntries(t, h.waitWrite(), a1)

	a2.storeProof(t, h.archive)
	assertEntries(t, h.waitWrite(), a1, a2)
}

// TestUpdaterSyncAndStop covers the manual sync path and the final sync on
// shutdown.
func TestUpdaterSyncAndStop(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)

	// Not started yet.
	require.ErrorIs(t, h.updater.Sync(context.Background()),
		ErrUpdaterNotActive)

	require.NoError(t, h.updater.Start())
	h.waitWrite()

	// Idempotent start.
	require.NoError(t, h.updater.Start())

	// Sync with nothing changed does not write.
	require.NoError(t, h.updater.Sync(context.Background()))
	h.assertNoWrite()

	// Sync with a change writes synchronously.
	a1 := h.newAsset()
	h.source.add(a1.ChainAsset)
	require.NoError(t, h.updater.Sync(context.Background()))
	assertEntries(t, h.waitWrite(), a1)

	// A change without notification is captured by the final sync on
	// Stop.
	a2 := h.newAsset()
	h.source.add(a2.ChainAsset)
	require.NoError(t, h.updater.Stop())
	assertEntries(t, h.waitWrite(), a1, a2)

	require.True(t, h.notifier.removed)
	require.True(t, h.minter.removed)
	require.True(t, h.porter.removed)
	require.ErrorIs(t, h.updater.Sync(context.Background()),
		ErrUpdaterNotActive)

	// Idempotent stop.
	require.NoError(t, h.updater.Stop())
}

// TestUpdaterSyncContext asserts that Sync honours its context.
func TestUpdaterSyncContext(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)
	h.start()
	h.waitWrite()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := h.updater.Sync(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

// TestUpdaterDeterministicOutput asserts that the same state produces the same
// plaintext regardless of map iteration order.
func TestUpdaterDeterministicOutput(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)
	var assets []*testChainAsset
	for i := 0; i < 5; i++ {
		a := h.newAsset()
		assets = append(assets, a)
		h.source.add(a.ChainAsset)
	}
	h.start()
	first := h.waitWrite()

	// Force a rewrite of identical content by spending and re-adding a
	// leaf.
	h.source.remove(assets[0].ChainAsset)
	require.NoError(t, h.updater.Sync(context.Background()))
	h.waitWrite()
	h.source.add(assets[0].ChainAsset)
	require.NoError(t, h.updater.Sync(context.Background()))
	second := h.waitWrite()

	firstPlain, err := EncodeWalletBackup(first)
	require.NoError(t, err)
	secondPlain, err := EncodeWalletBackup(second)
	require.NoError(t, err)
	require.Equal(t, firstPlain, secondPlain)
}

// TestUpdaterKeyLookupFailureTolerated asserts that a failing key locator
// lookup still produces an entry with the public key only.
func TestUpdaterKeyLookupFailureTolerated(t *testing.T) {
	t.Parallel()

	h := newUpdaterHarness(t)
	h.lookup.err = fmt.Errorf("%w", ErrKeyLocatorNotFound)
	a := h.newAsset()
	h.source.add(a.ChainAsset)
	h.start()

	wb := h.waitWrite()
	assertEntries(t, wb, a)

	info := keys(t, wb)[a.key()].AnchorInternalKeyInfo
	require.NotNil(t, info)
	require.True(t, a.AnchorInternalKey.IsEqual(info.PubKey))
	require.Equal(t, keychain.KeyLocator{}, info.KeyLocator)
}

// TestUpdaterFileSwapper runs the updater against the real File swapper to
// make sure the two compose, including reading back an existing file on a
// second start.
func TestUpdaterFileSwapper(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := dir + "/" + DefaultBackupFileName

	h := newUpdaterHarness(t)
	cfg := h.config()
	cfg.Swapper = NewFile(path)
	u, err := NewUpdater(cfg)
	require.NoError(t, err)

	a1 := h.newAsset()
	h.source.add(a1.ChainAsset)
	require.NoError(t, u.Start())
	require.NoError(t, u.Stop())

	packed, err := NewFile(path).Extract()
	require.NoError(t, err)
	assertEntries(t, h.decode(packed), a1)

	// Second run with a different DB state picks the file up and merges.
	h2 := newUpdaterHarness(t)
	h2.deriver = h.deriver
	cfg = h2.config()
	cfg.Swapper = NewFile(path)
	u2, err := NewUpdater(cfg)
	require.NoError(t, err)

	a2 := newTestChainAsset(t, h2.archive, false)
	h2.source.add(a2.ChainAsset)
	require.NoError(t, u2.Start())
	require.NoError(t, u2.Stop())

	packed, err = NewFile(path).Extract()
	require.NoError(t, err)
	assertEntries(t, h.decode(packed), a1, a2)
}

// TestEntryKeyBytes asserts the ordering key distinguishes every component.
func TestEntryKeyBytes(t *testing.T) {
	t.Parallel()

	base := entryKey{
		assetID:   asset.ID{1},
		scriptKey: asset.ToSerialized(test.RandPubKey(t)),
	}
	base.outpoint.Index = 1

	other := base
	other.outpoint.Index = 2
	require.NotEqual(t, base.bytes(), other.bytes())

	other = base
	other.assetID = asset.ID{2}
	require.NotEqual(t, base.bytes(), other.bytes())

	other = base
	other.scriptKey = asset.ToSerialized(test.RandPubKey(t))
	require.NotEqual(t, base.bytes(), other.bytes())

	require.Equal(t, base.bytes(), base.bytes())
}
