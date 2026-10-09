package tapreorg_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightninglabs/taproot-assets/tapreorg/chainsim"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

const (
	testSiteID    tapreorg.SiteID = "test-site"
	testThreshold uint32          = 3

	// The settle timeout is generous because the shared rapid
	// harness saturates SQLite (synchronous=full + fullfsync makes
	// every commit an F_FULLFSYNC on macOS); genuine convergence
	// under low load takes milliseconds.
	settleTimeout = 30 * time.Second
	settleTick    = 10 * time.Millisecond
)

// testSite is a convergent site: each handler records the delivered
// phase as the site's applied state, from whatever state it was in.
// Match data is a concatenation of satisfying txids.
type testSite struct {
	id tapreorg.SiteID

	mu        sync.Mutex
	evalCount map[chainhash.Hash]int
	applied   map[tapreorg.AnchoringID]tapreorg.Phase
	history   map[tapreorg.AnchoringID][]string

	failing atomic.Bool

	// evalPanic and panicking make the predicate and the delivery
	// handlers panic, modeling defective per-site code.
	evalPanic atomic.Bool
	panicking atomic.Bool
}

func newTestSite(id tapreorg.SiteID) *testSite {
	return &testSite{
		id:        id,
		evalCount: make(map[chainhash.Hash]int),
		applied:   make(map[tapreorg.AnchoringID]tapreorg.Phase),
		history:   make(map[tapreorg.AnchoringID][]string),
	}
}

func (s *testSite) ID() tapreorg.SiteID {
	return s.id
}

func (s *testSite) EvaluateCandidate(match tapreorg.VersionedBlob,
	spendingTx *wire.MsgTx) (tapreorg.Verdict, error) {

	if s.evalPanic.Load() {
		panic("predicate boom")
	}

	txid := spendingTx.TxHash()

	s.mu.Lock()
	s.evalCount[txid]++
	s.mu.Unlock()

	for i := 0; i+32 <= len(match.Data); i += 32 {
		if bytes.Equal(match.Data[i:i+32], txid[:]) {
			return tapreorg.VerdictSatisfies, nil
		}
	}

	return tapreorg.VerdictForeign, nil
}

// apply is the shared convergent handler body.
func (s *testSite) apply(name string, anchoring *tapreorg.Anchoring) error {
	if s.panicking.Load() {
		panic(fmt.Sprintf("handler %s boom", name))
	}
	if s.failing.Load() {
		return fmt.Errorf("site %v is failing", s.id)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied[anchoring.ID] = anchoring.Phase
	s.history[anchoring.ID] = append(s.history[anchoring.ID], name)

	return nil
}

func (s *testSite) OnWitnessed(ctx context.Context, tx tapreorg.RegistryTx,
	a *tapreorg.Anchoring) error {

	return s.apply("witnessed", a)
}

func (s *testSite) OnUnwitnessed(ctx context.Context, tx tapreorg.RegistryTx,
	a *tapreorg.Anchoring) error {

	return s.apply("unwitnessed", a)
}

func (s *testSite) OnConflicted(ctx context.Context, tx tapreorg.RegistryTx,
	a *tapreorg.Anchoring) error {

	return s.apply("conflicted", a)
}

func (s *testSite) OnBuried(ctx context.Context, tx tapreorg.RegistryTx,
	a *tapreorg.Anchoring) error {

	return s.apply("buried", a)
}

func (s *testSite) OnAbandoned(ctx context.Context, tx tapreorg.RegistryTx,
	a *tapreorg.Anchoring) error {

	return s.apply("abandoned", a)
}

// appliedPhase returns the site's applied state for an anchoring.
func (s *testSite) appliedPhase(id tapreorg.AnchoringID) tapreorg.Phase {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.applied[id]
}

// deliveries returns the delivered-handler history for an anchoring.
func (s *testSite) deliveries(id tapreorg.AnchoringID) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.history[id]...)
}

// evaluations returns how often the predicate ran for a candidate.
func (s *testSite) evaluations(txid chainhash.Hash) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.evalCount[txid]
}

// faultRegistry wraps the store with programmable failure, modeling
// a database that goes away mid-flight: while armed, registry calls
// fail before reaching the store. A method filter narrows the
// injection to one call site, for crash-consistency probes that need
// the failure to land between two specific writes.
type faultRegistry struct {
	tapreorg.Registry

	mu       sync.Mutex
	failures int
	method   string

	// detach, while set, runs registration transactions detached
	// from the caller's context: the model of a caller that
	// departs once its registration has committed, so that only
	// the watcher's post-commit hand-off sees the cancelled
	// context.
	detach atomic.Bool
}

// DetachContexts sets whether registrations run detached from the
// caller's context.
func (f *faultRegistry) DetachContexts(detach bool) {
	f.detach.Store(detach)
}

// FailNextCalls arms the next n registry calls to fail; a non-empty
// method restricts the injection to that method. Zero disarms.
func (f *faultRegistry) FailNextCalls(n int, method string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.failures, f.method = n, method
}

// failNext consumes one armed failure, if the method matches.
func (f *faultRegistry) failNext(method string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.failures <= 0 {
		return nil
	}
	if f.method != "" && f.method != method {
		return nil
	}
	f.failures--

	return fmt.Errorf("injected registry failure in %s", method)
}

func (f *faultRegistry) Register(ctx context.Context,
	spec tapreorg.RegistrationSpec, createdHeight uint32,
	phase1 func(context.Context, tapreorg.RegistryTx,
		tapreorg.AnchoringID) error,
	reconcile tapreorg.ReconcileFunc) (tapreorg.AnchoringID, error) {

	if err := f.failNext("Register"); err != nil {
		return 0, err
	}
	if f.detach.Load() {
		ctx = context.WithoutCancel(ctx)
	}

	return f.Registry.Register(
		ctx, spec, createdHeight, phase1, reconcile,
	)
}

func (f *faultRegistry) RegisterBatch(ctx context.Context,
	requests []tapreorg.RegistrationRequest, createdHeight uint32,
	phase1 tapreorg.BatchPhase1Func) ([]tapreorg.AnchoringID, error) {

	if err := f.failNext("RegisterBatch"); err != nil {
		return nil, err
	}
	if err := f.failNext("Register"); err != nil {
		return nil, err
	}
	if f.detach.Load() {
		ctx = context.WithoutCancel(ctx)
	}

	return f.Registry.RegisterBatch(
		ctx, requests, createdHeight, phase1,
	)
}

func (f *faultRegistry) GetAnchoring(ctx context.Context,
	id tapreorg.AnchoringID) (*tapreorg.Anchoring, error) {

	if err := f.failNext("GetAnchoring"); err != nil {
		return nil, err
	}

	return f.Registry.GetAnchoring(ctx, id)
}

func (f *faultRegistry) LiveAnchorings(
	ctx context.Context) ([]*tapreorg.Anchoring, error) {

	if err := f.failNext("LiveAnchorings"); err != nil {
		return nil, err
	}

	return f.Registry.LiveAnchorings(ctx)
}

func (f *faultRegistry) ChainView(ctx context.Context,
	id tapreorg.AnchoringID) (tapreorg.ChainView, error) {

	if err := f.failNext("ChainView"); err != nil {
		return tapreorg.ChainView{}, err
	}

	return f.Registry.ChainView(ctx, id)
}

func (f *faultRegistry) UpsertCandidate(ctx context.Context,
	id tapreorg.AnchoringID, candidate tapreorg.CandidateSpend) error {

	if err := f.failNext("UpsertCandidate"); err != nil {
		return err
	}

	return f.Registry.UpsertCandidate(ctx, id, candidate)
}

func (f *faultRegistry) SetPhase(ctx context.Context,
	id tapreorg.AnchoringID, phase tapreorg.Phase) error {

	if err := f.failNext("SetPhase"); err != nil {
		return err
	}

	return f.Registry.SetPhase(ctx, id, phase)
}

func (f *faultRegistry) Deliver(ctx context.Context,
	id tapreorg.AnchoringID, target tapreorg.Phase,
	handler func(context.Context, tapreorg.RegistryTx,
		*tapreorg.Anchoring) error) error {

	if err := f.failNext("Deliver"); err != nil {
		return err
	}

	return f.Registry.Deliver(ctx, id, target, handler)
}

func (f *faultRegistry) RecordDeliveryFailure(ctx context.Context,
	id tapreorg.AnchoringID, deliveryErr error, nextAttempt time.Time,
	stuck bool) error {

	if err := f.failNext("RecordDeliveryFailure"); err != nil {
		return err
	}

	return f.Registry.RecordDeliveryFailure(
		ctx, id, deliveryErr, nextAttempt, stuck,
	)
}

func (f *faultRegistry) PendingDeliveries(ctx context.Context,
	now time.Time) ([]*tapreorg.Anchoring, error) {

	if err := f.failNext("PendingDeliveries"); err != nil {
		return nil, err
	}

	return f.Registry.PendingDeliveries(ctx, now)
}

func (f *faultRegistry) DependencyEdges(ctx context.Context,
	parent tapreorg.AnchoringID) ([]tapreorg.DependencyEdge, error) {

	if err := f.failNext("DependencyEdges"); err != nil {
		return nil, err
	}

	return f.Registry.DependencyEdges(ctx, parent)
}

func (f *faultRegistry) IncomingEdges(ctx context.Context,
	child tapreorg.AnchoringID) ([]tapreorg.DependencyEdge, error) {

	if err := f.failNext("IncomingEdges"); err != nil {
		return nil, err
	}

	return f.Registry.IncomingEdges(ctx, child)
}

func (f *faultRegistry) StageForeclosure(ctx context.Context,
	child, parent tapreorg.AnchoringID,
	foreclosure tapreorg.ForeclosureEvent) error {

	if err := f.failNext("StageForeclosure"); err != nil {
		return err
	}

	return f.Registry.StageForeclosure(ctx, child, parent, foreclosure)
}

func (f *faultRegistry) ClearForeclosure(ctx context.Context,
	child, parent tapreorg.AnchoringID) error {

	if err := f.failNext("ClearForeclosure"); err != nil {
		return err
	}

	return f.Registry.ClearForeclosure(ctx, child, parent)
}

func (f *faultRegistry) PendingEffects(ctx context.Context,
	now time.Time, limit int32) ([]*tapreorg.StoredEffect, error) {

	if err := f.failNext("PendingEffects"); err != nil {
		return nil, err
	}

	return f.Registry.PendingEffects(ctx, now, limit)
}

func (f *faultRegistry) MarkEffectDispatched(ctx context.Context,
	effectID int64) error {

	if err := f.failNext("MarkEffectDispatched"); err != nil {
		return err
	}

	return f.Registry.MarkEffectDispatched(ctx, effectID)
}

func (f *faultRegistry) RecordEffectFailure(ctx context.Context,
	effectID int64, dispatchErr error, nextAttempt time.Time) error {

	if err := f.failNext("RecordEffectFailure"); err != nil {
		return err
	}

	return f.Registry.RecordEffectFailure(
		ctx, effectID, dispatchErr, nextAttempt,
	)
}

// harness wires a chainsim, a real SQLite-backed registry, a test
// site and the watcher together.
type harness struct {
	t *testing.T

	sim      *chainsim.Chain
	store    *tapdb.ReorgRegistryStore
	registry *faultRegistry
	rawDB    *sql.DB
	dbPath   string
	site     *testSite
	watcher  *tapreorg.Watcher

	// errChan receives the watcher's critical escalations, which
	// the daemon would treat as fatal. Scenarios composed solely of
	// transient faults must never emit here; escalation() checks.
	errChan chan error

	effects atomic.Int32

	txSeq atomic.Uint32
}

func newHarness(t *testing.T) *harness {
	dbPath := filepath.Join(t.TempDir(), "harness.db")
	db := tapdb.NewTestSqliteDbHandleFromPath(t, dbPath)
	executor := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	h := &harness{
		t:      t,
		sim:    chainsim.New(),
		rawDB:  db.DB,
		dbPath: dbPath,
		store: tapdb.NewReorgRegistryStore(
			executor, clock.NewDefaultClock(),
		),
		site:    newTestSite(testSiteID),
		errChan: make(chan error, 16),
	}
	h.registry = &faultRegistry{Registry: h.store}
	h.watcher = h.newWatcher()

	return h
}

// escalation returns a critical error the watcher escalated, if any.
func (h *harness) escalation() error {
	select {
	case err := <-h.errChan:
		return err
	default:
		return nil
	}
}

// newWatcher builds a watcher over the harness's sim and store, with
// aggressive timing for tests.
func (h *harness) newWatcher() *tapreorg.Watcher {
	w := tapreorg.NewWatcher(&tapreorg.WatcherConfig{
		Notifier:               h.sim,
		Registry:               h.registry,
		InitialDeliveryBackoff: 10 * time.Millisecond,
		MaxDeliveryBackoff:     40 * time.Millisecond,
		StuckAfterAttempts:     2,
		ScanInterval:           20 * time.Millisecond,
		DispatchTimeout:        100 * time.Millisecond,
		ErrChan:                h.errChan,
	})
	require.NoError(h.t, w.RegisterSite(h.site))
	require.NoError(h.t, w.RegisterEffectHandler(
		"test", func(context.Context, fn.Option[tapreorg.AnchoringID],
			tapreorg.VersionedBlob) error {

			h.effects.Add(1)
			return nil
		},
	))

	return w
}

// start starts the watcher and registers cleanup. No test scenario
// built from transient faults may escalate a critical error; the one
// test that exercises a genuinely fatal condition consumes the
// escalation itself.
func (h *harness) start() {
	require.NoError(h.t, h.watcher.Start())
	h.t.Cleanup(func() {
		require.NoError(h.t, h.watcher.Stop())
		require.NoError(h.t, h.escalation())
	})
}

// restart stops the current watcher and brings up a fresh instance
// over the same store and sim: process death and recovery. A start
// that fails on transient database contention is retried with a
// fresh instance (a failed Start consumes the instance's startOnce).
func (h *harness) restart() {
	require.NoError(h.t, h.watcher.Stop())

	// Injected notifier and registry faults model transient
	// distress of the running process; they do not survive process
	// death.
	h.sim.FailNextCalls(0)
	h.registry.FailNextCalls(0, "")

	var err error
	for attempt := 0; attempt < 50; attempt++ {
		h.watcher = h.newWatcher()
		err = h.watcher.Start()
		if !errors.Is(err, tapdb.ErrRetriesExceeded) {
			break
		}
		require.NoError(h.t, h.watcher.Stop())
		time.Sleep(settleTick)
	}
	require.NoError(h.t, err)
}

// flushPool evicts idle pool connections. Under heavy concurrent
// load, modernc/sqlite pool connections can end up pinned to an old
// WAL snapshot and serve stale reads for a long time (bounded in
// production by the pool's connection max lifetime); evicting idle
// connections forces fresh snapshots. This is a workaround for a
// pre-existing tapdb infrastructure wart the harness's read pressure
// exposes, not for watcher behavior.
func (h *harness) flushPool() {
	h.rawDB.SetMaxIdleConns(0)
	h.rawDB.SetMaxIdleConns(25)
}

// stdScript builds a standard (P2WSH-shaped) output script the
// notifier accepts; the sim rejects nonstandard registrations the
// way lnd does.
func stdScript(tag byte) []byte {
	script := make([]byte, 34)
	script[0] = txscript.OP_0
	script[1] = txscript.OP_DATA_32
	for i := 2; i < len(script); i++ {
		script[i] = tag
	}

	return script
}

// spendTx builds a transaction spending the given outpoints, unique
// per call.
func (h *harness) spendTx(ops ...wire.OutPoint) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	for i := range ops {
		tx.AddTxIn(wire.NewTxIn(&ops[i], nil, nil))
	}
	seq := h.txSeq.Add(1)
	tx.AddTxOut(wire.NewTxOut(int64(seq), stdScript(0x01)))

	return tx
}

// register stakes an anchoring over the given trigger outpoints,
// whose satisfying forms are the given transactions.
func (h *harness) register(threshold uint32, satisfying []*wire.MsgTx,
	triggers ...wire.OutPoint) tapreorg.AnchoringID {

	return h.registerSpec(
		h.spec(threshold, satisfying, triggers...), standardEffect,
	)
}

// registerEnqueuing registers an anchoring over one trigger whose
// phase-1 write enqueues the standard effect and then whatever the
// caller enqueues, in that order.
func (h *harness) registerEnqueuing(threshold uint32, op wire.OutPoint,
	enqueue func(context.Context, tapreorg.RegistryTx,
		tapreorg.AnchoringID) error) tapreorg.AnchoringID {

	phase1 := func(ctx context.Context, tx tapreorg.RegistryTx,
		newID tapreorg.AnchoringID) error {

		if err := standardEffect(ctx, tx, newID); err != nil {
			return err
		}

		return enqueue(ctx, tx, newID)
	}

	return h.registerSpec(h.spec(threshold, nil, op), phase1)
}

// spec builds a registration over the given triggers, satisfied by
// the given transactions.
func (h *harness) spec(threshold uint32, satisfying []*wire.MsgTx,
	triggers ...wire.OutPoint) tapreorg.RegistrationSpec {

	points := make([]tapreorg.TriggerOutPoint, len(triggers))
	for i, op := range triggers {
		points[i] = tapreorg.TriggerOutPoint{
			OutPoint:   op,
			PkScript:   stdScript(0x02),
			HeightHint: 1,
		}
	}
	triggerSet, err := tapreorg.NewTriggerSet(points)
	require.NoError(h.t, err)

	var matchData []byte
	for _, tx := range satisfying {
		txid := tx.TxHash()
		matchData = append(matchData, txid[:]...)
	}

	return tapreorg.RegistrationSpec{
		Site:     testSiteID,
		Triggers: triggerSet,
		MatchData: tapreorg.VersionedBlob{
			Version: 1,
			Data:    matchData,
		},
		Payload:   tapreorg.VersionedBlob{Version: 1},
		Threshold: threshold,
	}
}

// standardEffect is the phase-1 write of an ordinary registration: it
// enqueues the harness's standard effect for the new anchoring.
func standardEffect(ctx context.Context, tx tapreorg.RegistryTx,
	newID tapreorg.AnchoringID) error {

	return tx.EnqueueEffect(ctx, tapreorg.OutboxEffect{
		Kind:      "test",
		Anchoring: fn.Some(newID),
		Payload: tapreorg.VersionedBlob{
			Version: 1,
		},
	})
}

// registerSpec registers the spec with retry and read-back, shared by
// the trigger-set and seed-candidate registration helpers.
func (h *harness) registerSpec(spec tapreorg.RegistrationSpec,
	phase1 func(context.Context, tapreorg.RegistryTx,
		tapreorg.AnchoringID) error) tapreorg.AnchoringID {

	return h.registerSpecCtx( //nolint:contextcheck
		context.Background(), spec, phase1,
	)
}

// registerSpecCtx is registerSpec under the caller's context.
func (h *harness) registerSpecCtx(ctx context.Context,
	spec tapreorg.RegistrationSpec,
	phase1 func(context.Context, tapreorg.RegistryTx,
		tapreorg.AnchoringID) error) tapreorg.AnchoringID {

	// Registration is retried through transient database
	// contention: the harness's polling load can exhaust SQLite's
	// busy-retry budget, which is a load artifact, not a defect.
	var (
		id  tapreorg.AnchoringID
		err error
	)
	for attempt := 0; attempt < 50; attempt++ {
		id, err = h.watcher.Register(ctx, spec, phase1)
		if !errors.Is(err, tapdb.ErrRetriesExceeded) {
			break
		}
		time.Sleep(settleTick)
	}
	require.NoError(h.t, err)

	// The returned id names a committed row; verify it becomes
	// readable, tolerating transient contention and evicting
	// pinned pool snapshots along the way.
	readBackDeadline := time.Now().Add(10 * time.Second)
	for {
		_, err = h.store.GetAnchoring(context.Background(), id)
		if err == nil {
			break
		}
		if time.Now().After(readBackDeadline) {
			h.t.Fatalf("registered anchoring %d never became "+
				"readable: %v", id, err)
		}
		h.flushPool()
		time.Sleep(settleTick)
	}

	return id
}

// seedSpec builds a seeded registration for a transaction currently
// on the sim's chain, at its current location, keyed on its txid. The
// trigger outpoints, if any, are watched alongside the seed.
func (h *harness) seedSpec(threshold uint32, seedTx *wire.MsgTx,
	triggers ...wire.OutPoint) tapreorg.RegistrationSpec {

	ctx := context.Background()
	txid := seedTx.TxHash()

	height, ok := h.sim.TxHeight(txid)
	require.True(h.t, ok, "seed tx not on chain")
	blockHash, err := h.sim.GetBlockHash(ctx, int64(height))
	require.NoError(h.t, err)
	block, err := h.sim.GetBlock(ctx, blockHash)
	require.NoError(h.t, err)

	txIndex := -1
	for i, tx := range block.Transactions {
		if tx.TxHash() == txid {
			txIndex = i
			break
		}
	}
	require.GreaterOrEqual(h.t, txIndex, 0, "seed tx not in its block")

	witness, err := tapreorg.NewWitness(
		seedTx, blockHash, height, uint32(txIndex),
	)
	require.NoError(h.t, err)

	header := block.Header
	spec := tapreorg.RegistrationSpec{
		Site: testSiteID,
		MatchData: tapreorg.VersionedBlob{
			Version: 1,
			Data:    txid[:],
		},
		Payload:   tapreorg.VersionedBlob{Version: 1},
		Threshold: threshold,
		MatchKey:  txid[:],
		SeedCandidate: &tapreorg.CandidateSpend{
			Verdict:     tapreorg.VerdictSatisfies,
			W:           witness,
			OnChain:     true,
			BlockHeader: &header,
			MerkleProof: &proof.TxMerkleProof{},
		},
	}

	if len(triggers) > 0 {
		points := make([]tapreorg.TriggerOutPoint, len(triggers))
		for i, op := range triggers {
			points[i] = tapreorg.TriggerOutPoint{
				OutPoint:   op,
				PkScript:   stdScript(0x02),
				HeightHint: 1,
			}
		}
		triggerSet, err := tapreorg.NewTriggerSet(points)
		require.NoError(h.t, err)
		spec.Triggers = triggerSet
	}

	return spec
}

// settleWhere waits until the anchoring satisfies the condition.
func (h *harness) settleWhere(id tapreorg.AnchoringID,
	cond func(*tapreorg.Anchoring) bool) {

	h.t.Helper()

	require.Eventually(h.t, func() bool {
		anchoring, err := h.store.GetAnchoring(
			context.Background(), id,
		)
		if err != nil {
			return false
		}

		return cond(anchoring)
	}, settleTimeout, settleTick)
}

// settleConverged waits until the anchoring's sensed phase matches
// want, the site has durably acknowledged it, and the site's applied
// state agrees.
func (h *harness) settleConverged(id tapreorg.AnchoringID,
	want tapreorg.Phase) {

	h.t.Helper()

	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		if !tapreorg.PhaseEqual(a.Phase, want) {
			return false
		}
		if !tapreorg.PhaseEqual(a.DeliveredPhase, want) {
			return false
		}

		// The registration itself delivered Unwitnessed without
		// a handler call, so the site's applied state is only
		// checked once some phase change has been delivered.
		if tapreorg.PhaseEqual(want, tapreorg.Unwitnessed{}) {
			return true
		}
		applied := h.site.appliedPhase(id)

		return applied != nil && tapreorg.PhaseEqual(applied, want)
	})
}

// txHeightOf reports a transaction's current chain height for
// diagnostics, -1 when absent.
func txHeightOf(sim *chainsim.Chain, tx *wire.MsgTx) int {
	if height, ok := sim.TxHeight(tx.TxHash()); ok {
		return int(height)
	}

	return -1
}

// phaseKind names a phase variant for coarse assertions.
func phaseKind(p tapreorg.Phase) string {
	switch p.(type) {
	case tapreorg.Unwitnessed:
		return "unwitnessed"
	case tapreorg.Witnessed:
		return "witnessed"
	case tapreorg.Conflicted:
		return "conflicted"
	case tapreorg.Buried:
		return "buried"
	case tapreorg.Abandoned:
		return "abandoned"
	default:
		return fmt.Sprintf("unknown<%T>", p)
	}
}

// TestWatcherSeedWithTriggers drives a seed registered alongside its
// trigger set — the receive shape. A second registration for the
// same identity attaches and reconciles against the birth phase, so
// the site never sees an Unwitnessed for state it imported confirmed;
// and the trigger set is watched all the same, so a foreign spender
// that replaces the seed still forecloses the anchoring.
func TestWatcherSeedWithTriggers(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{0x52}, Index: 0}
	seedTx := h.spendTx(op)
	foreignTx := h.spendTx(op)
	h.sim.MineBlock(seedTx)

	spec := h.seedSpec(testThreshold, seedTx, op)
	id := h.registerSpec(spec, nil)
	require.Equal(t, "witnessed", phaseKind(h.site.appliedPhase(id)))

	// Sensing is handed off after the registration commits; the
	// trigger set is watched alongside the seed once it lands.
	require.Eventually(t, func() bool {
		return h.sim.SpendSubscribed(op)
	}, 5*time.Second, settleTick)

	// A second registration attaches to the seeded anchoring and
	// re-delivers its birth phase: witnessed, not the registry's
	// Unwitnessed default.
	again := h.registerSpec(spec, nil)
	require.Equal(t, id, again)
	require.NotContains(t, h.site.deliveries(id), "unwitnessed")
	require.Equal(t, "witnessed", phaseKind(h.site.appliedPhase(id)))

	// The trigger's foreign spender replaces the seed after a re-org
	// and buries: the chain decided against the seed, and the
	// anchoring is foreclosed through the watched trigger.
	h.sim.Reorg(1, []*wire.MsgTx{foreignTx})
	h.sim.MineBlocks(int(testThreshold) - 1)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		abandoned, ok := a.Phase.(tapreorg.Abandoned)
		if !ok {
			return false
		}
		cause, ok := abandoned.Cause.(tapreorg.ForeignBurial)
		return ok && cause.Spend.W.TxHash() == foreignTx.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.Equal(t, "abandoned", phaseKind(h.site.appliedPhase(id)))
}

// TestWatcherStuckDelivery wedges the site and asserts that sensing
// keeps tracking the chain while delivery is stuck (and visible as
// such), and that convergence resumes when the site heals.
func TestWatcherStuckDelivery(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{6}, Index: 0}
	satTx := h.spendTx(op)
	id := h.register(testThreshold, []*wire.MsgTx{satTx}, op)
	h.settleConverged(id, tapreorg.Unwitnessed{})

	h.site.failing.Store(true)

	// Sensing tracks the chain to burial while the site fails; the
	// delivered phase stays behind and the anchoring goes stuck.
	h.sim.MineBlock(satTx)
	h.sim.MineBlocks(int(testThreshold) - 1)

	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "buried" && a.Stuck &&
			tapreorg.PhaseEqual(
				a.DeliveredPhase, tapreorg.Unwitnessed{},
			)
	})

	// The site heals; the perpetual retry converges it. Coalescing
	// means the site sees only the latest phase: burial, without
	// the witnessed step it missed.
	h.site.failing.Store(false)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "buried" && !a.Stuck &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.Equal(t, "buried", phaseKind(h.site.appliedPhase(id)))
}

// TestWatcherEscalationNotDropped pins the delivery guarantee on the
// one fatal escalation: the daemon's consumer may not be ready when
// sensing dies — startup ordering, or a shared error channel already
// carrying another subsystem's failure — and the escalation must
// wait for it, never drop.
func TestWatcherEscalationNotDropped(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	// An unbuffered channel with no reader: any send that is not
	// waited on is lost.
	errChan := make(chan error)
	w := tapreorg.NewWatcher(&tapreorg.WatcherConfig{
		Notifier:               h.sim,
		Registry:               h.store,
		InitialDeliveryBackoff: 10 * time.Millisecond,
		MaxDeliveryBackoff:     40 * time.Millisecond,
		StuckAfterAttempts:     2,
		ScanInterval:           20 * time.Millisecond,
		ErrChan:                errChan,
	})
	require.NoError(t, w.RegisterSite(h.site))
	require.NoError(t, w.Start())
	t.Cleanup(func() { require.NoError(t, w.Stop()) })

	h.sim.SeverEpochStreams()

	// Let the sensing loop observe the loss and attempt the
	// escalation well before anyone listens.
	time.Sleep(20 * settleTick)

	select {
	case err := <-errChan:
		require.ErrorContains(t, err, "block epoch stream")

	case <-time.After(settleTimeout):
		t.Fatal("the escalation was dropped")
	}
}

// TestWatcherStaleActCertification constructs the disproved
// act-certification ordering: the notifier certifies threshold depth,
// but by the time the event is processed a deeper re-org has erased
// the certified location. Recording it would absorb a terminal phase
// on evidence the dominant chain disproves, so the watcher must
// refuse and resense.
func TestWatcherStaleActCertification(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{0xe2}, Index: 0}
	formA := h.spendTx(op)
	id := h.register(2, []*wire.MsgTx{formA}, op)

	h.sim.MineBlock(formA)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		_, ok := a.Phase.(tapreorg.Witnessed)
		return ok
	})

	// Freeze delivery, reach act depth, then erase the certified
	// location with a re-org deeper than the threshold: on release
	// the certification describes a dead chain.
	h.sim.HoldDeliveries()
	h.sim.MineBlocks(1)
	h.sim.Reorg(2, nil, nil)
	h.sim.ReleaseDeliveries()

	h.settleConverged(id, tapreorg.Unwitnessed{})

	// No burial on disproved evidence, durably or at the site.
	a, err := h.store.GetAnchoring(context.Background(), id)
	require.NoError(t, err)
	for _, spend := range a.Spends {
		require.False(t, spend.ActCertified)
	}
	require.NotContains(t, h.site.deliveries(id), "buried")
	require.NoError(t, h.escalation())
}

// TestWatcherEpochStreamError pins the error-arrival branch of the
// one fatal condition: an error on the block epoch stream, like its
// closure, means losing the chain and must escalate.
func TestWatcherEpochStreamError(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	h.sim.ErrorEpochStreams(errors.New("rpc wobble"))

	select {
	case err := <-h.errChan:
		require.ErrorContains(t, err, "block epoch stream")

	case <-time.After(settleTimeout):
		t.Fatal("an epoch stream error did not escalate")
	}
}

// TestWatcherForeclosureCertification drives a child's foreclosure
// through certification and then re-witnesses the parent yet again:
// the certified evidence is act-final, so the later parent form must
// not displace it, and the child's absorbed abandonment stays
// attributed to the transaction the notifier actually certified.
func TestWatcherForeclosureCertification(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	parentOp := wire.OutPoint{Hash: chainhash.Hash{0xe7}, Index: 0}
	pForm1 := h.spendTx(parentOp)
	pForm2 := h.spendTx(parentOp)
	pForm3 := h.spendTx(parentOp)
	parentID := h.register(
		4, []*wire.MsgTx{pForm1, pForm2, pForm3}, parentOp,
	)

	h.sim.MineBlock(pForm1)
	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed"
	})

	// The child depends on the parent's first form specifically.
	childOp := wire.OutPoint{Hash: pForm1.TxHash(), Index: 0}
	satChild := h.spendTx(childOp)
	childID := h.register(2, []*wire.MsgTx{satChild}, childOp)

	// The parent re-witnesses in a different form; at the child's
	// own threshold the notifier certifies the foreclosure and the
	// child absorbs, attributed to that form.
	h.sim.Reorg(1, []*wire.MsgTx{pForm2})
	h.sim.MineBlocks(1)

	h.settleWhere(childID, func(a *tapreorg.Anchoring) bool {
		abandoned, ok := a.Phase.(tapreorg.Abandoned)
		if !ok {
			return false
		}
		cause, ok := abandoned.Cause.(tapreorg.Foreclosed)
		if !ok || cause.Parent != parentID {
			return false
		}

		return cause.W.TxHash() == pForm2.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// A still deeper re-org hands the parent a third form. The
	// certified evidence on the child's edge is frozen: neither
	// the attribution nor the certification may move.
	h.sim.Reorg(2, []*wire.MsgTx{pForm3}, nil)
	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		w, ok := a.Phase.(tapreorg.Witnessed)
		return ok && w.W.TxHash() == pForm3.TxHash()
	})

	view, err := h.store.ChainView(context.Background(), childID)
	require.NoError(t, err)
	fc := view.Foreclosure.UnwrapToPtr()
	require.NotNil(t, fc)
	require.True(t, fc.ActCertified)
	require.Equal(t, pForm2.TxHash(), fc.W.TxHash())

	child, err := h.store.GetAnchoring(context.Background(), childID)
	require.NoError(t, err)
	abandoned, ok := child.Phase.(tapreorg.Abandoned)
	require.True(t, ok)
	cause, ok := abandoned.Cause.(tapreorg.Foreclosed)
	require.True(t, ok)
	require.Equal(t, pForm2.TxHash(), cause.W.TxHash())
	require.NoError(t, h.escalation())
}

// TestWatcherRegisterExistingReconciles pins the attach path of an
// identity-keyed registration: a second registration under the same
// (site, match key) returns the existing anchoring, re-delivers its
// delivered phase to the site inside the registration transaction,
// and unions trigger outpoints the first registration lacked — after
// which a foreign spend of an outpoint only the second registration
// revealed can still foreclose the stake. Without the union such an
// anchoring sat unwitnessed forever: the omitted outpoint had no
// spend subscription, so its foreign spend was invisible. A union a
// recorded satisfying candidate does not cover is refused instead of
// retroactively breaking the whole-set rule.
func TestWatcherRegisterExistingReconciles(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()
	ctx := context.Background()

	// The satisfying transaction spends two outpoints, but the
	// first registration only knows about one of them.
	opA := wire.OutPoint{Hash: chainhash.Hash{0xf6}, Index: 0}
	opB := wire.OutPoint{Hash: chainhash.Hash{0xf6}, Index: 1}
	opC := wire.OutPoint{Hash: chainhash.Hash{0xf6}, Index: 2}
	sat := h.spendTx(opA, opB)
	satTxid := sat.TxHash()

	matchKey := []byte("shared-anchor-identity")
	spec := func(ops ...wire.OutPoint) tapreorg.RegistrationSpec {
		points := make([]tapreorg.TriggerOutPoint, len(ops))
		for i, op := range ops {
			points[i] = tapreorg.TriggerOutPoint{
				OutPoint:   op,
				PkScript:   stdScript(0x02),
				HeightHint: 1,
			}
		}
		triggers, err := tapreorg.NewTriggerSet(points)
		require.NoError(t, err)

		return tapreorg.RegistrationSpec{
			Site:     testSiteID,
			Triggers: triggers,
			MatchData: tapreorg.VersionedBlob{
				Version: 1,
				Data:    satTxid[:],
			},
			Payload:   tapreorg.VersionedBlob{Version: 1},
			MatchKey:  matchKey,
			Threshold: 2,
		}
	}

	id := h.registerSpec(spec(opA), nil)

	// A duplicate registration before anything has been delivered
	// re-delivers the birth phase. The attach rule admits no
	// exemption: a delivered Unwitnessed is ambiguous between birth
	// and a soft re-org already delivered and at rest, and only the
	// unconditional re-delivery keeps state imported with a
	// confirmation a re-org discarded from outliving the rollback.
	require.Equal(t, id, h.registerSpec(spec(opA), nil))
	require.Equal(t, []string{"unwitnessed"}, h.site.deliveries(id))

	// Witness and deliver through the watched outpoint.
	h.sim.MineBlock(sat)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed" &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	delivered := len(h.site.deliveries(id))

	// A union the recorded satisfying candidate does not cover is
	// refused: the candidate would no longer spend the whole set.
	_, err := h.watcher.Register(ctx, spec(opA, opC), nil)
	require.ErrorIs(t, err, tapreorg.ErrIncompleteSpend)

	// The second registration reveals the satisfying transaction's
	// other input. Attaching re-delivers the delivered phase and
	// unions the revealed outpoint into the watched set.
	require.Equal(t, id, h.registerSpec(spec(opA, opB), nil))
	history := h.site.deliveries(id)
	require.Greater(t, len(history), delivered)
	require.Equal(t, "witnessed", history[len(history)-1])

	a, err := h.store.GetAnchoring(ctx, id)
	require.NoError(t, err)
	require.True(t, a.Triggers.Contains(opB))

	// The satisfying transaction re-orgs out and a foreign spend of
	// only the revealed outpoint replaces it. The union's spend
	// subscription observes it; at threshold depth the partial
	// foreign spend certifies and the stake is abandoned — exactly
	// the outcome an un-unioned trigger set could never reach.
	foreign := h.spendTx(opB)
	h.sim.Reorg(1, []*wire.MsgTx{foreign}, nil)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		abandoned, ok := a.Phase.(tapreorg.Abandoned)
		if !ok {
			return false
		}
		cause, ok := abandoned.Cause.(tapreorg.ForeignBurial)

		return ok && cause.Spend.W.TxHash() == foreign.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.NoError(t, h.escalation())
}

// identitySpec builds a registration spec under a fixed match key,
// satisfied by sat, over the given trigger outpoints: the shape of
// registrations that attach to one another.
func (h *harness) identitySpec(sat *wire.MsgTx, matchKey []byte,
	ops ...wire.OutPoint) tapreorg.RegistrationSpec {

	points := make([]tapreorg.TriggerOutPoint, len(ops))
	for i, op := range ops {
		points[i] = tapreorg.TriggerOutPoint{
			OutPoint:   op,
			PkScript:   stdScript(0x02),
			HeightHint: 1,
		}
	}
	triggers, err := tapreorg.NewTriggerSet(points)
	require.NoError(h.t, err)

	satTxid := sat.TxHash()

	return tapreorg.RegistrationSpec{
		Site:     testSiteID,
		Triggers: triggers,
		MatchData: tapreorg.VersionedBlob{
			Version: 1,
			Data:    satTxid[:],
		},
		Payload:   tapreorg.VersionedBlob{Version: 1},
		MatchKey:  matchKey,
		Threshold: 2,
	}
}

// TestWatcherSweepRebuildsGrownSensor pins the reconciliation sweep's
// second duty: a live anchoring whose registry trigger set has grown
// past what its sensor subscribed to is rebuilt over the enlarged
// set. A union the sensing loop never heard of — here one written
// through the registry directly, as a lost hand-off leaves it —
// would otherwise stay under-sensed until restart.
func TestWatcherSweepRebuildsGrownSensor(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()
	ctx := context.Background()

	opA := wire.OutPoint{Hash: chainhash.Hash{0xf8}, Index: 0}
	opB := wire.OutPoint{Hash: chainhash.Hash{0xf8}, Index: 1}
	sat := h.spendTx(opA, opB)
	matchKey := []byte("lost-hand-off")

	id := h.registerSpec(h.identitySpec(sat, matchKey, opA), nil)
	require.Eventually(t, func() bool {
		return h.sim.SpendSubscribed(opA)
	}, settleTimeout, settleTick)

	again, err := h.store.Register(
		ctx, h.identitySpec(sat, matchKey, opA, opB),
		h.sim.BestHeight(), nil, nil,
	)
	require.NoError(t, err)
	require.Equal(t, id, again)

	require.Eventually(t, func() bool {
		return h.sim.SpendSubscribed(opB)
	}, settleTimeout, settleTick)

	// The rebuilt sensor is whole: the satisfying spend of the full
	// set witnesses through it.
	h.sim.MineBlock(sat)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed" &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.NoError(t, h.escalation())
}

// TestWatcherZeroTriggerHint pins the hint a trigger registered
// without one is subscribed under: the anchoring's registration
// height. The notifier refuses a zero hint outright, so passing it
// through would leave the anchoring blind, and a site that does not
// know when an outpoint was created must not have to guess a height
// so low that the notifier rescans the chain from there.
func TestWatcherZeroTriggerHint(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.sim.MineBlocks(40)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{0xf9}, Index: 0}
	sat := h.spendTx(op)
	spec := h.identitySpec(sat, []byte("zero-hint"), op)
	points := spec.Triggers.OutPoints()
	points[0].HeightHint = 0
	triggers, err := tapreorg.NewTriggerSet(points)
	require.NoError(t, err)
	spec.Triggers = triggers

	registeredAt := h.sim.BestHeight()
	id := h.registerSpec(spec, nil)

	require.Eventually(t, func() bool {
		return h.sim.SpendSubscribed(op)
	}, settleTimeout, settleTick)
	hint, ok := h.sim.SpendHint(op)
	require.True(t, ok)
	require.Equal(t, registeredAt, hint)

	// The sensor is whole: the satisfying spend witnesses through it.
	h.sim.MineBlock(sat)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed"
	})
	require.NoError(t, h.escalation())
}

// TestWatcherNonStandardSpenderScripts pins candidate subscription
// against spenders carrying output scripts the notifier rejects —
// for a foreign spend, the counterparty's choice. A spender whose
// first output is nonstandard must be subscribed under a later,
// parseable output; a spender with no parseable output at all must
// be left pending, not turned into a rebuild-and-fail loop through
// the reconciliation sweep.
func TestWatcherNonStandardSpenderScripts(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	// A foreign spender with OP_RETURN at output zero and a
	// standard output behind it: the watcher must select the
	// parseable script, sense the conflict, and certify the
	// foreign burial through it.
	opA := wire.OutPoint{Hash: chainhash.Hash{0xf4}, Index: 0}
	foreign := wire.NewMsgTx(2)
	foreign.AddTxIn(wire.NewTxIn(&opA, nil, nil))
	foreign.AddTxOut(wire.NewTxOut(0, []byte{txscript.OP_RETURN}))
	foreign.AddTxOut(wire.NewTxOut(1, stdScript(0x03)))
	idA := h.register(2, nil, opA)

	h.sim.MineBlock(foreign)
	h.settleWhere(idA, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "conflicted"
	})

	h.sim.MineBlocks(1)
	h.settleWhere(idA, func(a *tapreorg.Anchoring) bool {
		abandoned, ok := a.Phase.(tapreorg.Abandoned)
		if !ok {
			return false
		}
		cause, ok := abandoned.Cause.(tapreorg.ForeignBurial)

		return ok && cause.Spend.W.TxHash() == foreign.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// A satisfying spender with no parseable output at all cannot
	// be subscribed: its confirmation is never recorded, so the
	// anchoring stays unwitnessed. What must not happen is a
	// resense loop — the spend re-evaluated on every rebuilt
	// sensor, forever.
	opB := wire.OutPoint{Hash: chainhash.Hash{0xf5}, Index: 0}
	unwatchable := wire.NewMsgTx(2)
	unwatchable.AddTxIn(wire.NewTxIn(&opB, nil, nil))
	unwatchable.AddTxOut(wire.NewTxOut(0, []byte{txscript.OP_RETURN}))
	idB := h.register(2, []*wire.MsgTx{unwatchable}, opB)

	h.sim.MineBlock(unwatchable)
	require.Eventually(t, func() bool {
		return h.site.evaluations(unwatchable.TxHash()) == 1
	}, settleTimeout, settleTick)

	// Dozens of scan intervals pass without a re-evaluation.
	require.Never(t, func() bool {
		return h.site.evaluations(unwatchable.TxHash()) > 1
	}, 1*time.Second, settleTick)

	anchoring, err := h.store.GetAnchoring(context.Background(), idB)
	require.NoError(t, err)
	require.Equal(t, "unwitnessed", phaseKind(anchoring.Phase))
	require.Empty(t, anchoring.Spends)
	require.NoError(t, h.escalation())
}

// TestWatcherCallbackPanicsContained proves the containment boundary
// around per-site code: a panic in any site callback — predicate,
// delivery handler, delivery listener, effect handler — is that one
// callback's failure, entering the ordinary retry paths, never a
// daemon crash. Uncontained, every stage here would kill a watcher
// goroutine, and the predicate case would recur on each restart via
// historical dispatch.
func TestWatcherCallbackPanicsContained(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	ctx := context.Background()

	// Three listeners, registered before Start: one panics on every
	// delivery, one blocks forever, one records. Convergence and
	// the recording listener must be unaffected by the other two.
	var (
		notifiedMu sync.Mutex
		notified   = make(map[tapreorg.AnchoringID]bool)
	)
	require.NoError(t, h.watcher.RegisterDeliveryListener(func(
		tapreorg.AnchoringID, tapreorg.SiteID, tapreorg.Phase) {

		panic("listener boom")
	}))
	block := make(chan struct{})
	require.NoError(t, h.watcher.RegisterDeliveryListener(func(
		tapreorg.AnchoringID, tapreorg.SiteID, tapreorg.Phase) {

		<-block
	}))
	require.NoError(t, h.watcher.RegisterDeliveryListener(func(
		id tapreorg.AnchoringID, _ tapreorg.SiteID,
		_ tapreorg.Phase) {

		notifiedMu.Lock()
		defer notifiedMu.Unlock()
		notified[id] = true
	}))

	// An effect handler that panics until the defect is fixed.
	var (
		effectPanic    atomic.Bool
		boomDispatched atomic.Int32
	)
	effectPanic.Store(true)
	require.NoError(t, h.watcher.RegisterEffectHandler(
		"boom",
		func(context.Context, fn.Option[tapreorg.AnchoringID],
			tapreorg.VersionedBlob) error {

			if effectPanic.Load() {
				panic("effect boom")
			}
			boomDispatched.Add(1)

			return nil
		},
	))

	h.start()
	defer close(block)

	// Stage 1: the predicate panics on a discovered candidate. The
	// sensing goroutine survives and the candidate is left
	// unevaluated — a deterministic defect, surfaced loudly, not
	// retried in place.
	op1 := wire.OutPoint{Hash: chainhash.Hash{0xeb}, Index: 0}
	sat1 := h.spendTx(op1)
	id1 := h.register(2, []*wire.MsgTx{sat1}, op1)

	h.site.evalPanic.Store(true)
	h.sim.MineBlock(sat1)
	time.Sleep(20 * settleTick)

	a1, err := h.store.GetAnchoring(ctx, id1)
	require.NoError(t, err)
	require.True(t, tapreorg.PhaseEqual(tapreorg.Unwitnessed{}, a1.Phase))

	// The defect is fixed and the sensor rebuilds (severed streams
	// stand in for the restart): historical dispatch re-delivers
	// the spend, and sensing proceeds.
	h.site.evalPanic.Store(false)
	h.sim.SeverSubscriptionStreams()
	h.settleWhere(id1, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed" &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// Stage 2: the delivery handler panics. The delivery fails into
	// the ordinary backoff bookkeeping — transaction rolled back,
	// attempts counted — and succeeds once the site recovers.
	op2 := wire.OutPoint{Hash: chainhash.Hash{0xec}, Index: 0}
	sat2 := h.spendTx(op2)
	id2 := h.register(2, []*wire.MsgTx{sat2}, op2)

	h.site.panicking.Store(true)
	h.sim.MineBlock(sat2)
	require.Eventually(t, func() bool {
		a, err := h.store.GetAnchoring(ctx, id2)
		return err == nil && a.DeliveryAttempts > 0
	}, settleTimeout, settleTick)

	h.site.panicking.Store(false)
	h.settleWhere(id2, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed" &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// The surviving listener was notified for both anchorings,
	// panicking and blocking peers notwithstanding.
	require.Eventually(t, func() bool {
		notifiedMu.Lock()
		defer notifiedMu.Unlock()

		return notified[id1] && notified[id2]
	}, settleTimeout, settleTick)

	// Stage 3: the effect handler panics. Dispatch fails into
	// backoff and completes once the defect is fixed.
	op3 := wire.OutPoint{Hash: chainhash.Hash{0xed}, Index: 0}
	h.registerEnqueuing(2, op3, func(ctx context.Context,
		tx tapreorg.RegistryTx, id tapreorg.AnchoringID) error {

		return tx.EnqueueEffect(ctx, tapreorg.OutboxEffect{
			Kind:      "boom",
			Anchoring: fn.Some(id),
			Payload:   tapreorg.VersionedBlob{Version: 1},
		})
	})

	require.Eventually(t, func() bool {
		effects, err := h.store.PendingEffects(
			ctx, time.Now().Add(time.Hour), 10,
		)
		if err != nil {
			return false
		}
		for _, effect := range effects {
			if effect.Effect.Kind == "boom" &&
				effect.Attempts > 0 {

				return true
			}
		}

		return false
	}, settleTimeout, settleTick)

	effectPanic.Store(false)
	require.Eventually(t, func() bool {
		return boomDispatched.Load() == 1
	}, settleTimeout, settleTick)
	require.NoError(t, h.escalation())
}

// TestWatcherEffectDispatchDeadline pins the dispatch deadline: all
// effects share one serial dispatcher, so a dispatch attempt that
// never returns — a remote push against a connection that stays open
// without answering — must be cut off at the deadline and fail into
// the ordinary backoff bookkeeping, leaving the effects behind it
// dispatchable.
func TestWatcherEffectDispatchDeadline(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	// A handler that returns only when its context is cancelled:
	// the shape of a hung remote call.
	var hangAttempts atomic.Int32
	require.NoError(t, h.watcher.RegisterEffectHandler(
		"hang",
		func(ctx context.Context, _ fn.Option[tapreorg.AnchoringID],
			_ tapreorg.VersionedBlob) error {

			<-ctx.Done()
			hangAttempts.Add(1)

			return ctx.Err()
		},
	))

	h.start()

	// Enqueue a hanging effect with a well-behaved effect behind it
	// in dispatch order.
	op := wire.OutPoint{Hash: chainhash.Hash{0xee}, Index: 0}
	h.registerEnqueuing(2, op, func(ctx context.Context,
		tx tapreorg.RegistryTx, id tapreorg.AnchoringID) error {

		err := tx.EnqueueEffect(ctx, tapreorg.OutboxEffect{
			Kind:      "hang",
			Anchoring: fn.Some(id),
			Payload:   tapreorg.VersionedBlob{Version: 1},
		})
		if err != nil {
			return err
		}

		return tx.EnqueueEffect(ctx, tapreorg.OutboxEffect{
			Kind:      "test",
			Anchoring: fn.Some(id),
			Payload:   tapreorg.VersionedBlob{Version: 1},
		})
	})

	// The deadline converts the hang into failed attempts that back
	// off and retry rather than parking the dispatcher.
	require.Eventually(t, func() bool {
		return hangAttempts.Load() >= 2
	}, settleTimeout, settleTick)

	// The effect queued behind the hanging one still dispatches
	// (registration's own phase-1 effect is the first of the two).
	require.Eventually(t, func() bool {
		return h.effects.Load() == 2
	}, settleTimeout, settleTick)
	require.NoError(t, h.escalation())
}

// TestWatcherEffectNotReady pins the not-ready dispatch policy: a
// handler that reports ErrEffectNotReady leaves its effect pending
// exactly as enqueued — no failure recorded, no backoff — and the
// effect dispatches once the handler finds its inputs, after the
// owning subsystem kicks the outbox.
func TestWatcherEffectNotReady(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	ctx := context.Background()

	var (
		ready               atomic.Bool
		attempts, completed atomic.Int32
	)
	require.NoError(t, h.watcher.RegisterEffectHandler(
		"gated",
		func(context.Context, fn.Option[tapreorg.AnchoringID],
			tapreorg.VersionedBlob) error {

			attempts.Add(1)
			if !ready.Load() {
				return fmt.Errorf("inputs pending: %w",
					tapreorg.ErrEffectNotReady)
			}
			completed.Add(1)

			return nil
		},
	))

	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{0xed}, Index: 0}
	h.registerEnqueuing(2, op, func(ctx context.Context,
		tx tapreorg.RegistryTx, id tapreorg.AnchoringID) error {

		return tx.EnqueueEffect(ctx, tapreorg.OutboxEffect{
			Kind:      "gated",
			Anchoring: fn.Some(id),
			Payload:   tapreorg.VersionedBlob{Version: 1},
		})
	})

	pendingGated := func() []*tapreorg.StoredEffect {
		pending, err := h.store.PendingEffects(ctx, time.Now(), 10)
		require.NoError(t, err)

		var gated []*tapreorg.StoredEffect
		for _, effect := range pending {
			if effect.Effect.Kind == "gated" {
				gated = append(gated, effect)
			}
		}

		return gated
	}

	// Every pass re-runs the handler, and every run leaves the effect
	// as it was enqueued: pending, with no attempt on record.
	require.Eventually(t, func() bool {
		return attempts.Load() >= 3
	}, settleTimeout, settleTick)
	gated := pendingGated()
	require.Len(t, gated, 1)
	require.Zero(t, gated[0].Attempts)
	require.Zero(t, completed.Load())

	// The inputs land: the owning subsystem kicks the outbox and the
	// effect dispatches.
	ready.Store(true)
	h.watcher.KickOutbox()
	require.Eventually(t, func() bool {
		return completed.Load() == 1
	}, settleTimeout, settleTick)
	require.Eventually(t, func() bool {
		return len(pendingGated()) == 0
	}, settleTimeout, settleTick)
	require.NoError(t, h.escalation())
}

// TestWatcherEffectDispatchPerHandlerDeadline pins the per-handler
// dispatch policy: a handler registered unbounded, and one registered
// with its own longer deadline, both outlive the configured default
// and complete in a single attempt. The default still bounds every
// other handler (TestWatcherEffectDispatchDeadline).
func TestWatcherEffectDispatchPerHandlerDeadline(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	// Each handler works well past the harness's 100ms default and
	// records whether the attempt was cut short by its context.
	const work = 300 * time.Millisecond
	var attempts, cutShort, completed atomic.Int32
	slow := func(ctx context.Context, _ fn.Option[tapreorg.AnchoringID],
		_ tapreorg.VersionedBlob) error {

		attempts.Add(1)
		select {
		case <-time.After(work):
			completed.Add(1)
			return nil

		case <-ctx.Done():
			cutShort.Add(1)
			return ctx.Err()
		}
	}
	require.NoError(t, h.watcher.RegisterEffectHandler(
		"unbounded", slow, tapreorg.WithDispatchTimeout(0),
	))
	require.NoError(t, h.watcher.RegisterEffectHandler(
		"long", slow, tapreorg.WithDispatchTimeout(time.Second),
	))

	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{0xef}, Index: 0}
	h.registerEnqueuing(2, op, func(ctx context.Context,
		tx tapreorg.RegistryTx, id tapreorg.AnchoringID) error {

		for _, kind := range []tapreorg.EffectKind{
			"unbounded", "long",
		} {
			effect := tapreorg.OutboxEffect{
				Kind:      kind,
				Anchoring: fn.Some(id),
				Payload: tapreorg.VersionedBlob{
					Version: 1,
				},
			}
			err := tx.EnqueueEffect(ctx, effect)
			if err != nil {
				return err
			}
		}

		return nil
	})

	require.Eventually(t, func() bool {
		return completed.Load() == 2
	}, settleTimeout, settleTick)
	require.EqualValues(t, 2, attempts.Load())
	require.Zero(t, cutShort.Load())
	require.NoError(t, h.escalation())
}

// TestWatcherLateRegistrationRefused pins the registration window:
// sites, listeners and effect handlers register strictly before
// Start, which is what lets the loops read their tables without
// synchronization.
func TestWatcherLateRegistrationRefused(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	require.Error(t, h.watcher.RegisterSite(newTestSite("late")))
	require.Error(t, h.watcher.RegisterEffectHandler(
		"late",
		func(context.Context, fn.Option[tapreorg.AnchoringID],
			tapreorg.VersionedBlob) error {

			return nil
		},
	))
	require.Error(t, h.watcher.RegisterDeliveryListener(func(
		tapreorg.AnchoringID, tapreorg.SiteID, tapreorg.Phase) {
	}))
}

// TestWatcherDefaultThreshold pins the policy hand-off: a
// registration that leaves the threshold unset inherits the
// watcher's configured default depth rather than silently
// registering at whatever a site hardcoded.
func TestWatcherDefaultThreshold(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{0xee}, Index: 0}
	id := h.register(0, nil, op)

	a, err := h.store.GetAnchoring(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, uint32(tapreorg.DefaultActThreshold), a.Threshold)
}

// TestWatcherRestageLossHeals injects a write failure into the exact
// gap the restage path leaves: the parent's phase advances durably,
// then the staging write toward its dependent fails. The loss must
// self-heal — the child's re-adoption rebuilds its incoming staging
// from the parent's durable phase — and the cascade must complete as
// if the write had never failed.
func TestWatcherRestageLossHeals(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	parentOp := wire.OutPoint{Hash: chainhash.Hash{0xea}, Index: 0}
	pForm1 := h.spendTx(parentOp)
	pForm2 := h.spendTx(parentOp)
	parentID := h.register(4, []*wire.MsgTx{pForm1, pForm2}, parentOp)

	h.sim.MineBlock(pForm1)
	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed"
	})

	childOp := wire.OutPoint{Hash: pForm1.TxHash(), Index: 0}
	satChild := h.spendTx(childOp)
	childID := h.register(2, []*wire.MsgTx{satChild}, childOp)

	// The next staging write fails, losing the parent's restage
	// toward the child exactly as a transient database error would.
	h.registry.FailNextCalls(1, "StageForeclosure")

	h.sim.Reorg(1, []*wire.MsgTx{pForm2})
	h.sim.MineBlocks(1)

	// The child heals through re-adoption and abandons by cascade
	// once the notifier certifies the foreclosing form at the
	// child's own threshold.
	h.settleWhere(childID, func(a *tapreorg.Anchoring) bool {
		abandoned, ok := a.Phase.(tapreorg.Abandoned)
		if !ok {
			return false
		}
		cause, ok := abandoned.Cause.(tapreorg.Foreclosed)

		return ok && cause.Parent == parentID &&
			cause.W.TxHash() == pForm2.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.NoError(t, h.escalation())
}

// TestWatcherStaleForeclosureCertification constructs the hostile
// ordering for the third location-verify defence: a foreclosure
// certification delivered after the chain has displaced the
// certified transaction — and after the parent has returned to the
// very form the child depends on. Absorbing the stale certification
// would abandon a child whose premises hold; it must be refused, and
// the foreclosure cleared.
func TestWatcherStaleForeclosureCertification(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	parentOp := wire.OutPoint{Hash: chainhash.Hash{0xe8}, Index: 0}
	pForm1 := h.spendTx(parentOp)
	pForm2 := h.spendTx(parentOp)
	parentID := h.register(4, []*wire.MsgTx{pForm1, pForm2}, parentOp)

	h.sim.MineBlock(pForm1)
	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed"
	})

	childOp := wire.OutPoint{Hash: pForm1.TxHash(), Index: 0}
	satChild := h.spendTx(childOp)
	childID := h.register(2, []*wire.MsgTx{satChild}, childOp)

	// The parent re-witnesses in a different form; foreclosure is
	// staged on the child, awaiting certification.
	h.sim.Reorg(1, []*wire.MsgTx{pForm2})
	require.Eventually(t, func() bool {
		view, err := h.store.ChainView(
			context.Background(), childID,
		)
		return err == nil && view.Foreclosure.IsSome()
	}, settleTimeout, settleTick)

	// Freeze delivery, reach the child's threshold — dispatching
	// the certification — then rewind the world to the form the
	// child depends on. On release, the certification describes a
	// transaction the chain has since disowned.
	h.sim.HoldDeliveries()
	h.sim.MineBlocks(1)
	h.sim.Reorg(2, []*wire.MsgTx{pForm1}, nil)
	h.sim.ReleaseDeliveries()

	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		w, ok := a.Phase.(tapreorg.Witnessed)
		return ok && w.W.TxHash() == pForm1.TxHash()
	})
	h.settleConverged(childID, tapreorg.Unwitnessed{})

	// The stale certification was refused: the child was never
	// abandoned, and whatever staging residue the edge carries, it
	// is not certified — certification is the only absorbing bit,
	// and it must never rest on a displaced location.
	require.NotContains(t, h.site.deliveries(childID), "abandoned")
	view, err := h.store.ChainView(context.Background(), childID)
	require.NoError(t, err)
	if fc := view.Foreclosure.UnwrapToPtr(); fc != nil {
		require.False(t, fc.ActCertified)
	}
	require.NoError(t, h.escalation())
}

// TestWatcherRestartReorgBelowForeclosureHeight covers a re-org during
// downtime below a staged foreclosure's recorded height. The
// staged foreclosing evidence records the height it certified against
// before a restart; a re-org during the downtime replays the
// foreclosing transaction lower. The recovered child's certification
// subscription must hint from the parent's trigger set, not from the
// staged evidence's recorded height: a hint above the transaction's
// new location would hide it from the historical rescan for good on
// backends without a transaction index, and the cascade would never
// certify. The parent is terminal (abandoned) throughout recovery, so
// no parent-side rederivation can correct the staging: the
// subscription's own hint is the only path to certification.
func TestWatcherRestartReorgBelowForeclosureHeight(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	parentOp := wire.OutPoint{Hash: chainhash.Hash{0xfb}, Index: 0}
	pForm1 := h.spendTx(parentOp)
	parentID := h.register(2, []*wire.MsgTx{pForm1}, parentOp)

	h.sim.MineBlock(pForm1)
	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed"
	})

	childOp := wire.OutPoint{Hash: pForm1.TxHash(), Index: 0}
	satChild := h.spendTx(childOp)
	childID := h.register(3, []*wire.MsgTx{satChild}, childOp)

	// A foreign spend displaces the parent's form one block above
	// the baseline and buries at the parent's threshold: the parent
	// abandons, and its terminal delivery settles the child's edge
	// with the foreign spend staged on-chain, recorded at its
	// current height. The child's own threshold stays out of reach.
	foreign := h.spendTx(parentOp)
	h.sim.Reorg(1, nil, []*wire.MsgTx{foreign})
	h.sim.MineBlocks(1)

	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		abandoned, ok := a.Phase.(tapreorg.Abandoned)
		if !ok {
			return false
		}
		cause, ok := abandoned.Cause.(tapreorg.ForeignBurial)

		return ok && cause.Spend.W.TxHash() == foreign.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.Eventually(t, func() bool {
		view, err := h.store.ChainView(context.Background(), childID)
		if err != nil {
			return false
		}
		fc := view.Foreclosure.UnwrapToPtr()

		return fc != nil && fc.OnChain && !fc.ActCertified &&
			fc.W.TxHash() == foreign.TxHash()
	}, settleTimeout, settleTick)

	// Down. The re-org replays the foreclosing transaction below the
	// staged evidence's recorded height, where it already holds the
	// child's threshold depth.
	require.NoError(t, h.watcher.Stop())
	h.sim.Reorg(3, []*wire.MsgTx{foreign}, nil, nil)

	h.watcher = h.newWatcher()
	require.NoError(t, h.watcher.Start())

	// Recovery must find the foreclosing transaction at its new
	// location, certify it, and abandon the child by cascade.
	h.settleWhere(childID, func(a *tapreorg.Anchoring) bool {
		abandoned, ok := a.Phase.(tapreorg.Abandoned)
		if !ok {
			return false
		}
		cause, ok := abandoned.Cause.(tapreorg.Foreclosed)

		return ok && cause.Parent == parentID &&
			cause.W.TxHash() == foreign.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.NoError(t, h.escalation())
}

// TestWatcherBuriedParentRestage pins the restage path against a
// buried parent: a parent buried in a different form than the child's
// edge depends on settles the edge with the burying witness staged
// on-chain, and the child's re-adoption must reproduce that staging
// from the parent's durable phase — never downgrade it.
func TestWatcherBuriedParentRestage(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	parentOp := wire.OutPoint{Hash: chainhash.Hash{0xfc}, Index: 0}
	pForm1 := h.spendTx(parentOp)
	pForm2 := h.spendTx(parentOp)
	parentID := h.register(2, []*wire.MsgTx{pForm1, pForm2}, parentOp)

	h.sim.MineBlock(pForm1)
	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed"
	})

	// The child depends on the parent's first form, at a threshold
	// deep enough that its own foreclosure certification stays out
	// of reach: the staged evidence below remains uncertified, and
	// therefore writable by the restage under test.
	childOp := wire.OutPoint{Hash: pForm1.TxHash(), Index: 0}
	satChild := h.spendTx(childOp)
	childID := h.register(6, []*wire.MsgTx{satChild}, childOp)

	// The parent's other form displaces the first and buries at the
	// parent's threshold: the terminal delivery settles the child's
	// edge with the burying witness staged on-chain.
	h.sim.Reorg(1, []*wire.MsgTx{pForm2})
	h.sim.MineBlocks(1)

	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		buried, ok := a.Phase.(tapreorg.Buried)

		return ok && buried.W.TxHash() == pForm2.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	stagedForeclosure := func() *tapreorg.ForeclosureEvent {
		view, err := h.store.ChainView(context.Background(), childID)
		if err != nil {
			return nil
		}

		return view.Foreclosure.UnwrapToPtr()
	}
	require.Eventually(t, func() bool {
		fc := stagedForeclosure()
		return fc != nil && fc.OnChain && !fc.ActCertified &&
			fc.W.TxHash() == pForm2.TxHash()
	}, settleTimeout, settleTick)

	// Process death and recovery: the child re-adopts and rebuilds
	// its incoming staging from the parent's durable Buried phase.
	// Across many reconciliation sweeps, the staged evidence must
	// never flip off-chain.
	h.restart()
	require.Never(t, func() bool {
		fc := stagedForeclosure()
		return fc != nil && !fc.OnChain
	}, 2*time.Second, settleTick)

	fc := stagedForeclosure()
	require.NotNil(t, fc)
	require.True(t, fc.OnChain)
	require.Equal(t, pForm2.TxHash(), fc.W.TxHash())
	require.NoError(t, h.escalation())
}

// TestWatcherForeclosureOffChainDowngrade pins the restage downgrade
// arm: when the chain disowns the parent's witness entirely, staged
// on-chain foreclosing evidence on the child's edge must be
// downgraded to off-chain — kept, but stripped of its chain claim.
func TestWatcherForeclosureOffChainDowngrade(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	// The parent's threshold keeps it live throughout; the child's
	// keeps the staged evidence below uncertified, and therefore
	// writable by the restage under test.
	parentOp := wire.OutPoint{Hash: chainhash.Hash{0xfd}, Index: 0}
	pForm1 := h.spendTx(parentOp)
	pForm2 := h.spendTx(parentOp)
	parentID := h.register(6, []*wire.MsgTx{pForm1, pForm2}, parentOp)

	h.sim.MineBlock(pForm1)
	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed"
	})

	childOp := wire.OutPoint{Hash: pForm1.TxHash(), Index: 0}
	satChild := h.spendTx(childOp)
	childID := h.register(6, []*wire.MsgTx{satChild}, childOp)

	// The parent re-witnesses in its other form: foreclosure is
	// staged on-chain against the child.
	h.sim.Reorg(1, []*wire.MsgTx{pForm2})

	stagedForeclosure := func() *tapreorg.ForeclosureEvent {
		view, err := h.store.ChainView(context.Background(), childID)
		if err != nil {
			return nil
		}

		return view.Foreclosure.UnwrapToPtr()
	}
	require.Eventually(t, func() bool {
		fc := stagedForeclosure()
		return fc != nil && fc.OnChain && !fc.ActCertified &&
			fc.W.TxHash() == pForm2.TxHash()
	}, settleTimeout, settleTick)

	// A shrinking re-org disowns the second form as well: the parent
	// returns to Unwitnessed, and the staged evidence — a witness
	// the chain no longer carries — must follow it off-chain without
	// being discarded.
	h.sim.Reorg(1)

	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "unwitnessed"
	})
	require.Eventually(t, func() bool {
		fc := stagedForeclosure()
		return fc != nil && !fc.OnChain && !fc.ActCertified &&
			fc.W.TxHash() == pForm2.TxHash()
	}, settleTimeout, settleTick)
	require.NoError(t, h.escalation())
}

// TestWatcherRapid is the randomized torture: arbitrary interleavings
// of mining, re-orgs (replaced-block re-inclusion and shrinking
// included), quiet blocks, restarts, severed and erroring streams,
// injected notifier faults, duplicated reports and held-back (stale)
// deliveries against one anchoring per iteration, with the expected
// phase computed from the simulated chain by an independent oracle,
// terminal absorption pinned, and any critical escalation a failure.
//
// The harness (database, sim, watcher) is shared across iterations
// for speed; each iteration uses fresh outpoints and candidates, so
// prior iterations' anchorings cannot influence its assertions.
func TestWatcherRapid(t *testing.T) {
	h := newHarness(t)
	h.start()

	var iteration uint32
	rapid.Check(t, func(rt *rapid.T) {
		iteration++

		var opHash chainhash.Hash
		opHash[0] = byte(iteration)
		opHash[1] = byte(iteration >> 8)
		opHash[31] = 0xee
		op := wire.OutPoint{Hash: opHash, Index: 0}

		formA := h.spendTx(op)
		formB := h.spendTx(op)
		foreign := h.spendTx(op)
		candidates := []*wire.MsgTx{formA, formB, foreign}

		threshold := uint32(rapid.IntRange(2, 4).Draw(rt, "threshold"))
		id := h.register(
			threshold, []*wire.MsgTx{formA, formB}, op,
		)

		// onChainSpender reports which candidate currently spends
		// the trigger on the sim chain, if any.
		onChainSpender := func() (*wire.MsgTx, uint32, bool) {
			for _, tx := range candidates {
				height, ok := h.sim.TxHeight(tx.TxHash())
				if ok {
					return tx, height, true
				}
			}

			return nil, 0, false
		}

		// oracle computes the expected phase kind (and witness,
		// when applicable) from the sim chain directly.
		oracle := func() (string, chainhash.Hash) {
			spender, height, ok := onChainSpender()
			if !ok {
				return "unwitnessed", chainhash.Hash{}
			}

			depth := h.sim.BestHeight() - height + 1
			satisfying := spender.TxHash() != foreign.TxHash()

			switch {
			case satisfying && depth >= threshold:
				return "buried", spender.TxHash()
			case satisfying:
				return "witnessed", spender.TxHash()
			case depth >= threshold:
				return "abandoned", chainhash.Hash{}
			default:
				return "conflicted", chainhash.Hash{}
			}
		}

		// Once the registry reaches a terminal phase, it must
		// never leave it, whatever the chain does.
		var pinned tapreorg.Phase

		// The chain may make a terminal phase sensible only
		// transiently (act depth reached, then erased by a
		// reorg deeper than the threshold — explicitly
		// unrecoverable by design). Whether sensing observed
		// the transient is a race both sides of which are
		// legitimate, so the oracle accepts any terminal the
		// chain ever made sensible, keyed by kind and deciding
		// transaction.
		possibleTerminals := make(map[string]bool)

		terminalKey := func(p tapreorg.Phase) string {
			switch phase := p.(type) {
			case tapreorg.Buried:
				return "buried:" + phase.W.TxHash().String()

			case tapreorg.Abandoned:
				cause := phase.Cause
				burial, ok := cause.(tapreorg.ForeignBurial)
				if !ok {
					return "abandoned:foreclosed"
				}
				txid := burial.Spend.W.TxHash()

				return "abandoned:" + txid.String()

			default:
				return ""
			}
		}

		// recordPossible captures the current chain state's
		// terminal reading, if any. It must run after every
		// chain state the notifier dispatched from, including
		// states an action passes through on its way to its
		// final one: sensing may have observed any of them.
		recordPossible := func() {
			kind, witness := oracle()
			switch kind {
			case "buried":
				possibleTerminals["buried:"+
					witness.String()] = true

			case "abandoned":
				txid := foreign.TxHash()
				possibleTerminals["abandoned:"+
					txid.String()] = true
			}
		}

		converged := func(a *tapreorg.Anchoring) bool {
			if pinned != nil {
				return tapreorg.PhaseEqual(
					a.Phase, pinned,
				) && tapreorg.PhaseEqual(
					a.DeliveredPhase, pinned,
				)
			}

			if !tapreorg.PhaseEqual(
				a.DeliveredPhase, a.Phase,
			) {

				return false
			}

			// A terminal registry phase is acceptable exactly
			// when the chain made it sensible at some point;
			// it pins from here on.
			if tapreorg.IsTerminal(a.Phase) {
				if !possibleTerminals[terminalKey(a.Phase)] {
					return false
				}
				pinned = a.Phase

				return true
			}

			wantKind, wantWitness := oracle()
			if phaseKind(a.Phase) != wantKind {
				return false
			}
			if w, ok := a.Phase.(tapreorg.Witnessed); ok &&
				w.W.TxHash() != wantWitness {

				return false
			}

			return true
		}

		settle := func() {
			deadline := time.Now().Add(settleTimeout)
			flushAt := time.Now().Add(settleTimeout / 3)
			for time.Now().Before(deadline) {
				// A stalled settle may be reading through
				// pinned pool snapshots; evict them.
				if time.Now().After(flushAt) {
					h.flushPool()
					flushAt = time.Now().Add(
						settleTimeout / 3,
					)
				}

				a, err := h.store.GetAnchoring(
					context.Background(), id,
				)
				if err != nil {
					// Under heavy concurrent load the
					// WAL-mode read can transiently
					// miss a just-committed row or
					// exhaust the busy-retry budget;
					// the poll simply retries, and a
					// persistent condition still
					// times out below. Anything else
					// is a real failure.
					transient := errors.Is(
						err,
						tapreorg.ErrAnchoringNotFound,
					) || errors.Is(
						err,
						tapdb.ErrRetriesExceeded,
					)
					require.True(rt, transient,
						"unexpected error: %v", err)
					time.Sleep(settleTick)
					continue
				}
				if converged(a) {
					return
				}

				time.Sleep(settleTick)
			}

			a, getErr := h.store.GetAnchoring(
				context.Background(), id,
			)
			var state, spends string
			if a != nil {
				state = fmt.Sprintf(
					"phase=%v delivered=%v stuck=%v",
					a.Phase, a.DeliveredPhase, a.Stuck,
				)
				for _, sp := range a.Spends {
					spends += fmt.Sprintf(
						" [%v on=%v cert=%v @%d]",
						sp.W.TxHash(), sp.OnChain,
						sp.ActCertified,
						sp.W.Height(),
					)
				}
			} else {
				state = fmt.Sprintf("unreadable: %v", getErr)
			}
			var total, maxID, exists int
			_ = h.rawDB.QueryRow(
				"SELECT count(*), coalesce(max(id), 0) "+
					"FROM reorg_anchorings",
			).Scan(&total, &maxID)
			_ = h.rawDB.QueryRow(
				"SELECT count(*) FROM reorg_anchorings "+
					"WHERE id = ?", int64(id),
			).Scan(&exists)

			// The same reads through a brand-new handle on
			// the same file distinguish pool-connection
			// snapshot pinning from genuine data loss.
			var fTotal, fMax, fExists int
			freshDB, freshErr := sql.Open("sqlite", h.dbPath)
			if freshErr == nil {
				_ = freshDB.QueryRow(
					"SELECT count(*), "+
						"coalesce(max(id), 0) "+
						"FROM reorg_anchorings",
				).Scan(&fTotal, &fMax)
				_ = freshDB.QueryRow(
					"SELECT count(*) "+
						"FROM reorg_anchorings "+
						"WHERE id = ?", int64(id),
				).Scan(&fExists)
				_ = freshDB.Close()
			}

			wantKind, wantWitness := oracle()
			rt.Fatalf("never settled: id=%d raw(total=%d "+
				"max=%d exists=%d) fresh(total=%d max=%d "+
				"exists=%d) registry %s; oracle "+
				"kind=%v witness=%v; pinned=%v; best=%d; "+
				"formA@%v formB@%v foreign@%v; spends:%s",
				id, total, maxID, exists, fTotal, fMax,
				fExists, state,
				wantKind, wantWitness, pinned,
				h.sim.BestHeight(),
				txHeightOf(h.sim, formA),
				txHeightOf(h.sim, formB),
				txHeightOf(h.sim, foreign), spends)
		}

		settle()

		numActions := rapid.IntRange(2, 8).Draw(rt, "numActions")
		for i := 0; i < numActions; i++ {
			label := fmt.Sprintf("action%d", i)

			switch rapid.IntRange(0, 9).Draw(rt, label) {
			// Quiet block.
			case 0:
				h.sim.MineBlocks(1)

			// Mine a candidate, if the trigger is unspent on
			// the current chain (the whole-set rule is a
			// property of one chain); a quiet block
			// otherwise.
			case 1:
				if _, _, spent := onChainSpender(); spent {
					h.sim.MineBlocks(1)
					break
				}
				pick := rapid.IntRange(0, 2).Draw(
					rt, label+".pick",
				)
				h.sim.MineBlock(candidates[pick])

			// Reorg, optionally substituting a different
			// candidate for whatever fell out. A fresh chain
			// has nothing to reorg; mine instead.
			case 2:
				depth := rapid.IntRange(1, 3).Draw(
					rt, label+".depth",
				)
				if depth > h.sim.Length() {
					depth = h.sim.Length()
				}
				if depth == 0 {
					h.sim.MineBlocks(1)
					recordPossible()
					settle()
					continue
				}
				replacement := make(
					[][]*wire.MsgTx, depth,
				)

				// When the reorg evicts the current
				// spender, it may re-include it at a
				// different slot in the replacement range
				// — the block-replaced shape lnd reports
				// as a re-org followed by a fresh
				// confirmation. Whole-set safe: the only
				// spender was in the truncated range.
				spender, sHeight, spent := onChainSpender()
				if spent &&
					sHeight > h.sim.BestHeight()-
						uint32(depth) &&
					rapid.Bool().Draw(
						rt, label+".reinclude",
					) {

					slot := rapid.IntRange(
						0, depth-1,
					).Draw(rt, label+".slot")
					replacement[slot] = []*wire.MsgTx{
						spender,
					}
				}

				h.sim.Reorg(depth, replacement...)
				if _, _, spent := onChainSpender(); !spent &&
					rapid.Bool().Draw(
						rt, label+".substitute",
					) {

					pick := rapid.IntRange(0, 2).Draw(
						rt, label+".pick",
					)
					h.sim.MineBlock(candidates[pick])
				}

			// Bury whatever stands.
			case 3:
				h.sim.MineBlocks(int(threshold))

			// Process death and recovery.
			case 4:
				h.restart()

			// Transient notifier distress: a burst of
			// injected call failures with subscription
			// streams severed or erroring. Sensing must
			// re-establish itself through the reconciliation
			// sweep, and none of it may escalate as critical.
			case 5:
				h.sim.FailNextCalls(rapid.IntRange(
					1, 3,
				).Draw(rt, label+".faults"))
				if rapid.Bool().Draw(rt, label+".sever") {
					h.sim.SeverSubscriptionStreams()
				} else {
					h.sim.ErrorSubscriptionStreams(
						errors.New("injected " +
							"stream error"),
					)
				}

			// Shrink: a shorter dominant chain, the best
			// height decreasing.
			case 6:
				depth := rapid.IntRange(1, 2).Draw(
					rt, label+".shrink",
				)
				if depth > h.sim.Length() {
					depth = h.sim.Length()
				}
				if depth == 0 {
					h.sim.MineBlocks(1)
					break
				}
				h.sim.Reorg(depth)

			// Duplicate standing reports: the at-least-once
			// notifier boundary.
			case 7:
				h.sim.ReplayLastEvents()

			// A lagging consumer: the chain moves more than
			// once before any of it is delivered, so every
			// event arrives describing a stale world.
			case 8:
				h.sim.HoldDeliveries()
				h.sim.MineBlocks(1)

				// The block may have buried a candidate that
				// the re-org below unburies again. The held
				// act report still arrives, stale, and act
				// certification is sticky, so that transient
				// reading is a legitimate terminal too.
				recordPossible()
				if h.sim.Length() > 0 && rapid.Bool().Draw(
					rt, label+".alsoReorg",
				) {

					// The notifier dispatched from the
					// state the block just made, so a
					// terminal it made sensible must be
					// admitted even though the re-org
					// erases it before the action ends.
					recordPossible()
					h.sim.Reorg(1)
				}
				h.sim.ReleaseDeliveries()

			// Transient database distress: registry writes
			// and reads fail mid-flight; resense and the
			// scan loops heal it.
			case 9:
				h.registry.FailNextCalls(rapid.IntRange(
					1, 3,
				).Draw(rt, label+".dbfaults"), "")
			}

			recordPossible()

			// Settling after every action serializes the
			// world; skipping it sometimes leaves events from
			// this action still in flight when the next lands,
			// making event-ordering races reachable. The last
			// action always settles.
			if i == numActions-1 || rapid.Bool().Draw(
				rt, label+".settle",
			) {

				settle()
			}
		}

		if err := h.escalation(); err != nil {
			rt.Fatalf("critical escalation during scenario "+
				"of transient faults: %v", err)
		}

		// Leftover injected faults would bleed into the next
		// iteration's registration, failing harness calls rather
		// than watcher paths.
		h.registry.FailNextCalls(0, "")
	})
}
