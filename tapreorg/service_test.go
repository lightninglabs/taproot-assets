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
		tapreorg.AnchoringID) error) (tapreorg.AnchoringID, error) {

	if err := f.failNext("Register"); err != nil {
		return 0, err
	}

	return f.Registry.Register(ctx, spec, createdHeight, phase1)
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

func (f *faultRegistry) Withdraw(ctx context.Context,
	id tapreorg.AnchoringID,
	onWithdraw func(context.Context, tapreorg.RegistryTx) error) error {

	if err := f.failNext("Withdraw"); err != nil {
		return err
	}

	return f.Registry.Withdraw(ctx, id, onWithdraw)
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
		ErrChan:                h.errChan,
	})
	require.NoError(h.t, w.RegisterSite(h.site))
	require.NoError(h.t, w.RegisterEffectHandler(
		"test", func(context.Context, tapreorg.VersionedBlob) error {
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

	spec := tapreorg.RegistrationSpec{
		Site:     testSiteID,
		Triggers: triggerSet,
		MatchData: tapreorg.VersionedBlob{
			Version: 1,
			Data:    matchData,
		},
		Payload:   tapreorg.VersionedBlob{Version: 1},
		Threshold: threshold,
	}
	phase1 := func(ctx context.Context, tx tapreorg.RegistryTx,
		newID tapreorg.AnchoringID) error {

		return tx.EnqueueEffect(ctx, tapreorg.OutboxEffect{
			Kind:      "test",
			Anchoring: fn.Some(newID),
			Payload: tapreorg.VersionedBlob{
				Version: 1,
			},
		})
	}

	// Registration is retried through transient database
	// contention: the harness's polling load can exhaust SQLite's
	// busy-retry budget, which is a load artifact, not a defect.
	var id tapreorg.AnchoringID
	for attempt := 0; attempt < 50; attempt++ {
		id, err = h.watcher.Register( //nolint:contextcheck
			context.Background(), spec, phase1,
		)
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
	case tapreorg.Withdrawn:
		return "withdrawn"
	default:
		return fmt.Sprintf("unknown<%T>", p)
	}
}

// TestWatcherHappyPath drives one anchoring from registration through
// witnessing to burial, checking the outbox and predicate economy on
// the way.
func TestWatcherHappyPath(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
	satTx := h.spendTx(op)
	id := h.register(testThreshold, []*wire.MsgTx{satTx}, op)

	// Registered, nothing on chain: unwitnessed and converged, and
	// the phase-1 effect dispatched.
	h.settleConverged(id, tapreorg.Unwitnessed{})
	require.Eventually(t, func() bool {
		return h.effects.Load() == 1
	}, settleTimeout, settleTick)

	// The satisfying spend confirms: witnessed.
	h.sim.MineBlock(satTx)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		w, ok := a.Phase.(tapreorg.Witnessed)
		if !ok || w.W.TxHash() != satTx.TxHash() {
			return false
		}

		return tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// Burial at threshold: act-confirmed, sensing ends.
	h.sim.MineBlocks(int(testThreshold) - 1)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		b, ok := a.Phase.(tapreorg.Buried)
		if !ok || b.W.TxHash() != satTx.TxHash() {
			return false
		}

		return tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.Equal(t, "buried", phaseKind(h.site.appliedPhase(id)))

	live, err := h.store.LiveAnchorings(context.Background())
	require.NoError(t, err)
	require.Empty(t, live)

	// The pure predicate ran exactly once for the candidate.
	require.Equal(t, 1, h.site.evaluations(satTx.TxHash()))
}

// TestWatcherConflictAbandon drives the adverse side: a foreign spend
// conflicts at potency, recovers when it reorgs out, and abandons at
// act depth when it returns and buries.
func TestWatcherConflictAbandon(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{2}, Index: 0}
	satTx := h.spendTx(op)
	foreignTx := h.spendTx(op)
	id := h.register(testThreshold, []*wire.MsgTx{satTx}, op)

	// A foreign spend confirms: conflicted, soft action only.
	h.sim.MineBlock(foreignTx)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "conflicted" &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// The foreign spend reorgs out with no successor: back to
	// unwitnessed. Excluded middle honoured — the registry never
	// asserts a stale conflict.
	h.sim.Reorg(1, nil)
	h.settleConverged(id, tapreorg.Unwitnessed{})
	require.Equal(
		t, "unwitnessed", phaseKind(h.site.appliedPhase(id)),
	)

	// The foreign spend returns and buries: the chain has decided
	// against us; compensation runs.
	h.sim.MineBlock(foreignTx)
	h.sim.MineBlocks(int(testThreshold) - 1)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		abandoned, ok := a.Phase.(tapreorg.Abandoned)
		if !ok {
			return false
		}
		cause, ok := abandoned.Cause.(tapreorg.ForeignBurial)
		if !ok || cause.Spend.W.TxHash() != foreignTx.TxHash() {
			return false
		}

		return tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.Equal(t, "abandoned", phaseKind(h.site.appliedPhase(id)))
}

// TestWatcherRewitness drives the form-change case: a different
// satisfying transaction (an RBF-style replacement) wins after a
// reorg, and the anchoring rewitnesses rather than conflicting.
func TestWatcherRewitness(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{3}, Index: 0}
	formA := h.spendTx(op)
	formB := h.spendTx(op)
	id := h.register(testThreshold, []*wire.MsgTx{formA, formB}, op)

	h.sim.MineBlock(formA)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		w, ok := a.Phase.(tapreorg.Witnessed)
		return ok && w.W.TxHash() == formA.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// The reorg replaces form A with form B in one step.
	h.sim.Reorg(1, []*wire.MsgTx{formB})
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		w, ok := a.Phase.(tapreorg.Witnessed)
		return ok && w.W.TxHash() == formB.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// Burial follows the winning form.
	h.sim.MineBlocks(int(testThreshold) - 1)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		b, ok := a.Phase.(tapreorg.Buried)
		return ok && b.W.TxHash() == formB.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
}

// TestWatcherReplacement drives the two-anchoring composition behind
// an RBF-style fee bump: each broadcast form registers its own
// anchoring over the same trigger, so each experiences the other as a
// foreign spend. When the replacement wins the fork, its anchoring
// buries while the original's drives through conflicted to abandoned,
// attributed to the replacement's burial.
func TestWatcherReplacement(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{7}, Index: 0}
	formA := h.spendTx(op)
	formB := h.spendTx(op)
	idA := h.register(testThreshold, []*wire.MsgTx{formA}, op)
	idB := h.register(testThreshold, []*wire.MsgTx{formB}, op)

	// The original form confirms first: its anchoring witnesses,
	// and the replacement's experiences it as a foreign spend.
	h.sim.MineBlock(formA)
	h.settleWhere(idA, func(a *tapreorg.Anchoring) bool {
		w, ok := a.Phase.(tapreorg.Witnessed)
		return ok && w.W.TxHash() == formA.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	h.settleWhere(idB, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "conflicted" &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// The re-org replaces the original with the fee-bumped form:
	// the roles swap exactly.
	h.sim.Reorg(1, []*wire.MsgTx{formB})
	h.settleWhere(idB, func(a *tapreorg.Anchoring) bool {
		w, ok := a.Phase.(tapreorg.Witnessed)
		return ok && w.W.TxHash() == formB.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	h.settleWhere(idA, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "conflicted" &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// The replacement buries at the threshold: the winner's act
	// fires, and the loser abandons with the winner's burial as
	// its foreign-burial cause — compensation runs exactly once,
	// on the losing anchoring.
	h.sim.MineBlocks(int(testThreshold) - 1)
	h.settleWhere(idB, func(a *tapreorg.Anchoring) bool {
		b, ok := a.Phase.(tapreorg.Buried)
		return ok && b.W.TxHash() == formB.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	h.settleWhere(idA, func(a *tapreorg.Anchoring) bool {
		abandoned, ok := a.Phase.(tapreorg.Abandoned)
		if !ok {
			return false
		}
		cause, ok := abandoned.Cause.(tapreorg.ForeignBurial)
		if !ok || cause.Spend.W.TxHash() != formB.TxHash() {
			return false
		}

		return tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.Equal(t, "buried", phaseKind(h.site.appliedPhase(idB)))
	require.Equal(t, "abandoned", phaseKind(h.site.appliedPhase(idA)))
}

// TestWatcherCascade drives dependency foreclosure: a child anchoring
// whose triggers were created by a parent's witness abandons, by
// cascade, when the parent's premises die at act depth.
func TestWatcherCascade(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	parentOp := wire.OutPoint{Hash: chainhash.Hash{4}, Index: 0}
	satParent := h.spendTx(parentOp)
	parentID := h.register(
		testThreshold, []*wire.MsgTx{satParent}, parentOp,
	)

	h.sim.MineBlock(satParent)
	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed"
	})

	// The child spends the parent witness's output 0; the edge is
	// derived automatically at registration.
	childOp := wire.OutPoint{Hash: satParent.TxHash(), Index: 0}
	satChild := h.spendTx(childOp)
	childID := h.register(testThreshold, []*wire.MsgTx{satChild}, childOp)

	h.sim.MineBlock(satChild)
	h.settleWhere(childID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed"
	})

	// The chain discards both and a foreign spend claims the
	// parent's trigger. The child's own witness is gone (its
	// outpoint no longer exists), and no direct evidence about the
	// child can ever arrive again.
	foreignParent := h.spendTx(parentOp)
	h.sim.Reorg(2, []*wire.MsgTx{foreignParent}, nil)

	h.settleWhere(childID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "unwitnessed"
	})

	// The foreign spend buries: the parent abandons directly, and
	// the child follows by cascade, attributed to the parent.
	h.sim.MineBlocks(int(testThreshold))

	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "abandoned" &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	h.settleWhere(childID, func(a *tapreorg.Anchoring) bool {
		abandoned, ok := a.Phase.(tapreorg.Abandoned)
		if !ok {
			return false
		}
		cause, ok := abandoned.Cause.(tapreorg.Foreclosed)
		if !ok || cause.Parent != parentID {
			return false
		}

		return tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
}

// TestWatcherRestart kills the watcher mid-flight, moves the chain
// while it is down, and asserts a fresh instance converges from the
// registry alone.
func TestWatcherRestart(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{5}, Index: 0}
	satTx := h.spendTx(op)
	id := h.register(testThreshold, []*wire.MsgTx{satTx}, op)

	h.sim.MineBlock(satTx)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed" &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// Down across the burial boundary.
	require.NoError(t, h.watcher.Stop())
	h.sim.MineBlocks(int(testThreshold) - 1)

	h.watcher = h.newWatcher()
	require.NoError(t, h.watcher.Start())

	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		b, ok := a.Phase.(tapreorg.Buried)
		return ok && b.W.TxHash() == satTx.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.Equal(t, "buried", phaseKind(h.site.appliedPhase(id)))
}

// TestWatcherRestartReorgBelowRecordedHeight pins the re-subscription
// hint against the hostile downtime re-org: while the watcher is
// down, the chain re-organizes the recorded witness to a height
// BELOW where it was recorded. The notifier's historical rescan
// starts no lower than the caller's hint, so re-subscribing at the
// recorded height would never find the transaction again; the
// verify-on-adoption pass would flip the candidate off-chain, the
// spend redelivery would dedup against the stale subscription, and
// the anchoring would sit unwitnessed with its witness confirmed.
// Hinting from the trigger set instead recovers the new location.
func TestWatcherRestartReorgBelowRecordedHeight(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{0xf6}, Index: 0}
	satTx := h.spendTx(op)
	id := h.register(testThreshold, []*wire.MsgTx{satTx}, op)

	// Two empty blocks, then the witness: recorded at baseline+3.
	h.sim.MineBlocks(2)
	h.sim.MineBlock(satTx)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		w, ok := a.Phase.(tapreorg.Witnessed)
		return ok && w.W.TxHash() == satTx.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// Down. The re-org replays the same witness two blocks lower.
	require.NoError(t, h.watcher.Stop())
	h.sim.Reorg(3, []*wire.MsgTx{satTx}, nil, nil)

	h.watcher = h.newWatcher()
	require.NoError(t, h.watcher.Start())

	// At its new location the witness already holds threshold
	// depth: recovery must find it, re-locate it, and certify.
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		b, ok := a.Phase.(tapreorg.Buried)
		return ok && b.W.TxHash() == satTx.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.Equal(t, "buried", phaseKind(h.site.appliedPhase(id)))
	require.NoError(t, h.escalation())
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

// TestWatcherStreamTermination pins the self-healing clause on its
// most common real trigger: the notifier closing subscription streams,
// as lnd does when it prunes registrations a safety margin past their
// dispatch, or when it restarts. The severed sensor must be rebuilt by
// the reconciliation sweep — not orphaned — so that sensing continues
// to certify outcomes afterwards.
func TestWatcherStreamTermination(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{0xd1}, Index: 0}
	formA := h.spendTx(op)
	id := h.register(3, []*wire.MsgTx{formA}, op)

	h.settleConverged(id, tapreorg.Unwitnessed{})

	h.sim.MineBlock(formA)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		_, ok := a.Phase.(tapreorg.Witnessed)
		return ok
	})

	// Sever every stream, then bury: the burial certification can
	// only be sensed by a rebuilt sensor.
	h.sim.SeverSubscriptionStreams()
	h.sim.MineBlocks(3)

	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		_, ok := a.Phase.(tapreorg.Buried)
		return ok && tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
}

// TestWatcherEpochTermination pins the one deliberately fatal
// condition: losing the block epoch stream means losing the chain,
// and it must escalate loudly rather than freeze sensing behind a
// healthy-looking daemon.
func TestWatcherEpochTermination(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	h.sim.SeverEpochStreams()

	select {
	case err := <-h.errChan:
		require.ErrorContains(t, err, "block epoch stream")

	case <-time.After(settleTimeout):
		t.Fatal("losing the epoch stream did not escalate")
	}
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

// TestWatcherRegistryFaults injects database failures into the
// sensing and delivery write paths mid-flight: every failed write
// must heal through resense and the reconciliation sweep, none may
// escalate, and convergence must complete once the database returns.
func TestWatcherRegistryFaults(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{0xe6}, Index: 0}
	formA := h.spendTx(op)
	id := h.register(3, []*wire.MsgTx{formA}, op)

	// The witnessing writes fail on first contact.
	h.registry.FailNextCalls(2, "")
	h.sim.MineBlock(formA)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		_, ok := a.Phase.(tapreorg.Witnessed)
		return ok && tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})

	// The burial certification's writes fail on first contact.
	h.registry.FailNextCalls(2, "")
	h.sim.MineBlocks(3)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		_, ok := a.Phase.(tapreorg.Buried)
		return ok && tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.NoError(t, h.escalation())
}

// TestWatcherStaleConfDelivery constructs, deterministically, the
// hostile ordering the location-verify defence exists for: a
// confirmation delivered after the chain has already displaced its
// block. The lagging consumer sees the event only once the world it
// describes is gone, and must drop it rather than record a disproved
// location.
func TestWatcherStaleConfDelivery(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{0xe1}, Index: 0}
	formA := h.spendTx(op)
	id := h.register(3, []*wire.MsgTx{formA}, op)

	h.sim.MineBlock(formA)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		_, ok := a.Phase.(tapreorg.Witnessed)
		return ok
	})

	recorded, err := h.store.GetAnchoring(context.Background(), id)
	require.NoError(t, err)
	require.Len(t, recorded.Spends, 1)
	originalBlock := recorded.Spends[0].W.BlockHash()

	// Freeze delivery, then move formA to a replacement block and
	// evict it again: on release the watcher receives a
	// confirmation naming a block hash the chain no longer holds,
	// followed by the re-org signal.
	h.sim.HoldDeliveries()
	h.sim.Reorg(1, []*wire.MsgTx{formA})
	h.sim.Reorg(1, nil)
	h.sim.ReleaseDeliveries()

	h.settleConverged(id, tapreorg.Unwitnessed{})

	// The stale confirmation was dropped, not recorded: the
	// candidate still carries the original block, off-chain, not
	// the displaced replacement.
	a, err := h.store.GetAnchoring(context.Background(), id)
	require.NoError(t, err)
	require.Len(t, a.Spends, 1)
	require.Equal(t, originalBlock, a.Spends[0].W.BlockHash())
	require.False(t, a.Spends[0].OnChain)
	require.NoError(t, h.escalation())
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

// TestWatcherDuplicateDeliveries replays every standing report — the
// duplicates an at-least-once notifier boundary permits — and pins
// idempotence end to end: no phase flap, no repeated site delivery,
// no escalation.
func TestWatcherDuplicateDeliveries(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{0xe3}, Index: 0}
	formA := h.spendTx(op)
	id := h.register(3, []*wire.MsgTx{formA}, op)

	witnessedDelivered := func(a *tapreorg.Anchoring) bool {
		_, ok := a.Phase.(tapreorg.Witnessed)
		return ok && tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	}

	h.sim.MineBlock(formA)
	h.settleWhere(id, witnessedDelivered)

	h.sim.ReplayLastEvents()
	h.sim.ReplayLastEvents()
	time.Sleep(50 * settleTick)

	h.settleWhere(id, witnessedDelivered)
	require.Equal(t, []string{"witnessed"}, h.site.deliveries(id))

	// Burial certifies through the same duplicated boundary; the
	// terminal phase then absorbs any further replay.
	h.sim.MineBlocks(3)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		_, ok := a.Phase.(tapreorg.Buried)
		return ok && tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	h.sim.ReplayLastEvents()
	time.Sleep(50 * settleTick)

	require.Equal(
		t, []string{"witnessed", "buried"}, h.site.deliveries(id),
	)
	require.NoError(t, h.escalation())
}

// TestWatcherSubscriptionStreamErrors delivers errors on the
// subscription error channels — the way lnd reports a server-side
// subscription failure — and requires full recovery through the
// resense path, with no critical escalation.
func TestWatcherSubscriptionStreamErrors(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{0xe4}, Index: 0}
	formA := h.spendTx(op)
	id := h.register(3, []*wire.MsgTx{formA}, op)

	h.sim.MineBlock(formA)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		_, ok := a.Phase.(tapreorg.Witnessed)
		return ok
	})

	h.sim.ErrorSubscriptionStreams(errors.New("server-side failure"))
	h.sim.MineBlocks(3)

	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		_, ok := a.Phase.(tapreorg.Buried)
		return ok && tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
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

// TestWatcherShrinkingReorg re-organizes to a shorter dominant chain:
// the best height decreases, the witness vanishes, and sensing must
// follow the chain down and back up again.
func TestWatcherShrinkingReorg(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	op := wire.OutPoint{Hash: chainhash.Hash{0xe5}, Index: 0}
	formA := h.spendTx(op)
	id := h.register(3, []*wire.MsgTx{formA}, op)

	h.sim.MineBlocks(2)
	h.sim.MineBlock(formA)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		_, ok := a.Phase.(tapreorg.Witnessed)
		return ok
	})

	// A shorter chain displaces the witness entirely.
	before := h.sim.BestHeight()
	h.sim.Reorg(2)
	require.Less(t, h.sim.BestHeight(), before)

	h.settleConverged(id, tapreorg.Unwitnessed{})

	// The same displacement across a restart: no loss signal this
	// time — the rebuilt sensor's own location verification must
	// read a recorded height beyond the tip as disproof, not as a
	// notifier error to retry forever.
	h.sim.MineBlock(formA)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		_, ok := a.Phase.(tapreorg.Witnessed)
		return ok
	})
	require.NoError(t, h.watcher.Stop())
	h.sim.Reorg(1)
	h.watcher = h.newWatcher()
	require.NoError(t, h.watcher.Start())

	h.settleConverged(id, tapreorg.Unwitnessed{})

	// The world reasserts itself on the shorter chain.
	h.sim.MineBlock(formA)
	h.sim.MineBlocks(2)
	h.settleWhere(id, func(a *tapreorg.Anchoring) bool {
		_, ok := a.Phase.(tapreorg.Buried)
		return ok && tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.NoError(t, h.escalation())
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

// TestWatcherChildBeforeParentConfirms pins the ordinary chained
// registration ordering: the child stakes on outputs of the parent's
// yet-unconfirmed witness transaction, so no edge can derive at its
// registration. The edge derives when the parent's form is first
// observed on chain, and from there the full dependency doctrine
// holds: withdrawal refused, foreclosure staged and certified, the
// child abandoned by cascade.
func TestWatcherChildBeforeParentConfirms(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	parentOp := wire.OutPoint{Hash: chainhash.Hash{0xe9}, Index: 0}
	pForm1 := h.spendTx(parentOp)
	pForm2 := h.spendTx(parentOp)
	parentID := h.register(4, []*wire.MsgTx{pForm1, pForm2}, parentOp)

	// The child registers against pForm1's output before pForm1 has
	// ever been mined: the registry cannot yet know the parent.
	childOp := wire.OutPoint{Hash: pForm1.TxHash(), Index: 0}
	satChild := h.spendTx(childOp)
	childID := h.register(2, []*wire.MsgTx{satChild}, childOp)

	edges, err := h.store.DependencyEdges(context.Background(), parentID)
	require.NoError(t, err)
	require.Empty(t, edges)

	// The parent's form confirms: the edge derives from the newly
	// recorded candidate, and the withdrawal guard holds from here.
	h.sim.MineBlock(pForm1)
	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed"
	})

	edges, err = h.store.DependencyEdges(context.Background(), parentID)
	require.NoError(t, err)
	require.Len(t, edges, 1)
	require.Equal(t, childID, edges[0].Child)
	require.Equal(t, pForm1.TxHash(), edges[0].ParentWitnessTxHash)

	err = h.watcher.Withdraw(context.Background(), parentID, nil)
	require.ErrorIs(t, err, tapreorg.ErrLiveDependents)

	// The parent re-witnesses in its other form; at the child's own
	// threshold the notifier certifies the foreclosure and the
	// child abandons by cascade, attributed to that form.
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
	require.NoError(t, h.escalation())
}

// TestWatcherPartialSpendForeign pins the structural half of the
// whole-set rule: a transaction spending only part of an anchoring's
// trigger set cannot realize it, so the watcher classifies it foreign
// without consulting the site predicate — coexistence of satisfying
// and foreign outcomes on one chain must stay unrepresentable no
// matter what a site's predicate would have said. A complete spend
// (extra non-trigger inputs included) reaches the predicate as
// before.
func TestWatcherPartialSpendForeign(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	// The partial spender consumes trigger A but not B — and is
	// listed in the match data, so the predicate would bless it if
	// it were ever consulted.
	opA := wire.OutPoint{Hash: chainhash.Hash{0xf0}, Index: 0}
	opB := wire.OutPoint{Hash: chainhash.Hash{0xf0}, Index: 1}
	partial := h.spendTx(opA)
	id1 := h.register(2, []*wire.MsgTx{partial}, opA, opB)

	h.sim.MineBlock(partial)
	h.settleWhere(id1, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "conflicted"
	})
	require.Zero(t, h.site.evaluations(partial.TxHash()))

	// At threshold depth the partial spend certifies: the stake is
	// genuinely foreclosed, act-finally, attributed to the foreign
	// spender.
	h.sim.MineBlocks(1)
	h.settleWhere(id1, func(a *tapreorg.Anchoring) bool {
		abandoned, ok := a.Phase.(tapreorg.Abandoned)
		if !ok {
			return false
		}
		cause, ok := abandoned.Cause.(tapreorg.ForeignBurial)

		return ok && cause.Spend.W.TxHash() == partial.TxHash() &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.Zero(t, h.site.evaluations(partial.TxHash()))

	// A complete spend — extra non-trigger input included — reaches
	// the predicate and realizes its anchoring: coverage means the
	// trigger set is a subset of the inputs, not the whole of them.
	opC := wire.OutPoint{Hash: chainhash.Hash{0xf1}, Index: 0}
	opD := wire.OutPoint{Hash: chainhash.Hash{0xf1}, Index: 1}
	opFee := wire.OutPoint{Hash: chainhash.Hash{0xf1}, Index: 2}
	complete := h.spendTx(opC, opD, opFee)
	id2 := h.register(2, []*wire.MsgTx{complete}, opC, opD)

	h.sim.MineBlock(complete)
	h.sim.MineBlocks(1)
	h.settleWhere(id2, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "buried" &&
			tapreorg.PhaseEqual(a.DeliveredPhase, a.Phase)
	})
	require.Equal(t, 1, h.site.evaluations(complete.TxHash()))
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
		func(context.Context, tapreorg.VersionedBlob) error {
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
	id3 := h.register(2, nil, op3)
	require.NoError(t, h.watcher.Withdraw(
		ctx, id3,
		func(ctx context.Context, tx tapreorg.RegistryTx) error {
			return tx.EnqueueEffect(ctx, tapreorg.OutboxEffect{
				Kind:      "boom",
				Anchoring: fn.Some(id3),
				Payload:   tapreorg.VersionedBlob{Version: 1},
			})
		},
	))

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
		func(context.Context, tapreorg.VersionedBlob) error {
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

// TestWatcherAbandonedParentRestage pins the restage path against an
// abandoned parent. A terminal abandonment settles the dependents'
// edges with the cause witness staged on-chain; the child's next
// adoption rebuilds its incoming staging from the parent's durable
// phase, and must reproduce that settlement — not read "abandoned"
// as "not witnessed" and downgrade the staged evidence to off-chain,
// contradicting what the delivery just wrote.
func TestWatcherAbandonedParentRestage(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.start()

	parentOp := wire.OutPoint{Hash: chainhash.Hash{0xf7}, Index: 0}
	pForm1 := h.spendTx(parentOp)
	parentID := h.register(2, []*wire.MsgTx{pForm1}, parentOp)

	h.sim.MineBlock(pForm1)
	h.settleWhere(parentID, func(a *tapreorg.Anchoring) bool {
		return phaseKind(a.Phase) == "witnessed"
	})

	// The child depends on the parent's form, at a threshold deep
	// enough that its own foreclosure certification stays out of
	// reach: the staged evidence below remains uncertified, and
	// therefore writable by the restage under test.
	childOp := wire.OutPoint{Hash: pForm1.TxHash(), Index: 0}
	satChild := h.spendTx(childOp)
	childID := h.register(6, []*wire.MsgTx{satChild}, childOp)

	// A foreign spend displaces the parent's form and buries at the
	// parent's threshold: the parent abandons, and the terminal
	// delivery settles the child's edge with the foreign spend
	// staged on-chain.
	foreign := h.spendTx(parentOp)
	h.sim.Reorg(1, []*wire.MsgTx{foreign})
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

	stagedOnChain := func() *tapreorg.ForeclosureEvent {
		view, err := h.store.ChainView(context.Background(), childID)
		if err != nil {
			return nil
		}

		return view.Foreclosure.UnwrapToPtr()
	}
	require.Eventually(t, func() bool {
		fc := stagedOnChain()
		return fc != nil && fc.OnChain && !fc.ActCertified &&
			fc.W.TxHash() == foreign.TxHash()
	}, settleTimeout, settleTick)

	// Process death and recovery: the child re-adopts and rebuilds
	// its incoming staging from the parent's durable Abandoned
	// phase. Across many reconciliation sweeps, the staged evidence
	// must never flip off-chain.
	h.restart()
	require.Never(t, func() bool {
		fc := stagedOnChain()
		return fc != nil && !fc.OnChain
	}, 2*time.Second, settleTick)

	fc := stagedOnChain()
	require.NotNil(t, fc)
	require.True(t, fc.OnChain)
	require.Equal(t, foreign.TxHash(), fc.W.TxHash())
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

// TestWatcherRestartReorgBelowForeclosureHeight is the foreclosure
// counterpart of TestWatcherRestartReorgBelowRecordedHeight. The
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
// buried parent, mirroring TestWatcherAbandonedParentRestage: a
// parent buried in a different form than the child's edge depends on
// settles the edge with the burying witness staged on-chain, and the
// child's re-adoption must reproduce that staging from the parent's
// durable phase — never downgrade it.
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
		// terminal reading, if any; called after every action.
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
				if h.sim.Length() > 0 && rapid.Bool().Draw(
					rt, label+".alsoReorg",
				) {

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

		// Leftover injected faults would bleed into the withdraw
		// below and the next iteration's registration, failing
		// harness calls rather than watcher paths.
		h.registry.FailNextCalls(0, "")

		// Bound the shared harness's live set: production
		// anchorings terminate, and a monotonically growing
		// sensor population is a harness artifact that only
		// stresses the database. Withdrawal is refused exactly
		// when the anchoring already terminated on its own;
		// transient contention is retried.
		for attempt := 0; attempt < 50; attempt++ {
			err := h.watcher.Withdraw(
				context.Background(), id, nil,
			)
			if errors.Is(err, tapdb.ErrRetriesExceeded) {
				time.Sleep(settleTick)
				continue
			}
			if err != nil {
				require.ErrorIs(
					rt, err, tapreorg.ErrTerminalPhase,
				)
			}
			break
		}
	})
}
