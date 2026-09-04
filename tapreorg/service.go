package tapreorg

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/clock"
)

const (
	// DefaultInitialDeliveryBackoff is the default backoff after a
	// first failed delivery or dispatch attempt.
	DefaultInitialDeliveryBackoff = 30 * time.Second

	// DefaultMaxDeliveryBackoff caps the exponential delivery and
	// dispatch backoff.
	DefaultMaxDeliveryBackoff = 10 * time.Minute

	// DefaultStuckAfterAttempts is the number of consecutive
	// delivery failures after which an anchoring is flagged stuck.
	// Retries continue past it, at the capped backoff, forever.
	DefaultStuckAfterAttempts = 10

	// DefaultScanInterval is the default cadence of the delivery
	// and outbox reconciliation scans. Scans also run immediately
	// when sensing changes a phase, so this is a floor on recovery
	// latency, not on delivery latency.
	DefaultScanInterval = time.Minute

	// DefaultActThreshold is the act-confirmation depth given to
	// registrations that leave their threshold unset, when the
	// watcher itself was not configured with one. It matches the
	// daemon's default --reorgsafedepth.
	DefaultActThreshold = 6

	// outboxBatchSize bounds how many effects one dispatch pass
	// claims.
	outboxBatchSize = 32
)

// EffectHandler dispatches one kind of outbox effect. Handlers must
// be idempotent: an effect can be dispatched more than once if the
// process dies between the dispatch and the bookkeeping write.
type EffectHandler func(ctx context.Context, payload VersionedBlob) error

// WatcherConfig houses the watcher's dependencies and policy knobs.
type WatcherConfig struct {
	// Notifier is the chain-sensing surface.
	Notifier ChainNotifier

	// Registry is the durable anchoring store.
	Registry Registry

	// InitialDeliveryBackoff, MaxDeliveryBackoff and
	// StuckAfterAttempts set the delivery failure policy.
	InitialDeliveryBackoff time.Duration
	MaxDeliveryBackoff     time.Duration
	StuckAfterAttempts     uint32

	// ScanInterval is the cadence of the delivery and outbox
	// reconciliation scans.
	ScanInterval time.Duration

	// DefaultThreshold is the act-confirmation depth given to
	// registrations that leave RegistrationSpec.Threshold zero. It
	// carries the operator's re-org safety policy (the daemon's
	// --reorgsafedepth) into the watcher, so sites inherit that
	// notion of a safe depth unless they deliberately choose
	// their own.
	DefaultThreshold uint32

	// Clock is the time source for backoff bookkeeping.
	Clock clock.Clock

	// ErrChan reports critical errors to the main server, which
	// treats them as fatal. Only unrecoverable conditions travel
	// here — losing the block epoch stream, and nothing else:
	// database and notifier hiccups retry via the reconciliation
	// sweep, broken subscription streams rebuild their sensor, and
	// delivery failures back off through the registry's own
	// bookkeeping. A send blocks until consumed or the watcher
	// stops; it is never dropped.
	ErrChan chan<- error
}

// fillDefaults populates zero-valued policy knobs.
func (c *WatcherConfig) fillDefaults() {
	if c.InitialDeliveryBackoff == 0 {
		c.InitialDeliveryBackoff = DefaultInitialDeliveryBackoff
	}
	if c.MaxDeliveryBackoff == 0 {
		c.MaxDeliveryBackoff = DefaultMaxDeliveryBackoff
	}
	if c.StuckAfterAttempts == 0 {
		c.StuckAfterAttempts = DefaultStuckAfterAttempts
	}
	if c.ScanInterval == 0 {
		c.ScanInterval = DefaultScanInterval
	}
	if c.DefaultThreshold == 0 {
		c.DefaultThreshold = DefaultActThreshold
	}
	if c.Clock == nil {
		c.Clock = clock.NewDefaultClock()
	}
}

// Watcher is the daemon's single organ for reconciling speculative
// local state with chain history: it senses the chain into per-
// anchoring chain views, derives phases as a pure function of those
// views, and converges sites to the derived phases through handlers
// that run atomically with the registry advance.
type Watcher struct {
	startOnce sync.Once
	stopOnce  sync.Once

	// startErr latches the outcome of the first Start call.
	startErr error

	// started flips once Start begins, closing the registration
	// window: the loops read the site, listener and handler tables
	// without synchronization from then on.
	started atomic.Bool

	cfg *WatcherConfig

	sites          map[SiteID]Site
	effectHandlers map[EffectKind]EffectHandler
	listeners      []DeliveryListener

	bestHeight atomic.Uint32

	// events funnels all sensing inputs into the sensing loop.
	events chan any

	// deliveryKick and outboxKick wake the respective loops ahead
	// of their scan tickers.
	deliveryKick chan struct{}
	outboxKick   chan struct{}

	// sensors is owned by the sensing loop.
	sensors map[AnchoringID]*sensor

	*fn.ContextGuard
}

// NewWatcher creates a new watcher from the given config. Sites and
// effect handlers are registered before Start.
func NewWatcher(cfg *WatcherConfig) *Watcher {
	cfg.fillDefaults()

	return &Watcher{
		cfg:            cfg,
		sites:          make(map[SiteID]Site),
		effectHandlers: make(map[EffectKind]EffectHandler),
		events:         make(chan any),
		deliveryKick:   make(chan struct{}, 1),
		outboxKick:     make(chan struct{}, 1),
		sensors:        make(map[AnchoringID]*sensor),
		ContextGuard: &fn.ContextGuard{
			DefaultTimeout: DefaultTimeout,
			Quit:           make(chan struct{}),
		},
	}
}

// RegisterSite installs a site implementation. All sites must be
// registered before Start, so that restart reconciliation can route
// replayed deliveries; the watcher's loops read the site map without
// synchronization on the same grounds, so late registration is
// refused rather than raced.
func (w *Watcher) RegisterSite(site Site) error {
	if w.started.Load() {
		return fmt.Errorf("site %v registered after Start",
			site.ID())
	}
	if _, ok := w.sites[site.ID()]; ok {
		return fmt.Errorf("site %v already registered", site.ID())
	}
	w.sites[site.ID()] = site

	return nil
}

// DeliveryListener observes successful deliveries, invoked on its own
// goroutine after the delivery transaction commits. Latency path
// only: the registry remains the durable delivery record, a missed
// notification is recovered by reading it, and notifications across
// deliveries carry no ordering guarantee. The watcher does not wait
// for listeners at shutdown.
type DeliveryListener func(id AnchoringID, site SiteID, phase Phase)

// RegisterDeliveryListener installs a delivery listener. All
// listeners are registered before Start; late registration is
// refused, as with RegisterSite.
func (w *Watcher) RegisterDeliveryListener(
	listener DeliveryListener) error {

	if w.started.Load() {
		return errors.New("delivery listener registered after Start")
	}
	w.listeners = append(w.listeners, listener)

	return nil
}

// RegisterEffectHandler installs the dispatch handler for one effect
// kind. All handlers are registered before Start; late registration
// is refused, as with RegisterSite.
func (w *Watcher) RegisterEffectHandler(kind EffectKind,
	handler EffectHandler) error {

	if w.started.Load() {
		return fmt.Errorf("effect handler %v registered after Start",
			kind)
	}
	if _, ok := w.effectHandlers[kind]; ok {
		return fmt.Errorf("effect handler %v already registered",
			kind)
	}
	w.effectHandlers[kind] = handler

	return nil
}

// Start brings the watcher up: it re-establishes sensing for every
// live anchoring in the registry and launches the sensing, delivery
// and outbox loops. Sites do nothing special at startup; the delivery
// scan replays whatever their delivered phase lags. A failed Start is
// definitive for this instance: later calls return the same error
// rather than a spurious nil.
func (w *Watcher) Start() error {
	w.startOnce.Do(func() {
		w.started.Store(true)
		w.startErr = w.start()
	})

	return w.startErr
}

// start performs the actual startup work behind the Start latch.
func (w *Watcher) start() error {
	log.Info("Starting re-org watcher")

	ctx, cancel := w.WithCtxQuitNoTimeout()
	defer cancel()

	height, err := w.cfg.Notifier.CurrentHeight(ctx)
	if err != nil {
		return fmt.Errorf("unable to get current height: %w", err)
	}
	w.bestHeight.Store(height)

	live, err := w.cfg.Registry.LiveAnchorings(ctx)
	if err != nil {
		return fmt.Errorf("unable to load live anchorings: %w", err)
	}

	// The epoch subscription is established here, not in the
	// sensing loop, so that a watcher that started successfully is
	// guaranteed to be sensing: a failure surfaces as a Start
	// error rather than as an asynchronous fatality from a loop
	// the caller cannot observe. Its context must outlive this
	// function; the sensing loop owns the cancel.
	epochCtx, epochCancel := w.WithCtxQuitNoTimeout()
	epochChan, epochErr, err := w.cfg.Notifier.RegisterBlockEpochNtfn(
		epochCtx,
	)
	if err != nil {
		epochCancel()
		return fmt.Errorf("unable to register block epochs: %w", err)
	}

	w.Wg.Add(3)
	go w.sensingLoop(epochCtx, epochCancel, epochChan, epochErr, live)
	go w.deliveryLoop()
	go w.outboxLoop()

	return nil
}

// Stop signals the watcher to exit and waits for its loops.
func (w *Watcher) Stop() error {
	w.stopOnce.Do(func() {
		log.Info("Stopping re-org watcher")

		close(w.Quit)
		w.Wg.Wait()
	})

	return nil
}

// Register stakes a new anchoring: the registry insert, dependency-
// edge derivation and the site's phase-1 write commit in one
// transaction, and sensing begins immediately after. The site must
// have been registered with the watcher.
func (w *Watcher) Register(ctx context.Context, spec RegistrationSpec,
	phase1 func(context.Context, RegistryTx,
		AnchoringID) error) (AnchoringID, error) {

	if _, ok := w.sites[spec.Site]; !ok {
		return 0, fmt.Errorf("unknown site %v", spec.Site)
	}

	// An unset threshold defers to the watcher's configured policy
	// default.
	if spec.Threshold == 0 {
		spec.Threshold = w.cfg.DefaultThreshold
	}

	id, err := w.cfg.Registry.Register(
		ctx, spec, w.bestHeight.Load(), phase1,
	)
	if err != nil {
		return 0, err
	}

	// The anchoring is durably registered from here on, so the
	// sensing hand-off is best-effort: a live anchoring without a
	// sensor is adopted by the reconciliation sweep, and an error
	// returned now would misreport a committed registration as
	// failed.
	if err := w.sendEvent(ctx, evSense{id: id}); err != nil {
		log.Warnf("Anchoring %d: sensing hand-off failed, "+
			"reconciliation sweep will adopt: %v", id, err)
	}

	return id, nil
}

// Withdraw revokes a live stake: the site's withdrawal write and the
// terminal registry advance commit in one transaction, and sensing
// stops.
func (w *Watcher) Withdraw(ctx context.Context, id AnchoringID,
	onWithdraw func(context.Context, RegistryTx) error) error {

	if err := w.cfg.Registry.Withdraw(ctx, id, onWithdraw); err != nil {
		return err
	}

	// The withdrawal is committed; tearing down the sensor is
	// best-effort bookkeeping (a leftover sensor stops itself on
	// its next re-derivation, which sees the terminal phase).
	if err := w.sendEvent(ctx, evStopSensing{id: id}); err != nil {
		log.Warnf("Anchoring %d: stop-sensing hand-off failed: %v",
			id, err)
	}

	return nil
}

// sendEvent delivers an event to the sensing loop, respecting
// shutdown and the caller's context.
func (w *Watcher) sendEvent(ctx context.Context, event any) error {
	select {
	case w.events <- event:
		return nil

	case <-ctx.Done():
		return ctx.Err()

	case <-w.Quit:
		return fmt.Errorf("watcher shutting down")
	}
}

// Internal sensing events.
type (
	// evSense (re-)establishes sensing for an anchoring and
	// re-derives its phase.
	evSense struct {
		id AnchoringID
	}

	// evStopSensing tears down sensing for an anchoring.
	evStopSensing struct {
		id AnchoringID
	}

	// evSpendDetail reports a confirmed spend of a trigger
	// outpoint.
	evSpendDetail struct {
		id     AnchoringID
		op     wire.OutPoint
		detail *chainntnfs.SpendDetail
	}

	// evSpendReorg reports that the previously reported spend of a
	// trigger outpoint was re-organized out.
	evSpendReorg struct {
		id AnchoringID
		op wire.OutPoint
	}

	// evCandidateConf reports a candidate transaction's (re-)
	// confirmation, with its full location.
	evCandidateConf struct {
		id   AnchoringID
		txid chainhash.Hash
		conf *chainntnfs.TxConfirmation
	}

	// evCandidateActConf reports the notifier certifying a
	// candidate at the anchoring's threshold depth.
	evCandidateActConf struct {
		id   AnchoringID
		txid chainhash.Hash
		conf *chainntnfs.TxConfirmation
	}

	// evForeclosureActConf reports the notifier certifying a
	// foreclosing transaction at the child anchoring's threshold
	// depth.
	evForeclosureActConf struct {
		child  AnchoringID
		parent AnchoringID
		conf   *chainntnfs.TxConfirmation
	}

	// evCandidateReorg reports that a candidate transaction was
	// re-organized out.
	evCandidateReorg struct {
		id   AnchoringID
		txid chainhash.Hash
	}

	// evResense reports a broken subscription stream: the sensor is
	// dropped so the reconciliation sweep re-establishes sensing.
	// The sensor pointer guards against a stale goroutine (from a
	// generation already torn down) dropping its successor.
	evResense struct {
		id AnchoringID
		s  *sensor
	}
)

// pendingCandidate is a discovered spender awaiting its precise
// location from the candidate confirmation subscription.
type pendingCandidate struct {
	tx      *wire.MsgTx
	verdict Verdict
}

// sensor is the sensing loop's bookkeeping for one live anchoring.
type sensor struct {
	anchoring *Anchoring

	// cancel tears down every subscription of this sensor.
	cancel context.CancelFunc

	// ctx is the subscription context.
	ctx context.Context

	// candidateSubs tracks which candidate txids have a live
	// location subscription (one confirmation, reorg-aware).
	candidateSubs map[chainhash.Hash]struct{}

	// actSubs tracks which candidate txids have a live
	// certification subscription (threshold confirmations).
	actSubs map[chainhash.Hash]struct{}

	// foreclosureSubs tracks which foreclosing txids have a live
	// certification subscription.
	foreclosureSubs map[chainhash.Hash]struct{}

	// pending holds discovered spenders not yet located.
	pending map[chainhash.Hash]*pendingCandidate
}

// sensingLoop owns all chain subscriptions and the registry's sensed
// state. It never calls a site handler and is never blocked by one.
// The epoch stream is registered by Start and handed in, together
// with the context (and its cancel) every sensor derives from.
func (w *Watcher) sensingLoop(ctx context.Context,
	cancel context.CancelFunc, epochChan chan int32,
	epochErr chan error, initial []*Anchoring) {

	defer w.Wg.Done()
	defer cancel()

	// Re-establish sensing for everything live, then re-derive:
	// events missed while down are recovered by the notifier's
	// historical dispatch, and phase is a function of view, so one
	// derivation pass makes the registry current. A failed start is
	// left to the reconciliation sweep rather than escalated.
	for _, anchoring := range initial {
		if err := w.adopt(ctx, anchoring); err != nil {
			log.Warnf("Unable to start sensor, sweep will "+
				"retry: %v", err)
		}
	}

	// The reconciliation sweep is the safety net for transient
	// failures anywhere on the sensing path: a live anchoring
	// without a sensor (a failed registration hand-off, a failed
	// startup load) is re-adopted on the next tick rather than
	// staying orphaned until restart.
	ticker := time.NewTicker(w.cfg.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case event := <-w.events:
			w.handleSensingEvent(ctx, event)

		case <-ticker.C:
			w.reconcileSensors(ctx)

		case height, ok := <-epochChan:
			if !ok {
				// Losing the epoch stream means losing the
				// chain: sensing cannot continue, and dying
				// silently would freeze every anchoring
				// behind a healthy-looking daemon. Escalate
				// loudly, matching how the daemon treats
				// losing lnd everywhere else.
				if ctx.Err() == nil {
					w.reportErr(errors.New(
						"block epoch stream closed",
					))
				}
				return
			}
			// The stored best height feeds new registrations
			// their CreatedHeight. Nothing else derives from it:
			// act finality is driven exclusively by the sticky
			// ActCertified flag written from the notifier's
			// threshold-conf certifications (candidates
			// resense on their own upsert), so there is no
			// per-block re-derive-all — DerivePhase is a
			// function of the anchoring's chain view, not the
			// tip height.
			w.bestHeight.Store(uint32(height))

		case err := <-epochErr:
			// A closed error channel delivers nil; either way
			// the stream is dead and sensing with it, so any
			// non-shutdown cause escalates before returning.
			if err == nil {
				err = errors.New("stream terminated")
			}
			if ctx.Err() == nil && !fn.IsCanceled(err) &&
				!fn.IsRpcErr(
					err,
					chainntnfs.ErrChainNotifierShuttingDown,
				) {

				w.reportErr(fmt.Errorf("block epoch "+
					"stream: %w", err))
			}

			return

		case <-w.Quit:
			return
		}
	}
}

// witnessEnrichment extracts the including block's header and the
// transaction's merkle inclusion proof from a confirmation event, so
// handlers can rebuild proofs without network access.
func witnessEnrichment(
	conf *chainntnfs.TxConfirmation) (*wire.BlockHeader,
	*proof.TxMerkleProof) {

	if conf.Block == nil {
		return nil, nil
	}

	header := conf.Block.Header
	merkle, err := proof.NewTxMerkleProof(
		conf.Block.Transactions, int(conf.TxIndex),
	)
	if err != nil {
		log.Errorf("Unable to build merkle proof from conf "+
			"block: %v", err)
		return &header, nil
	}

	return &header, merkle
}

// verifyLocation reports whether a transaction recorded at (height,
// blockHash) is part of the dominant chain right now. Chain events
// arrive on channels with no mutual ordering guarantee (a candidate's
// confirmation and its loss signal travel on separate channels, and a
// rebuilt sensor can be preceded by a prior generation's queued
// events), so location-bearing events are verified against the chain
// itself before they are recorded, and loss signals before they flip
// anything. The chain is the source of truth; events are only hints.
func (w *Watcher) verifyLocation(ctx context.Context, height uint32,
	blockHash chainhash.Hash) (bool, error) {

	hash, err := w.cfg.Notifier.GetBlockHash(ctx, int64(height))
	if err != nil {
		// The dominant chain may be shorter than the recorded
		// height — a re-org onto a shorter-but-heavier chain.
		// No block exists there at all, so the location is
		// definitionally disproved, not unknown: treating the
		// lookup failure as transient would retry a question
		// the chain can no longer answer. A torn read against
		// a concurrent extension is benign — a spuriously
		// off-chain candidate re-records through its still-live
		// confirmation subscription.
		best, bestErr := w.cfg.Notifier.CurrentHeight(ctx)
		if bestErr == nil && height > best {
			return false, nil
		}

		return false, err
	}

	return hash == blockHash, nil
}

// resense drops an anchoring's sensor so the reconciliation sweep
// re-adopts it: subscriptions are re-established and the notifier's
// historical dispatch regenerates whatever facts a failed write
// discarded. The chain is the source of truth, so no sensing failure
// is unrecoverable — this is the uniform self-healing path for
// transient failures anywhere in a sensor's pipeline.
func (w *Watcher) resense(id AnchoringID) {
	w.stopSensor(id)
}

// reconcileSensors adopts live anchorings that have no sensor —
// however they came to be missed. Sensing must never depend on any
// single hand-off succeeding.
func (w *Watcher) reconcileSensors(ctx context.Context) {
	live, err := w.cfg.Registry.LiveAnchorings(ctx)
	if err != nil {
		// A failed scan is transient by construction — the next
		// tick repeats it — so it is never escalated.
		log.Warnf("Unable to reconcile sensors, next sweep will "+
			"retry: %v", err)
		return
	}

	for _, anchoring := range live {
		if _, ok := w.sensors[anchoring.ID]; ok {
			continue
		}

		log.Infof("Anchoring %d (site=%v): adopted by "+
			"reconciliation sweep", anchoring.ID, anchoring.Site)

		if err := w.adopt(ctx, anchoring); err != nil {
			log.Warnf("Unable to start sensor, next sweep "+
				"will retry: %v", err)
		}
	}
}

// adopt (re-)establishes sensing for an anchoring and re-derives its
// phase. It then restages the anchoring's dependents' edges even when
// the derivation changed nothing: an adoption may be retrying exactly
// a lost restage, which a no-change derivation would otherwise skip.
func (w *Watcher) adopt(ctx context.Context, anchoring *Anchoring) error {
	if err := w.startSensor(ctx, anchoring); err != nil {
		return err
	}
	w.rederive(ctx, anchoring.ID)

	if s, ok := w.sensors[anchoring.ID]; ok {
		w.restageDependentForeclosures(
			ctx, anchoring.ID, s.anchoring.Phase,
		)
	}

	return nil
}

// handleSensingEvent processes one sensing input.
func (w *Watcher) handleSensingEvent(ctx context.Context, event any) {
	switch ev := event.(type) {
	case evSense:
		// Failures here leave the anchoring without a sensor,
		// which is precisely the state the reconciliation sweep
		// repairs; nothing to escalate.
		anchoring, err := w.cfg.Registry.GetAnchoring(ctx, ev.id)
		if err != nil {
			log.Warnf("Unable to load anchoring %d, sweep "+
				"will retry: %v", ev.id, err)
			return
		}
		if err := w.adopt(ctx, anchoring); err != nil {
			log.Warnf("Unable to start sensor, sweep will "+
				"retry: %v", err)
			return
		}

	case evStopSensing:
		w.stopSensor(ev.id)

	case evResense:
		if cur, ok := w.sensors[ev.id]; ok && cur == ev.s {
			w.resense(ev.id)
		}

	case evSpendDetail:
		w.handleSpendDetail(ctx, ev)

	case evSpendReorg:
		// The spend subscription's re-org signal names no
		// transaction, and attributing it to the last reported
		// spender races with the replacement's own spend
		// detail: acting on it can mark the *new* spender
		// off-chain. Every discovered candidate carries its own
		// confirmation subscription whose re-org channel is the
		// sound per-candidate loss signal, so this signal's only
		// job is keeping the spend stream alive; it is
		// deliberately not acted upon.

	case evCandidateConf:
		w.handleCandidateConf(ctx, ev)

	case evCandidateActConf:
		w.handleCandidateActConf(ctx, ev)

	case evForeclosureActConf:
		w.handleForeclosureActConf(ctx, ev)

	case evCandidateReorg:
		w.markCandidateOffChain(ctx, ev.id, ev.txid)

	default:
		log.Errorf("Unknown sensing event %T", event)
	}
}

// startSensor opens the spend subscriptions for an anchoring's
// trigger set and the confirmation subscriptions for its known
// candidates.
func (w *Watcher) startSensor(ctx context.Context,
	anchoring *Anchoring) error {

	if _, ok := w.sensors[anchoring.ID]; ok {
		return nil
	}
	if IsTerminal(anchoring.Phase) {
		return nil
	}

	sensorCtx, cancel := context.WithCancel(ctx)
	s := &sensor{
		anchoring:       anchoring,
		cancel:          cancel,
		ctx:             sensorCtx,
		candidateSubs:   make(map[chainhash.Hash]struct{}),
		actSubs:         make(map[chainhash.Hash]struct{}),
		foreclosureSubs: make(map[chainhash.Hash]struct{}),
		pending:         make(map[chainhash.Hash]*pendingCandidate),
	}

	for _, trigger := range anchoring.Triggers.OutPoints() {
		if err := w.watchTrigger(s, trigger); err != nil {
			cancel()
			return fmt.Errorf("anchoring %d: %w", anchoring.ID,
				err)
		}
	}

	// Known candidates re-subscribe so their re-confirmations and
	// re-orgs keep flowing after a restart.
	for _, candidate := range anchoring.Spends {
		err := w.watchCandidate(s, candidate.W.TxHash(),
			candidate.W.Tx())
		if err != nil {
			cancel()
			return fmt.Errorf("anchoring %d: %w", anchoring.ID,
				err)
		}
	}

	// Reconciliation: notifications missed while unsubscribed are
	// recovered by historical dispatch only for transactions still
	// in the chain — a candidate recorded on-chain that fell out
	// while we were down would otherwise stay on-chain forever.
	// Verify each recorded location against the dominant chain.
	//
	// This runs strictly after the subscriptions above so the two
	// coverages meet with overlap: a loss before this check is
	// caught here, a loss after it signals the now-live
	// subscription. Verifying first would leave a silent gap — a
	// reorg landing between the check and the subscription is too
	// late for one and invisible to the other, since a fresh
	// subscription never signals a transaction that is already
	// gone.
	//
	// A verification error is treated as "unknown, retry later": it
	// is almost always a transient notifier hiccup, and aborting
	// here leaves the anchoring sensorless, so the reconciliation
	// sweep re-runs this whole verification on its next tick. The
	// alternative — flipping OnChain=false on any error — spuriously
	// downgrades every recorded on-chain candidate on a startup with
	// a slow notifier, firing every site's OnUnwitnessed/OnConflicted
	// handlers for what turns out to be a still-buried tx. (A
	// recorded height above the dominant chain's tip is not such an
	// error: verifyLocation reads it as definitive disproof.)
	for i := range anchoring.Spends {
		candidate := anchoring.Spends[i]
		if !candidate.OnChain {
			continue
		}

		onChain, err := w.verifyLocation(
			ctx, candidate.W.Height(), candidate.W.BlockHash(),
		)
		switch {
		case err != nil:
			cancel()
			return fmt.Errorf("anchoring %d: unable to verify "+
				"candidate %v location at height %d: %w",
				anchoring.ID, candidate.W.TxHash(),
				candidate.W.Height(), err)

		case onChain:
			continue
		}

		candidate.OnChain = false
		err = w.cfg.Registry.UpsertCandidate(
			ctx, anchoring.ID, candidate,
		)
		if err != nil {
			cancel()
			return fmt.Errorf("anchoring %d: unable to "+
				"reconcile candidate %v: %w", anchoring.ID,
				candidate.W.TxHash(), err)
		}
		anchoring.Spends[i] = candidate
	}

	// Incoming foreclosure staging is reconciled before adoption: a
	// parent's lost restage toward this anchoring is rebuilt here
	// from the parents' durable phases, so derivation always sees
	// healed evidence.
	if err := w.reconcileForeclosures(ctx, anchoring.ID); err != nil {
		cancel()
		return fmt.Errorf("anchoring %d: %w", anchoring.ID, err)
	}

	// The sensor is adoptable only now that every subscription is
	// live, every recorded location verified and the incoming
	// staging reconciled: a partial sensor in the map would be
	// skipped by the reconciliation sweep, turning any failure
	// above permanent.
	w.sensors[anchoring.ID] = s

	return nil
}

// stopSensor cancels an anchoring's subscriptions and forgets it.
func (w *Watcher) stopSensor(id AnchoringID) {
	s, ok := w.sensors[id]
	if !ok {
		return
	}
	s.cancel()
	delete(w.sensors, id)
}

// watchTrigger opens the spend subscription for one trigger outpoint
// and forwards its events into the sensing loop.
func (w *Watcher) watchTrigger(s *sensor, trigger TriggerOutPoint) error {
	op := trigger.OutPoint
	reOrgChan := make(chan struct{}, 1)

	spendChan, errChan, err := w.cfg.Notifier.RegisterSpendNtfn(
		s.ctx, &op, trigger.PkScript, trigger.HeightHint, reOrgChan,
	)
	if err != nil {
		return fmt.Errorf("unable to register spend ntfn for %v: %w",
			op, err)
	}

	id := s.anchoring.ID
	w.Wg.Add(1)
	go func() {
		defer w.Wg.Done()

		for {
			select {
			case detail, ok := <-spendChan:
				if !ok {
					w.streamBroken(
						s, id, nil, "spend",
						op.String(),
					)
					return
				}
				w.forwardEvent(s.ctx, evSpendDetail{
					id: id, op: op, detail: detail,
				})

			case <-reOrgChan:
				w.forwardEvent(s.ctx, evSpendReorg{
					id: id, op: op,
				})

			case err := <-errChan:
				w.streamBroken(
					s, id, err, "spend", op.String(),
				)
				return

			case <-s.ctx.Done():
				return

			case <-w.Quit:
				return
			}
		}
	}()

	return nil
}

// watchScript returns the script under which a transaction's
// confirmations can be registered with the notifier: the first
// output script that parses as a standard class, which is what lnd
// accepts. Confirmation dispatch is keyed on the txid, so any of the
// transaction's own output scripts serves; a transaction none of
// whose outputs parse cannot be registered at all.
func watchScript(tx *wire.MsgTx) ([]byte, error) {
	for _, out := range tx.TxOut {
		if _, err := txscript.ParsePkScript(out.PkScript); err == nil {
			return out.PkScript, nil
		}
	}

	return nil, errors.New("no standard output script")
}

// earliestSpendHint returns the lowest height at which any spend of
// the anchoring's trigger set could have confirmed: the lowest
// trigger height hint, falling back to the anchoring's creation
// height when the triggers carry none.
func earliestSpendHint(a *Anchoring) uint32 {
	var hint uint32
	for _, trigger := range a.Triggers.OutPoints() {
		if trigger.HeightHint == 0 {
			continue
		}
		if hint == 0 || trigger.HeightHint < hint {
			hint = trigger.HeightHint
		}
	}
	if hint == 0 {
		hint = a.CreatedHeight
	}

	return hint
}

// watchCandidate opens the location and certification subscriptions
// for one candidate transaction and forwards their events into the
// sensing loop. The location subscription (one confirmation,
// reorg-aware) is the canonical locator: it supplies the block hash
// and transaction index the spend detail lacks, and its re-org
// channel is the per-candidate loss signal. The certification
// subscription (threshold confirmations) is the only source of
// act-tier truth: the notifier fires it exactly when the candidate
// genuinely holds the threshold depth on the dominant chain.
//
// The subscriptions hint from the trigger set, never from the
// candidate's recorded or reported height: the notifier starts its
// historical rescan no lower than the hint, and a height observed
// before a re-org (across a restart, say) may lie above where the
// transaction now sits, hiding it from the rescan for good on
// backends without a transaction index. The trigger hints bound
// every possible spend from below, so they are always safe.
func (w *Watcher) watchCandidate(s *sensor, txid chainhash.Hash,
	tx *wire.MsgTx) error {

	if _, ok := s.candidateSubs[txid]; ok {
		return nil
	}

	heightHint := earliestSpendHint(s.anchoring)
	id := s.anchoring.ID

	// A spender none of whose outputs the notifier accepts — the
	// counterparty's choice, for a foreign spend — cannot be
	// subscribed. Treating that as an error would rebuild the
	// sensor every scan just to fail identically, so the candidate
	// is left unsubscribed instead: it stays pending, and a
	// restart's historical spend dispatch rediscovers it.
	script, err := watchScript(tx)
	if err != nil {
		log.Warnf("Anchoring %d: cannot watch candidate %v: %v",
			id, txid, err)
		return nil
	}

	reOrgChan := make(chan struct{}, 1)
	confEvent, errChan, err := w.cfg.Notifier.RegisterConfirmationsNtfn(
		s.ctx, &txid, script, 1, heightHint, true,
		reOrgChan,
	)
	if err != nil {
		return fmt.Errorf("unable to register conf ntfn for %v: %w",
			txid, err)
	}

	s.candidateSubs[txid] = struct{}{}

	w.Wg.Add(1)
	go func() {
		defer w.Wg.Done()
		defer confEvent.Cancel()

		for {
			select {
			case conf, ok := <-confEvent.Confirmed:
				if !ok {
					w.streamBroken(
						s, id, nil, "conf",
						txid.String(),
					)
					return
				}
				w.forwardEvent(s.ctx, evCandidateConf{
					id: id, txid: txid, conf: conf,
				})

			case <-reOrgChan:
				w.forwardEvent(s.ctx, evCandidateReorg{
					id: id, txid: txid,
				})

			case err := <-errChan:
				w.streamBroken(
					s, id, err, "conf", txid.String(),
				)
				return

			case <-s.ctx.Done():
				return

			case <-w.Quit:
				return
			}
		}
	}()

	// At a threshold of one, the location subscription's event is
	// itself the certification; no second subscription is needed.
	if s.anchoring.Threshold <= 1 {
		return nil
	}

	actEvent, actErrChan, err := w.cfg.Notifier.RegisterConfirmationsNtfn(
		s.ctx, &txid, script, s.anchoring.Threshold,
		heightHint, true, nil,
	)
	if err != nil {
		return fmt.Errorf("unable to register act conf ntfn for "+
			"%v: %w", txid, err)
	}

	s.actSubs[txid] = struct{}{}

	w.Wg.Add(1)
	go func() {
		defer w.Wg.Done()
		defer actEvent.Cancel()

		for {
			select {
			case conf, ok := <-actEvent.Confirmed:
				if !ok {
					w.streamBroken(
						s, id, nil, "act conf",
						txid.String(),
					)
					return
				}
				w.forwardEvent(s.ctx, evCandidateActConf{
					id: id, txid: txid, conf: conf,
				})

			case err := <-actErrChan:
				w.streamBroken(
					s, id, err, "act conf",
					txid.String(),
				)
				return

			case <-s.ctx.Done():
				return

			case <-w.Quit:
				return
			}
		}
	}()

	return nil
}

// watchForeclosure opens the certification subscription for a staged
// foreclosing transaction at the child's threshold depth.
//
// The subscription hints from the parent's trigger set, never from
// the foreclosing witness's recorded height: the staged evidence may
// record a location a re-org has since displaced downward (across a
// restart, say), and a hint above the transaction's true height hides
// it from the historical rescan for good on backends without a
// transaction index. The foreclosing transaction spends the parent's
// trigger set, so the parent's trigger hints bound its confirmation
// height from below.
func (w *Watcher) watchForeclosure(ctx context.Context, s *sensor,
	parent AnchoringID, foreclosing Witness) error {

	txid := foreclosing.TxHash()
	if _, ok := s.foreclosureSubs[txid]; ok {
		return nil
	}

	// Unwatchable foreclosing forms are skipped like unwatchable
	// candidates. By provenance they should not arise: a foreclosing
	// witness was recorded as some parent's candidate, which
	// required a watchable script.
	tx := foreclosing.Tx()
	script, err := watchScript(tx)
	if err != nil {
		log.Warnf("Anchoring %d: cannot watch foreclosure %v: %v",
			s.anchoring.ID, txid, err)
		return nil
	}

	parentAnchoring, err := w.cfg.Registry.GetAnchoring(ctx, parent)
	if err != nil {
		return fmt.Errorf("unable to load foreclosing parent %d: %w",
			parent, err)
	}
	heightHint := earliestSpendHint(parentAnchoring)

	confEvent, errChan, err := w.cfg.Notifier.RegisterConfirmationsNtfn(
		s.ctx, &txid, script, s.anchoring.Threshold,
		heightHint, true, nil,
	)
	if err != nil {
		return fmt.Errorf("unable to register foreclosure conf "+
			"ntfn for %v: %w", txid, err)
	}

	s.foreclosureSubs[txid] = struct{}{}

	child := s.anchoring.ID
	w.Wg.Add(1)
	go func() {
		defer w.Wg.Done()
		defer confEvent.Cancel()

		for {
			select {
			case conf, ok := <-confEvent.Confirmed:
				if !ok {
					w.streamBroken(
						s, child, nil,
						"foreclosure conf",
						txid.String(),
					)
					return
				}
				w.forwardEvent(s.ctx, evForeclosureActConf{
					child:  child,
					parent: parent,
					conf:   conf,
				})

			case err := <-errChan:
				w.streamBroken(
					s, child, err, "foreclosure conf",
					txid.String(),
				)
				return

			case <-s.ctx.Done():
				return

			case <-w.Quit:
				return
			}
		}
	}()

	return nil
}

// forwardEvent pushes a subscription event into the sensing loop,
// giving up on sensor teardown or shutdown.
func (w *Watcher) forwardEvent(sensorCtx context.Context, event any) {
	select {
	case w.events <- event:
	case <-sensorCtx.Done():
	case <-w.Quit:
	}
}

// handleSpendDetail processes a confirmed spend of a trigger
// outpoint: evaluate the site predicate once for a newly discovered
// spender, and ensure the candidate's confirmation subscription is
// open.
func (w *Watcher) handleSpendDetail(ctx context.Context, ev evSpendDetail) {
	s, ok := w.sensors[ev.id]
	if !ok {
		return
	}

	detail := ev.detail
	if detail.SpenderTxHash == nil || detail.SpendingTx == nil {
		// A malformed detail cannot be acted on; rebuilding the
		// sensor re-delivers the spend through historical
		// dispatch, intact.
		log.Errorf("Anchoring %d: malformed spend detail for %v, "+
			"resensing", ev.id, ev.op)
		w.resense(ev.id)
		return
	}
	txid := *detail.SpenderTxHash

	// A known candidate: its verdict is already recorded, and its
	// confirmation subscription (opened below if missing) delivers
	// location changes.
	known := false
	for _, candidate := range s.anchoring.Spends {
		if candidate.W.TxHash() == txid {
			known = true
			break
		}
	}
	if _, ok := s.pending[txid]; ok {
		known = true
	}

	if !known {
		// The whole-set rule is enforced structurally before the
		// site is ever consulted: a transaction spending only
		// part of the trigger set cannot realize the anchoring,
		// and while it stands it forecloses any transaction that
		// could — it is foreign by construction. Only a spender
		// covering the entire set poses the semantic question
		// the site's predicate exists to answer, which is what
		// makes the coexistence of satisfying and foreign
		// outcomes on one chain unrepresentable regardless of
		// site code.
		verdict := VerdictForeign
		spent := s.anchoring.Triggers.SpentBy(detail.SpendingTx)
		if len(spent) == s.anchoring.Triggers.Len() {
			site, ok := w.sites[s.anchoring.Site]
			if !ok {
				// A wiring defect (sites register before
				// Start), deterministic until the daemon
				// restarts with the site in place;
				// escalating or resensing would only
				// repeat it.
				log.Errorf("Anchoring %d: no site %v "+
					"registered, cannot evaluate "+
					"candidate %v", ev.id,
					s.anchoring.Site, txid)
				return
			}

			err := capturePanic("site predicate", func() error {
				var evalErr error
				verdict, evalErr = site.EvaluateCandidate(
					s.anchoring.MatchData,
					detail.SpendingTx,
				)

				return evalErr
			})
			if err != nil {
				// A predicate error — a panic included —
				// is a code defect (a decode failure),
				// not a chain condition: surface it
				// loudly and leave the candidate
				// unevaluated; the spend subscription
				// will re-deliver it on restart once the
				// defect is fixed. Note the spending
				// transaction is counterparty data, so
				// this path must never escalate to a
				// daemon fault: a rejected payload would
				// become a remotely triggered,
				// restart-persistent crash.
				log.Errorf("Anchoring %d: predicate "+
					"failed on candidate %v: %v",
					ev.id, txid, err)
				return
			}
		}

		s.pending[txid] = &pendingCandidate{
			tx:      detail.SpendingTx.Copy(),
			verdict: verdict,
		}
	}

	err := w.watchCandidate(s, txid, detail.SpendingTx)
	if err != nil {
		log.Warnf("Anchoring %d: unable to watch candidate %v, "+
			"resensing: %v", ev.id, txid, err)
		w.resense(ev.id)
	}
}

// handleCandidateConf records a candidate's full location in the
// registry and re-derives.
func (w *Watcher) handleCandidateConf(ctx context.Context,
	ev evCandidateConf) {

	s, ok := w.sensors[ev.id]
	if !ok {
		return
	}

	conf := ev.conf
	if conf.BlockHash == nil || conf.Tx == nil {
		log.Errorf("Anchoring %d: malformed conf for %v, "+
			"resensing", ev.id, ev.txid)
		w.resense(ev.id)
		return
	}

	witness, err := NewWitness(
		conf.Tx, *conf.BlockHash, conf.BlockHeight, conf.TxIndex,
	)
	if err != nil {
		log.Errorf("Anchoring %d: bad conf for %v, resensing: %v",
			ev.id, ev.txid, err)
		w.resense(ev.id)
		return
	}

	// The verdict comes from the pending record for a new
	// candidate, or from the recorded chain view for a
	// re-confirming one. The pending entry is consumed only once
	// the observation is durably recorded below: consuming it for
	// an event that then turns out stale would leave the candidate
	// in neither the pending map nor the registry, and its next
	// confirmation with no verdict to attach.
	var (
		verdict     Verdict
		found       bool
		fromPending bool
	)
	if pending, ok := s.pending[ev.txid]; ok {
		verdict, found, fromPending = pending.verdict, true, true
	} else {
		for _, candidate := range s.anchoring.Spends {
			if candidate.W.TxHash() == ev.txid {
				verdict, found = candidate.Verdict, true
				break
			}
		}
	}
	if !found {
		// A confirmation for a transaction we never evaluated:
		// nothing sound to record here, but rebuilding the
		// sensor replays the spend discovery that evidently went
		// missing, evaluation included.
		log.Warnf("Anchoring %d: conf for unknown candidate %v, "+
			"resensing", ev.id, ev.txid)
		w.resense(ev.id)
		return
	}

	// A confirmation may be stale by the time it is processed (the
	// chain moved on, or the event predates a sensor rebuild);
	// verify the location before recording it as on-chain. A stale
	// confirmation is simply dropped: whatever the chain holds now
	// produces its own events.
	onChain, err := w.verifyLocation(
		ctx, witness.Height(), witness.BlockHash(),
	)
	if err != nil {
		log.Warnf("Anchoring %d: unable to verify candidate %v, "+
			"resensing: %v", ev.id, ev.txid, err)
		w.resense(ev.id)
		return
	}
	if !onChain {
		log.Debugf("Anchoring %d: dropping stale confirmation of "+
			"%v at height %d", ev.id, ev.txid, witness.Height())
		return
	}

	// The trigger outpoints this candidate spends, recomputed from
	// the transaction itself.
	spent := s.anchoring.Triggers.SpentBy(conf.Tx)

	header, merkle := witnessEnrichment(conf)
	err = w.cfg.Registry.UpsertCandidate(ctx, ev.id, CandidateSpend{
		Verdict: verdict,
		W:       witness,
		OnChain: true,
		// At a threshold of one, the first confirmation is
		// itself the act certification.
		ActCertified:   s.anchoring.Threshold <= 1,
		BlockHeader:    header,
		MerkleProof:    merkle,
		SpentOutPoints: spent,
	})
	if err != nil {
		log.Warnf("Anchoring %d: unable to record candidate %v, "+
			"resensing: %v", ev.id, ev.txid, err)
		w.resense(ev.id)
		return
	}

	if fromPending {
		delete(s.pending, ev.txid)
	}

	w.rederive(ctx, ev.id)
}

// handleCandidateActConf records a notifier certification of a
// candidate at the anchoring's threshold depth and re-derives. The
// notifier only fires the certification for a transaction genuinely
// at that depth on the dominant chain, but the event can be stale by
// the time it is processed, so the certifying location is verified
// against the chain before anything is recorded. Once recorded, the
// certification is sticky: a reorg deeper than the threshold after
// that point is the out-of-scope case, not a retraction.
//
// The pending-map lookup below is a fallback for recovery paths
// where the location event's in-memory bookkeeping was lost but the
// spend discovery re-ran; ordinarily the location conf that preceded
// this certification already consumed the entry.
func (w *Watcher) handleCandidateActConf(ctx context.Context,
	ev evCandidateActConf) {

	s, ok := w.sensors[ev.id]
	if !ok {
		return
	}

	conf := ev.conf
	if conf.BlockHash == nil || conf.Tx == nil {
		log.Errorf("Anchoring %d: malformed act conf for %v, "+
			"resensing", ev.id, ev.txid)
		w.resense(ev.id)
		return
	}

	witness, err := NewWitness(
		conf.Tx, *conf.BlockHash, conf.BlockHeight, conf.TxIndex,
	)
	if err != nil {
		log.Errorf("Anchoring %d: bad act conf for %v, "+
			"resensing: %v", ev.id, ev.txid, err)
		w.resense(ev.id)
		return
	}

	var (
		verdict     Verdict
		found       bool
		fromPending bool
	)
	if pending, ok := s.pending[ev.txid]; ok {
		verdict, found, fromPending = pending.verdict, true, true
	} else {
		for _, candidate := range s.anchoring.Spends {
			if candidate.W.TxHash() == ev.txid {
				verdict, found = candidate.Verdict, true
				break
			}
		}
	}
	if !found {
		log.Warnf("Anchoring %d: act conf for unknown candidate "+
			"%v, resensing", ev.id, ev.txid)
		w.resense(ev.id)
		return
	}

	spent := s.anchoring.Triggers.SpentBy(conf.Tx)

	onChain, err := w.verifyLocation(
		ctx, witness.Height(), witness.BlockHash(),
	)
	if err != nil {
		log.Warnf("Anchoring %d: unable to verify act conf of "+
			"%v, resensing: %v", ev.id, ev.txid, err)
		w.resense(ev.id)
		return
	}

	// The chain has already displaced the certifying location: a
	// reorg at least threshold deep landed between the notifier's
	// dispatch and this point. Recording the certification anyway
	// would freeze a disproved location — orphaned block header and
	// merkle proof included — into the very row burial handlers
	// rebuild proofs from. Drop it and rebuild the sensor instead:
	// if the candidate re-buries on the surviving chain, the fresh
	// certification subscription re-fires with a location that
	// holds; if it never does, withholding act finality was exactly
	// right.
	if !onChain {
		log.Warnf("Anchoring %d: act certification of %v at "+
			"height %d disproved by the dominant chain, "+
			"resensing", ev.id, ev.txid, witness.Height())
		w.resense(ev.id)
		return
	}

	header, merkle := witnessEnrichment(conf)
	err = w.cfg.Registry.UpsertCandidate(ctx, ev.id, CandidateSpend{
		Verdict:        verdict,
		W:              witness,
		OnChain:        true,
		ActCertified:   true,
		BlockHeader:    header,
		MerkleProof:    merkle,
		SpentOutPoints: spent,
	})
	if err != nil {
		log.Warnf("Anchoring %d: unable to certify candidate %v, "+
			"resensing: %v", ev.id, ev.txid, err)
		w.resense(ev.id)
		return
	}

	if fromPending {
		delete(s.pending, ev.txid)
	}

	w.rederive(ctx, ev.id)
}

// handleForeclosureActConf records a notifier certification of a
// foreclosing transaction at the child's threshold depth and
// re-derives the child.
func (w *Watcher) handleForeclosureActConf(ctx context.Context,
	ev evForeclosureActConf) {

	if _, ok := w.sensors[ev.child]; !ok {
		return
	}

	conf := ev.conf
	if conf.BlockHash == nil || conf.Tx == nil {
		log.Errorf("Anchoring %d: malformed foreclosure conf, "+
			"resensing", ev.child)
		w.resense(ev.child)
		return
	}

	witness, err := NewWitness(
		conf.Tx, *conf.BlockHash, conf.BlockHeight, conf.TxIndex,
	)
	if err != nil {
		log.Errorf("Anchoring %d: bad foreclosure conf, "+
			"resensing: %v", ev.child, err)
		w.resense(ev.child)
		return
	}

	onChain, err := w.verifyLocation(
		ctx, witness.Height(), witness.BlockHash(),
	)
	if err != nil {
		log.Warnf("Anchoring %d: unable to verify foreclosure "+
			"conf, resensing: %v", ev.child, err)
		w.resense(ev.child)
		return
	}

	// As with candidate certifications: a certifying location the
	// chain has already displaced is not recorded, since a
	// certified foreclosure is absorbing and would abandon the
	// child on disproved evidence. The rebuilt sensor re-certifies
	// from the surviving chain if the foreclosure still stands.
	if !onChain {
		log.Warnf("Anchoring %d: foreclosure certification of %v "+
			"disproved by the dominant chain, resensing",
			ev.child, witness.TxHash())
		w.resense(ev.child)
		return
	}

	err = w.cfg.Registry.StageForeclosure(
		ctx, ev.child, ev.parent, ForeclosureEvent{
			Parent:       ev.parent,
			W:            witness,
			OnChain:      true,
			ActCertified: true,
		},
	)
	if err != nil {
		log.Warnf("Anchoring %d: unable to certify foreclosure, "+
			"resensing: %v", ev.child, err)
		w.resense(ev.child)
		return
	}

	w.rederive(ctx, ev.child)
}

// markCandidateOffChain flips a recorded candidate off-chain and
// re-derives.
func (w *Watcher) markCandidateOffChain(ctx context.Context,
	id AnchoringID, txid chainhash.Hash) {

	s, ok := w.sensors[id]
	if !ok {
		return
	}

	for _, candidate := range s.anchoring.Spends {
		if candidate.W.TxHash() != txid || !candidate.OnChain {
			continue
		}

		// A loss signal may itself be stale (reordered past the
		// confirmation that superseded it); flip the candidate
		// off-chain only if its recorded location really is gone
		// from the dominant chain.
		stillThere, err := w.verifyLocation(
			ctx, candidate.W.Height(), candidate.W.BlockHash(),
		)
		if err != nil {
			log.Warnf("Anchoring %d: unable to verify loss of "+
				"%v, resensing: %v", id, txid, err)
			w.resense(id)
			return
		}
		if stillThere {
			log.Debugf("Anchoring %d: dropping stale loss "+
				"signal for %v", id, txid)
			return
		}

		candidate.OnChain = false
		err = w.cfg.Registry.UpsertCandidate(ctx, id, candidate)
		if err != nil {
			log.Warnf("Anchoring %d: unable to mark candidate "+
				"%v off-chain, resensing: %v", id, txid, err)
			w.resense(id)
			return
		}

		w.rederive(ctx, id)
		return
	}
}

// rederive recomputes an anchoring's phase from its chain view,
// persists a change, keeps dependents' staged foreclosures current,
// and kicks the delivery loop.
func (w *Watcher) rederive(ctx context.Context, id AnchoringID) {
	s, ok := w.sensors[id]
	if !ok {
		return
	}

	view, err := w.cfg.Registry.ChainView(ctx, id)
	if err != nil {
		log.Warnf("Anchoring %d: unable to load chain view, "+
			"resensing: %v", id, err)
		w.resense(id)
		return
	}

	derived := DerivePhase(view)

	// A staged but uncertified foreclosure needs its certification
	// subscription: the child abandons only when the notifier
	// certifies the foreclosing transaction at the child's own
	// threshold.
	if fc := view.Foreclosure.UnwrapToPtr(); fc != nil &&
		!fc.ActCertified {

		err := w.watchForeclosure(ctx, s, fc.Parent, fc.W)
		if err != nil {
			log.Warnf("Anchoring %d: unable to watch "+
				"foreclosure, resensing: %v", id, err)
			w.resense(id)
			return
		}
	}

	// Refresh the sensor's cached aggregate: candidates may have
	// changed even when the phase did not.
	fresh, err := w.cfg.Registry.GetAnchoring(ctx, id)
	if err != nil {
		log.Warnf("Anchoring %d: unable to reload, resensing: %v",
			id, err)
		w.resense(id)
		return
	}
	s.anchoring = fresh

	// Terminal sensed phases are absorbing: act-level finality is
	// exactly the point past which the chain's later opinion no
	// longer counts. A reorg deeper than the threshold after the
	// registry has sensed Buried or Abandoned does not reopen the
	// question; sensing simply ends.
	if IsTerminal(fresh.Phase) {
		w.stopSensor(id)
		return
	}

	if PhaseEqual(derived, fresh.Phase) {
		return
	}

	if err := w.cfg.Registry.SetPhase(ctx, id, derived); err != nil {
		// A concurrent writer — a site-initiated withdrawal —
		// pinned the row terminal between the check above and
		// this write; the row-level guard held. Resensing
		// adopts the terminal outcome.
		if errors.Is(err, ErrTerminalPhase) {
			log.Infof("Anchoring %d: pinned terminal by a "+
				"concurrent writer, resensing", id)
			w.resense(id)
			return
		}

		log.Warnf("Anchoring %d: unable to set phase, "+
			"resensing: %v", id, err)
		w.resense(id)
		return
	}
	s.anchoring.Phase = derived

	log.Infof("Anchoring %d (site=%v): phase %v -> %v", id,
		fresh.Site, fresh.Phase, derived)

	if IsTerminal(derived) {
		w.stopSensor(id)
	}

	w.restageDependentForeclosures(ctx, id, derived)
	w.kick(w.deliveryKick)
}

// restageEdge reconciles one child→parent edge's staged foreclosure
// with the parent's phase: a witness in a different form than the
// edge depends on stages foreclosure; the depended-upon form clears
// it; loss of the witness downgrades staged evidence to off-chain.
// The staging is a pure function of (parent phase, edge), so lost
// writes are always rebuildable; an edge carrying a certified
// foreclosure is frozen by the registry, making every write here
// benign against it.
func (w *Watcher) restageEdge(ctx context.Context, parentPhase Phase,
	edge DependencyEdge) error {

	var witness *Witness
	switch p := parentPhase.(type) {
	case Witnessed:
		witness = &p.W
	case Buried:
		witness = &p.W

	// An abandoned parent forecloses every edge: the transaction
	// that decided against it stands on chain with act-level
	// finality, whatever form the child depended on. Stage the
	// cause witness, mirroring the terminal delivery's settlement,
	// rather than falling through to the not-witnessed downgrade
	// below.
	case Abandoned:
		return w.cfg.Registry.StageForeclosure(
			ctx, edge.Child, edge.Parent, ForeclosureEvent{
				Parent:  edge.Parent,
				W:       p.Cause.Witness(),
				OnChain: true,
			},
		)
	}

	switch {
	// The parent is witnessed in the very form the child depends
	// on: no foreclosure.
	case witness != nil && witness.TxHash() == edge.ParentWitnessTxHash:
		return w.cfg.Registry.ClearForeclosure(
			ctx, edge.Child, edge.Parent,
		)

	// The parent is witnessed in a different form: the depended-
	// upon outputs are gone while that form stands.
	case witness != nil:
		return w.cfg.Registry.StageForeclosure(
			ctx, edge.Child, edge.Parent, ForeclosureEvent{
				Parent:  edge.Parent,
				W:       *witness,
				OnChain: true,
			},
		)

	// The parent is not witnessed at all: any staged foreclosing
	// evidence is itself off-chain.
	default:
		staged := edge.Foreclosure.UnwrapToPtr()
		if staged == nil || !staged.OnChain {
			return nil
		}
		staged.OnChain = false

		return w.cfg.Registry.StageForeclosure(
			ctx, edge.Child, edge.Parent, *staged,
		)
	}
}

// reconcileForeclosures rebuilds an anchoring's incoming staged
// foreclosure evidence from its parents' current phases. It runs at
// sensor adoption, which makes a lost restage self-healing: any
// failure on the parent-side restage path drops a sensor, and the
// sweep's re-adoption arrives here, where the staging is recomputed
// from durable state.
func (w *Watcher) reconcileForeclosures(ctx context.Context,
	id AnchoringID) error {

	edges, err := w.cfg.Registry.IncomingEdges(ctx, id)
	if err != nil {
		return fmt.Errorf("unable to load incoming edges: %w", err)
	}

	for _, edge := range edges {
		parent, err := w.cfg.Registry.GetAnchoring(ctx, edge.Parent)
		if err != nil {
			return fmt.Errorf("unable to load parent %d: %w",
				edge.Parent, err)
		}

		if err := w.restageEdge(ctx, parent.Phase, edge); err != nil {
			return fmt.Errorf("unable to restage edge from "+
				"%d: %w", edge.Parent, err)
		}
	}

	return nil
}

// restageDependentForeclosures keeps the staged foreclosure evidence
// on this anchoring's dependents consistent with its current phase.
// This is the latency path; terminal deliveries settle the edges
// again inside the delivery transaction, and a child's adoption
// rebuilds its incoming staging, so a write lost here is always
// recovered.
func (w *Watcher) restageDependentForeclosures(ctx context.Context,
	id AnchoringID, phase Phase) {

	edges, err := w.cfg.Registry.DependencyEdges(ctx, id)
	if err != nil {
		// Dropping this sensor re-runs the restage on the
		// sweep's re-adoption: adoption re-derives, and a
		// re-derivation that changes no phase still restages
		// dependents through the adoption path.
		log.Warnf("Anchoring %d: unable to load dependency "+
			"edges, resensing: %v", id, err)
		w.resense(id)
		return
	}

	for _, edge := range edges {
		if err := w.restageEdge(ctx, phase, edge); err != nil {
			// The child's re-adoption rebuilds its incoming
			// staging from this parent's durable phase, so
			// dropping the child's sensor retries exactly
			// the write that failed.
			log.Warnf("Anchoring %d: unable to restage "+
				"foreclosure on %d, resensing it: %v", id,
				edge.Child, err)
			w.resense(edge.Child)
			continue
		}

		w.rederive(ctx, edge.Child)
	}
}

// deliveryLoop converges sites to sensed phases: it scans for
// anchorings whose delivered phase lags, runs the site handler
// atomically with the registry advance, and applies the failure
// policy. Deliveries run one at a time.
func (w *Watcher) deliveryLoop() {
	defer w.Wg.Done()

	ctx, cancel := w.WithCtxQuitNoTimeout()
	defer cancel()

	ticker := time.NewTicker(w.cfg.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		case <-w.deliveryKick:
		case <-w.Quit:
			return
		}

		w.deliverPending(ctx)
	}
}

// deliverPending runs one delivery pass.
func (w *Watcher) deliverPending(ctx context.Context) {
	pending, err := w.cfg.Registry.PendingDeliveries(
		ctx, w.cfg.Clock.Now(),
	)
	if err != nil {
		log.Warnf("Unable to scan pending deliveries, next scan "+
			"will retry: %v", err)
		return
	}

	for _, anchoring := range pending {
		select {
		case <-w.Quit:
			return
		default:
		}

		w.deliverOne(ctx, anchoring)
	}
}

// deliverOne attempts one delivery and applies the failure policy.
func (w *Watcher) deliverOne(ctx context.Context, anchoring *Anchoring) {
	site, ok := w.sites[anchoring.Site]
	if !ok {
		// No site implementation for a persisted anchoring is a
		// wiring defect; record it through the normal failure
		// path so it is visible and retried once fixed.
		w.failDelivery(ctx, anchoring, fmt.Errorf("no site %v "+
			"registered", anchoring.Site))
		return
	}

	target := anchoring.Phase
	err := w.cfg.Registry.Deliver(
		ctx, anchoring.ID, target,
		func(ctx context.Context, tx RegistryTx,
			fresh *Anchoring) error {

			// A panicking handler rolls its transaction back
			// and fails this one delivery, entering the
			// ordinary backoff-and-retry bookkeeping.
			return capturePanic("site handler", func() error {
				return dispatchPhase(
					ctx, site, tx, fresh, target,
				)
			})
		},
	)
	switch {
	// Sensing moved on mid-flight; the rescan will pick up the new
	// phase.
	case errors.Is(err, ErrStaleDelivery):
		w.kick(w.deliveryKick)
		return

	case err != nil:
		w.failDelivery(ctx, anchoring, err)
		return
	}

	log.Infof("Anchoring %d (site=%v): delivered %v", anchoring.ID,
		anchoring.Site, target)

	// Listeners are latency path only, so they run off the delivery
	// loop, one goroutine per listener: a slow, blocking or
	// panicking listener must neither stall convergence nor take
	// the daemon down. The registry remains the durable delivery
	// record, so nothing is owed to a listener that never returns;
	// shutdown does not wait for them.
	for _, listener := range w.listeners {
		go func() {
			err := capturePanic("delivery listener", func() error {
				listener(anchoring.ID, anchoring.Site, target)
				return nil
			})
			if err != nil {
				log.Errorf("Anchoring %d: %v", anchoring.ID,
					err)
			}
		}()
	}

	// Handlers may have enqueued effects.
	w.kick(w.outboxKick)

	if !IsTerminal(target) {
		return
	}

	// Terminal delivery ends sensing. It also settled its
	// dependents' edges (inside the delivery transaction); their
	// phases re-derive now, parent-first by construction.
	err = w.sendEvent(ctx, evStopSensing{id: anchoring.ID})
	if err != nil {
		return
	}
	edges, err := w.cfg.Registry.DependencyEdges(ctx, anchoring.ID)
	if err != nil {
		// The edge settlements themselves committed with the
		// delivery; only the prompt re-derivation nudge is
		// lost, and the children re-derive on their next
		// sensing event.
		log.Warnf("Anchoring %d: unable to load dependents "+
			"for cascade: %v", anchoring.ID, err)
		return
	}
	for _, edge := range edges {
		err := w.sendEvent(ctx, evSense{id: edge.Child})
		if err != nil {
			return
		}
	}
}

// backoffFor computes the next-attempt backoff for the given attempt
// count under the watcher's exponential-with-cap policy: the base
// InitialDeliveryBackoff doubled once per prior attempt, capped at
// MaxDeliveryBackoff. Attempts of 0 or 1 return the base backoff;
// higher attempts double it until the cap is reached.
func (w *Watcher) backoffFor(attempts uint32) time.Duration {
	backoff := w.cfg.InitialDeliveryBackoff
	limit := w.cfg.MaxDeliveryBackoff
	for i := uint32(1); i < attempts && backoff < limit; i++ {
		backoff *= 2
	}
	if backoff > w.cfg.MaxDeliveryBackoff {
		backoff = w.cfg.MaxDeliveryBackoff
	}

	return backoff
}

// failDelivery records a failed delivery attempt with exponential
// backoff, flagging the anchoring stuck once attempts pass the
// threshold. Retries never stop; stuck is a visibility condition, not
// an end state.
func (w *Watcher) failDelivery(ctx context.Context, anchoring *Anchoring,
	deliveryErr error) {

	attempts := anchoring.DeliveryAttempts + 1
	stuck := attempts >= w.cfg.StuckAfterAttempts

	backoff := w.backoffFor(attempts)

	log.Errorf("Anchoring %d (site=%v): delivery of %v failed "+
		"(attempt %d, stuck=%v): %v", anchoring.ID, anchoring.Site,
		anchoring.Phase, attempts, stuck, deliveryErr)

	err := w.cfg.Registry.RecordDeliveryFailure(
		ctx, anchoring.ID, deliveryErr,
		w.cfg.Clock.Now().Add(backoff), stuck,
	)
	if err != nil {
		log.Warnf("Anchoring %d: unable to record delivery "+
			"failure: %v", anchoring.ID, err)
	}
}

// capturePanic runs fn, converting a panic into a returned error
// carrying the panic value and stack. Site, listener and effect
// callbacks operate on counterparty-influenced data at the daemon's
// boundary; a panic there is contained as a failure of that one
// callback, never a daemon crash — lnd's historical dispatch would
// re-deliver the offending payload on every restart, so an
// uncontained panic is a remotely triggered, restart-persistent one.
func capturePanic(desc string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s panicked: %v\n%s", desc, r,
				debug.Stack())
		}
	}()

	return fn()
}

// dispatchPhase routes a delivery to the site handler for the target
// phase.
func dispatchPhase(ctx context.Context, site Site, tx RegistryTx,
	anchoring *Anchoring, target Phase) error {

	switch target.(type) {
	case Unwitnessed:
		return site.OnUnwitnessed(ctx, tx, anchoring)

	case Witnessed:
		return site.OnWitnessed(ctx, tx, anchoring)

	case Conflicted:
		return site.OnConflicted(ctx, tx, anchoring)

	case Buried:
		return site.OnBuried(ctx, tx, anchoring)

	case Abandoned:
		return site.OnAbandoned(ctx, tx, anchoring)

	case Withdrawn:
		// Withdrawal is site-initiated; sensed and delivered
		// advance together at withdrawal time, so no delivery
		// ever targets it.
		return fmt.Errorf("withdrawn is never delivered")

	default:
		return fmt.Errorf("unknown phase %T", target)
	}
}

// outboxLoop dispatches enqueued external effects, idempotently and
// with backoff.
func (w *Watcher) outboxLoop() {
	defer w.Wg.Done()

	ctx, cancel := w.WithCtxQuitNoTimeout()
	defer cancel()

	ticker := time.NewTicker(w.cfg.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		case <-w.outboxKick:
		case <-w.Quit:
			return
		}

		w.dispatchEffects(ctx)
	}
}

// dispatchEffects runs one outbox pass.
func (w *Watcher) dispatchEffects(ctx context.Context) {
	for {
		effects, err := w.cfg.Registry.PendingEffects(
			ctx, w.cfg.Clock.Now(), outboxBatchSize,
		)
		if err != nil {
			log.Warnf("Unable to scan outbox, next scan will "+
				"retry: %v", err)
			return
		}
		if len(effects) == 0 {
			return
		}

		advanced := false
		for _, effect := range effects {
			select {
			case <-w.Quit:
				return
			default:
			}

			if w.dispatchOne(ctx, effect) {
				advanced = true
			}
		}

		// A pass that advanced no effect's bookkeeping would
		// re-fetch the same rows and re-invoke their handlers
		// in a tight loop; wait for the next scan instead.
		if !advanced || len(effects) < outboxBatchSize {
			return
		}
	}
}

// dispatchOne dispatches a single effect and applies the failure
// policy. It reports whether the effect's bookkeeping advanced (the
// effect was marked dispatched, or its failure was recorded with a
// backoff): an effect whose bookkeeping did not advance would be
// re-fetched, and re-dispatched, by an immediate rescan.
func (w *Watcher) dispatchOne(ctx context.Context,
	effect *StoredEffect) bool {

	var dispatchErr error
	handler, ok := w.effectHandlers[effect.Effect.Kind]
	if !ok {
		dispatchErr = fmt.Errorf("no handler for effect kind %v",
			effect.Effect.Kind)
	} else {
		// A panicking handler fails this one dispatch, entering
		// the ordinary backoff-and-retry bookkeeping.
		dispatchErr = capturePanic("effect handler", func() error {
			return handler(ctx, effect.Effect.Payload)
		})
	}

	if dispatchErr == nil {
		err := w.cfg.Registry.MarkEffectDispatched(ctx, effect.ID)
		if err != nil {
			log.Warnf("Unable to mark effect %d dispatched: %v",
				effect.ID, err)
			return false
		}
		return true
	}

	attempts := effect.Attempts + 1
	backoff := w.backoffFor(attempts)

	log.Errorf("Effect %d (kind=%v): dispatch failed (attempt %d): %v",
		effect.ID, effect.Effect.Kind, attempts, dispatchErr)

	err := w.cfg.Registry.RecordEffectFailure(
		ctx, effect.ID, dispatchErr, w.cfg.Clock.Now().Add(backoff),
	)
	if err != nil {
		log.Warnf("Unable to record effect %d failure: %v",
			effect.ID, err)
		return false
	}

	return true
}

// kick wakes a loop ahead of its ticker.
func (w *Watcher) kick(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// streamBroken handles a subscription stream ending, from either an
// error or a channel close. Broken streams are routine — the notifier
// prunes conf and spend subscriptions a safety margin past their
// dispatch, and an lnd restart severs every stream at once — so the
// response is repair, not escalation: the sensor is dropped (via the
// sensing loop, which owns it) and the reconciliation sweep
// re-establishes sensing, with historical dispatch regenerating any
// missed facts. Benign shutdown artifacts are ignored.
func (w *Watcher) streamBroken(s *sensor, id AnchoringID, err error,
	kind, subject string) {

	if fn.IsCanceled(err) ||
		fn.IsRpcErr(err, chainntnfs.ErrChainNotifierShuttingDown) {

		return
	}

	if err == nil {
		log.Debugf("Anchoring %d: %s stream for %s closed, "+
			"resensing", id, kind, subject)
	} else {
		log.Warnf("Anchoring %d: %s stream for %s broke, "+
			"resensing: %v", id, kind, subject, err)
	}

	w.forwardEvent(s.ctx, evResense{id: id, s: s})
}

// reportErr reports a critical error to the main server. The send
// blocks until the consumer takes it or the watcher shuts down: the
// escalation exists precisely so the daemon does not run on with
// sensing dead, so an unready consumer — startup, or a shared error
// channel already carrying another subsystem's failure — must delay
// it, never drop it.
func (w *Watcher) reportErr(err error) {
	log.Errorf("Watcher error: %v", err)

	select {
	case w.cfg.ErrChan <- err:
	case <-w.Quit:
	}
}
