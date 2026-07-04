package tapdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/universe"
)

// defaultFlushTimeout bounds a single flush transaction. Flushes run on
// a background context, decoupled from any caller's deadline, so
// without a bound a stalled database would pin the flusher role — and
// every caller awaiting it — indefinitely.
const defaultFlushTimeout = time.Minute

// maxFlushBatchSize bounds the number of universes applied in a single
// flush transaction, so that no flush can grow into a transaction
// large enough to overrun the flush timeout wholesale. Excess pending
// updates simply roll over into the next round.
const maxFlushBatchSize = 2048

// defaultFlushRetryBackoff is the initial delay before the universes
// of a failed flush round are retried. It doubles per consecutive
// failure, up to maxFlushRetryBackoff.
const defaultFlushRetryBackoff = time.Second

// maxFlushRetryBackoff caps the exponential backoff between retries of
// failing flush rounds, so a database outage is probed at a bounded,
// unhurried rate for however long it lasts.
const maxFlushRetryBackoff = time.Minute

// errUniverseDeleted is delivered to waiters whose universe no longer
// exists by the time the flush reads it back: the universe was deleted
// after the update was submitted. Deletion removes the universe's
// multiverse leaf in the same transaction as its tree, so there is
// nothing left to refresh.
var errUniverseDeleted = errors.New(
	"universe deleted during multiverse update",
)

// errCoalescerStopped is delivered to waiters, and returned to new
// submitters, once the coalescer has been stopped. Universe leaves
// already committed stay durable; their multiverse entries are
// repaired by startup reconciliation on the next run.
var errCoalescerStopped = errors.New("multiverse coalescer stopped")

// errFlushPanicked wraps a panic recovered during a flush. Unlike an
// error returned by the database, a panic is presumed to be a bug
// rather than a transient failure, so panicked rounds are not retried.
var errFlushPanicked = errors.New("multiverse flush panic")

// multiverseFlushTx is the transaction options for the coalescer's
// flushes. It is a distinct type so flush transactions are
// recognizable as such, in particular by tests acting at the boundary
// between a universe commit and its multiverse flush.
//
// Flushes run at the default serializable isolation, so consistency of
// the multiverse trees is enforced by the database itself, against
// every writer — including ones outside this process, such as a second
// tapd sharing the database during a rolling restart. The in-process
// write mutex is not what makes concurrent writes safe; its role is
// confined to ordering the post-commit cache maintenance of the
// writers within this process.
type multiverseFlushTx struct{}

// ReadOnly returns false: flushes write.
func (multiverseFlushTx) ReadOnly() bool {
	return false
}

// multiverseRootUpdate is the outcome of a flushed multiverse root
// update: the universe root the flush derived and committed, the
// multiverse root after the flush that carried the update, and the
// inclusion proof for the universe's leaf within that root.
type multiverseRootUpdate struct {
	// universeRoot is the universe root the flush derived inside its
	// transaction and committed to the multiverse leaf. It may be
	// fresher than the root a waiter's own transaction committed, if
	// a concurrent insert into the same universe landed in between.
	universeRoot mssmt.Node

	// multiverseRoot is the root of the multiverse tree after the
	// flush.
	multiverseRoot mssmt.Node

	// inclusionProof is the inclusion proof of the universe's leaf
	// within multiverseRoot.
	inclusionProof *mssmt.Proof
}

// flushResult is what a waiter receives once the flush carrying its
// update has completed, or failed.
type flushResult struct {
	update multiverseRootUpdate
	err    error
}

// flushWaiter is a caller awaiting the flush of a pending update. Only
// waiters that want the multiverse root and inclusion proof cause them
// to be generated; batch callers skip that work.
type flushWaiter struct {
	result    chan flushResult
	wantProof bool
}

// pendingRootUpdate is a universe awaiting a refresh of its multiverse
// leaf, along with every caller awaiting a flush that carries the
// refresh. Keeping at most one pending entry per universe is what
// coalesces redundant multiverse writes: the flush derives the
// universe's current root itself, so a single write covers every
// caller.
type pendingRootUpdate struct {
	id      universe.Identifier
	waiters []flushWaiter
}

// multiverseRootCoalescer serializes all writes to the shared
// multiverse trees through a single flusher, coalescing concurrent
// updates into one write transaction.
//
// Every proof leaf insert must reflect its universe's new root in the
// shared multiverse tree for its proof type. Doing that write inside
// each insert's own transaction makes any two concurrent inserts
// collide on the multiverse root rows: under Postgres serializable
// isolation one of them aborts and retries with backoff, effectively
// serializing ingest across universes. Routing the updates through the
// coalescer removes the shared rows from the insert transactions
// entirely: inserts commit in parallel, and their multiverse updates
// are applied by at most one flusher at a time, batched together.
//
// The flusher is an on-demand background goroutine: the first caller
// to find the coalescer idle starts it, and it flushes pending
// updates in rounds until none remain, then exits. Callers await only
// the result of the flush carrying their own update, never the drain
// of the whole queue. At low load an update flushes immediately; under
// load updates accumulate while a flush is in flight and are applied
// together in the next round.
//
// A failed round is not dropped: its waiters receive an error typed as
// universe.ErrMultiversePending, its universes are re-marked dirty,
// and the flusher retries them with bounded exponential backoff until
// the database recovers or the coalescer is stopped. Universe leaves
// are committed before their updates are submitted here, so retrying
// is what heals the gap between durable universe state and the shared
// multiverse trees without requiring further writes or a restart.
type multiverseRootCoalescer struct {
	db BatchedMultiverse

	// onRefresh, if set, is invoked after a flush commits, once per
	// refreshed universe, with the universe root the flush derived.
	// Flushes execute strictly one at a time, so invocations for the
	// same universe arrive in commit order; this makes the callback a
	// safe place to install roots into caches, which the unordered
	// post-commit sections of concurrent inserts are not.
	onRefresh func(root universe.Root)

	// onFlushError, if set, is invoked after a flush fails, including
	// by panic. The universes of the failed round may hold committed
	// universe roots that were never reported through onRefresh, so
	// state maintained incrementally from that callback must be
	// rebuilt.
	onFlushError func()

	// writeMu serializes all multiverse writes in this process. The
	// flusher holds it for the duration of a flush transaction and
	// its post-commit callbacks, and the deletion paths hold it
	// around theirs. This keeps the cache maintenance done after
	// those transactions in commit order — without it, a flush could
	// reinstall a cached root for a universe whose deletion committed
	// after the flush did — and keeps flushes and deletions from
	// aborting each other under serializable isolation.
	writeMu sync.Locker

	mu sync.Mutex

	// pending holds the universes awaiting a multiverse leaf refresh.
	// The map keying enforces at most one pending update per
	// universe.
	pending map[universeIDKey]*pendingRootUpdate

	// order tracks the first-submission order of pending universes,
	// so flushes apply updates deterministically.
	order []universeIDKey

	// flushing is true while the background flusher goroutine is
	// running.
	flushing bool

	// stopped is set once stop has been called; from then on new
	// submissions fail fast and the flusher winds down.
	stopped bool

	// quit is closed by stop to interrupt the flusher's retry
	// backoff.
	quit chan struct{}

	// wg tracks the background flusher goroutine.
	wg sync.WaitGroup

	// flushBatchSize is the maximum number of universes applied per
	// flush transaction. It defaults to maxFlushBatchSize and is only
	// overridden in tests.
	flushBatchSize int

	// initialRetryBackoff is the delay before the first retry of a
	// failed flush round. It defaults to defaultFlushRetryBackoff and
	// is only overridden in tests.
	initialRetryBackoff time.Duration

	// maxRetryBackoff caps the exponential retry backoff. It defaults
	// to maxFlushRetryBackoff and is only overridden in tests.
	maxRetryBackoff time.Duration
}

// newMultiverseRootCoalescer creates a new coalescer that writes
// through the given db handle. The given lock must be held by every
// other multiverse writer in the process.
func newMultiverseRootCoalescer(db BatchedMultiverse,
	writeMu sync.Locker) *multiverseRootCoalescer {

	return &multiverseRootCoalescer{
		db:                  db,
		writeMu:             writeMu,
		pending:             make(map[universeIDKey]*pendingRootUpdate),
		quit:                make(chan struct{}),
		flushBatchSize:      maxFlushBatchSize,
		initialRetryBackoff: defaultFlushRetryBackoff,
		maxRetryBackoff:     maxFlushRetryBackoff,
	}
}

// updateRoot marks the given universe's multiverse leaf as needing a
// refresh and returns once a flush carrying the refresh has committed,
// returning the universe root the flush derived along with the
// multiverse root and the universe leaf's inclusion proof from that
// flush.
//
// The flush derives the universe's current root inside its own
// transaction rather than trusting a value submitted here: callers
// submit after their universe transaction commits, so submission order
// does not track commit order, and the latest submission may carry a
// stale root. Deriving at flush time guarantees the leaf written is at
// least as fresh as the root committed by any caller it covers.
func (c *multiverseRootCoalescer) updateRoot(ctx context.Context,
	id universe.Identifier) (multiverseRootUpdate, error) {

	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return multiverseRootUpdate{}, errCoalescerStopped
	}
	result := c.enqueue(id, true)
	c.maybeStartFlusher()
	c.mu.Unlock()

	select {
	case res := <-result:
		return res.update, res.err

	case <-ctx.Done():
		return multiverseRootUpdate{}, ctx.Err()
	}
}

// updateRoots marks each given universe's multiverse leaf as needing a
// refresh and returns once a flush carrying every refresh has
// committed. Unlike updateRoot, it does not cause multiverse roots or
// inclusion proofs to be generated, as batch callers do not consume
// them.
func (c *multiverseRootCoalescer) updateRoots(ctx context.Context,
	ids []universe.Identifier) error {

	if len(ids) == 0 {
		return nil
	}

	waiters := make([]chan flushResult, len(ids))

	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return errCoalescerStopped
	}
	for i, id := range ids {
		waiters[i] = c.enqueue(id, false)
	}
	c.maybeStartFlusher()
	c.mu.Unlock()

	for _, waiter := range waiters {
		select {
		case res := <-waiter:
			if res.err != nil {
				return res.err
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// enqueue marks the given universe's multiverse leaf as needing a
// refresh and registers a waiter for the flush that carries it.
//
// NOTE: The caller must hold c.mu.
func (c *multiverseRootCoalescer) enqueue(id universe.Identifier,
	wantProof bool) chan flushResult {

	result := make(chan flushResult, 1)

	key := id.String()
	update, ok := c.pending[key]
	if !ok {
		update = &pendingRootUpdate{id: id}
		c.pending[key] = update
		c.order = append(c.order, key)
	}
	update.waiters = append(update.waiters, flushWaiter{
		result:    result,
		wantProof: wantProof,
	})

	return result
}

// maybeStartFlusher starts the background flusher goroutine if none is
// running.
//
// NOTE: The caller must hold c.mu.
func (c *multiverseRootCoalescer) maybeStartFlusher() {
	if c.flushing {
		return
	}

	c.flushing = true
	c.wg.Add(1)
	go c.runFlusher()
}

// runFlusher drains pending updates in rounds until none remain,
// applying each round in a single write transaction, then exits. It
// runs in its own goroutine, so no caller is ever conscripted into
// draining the queue: each awaits only its own result, bounded by its
// own context.
//
// A failed round keeps its universes dirty and is retried with
// bounded exponential backoff, so the gap between committed universe
// leaves and the shared multiverse trees closes on its own once the
// database recovers.
func (c *multiverseRootCoalescer) runFlusher() {
	defer c.wg.Done()

	backoff := c.initialRetryBackoff
	for {
		c.mu.Lock()
		if len(c.order) == 0 || c.stopped {
			c.flushing = false
			c.mu.Unlock()
			return
		}

		n := min(len(c.order), c.flushBatchSize)
		batch := make([]*pendingRootUpdate, 0, n)
		for _, key := range c.order[:n] {
			batch = append(batch, c.pending[key])
			delete(c.pending, key)
		}
		c.order = c.order[n:]
		queued := len(c.order)
		c.mu.Unlock()

		err := c.flushBatch(batch, queued)
		if err == nil {
			backoff = c.initialRetryBackoff
			continue
		}

		// A panic is presumed to be a bug rather than a transient
		// database failure; retrying would re-trigger it at every
		// backoff. The round's universes stay diverged until their
		// next update or startup reconciliation.
		if errors.Is(err, errFlushPanicked) {
			continue
		}

		// The round's waiters have been served the typed error, but
		// its universes still hold committed roots the multiverse
		// does not commit to. Re-mark them dirty and retry after
		// the backoff, so recovery requires no further writes.
		c.requeue(batch)

		log.Warnf("Retrying multiverse flush of %d universes in %v",
			len(batch), backoff)

		select {
		case <-time.After(backoff):
		case <-c.quit:
			c.mu.Lock()
			c.flushing = false
			c.mu.Unlock()
			return
		}

		backoff = min(2*backoff, c.maxRetryBackoff)
	}
}

// requeue re-marks the universes of a failed round as dirty. Their
// waiters have already been served, so the fresh entries carry none;
// universes re-submitted while the failed flush ran already have
// entries of their own, which absorb these.
func (c *multiverseRootCoalescer) requeue(batch []*pendingRootUpdate) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// The failed round predates everything queued behind it, so its
	// universes return to the front, preserving first-submission
	// order.
	keys := make([]universeIDKey, 0, len(batch))
	for _, update := range batch {
		key := update.id.String()
		if _, ok := c.pending[key]; ok {
			continue
		}

		c.pending[key] = &pendingRootUpdate{id: update.id}
		keys = append(keys, key)
	}
	c.order = append(keys, c.order...)
}

// stop rejects new submissions, winds down the flusher and fails every
// pending waiter. A flush transaction already in flight completes or
// fails on its own; stop blocks until the flusher has exited, bounded
// by the flush timeout. Universe leaves already committed stay
// durable, and multiverse updates abandoned here are repaired by
// startup reconciliation on the next run.
func (c *multiverseRootCoalescer) stop() {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	close(c.quit)

	pending := c.pending
	c.pending = make(map[universeIDKey]*pendingRootUpdate)
	c.order = nil
	c.mu.Unlock()

	res := flushResult{err: errCoalescerStopped}
	for _, update := range pending {
		for _, waiter := range update.waiters {
			// Waiter channels are buffered, so this never
			// blocks.
			waiter.result <- res
		}
	}

	c.wg.Wait()
}

// flushBatch applies one round of updates in a single write transaction
// and delivers the outcome to every waiter of the round. It returns
// the flush error, if any, wrapped in errFlushPanicked when the flush
// panicked rather than failing.
func (c *multiverseRootCoalescer) flushBatch(batch []*pendingRootUpdate,
	queued int) (flushErr error) {

	start := time.Now()

	// A panic during the flush must not strand the round's waiters or
	// unwind into the flusher's loop: were the panic recovered further
	// up the stack, the coalescer would be blocked for every future
	// update. Convert it into an error for every waiter of the round
	// instead, and let the flusher continue.
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		log.Criticalf("Multiverse flush panic (batch_size=%d, "+
			"queue_depth=%d, duration=%v): %v\n%s", len(batch),
			queued, time.Since(start), r, debug.Stack())

		flushErr = fmt.Errorf("%w: %v", errFlushPanicked, r)

		if c.onFlushError != nil {
			c.onFlushError()
		}

		res := flushResult{
			err: fmt.Errorf("%w: %w", universe.ErrMultiversePending,
				flushErr),
		}
		for _, update := range batch {
			// The waiter channels are buffered, so a send only
			// fails if the waiter was already served by the
			// normal delivery path below.
			for _, waiter := range update.waiters {
				select {
				case waiter.result <- res:
				default:
				}
			}
		}
	}()

	// The flush must not be tied to any single caller's context: the
	// universe transactions the updates stem from have already
	// committed, and other callers in the round await this write. It
	// must still be bounded, so a stalled database cannot pin the
	// flusher forever.
	ctx, cancel := context.WithTimeout(
		context.Background(), defaultFlushTimeout,
	)
	defer cancel()

	wantProof := func(update *pendingRootUpdate) bool {
		for _, waiter := range update.waiters {
			if waiter.wantProof {
				return true
			}
		}

		return false
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var (
		results = make([]multiverseRootUpdate, len(batch))
		missing = make([]bool, len(batch))
		roots   = make([]universe.Root, len(batch))
	)
	flushTx := multiverseFlushTx{}
	err := c.db.ExecTx(
		ctx, flushTx, func(store BaseMultiverseStore) error {
			// The transaction may retry the closure wholesale,
			// so reset the per-entry state it populates.
			for i := range missing {
				missing[i] = false
			}

			// Refresh every universe's multiverse leaf first,
			// then read back the resulting root and one
			// inclusion proof per universe that has a waiter
			// consuming them.
			for i, update := range batch {
				// Derive the universe's current root here,
				// inside the flush transaction, rather than
				// using a submitted value: submissions
				// follow their universe transactions'
				// commits, so submission order does not
				// track commit order, and the latest
				// submitted root may be stale.
				uniRoot, err := store.FetchUniverseRoot(
					ctx, update.id.String(),
				)
				switch {
				case errors.Is(err, sql.ErrNoRows):
					// The universe was deleted after
					// being marked dirty. Its waiters
					// receive a typed error below.
					missing[i] = true
					continue

				case err != nil:
					return fmt.Errorf("failed universe "+
						"root fetch for %v: %w",
						update.id.String(), err)
				}

				var rootHash mssmt.NodeHash
				copy(rootHash[:], uniRoot.RootHash[:])
				root := mssmt.NewComputedNode(
					rootHash, uint64(uniRoot.RootSum),
				)
				roots[i] = universe.Root{
					ID:        update.id,
					AssetName: uniRoot.AssetName,
					Node:      root,
				}

				err = upsertMultiverseLeafEntry(
					ctx, store, update.id, root,
				)
				if err != nil {
					return fmt.Errorf("failed multiverse "+
						"upsert for %v: %w",
						update.id.String(), err)
				}
			}

			for i, update := range batch {
				if missing[i] || !wantProof(update) {
					continue
				}

				root, proof, err := multiverseRootAndProof(
					ctx, store, update.id,
				)
				if err != nil {
					return fmt.Errorf("failed multiverse "+
						"root fetch for %v: %w",
						update.id.String(), err)
				}

				results[i] = multiverseRootUpdate{
					universeRoot:   roots[i].Node,
					multiverseRoot: root,
					inclusionProof: proof,
				}
			}

			return nil
		},
	)

	// The flush has committed: report the derived roots before
	// delivering results. Flushes run strictly one at a time, so
	// these arrive in commit order per universe.
	if err == nil && c.onRefresh != nil {
		for i := range batch {
			if missing[i] {
				continue
			}

			c.onRefresh(roots[i])
		}
	}
	if err != nil && c.onFlushError != nil {
		c.onFlushError()
	}

	switch {
	case err != nil:
		log.Errorf("Multiverse flush failed (batch_size=%d, "+
			"queue_depth=%d, duration=%v): %v", len(batch),
			queued, time.Since(start), err)

	default:
		log.Debugf("Multiverse flush committed (batch_size=%d, "+
			"queue_depth=%d, duration=%v)", len(batch), queued,
			time.Since(start))
	}

	for i, update := range batch {
		res := flushResult{err: err}
		switch {
		case err != nil:
			// The universe transactions behind this round have
			// already committed; only the multiverse update is
			// outstanding, and the flusher keeps retrying it.
			// Give waiters that typed context along with the
			// cause.
			res.err = fmt.Errorf("%w: %w",
				universe.ErrMultiversePending, err)

		case missing[i]:
			res.err = errUniverseDeleted

		default:
			res.update = results[i]
		}

		// Every waiter channel is buffered, so delivery never
		// blocks the flusher, even if a waiter has abandoned its
		// call due to context cancellation.
		for _, waiter := range update.waiters {
			waiter.result <- res
		}
	}

	return err
}
