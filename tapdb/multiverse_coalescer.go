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

// errUniverseDeleted is delivered to waiters whose universe no longer
// exists by the time the flush reads it back: the universe was deleted
// after the update was submitted. Deletion removes the universe's
// multiverse leaf in the same transaction as its tree, so there is
// nothing left to refresh.
var errUniverseDeleted = errors.New(
	"universe deleted during multiverse update",
)

// multiverseFlushTx is the transaction options for the coalescer's
// flushes. The flush is the sole writer of the multiverse namespaces
// (enforced by the single-flusher role plus the multiverse write mutex
// shared with the deletion paths), so serializable isolation buys it
// nothing. Running it at read committed on Postgres means it takes no
// predicate locks, and, since only serializable writers flag conflicts
// on serializable readers, it can neither abort nor be aborted by the
// concurrent universe insert transactions.
//
// Abort-freedom alone is not what makes the downgrade safe, though: a
// read-committed writer can invalidate a concurrent serializable
// transaction's reads without either of them aborting. Safety rests on
// write disjointness: the flush writes only multiverse rows, which the
// serializable insert transactions neither read nor write.
type multiverseFlushTx struct{}

// ReadOnly returns false: flushes write.
func (multiverseFlushTx) ReadOnly() bool {
	return false
}

// TxIsolation overrides the flush transaction's isolation level.
func (multiverseFlushTx) TxIsolation() sql.IsolationLevel {
	return sql.LevelReadCommitted
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
// The flusher role is leader-based rather than a dedicated goroutine:
// the first caller to find the coalescer idle flushes pending updates
// in rounds until none remain, while every other caller just awaits
// its result. This yields group commit without any lifecycle
// management: at low load an update flushes immediately, and under
// load updates accumulate while a flush is in flight and are applied
// together in the next round.
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
	// flusher holds it for the duration of a flush transaction, and
	// the deletion paths hold it around theirs. This mutual
	// exclusion is what makes it safe to run flushes below
	// serializable isolation.
	writeMu sync.Locker

	mu sync.Mutex

	// pending holds the universes awaiting a multiverse leaf refresh.
	// The map keying enforces at most one pending update per
	// universe.
	pending map[universeIDKey]*pendingRootUpdate

	// order tracks the first-submission order of pending universes,
	// so flushes apply updates deterministically.
	order []universeIDKey

	// flushing is true while some caller holds the flusher role.
	flushing bool

	// flushBatchSize is the maximum number of universes applied per
	// flush transaction. It defaults to maxFlushBatchSize and is only
	// overridden in tests.
	flushBatchSize int
}

// newMultiverseRootCoalescer creates a new coalescer that writes
// through the given db handle. The given lock must be held by every
// other multiverse writer in the process.
func newMultiverseRootCoalescer(db BatchedMultiverse,
	writeMu sync.Locker) *multiverseRootCoalescer {

	return &multiverseRootCoalescer{
		db:             db,
		writeMu:        writeMu,
		pending:        make(map[universeIDKey]*pendingRootUpdate),
		flushBatchSize: maxFlushBatchSize,
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
	result := c.enqueue(id, true)
	lead := !c.flushing
	if lead {
		c.flushing = true
	}
	c.mu.Unlock()

	if lead {
		c.flush()
	}

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
	for i, id := range ids {
		waiters[i] = c.enqueue(id, false)
	}
	lead := !c.flushing
	if lead {
		c.flushing = true
	}
	c.mu.Unlock()

	if lead {
		c.flush()
	}

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

// flush drains pending updates in rounds until none remain, applying
// each round in a single write transaction.
func (c *multiverseRootCoalescer) flush() {
	for {
		c.mu.Lock()
		if len(c.order) == 0 {
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
		c.mu.Unlock()

		c.flushBatch(batch)
	}
}

// flushBatch applies one round of updates in a single write transaction
// and delivers the outcome to every waiter of the round.
func (c *multiverseRootCoalescer) flushBatch(batch []*pendingRootUpdate) {
	// A panic during the flush must not strand the round's waiters or
	// unwind past the flusher role's bookkeeping: were the panic
	// recovered further up the stack, the coalescer would be blocked
	// for every future update. Convert it into an error for every
	// waiter of the round instead, and let the flusher continue.
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		log.Criticalf("Multiverse flush panic: %v\n%s", r,
			debug.Stack())

		if c.onFlushError != nil {
			c.onFlushError()
		}

		res := flushResult{
			err: fmt.Errorf("multiverse flush panic: %v", r),
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

	for i, update := range batch {
		res := flushResult{err: err}
		switch {
		case err == nil && missing[i]:
			res.err = errUniverseDeleted

		case err == nil:
			res.update = results[i]
		}

		// Every waiter channel is buffered, so delivery never
		// blocks the flusher, even if a waiter has abandoned its
		// call due to context cancellation.
		for _, waiter := range update.waiters {
			waiter.result <- res
		}
	}
}
