package tapreorg

import (
	"context"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
)

// EffectKind names a kind of external effect dispatched through the
// outbox. Kinds are site-chosen stable strings; a dispatch handler is
// registered per kind.
type EffectKind string

// OutboxEffect is an external effect enqueued in the same transaction
// as the registry advance that produced it, and dispatched
// asynchronously and idempotently. The invariant: the registry never
// advances past an external effect that was not at least durably
// enqueued.
type OutboxEffect struct {
	// Kind routes the effect to its dispatch handler.
	Kind EffectKind

	// Anchoring optionally ties the effect to the anchoring whose
	// delivery enqueued it.
	Anchoring fn.Option[AnchoringID]

	// Payload is the effect's opaque, versioned payload.
	Payload VersionedBlob
}

// RegistryTx is the transaction-scoped handle passed to site handlers
// and phase-1 writes. Its only producer is the registry's transaction
// executor: a handler holding one is, structurally, inside the same
// database transaction as the registry advance it accompanies, so
// site state and registry state cannot drift.
//
// Handlers must confine themselves to database work through this
// handle plus outbox enqueues; external effects are enqueued, never
// performed inline. Note that the underlying executor re-runs the
// transaction body on serialization retries, which is safe precisely
// because handlers are convergent.
type RegistryTx interface {
	// Queries exposes the full generated query set, scoped to the
	// transaction. Sites narrow it to their own store interfaces.
	Queries() *sqlc.Queries

	// EnqueueEffect durably enqueues an external effect in this
	// transaction, for asynchronous idempotent dispatch.
	EnqueueEffect(ctx context.Context, effect OutboxEffect) error
}

// Site is the contract a subsystem implements to stake local state on
// chain outcomes through the watcher. From registration onward the
// site holds no chain subscriptions of its own for the stake; the
// watcher is the sole sensor, and drives the site through the
// handlers below.
//
// Handlers are state-convergent, not event-sequential: each must
// bring the site's state into adequation with the delivered phase
// from whatever local state the site is actually in, because phase
// changes coalesce — if Witnessed delivery was stuck and the witness
// meanwhile buried, the site receives only OnBuried, and OnBuried
// must do whatever OnWitnessed would have done first. The site's own
// database tells it what has and hasn't been applied; the handler
// reconciles. This one requirement buys restart safety, coalescing
// safety and retry safety with a single discipline.
type Site interface {
	// ID returns the site's stable identifier.
	ID() SiteID

	// EvaluateCandidate is the site's pure predicate over a
	// candidate spending transaction: does the candidate realize
	// the anchoring described by the match data, or foreclose it?
	// It is only consulted for transactions that spend the
	// anchoring's entire trigger set — a partial spend is foreign
	// by construction and never reaches the predicate — so the
	// question is purely semantic: is this an acceptable form of
	// the intended outcome? No I/O, no database access; a returned
	// error indicates a decode failure (a code defect, not a chain
	// condition) and is surfaced loudly by the watcher.
	EvaluateCandidate(match VersionedBlob,
		spendingTx *wire.MsgTx) (Verdict, error)

	// OnWitnessed converges the site to a witnessed anchoring:
	// apply or re-key confirmation-dependent state. When the
	// witness has changed form (a different transaction), this is
	// re-derivation rather than patching.
	OnWitnessed(ctx context.Context, tx RegistryTx,
		anchoring *Anchoring) error

	// OnUnwitnessed converges the site to an unwitnessed
	// anchoring after a witness was lost with no successor: soft
	// downgrade only, nothing is reversed.
	OnUnwitnessed(ctx context.Context, tx RegistryTx,
		anchoring *Anchoring) error

	// OnConflicted converges the site to a conflicted anchoring:
	// soft negative action only — the foreign spend can itself
	// reorg out.
	OnConflicted(ctx context.Context, tx RegistryTx,
		anchoring *Anchoring) error

	// OnBuried converges the site to an act-confirmed anchoring
	// and releases act-gated external effects (via the outbox).
	OnBuried(ctx context.Context, tx RegistryTx,
		anchoring *Anchoring) error

	// OnAbandoned compensates: the inverse of everything the site
	// applied on the strength of this stake.
	OnAbandoned(ctx context.Context, tx RegistryTx,
		anchoring *Anchoring) error
}
