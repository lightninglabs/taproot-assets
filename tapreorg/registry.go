package tapreorg

import (
	"context"
	"errors"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightninglabs/taproot-assets/fn"
)

var (
	// ErrAnchoringNotFound is returned when an anchoring ID does
	// not resolve to a registry row.
	ErrAnchoringNotFound = errors.New("anchoring not found")

	// ErrLiveDependents is returned when a withdrawal is attempted
	// on an anchoring that live anchorings still depend on.
	ErrLiveDependents = errors.New("anchoring has live dependents")

	// ErrTerminalPhase is returned when an operation requires a
	// live anchoring but the anchoring is terminal.
	ErrTerminalPhase = errors.New("anchoring is terminal")

	// ErrIncompleteSpend is returned when a satisfying candidate's
	// transaction does not spend the anchoring's entire trigger
	// set: under the whole-set rule such a transaction cannot
	// realize the anchoring, and recording it as satisfying would
	// let satisfying and foreign outcomes coexist on one chain.
	ErrIncompleteSpend = errors.New("satisfying candidate does not " +
		"spend the entire trigger set")

	// ErrStaleDelivery is returned by Deliver when the sensed
	// phase changed between the delivery decision and the delivery
	// transaction; the delivery is a benign no-op and the caller
	// simply rescans.
	ErrStaleDelivery = errors.New("sensed phase changed; " +
		"delivery is stale")
)

// DependencyEdge records that a child anchoring's trigger outpoints
// were created by a parent anchoring's witness, pinned to the
// specific witness transaction the child depends on. The edge is
// foreclosed when the parent can no longer supply the outpoint: the
// parent was abandoned, or its witness changed to a different
// transaction. Foreclosure staged at potency depth is reversible;
// only at the child's threshold does it abandon the child.
type DependencyEdge struct {
	// Child is the depending anchoring.
	Child AnchoringID

	// Parent is the depended-upon anchoring.
	Parent AnchoringID

	// ParentWitnessTxHash is the specific parent witness
	// transaction whose outputs the child spends.
	ParentWitnessTxHash chainhash.Hash

	// Foreclosure is the staged foreclosing evidence, if any.
	Foreclosure fn.Option[ForeclosureEvent]
}

// StoredEffect is an outbox row as read back for dispatch.
type StoredEffect struct {
	// ID is the outbox row ID.
	ID int64

	// Effect is the enqueued effect.
	Effect OutboxEffect

	// Attempts counts failed dispatch attempts so far.
	Attempts uint32
}

// Registry is the durable store of anchorings: the watcher's source
// of truth. Implemented by tapdb, over the same database every site's
// state lives in — which is what makes the transactional coupling of
// registry advances and site handlers possible.
type Registry interface {
	// Register inserts the anchoring (phase Unwitnessed, delivered
	// Unwitnessed) at the given best height, derives its
	// dependency edges from live anchorings with a recorded
	// satisfying candidate that created its trigger outpoints, and
	// runs the site's phase-1 speculative write — all in one
	// transaction. There is no instant at which the stake exists
	// without its registration. The phase-1 write receives the new
	// anchoring's ID so the site can key its own rows (and
	// effects) to it.
	//
	// A child registered before its parent's transaction has ever
	// been observed cannot be matched here; its edge derives when
	// the parent first records a satisfying candidate in the
	// depended-upon form (see UpsertCandidate). A parent that
	// never confirms in that form derives no edge — but then the
	// child's trigger outpoints never exist on chain either, so no
	// chain outcome is being missed.
	Register(ctx context.Context, spec RegistrationSpec,
		createdHeight uint32,
		phase1 func(context.Context, RegistryTx,
			AnchoringID) error) (AnchoringID, error)

	// GetAnchoring fetches an anchoring with its chain view.
	GetAnchoring(ctx context.Context,
		id AnchoringID) (*Anchoring, error)

	// LiveAnchorings returns all anchorings in a non-terminal
	// phase, with their chain views.
	LiveAnchorings(ctx context.Context) ([]*Anchoring, error)

	// ChainView assembles the anchoring's chain view: its
	// candidate spends plus its strongest staged foreclosure.
	ChainView(ctx context.Context, id AnchoringID) (ChainView, error)

	// UpsertCandidate records or updates a candidate spend
	// observation, keyed by (anchoring, spending txid). A
	// satisfying candidate whose transaction does not spend the
	// anchoring's entire trigger set is refused with
	// ErrIncompleteSpend — the whole-set rule held at the durable
	// boundary. Recording a satisfying candidate also derives
	// dependency edges, in the same transaction, for live children
	// staked on the transaction's outputs that registered before
	// the form was first observed.
	UpsertCandidate(ctx context.Context, id AnchoringID,
		candidate CandidateSpend) error

	// SetPhase persists a newly derived phase for a live
	// anchoring. Terminal phases are absorbing at the row level:
	// if another writer pinned the anchoring terminal after the
	// caller derived, the stale write is refused with
	// ErrTerminalPhase and the row is left untouched.
	SetPhase(ctx context.Context, id AnchoringID, phase Phase) error

	// Deliver invokes the handler inside a transaction and, on
	// success, records the target phase as delivered — resetting
	// the failure bookkeeping, stamping terminal phases terminal,
	// and, for a terminal target, settling the anchoring's live
	// dependents' edges in the same transaction: an abandonment
	// forecloses every edge (which is what makes cascade delivery
	// parent-first structural), and a burial forecloses the edges
	// depending on a different form while clearing those pinned to
	// the buried one. If the sensed phase no longer equals the
	// target, ErrStaleDelivery is returned and nothing happens.
	//
	// The handler receives an Anchoring aggregate assembled inside
	// the delivery transaction (candidates and their block
	// enrichment reflect the durable state at the moment the tx
	// opens, not whatever the caller last scanned). Handlers that
	// read candidate evidence — the mint site's witness context,
	// the porter's witness context — thus never see stale
	// enrichment data.
	Deliver(ctx context.Context, id AnchoringID, target Phase,
		handler func(context.Context, RegistryTx,
			*Anchoring) error) error

	// RecordDeliveryFailure records a failed delivery attempt:
	// attempt count, error text, next-attempt time, and the stuck
	// flag once attempts pass the caller's threshold.
	RecordDeliveryFailure(ctx context.Context, id AnchoringID,
		deliveryErr error, nextAttempt time.Time, stuck bool) error

	// PendingDeliveries returns the live-or-terminal anchorings
	// whose delivered phase lags their sensed phase and whose
	// next-attempt time has passed.
	PendingDeliveries(ctx context.Context,
		now time.Time) ([]*Anchoring, error)

	// Withdraw runs the site's withdrawal write and moves the
	// anchoring to Withdrawn in one transaction. It refuses when
	// live anchorings still depend on this one
	// (ErrLiveDependents), and when the anchoring is already
	// terminal (ErrTerminalPhase).
	Withdraw(ctx context.Context, id AnchoringID,
		onWithdraw func(context.Context, RegistryTx) error) error

	// DependencyEdges returns the edges from live children to the
	// given parent.
	DependencyEdges(ctx context.Context,
		parent AnchoringID) ([]DependencyEdge, error)

	// IncomingEdges returns the edges from the given child to its
	// parents. Staged foreclosure evidence is a pure function of
	// the parent's phase and the edge's depended-upon form, so a
	// child can rebuild its own staging from these edges when a
	// parent's restage write was lost.
	IncomingEdges(ctx context.Context,
		child AnchoringID) ([]DependencyEdge, error)

	// StageForeclosure stages (or refreshes) foreclosing evidence
	// on the child→parent edge. Staging is reversible until the
	// child's threshold is reached.
	StageForeclosure(ctx context.Context, child, parent AnchoringID,
		foreclosure ForeclosureEvent) error

	// ClearForeclosure removes staged foreclosing evidence from
	// the child→parent edge (the foreclosing event itself reorged
	// out, or the parent's witness reverted to the depended-upon
	// form).
	ClearForeclosure(ctx context.Context,
		child, parent AnchoringID) error

	// PendingEffects returns undispatched outbox effects whose
	// next-attempt time has passed, oldest first.
	PendingEffects(ctx context.Context, now time.Time,
		limit int32) ([]*StoredEffect, error)

	// MarkEffectDispatched marks an outbox effect dispatched.
	MarkEffectDispatched(ctx context.Context, effectID int64) error

	// RecordEffectFailure records a failed dispatch attempt and
	// its backoff.
	RecordEffectFailure(ctx context.Context, effectID int64,
		dispatchErr error, nextAttempt time.Time) error
}
