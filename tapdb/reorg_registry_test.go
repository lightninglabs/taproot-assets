package tapdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// newReorgStore builds a registry store over a fresh test database,
// with a test clock.
func newReorgStore(t testing.TB) (*ReorgRegistryStore, *clock.TestClock) {
	db := NewTestDB(t)
	testClock := clock.NewTestClock(time.Unix(1_000_000, 0))

	executor := NewTransactionExecutor(
		db, func(tx *sql.Tx) *sqlc.Queries {
			return db.WithTx(tx)
		},
	)

	return NewReorgRegistryStore(executor, testClock), testClock
}

// testOutPoint returns a deterministic outpoint.
func testOutPoint(seed byte, index uint32) wire.OutPoint {
	var op wire.OutPoint
	op.Hash[0] = seed
	op.Index = index

	return op
}

// testTriggerSet returns a trigger set over the given outpoints.
func testTriggerSet(t require.TestingT,
	ops ...wire.OutPoint) tapreorg.TriggerSet {

	points := make([]tapreorg.TriggerOutPoint, len(ops))
	for i, op := range ops {
		points[i] = tapreorg.TriggerOutPoint{
			OutPoint: op,
			PkScript: append(
				[]byte{txscript.OP_0, txscript.OP_DATA_32},
				make([]byte, 32)...,
			),
			HeightHint: 100,
		}
	}

	triggers, err := tapreorg.NewTriggerSet(points)
	require.NoError(t, err)

	return triggers
}

// testSpec returns a valid registration spec over the given trigger
// outpoints.
func testSpec(t require.TestingT, site tapreorg.SiteID,
	ops ...wire.OutPoint) tapreorg.RegistrationSpec {

	return tapreorg.RegistrationSpec{
		Site:      site,
		Triggers:  testTriggerSet(t, ops...),
		MatchData: tapreorg.VersionedBlob{Version: 1},
		Payload:   tapreorg.VersionedBlob{Version: 1},
		Threshold: 6,
	}
}

// testWitness returns a witness whose transaction spends the given
// outpoints, located at the given height. The seed varies the
// transaction (and therefore its txid).
func testWitness(t require.TestingT, seed byte, height uint32,
	spends ...wire.OutPoint) tapreorg.Witness {

	tx := wire.NewMsgTx(2)
	for i := range spends {
		tx.AddTxIn(wire.NewTxIn(&spends[i], nil, nil))
	}
	tx.AddTxOut(wire.NewTxOut(int64(seed)+1_000, []byte{0x51, seed}))

	var blockHash chainhash.Hash
	blockHash[0] = seed

	w, err := tapreorg.NewWitness(tx, blockHash, height, 1)
	require.NoError(t, err)

	return w
}

// testEffect returns an effect bound to the given anchoring.
func testEffect(id tapreorg.AnchoringID, kind string) tapreorg.OutboxEffect {
	return tapreorg.OutboxEffect{
		Kind:      tapreorg.EffectKind(kind),
		Anchoring: fn.Some(id),
		Payload: tapreorg.VersionedBlob{
			Version: 1,
			Data:    []byte(kind),
		},
	}
}

// TestReorgRegistryLifecycle drives one anchoring through
// registration, sensing, failed and successful delivery, outbox
// dispatch and burial.
func TestReorgRegistryLifecycle(t *testing.T) {
	t.Parallel()

	store, testClock := newReorgStore(t)
	ctx := context.Background()

	op := testOutPoint(1, 0)
	spec := testSpec(t, "porter", op)

	// Registration runs the phase-1 write in the same transaction;
	// the effect it enqueues proves the handle works.
	id, err := store.Register(
		ctx, spec, 500,
		func(ctx context.Context, tx tapreorg.RegistryTx,
			newID tapreorg.AnchoringID) error {

			return tx.EnqueueEffect(
				ctx, testEffect(newID, "phase1"),
			)
		},
	)
	require.NoError(t, err)

	anchoring, err := store.GetAnchoring(ctx, id)
	require.NoError(t, err)
	require.Equal(t, tapreorg.SiteID("porter"), anchoring.Site)
	require.True(t, tapreorg.PhaseEqual(
		tapreorg.Unwitnessed{}, anchoring.Phase,
	))
	require.True(t, tapreorg.PhaseEqual(
		tapreorg.Unwitnessed{}, anchoring.DeliveredPhase,
	))
	require.Equal(t, 1, anchoring.Triggers.Len())
	require.True(t, anchoring.Triggers.Contains(op))

	// Converged: nothing pending.
	pending, err := store.PendingDeliveries(ctx, testClock.Now())
	require.NoError(t, err)
	require.Empty(t, pending)

	// A satisfying candidate confirms; sensing records it and
	// derives Witnessed.
	w := testWitness(t, 7, 600, op)
	require.NoError(t, store.UpsertCandidate(
		ctx, id, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictSatisfies,
			W:              w,
			OnChain:        true,
			SpentOutPoints: []wire.OutPoint{op},
		},
	))

	view, err := store.ChainView(ctx, id)
	require.NoError(t, err)
	witnessed := tapreorg.DerivePhase(view)
	require.IsType(t, tapreorg.Witnessed{}, witnessed)
	require.NoError(t, store.SetPhase(ctx, id, witnessed))

	pending, err = store.PendingDeliveries(ctx, testClock.Now())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, id, pending[0].ID)

	// Delivering a phase sensing has moved past is stale.
	err = store.Deliver(ctx, id, tapreorg.Buried{W: w}, nil)
	require.ErrorIs(t, err, tapreorg.ErrStaleDelivery)

	// A failing handler rolls the delivery back.
	handlerErr := errors.New("site failure")
	err = store.Deliver(
		ctx, id, witnessed,
		func(context.Context, tapreorg.RegistryTx,
			*tapreorg.Anchoring) error {

			return handlerErr
		},
	)
	require.ErrorIs(t, err, handlerErr)

	// Failure bookkeeping backs the delivery off.
	nextAttempt := testClock.Now().Add(time.Minute)
	require.NoError(t, store.RecordDeliveryFailure(
		ctx, id, handlerErr, nextAttempt, false,
	))

	pending, err = store.PendingDeliveries(ctx, testClock.Now())
	require.NoError(t, err)
	require.Empty(t, pending)

	testClock.SetTime(testClock.Now().Add(2 * time.Minute))
	pending, err = store.PendingDeliveries(ctx, testClock.Now())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.EqualValues(t, 1, pending[0].DeliveryAttempts)

	// Successful delivery: handler effect enqueued, bookkeeping
	// reset, site converged.
	err = store.Deliver(
		ctx, id, witnessed,
		func(ctx context.Context, tx tapreorg.RegistryTx,
			_ *tapreorg.Anchoring) error {

			return tx.EnqueueEffect(ctx, testEffect(id, "conf"))
		},
	)
	require.NoError(t, err)

	anchoring, err = store.GetAnchoring(ctx, id)
	require.NoError(t, err)
	require.True(t, tapreorg.PhaseEqual(
		witnessed, anchoring.DeliveredPhase,
	))
	require.Zero(t, anchoring.DeliveryAttempts)

	pending, err = store.PendingDeliveries(ctx, testClock.Now())
	require.NoError(t, err)
	require.Empty(t, pending)

	// Both effects are pending dispatch; dispatch one, fail the
	// other, then dispatch it after its backoff.
	effects, err := store.PendingEffects(ctx, testClock.Now(), 10)
	require.NoError(t, err)
	require.Len(t, effects, 2)

	require.NoError(t, store.MarkEffectDispatched(ctx, effects[0].ID))

	dispatchErr := errors.New("universe unreachable")
	retryAt := testClock.Now().Add(time.Minute)
	require.NoError(t, store.RecordEffectFailure(
		ctx, effects[1].ID, dispatchErr, retryAt,
	))

	effects, err = store.PendingEffects(ctx, testClock.Now(), 10)
	require.NoError(t, err)
	require.Empty(t, effects)

	testClock.SetTime(testClock.Now().Add(2 * time.Minute))
	effects, err = store.PendingEffects(ctx, testClock.Now(), 10)
	require.NoError(t, err)
	require.Len(t, effects, 1)
	require.EqualValues(t, 1, effects[0].Attempts)
	require.NoError(t, store.MarkEffectDispatched(ctx, effects[0].ID))

	// Burial: the notifier certifies the candidate at threshold
	// depth; the certified view derives Buried, whose terminal
	// delivery drops the anchoring from the live set.
	require.NoError(t, store.UpsertCandidate(
		ctx, id, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictSatisfies,
			W:              w,
			OnChain:        true,
			ActCertified:   true,
			SpentOutPoints: []wire.OutPoint{op},
		},
	))
	view, err = store.ChainView(ctx, id)
	require.NoError(t, err)
	buried := tapreorg.DerivePhase(view)
	require.IsType(t, tapreorg.Buried{}, buried)
	require.NoError(t, store.SetPhase(ctx, id, buried))
	require.NoError(t, store.Deliver(ctx, id, buried, nil))

	live, err := store.LiveAnchorings(ctx)
	require.NoError(t, err)
	require.Empty(t, live)

	// Unknown IDs surface as not-found.
	_, err = store.GetAnchoring(ctx, id+999)
	require.ErrorIs(t, err, tapreorg.ErrAnchoringNotFound)
}

// TestReorgRegistryHandlerAtomicity asserts the registry never
// advances past a failed handler: the handler's own writes (an
// enqueued effect) roll back with the delivery.
func TestReorgRegistryHandlerAtomicity(t *testing.T) {
	t.Parallel()

	store, testClock := newReorgStore(t)
	ctx := context.Background()

	op := testOutPoint(2, 0)
	id, err := store.Register(ctx, testSpec(t, "porter", op), 500, nil)
	require.NoError(t, err)

	w := testWitness(t, 3, 600, op)
	require.NoError(t, store.UpsertCandidate(
		ctx, id, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictSatisfies,
			W:              w,
			OnChain:        true,
			SpentOutPoints: []wire.OutPoint{op},
		},
	))
	witnessed := tapreorg.Witnessed{W: w}
	require.NoError(t, store.SetPhase(ctx, id, witnessed))

	// The handler enqueues an effect and then fails: neither the
	// delivery nor the effect may survive.
	boom := errors.New("boom")
	err = store.Deliver(
		ctx, id, witnessed,
		func(ctx context.Context, tx tapreorg.RegistryTx,
			_ *tapreorg.Anchoring) error {

			err := tx.EnqueueEffect(ctx, testEffect(id, "leak"))
			require.NoError(t, err)

			return boom
		},
	)
	require.ErrorIs(t, err, boom)

	anchoring, err := store.GetAnchoring(ctx, id)
	require.NoError(t, err)
	require.True(t, tapreorg.PhaseEqual(
		tapreorg.Unwitnessed{}, anchoring.DeliveredPhase,
	))

	effects, err := store.PendingEffects(ctx, testClock.Now(), 10)
	require.NoError(t, err)
	require.Empty(t, effects)
}

// TestReorgRegistryDependencies exercises automatic edge derivation,
// the withdrawal guard, cascade foreclosure on abandonment, and the
// child's resulting derivation.
func TestReorgRegistryDependencies(t *testing.T) {
	t.Parallel()

	store, _ := newReorgStore(t)
	ctx := context.Background()

	// The parent anchors at witness wP; the child spends wP's
	// output 0.
	parentOp := testOutPoint(4, 0)
	parentID, err := store.Register(
		ctx, testSpec(t, "minter", parentOp), 500, nil,
	)
	require.NoError(t, err)

	wP := testWitness(t, 5, 600, parentOp)
	require.NoError(t, store.UpsertCandidate(
		ctx, parentID, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictSatisfies,
			W:              wP,
			OnChain:        true,
			SpentOutPoints: []wire.OutPoint{parentOp},
		},
	))
	require.NoError(t, store.SetPhase(
		ctx, parentID, tapreorg.Witnessed{W: wP},
	))

	childOp := wire.OutPoint{Hash: wP.TxHash(), Index: 0}
	childID, err := store.Register(
		ctx, testSpec(t, "porter", childOp), 601, nil,
	)
	require.NoError(t, err)

	// The edge was derived automatically, pinned to wP.
	edges, err := store.DependencyEdges(ctx, parentID)
	require.NoError(t, err)
	require.Len(t, edges, 1)
	require.Equal(t, childID, edges[0].Child)
	require.Equal(t, wP.TxHash(), edges[0].ParentWitnessTxHash)
	require.True(t, edges[0].Foreclosure.IsNone())

	// A parent with live dependents cannot be withdrawn.
	err = store.Withdraw(ctx, parentID, nil)
	require.ErrorIs(t, err, tapreorg.ErrLiveDependents)

	// A foreign spend of the parent's trigger buries; the parent
	// abandons, and its delivery forecloses the child's edge in
	// the same transaction.
	wF := testWitness(t, 6, 610, parentOp)
	abandoned := tapreorg.Abandoned{Cause: tapreorg.ForeignBurial{
		Spend: tapreorg.ForeignSpend{SpentOutPoint: parentOp, W: wF},
	}}
	require.NoError(t, store.SetPhase(ctx, parentID, abandoned))
	require.NoError(t, store.Deliver(ctx, parentID, abandoned, nil))

	edges, err = store.DependencyEdges(ctx, parentID)
	require.NoError(t, err)
	require.Len(t, edges, 1)
	fc := edges[0].Foreclosure.UnwrapToPtr()
	require.NotNil(t, fc)
	require.True(t, fc.OnChain)
	require.Equal(t, wF.TxHash(), fc.W.TxHash())

	// The child's chain view carries the staged foreclosure, but
	// while uncertified it carries no force: the child abandons
	// only when the notifier certifies the foreclosing transaction
	// at the child's own threshold.
	view, err := store.ChainView(ctx, childID)
	require.NoError(t, err)
	require.True(t, view.Foreclosure.IsSome())

	shallow := tapreorg.DerivePhase(view)
	require.True(t, tapreorg.PhaseEqual(tapreorg.Unwitnessed{}, shallow))

	// Certification of the foreclosing transaction resolves the
	// child, attributed to the parent.
	require.NoError(t, store.StageForeclosure(
		ctx, childID, parentID, tapreorg.ForeclosureEvent{
			Parent:       parentID,
			W:            wF,
			OnChain:      true,
			ActCertified: true,
		},
	))
	view, err = store.ChainView(ctx, childID)
	require.NoError(t, err)

	childPhase := tapreorg.DerivePhase(view)
	childAbandoned, ok := childPhase.(tapreorg.Abandoned)
	require.True(t, ok)
	cause, ok := childAbandoned.Cause.(tapreorg.Foreclosed)
	require.True(t, ok)
	require.Equal(t, parentID, cause.Parent)
	require.Equal(t, wF.TxHash(), cause.W.TxHash())

	// Terminal anchorings cannot be withdrawn.
	require.NoError(t, store.SetPhase(ctx, childID, childPhase))
	err = store.Withdraw(ctx, childID, nil)
	require.ErrorIs(t, err, tapreorg.ErrTerminalPhase)
	err = store.Withdraw(ctx, parentID, nil)
	require.ErrorIs(t, err, tapreorg.ErrTerminalPhase)

	// A live, dependent-free anchoring withdraws cleanly, sensed
	// and delivered advancing together.
	loneID, err := store.Register(
		ctx, testSpec(t, "porter", testOutPoint(9, 1)), 700, nil,
	)
	require.NoError(t, err)
	require.NoError(t, store.Withdraw(
		ctx, loneID,
		func(ctx context.Context,
			tx tapreorg.RegistryTx) error {

			return tx.EnqueueEffect(
				ctx, testEffect(loneID, "undo"),
			)
		},
	))

	lone, err := store.GetAnchoring(ctx, loneID)
	require.NoError(t, err)
	require.True(t, tapreorg.PhaseEqual(tapreorg.Withdrawn{}, lone.Phase))
	require.True(t, tapreorg.PhaseEqual(
		tapreorg.Withdrawn{}, lone.DeliveredPhase,
	))
}

// TestReorgRegistryEdgesBeforeParentObserved pins the ordinary
// chained-transfer ordering: a child that registers before its
// parent's transaction has been observed on chain cannot find the
// parent at registration, so its edge derives the moment the parent
// records a satisfying candidate in the depended-upon form.
func TestReorgRegistryEdgesBeforeParentObserved(t *testing.T) {
	t.Parallel()

	store, _ := newReorgStore(t)
	ctx := context.Background()

	parentOp := testOutPoint(4, 0)
	parentID, err := store.Register(
		ctx, testSpec(t, "minter", parentOp), 500, nil,
	)
	require.NoError(t, err)

	// The child stakes on an output of the parent's yet-unconfirmed
	// witness transaction wP: the registry has never seen wP, so no
	// edge can derive at registration.
	wP := testWitness(t, 5, 600, parentOp)
	childOp := wire.OutPoint{Hash: wP.TxHash(), Index: 0}
	childID, err := store.Register(
		ctx, testSpec(t, "porter", childOp), 550, nil,
	)
	require.NoError(t, err)

	edges, err := store.DependencyEdges(ctx, parentID)
	require.NoError(t, err)
	require.Empty(t, edges)

	// The parent's satisfying candidate wP is recorded (its first
	// confirmation): the child's edge derives now, pinned to wP,
	// and the live-dependent withdrawal guard holds from here on.
	satisfying := tapreorg.CandidateSpend{
		Verdict:        tapreorg.VerdictSatisfies,
		W:              wP,
		OnChain:        true,
		SpentOutPoints: []wire.OutPoint{parentOp},
	}
	require.NoError(t, store.UpsertCandidate(ctx, parentID, satisfying))

	edges, err = store.DependencyEdges(ctx, parentID)
	require.NoError(t, err)
	require.Len(t, edges, 1)
	require.Equal(t, childID, edges[0].Child)
	require.Equal(t, wP.TxHash(), edges[0].ParentWitnessTxHash)

	err = store.Withdraw(ctx, parentID, nil)
	require.ErrorIs(t, err, tapreorg.ErrLiveDependents)

	// Re-recording the candidate (a re-confirmation) leaves the
	// single edge untouched.
	require.NoError(t, store.UpsertCandidate(ctx, parentID, satisfying))
	edges, err = store.DependencyEdges(ctx, parentID)
	require.NoError(t, err)
	require.Len(t, edges, 1)
	require.True(t, edges[0].Foreclosure.IsNone())

	// A child registering while the depended-upon form is recorded
	// but currently off-chain still finds its parent: the candidate
	// record, not the current witness, identifies the form.
	satisfying.OnChain = false
	require.NoError(t, store.UpsertCandidate(ctx, parentID, satisfying))

	child2Op := wire.OutPoint{Hash: wP.TxHash(), Index: 1}
	child2ID, err := store.Register(
		ctx, testSpec(t, "porter", child2Op), 610, nil,
	)
	require.NoError(t, err)

	edges, err = store.DependencyEdges(ctx, parentID)
	require.NoError(t, err)
	require.Len(t, edges, 2)
	require.Equal(t, child2ID, edges[1].Child)

	// Foreign candidates never derive edges, in either direction: a
	// child staked on a foreign spender's outputs is not depending
	// on any outcome of this parent's anchoring.
	wF := testWitness(t, 6, 610, parentOp)
	child3Op := wire.OutPoint{Hash: wF.TxHash(), Index: 0}
	_, err = store.Register(
		ctx, testSpec(t, "porter", child3Op), 611, nil,
	)
	require.NoError(t, err)

	require.NoError(t, store.UpsertCandidate(
		ctx, parentID, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictForeign,
			W:              wF,
			OnChain:        true,
			SpentOutPoints: []wire.OutPoint{parentOp},
		},
	))

	edges, err = store.DependencyEdges(ctx, parentID)
	require.NoError(t, err)
	require.Len(t, edges, 2)
}

// TestReorgRegistryBurialSettlesEdges pins the terminal edge
// settlement: delivering Buried clears the edges pinned to the buried
// form and forecloses every other edge, inside the delivery
// transaction — so a burial's effect on its dependents can never be
// lost between the delivery and a later restage.
func TestReorgRegistryBurialSettlesEdges(t *testing.T) {
	t.Parallel()

	store, _ := newReorgStore(t)
	ctx := context.Background()

	parentOp := testOutPoint(50, 0)
	parentID, err := store.Register(
		ctx, testSpec(t, "minter", parentOp), 500, nil,
	)
	require.NoError(t, err)

	// Two observed satisfying forms: wP (on chain, about to bury)
	// and wQ (reorged out). One child depends on each.
	wP := testWitness(t, 51, 600, parentOp)
	wQ := testWitness(t, 52, 601, parentOp)
	require.NoError(t, store.UpsertCandidate(
		ctx, parentID, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictSatisfies,
			W:              wP,
			OnChain:        true,
			ActCertified:   true,
			SpentOutPoints: []wire.OutPoint{parentOp},
		},
	))
	require.NoError(t, store.UpsertCandidate(
		ctx, parentID, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictSatisfies,
			W:              wQ,
			OnChain:        false,
			SpentOutPoints: []wire.OutPoint{parentOp},
		},
	))

	childAID, err := store.Register(
		ctx, testSpec(
			t, "porter",
			wire.OutPoint{Hash: wP.TxHash(), Index: 0},
		), 601, nil,
	)
	require.NoError(t, err)
	childBID, err := store.Register(
		ctx, testSpec(
			t, "porter",
			wire.OutPoint{Hash: wQ.TxHash(), Index: 0},
		), 602, nil,
	)
	require.NoError(t, err)

	// Stale uncertified staging on child A's edge, to prove the
	// burial clears the depended-upon form's edge.
	require.NoError(t, store.StageForeclosure(
		ctx, childAID, parentID, tapreorg.ForeclosureEvent{
			Parent: parentID, W: wQ, OnChain: true,
		},
	))

	buried := tapreorg.Buried{W: wP}
	require.NoError(t, store.SetPhase(ctx, parentID, buried))
	require.NoError(t, store.Deliver(ctx, parentID, buried, nil))

	edges, err := store.DependencyEdges(ctx, parentID)
	require.NoError(t, err)
	require.Len(t, edges, 2)
	for _, edge := range edges {
		switch edge.Child {
		case childAID:
			require.True(t, edge.Foreclosure.IsNone())

		case childBID:
			fc := edge.Foreclosure.UnwrapToPtr()
			require.NotNil(t, fc)
			require.True(t, fc.OnChain)
			require.False(t, fc.ActCertified)
			require.Equal(t, wP.TxHash(), fc.W.TxHash())

		default:
			t.Fatalf("unexpected edge child %d", edge.Child)
		}
	}
}

// TestReorgRegistryTerminalAbsorbing pins the row-level absorbing
// invariant: once an anchoring's sensed phase is terminal, SetPhase
// refuses to move it, whatever the caller derived. The sensing loop's
// terminal check reads in a different transaction than its write, so
// the row itself must hold the line against a concurrent Withdraw.
func TestReorgRegistryTerminalAbsorbing(t *testing.T) {
	t.Parallel()

	store, _ := newReorgStore(t)
	ctx := context.Background()

	op := testOutPoint(30, 0)
	id, err := store.Register(ctx, testSpec(t, "porter", op), 500, nil)
	require.NoError(t, err)

	w := testWitness(t, 31, 600, op)
	buried := tapreorg.Buried{W: w}
	require.NoError(t, store.SetPhase(ctx, id, buried))

	// A stale derivation arriving after burial is refused, and the
	// row is untouched.
	err = store.SetPhase(ctx, id, tapreorg.Witnessed{W: w})
	require.ErrorIs(t, err, tapreorg.ErrTerminalPhase)

	a, err := store.GetAnchoring(ctx, id)
	require.NoError(t, err)
	require.True(t, tapreorg.PhaseEqual(buried, a.Phase))

	// The Withdraw shape of the same race: a withdrawal commits
	// between the sensing loop's terminal check and its write. The
	// straggling write must lose, and the withdrawal outcome must
	// survive intact, sensed and delivered alike.
	id2, err := store.Register(
		ctx, testSpec(t, "porter", testOutPoint(32, 0)), 500, nil,
	)
	require.NoError(t, err)
	require.NoError(t, store.Withdraw(ctx, id2, nil))

	err = store.SetPhase(ctx, id2, tapreorg.Witnessed{W: w})
	require.ErrorIs(t, err, tapreorg.ErrTerminalPhase)

	a2, err := store.GetAnchoring(ctx, id2)
	require.NoError(t, err)
	require.True(t, tapreorg.PhaseEqual(tapreorg.Withdrawn{}, a2.Phase))
	require.True(t, tapreorg.PhaseEqual(
		tapreorg.Withdrawn{}, a2.DeliveredPhase,
	))
}

// TestReorgRegistryCertifiedForeclosureFrozen pins the edge-level
// absorbing invariant: the first certified foreclosure freezes the
// edge's evidence entirely. While uncertified, staged evidence tracks
// the parent's current form freely; after certification, restaging —
// fresher forms, off-chain flips, clears — no longer counts, since
// the child would otherwise absorb an abandonment on a transaction
// the notifier never certified.
func TestReorgRegistryCertifiedForeclosureFrozen(t *testing.T) {
	t.Parallel()

	store, _ := newReorgStore(t)
	ctx := context.Background()

	parentOp := testOutPoint(40, 0)
	parentID, err := store.Register(
		ctx, testSpec(t, "minter", parentOp), 500, nil,
	)
	require.NoError(t, err)

	wP := testWitness(t, 41, 600, parentOp)
	require.NoError(t, store.UpsertCandidate(
		ctx, parentID, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictSatisfies,
			W:              wP,
			OnChain:        true,
			SpentOutPoints: []wire.OutPoint{parentOp},
		},
	))
	require.NoError(t, store.SetPhase(
		ctx, parentID, tapreorg.Witnessed{W: wP},
	))

	childOp := wire.OutPoint{Hash: wP.TxHash(), Index: 0}
	childID, err := store.Register(
		ctx, testSpec(t, "porter", childOp), 601, nil,
	)
	require.NoError(t, err)

	staged := func() tapreorg.ForeclosureEvent {
		edges, err := store.DependencyEdges(ctx, parentID)
		require.NoError(t, err)
		require.Len(t, edges, 1)
		fc := edges[0].Foreclosure.UnwrapToPtr()
		require.NotNil(t, fc)

		return *fc
	}

	// Uncertified evidence tracks the parent's current form freely.
	wA := testWitness(t, 42, 610, parentOp)
	require.NoError(t, store.StageForeclosure(
		ctx, childID, parentID, tapreorg.ForeclosureEvent{
			Parent: parentID, W: wA, OnChain: true,
		},
	))
	wB := testWitness(t, 43, 611, parentOp)
	require.NoError(t, store.StageForeclosure(
		ctx, childID, parentID, tapreorg.ForeclosureEvent{
			Parent: parentID, W: wB, OnChain: true,
		},
	))
	require.Equal(t, wB.TxHash(), staged().W.TxHash())

	// The notifier certifies wB at the child's threshold.
	require.NoError(t, store.StageForeclosure(
		ctx, childID, parentID, tapreorg.ForeclosureEvent{
			Parent: parentID, W: wB, OnChain: true,
			ActCertified: true,
		},
	))
	require.True(t, staged().ActCertified)

	// A later uncertified form must not displace certified
	// evidence.
	wC := testWitness(t, 44, 612, parentOp)
	require.NoError(t, store.StageForeclosure(
		ctx, childID, parentID, tapreorg.ForeclosureEvent{
			Parent: parentID, W: wC, OnChain: true,
		},
	))
	fc := staged()
	require.Equal(t, wB.TxHash(), fc.W.TxHash())
	require.True(t, fc.ActCertified)
	require.True(t, fc.OnChain)

	// Nor can a reorg talk certified evidence off-chain: act-level
	// finality is exactly the point past which the chain's later
	// opinion no longer counts.
	offChain := fc
	offChain.OnChain = false
	require.NoError(t, store.StageForeclosure(
		ctx, childID, parentID, offChain,
	))
	require.True(t, staged().OnChain)

	// And a certified foreclosure is never cleared.
	require.NoError(t, store.ClearForeclosure(ctx, childID, parentID))
	require.True(t, staged().ActCertified)
}

// TestReorgRegistryStrongestForeclosure pins the strongest-staged-
// foreclosure selection across a child with two parents: certified
// evidence beats uncertified, on-chain beats off-chain, and within a
// tier the deeper (lower) evidence wins — whichever edge carries it.
// The selection decides which parent the child's abandonment is
// attributed to.
func TestReorgRegistryStrongestForeclosure(t *testing.T) {
	t.Parallel()

	store, _ := newReorgStore(t)
	ctx := context.Background()

	// Two parents, each witnessed in its own form; the child spends
	// one output of each, so both edges derive at registration.
	op1 := testOutPoint(0xa1, 0)
	op2 := testOutPoint(0xa2, 0)
	p1, err := store.Register(ctx, testSpec(t, "minter", op1), 500, nil)
	require.NoError(t, err)
	p2, err := store.Register(ctx, testSpec(t, "minter", op2), 500, nil)
	require.NoError(t, err)

	wP1 := testWitness(t, 0xb1, 600, op1)
	require.NoError(t, store.UpsertCandidate(
		ctx, p1, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictSatisfies,
			W:              wP1,
			OnChain:        true,
			SpentOutPoints: []wire.OutPoint{op1},
		},
	))
	require.NoError(t, store.SetPhase(
		ctx, p1, tapreorg.Witnessed{W: wP1},
	))
	wP2 := testWitness(t, 0xb2, 600, op2)
	require.NoError(t, store.UpsertCandidate(
		ctx, p2, tapreorg.CandidateSpend{
			Verdict:        tapreorg.VerdictSatisfies,
			W:              wP2,
			OnChain:        true,
			SpentOutPoints: []wire.OutPoint{op2},
		},
	))
	require.NoError(t, store.SetPhase(
		ctx, p2, tapreorg.Witnessed{W: wP2},
	))

	childID, err := store.Register(ctx, testSpec(
		t, "porter",
		wire.OutPoint{Hash: wP1.TxHash(), Index: 0},
		wire.OutPoint{Hash: wP2.TxHash(), Index: 0},
	), 601, nil)
	require.NoError(t, err)

	edges, err := store.IncomingEdges(ctx, childID)
	require.NoError(t, err)
	require.Len(t, edges, 2)

	// Foreclosing evidence per parent; p1's runs deeper (lower).
	fc1 := testWitness(t, 0xc1, 620, op1)
	fc2 := testWitness(t, 0xc2, 630, op2)

	strongest := func() (tapreorg.ForeclosureEvent, tapreorg.Phase) {
		view, err := store.ChainView(ctx, childID)
		require.NoError(t, err)
		fc := view.Foreclosure.UnwrapToPtr()
		require.NotNil(t, fc)

		return *fc, tapreorg.DerivePhase(view)
	}

	// Alone, p1's off-chain staging is the view's foreclosure.
	require.NoError(t, store.StageForeclosure(
		ctx, childID, p1, tapreorg.ForeclosureEvent{
			Parent: p1, W: fc1,
		},
	))
	sel, _ := strongest()
	require.Equal(t, p1, sel.Parent)

	// On-chain beats off-chain, though p2's evidence sits higher.
	require.NoError(t, store.StageForeclosure(
		ctx, childID, p2, tapreorg.ForeclosureEvent{
			Parent: p2, W: fc2, OnChain: true,
		},
	))
	sel, _ = strongest()
	require.Equal(t, p2, sel.Parent)

	// Both on-chain: the deeper evidence wins.
	require.NoError(t, store.StageForeclosure(
		ctx, childID, p1, tapreorg.ForeclosureEvent{
			Parent: p1, W: fc1, OnChain: true,
		},
	))
	sel, _ = strongest()
	require.Equal(t, p1, sel.Parent)

	// Certification trumps depth, and decides the attribution: the
	// child abandons foreclosed by p2.
	require.NoError(t, store.StageForeclosure(
		ctx, childID, p2, tapreorg.ForeclosureEvent{
			Parent: p2, W: fc2, OnChain: true,
			ActCertified: true,
		},
	))
	sel, phase := strongest()
	require.Equal(t, p2, sel.Parent)
	abandoned, ok := phase.(tapreorg.Abandoned)
	require.True(t, ok)
	cause, ok := abandoned.Cause.(tapreorg.Foreclosed)
	require.True(t, ok)
	require.Equal(t, p2, cause.Parent)
	require.Equal(t, fc2.TxHash(), cause.W.TxHash())

	// Both certified: depth decides again, and the attribution
	// follows.
	require.NoError(t, store.StageForeclosure(
		ctx, childID, p1, tapreorg.ForeclosureEvent{
			Parent: p1, W: fc1, OnChain: true,
			ActCertified: true,
		},
	))
	sel, phase = strongest()
	require.Equal(t, p1, sel.Parent)
	abandoned, ok = phase.(tapreorg.Abandoned)
	require.True(t, ok)
	cause, ok = abandoned.Cause.(tapreorg.Foreclosed)
	require.True(t, ok)
	require.Equal(t, p1, cause.Parent)
	require.Equal(t, fc1.TxHash(), cause.W.TxHash())
}

// TestReorgRegistryRapid is a model-based test of the pending-
// delivery invariant: after arbitrary interleavings of registration,
// phase changes, deliveries, failures and clock advances, the set of
// pending deliveries reported by the store is exactly the model's
// {id : phase != delivered && nextAttempt <= now}.
func TestReorgRegistryRapid(t *testing.T) {
	t.Parallel()

	// The store is shared across rapid iterations (a fresh database
	// costs seconds of migrations), so every comparison below is
	// scoped to the iteration's own anchoring IDs. Leaked state
	// from prior iterations is invisible to the assertions; the
	// cost is that shrunk counterexamples may depend on accumulated
	// rows.
	store, testClock := newReorgStore(t)

	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()

		type modelAnchoring struct {
			phase     tapreorg.Phase
			delivered tapreorg.Phase
			nextAt    time.Time
			op        wire.OutPoint
			seq       byte
		}
		model := make(map[tapreorg.AnchoringID]*modelAnchoring)
		ids := make([]tapreorg.AnchoringID, 0)

		var seed byte
		numOps := rapid.IntRange(5, 25).Draw(rt, "numOps")
		for i := 0; i < numOps; i++ {
			opKind := rapid.IntRange(0, 3).Draw(
				rt, fmt.Sprintf("op%d", i),
			)

			// Without anchorings, only registration applies.
			if len(ids) == 0 {
				opKind = 0
			}

			switch opKind {
			// Register a new anchoring.
			case 0:
				seed++
				op := testOutPoint(seed, uint32(seed))
				id, err := store.Register(
					ctx, testSpec(rt, "site", op), 500,
					nil,
				)
				require.NoError(rt, err)

				model[id] = &modelAnchoring{
					phase:     tapreorg.Unwitnessed{},
					delivered: tapreorg.Unwitnessed{},
					nextAt:    time.Unix(0, 0),
					op:        op,
					seq:       seed,
				}
				ids = append(ids, id)

			// Sense a new phase (a fresh witness each time, so
			// rewitness forces redelivery).
			case 1:
				id := ids[rapid.IntRange(0, len(ids)-1).Draw(
					rt, fmt.Sprintf("op%d.id", i),
				)]
				m := model[id]
				if tapreorg.IsTerminal(m.phase) {
					continue
				}

				m.seq += 100
				w := testWitness(
					rt, m.seq,
					uint32(600+i), m.op,
				)
				var phase tapreorg.Phase = tapreorg.Witnessed{
					W: w,
				}
				if rapid.Bool().Draw(
					rt, fmt.Sprintf("op%d.unwit", i),
				) {

					phase = tapreorg.Unwitnessed{}
				}

				require.NoError(rt, store.SetPhase(
					ctx, id, phase,
				))
				m.phase = phase

				// A new sensed phase resets the previous
				// objective's failure bookkeeping.
				m.nextAt = time.Unix(0, 0)

			// Attempt delivery of the sensed phase.
			case 2:
				id := ids[rapid.IntRange(0, len(ids)-1).Draw(
					rt, fmt.Sprintf("op%d.id", i),
				)]
				m := model[id]

				fail := rapid.Bool().Draw(
					rt, fmt.Sprintf("op%d.fail", i),
				)
				if fail {
					boom := errors.New("boom")
					err := store.Deliver(
						ctx, id, m.phase,
						func(context.Context,
							tapreorg.RegistryTx,
							*tapreorg.Anchoring,
						) error {

							return boom
						},
					)
					if !tapreorg.PhaseEqual(
						m.phase, m.delivered,
					) {

						require.ErrorIs(rt, err, boom)
					} else {
						// Already converged: the
						// handler never runs.
						require.NoError(rt, err)
						continue
					}

					next := testClock.Now().Add(
						time.Minute,
					)
					require.NoError(
						rt,
						store.RecordDeliveryFailure(
							ctx, id, boom, next,
							false,
						),
					)
					m.nextAt = next

					continue
				}

				err := store.Deliver(ctx, id, m.phase, nil)
				require.NoError(rt, err)
				m.delivered = m.phase
				m.nextAt = time.Unix(0, 0)

			// Advance the clock past pending backoffs.
			case 3:
				testClock.SetTime(testClock.Now().Add(
					2 * time.Minute,
				))
			}

			// The invariant: pending deliveries are exactly the
			// model's lagging, unbacked-off anchorings.
			now := testClock.Now()
			pending, err := store.PendingDeliveries(ctx, now)
			require.NoError(rt, err)

			got := make(map[tapreorg.AnchoringID]bool)
			for _, p := range pending {
				// Scope to this iteration's anchorings; the
				// shared database may hold rows from prior
				// iterations.
				if _, ours := model[p.ID]; ours {
					got[p.ID] = true
				}
			}

			want := make(map[tapreorg.AnchoringID]bool)
			for id, m := range model {
				lagging := !tapreorg.PhaseEqual(
					m.phase, m.delivered,
				)
				if lagging && !m.nextAt.After(now) {
					want[id] = true
				}
			}

			require.Equal(rt, want, got)
		}
	})
}
