package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightningnetwork/lnd/clock"
)

// BatchedReorgRegistry is the transaction interface the re-org
// registry store runs on. It is instantiated at the *full* generated
// query set — unlike the narrowed per-store queriers elsewhere in
// this package — because registry advances run site handlers inside
// the same transaction, and a site handler may touch any store's
// tables.
type BatchedReorgRegistry = BatchedTx[*sqlc.Queries]

// ReorgRegistryStore implements tapreorg.Registry over the shared
// database.
type ReorgRegistryStore struct {
	db    BatchedReorgRegistry
	clock clock.Clock
}

// NewReorgRegistryStore creates a new registry store.
func NewReorgRegistryStore(db BatchedReorgRegistry,
	clock clock.Clock) *ReorgRegistryStore {

	return &ReorgRegistryStore{db: db, clock: clock}
}

// registryTx implements tapreorg.RegistryTx: the transaction-scoped
// handle passed to site handlers and phase-1 writes. Its only
// producers are the ExecTx bodies in this file.
type registryTx struct {
	q     *sqlc.Queries
	clock clock.Clock
}

// Queries exposes the full generated query set, scoped to the
// transaction.
func (r *registryTx) Queries() *sqlc.Queries {
	return r.q
}

// EnqueueEffect durably enqueues an external effect in this
// transaction.
func (r *registryTx) EnqueueEffect(ctx context.Context,
	effect tapreorg.OutboxEffect) error {

	var anchoringID sql.NullInt64
	effect.Anchoring.WhenSome(func(id tapreorg.AnchoringID) {
		anchoringID = sql.NullInt64{Int64: int64(id), Valid: true}
	})

	_, err := r.q.InsertReorgEffect(ctx, sqlc.InsertReorgEffectParams{
		AnchoringID:    anchoringID,
		EffectKind:     string(effect.Kind),
		PayloadVersion: int16(effect.Payload.Version),
		PayloadData:    orEmpty(effect.Payload.Data),
		CreatedAt:      r.clock.Now().Unix(),
	})

	return err
}

// A compile-time assertion that the handle satisfies the contract.
var _ tapreorg.RegistryTx = (*registryTx)(nil)

// Register inserts the anchoring, derives its dependency edges and
// runs the site's phase-1 write, all in one transaction.
func (s *ReorgRegistryStore) Register(ctx context.Context,
	spec tapreorg.RegistrationSpec, createdHeight uint32,
	phase1 func(context.Context, tapreorg.RegistryTx,
		tapreorg.AnchoringID) error) (tapreorg.AnchoringID, error) {

	if err := spec.Validate(); err != nil {
		return 0, err
	}

	unwitnessedCode, unwitnessedEv, err := tapreorg.EncodePhase(
		tapreorg.Unwitnessed{},
	)
	if err != nil {
		return 0, err
	}

	matchVersion := int16(spec.MatchData.Version)

	var id int64
	dbErr := s.db.ExecTx(ctx, WriteTxOption(), func(q *sqlc.Queries) error {
		var err error
		id, err = q.InsertReorgAnchoring(
			ctx, sqlc.InsertReorgAnchoringParams{
				SiteID:            string(spec.Site),
				Threshold:         int32(spec.Threshold),
				MatchVersion:      matchVersion,
				MatchData:         orEmpty(spec.MatchData.Data),
				PayloadVersion:    int16(spec.Payload.Version),
				PayloadData:       orEmpty(spec.Payload.Data),
				CreatedHeight:     int32(createdHeight),
				PhaseCode:         int16(unwitnessedCode),
				PhaseEvidence:     orEmpty(unwitnessedEv),
				DeliveredCode:     int16(unwitnessedCode),
				DeliveredEvidence: orEmpty(unwitnessedEv),
			},
		)
		if err != nil {
			return fmt.Errorf("unable to insert anchoring: %w",
				err)
		}

		// Insert the trigger set and derive dependency edges:
		// any live anchoring with a recorded satisfying
		// candidate that created one of our trigger outpoints
		// is a parent. A parent whose transaction has never
		// been observed cannot be found here; that edge
		// derives when the candidate is first recorded (see
		// UpsertCandidate).
		parents := make(map[int64]chainhash.Hash)
		for _, trigger := range spec.Triggers.OutPoints() {
			err := q.InsertReorgTriggerOutpoint(
				ctx, sqlc.InsertReorgTriggerOutpointParams{
					AnchoringID:  id,
					OutpointTxid: trigger.OutPoint.Hash[:],
					OutpointIndex: int32(
						trigger.OutPoint.Index,
					),
					PkScript: orEmpty(trigger.PkScript),
					HeightHint: int32(
						trigger.HeightHint,
					),
				},
			)
			if err != nil {
				return fmt.Errorf("unable to insert "+
					"trigger outpoint: %w", err)
			}

			candidates, err := q.FetchLiveReorgParentsByCandidate(
				ctx, trigger.OutPoint.Hash[:],
			)
			if err != nil {
				return fmt.Errorf("unable to look up "+
					"parent anchorings: %w", err)
			}
			for _, parentID := range candidates {
				if parentID == id {
					continue
				}
				parents[parentID] = trigger.OutPoint.Hash
			}
		}

		for parentID, witnessTxid := range parents {
			err := q.UpsertReorgDependency(
				ctx, sqlc.UpsertReorgDependencyParams{
					ChildID:  id,
					ParentID: parentID,
					ParentWitnessTxid: witnessTxid.
						CloneBytes(),
				},
			)
			if err != nil {
				return fmt.Errorf("unable to insert "+
					"dependency edge: %w", err)
			}
		}

		if phase1 != nil {
			handle := &registryTx{q: q, clock: s.clock}
			newID := tapreorg.AnchoringID(id)
			if err := phase1(ctx, handle, newID); err != nil {
				return fmt.Errorf("phase-1 write: %w", err)
			}
		}

		return nil
	})
	if dbErr != nil {
		return 0, dbErr
	}

	return tapreorg.AnchoringID(id), nil
}

// GetAnchoring fetches an anchoring with its chain view.
func (s *ReorgRegistryStore) GetAnchoring(ctx context.Context,
	id tapreorg.AnchoringID) (*tapreorg.Anchoring, error) {

	var anchoring *tapreorg.Anchoring
	dbErr := s.db.ExecTx(ctx, ReadTxOption(), func(q *sqlc.Queries) error {
		row, err := q.FetchReorgAnchoring(ctx, int64(id))
		if err != nil {
			return mapAnchoringErr(err)
		}

		anchoring, err = assembleAnchoring(ctx, q, row)

		return err
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return anchoring, nil
}

// LiveAnchorings returns all anchorings in a non-terminal phase. A
// row that cannot be assembled is skipped with an error log rather
// than failing the scan: one corrupt anchoring must not block the
// sensing and delivery of every other one.
func (s *ReorgRegistryStore) LiveAnchorings(
	ctx context.Context) ([]*tapreorg.Anchoring, error) {

	var out []*tapreorg.Anchoring
	dbErr := s.db.ExecTx(ctx, ReadTxOption(), func(q *sqlc.Queries) error {
		rows, err := q.ListLiveReorgAnchorings(ctx)
		if err != nil {
			return err
		}

		out = assembleAnchorings(ctx, q, rows)

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return out, nil
}

// AllAnchorings returns every anchoring in the registry, live and
// terminal, for the observability surface.
func (s *ReorgRegistryStore) AllAnchorings(
	ctx context.Context) ([]*tapreorg.Anchoring, error) {

	var out []*tapreorg.Anchoring
	dbErr := s.db.ExecTx(ctx, ReadTxOption(), func(q *sqlc.Queries) error {
		rows, err := q.ListReorgAnchorings(ctx)
		if err != nil {
			return err
		}

		out = make([]*tapreorg.Anchoring, 0, len(rows))
		for _, row := range rows {
			anchoring, err := assembleAnchoring(ctx, q, row)
			if err != nil {
				return err
			}
			out = append(out, anchoring)
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return out, nil
}

// ChainView assembles the anchoring's chain view.
func (s *ReorgRegistryStore) ChainView(ctx context.Context,
	id tapreorg.AnchoringID) (tapreorg.ChainView, error) {

	var view tapreorg.ChainView
	dbErr := s.db.ExecTx(ctx, ReadTxOption(), func(q *sqlc.Queries) error {
		// Ensure the anchoring exists so a bogus ID errors
		// rather than yielding an empty view.
		if _, err := q.FetchReorgAnchoring(ctx, int64(id)); err != nil {
			return mapAnchoringErr(err)
		}

		var err error
		view, err = assembleChainView(ctx, q, int64(id))

		return err
	})
	if dbErr != nil {
		return tapreorg.ChainView{}, dbErr
	}

	return view, nil
}

// UpsertCandidate records or updates a candidate spend observation.
func (s *ReorgRegistryStore) UpsertCandidate(ctx context.Context,
	id tapreorg.AnchoringID, candidate tapreorg.CandidateSpend) error {

	var rawTx bytes.Buffer
	if err := candidate.W.Tx().Serialize(&rawTx); err != nil {
		return fmt.Errorf("unable to serialize candidate tx: %w", err)
	}

	spenderTxid := candidate.W.TxHash()
	blockHash := candidate.W.BlockHash()

	var headerBytes, merkleBytes []byte
	if candidate.BlockHeader != nil {
		var buf bytes.Buffer
		err := candidate.BlockHeader.Serialize(&buf)
		if err != nil {
			return fmt.Errorf("unable to serialize block "+
				"header: %w", err)
		}
		headerBytes = buf.Bytes()
	}
	if candidate.MerkleProof != nil {
		var buf bytes.Buffer
		err := candidate.MerkleProof.Encode(&buf)
		if err != nil {
			return fmt.Errorf("unable to encode merkle "+
				"proof: %w", err)
		}
		merkleBytes = buf.Bytes()
	}

	return s.db.ExecTx(ctx, WriteTxOption(), func(q *sqlc.Queries) error {
		// The whole-set rule, held at the durable boundary: a
		// satisfying candidate must spend the anchoring's entire
		// trigger set. Coverage is recomputed from the
		// transaction itself, so no caller can record a partial
		// satisfier, however it arrived.
		if candidate.Verdict == tapreorg.VerdictSatisfies {
			triggers, err := q.FetchReorgTriggerOutpoints(
				ctx, int64(id),
			)
			if err != nil {
				return fmt.Errorf("unable to fetch trigger "+
					"outpoints: %w", err)
			}
			tx := candidate.W.Tx()
			for _, trigger := range triggers {
				if !spendsTrigger(tx, trigger) {
					return fmt.Errorf("anchoring %d: %w",
						id,
						tapreorg.ErrIncompleteSpend)
				}
			}
		}

		err := q.UpsertReorgCandidateSpend(
			ctx, sqlc.UpsertReorgCandidateSpendParams{
				AnchoringID: int64(id),
				SpenderTxid: spenderTxid.CloneBytes(),
				RawTx:       rawTx.Bytes(),
				Verdict: sql.NullInt16{
					Int16: int16(candidate.Verdict),
					Valid: true,
				},
				OnChain:   candidate.OnChain,
				BlockHash: blockHash.CloneBytes(),
				BlockHeight: sql.NullInt32{
					Int32: int32(candidate.W.Height()),
					Valid: true,
				},
				TxIndex: sql.NullInt32{
					Int32: int32(candidate.W.TxIndex()),
					Valid: true,
				},
				ActCertified: candidate.ActCertified,
				BlockHeader:  headerBytes,
				MerkleProof:  merkleBytes,
				SpentOutpoints: orEmpty(
					tapreorg.EncodeOutPoints(
						candidate.SpentOutPoints,
					),
				),
			},
		)
		if err != nil {
			return err
		}

		// A satisfying candidate identifies this anchoring as the
		// parent of every child staked on the transaction's
		// outputs. A child registered before this form was first
		// observed could not derive its edge at registration;
		// derive it now.
		if candidate.Verdict != tapreorg.VerdictSatisfies {
			return nil
		}

		children, err := q.FetchLiveReorgDependentsByTrigger(
			ctx, spenderTxid.CloneBytes(),
		)
		if err != nil {
			return fmt.Errorf("unable to look up dependent "+
				"anchorings: %w", err)
		}
		for _, childID := range children {
			if childID == int64(id) {
				continue
			}
			err := q.UpsertReorgDependency(
				ctx, sqlc.UpsertReorgDependencyParams{
					ChildID:  childID,
					ParentID: int64(id),
					ParentWitnessTxid: spenderTxid.
						CloneBytes(),
				},
			)
			if err != nil {
				return fmt.Errorf("unable to derive "+
					"dependency edge: %w", err)
			}
		}

		return nil
	})
}

// SetPhase persists a newly derived phase.
func (s *ReorgRegistryStore) SetPhase(ctx context.Context,
	id tapreorg.AnchoringID, phase tapreorg.Phase) error {

	code, evidence, err := tapreorg.EncodePhase(phase)
	if err != nil {
		return err
	}

	return s.db.ExecTx(ctx, WriteTxOption(), func(q *sqlc.Queries) error {
		rows, err := q.SetReorgAnchoringPhase(
			ctx, sqlc.SetReorgAnchoringPhaseParams{
				ID:            int64(id),
				PhaseCode:     int16(code),
				PhaseEvidence: orEmpty(evidence),
				WitnessTxid:   witnessTxidOf(phase),
			},
		)
		if err != nil {
			return err
		}

		// Zero rows means the row-level guard held: another
		// writer pinned the anchoring terminal after the caller
		// derived. Terminal phases are absorbing, so the stale
		// derivation is refused rather than applied.
		if rows == 0 {
			return tapreorg.ErrTerminalPhase
		}

		return nil
	})
}

// Deliver invokes the handler inside a transaction and, on success,
// records the target phase as delivered — settling live dependents'
// edges in the same transaction when the target is terminal.
func (s *ReorgRegistryStore) Deliver(ctx context.Context,
	id tapreorg.AnchoringID, target tapreorg.Phase,
	handler func(context.Context, tapreorg.RegistryTx,
		*tapreorg.Anchoring) error) error {

	targetCode, targetEv, err := tapreorg.EncodePhase(target)
	if err != nil {
		return err
	}

	return s.db.ExecTx(ctx, WriteTxOption(), func(q *sqlc.Queries) error {
		row, err := q.FetchReorgAnchoring(ctx, int64(id))
		if err != nil {
			return mapAnchoringErr(err)
		}

		// The sensed phase must still be the target: if sensing
		// moved on between the delivery decision and this
		// transaction, the delivery is stale and the caller
		// simply rescans.
		if row.PhaseCode != int16(targetCode) ||
			!bytes.Equal(row.PhaseEvidence, orEmpty(targetEv)) {

			return tapreorg.ErrStaleDelivery
		}

		// Already delivered: a benign no-op.
		if row.DeliveredCode == int16(targetCode) &&
			bytes.Equal(
				row.DeliveredEvidence, orEmpty(targetEv),
			) {

			return nil
		}

		if handler != nil {
			// Re-assemble the anchoring inside this transaction
			// so its chain view reflects any candidate
			// enrichment sensing has committed between the
			// caller's pending scan and here. Handlers that
			// read Spends[i].BlockHeader / MerkleProof cannot
			// see stale evidence.
			fresh, err := assembleAnchoring(ctx, q, row)
			if err != nil {
				return fmt.Errorf("unable to assemble "+
					"anchoring for delivery: %w", err)
			}

			handle := &registryTx{q: q, clock: s.clock}
			if err := handler(ctx, handle, fresh); err != nil {
				return err
			}
		}

		var terminalAt sql.NullInt64
		if tapreorg.IsTerminal(target) {
			terminalAt = sql.NullInt64{
				Int64: s.clock.Now().Unix(),
				Valid: true,
			}
		}

		err = q.MarkReorgAnchoringDelivered(
			ctx, sqlc.MarkReorgAnchoringDeliveredParams{
				ID:                int64(id),
				DeliveredCode:     int16(targetCode),
				DeliveredEvidence: orEmpty(targetEv),
				TerminalAt:        terminalAt,
			},
		)
		if err != nil {
			return fmt.Errorf("unable to mark delivered: %w", err)
		}

		// A terminal delivery settles its live dependents' edges
		// in the same transaction, so the settlement cannot be
		// lost between the delivery and a later restage. An
		// abandonment forecloses every edge — which is what
		// makes cascade delivery parent-first structural. A
		// burial is the parent's final form: edges depending on
		// that very form are cleared, and every other edge is
		// foreclosed by it.
		switch phase := target.(type) {
		case tapreorg.Abandoned:
			return settleDependentEdges(
				ctx, q, int64(id), phase.Cause.Witness(),
				false,
			)

		case tapreorg.Buried:
			return settleDependentEdges(
				ctx, q, int64(id), phase.W, true,
			)

		default:
			return nil
		}
	})
}

// settleDependentEdges stages the given witness as foreclosing
// evidence on every one of the parent's dependency edges. With
// clearDependedForm set, edges pinned to that witness's own form are
// cleared instead — their premise holds. Edges carrying a certified
// foreclosure are frozen by the updates' own row-level guards.
func settleDependentEdges(ctx context.Context, q *sqlc.Queries,
	parentID int64, foreclosing tapreorg.Witness,
	clearDependedForm bool) error {

	evidence, err := foreclosing.Encode()
	if err != nil {
		return err
	}
	foreclosingTxid := foreclosing.TxHash()

	edges, err := q.FetchReorgDependencyEdgesByParent(ctx, parentID)
	if err != nil {
		return fmt.Errorf("unable to fetch dependents: %w", err)
	}
	for _, edge := range edges {
		if clearDependedForm && bytes.Equal(
			edge.ParentWitnessTxid, foreclosingTxid[:],
		) {

			err := q.ClearReorgDependencyForeclosure(
				ctx,
				sqlc.ClearReorgDependencyForeclosureParams{
					ChildID:  edge.ChildID,
					ParentID: parentID,
				},
			)
			if err != nil {
				return fmt.Errorf("unable to clear "+
					"dependent %d: %w", edge.ChildID, err)
			}

			continue
		}

		err := q.UpdateReorgDependencyForeclosure(
			ctx, sqlc.UpdateReorgDependencyForeclosureParams{
				ChildID:             edge.ChildID,
				ParentID:            parentID,
				ForeclosingEvidence: evidence,
				ForeclosingOnChain:  true,
			},
		)
		if err != nil {
			return fmt.Errorf("unable to foreclose "+
				"dependent %d: %w", edge.ChildID, err)
		}
	}

	return nil
}

// RecordDeliveryFailure records a failed delivery attempt.
func (s *ReorgRegistryStore) RecordDeliveryFailure(ctx context.Context,
	id tapreorg.AnchoringID, deliveryErr error, nextAttempt time.Time,
	stuck bool) error {

	var errText sql.NullString
	if deliveryErr != nil {
		errText = sql.NullString{
			String: deliveryErr.Error(),
			Valid:  true,
		}
	}

	return s.db.ExecTx(ctx, WriteTxOption(), func(q *sqlc.Queries) error {
		return q.RecordReorgDeliveryFailure(
			ctx, sqlc.RecordReorgDeliveryFailureParams{
				ID:                int64(id),
				LastDeliveryError: errText,
				NextDeliveryAt:    nextAttempt.Unix(),
				Stuck:             stuck,
			},
		)
	})
}

// PendingDeliveries returns the anchorings whose delivered phase lags
// their sensed phase and whose next-attempt time has passed.
func (s *ReorgRegistryStore) PendingDeliveries(ctx context.Context,
	now time.Time) ([]*tapreorg.Anchoring, error) {

	var out []*tapreorg.Anchoring
	dbErr := s.db.ExecTx(ctx, ReadTxOption(), func(q *sqlc.Queries) error {
		rows, err := q.ListReorgPendingDeliveries(ctx, now.Unix())
		if err != nil {
			return err
		}

		out = assembleAnchorings(ctx, q, rows)

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return out, nil
}

// Withdraw runs the site's withdrawal write and moves the anchoring
// to Withdrawn in one transaction, refusing when live dependents
// exist or the anchoring is already terminal.
func (s *ReorgRegistryStore) Withdraw(ctx context.Context,
	id tapreorg.AnchoringID,
	onWithdraw func(context.Context, tapreorg.RegistryTx) error) error {

	withdrawnCode, withdrawnEv, err := tapreorg.EncodePhase(
		tapreorg.Withdrawn{},
	)
	if err != nil {
		return err
	}

	return s.db.ExecTx(ctx, WriteTxOption(), func(q *sqlc.Queries) error {
		row, err := q.FetchReorgAnchoring(ctx, int64(id))
		if err != nil {
			return mapAnchoringErr(err)
		}

		phase, err := tapreorg.DecodePhase(
			tapreorg.PhaseCode(row.PhaseCode), row.PhaseEvidence,
		)
		if err != nil {
			return err
		}
		if tapreorg.IsTerminal(phase) {
			return tapreorg.ErrTerminalPhase
		}

		dependents, err := q.CountLiveReorgDependents(ctx, int64(id))
		if err != nil {
			return err
		}
		if dependents > 0 {
			return tapreorg.ErrLiveDependents
		}

		if onWithdraw != nil {
			handle := &registryTx{q: q, clock: s.clock}
			if err := onWithdraw(ctx, handle); err != nil {
				return err
			}
		}

		// Withdrawal is site-initiated, so sensed and delivered
		// phase advance together: there is no signal left to
		// deliver. The row was read live in this transaction, so
		// the update's terminal guard always passes here.
		_, err = q.SetReorgAnchoringPhase(
			ctx, sqlc.SetReorgAnchoringPhaseParams{
				ID:            int64(id),
				PhaseCode:     int16(withdrawnCode),
				PhaseEvidence: orEmpty(withdrawnEv),
				WitnessTxid:   nil,
			},
		)
		if err != nil {
			return err
		}

		return q.MarkReorgAnchoringDelivered(
			ctx, sqlc.MarkReorgAnchoringDeliveredParams{
				ID:                int64(id),
				DeliveredCode:     int16(withdrawnCode),
				DeliveredEvidence: orEmpty(withdrawnEv),
				TerminalAt: sql.NullInt64{
					Int64: s.clock.Now().Unix(),
					Valid: true,
				},
			},
		)
	})
}

// DependencyEdges returns the edges from live children to the given
// parent.
func (s *ReorgRegistryStore) DependencyEdges(ctx context.Context,
	parent tapreorg.AnchoringID) ([]tapreorg.DependencyEdge, error) {

	var out []tapreorg.DependencyEdge
	dbErr := s.db.ExecTx(ctx, ReadTxOption(), func(q *sqlc.Queries) error {
		rows, err := q.FetchReorgDependencyEdgesByParent(
			ctx, int64(parent),
		)
		if err != nil {
			return err
		}

		out = make([]tapreorg.DependencyEdge, 0, len(rows))
		for _, row := range rows {
			edge, err := assembleEdge(row)
			if err != nil {
				return err
			}
			out = append(out, edge)
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return out, nil
}

// IncomingEdges returns the edges from the given child to its
// parents.
func (s *ReorgRegistryStore) IncomingEdges(ctx context.Context,
	child tapreorg.AnchoringID) ([]tapreorg.DependencyEdge, error) {

	var out []tapreorg.DependencyEdge
	dbErr := s.db.ExecTx(ctx, ReadTxOption(), func(q *sqlc.Queries) error {
		rows, err := q.FetchReorgDependencyEdgesByChild(
			ctx, int64(child),
		)
		if err != nil {
			return err
		}

		out = make([]tapreorg.DependencyEdge, 0, len(rows))
		for _, row := range rows {
			edge, err := assembleEdge(row)
			if err != nil {
				return err
			}
			out = append(out, edge)
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return out, nil
}

// StageForeclosure stages (or refreshes) foreclosing evidence on the
// child→parent edge. Once the edge carries a certified foreclosure it
// is frozen, and later stagings are benign no-ops.
func (s *ReorgRegistryStore) StageForeclosure(ctx context.Context,
	child, parent tapreorg.AnchoringID,
	foreclosure tapreorg.ForeclosureEvent) error {

	evidence, err := foreclosure.W.Encode()
	if err != nil {
		return err
	}

	return s.db.ExecTx(ctx, WriteTxOption(), func(q *sqlc.Queries) error {
		return q.UpdateReorgDependencyForeclosure(
			ctx, sqlc.UpdateReorgDependencyForeclosureParams{
				ChildID:             int64(child),
				ParentID:            int64(parent),
				ForeclosingEvidence: evidence,
				ForeclosingOnChain:  foreclosure.OnChain,
				ForeclosingActCertified: foreclosure.
					ActCertified,
			},
		)
	})
}

// ClearForeclosure removes staged foreclosing evidence from the
// child→parent edge.
func (s *ReorgRegistryStore) ClearForeclosure(ctx context.Context,
	child, parent tapreorg.AnchoringID) error {

	return s.db.ExecTx(ctx, WriteTxOption(), func(q *sqlc.Queries) error {
		return q.ClearReorgDependencyForeclosure(
			ctx, sqlc.ClearReorgDependencyForeclosureParams{
				ChildID:  int64(child),
				ParentID: int64(parent),
			},
		)
	})
}

// PendingEffects returns undispatched outbox effects whose
// next-attempt time has passed.
func (s *ReorgRegistryStore) PendingEffects(ctx context.Context,
	now time.Time, limit int32) ([]*tapreorg.StoredEffect, error) {

	var out []*tapreorg.StoredEffect
	dbErr := s.db.ExecTx(ctx, ReadTxOption(), func(q *sqlc.Queries) error {
		rows, err := q.ListReorgPendingEffects(
			ctx, sqlc.ListReorgPendingEffectsParams{
				Now:        now.Unix(),
				MaxEffects: limit,
			},
		)
		if err != nil {
			return err
		}

		out = make([]*tapreorg.StoredEffect, 0, len(rows))
		for _, row := range rows {
			anchoring := fn.None[tapreorg.AnchoringID]()
			if row.AnchoringID.Valid {
				anchoring = fn.Some(tapreorg.AnchoringID(
					row.AnchoringID.Int64,
				))
			}

			out = append(out, &tapreorg.StoredEffect{
				ID: row.ID,
				Effect: tapreorg.OutboxEffect{
					Kind: tapreorg.EffectKind(
						row.EffectKind,
					),
					Anchoring: anchoring,
					Payload: tapreorg.VersionedBlob{
						Version: uint16(
							row.PayloadVersion,
						),
						Data: row.PayloadData,
					},
				},
				Attempts: uint32(row.Attempts),
			})
		}

		return nil
	})
	if dbErr != nil {
		return nil, dbErr
	}

	return out, nil
}

// MarkEffectDispatched marks an outbox effect dispatched.
func (s *ReorgRegistryStore) MarkEffectDispatched(ctx context.Context,
	effectID int64) error {

	return s.db.ExecTx(ctx, WriteTxOption(), func(q *sqlc.Queries) error {
		return q.MarkReorgEffectDispatched(
			ctx, sqlc.MarkReorgEffectDispatchedParams{
				ID: effectID,
				DispatchedAt: sql.NullInt64{
					Int64: s.clock.Now().Unix(),
					Valid: true,
				},
			},
		)
	})
}

// RecordEffectFailure records a failed dispatch attempt.
func (s *ReorgRegistryStore) RecordEffectFailure(ctx context.Context,
	effectID int64, dispatchErr error, nextAttempt time.Time) error {

	var errText sql.NullString
	if dispatchErr != nil {
		errText = sql.NullString{
			String: dispatchErr.Error(),
			Valid:  true,
		}
	}

	return s.db.ExecTx(ctx, WriteTxOption(), func(q *sqlc.Queries) error {
		return q.RecordReorgEffectFailure(
			ctx, sqlc.RecordReorgEffectFailureParams{
				ID:            effectID,
				LastError:     errText,
				NextAttemptAt: nextAttempt.Unix(),
			},
		)
	})
}

// assembleAnchorings builds aggregates for a scan's rows, skipping —
// with an error log — any row that cannot be assembled: scans feed
// sensing, delivery and observability, and one undecodable anchoring
// must not halt all the others. The skipped anchoring itself is not
// lost, merely unserved until repaired; every scan is periodic, so
// it is retried (and re-logged) on each pass.
func assembleAnchorings(ctx context.Context, q *sqlc.Queries,
	rows []sqlc.ReorgAnchoring) []*tapreorg.Anchoring {

	out := make([]*tapreorg.Anchoring, 0, len(rows))
	for _, row := range rows {
		anchoring, err := assembleAnchoring(ctx, q, row)
		if err != nil {
			log.Errorf("Skipping undecodable anchoring %d: %v",
				row.ID, err)
			continue
		}
		out = append(out, anchoring)
	}

	return out
}

// assembleAnchoring builds the full aggregate from a row plus its
// trigger, spend and dependency records, within the caller's
// transaction.
func assembleAnchoring(ctx context.Context, q *sqlc.Queries,
	row sqlc.ReorgAnchoring) (*tapreorg.Anchoring, error) {

	phase, err := tapreorg.DecodePhase(
		tapreorg.PhaseCode(row.PhaseCode), row.PhaseEvidence,
	)
	if err != nil {
		return nil, fmt.Errorf("anchoring %d phase: %w", row.ID, err)
	}

	delivered, err := tapreorg.DecodePhase(
		tapreorg.PhaseCode(row.DeliveredCode), row.DeliveredEvidence,
	)
	if err != nil {
		return nil, fmt.Errorf("anchoring %d delivered phase: %w",
			row.ID, err)
	}

	triggerRows, err := q.FetchReorgTriggerOutpoints(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	triggerPoints := make([]tapreorg.TriggerOutPoint, len(triggerRows))
	for i, tr := range triggerRows {
		txid, err := chainhash.NewHash(tr.OutpointTxid)
		if err != nil {
			return nil, err
		}
		triggerPoints[i] = tapreorg.TriggerOutPoint{
			OutPoint: wire.OutPoint{
				Hash:  *txid,
				Index: uint32(tr.OutpointIndex),
			},
			PkScript:   tr.PkScript,
			HeightHint: uint32(tr.HeightHint),
		}
	}
	triggers, err := tapreorg.NewTriggerSet(triggerPoints)
	if err != nil {
		return nil, fmt.Errorf("anchoring %d triggers: %w", row.ID,
			err)
	}

	view, err := assembleChainView(ctx, q, row.ID)
	if err != nil {
		return nil, err
	}

	return &tapreorg.Anchoring{
		ID:        tapreorg.AnchoringID(row.ID),
		Site:      tapreorg.SiteID(row.SiteID),
		Triggers:  triggers,
		Threshold: uint32(row.Threshold),
		MatchData: tapreorg.VersionedBlob{
			Version: uint16(row.MatchVersion),
			Data:    row.MatchData,
		},
		Payload: tapreorg.VersionedBlob{
			Version: uint16(row.PayloadVersion),
			Data:    row.PayloadData,
		},
		CreatedHeight:    uint32(row.CreatedHeight),
		Phase:            phase,
		DeliveredPhase:   delivered,
		Stuck:            row.Stuck,
		DeliveryAttempts: uint32(row.DeliveryAttempts),
		Spends:           view.Spends,
	}, nil
}

// assembleChainView builds the chain view: candidate spends plus the
// strongest staged foreclosure, within the caller's transaction.
func assembleChainView(ctx context.Context, q *sqlc.Queries,
	id int64) (tapreorg.ChainView, error) {

	spendRows, err := q.FetchReorgCandidateSpends(ctx, id)
	if err != nil {
		return tapreorg.ChainView{}, err
	}

	view := tapreorg.ChainView{
		Spends: make([]tapreorg.CandidateSpend, 0, len(spendRows)),
	}
	for _, sr := range spendRows {
		candidate, err := assembleCandidate(sr)
		if err != nil {
			return tapreorg.ChainView{}, err
		}
		view.Spends = append(view.Spends, candidate)
	}

	// The strongest staged foreclosure: on-chain beats off-chain,
	// then deeper (lower height) wins.
	edges, err := q.FetchReorgDependencyEdgesByChild(ctx, id)
	if err != nil {
		return tapreorg.ChainView{}, err
	}
	for _, edge := range edges {
		if len(edge.ForeclosingEvidence) == 0 {
			continue
		}

		w, err := tapreorg.DecodeWitnessBlob(edge.ForeclosingEvidence)
		if err != nil {
			return tapreorg.ChainView{}, fmt.Errorf("edge "+
				"%d→%d foreclosure: %w", edge.ChildID,
				edge.ParentID, err)
		}

		event := tapreorg.ForeclosureEvent{
			Parent:       tapreorg.AnchoringID(edge.ParentID),
			W:            w,
			OnChain:      edge.ForeclosingOnChain,
			ActCertified: edge.ForeclosingActCertified,
		}

		current := view.Foreclosure.UnwrapToPtr()
		if current == nil || foreclosureStronger(event, *current) {
			view.Foreclosure = fn.Some(event)
		}
	}

	return view, nil
}

// foreclosureStronger reports whether a should replace b as the
// view's staged foreclosure: certified beats uncertified, then
// on-chain beats off-chain, then deeper wins.
func foreclosureStronger(a, b tapreorg.ForeclosureEvent) bool {
	if a.ActCertified != b.ActCertified {
		return a.ActCertified
	}
	if a.OnChain != b.OnChain {
		return a.OnChain
	}

	return a.W.Height() < b.W.Height()
}

// assembleCandidate builds a candidate spend from its row.
func assembleCandidate(
	row sqlc.ReorgCandidateSpend) (tapreorg.CandidateSpend, error) {

	var zero tapreorg.CandidateSpend

	if !row.Verdict.Valid {
		return zero, fmt.Errorf("candidate %d has no verdict", row.ID)
	}
	verdict, err := tapreorg.NewVerdict(uint8(row.Verdict.Int16))
	if err != nil {
		return zero, err
	}

	if !row.BlockHeight.Valid || !row.TxIndex.Valid {
		return zero, fmt.Errorf("candidate %d is not fully located",
			row.ID)
	}
	blockHash, err := chainhash.NewHash(row.BlockHash)
	if err != nil {
		return zero, err
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(row.RawTx)); err != nil {
		return zero, fmt.Errorf("candidate %d tx: %w", row.ID, err)
	}

	w, err := tapreorg.NewWitness(
		&tx, *blockHash, uint32(row.BlockHeight.Int32),
		uint32(row.TxIndex.Int32),
	)
	if err != nil {
		return zero, err
	}

	spent, err := tapreorg.DecodeOutPoints(row.SpentOutpoints)
	if err != nil {
		return zero, err
	}

	var header *wire.BlockHeader
	if len(row.BlockHeader) > 0 {
		header = &wire.BlockHeader{}
		err := header.Deserialize(bytes.NewReader(row.BlockHeader))
		if err != nil {
			return zero, fmt.Errorf("candidate %d header: %w",
				row.ID, err)
		}
	}

	var merkle *proof.TxMerkleProof
	if len(row.MerkleProof) > 0 {
		merkle = &proof.TxMerkleProof{}
		err := merkle.Decode(bytes.NewReader(row.MerkleProof))
		if err != nil {
			return zero, fmt.Errorf("candidate %d merkle "+
				"proof: %w", row.ID, err)
		}
	}

	return tapreorg.CandidateSpend{
		Verdict:        verdict,
		W:              w,
		OnChain:        row.OnChain,
		ActCertified:   row.ActCertified,
		BlockHeader:    header,
		MerkleProof:    merkle,
		SpentOutPoints: spent,
	}, nil
}

// assembleEdge builds a dependency edge from its row.
func assembleEdge(row sqlc.ReorgDependency) (tapreorg.DependencyEdge, error) {
	parentTxid, err := chainhash.NewHash(row.ParentWitnessTxid)
	if err != nil {
		return tapreorg.DependencyEdge{}, err
	}

	edge := tapreorg.DependencyEdge{
		Child:               tapreorg.AnchoringID(row.ChildID),
		Parent:              tapreorg.AnchoringID(row.ParentID),
		ParentWitnessTxHash: *parentTxid,
	}

	if len(row.ForeclosingEvidence) > 0 {
		w, err := tapreorg.DecodeWitnessBlob(row.ForeclosingEvidence)
		if err != nil {
			return tapreorg.DependencyEdge{}, err
		}
		edge.Foreclosure = fn.Some(tapreorg.ForeclosureEvent{
			Parent:       tapreorg.AnchoringID(row.ParentID),
			W:            w,
			OnChain:      row.ForeclosingOnChain,
			ActCertified: row.ForeclosingActCertified,
		})
	}

	return edge, nil
}

// witnessTxidOf returns the current witness transaction hash for
// witnessed/buried phases, nil otherwise.
func witnessTxidOf(phase tapreorg.Phase) []byte {
	switch p := phase.(type) {
	case tapreorg.Witnessed:
		h := p.W.TxHash()
		return h.CloneBytes()

	case tapreorg.Buried:
		h := p.W.TxHash()
		return h.CloneBytes()

	default:
		return nil
	}
}

// mapAnchoringErr maps sql.ErrNoRows to the registry's not-found
// error.
func mapAnchoringErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return tapreorg.ErrAnchoringNotFound
	}

	return err
}

// spendsTrigger reports whether the transaction spends the trigger
// row's outpoint.
func spendsTrigger(tx *wire.MsgTx, row sqlc.ReorgTriggerOutpoint) bool {
	for _, txIn := range tx.TxIn {
		op := txIn.PreviousOutPoint
		if bytes.Equal(op.Hash[:], row.OutpointTxid) &&
			op.Index == uint32(row.OutpointIndex) {

			return true
		}
	}

	return false
}

// orEmpty normalizes a nil byte slice to an empty one, so that
// NOT NULL blob columns accept it.
func orEmpty(b []byte) []byte {
	if b == nil {
		return []byte{}
	}

	return b
}

// A compile-time assertion that the store satisfies the registry
// contract.
var _ tapreorg.Registry = (*ReorgRegistryStore)(nil)
