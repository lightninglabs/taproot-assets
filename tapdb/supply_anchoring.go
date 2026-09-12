package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
)

// This file houses the transaction-scoped bodies of the supply-commit
// site's persistence, run inside the re-org watcher's delivery
// transaction. Finalization is the same act the legacy state machine
// performs via ApplyStateTransition, but reconstructed entirely from
// durable state: the pending transition and its update events come
// from the database, and the chain proof comes from the anchoring's
// enriched witness — no in-memory state machine data crosses the
// boundary, so a restart at any point loses nothing.

// ApplyCommitFinalize finalizes the pending supply-commit transition
// whose commitment transaction is commitTxid: the pending updates are
// applied to the durable supply trees, the commitment row receives its
// chain details from the supplied proof, spent pre-commitments are
// marked, the transition is finalized, and the state-machine row
// returns to rest. Any updates that went dangling while the commitment
// awaited burial are bound into the next pending transition, with the
// state-machine row parked in UpdatesPendingState so a resuming
// machine picks them up. Convergent: a commitment that already carries
// chain details was applied, and the call is a no-op.
func (s *SupplyCommitMachine) ApplyCommitFinalize(ctx context.Context,
	q *sqlc.Queries, groupKey *btcec.PublicKey, commitTxid chainhash.Hash,
	chainProof supplycommit.ChainProof) error {

	groupKeyBytes := schnorr.SerializePubKey(groupKey)
	assetSpec := asset.NewSpecifierFromGroupKey(*groupKey)

	// The commitment row is created when the signed transaction is
	// persisted, and its chain columns are written exactly once, at
	// finalization. A row that already carries a block height was
	// applied: converge as a no-op.
	commitRow, err := q.QuerySupplyCommitmentByTxid(
		ctx, sqlc.QuerySupplyCommitmentByTxidParams{
			GroupKey: groupKeyBytes,
			Txid:     commitTxid[:],
		},
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("no supply commitment known for tx %v",
			commitTxid)

	case err != nil:
		return fmt.Errorf("unable to query commitment for tx %v: %w",
			commitTxid, err)
	}
	if commitRow.BlockHeight.Valid {
		return nil
	}

	// The pending transition must be the one that created this
	// commitment; anything else means the durable record and the
	// anchoring registry disagree, which no amount of writing here
	// can honestly repair.
	transitionRow, err := q.QueryPendingSupplyCommitTransition(
		ctx, groupKeyBytes,
	)
	if err != nil {
		return fmt.Errorf("no pending transition for group: %w", err)
	}
	dbTransition := transitionRow.SupplyCommitTransition
	if !dbTransition.NewCommitmentID.Valid ||
		dbTransition.NewCommitmentID.Int64 != commitRow.CommitID {

		return fmt.Errorf("pending transition %d does not reference "+
			"commitment tx %v", dbTransition.TransitionID,
			commitTxid)
	}

	// Reconstruct the transition from the durable record.
	eventRows, err := q.QuerySupplyUpdateEvents(
		ctx, sqlInt64(dbTransition.TransitionID),
	)
	if err != nil {
		return fmt.Errorf("unable to query update events: %w", err)
	}
	pendingUpdates := make(
		[]supplycommit.SupplyUpdateEvent, 0, len(eventRows),
	)
	for _, eventRow := range eventRows {
		event, err := deserializeSupplyUpdateEvent(
			eventRow.UpdateTypeName,
			bytes.NewReader(eventRow.EventData),
		)
		if err != nil {
			return fmt.Errorf("unable to deserialize update "+
				"event: %w", err)
		}
		pendingUpdates = append(pendingUpdates, event)
	}

	newCommitOpt, err := fetchCommitment(
		ctx, q, dbTransition.NewCommitmentID,
	)
	if err != nil {
		return fmt.Errorf("unable to fetch new commitment: %w", err)
	}
	newCommit, err := newCommitOpt.UnwrapOrErr(
		fmt.Errorf("commitment %d vanished mid-transaction",
			commitRow.CommitID),
	)
	if err != nil {
		return err
	}

	transition := supplycommit.SupplyStateTransition{
		PendingUpdates: pendingUpdates,
		NewCommitment:  newCommit,
		ChainProof:     lfn.Some(chainProof),
	}
	err = applyStateTransitionBody(
		ctx, q, assetSpec, groupKeyBytes, transition,
	)
	if err != nil {
		return fmt.Errorf("unable to apply transition: %w", err)
	}

	// Bind any updates that accumulated while the commitment awaited
	// burial, and park the machine row where a resuming machine will
	// pick them up.
	bound, err := bindDanglingUpdatesBody(ctx, q, groupKeyBytes)
	if err != nil {
		return fmt.Errorf("unable to bind dangling updates: %w", err)
	}
	if len(bound) > 0 {
		err := setSupplyStateMachineState(
			ctx, q, groupKeyBytes,
			&supplycommit.UpdatesPendingState{},
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// ApplyCommitTxStake persists the signed commitment transaction of the
// pending transition and moves the state-machine row to
// CommitBroadcastState, using the given transaction-scoped query set.
// This is the supply site's phase-1 write: it commits atomically with
// the anchoring registration that stakes the transition on the
// transaction, so no durable broadcast state can exist without its
// anchoring, nor an anchoring without the state it watches over.
func (s *SupplyCommitMachine) ApplyCommitTxStake(ctx context.Context,
	q *sqlc.Queries, assetSpec asset.Specifier,
	commitDetails supplycommit.SupplyCommitTxn) error {

	groupKey := assetSpec.UnwrapGroupKeyToPtr()
	if groupKey == nil {
		return ErrMissingGroupKey
	}

	return insertSignedCommitTxBody(
		ctx, q, schnorr.SerializePubKey(groupKey), commitDetails,
	)
}

// ApplyCommitAbandonment compensates a supply commitment the chain
// decided against with act-level finality: its inputs were claimed by
// a buried conflicting transaction, so the commitment can never
// confirm. The pending transition and its never-confirmed commitment
// row are removed, and the transition's updates return to the dangling
// pool, from which they are immediately rebound into a fresh pending
// transition so they re-enter the pipeline on the next cycle.
// Convergent: with no pending transition riding on the abandoned
// transaction, the call is a no-op.
func (s *SupplyCommitMachine) ApplyCommitAbandonment(ctx context.Context,
	q *sqlc.Queries, groupKey *btcec.PublicKey,
	commitTxid chainhash.Hash) error {

	groupKeyBytes := schnorr.SerializePubKey(groupKey)

	transitionRow, err := q.QueryPendingSupplyCommitTransition(
		ctx, groupKeyBytes,
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Nothing pending: the compensation already ran, or the
		// transition never reached signing.
		return nil

	case err != nil:
		return fmt.Errorf("unable to query pending transition: %w",
			err)
	}
	dbTransition := transitionRow.SupplyCommitTransition

	// Only compensate when the pending transition actually rides on
	// the abandoned transaction; a fresh transition created after a
	// prior compensation must not be touched.
	if !dbTransition.PendingCommitTxnID.Valid {
		return nil
	}
	chainTx, err := q.FetchChainTxByID(
		ctx, dbTransition.PendingCommitTxnID.Int64,
	)
	if err != nil {
		return fmt.Errorf("unable to fetch pending commit tx: %w",
			err)
	}
	var pendingTx wire.MsgTx
	err = pendingTx.Deserialize(bytes.NewReader(chainTx.RawTx))
	if err != nil {
		return fmt.Errorf("unable to deserialize pending commit "+
			"tx: %w", err)
	}
	if pendingTx.TxHash() != commitTxid {
		return nil
	}

	// Return the transition's updates to the dangling pool, then
	// remove the transition and its never-confirmed commitment.
	err = q.UnbindSupplyUpdateEvents(
		ctx, sqlInt64(dbTransition.TransitionID),
	)
	if err != nil {
		return fmt.Errorf("unable to unbind update events: %w", err)
	}
	err = q.DeleteSupplyCommitTransition(ctx, dbTransition.TransitionID)
	if err != nil {
		return fmt.Errorf("unable to delete transition: %w", err)
	}
	if dbTransition.NewCommitmentID.Valid {
		err = q.DeleteSupplyCommitment(
			ctx, dbTransition.NewCommitmentID.Int64,
		)
		if err != nil {
			return fmt.Errorf("unable to delete commitment: %w",
				err)
		}
	}

	// Rebind everything dangling — the abandoned transition's updates
	// plus anything that accumulated during the wait — so the supply
	// changes are recommitted by a future cycle rather than lost.
	bound, err := bindDanglingUpdatesBody(ctx, q, groupKeyBytes)
	if err != nil {
		return fmt.Errorf("unable to rebind updates: %w", err)
	}

	var nextState supplycommit.State = &supplycommit.DefaultState{}
	if len(bound) > 0 {
		nextState = &supplycommit.UpdatesPendingState{}
	}

	return setSupplyStateMachineState(ctx, q, groupKeyBytes, nextState)
}

// setSupplyStateMachineState writes the state-machine row's state name,
// leaving the latest commitment pointer untouched.
func setSupplyStateMachineState(ctx context.Context, q *sqlc.Queries,
	groupKeyBytes []byte, state supplycommit.State) error {

	stateName, err := stateToDBString(state)
	if err != nil {
		return err
	}
	_, err = q.UpsertSupplyCommitStateMachine(
		ctx, SupplyCommitMachineParams{
			GroupKey:  groupKeyBytes,
			StateName: sqlStr(stateName),
		},
	)
	if err != nil {
		return fmt.Errorf("unable to set state machine state: %w",
			err)
	}

	return nil
}

// FetchCommitmentPushData loads everything the push dispatcher needs
// about a finalized commitment from the durable record: the root
// commitment (with its chain-transaction context), the update events
// the finalized transition committed, and the chain proof written at
// finalization.
func (s *SupplyCommitMachine) FetchCommitmentPushData(ctx context.Context,
	groupKey *btcec.PublicKey, commitTxid chainhash.Hash) (
	supplycommit.RootCommitment, []supplycommit.SupplyUpdateEvent,
	supplycommit.ChainProof, error) {

	var (
		groupKeyBytes = schnorr.SerializePubKey(groupKey)
		commitment    supplycommit.RootCommitment
		updates       []supplycommit.SupplyUpdateEvent
		chainProof    supplycommit.ChainProof
	)

	readTx := ReadTxOption()
	err := s.db.ExecTx(ctx, readTx, func(db SupplyCommitStore) error {
		commitRow, err := db.QuerySupplyCommitmentByTxid(
			ctx, sqlc.QuerySupplyCommitmentByTxidParams{
				GroupKey: groupKeyBytes,
				Txid:     commitTxid[:],
			},
		)
		if err != nil {
			return fmt.Errorf("unable to query commitment for "+
				"tx %v: %w", commitTxid, err)
		}

		commitOpt, err := fetchCommitment(
			ctx, db, sqlInt64(commitRow.CommitID),
		)
		if err != nil {
			return fmt.Errorf("unable to fetch commitment: %w",
				err)
		}
		commit, err := commitOpt.UnwrapOrErr(
			fmt.Errorf("commitment %d vanished mid-transaction",
				commitRow.CommitID),
		)
		if err != nil {
			return err
		}
		commitment = commit

		// The chain proof is written exactly once, at finalization;
		// its absence means the push was dispatched for a commitment
		// that was never finalized.
		var haveProof bool
		commitment.CommitmentBlock.WhenSome(
			func(b supplycommit.CommitmentBlock) {
				if b.BlockHeader == nil ||
					b.MerkleProof == nil {

					return
				}
				chainProof = supplycommit.ChainProof{
					Header:      *b.BlockHeader,
					BlockHeight: b.Height,
					MerkleProof: *b.MerkleProof,
					TxIndex:     b.TxIndex,
				}
				haveProof = true
			},
		)
		if !haveProof {
			return fmt.Errorf("commitment %v has no chain proof",
				commitTxid)
		}

		transitionRow, err :=
			db.QuerySupplyCommitTransitionByNewCommitment(
				ctx, sqlInt64(commitRow.CommitID),
			)
		if err != nil {
			return fmt.Errorf("unable to query transition for "+
				"commitment %d: %w", commitRow.CommitID, err)
		}
		dbTransition := transitionRow.SupplyCommitTransition

		eventRows, err := db.QuerySupplyUpdateEvents(
			ctx, sqlInt64(dbTransition.TransitionID),
		)
		if err != nil {
			return fmt.Errorf("unable to query update events: "+
				"%w", err)
		}
		updates = make(
			[]supplycommit.SupplyUpdateEvent, 0, len(eventRows),
		)
		for _, eventRow := range eventRows {
			event, err := deserializeSupplyUpdateEvent(
				eventRow.UpdateTypeName,
				bytes.NewReader(eventRow.EventData),
			)
			if err != nil {
				return fmt.Errorf("unable to deserialize "+
					"update event: %w", err)
			}
			updates = append(updates, event)
		}

		return nil
	})
	if err != nil {
		return commitment, nil, chainProof, err
	}

	return commitment, updates, chainProof, nil
}

// A compile-time assertion that the supply-commit store provides the
// supply site's persistence surface.
var _ supplycommit.SupplyAnchoringLog = (*SupplyCommitMachine)(nil)
