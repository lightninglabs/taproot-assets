package tapdb

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/stretchr/testify/require"
)

// supplyAnchoringHarness extends the supply-commit harness with a raw
// query executor, mirroring how the re-org watcher's delivery
// transaction scopes site handlers around a bare *sqlc.Queries.
type supplyAnchoringHarness struct {
	*supplyCommitTestHarness
	executor *TransactionExecutor[*sqlc.Queries]
}

func newSupplyAnchoringHarness(t *testing.T) *supplyAnchoringHarness {
	h := newSupplyCommitTestHarness(t)
	executor := NewTransactionExecutor(
		h.baseDB, func(tx *sql.Tx) *sqlc.Queries {
			return h.baseDB.WithTx(tx)
		},
	)

	return &supplyAnchoringHarness{h, executor}
}

func (h *supplyAnchoringHarness) applyFinalize(commitTxid chainhash.Hash,
	chainProof supplycommit.ChainProof) error {

	return h.executor.ExecTx(
		h.ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return h.commitMachine.ApplyCommitFinalize(
				h.ctx, q, h.groupPubKey, commitTxid,
				chainProof,
			)
		},
	)
}

func (h *supplyAnchoringHarness) applyAbandonment(
	commitTxid chainhash.Hash) error {

	return h.executor.ExecTx(
		h.ctx, WriteTxOption(), func(q *sqlc.Queries) error {
			return h.commitMachine.ApplyCommitAbandonment(
				h.ctx, q, h.groupPubKey, commitTxid,
			)
		},
	)
}

// stageBroadcastTransition drives a transition to the broadcast point:
// pending updates inserted, transition frozen (as the machine does on
// the tick that starts a commitment cycle), signed commit transaction
// persisted. This is exactly the durable state a registered anchoring
// rides on while it awaits burial.
func (h *supplyAnchoringHarness) stageBroadcastTransition(
	updates []supplycommit.SupplyUpdateEvent) stateTransitionOutput {

	h.t.Helper()

	h.assertCurrentStateIs(&supplycommit.DefaultState{})
	for _, event := range updates {
		require.NoError(h.t, h.commitMachine.InsertPendingUpdate(
			h.ctx, h.assetSpec, event,
		))
	}
	h.assertCurrentStateIs(&supplycommit.UpdatesPendingState{})

	require.NoError(h.t, h.commitMachine.FreezePendingTransition(
		h.ctx, h.assetSpec,
	))

	commitTx := randTx(h.t, 1)
	internalKey, _ := test.RandKeyDesc(h.t)
	outputKey := test.RandPubKey(h.t)
	const outputIndex = 1
	require.NoError(h.t, h.commitMachine.InsertSignedCommitTx(
		h.ctx, h.assetSpec, supplycommit.SupplyCommitTxn{
			Txn:         commitTx,
			InternalKey: internalKey,
			OutputKey:   outputKey,
			OutputIndex: outputIndex,
		},
	))
	h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})

	chainProof := supplycommit.ChainProof{
		Header: wire.BlockHeader{
			Version:    int32(test.RandInt[uint32]()),
			PrevBlock:  test.RandHash(),
			MerkleRoot: test.RandHash(),
			Timestamp:  time.Unix(test.RandInt[int64](), 0),
			Bits:       test.RandInt[uint32](),
			Nonce:      test.RandInt[uint32](),
		},
		BlockHeight: 700,
		MerkleProof: proof.TxMerkleProof{
			Bits:  []bool{test.RandBool()},
			Nodes: []chainhash.Hash{test.RandHash()},
		},
		TxIndex: 1,
	}

	return stateTransitionOutput{
		appliedUpdates: updates,
		internalKey:    internalKey,
		outputKey:      outputKey,
		commitTx:       commitTx,
		chainProof:     chainProof,
		txOutIndex:     outputIndex,
	}
}

// TestSupplyAnchoringFinalize drives a transition to broadcast and
// finalizes it through the anchoring body, asserting the same end
// state the legacy ApplyStateTransition path produces (the shared
// assertion recomputes the expected supply root in memory), then
// re-applies to prove convergence.
func TestSupplyAnchoringFinalize(t *testing.T) {
	t.Parallel()

	h := newSupplyAnchoringHarness(t)
	updates := []supplycommit.SupplyUpdateEvent{
		h.randMintEvent(), h.randBurnEvent(), h.randIgnoreEvent(),
	}
	out := h.stageBroadcastTransition(updates)
	commitTxid := out.commitTx.TxHash()

	require.NoError(t, h.applyFinalize(commitTxid, out.chainProof))
	h.assertTransitionApplied(out)

	// A redelivered burial converges as a no-op: the end state is
	// byte-for-byte the same, and in particular the supply trees are
	// not re-applied.
	require.NoError(t, h.applyFinalize(commitTxid, out.chainProof))
	h.assertTransitionApplied(out)
}

// TestSupplyAnchoringFinalizeDangling asserts that updates arriving
// while the commitment awaits burial are bound into the next pending
// transition by the finalize body, with the state-machine row parked
// in UpdatesPendingState for a resuming machine.
func TestSupplyAnchoringFinalizeDangling(t *testing.T) {
	t.Parallel()

	h := newSupplyAnchoringHarness(t)
	updates := []supplycommit.SupplyUpdateEvent{h.randMintEvent()}
	out := h.stageBroadcastTransition(updates)
	commitTxid := out.commitTx.TxHash()

	// A supply update arriving mid-wait lands dangling: the pending
	// transition is frozen.
	danglingUpdate := h.randIgnoreEvent()
	require.NoError(t, h.commitMachine.InsertPendingUpdate(
		h.ctx, h.assetSpec, danglingUpdate,
	))
	require.Len(t, h.fetchDanglingUpdates(), 1)
	h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})

	require.NoError(t, h.applyFinalize(commitTxid, out.chainProof))

	// The dangling update now rides a fresh pending transition whose
	// old commitment is the one just finalized, and the machine row
	// waits in UpdatesPendingState.
	h.assertCurrentStateIs(&supplycommit.UpdatesPendingState{})
	require.Len(t, h.fetchDanglingUpdates(), 0)
	h.assertPendingUpdates(
		[]supplycommit.SupplyUpdateEvent{danglingUpdate},
	)

	transition := h.assertPendingTransitionExists()
	stateMachine, err := h.fetchStateMachine()
	require.NoError(t, err)
	require.True(t, stateMachine.LatestCommitmentID.Valid)
	require.Equal(
		t, stateMachine.LatestCommitmentID, transition.OldCommitmentID,
	)
}

// TestSupplyAnchoringAbandonment asserts the compensation for a
// commitment the chain decided against: the dead transition and its
// never-confirmed commitment row are removed, and the updates re-enter
// the pipeline through a fresh pending transition.
func TestSupplyAnchoringAbandonment(t *testing.T) {
	t.Parallel()

	h := newSupplyAnchoringHarness(t)
	updates := []supplycommit.SupplyUpdateEvent{
		h.randMintEvent(), h.randBurnEvent(),
	}
	out := h.stageBroadcastTransition(updates)
	commitTxid := out.commitTx.TxHash()

	require.NoError(t, h.applyAbandonment(commitTxid))

	// The commitment row is gone.
	_, err := h.db.QuerySupplyCommitmentByTxid(
		h.ctx, sqlc.QuerySupplyCommitmentByTxidParams{
			GroupKey: h.groupKeyBytes,
			Txid:     commitTxid[:],
		},
	)
	require.ErrorIs(t, err, sql.ErrNoRows)

	// The updates were rebound into a fresh transition with no
	// commitment or transaction attached, and the machine row waits
	// in UpdatesPendingState, ready for the next cycle.
	h.assertCurrentStateIs(&supplycommit.UpdatesPendingState{})
	transition := h.assertPendingTransitionExists()
	require.False(t, transition.PendingCommitTxnID.Valid)
	require.False(t, transition.NewCommitmentID.Valid)
	require.False(t, transition.Frozen)
	h.assertPendingUpdates(updates)

	// A redelivered abandonment is a no-op: the fresh transition does
	// not ride the abandoned transaction.
	require.NoError(t, h.applyAbandonment(commitTxid))
	afterRedelivery := h.assertPendingTransitionExists()
	require.Equal(
		t, transition.TransitionID, afterRedelivery.TransitionID,
	)
}

// TestSupplyAnchoringStake asserts the signing step's stake: the signed
// commitment transaction is persisted by the phase-1 write of the
// anchoring registration, so the broadcast state and the anchoring
// commit together — and a phase-1 write that fails leaves neither.
func TestSupplyAnchoringStake(t *testing.T) {
	t.Parallel()

	h := newSupplyAnchoringHarness(t)
	registry := NewReorgRegistryStore(
		h.executor, clock.NewTestClock(time.Unix(1_000_000, 0)),
	)

	// Drive the transition to the point of signing: updates pending
	// and the transition frozen, with no commitment transaction yet.
	require.NoError(t, h.commitMachine.InsertPendingUpdate(
		h.ctx, h.assetSpec, h.randMintEvent(),
	))
	require.NoError(t, h.commitMachine.FreezePendingTransition(
		h.ctx, h.assetSpec,
	))
	h.assertCurrentStateIs(&supplycommit.UpdatesPendingState{})

	commitTx := randTx(t, 1)
	commitTxid := commitTx.TxHash()
	internalKey, _ := test.RandKeyDesc(t)
	details := supplycommit.SupplyCommitTxn{
		Txn:         commitTx,
		InternalKey: internalKey,
		OutputKey:   test.RandPubKey(t),
		OutputIndex: 0,
	}

	p2trScript := append([]byte{0x51, 0x20}, test.RandBytes(32)...)
	triggers, err := tapreorg.NewTriggerSet([]tapreorg.TriggerOutPoint{{
		OutPoint:   commitTx.TxIn[0].PreviousOutPoint,
		PkScript:   p2trScript,
		HeightHint: 1,
	}})
	require.NoError(t, err)
	blob := tapreorg.VersionedBlob{Version: 1, Data: commitTxid[:]}
	spec := tapreorg.RegistrationSpec{
		Site:      supplycommit.SupplySiteID,
		Triggers:  triggers,
		MatchData: blob,
		Payload:   blob,
		MatchKey:  commitTxid.CloneBytes(),
		Threshold: 3,
	}
	lookup := func() *tapreorg.Anchoring {
		anchoring, err := registry.LookupByMatchKey(
			h.ctx, supplycommit.SupplySiteID,
			commitTxid.CloneBytes(),
		)
		require.NoError(t, err)

		return anchoring
	}

	// A phase-1 write that fails after the stake body has run rolls
	// the whole registration back: no anchoring, and the record still
	// waits to be signed.
	stakeErr := errors.New("stake refused")
	_, err = registry.Register(
		h.ctx, spec, 100, func(ctx context.Context,
			tx tapreorg.RegistryTx, _ tapreorg.AnchoringID) error {

			err := h.commitMachine.ApplyCommitTxStake(
				ctx, tx.Queries(), h.assetSpec, details,
			)
			require.NoError(t, err)

			return stakeErr
		}, nil,
	)
	require.ErrorIs(t, err, stakeErr)

	require.Nil(t, lookup())
	h.assertCurrentStateIs(&supplycommit.UpdatesPendingState{})
	transition := h.assertPendingTransitionExists()
	require.False(t, transition.PendingCommitTxnID.Valid)
	require.False(t, transition.NewCommitmentID.Valid)

	// The stake and the registration commit together.
	id, err := registry.Register(
		h.ctx, spec, 100, func(ctx context.Context,
			tx tapreorg.RegistryTx, _ tapreorg.AnchoringID) error {

			return h.commitMachine.ApplyCommitTxStake(
				ctx, tx.Queries(), h.assetSpec, details,
			)
		}, nil,
	)
	require.NoError(t, err)

	anchoring := lookup()
	require.NotNil(t, anchoring)
	require.Equal(t, id, anchoring.ID)
	h.assertCurrentStateIs(&supplycommit.CommitBroadcastState{})
	transition = h.assertPendingTransitionExists()
	require.True(t, transition.PendingCommitTxnID.Valid)
	require.True(t, transition.NewCommitmentID.Valid)
	_, err = h.db.QuerySupplyCommitmentByTxid(
		h.ctx, sqlc.QuerySupplyCommitmentByTxidParams{
			GroupKey: h.groupKeyBytes,
			Txid:     commitTxid[:],
		},
	)
	require.NoError(t, err)
}

// TestSupplyAnchoringPushData asserts that the push dispatcher's fetch
// rebuilds the finalized commitment, its update events and its chain
// proof from the durable record alone.
func TestSupplyAnchoringPushData(t *testing.T) {
	t.Parallel()

	h := newSupplyAnchoringHarness(t)
	updates := []supplycommit.SupplyUpdateEvent{
		h.randMintEvent(), h.randIgnoreEvent(),
	}
	out := h.stageBroadcastTransition(updates)
	commitTxid := out.commitTx.TxHash()

	// Before finalization there is no chain proof to push.
	_, _, _, err := h.commitMachine.FetchCommitmentPushData(
		h.ctx, h.groupPubKey, commitTxid,
	)
	require.ErrorContains(t, err, "no chain proof")

	require.NoError(t, h.applyFinalize(commitTxid, out.chainProof))

	commitment, events, chainProof, err :=
		h.commitMachine.FetchCommitmentPushData(
			h.ctx, h.groupPubKey, commitTxid,
		)
	require.NoError(t, err)

	require.Equal(t, commitTxid, commitment.Txn.TxHash())
	require.Equal(
		t, out.outputKey.SerializeCompressed(),
		commitment.OutputKey.SerializeCompressed(),
	)
	require.NotNil(t, commitment.SupplyRoot)

	require.Equal(
		t, out.chainProof.Header.BlockHash(),
		chainProof.Header.BlockHash(),
	)
	require.Equal(
		t, out.chainProof.BlockHeight, chainProof.BlockHeight,
	)

	require.Len(t, events, len(updates))
	_, err = supplycommit.NewSupplyLeavesFromEvents(events)
	require.NoError(t, err)
}
