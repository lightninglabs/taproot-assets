package supplycommit

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/stretchr/testify/require"
)

// recordingSupplyLog counts the persistence calls each handler makes,
// and records the arguments the site derived from its payload and
// witness.
type recordingSupplyLog struct {
	finalizes   int
	abandonment int

	lastTxid     chainhash.Hash
	lastGroupKey *btcec.PublicKey
	lastProof    ChainProof
}

func (l *recordingSupplyLog) ApplyCommitFinalize(_ context.Context,
	_ *sqlc.Queries, groupKey *btcec.PublicKey,
	commitTxid chainhash.Hash, chainProof ChainProof) error {

	l.finalizes++
	l.lastTxid = commitTxid
	l.lastGroupKey = groupKey
	l.lastProof = chainProof

	return nil
}

func (l *recordingSupplyLog) ApplyCommitAbandonment(_ context.Context,
	_ *sqlc.Queries, groupKey *btcec.PublicKey,
	commitTxid chainhash.Hash) error {

	l.abandonment++
	l.lastTxid = commitTxid
	l.lastGroupKey = groupKey

	return nil
}

func (l *recordingSupplyLog) FetchCommitmentPushData(_ context.Context,
	_ *btcec.PublicKey, _ chainhash.Hash) (RootCommitment,
	[]SupplyUpdateEvent, ChainProof, error) {

	return RootCommitment{}, nil, ChainProof{}, nil
}

// recordingSupplyTx is a RegistryTx that records enqueued effects.
type recordingSupplyTx struct {
	effects []tapreorg.OutboxEffect
}

func (r *recordingSupplyTx) Queries() *sqlc.Queries {
	return nil
}

func (r *recordingSupplyTx) EnqueueEffect(_ context.Context,
	effect tapreorg.OutboxEffect) error {

	r.effects = append(r.effects, effect)

	return nil
}

// TestSupplySiteActGating pins the supply site's act-gating contract.
//
// This is the site that most needs it. Its burial handler is the only
// one on the branch whose effect crosses a trust boundary: it pushes
// the finalized commitment to remote universes, where the code's own
// reasoning notes that receivers cannot retract a predecessor once
// they hold it. Everything below burial must therefore leave both the
// durable supply trees and the outbox untouched, so that a
// re-organization above the act threshold costs nothing externally.
//
// The mint and porter sites already assert this shape. The supply
// site had no handler-level test at all.
func TestSupplySiteActGating(t *testing.T) {
	t.Parallel()

	commitTx := wire.NewMsgTx(2)
	commitTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	commitTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51}))

	groupKey := test.RandPubKey(t)

	var blob supplyBlob
	blob.CommitTxid = commitTx.TxHash()
	copy(blob.GroupKey[:], groupKey.SerializeCompressed())
	payload := encodeSupplyBlob(blob)

	witness, err := tapreorg.NewWitness(
		commitTx, chainhash.Hash{0xbb}, 700, 3,
	)
	require.NoError(t, err)

	header := &wire.BlockHeader{Nonce: 1}
	anchoring := &tapreorg.Anchoring{
		ID:      11,
		Site:    SupplySiteID,
		Payload: payload,
		Spends: []tapreorg.CandidateSpend{{
			Verdict:     tapreorg.VerdictSatisfies,
			W:           witness,
			OnChain:     true,
			BlockHeader: header,
			MerkleProof: &proof.TxMerkleProof{},
		}},
	}

	log := &recordingSupplyLog{}
	site := &SupplySite{Log: log}
	ctx := context.Background()
	tx := &recordingSupplyTx{}

	// The potency tier persists nothing and emits nothing. A
	// commitment that is witnessed, then lost, then conflicted has
	// not yet cost the group anything a re-org could not undo.
	anchoring.Phase = tapreorg.Witnessed{W: witness}
	require.NoError(t, site.OnWitnessed(ctx, tx, anchoring))

	anchoring.Phase = tapreorg.Unwitnessed{}
	require.NoError(t, site.OnUnwitnessed(ctx, tx, anchoring))

	anchoring.Phase = tapreorg.Conflicted{}
	require.NoError(t, site.OnConflicted(ctx, tx, anchoring))

	require.Zero(t, log.finalizes, "finalized before burial")
	require.Zero(t, log.abandonment, "compensated at the potency tier")
	require.Empty(t, tx.effects, "emitted before burial")

	// Burial finalizes in this delivery transaction and enqueues
	// exactly one push effect, carrying the anchoring's own payload
	// so the dispatcher can rebuild from durable state.
	anchoring.Phase = tapreorg.Buried{W: witness}
	require.NoError(t, site.OnBuried(ctx, tx, anchoring))

	require.Equal(t, 1, log.finalizes)
	require.Equal(t, blob.CommitTxid, log.lastTxid)
	require.True(t, groupKey.IsEqual(log.lastGroupKey))
	require.Len(t, tx.effects, 1)
	require.Equal(t, CommitPushEffectKind, tx.effects[0].Kind)
	require.Equal(t, anchoring.ID, tx.effects[0].Anchoring.UnwrapOr(0))
	require.Equal(t, payload, tx.effects[0].Payload)

	// The chain proof handed to finalization comes from the
	// anchoring's enriched witness, not from anything the caller
	// supplied — this is what a re-confirmation refreshes.
	require.Equal(t, *header, log.lastProof.Header)
	require.EqualValues(t, 700, log.lastProof.BlockHeight)
	require.EqualValues(t, 3, log.lastProof.TxIndex)

	// Burial is convergent: a coalesced redelivery re-finalizes
	// (the log body is a no-op once chain details exist) and
	// re-enqueues rather than silently skipping, so the outbox
	// remains the single source of delivery.
	require.NoError(t, site.OnBuried(ctx, tx, anchoring))
	require.Equal(t, 2, log.finalizes)
	require.Len(t, tx.effects, 2)

	// Abandonment compensates locally and emits exactly one nudge,
	// addressed to the group, so the resting machine adopts the
	// rebound updates and starts the next cycle unattended. The push,
	// if it ever went out, is the outbox's to reconcile.
	before := len(tx.effects)
	anchoring.Phase = tapreorg.Abandoned{}
	require.NoError(t, site.OnAbandoned(ctx, tx, anchoring))
	require.Equal(t, 1, log.abandonment)
	require.Equal(t, blob.CommitTxid, log.lastTxid)
	require.Len(t, tx.effects, before+1)

	nudge := tx.effects[before]
	require.Equal(t, CommitNudgeEffectKind, nudge.Kind)
	require.Equal(t, anchoring.ID, nudge.Anchoring.UnwrapOr(0))
	decoded, err := decodeNudgeBlob(nudge.Payload)
	require.NoError(t, err)
	require.Equal(t, blob.GroupKey, decoded.GroupKey)
}
