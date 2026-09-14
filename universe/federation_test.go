package universe

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// errRegistrar is a BatchRegistrar whose upserts return the configured error
// without storing anything.
type errRegistrar struct {
	err error
}

func (r *errRegistrar) UpsertProofLeaf(context.Context, Identifier,
	LeafKey, *Leaf) (*Proof, error) {

	return nil, r.err
}

func (r *errRegistrar) UpsertProofLeafBatch(context.Context,
	[]*Item) error {

	return r.err
}

func (r *errRegistrar) Close() error {
	return nil
}

// TestFederationPushPendingMultiverse asserts the weakened local upsert
// contract: ErrMultiversePending means the leaf is durable, so federation work
// is still queued while the caller receives the typed error. Other local
// upsert errors must not enqueue remote work.
func TestFederationPushPendingMultiverse(t *testing.T) {
	t.Parallel()

	pendingErr := fmt.Errorf("upsert: %w", ErrMultiversePending)
	hardErr := errors.New("database exploded")

	newItem := func(index uint32) *Item {
		return &Item{
			ID:           issuanceID(),
			Key:          leafKey(index),
			Leaf:         &Leaf{},
			LogProofSync: true,
		}
	}

	t.Run("single_pending_queues_push", func(t *testing.T) {
		t.Parallel()

		db := newPusherTestDB()
		envoy := NewFederationEnvoy(FederationConfig{
			LocalRegistrar: &errRegistrar{err: pendingErr},
			FederationDB:   db,
		})

		_, err := envoy.UpsertProofLeaf(
			context.Background(), issuanceID(), leafKey(1), &Leaf{},
		)
		require.ErrorIs(t, err, ErrMultiversePending)
		require.Len(t, db.pending(), 1)
	})

	t.Run("batch_pending_queues_pushes", func(t *testing.T) {
		t.Parallel()

		db := newPusherTestDB()
		envoy := NewFederationEnvoy(FederationConfig{
			LocalRegistrar: &errRegistrar{err: pendingErr},
			FederationDB:   db,
		})

		items := []*Item{
			newItem(1),
			newItem(2),
			newItem(3),
		}
		err := envoy.UpsertProofLeafBatch(context.Background(), items)
		require.ErrorIs(t, err, ErrMultiversePending)
		require.Len(t, db.pending(), len(items))
	})

	t.Run("single_hard_error_aborts", func(t *testing.T) {
		t.Parallel()

		db := newPusherTestDB()
		envoy := NewFederationEnvoy(FederationConfig{
			LocalRegistrar: &errRegistrar{err: hardErr},
			FederationDB:   db,
		})

		_, err := envoy.UpsertProofLeaf(
			context.Background(), issuanceID(), leafKey(1), &Leaf{},
		)
		require.ErrorIs(t, err, hardErr)
		require.Empty(t, db.pending())
	})

	t.Run("batch_hard_error_aborts", func(t *testing.T) {
		t.Parallel()

		db := newPusherTestDB()
		envoy := NewFederationEnvoy(FederationConfig{
			LocalRegistrar: &errRegistrar{err: hardErr},
			FederationDB:   db,
		})

		err := envoy.UpsertProofLeafBatch(context.Background(), []*Item{
			newItem(1), newItem(2), newItem(3),
		})
		require.ErrorIs(t, err, hardErr)
		require.Empty(t, db.pending())
	})
}
