package universe

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// errRegistrar is a BatchRegistrar whose upserts return the configured
// error without storing anything.
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

func (r *errRegistrar) Close() error { return nil }

// recordingRegistrar records every proof leaf pushed to it, standing
// in for a remote federation server.
type recordingRegistrar struct {
	mu   sync.Mutex
	keys []LeafKey
}

func (r *recordingRegistrar) UpsertProofLeaf(_ context.Context,
	_ Identifier, key LeafKey, _ *Leaf) (*Proof, error) {

	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = append(r.keys, key)

	return &Proof{}, nil
}

func (r *recordingRegistrar) Close() error { return nil }

func (r *recordingRegistrar) numPushed() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.keys)
}

// staticServerDB serves a fixed federation server list; every other
// FederationDB method panics via the embedded nil interface.
type staticServerDB struct {
	FederationDB

	servers []ServerAddr
}

func (s *staticServerDB) UniverseServers(
	context.Context) ([]ServerAddr, error) {

	return s.servers, nil
}

// newTestEnvoy wires a federation envoy whose local registrar is the
// given mock and whose single federation server records what is
// pushed to it. The envoy is not started; tests drive the push
// handlers directly.
func newTestEnvoy(local BatchRegistrar,
	remote *recordingRegistrar) *FederationEnvoy {

	return NewFederationEnvoy(FederationConfig{
		LocalRegistrar: local,
		FederationDB: &staticServerDB{
			servers: []ServerAddr{
				NewServerAddr(1, "test-server:10029"),
			},
		},
		NewRemoteRegistrar: func(ServerAddr) (Registrar, error) {
			return remote, nil
		},
	})
}

// TestFederationPushPendingMultiverse asserts the push handlers honour
// the weakened upsert contract: an error wrapping ErrMultiversePending
// means the leaves are durably stored, so the federation push must
// still run — skipping it would strand the proofs local-only — while
// the caller receives the typed error. Any other upsert error must
// abort the push.
func TestFederationPushPendingMultiverse(t *testing.T) {
	t.Parallel()

	pendingErr := fmt.Errorf("upsert: %w", ErrMultiversePending)
	hardErr := errors.New("database exploded")

	newBatch := func(n int) []*Item {
		items := make([]*Item, n)
		for i := range items {
			items[i] = &Item{
				ID:   randIdentifier(),
				Key:  BaseLeafKey{},
				Leaf: &Leaf{},
			}
		}

		return items
	}

	t.Run("single_pending_pushes", func(t *testing.T) {
		t.Parallel()

		remote := &recordingRegistrar{}
		envoy := newTestEnvoy(&errRegistrar{err: pendingErr}, remote)

		pushReq := &FederationPushReq{
			ID:   randIdentifier(),
			Key:  BaseLeafKey{},
			Leaf: &Leaf{},
			resp: make(chan *Proof, 1),
			err:  make(chan error, 1),
		}
		require.NoError(t, envoy.handlePushRequest(pushReq))

		// The caller must see the typed error, and the proof must
		// have been pushed to the federation server regardless.
		select {
		case err := <-pushReq.err:
			require.ErrorIs(t, err, ErrMultiversePending)
		default:
			t.Fatal("caller was not served the pending error")
		}
		require.Equal(t, 1, remote.numPushed())
	})

	t.Run("batch_pending_pushes", func(t *testing.T) {
		t.Parallel()

		remote := &recordingRegistrar{}
		envoy := newTestEnvoy(&errRegistrar{err: pendingErr}, remote)

		batch := newBatch(3)
		pushReq := &FederationProofBatchPushReq{
			Batch: batch,
			resp:  make(chan struct{}, 1),
			err:   make(chan error, 1),
		}
		require.NoError(t, envoy.handleBatchPushRequest(pushReq))

		// The caller must see the typed error, and every leaf of
		// the batch must have been pushed regardless.
		select {
		case err := <-pushReq.err:
			require.ErrorIs(t, err, ErrMultiversePending)
		default:
			t.Fatal("caller was not served the pending error")
		}
		require.Equal(t, len(batch), remote.numPushed())
	})

	t.Run("single_hard_error_aborts", func(t *testing.T) {
		t.Parallel()

		remote := &recordingRegistrar{}
		envoy := newTestEnvoy(&errRegistrar{err: hardErr}, remote)

		pushReq := &FederationPushReq{
			ID:   randIdentifier(),
			Key:  BaseLeafKey{},
			Leaf: &Leaf{},
			resp: make(chan *Proof, 1),
			err:  make(chan error, 1),
		}
		require.ErrorIs(t, envoy.handlePushRequest(pushReq), hardErr)

		select {
		case err := <-pushReq.err:
			require.ErrorIs(t, err, hardErr)
		default:
			t.Fatal("caller was not served the upsert error")
		}
		require.Zero(t, remote.numPushed())
	})

	t.Run("batch_hard_error_aborts", func(t *testing.T) {
		t.Parallel()

		remote := &recordingRegistrar{}
		envoy := newTestEnvoy(&errRegistrar{err: hardErr}, remote)

		pushReq := &FederationProofBatchPushReq{
			Batch: newBatch(3),
			resp:  make(chan struct{}, 1),
			err:   make(chan error, 1),
		}
		require.ErrorIs(
			t, envoy.handleBatchPushRequest(pushReq), hardErr,
		)

		select {
		case err := <-pushReq.err:
			require.ErrorIs(t, err, hardErr)
		default:
			t.Fatal("caller was not served the upsert error")
		}
		require.Zero(t, remote.numPushed())
	})
}
