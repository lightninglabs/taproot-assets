package universe

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

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

// hangingRegistrar stands in for a federation member that accepts every
// push and never answers: each upsert blocks until its context ends.
type hangingRegistrar struct {
	mu       sync.Mutex
	attempts int
}

func (r *hangingRegistrar) UpsertProofLeaf(ctx context.Context, _ Identifier,
	_ LeafKey, _ *Leaf) (*Proof, error) {

	r.mu.Lock()
	r.attempts++
	r.mu.Unlock()

	<-ctx.Done()

	return nil, ctx.Err()
}

func (r *hangingRegistrar) Close() error { return nil }

func (r *hangingRegistrar) numAttempts() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.attempts
}

// newStuckMemberEnvoy wires an envoy whose federation has one member
// that never answers and one that records what it receives, with the
// per-push deadline shortened to keep the test quick.
func newStuckMemberEnvoy(stuck *hangingRegistrar,
	live *recordingRegistrar) *FederationEnvoy {

	stuckAddr := NewServerAddr(1, "stuck:10029")
	liveAddr := NewServerAddr(2, "live:10029")
	envoy := NewFederationEnvoy(FederationConfig{
		LocalRegistrar: &errRegistrar{},
		FederationDB: &staticServerDB{
			servers: []ServerAddr{stuckAddr, liveAddr},
		},
		NewRemoteRegistrar: func(addr ServerAddr) (Registrar, error) {
			if addr.HostStr() == stuckAddr.HostStr() {
				return stuck, nil
			}

			return live, nil
		},
	})
	envoy.DefaultTimeout = 50 * time.Millisecond

	return envoy
}

// TestFederationPushStuckMember asserts that a federation member which
// accepts pushes and never answers costs the envoy a bounded wait: every
// push carries its own deadline, and a batch drops the member after the
// first expired push instead of paying the deadline once per leaf. The
// healthy member receives everything either way.
func TestFederationPushStuckMember(t *testing.T) {
	t.Parallel()

	t.Run("batch", func(t *testing.T) {
		t.Parallel()

		stuck, live := &hangingRegistrar{}, &recordingRegistrar{}
		envoy := newStuckMemberEnvoy(stuck, live)

		const numLeaves = 4
		batch := make([]*Item, numLeaves)
		for i := range batch {
			batch[i] = &Item{
				ID:   randIdentifier(),
				Key:  BaseLeafKey{},
				Leaf: &Leaf{},
			}
		}
		pushReq := &FederationProofBatchPushReq{
			Batch: batch,
			resp:  make(chan struct{}, 1),
			err:   make(chan error, 1),
		}

		start := time.Now()
		require.NoError(t, envoy.handleBatchPushRequest(pushReq))
		require.Less(t, time.Since(start), time.Second)
		require.Equal(
			t, 1, stuck.numAttempts(),
			"batch kept pushing to a member that missed a deadline",
		)
		require.Equal(t, numLeaves, live.numPushed())
	})

	t.Run("single", func(t *testing.T) {
		t.Parallel()

		stuck, live := &hangingRegistrar{}, &recordingRegistrar{}
		envoy := newStuckMemberEnvoy(stuck, live)

		pushReq := &FederationPushReq{
			ID:   randIdentifier(),
			Key:  BaseLeafKey{},
			Leaf: &Leaf{},
			resp: make(chan *Proof, 1),
			err:  make(chan error, 1),
		}

		start := time.Now()
		require.NoError(t, envoy.handlePushRequest(pushReq))
		require.Less(t, time.Since(start), time.Second)
		require.Equal(t, 1, stuck.numAttempts())
		require.Equal(t, 1, live.numPushed())
	})
}
