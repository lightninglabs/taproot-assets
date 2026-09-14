package universe

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

type pusherTestDB struct {
	FederationDB

	mu      sync.Mutex
	servers []ServerAddr
	entries map[string]*ProofSyncLogEntry
	order   []string
}

func newPusherTestDB() *pusherTestDB {
	return &pusherTestDB{
		servers: []ServerAddr{
			NewServerAddr(1, "test-server:10029"),
		},
		entries: make(map[string]*ProofSyncLogEntry),
	}
}

func proofPushKey(id Identifier, key LeafKey, addr ServerAddr) string {
	outpoint := key.LeafOutPoint()
	return fmt.Sprintf(
		"%s/%s/%s/%d", id.String(), addr.HostStr(),
		outpoint.Hash.String(), outpoint.Index,
	)
}

func (d *pusherTestDB) UniverseServers(
	context.Context) ([]ServerAddr, error) {

	d.mu.Lock()
	defer d.mu.Unlock()

	return append([]ServerAddr(nil), d.servers...), nil
}

func (d *pusherTestDB) QueryFederationProofSyncLog(_ context.Context,
	id Identifier, key LeafKey, _ SyncDirection,
	status ProofSyncStatus) ([]*ProofSyncLogEntry, error) {

	d.mu.Lock()
	defer d.mu.Unlock()

	var result []*ProofSyncLogEntry
	for _, addr := range d.servers {
		entry, ok := d.entries[proofPushKey(id, key, addr)]
		if !ok || entry.SyncStatus != status {
			continue
		}

		copyEntry := *entry
		result = append(result, &copyEntry)
	}

	return result, nil
}

func (d *pusherTestDB) UpsertFederationProofSyncLog(_ context.Context,
	id Identifier, key LeafKey, addr ServerAddr, direction SyncDirection,
	status ProofSyncStatus, bump bool) (int64, error) {

	d.mu.Lock()
	defer d.mu.Unlock()

	mapKey := proofPushKey(id, key, addr)
	entry, ok := d.entries[mapKey]
	if !ok {
		entry = &ProofSyncLogEntry{
			SyncDirection: direction,
			ServerAddr:    addr,
			UniID:         id,
			LeafKey:       key,
			Leaf:          Leaf{},
		}
		d.entries[mapKey] = entry
		d.order = append(d.order, mapKey)
	}

	entry.SyncStatus = status
	if bump {
		entry.AttemptCounter++
	}

	return int64(len(d.order)), nil
}

func (d *pusherTestDB) pending() []*ProofSyncLogEntry {
	d.mu.Lock()
	defer d.mu.Unlock()

	result := make([]*ProofSyncLogEntry, 0, len(d.order))
	for _, mapKey := range d.order {
		entry := d.entries[mapKey]
		if entry.SyncStatus != ProofSyncStatusPending {
			continue
		}

		copyEntry := *entry
		result = append(result, &copyEntry)
	}

	return result
}

func (d *pusherTestDB) FetchPendingProofsSyncLog(
	context.Context, *SyncDirection) ([]*ProofSyncLogEntry, error) {

	return d.pending(), nil
}

func (d *pusherTestDB) FetchPendingProofsSyncLogFIFO(
	context.Context, *SyncDirection) ([]*ProofSyncLogEntry, error) {

	return d.pending(), nil
}

type queueErrorDB struct {
	FederationDB
	err error
}

func (d *queueErrorDB) UniverseServers(
	context.Context) ([]ServerAddr, error) {

	return nil, d.err
}

type contextRegistrar struct{}

func (*contextRegistrar) UpsertProofLeaf(ctx context.Context, _ Identifier,
	_ LeafKey, _ *Leaf) (*Proof, error) {

	<-ctx.Done()
	return nil, ctx.Err()
}

func (*contextRegistrar) UpsertProofLeafBatch(ctx context.Context,
	_ []*Item) error {

	<-ctx.Done()
	return ctx.Err()
}

func (*contextRegistrar) Close() error {
	return nil
}

type successfulRegistrar struct{}

func (*successfulRegistrar) UpsertProofLeaf(context.Context, Identifier,
	LeafKey, *Leaf) (*Proof, error) {

	return &Proof{}, nil
}

func (*successfulRegistrar) UpsertProofLeafBatch(context.Context,
	[]*Item) error {

	return nil
}

func (*successfulRegistrar) Close() error {
	return nil
}

type blockingRegistrar struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (r *blockingRegistrar) UpsertProofLeaf(ctx context.Context, _ Identifier,
	_ LeafKey, _ *Leaf) (*Proof, error) {

	r.once.Do(func() {
		close(r.entered)
	})

	select {
	case <-r.release:
		return &Proof{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (*blockingRegistrar) Close() error {
	return nil
}

type orderedFailRegistrar struct {
	mu        sync.Mutex
	attempts  []uint32
	failIndex uint32
}

func (r *orderedFailRegistrar) UpsertProofLeaf(_ context.Context,
	_ Identifier, key LeafKey, _ *Leaf) (*Proof, error) {

	index := key.LeafOutPoint().Index

	r.mu.Lock()
	r.attempts = append(r.attempts, index)
	r.mu.Unlock()

	if r.failIndex != 0 && index == r.failIndex {
		return nil, errors.New("configured push failure")
	}

	return &Proof{}, nil
}

func (*orderedFailRegistrar) Close() error {
	return nil
}

func (r *orderedFailRegistrar) pushed() []uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]uint32(nil), r.attempts...)
}

func issuanceID() Identifier {
	id := randIdentifier()
	id.ProofType = ProofTypeIssuance
	return id
}

func leafKey(index uint32) BaseLeafKey {
	return BaseLeafKey{
		OutPoint: wire.OutPoint{Index: index},
	}
}

func TestFederationUpsertUsesCallerContext(t *testing.T) {
	t.Parallel()

	envoy := NewFederationEnvoy(FederationConfig{
		LocalRegistrar: &contextRegistrar{},
		FederationDB:   newPusherTestDB(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := envoy.UpsertProofLeaf(
		ctx, issuanceID(), leafKey(1), &Leaf{},
	)
	require.ErrorIs(t, err, context.Canceled)

	err = envoy.UpsertProofLeafBatch(ctx, []*Item{
		{
			ID:           issuanceID(),
			Key:          leafKey(2),
			Leaf:         &Leaf{},
			LogProofSync: true,
		},
	})
	require.ErrorIs(t, err, context.Canceled)
}

func TestFederationQueueFailureRemainsBestEffort(t *testing.T) {
	t.Parallel()

	queueErr := errors.New("federation database unavailable")
	envoy := NewFederationEnvoy(FederationConfig{
		LocalRegistrar: &successfulRegistrar{},
		FederationDB: &queueErrorDB{
			err: queueErr,
		},
	})

	_, err := envoy.UpsertProofLeaf(
		context.Background(), issuanceID(), leafKey(1), &Leaf{},
	)
	require.NoError(t, err)

	err = envoy.UpsertProofLeafBatch(context.Background(), []*Item{
		{
			ID:           issuanceID(),
			Key:          leafKey(2),
			Leaf:         &Leaf{},
			LogProofSync: true,
		},
	})
	require.NoError(t, err)
}

func TestFederationSlowPushDoesNotBlockLocalUpsert(t *testing.T) {
	t.Parallel()

	db := newPusherTestDB()
	remote := &blockingRegistrar{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	envoy := NewFederationEnvoy(FederationConfig{
		LocalRegistrar: &successfulRegistrar{},
		FederationDB:   db,
		SyncInterval:   time.Minute,
		NewRemoteRegistrar: func(ServerAddr) (Registrar, error) {
			return remote, nil
		},
	})

	envoy.Wg.Add(1)
	go envoy.pusher()
	defer envoy.Stop()

	_, err := envoy.UpsertProofLeaf(
		context.Background(), issuanceID(), leafKey(1), &Leaf{},
	)
	require.NoError(t, err)

	select {
	case <-remote.entered:
	case <-time.After(time.Second):
		t.Fatal("remote federation push did not start")
	}

	secondDone := make(chan error, 1)
	go func() {
		_, err := envoy.UpsertProofLeaf(
			context.Background(), issuanceID(), leafKey(2), &Leaf{},
		)
		secondDone <- err
	}()

	select {
	case err := <-secondDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("local upsert blocked behind remote federation push")
	}

	close(remote.release)
}

func TestFederationPusherPreservesPerServerFIFO(t *testing.T) {
	t.Parallel()

	db := newPusherTestDB()
	blockedServer := NewServerAddr(1, "blocked-server:10029")
	healthyServer := NewServerAddr(2, "healthy-server:10029")
	db.servers = []ServerAddr{blockedServer, healthyServer}

	id := issuanceID()
	for idx := uint32(1); idx <= 2; idx++ {
		for _, server := range db.servers {
			_, err := db.UpsertFederationProofSyncLog(
				context.Background(), id, leafKey(idx), server,
				SyncDirectionPush, ProofSyncStatusPending, false,
			)
			require.NoError(t, err)
		}
	}

	blockedRemote := &orderedFailRegistrar{failIndex: 1}
	healthyRemote := &orderedFailRegistrar{}
	envoy := NewFederationEnvoy(FederationConfig{
		FederationDB: db,
		SyncInterval: time.Minute,
		NewRemoteRegistrar: func(addr ServerAddr) (Registrar, error) {
			switch addr.HostStr() {
			case blockedServer.HostStr():
				return blockedRemote, nil
			case healthyServer.HostStr():
				return healthyRemote, nil
			default:
				return nil, fmt.Errorf("unexpected server: %v",
					addr.HostStr())
			}
		},
	})

	err := envoy.handlePendingProofPushes()
	require.NoError(t, err)

	// The second proof for the failing member remains behind the failed
	// first proof, while the healthy member drains both entries in order.
	require.Equal(t, []uint32{1}, blockedRemote.pushed())
	require.Equal(t, []uint32{1, 2}, healthyRemote.pushed())
	require.Len(t, db.pending(), 2)
}
