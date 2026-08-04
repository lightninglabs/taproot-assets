package universe

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// mockFederationDB is a minimal in-memory FederationDB carrying just
// enough state for the envoy's delta sync path: per-server cursors.
type mockFederationDB struct {
	mu      sync.Mutex
	cursors map[string]uint64
}

func newMockFederationDB() *mockFederationDB {
	return &mockFederationDB{
		cursors: make(map[string]uint64),
	}
}

func (m *mockFederationDB) UniverseServers(
	_ context.Context) ([]ServerAddr, error) {

	return nil, nil
}

func (m *mockFederationDB) AddServers(_ context.Context,
	_ ...ServerAddr) error {

	return nil
}

func (m *mockFederationDB) RemoveServers(_ context.Context,
	_ ...ServerAddr) error {

	return nil
}

func (m *mockFederationDB) LogNewSyncs(_ context.Context,
	_ ...ServerAddr) error {

	return nil
}

func (m *mockFederationDB) UpsertSyncCursor(_ context.Context,
	addr ServerAddr, seq uint64) error {

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cursors[addr.HostStr()] = seq
	return nil
}

func (m *mockFederationDB) FetchSyncCursor(_ context.Context,
	addr ServerAddr) (uint64, error) {

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cursors[addr.HostStr()], nil
}

func (m *mockFederationDB) UpsertFederationProofSyncLog(_ context.Context,
	_ Identifier, _ LeafKey, _ ServerAddr, _ SyncDirection,
	_ ProofSyncStatus, _ bool) (int64, error) {

	return 0, nil
}

func (m *mockFederationDB) QueryFederationProofSyncLog(_ context.Context,
	_ Identifier, _ LeafKey, _ SyncDirection,
	_ ProofSyncStatus) ([]*ProofSyncLogEntry, error) {

	return nil, nil
}

func (m *mockFederationDB) FetchPendingProofsSyncLog(_ context.Context,
	_ *SyncDirection) ([]*ProofSyncLogEntry, error) {

	return nil, nil
}

func (m *mockFederationDB) DeleteProofsSyncLogEntries(_ context.Context,
	_ ...ServerAddr) error {

	return nil
}

func (m *mockFederationDB) QueryFederationSyncConfigs(
	_ context.Context) ([]*FedGlobalSyncConfig, []*FedUniSyncConfig,
	error) {

	return nil, nil, nil
}

func (m *mockFederationDB) UpsertFederationSyncConfig(_ context.Context,
	_ []*FedGlobalSyncConfig, _ []*FedUniSyncConfig) error {

	return nil
}

var _ FederationDB = (*mockFederationDB)(nil)

// countingDeltaSet wraps a memUniverseSet and counts SyncDelta calls,
// so tests can observe which sync path the envoy chose.
type countingDeltaSet struct {
	*memUniverseSet

	deltaCalls atomic.Int32
}

func (c *countingDeltaSet) SyncDelta(ctx context.Context, sinceSeq uint64,
	pageSize int32) (*DeltaPage, error) {

	c.deltaCalls.Add(1)
	return c.memUniverseSet.SyncDelta(ctx, sinceSeq, pageSize)
}

// newDeltaEnvoy builds a federation envoy whose syncer talks to the
// given remote engine and whose local side is a fresh in-memory set.
func newDeltaEnvoy(fedDB FederationDB, remoteFn func() DiffEngine,
	disableDelta bool) (*FederationEnvoy, *memUniverseSet) {

	local := newMemUniverseSet()
	syncer := newMemSyncer(local, remoteFn, 50)

	envoy := NewFederationEnvoy(FederationConfig{
		FederationDB:     fedDB,
		UniverseSyncer:   syncer,
		LocalRegistrar:   local,
		DisableDeltaSync: disableDelta,
	})

	return envoy, local
}

// seedRemote populates a remote universe set with a couple of
// universes.
func seedRemote(t *testing.T) *memUniverseSet {
	t.Helper()

	remote := newMemUniverseSet()
	issuanceID := Identifier{ProofType: ProofTypeIssuance}
	issuanceID.AssetID[0] = 1
	transferID := Identifier{ProofType: ProofTypeTransfer}
	transferID.AssetID[0] = 2

	for i := 0; i < 3; i++ {
		require.NoError(t, remote.insert(
			issuanceID, randomTestLeafKey(t), randomTestLeaf(t),
		))
		require.NoError(t, remote.insert(
			transferID, randomTestLeafKey(t), randomTestLeaf(t),
		))
	}

	return remote
}

// TestEnvoyDeltaSync pins the envoy's happy path: a delta-capable
// remote is synced via the cursor, which is then persisted, and a
// second pass is an incremental no-op that still advances the cursor
// for newly arrived leaves.
func TestEnvoyDeltaSync(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	remote := seedRemote(t)
	counting := &countingDeltaSet{memUniverseSet: remote}
	fedDB := newMockFederationDB()

	envoy, local := newDeltaEnvoy(
		fedDB, func() DiffEngine { return counting }, false,
	)
	addr := NewServerAddrFromStr("delta-peer:10029")

	err := envoy.syncServerState(ctx, addr, allowAllConfigs())
	require.NoError(t, err)
	require.Positive(t, counting.deltaCalls.Load())

	requireConverged(t, local, remote)

	cursor, err := fedDB.FetchSyncCursor(ctx, addr)
	require.NoError(t, err)
	require.Equal(t, remote.maxSeq(), cursor)

	// New activity on the remote: the next tick picks up exactly the
	// new leaves and advances the cursor.
	newID := Identifier{ProofType: ProofTypeIssuance}
	newID.AssetID[0] = 3
	require.NoError(t, remote.insert(
		newID, randomTestLeafKey(t), randomTestLeaf(t),
	))

	err = envoy.syncServerState(ctx, addr, allowAllConfigs())
	require.NoError(t, err)

	requireConverged(t, local, remote)

	cursor, err = fedDB.FetchSyncCursor(ctx, addr)
	require.NoError(t, err)
	require.Equal(t, remote.maxSeq(), cursor)

	require.NoError(t, envoy.Stop())
}

// TestEnvoyDeltaSyncUnsupported pins the compatibility fallback: a
// remote without delta support is synced via enumeration, converging
// without ever advancing the cursor.
func TestEnvoyDeltaSyncUnsupported(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	remote := seedRemote(t)
	fedDB := newMockFederationDB()

	envoy, local := newDeltaEnvoy(fedDB, func() DiffEngine {
		return &diffOnlyEngine{inner: remote}
	}, false)
	addr := NewServerAddrFromStr("legacy-peer:10029")

	err := envoy.syncServerState(ctx, addr, allowAllConfigs())
	require.NoError(t, err)

	requireConverged(t, local, remote)

	cursor, err := fedDB.FetchSyncCursor(ctx, addr)
	require.NoError(t, err)
	require.Zero(t, cursor)

	require.NoError(t, envoy.Stop())
}

// TestEnvoyDeltaSyncKillSwitch pins the config kill switch: with
// DisableDeltaSync set, the envoy uses enumeration sync even though
// both sides support deltas.
func TestEnvoyDeltaSyncKillSwitch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	remote := seedRemote(t)
	counting := &countingDeltaSet{memUniverseSet: remote}
	fedDB := newMockFederationDB()

	envoy, local := newDeltaEnvoy(
		fedDB, func() DiffEngine { return counting }, true,
	)
	addr := NewServerAddrFromStr("delta-peer:10029")

	err := envoy.syncServerState(ctx, addr, allowAllConfigs())
	require.NoError(t, err)
	require.Zero(t, counting.deltaCalls.Load())

	requireConverged(t, local, remote)

	require.NoError(t, envoy.Stop())
}
