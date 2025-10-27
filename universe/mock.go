package universe

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// MockFederationDB is a mock implementation of the FederationDB interface
// for testing.
type MockFederationDB struct {
	mock.Mock
}

func (m *MockFederationDB) UniverseServers(ctx context.Context) (
	[]ServerAddr, error) {

	args := m.Called(ctx)
	return args.Get(0).([]ServerAddr), args.Error(1)
}

func (m *MockFederationDB) AddServers(ctx context.Context,
	addrs ...ServerAddr) error {

	args := m.Called(ctx, addrs)
	return args.Error(0)
}

func (m *MockFederationDB) RemoveServers(ctx context.Context,
	addrs ...ServerAddr) error {

	args := m.Called(ctx, addrs)
	return args.Error(0)
}

func (m *MockFederationDB) LogNewSyncs(ctx context.Context,
	addrs ...ServerAddr) error {

	args := m.Called(ctx, addrs)
	return args.Error(0)
}

func (m *MockFederationDB) QueryFederationSyncConfigs(
	ctx context.Context) ([]*FedGlobalSyncConfig, []*FedUniSyncConfig,
	error) {

	args := m.Called(ctx)
	return args.Get(0).([]*FedGlobalSyncConfig),
		args.Get(1).([]*FedUniSyncConfig), args.Error(2)
}

func (m *MockFederationDB) UpsertFederationSyncConfig(
	ctx context.Context, globalSyncConfigs []*FedGlobalSyncConfig,
	uniSyncConfigs []*FedUniSyncConfig) error {

	args := m.Called(ctx, globalSyncConfigs, uniSyncConfigs)
	return args.Error(0)
}

func (m *MockFederationDB) UpsertFederationProofSyncLog(
	ctx context.Context, uniID Identifier, leafKey LeafKey,
	addr ServerAddr, syncDirection SyncDirection,
	syncStatus ProofSyncStatus,
	bumpSyncAttemptCounter bool) (int64, error) {

	args := m.Called(ctx, uniID, leafKey, addr, syncDirection,
		syncStatus, bumpSyncAttemptCounter)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockFederationDB) QueryFederationProofSyncLog(
	ctx context.Context, uniID Identifier, leafKey LeafKey,
	syncDirection SyncDirection,
	syncStatus ProofSyncStatus) ([]*ProofSyncLogEntry, error) {

	args := m.Called(ctx, uniID, leafKey, syncDirection, syncStatus)
	return args.Get(0).([]*ProofSyncLogEntry), args.Error(1)
}

func (m *MockFederationDB) FetchPendingProofsSyncLog(
	ctx context.Context,
	syncDirection *SyncDirection) ([]*ProofSyncLogEntry, error) {

	args := m.Called(ctx, syncDirection)
	return args.Get(0).([]*ProofSyncLogEntry), args.Error(1)
}

func (m *MockFederationDB) DeleteProofsSyncLogEntries(
	ctx context.Context, servers ...ServerAddr) error {

	args := m.Called(ctx, servers)
	return args.Error(0)
}

// MockSyncer is a mock implementation of the Syncer interface for testing.
type MockSyncer struct {
	mock.Mock
}

// SyncUniverse implements the Syncer interface.
func (m *MockSyncer) SyncUniverse(ctx context.Context, host ServerAddr,
	syncType SyncType, syncConfigs SyncConfigs,
	idsToSync ...Identifier) ([]AssetSyncDiff, error) {

	args := m.Called(ctx, host, syncType, syncConfigs, idsToSync)
	return args.Get(0).([]AssetSyncDiff), args.Error(1)
}
