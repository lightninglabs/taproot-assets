package universe

import (
	"context"
	"errors"
	"testing"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestFederationEnvoyAddServer tests the AddServer method of FederationEnvoy.
func TestFederationEnvoyAddServer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("successfully add new servers", func(t *testing.T) {
		t.Parallel()

		mockDB := &MockFederationDB{}
		mockSyncer := &MockSyncer{}

		// Set up expectations
		mockDB.On("UniverseServers", mock.Anything).Return(
			[]ServerAddr{}, nil)

		expectedAddrs := []ServerAddr{
			NewServerAddrFromStr("server1.example.com"),
			NewServerAddrFromStr("server2.example.com"),
		}
		mockDB.On("AddServers", mock.Anything,
			expectedAddrs).Return(nil)

		// Mock the QueryFederationSyncConfigs call used by SyncServers
		mockDB.On("QueryFederationSyncConfigs", mock.Anything).Return(
			[]*FedGlobalSyncConfig(nil), []*FedUniSyncConfig(nil),
			nil,
		)

		mockSyncer.On("SyncUniverse", mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, mock.Anything).Return(
			[]AssetSyncDiff(nil), nil)

		successfulServerChecker := func(addr ServerAddr) error {
			// Simulate successful connection check.
			return nil
		}

		envoy := &FederationEnvoy{
			cfg: FederationConfig{
				FederationDB:   mockDB,
				UniverseSyncer: mockSyncer,
				ServerChecker:  successfulServerChecker,
			},
			ContextGuard: &fn.ContextGuard{
				DefaultTimeout: DefaultTimeout,
				Quit:           make(chan struct{}),
			},
		}

		addrs := []ServerAddr{
			NewServerAddrFromStr("server1.example.com"),
			NewServerAddrFromStr("server2.example.com"),
		}

		reports, err := envoy.AddServer(ctx, true, addrs...)
		require.NoError(t, err)
		require.Len(t, reports, 2)

		// Verify the reports.
		for _, report := range reports {
			require.Equal(
				t, fn.Some(true), report.ConnectionSuccess,
			)
			require.False(t, report.KnownServer)
			require.NoError(t, report.Error)
		}

		// Verify all expectations were met
		mockDB.AssertExpectations(t)
		mockSyncer.AssertExpectations(t)
	})

	t.Run("connection check disabled", func(t *testing.T) {
		t.Parallel()

		mockDB := &MockFederationDB{}
		mockSyncer := &MockSyncer{}

		// Set up expectations
		mockDB.On("UniverseServers", mock.Anything).Return(
			[]ServerAddr{}, nil)

		expectedAddr := NewServerAddrFromStr("server.example.com")
		mockDB.On("AddServers", mock.Anything,
			[]ServerAddr{expectedAddr}).Return(nil)

		// Mock the QueryFederationSyncConfigs call used by SyncServers
		mockDB.On("QueryFederationSyncConfigs", mock.Anything).Return(
			[]*FedGlobalSyncConfig(nil), []*FedUniSyncConfig(nil),
			nil,
		)

		mockSyncer.On("SyncUniverse", mock.Anything, mock.Anything,
			mock.Anything, mock.Anything, mock.Anything).Return(
			[]AssetSyncDiff(nil), nil)

		shouldNotBeCalledServerChecker := func(addr ServerAddr) error {
			t.Fatal("ServerChecker should not be called when " +
				"connection check is disabled")
			return nil
		}

		envoy := &FederationEnvoy{
			cfg: FederationConfig{
				FederationDB:   mockDB,
				UniverseSyncer: mockSyncer,
				ServerChecker:  shouldNotBeCalledServerChecker,
			},
			ContextGuard: &fn.ContextGuard{
				DefaultTimeout: DefaultTimeout,
				Quit:           make(chan struct{}),
			},
		}

		reports, err := envoy.AddServer(ctx, false, expectedAddr)
		require.NoError(t, err)
		require.Len(t, reports, 1)

		// Verify the report when connection check is disabled.
		report := reports[0]
		require.Equal(t, fn.None[bool](), report.ConnectionSuccess)
		require.False(t, report.KnownServer)
		require.NoError(t, report.Error)

		// Verify all expectations were met
		mockDB.AssertExpectations(t)
		mockSyncer.AssertExpectations(t)
	})

	t.Run("connection check fails", func(t *testing.T) {
		t.Parallel()

		mockDB := &MockFederationDB{}
		mockSyncer := &MockSyncer{}

		// Set up expectations - only UniverseServers should be called
		mockDB.On("UniverseServers", mock.Anything).Return(
			[]ServerAddr{}, nil)
		// AddServers and SyncUniverse should NOT be called

		failingServerChecker := func(addr ServerAddr) error {
			return errors.New("connection failed")
		}

		envoy := &FederationEnvoy{
			cfg: FederationConfig{
				FederationDB:   mockDB,
				UniverseSyncer: mockSyncer,
				ServerChecker:  failingServerChecker,
			},
			ContextGuard: &fn.ContextGuard{
				DefaultTimeout: DefaultTimeout,
				Quit:           make(chan struct{}),
			},
		}

		addr := NewServerAddrFromStr("unreachable.example.com")
		reports, err := envoy.AddServer(ctx, true, addr)
		require.NoError(t, err)
		require.Len(t, reports, 1)

		// Verify the report when connection check fails.
		report := reports[0]
		require.Equal(t, fn.Some(false), report.ConnectionSuccess)
		require.False(t, report.KnownServer)
		require.Error(t, report.Error)
		require.ErrorIs(t, report.Error, ErrUniConnFailed)

		// Verify expectations were met
		mockDB.AssertExpectations(t)
		mockSyncer.AssertExpectations(t)
	})

	t.Run("skip known servers", func(t *testing.T) {
		t.Parallel()

		existingServer := NewServerAddrFromStr("existing.example.com")

		mockDB := &MockFederationDB{}
		mockSyncer := &MockSyncer{}

		// Set up expectations - only UniverseServers should be called
		mockDB.On("UniverseServers", mock.Anything).Return(
			[]ServerAddr{existingServer}, nil)
		// AddServers and SyncUniverse should NOT be called for known
		// servers

		successfulServerChecker := func(addr ServerAddr) error {
			return nil
		}

		envoy := &FederationEnvoy{
			cfg: FederationConfig{
				FederationDB:   mockDB,
				UniverseSyncer: mockSyncer,
				ServerChecker:  successfulServerChecker,
			},
			ContextGuard: &fn.ContextGuard{
				DefaultTimeout: DefaultTimeout,
				Quit:           make(chan struct{}),
			},
		}

		reports, err := envoy.AddServer(ctx, true, existingServer)
		require.NoError(t, err)
		require.Len(t, reports, 1)

		// Verify the report for known server.
		report := reports[0]
		require.Equal(t, fn.Some(true), report.ConnectionSuccess)
		require.True(t, report.KnownServer)
		require.NoError(t, report.Error)

		// Verify expectations were met
		mockDB.AssertExpectations(t)
		mockSyncer.AssertExpectations(t)
	})
}
