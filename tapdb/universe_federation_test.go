package tapdb

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/rand"
)

func newTestFederationDb(t *testing.T,
	clock clock.Clock) (*UniverseFederationDB, sqlc.Querier) {

	db := NewTestDB(t)

	dbTxer := NewTransactionExecutor(db,
		func(tx *sql.Tx) UniverseServerStore {
			return db.WithTx(tx)
		},
	)

	return NewUniverseFederationDB(dbTxer, clock), db
}

// TestUniverseFederationCRUD tests that we can add and remove servers from the
// Universe DB, and also update the sync log.
func TestUniverseFederationCRUD(t *testing.T) {
	t.Parallel()

	var (
		ctx = context.Background()

		db    = NewDbHandle(t)
		fedDB = db.UniverseFederationStore
	)

	// If we try to list the set of servers without any added, we should
	// get the error we expect.
	dbServers, err := fedDB.UniverseServers(ctx)
	require.NoError(t, err)
	require.Empty(t, dbServers)

	// Next, we'll try to add a new series of servers to the DB.
	addrs := db.AddRandomServerAddrs(t, 10)

	// If we try to insert them all again, then we should get an error as
	// we ensure the host names are unique.
	err = fedDB.AddServers(ctx, addrs...)
	require.ErrorIs(t, err, universe.ErrDuplicateUniverse)

	// Next, we should be able to fetch all the active hosts.
	dbAddrs, err := fedDB.UniverseServers(ctx)
	require.NoError(t, err)

	// The hosts we fetched should match exactly the ones we inserted.
	// However these will have their ID populated.
	require.Equal(t, len(addrs), len(dbAddrs))
	require.Equal(t, addrs, dbAddrs)

	// Next, we'll pick three random server address to delete.
	delAddr1 := addrs[rand.Int()%len(addrs)]
	delAddr2 := addrs[rand.Int()%len(addrs)]
	delAddr3 := addrs[rand.Int()%len(addrs)]

	err = fedDB.RemoveServers(ctx, delAddr1, delAddr2, delAddr3)
	require.NoError(t, err)

	// We shouldn't be able to find the deleted addr in the DB anymore.
	dbAddrs, err = fedDB.UniverseServers(ctx)
	require.NoError(t, err)
	require.NotContains(t, dbAddrs, delAddr1)
	require.NotContains(t, dbAddrs, delAddr2)
	require.NotContains(t, dbAddrs, delAddr3)
	require.Equal(t, len(addrs)-3, len(dbAddrs))

	// Next, we'll pick another random server address to update the sync
	// timestamp of.
	addrToUpdate := addrs[rand.Int()%len(dbAddrs)]
	err = fedDB.LogNewSyncs(ctx, addrToUpdate)
	require.NoError(t, err)
}

// TestFederationProofSyncLogCRUD tests that we can add, modify, and remove
// proof sync log entries from the Universe DB.
func TestFederationProofSyncLogCRUD(t *testing.T) {
	t.Parallel()

	var (
		ctx      = context.Background()
		dbHandle = NewDbHandle(t)
		fedStore = dbHandle.UniverseFederationStore
	)

	// Populate the database with a random asset, its associated proof, and
	// a set of servers.
	testAsset, testAnnotatedProof := dbHandle.AddRandomAssetProof(t)
	uniProof := dbHandle.AddUniProofLeaf(t, testAsset, testAnnotatedProof)
	uniId := universe.NewUniIDFromAsset(*testAsset)

	servers := dbHandle.AddRandomServerAddrs(t, 3)

	// Designate pending sync status for all servers except the first.
	// Make a map set of pending sync servers.
	pendingSyncServers := make(map[universe.ServerAddr]struct{})
	for i := range servers {
		server := servers[i]
		if i == 0 {
			continue
		}
		pendingSyncServers[server] = struct{}{}
	}

	// Add log entries for the first server.
	syncServer := servers[0]

	// Add push log entry.
	_, err := fedStore.UpsertFederationProofSyncLog(
		ctx, uniId, uniProof.LeafKey, syncServer,
		universe.SyncDirectionPush, universe.ProofSyncStatusComplete,
		true,
	)
	require.NoError(t, err)

	// Add pull log entry.
	_, err = fedStore.UpsertFederationProofSyncLog(
		ctx, uniId, uniProof.LeafKey, syncServer,
		universe.SyncDirectionPull, universe.ProofSyncStatusComplete,
		true,
	)
	require.NoError(t, err)

	// We've already added log entries for the first server. We will now
	// insert new proof sync log entries for the remaining servers.
	for _, server := range servers[1:] {
		_, err := fedStore.UpsertFederationProofSyncLog(
			ctx, uniId, uniProof.LeafKey, server,
			universe.SyncDirectionPush,
			universe.ProofSyncStatusPending, false,
		)
		require.NoError(t, err)
	}

	// Retrieve all sync status pending log entries.
	syncDirectionPush := universe.SyncDirectionPush
	pendingLogEntries, err := fedStore.FetchPendingProofsSyncLog(
		ctx, &syncDirectionPush,
	)
	require.NoError(t, err)
	require.Len(t, pendingLogEntries, 2)

	for i := range pendingLogEntries {
		entry := pendingLogEntries[i]
		require.Equal(
			t, universe.ProofSyncStatusPending, entry.SyncStatus,
		)
		require.Equal(
			t, universe.SyncDirectionPush, entry.SyncDirection,
		)
		require.Equal(t, uniId.String(), entry.UniID.String())
		require.Equal(t, int64(0), entry.AttemptCounter)

		assertProofSyncLogLeafKey(t, uniProof.LeafKey, entry.LeafKey)
		assertProofSyncLogLeaf(t, *uniProof.Leaf, entry.Leaf)

		// Check for server address in pending sync server set.
		_, ok := pendingSyncServers[entry.ServerAddr]
		require.True(t, ok)
	}

	// Retrieve all push sync status complete log entries.
	completePushLogEntries, err := fedStore.QueryFederationProofSyncLog(
		ctx, uniId, uniProof.LeafKey, universe.SyncDirectionPush,
		universe.ProofSyncStatusComplete,
	)
	require.NoError(t, err)

	// There should only be one complete push log entry.
	require.Len(t, completePushLogEntries, 1)

	// Check that the complete log entry is as expected.
	completePushEntry := completePushLogEntries[0]

	require.Equal(t, servers[0], completePushEntry.ServerAddr)
	require.Equal(
		t, universe.ProofSyncStatusComplete,
		completePushEntry.SyncStatus,
	)
	require.Equal(
		t, universe.SyncDirectionPush, completePushEntry.SyncDirection,
	)
	require.Equal(t, uniId.String(), completePushEntry.UniID.String())
	require.Equal(t, int64(0), completePushEntry.AttemptCounter)

	assertProofSyncLogLeafKey(
		t, uniProof.LeafKey, completePushEntry.LeafKey,
	)
	assertProofSyncLogLeaf(t, *uniProof.Leaf, completePushEntry.Leaf)

	// Retrieve all pull sync status complete log entries.
	completePullLogEntries, err := fedStore.QueryFederationProofSyncLog(
		ctx, uniId, uniProof.LeafKey, universe.SyncDirectionPull,
		universe.ProofSyncStatusComplete,
	)
	require.NoError(t, err)

	// There should only be one complete push log entry.
	require.Len(t, completePullLogEntries, 1)

	// Check that the complete log entry is as expected.
	completePullEntry := completePullLogEntries[0]

	require.Equal(t, servers[0], completePullEntry.ServerAddr)
	require.Equal(
		t, universe.ProofSyncStatusComplete,
		completePullEntry.SyncStatus,
	)
	require.Equal(
		t, universe.SyncDirectionPull, completePullEntry.SyncDirection,
	)
	require.Equal(t, uniId.String(), completePullEntry.UniID.String())
	require.Equal(t, int64(0), completePullEntry.AttemptCounter)

	assertProofSyncLogLeafKey(
		t, uniProof.LeafKey, completePullEntry.LeafKey,
	)
	assertProofSyncLogLeaf(t, *uniProof.Leaf, completePullEntry.Leaf)

	// Increment the attempt counter for one of the pending log entries.
	_, err = fedStore.UpsertFederationProofSyncLog(
		ctx, uniId, uniProof.LeafKey, servers[1],
		universe.SyncDirectionPush, universe.ProofSyncStatusPending,
		true,
	)
	require.NoError(t, err)

	// Check that the attempt counter was incremented as expected.
	pendingLogEntries, err = fedStore.QueryFederationProofSyncLog(
		ctx, uniId, uniProof.LeafKey, universe.SyncDirectionPush,
		universe.ProofSyncStatusPending,
	)
	require.NoError(t, err)
	require.Len(t, pendingLogEntries, 2)

	for i := range pendingLogEntries {
		entry := pendingLogEntries[i]
		if entry.ServerAddr == servers[1] {
			require.Equal(t, int64(1), entry.AttemptCounter)
		} else {
			require.Equal(t, int64(0), entry.AttemptCounter)
		}
	}

	// Upsert without incrementing the attempt counter for one of the
	// pending log entries.
	_, err = fedStore.UpsertFederationProofSyncLog(
		ctx, uniId, uniProof.LeafKey, servers[1],
		universe.SyncDirectionPush, universe.ProofSyncStatusPending,
		false,
	)
	require.NoError(t, err)

	// Check that the attempt counter was not changed as expected.
	pendingLogEntries, err = fedStore.QueryFederationProofSyncLog(
		ctx, uniId, uniProof.LeafKey, universe.SyncDirectionPush,
		universe.ProofSyncStatusPending,
	)
	require.NoError(t, err)
	require.Len(t, pendingLogEntries, 2)

	for i := range pendingLogEntries {
		entry := pendingLogEntries[i]
		if entry.ServerAddr == servers[1] {
			require.Equal(t, int64(1), entry.AttemptCounter)
		} else {
			require.Equal(t, int64(0), entry.AttemptCounter)
		}
	}

	// Set the sync status to complete for one of the pending log entries.
	_, err = fedStore.UpsertFederationProofSyncLog(
		ctx, uniId, uniProof.LeafKey, servers[1],
		universe.SyncDirectionPush, universe.ProofSyncStatusComplete,
		false,
	)
	require.NoError(t, err)

	// Check that the sync status was updated as expected.
	pendingLogEntries, err = fedStore.QueryFederationProofSyncLog(
		ctx, uniId, uniProof.LeafKey, universe.SyncDirectionPush,
		universe.ProofSyncStatusPending,
	)
	require.NoError(t, err)
	require.Len(t, pendingLogEntries, 1)

	completePushLogEntries, err = fedStore.QueryFederationProofSyncLog(
		ctx, uniId, uniProof.LeafKey, universe.SyncDirectionPush,
		universe.ProofSyncStatusComplete,
	)
	require.NoError(t, err)
	require.Len(t, completePushLogEntries, 2)

	// Delete log entries for one of the servers.
	err = fedStore.DeleteProofsSyncLogEntries(ctx, servers[0], servers[1])
	require.NoError(t, err)

	// Only one log entry should remain and it should have sync status
	// pending.
	pendingLogEntries, err = fedStore.QueryFederationProofSyncLog(
		ctx, uniId, uniProof.LeafKey, universe.SyncDirectionPush,
		universe.ProofSyncStatusPending,
	)
	require.NoError(t, err)
	require.Len(t, pendingLogEntries, 1)

	// Check that the remaining log entry is as expected.
	pendingEntry := pendingLogEntries[0]
	require.Equal(t, servers[2], pendingEntry.ServerAddr)
}

// assertProofSyncLogLeafKey asserts that a leaf key derived from a proof sync
// log entry is equal to a given leaf key.
func assertProofSyncLogLeafKey(t *testing.T, actualLeafKey universe.LeafKey,
	logLeafKey universe.LeafKey) {

	// We can safely ignore the tweaked script key as it is the derivation
	// information for the script key. It is only ever known to the owner of
	// the asset and is never serialized in a proof
	baseKey, ok := actualLeafKey.(universe.BaseLeafKey)
	require.True(t, ok)
	baseKey.ScriptKey.TweakedScriptKey = nil
	actualLeafKey = baseKey
	require.Equal(t, actualLeafKey, logLeafKey)
}

// assertProofSyncLogLeaf asserts that a leaf derived from a proof sync log
// entry is equal to a given universe leaf.
func assertProofSyncLogLeaf(t *testing.T, actualLeaf universe.Leaf,
	logLeaf universe.Leaf) {

	if actualLeaf.GenesisWithGroup.GroupKey != nil {
		// We can safely ignore the group key witness as it is the
		// basically just extracted from the asset and won't be relevant
		// when parsing the proof.
		actualLeaf.GenesisWithGroup.GroupKey.Witness = nil

		// We can safely ignore the pre-tweaked group key
		// (GroupKey.RawKey) as it is the derivation information for the
		// group key. It is only ever known to the owner of the asset
		// and is never serialized in a proof.
		actualLeaf.GenesisWithGroup.GroupKey.RawKey.PubKey = nil
	}

	require.Equal(t, actualLeaf.Amt, logLeaf.Amt)
	require.Equal(t, actualLeaf.RawProof, logLeaf.RawProof)
	require.Equal(t, actualLeaf.GenesisWithGroup, logLeaf.GenesisWithGroup)

	// We compare the assets with our custom asset quality function as the
	// SplitCommitmentRoot field MS-SMT node types will differ. A computed
	// node is derived from the database data whereas the generated asset
	// may have a MS-SMT branch node type.
	actualLeaf.Asset.DeepEqual(logLeaf.Asset)
}

// TestFederationConfigDefault tests that we're able to fetch the default
// federation config.
func TestFederationConfigDefault(t *testing.T) {
	t.Parallel()

	testClock := clock.NewTestClock(time.Now())
	fedDB, _ := newTestFederationDb(t, testClock)

	ctx := context.Background()

	// If we try to fetch the default config without any added, we should
	// should get the default config.
	globalConfig, _, err := fedDB.QueryFederationSyncConfigs(ctx)
	require.NoError(t, err)
	require.Equal(t, defaultGlobalSyncConfigs, globalConfig)
}

// TestFederationConfigCRUD tests that we're able to properly update the global
// and local federation configs.
func TestFederationConfigCRUD(t *testing.T) {
	t.Parallel()

	testClock := clock.NewTestClock(time.Now())
	fedDB, _ := newTestFederationDb(t, testClock)

	ctx := context.Background()

	// First, we'll add a new global config, but just for the issuance
	// proof type.
	newGlobalProof := fn.MakeSlice(&universe.FedGlobalSyncConfig{
		ProofType:       universe.ProofTypeIssuance,
		AllowSyncInsert: true,
		AllowSyncExport: true,
	})

	err := fedDB.UpsertFederationSyncConfig(
		ctx, newGlobalProof, nil,
	)
	require.NoError(t, err)

	// If we query for the global config, then we should get the issuance
	// proof type we just modified, and also the existing global config for
	// transfer proof type.
	expectedCfgs := append(
		newGlobalProof, defaultGlobalSyncConfigs[1],
	)

	dbGlobalCfg, _, err := fedDB.QueryFederationSyncConfigs(ctx)
	require.NoError(t, err)

	require.Equal(t, expectedCfgs, dbGlobalCfg)

	// Next, make the same modification, but for the transfer proof type.
	newGlobalTransfer := fn.MakeSlice(&universe.FedGlobalSyncConfig{
		ProofType:       universe.ProofTypeTransfer,
		AllowSyncInsert: true,
		AllowSyncExport: true,
	})
	err = fedDB.UpsertFederationSyncConfig(
		ctx, newGlobalTransfer, nil,
	)
	require.NoError(t, err)

	dbGlobalCfg, _, err = fedDB.QueryFederationSyncConfigs(ctx)
	require.NoError(t, err)

	expectedCfgs = append(newGlobalProof, newGlobalTransfer...)
	require.Equal(t, expectedCfgs, dbGlobalCfg)

	// We should be able to update them both in the same txn.
	for _, cfg := range expectedCfgs {
		cfg.AllowSyncInsert = false
		cfg.AllowSyncExport = false
	}

	err = fedDB.UpsertFederationSyncConfig(ctx, expectedCfgs, nil)
	require.NoError(t, err)

	dbGlobalCfg, _, err = fedDB.QueryFederationSyncConfigs(ctx)
	require.NoError(t, err)
	require.Equal(t, expectedCfgs, dbGlobalCfg)

	// Finally, if we insert the current config again, we should see no
	// change in the returned configs.
	singleCfg := fn.MakeSlice(dbGlobalCfg[0])
	err = fedDB.UpsertFederationSyncConfig(ctx, singleCfg, nil)
	require.NoError(t, err)

	dbGlobalCfg, _, err = fedDB.QueryFederationSyncConfigs(ctx)
	require.NoError(t, err)
	require.Equal(t, expectedCfgs, dbGlobalCfg)

	// Now, create configs for specific assets.
	randAssetIDBytes := test.RandBytes(32)
	randGroupKey := test.RandPubKey(t)
	groupCfg := &universe.FedUniSyncConfig{
		UniverseID: universe.Identifier{
			GroupKey:  randGroupKey,
			ProofType: universe.ProofTypeIssuance,
		},
		AllowSyncInsert: true,
		AllowSyncExport: false,
	}
	assetCfg := &universe.FedUniSyncConfig{
		UniverseID: universe.Identifier{
			ProofType: universe.ProofTypeTransfer,
		},
		AllowSyncInsert: false,
		AllowSyncExport: true,
	}
	copy(assetCfg.UniverseID.AssetID[:], randAssetIDBytes)

	// Before insertion, there should be no asset-specific configs.
	_, dbLocalCfg, err := fedDB.QueryFederationSyncConfigs(ctx)
	require.NoError(t, err)
	require.Empty(t, dbLocalCfg)

	// Next, store the asset configs and verify that we get the same configs
	// back from a query.
	localCfg := fn.MakeSlice(groupCfg, assetCfg)
	err = fedDB.UpsertFederationSyncConfig(ctx, nil, localCfg)
	require.NoError(t, err)

	_, dbLocalCfg, err = fedDB.QueryFederationSyncConfigs(ctx)
	require.NoError(t, err)
	require.Equal(t, localCfg, dbLocalCfg)

	// We should be able to overwrite a stored config.
	groupNewCfg := &universe.FedUniSyncConfig{
		UniverseID: universe.Identifier{
			GroupKey:  randGroupKey,
			ProofType: universe.ProofTypeIssuance,
		},
		AllowSyncInsert: true,
		AllowSyncExport: true,
	}
	err = fedDB.UpsertFederationSyncConfig(
		ctx, nil, fn.MakeSlice(groupNewCfg),
	)
	require.NoError(t, err)

	_, dbLocalCfg, err = fedDB.QueryFederationSyncConfigs(ctx)
	require.NoError(t, err)
	require.NotEqual(t, localCfg, dbLocalCfg)

	localCfg = fn.MakeSlice(groupNewCfg, assetCfg)
	require.Equal(t, localCfg, dbLocalCfg)
}
