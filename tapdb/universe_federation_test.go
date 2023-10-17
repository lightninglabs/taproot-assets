package tapdb

import (
	"context"
	"database/sql"
	"fmt"
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

	testClock := clock.NewTestClock(time.Now())
	fedDB, _ := newTestFederationDb(t, testClock)

	ctx := context.Background()

	// If we try to list the set of servers without any added, we should
	// get the error we expect.
	dbServers, err := fedDB.UniverseServers(ctx)
	require.NoError(t, err)
	require.Empty(t, dbServers)

	// Next, we'll try to add a new series of servers to the DB.
	const numServers = 10
	addrs := make([]universe.ServerAddr, 0, numServers)
	for i := int64(0); i < numServers; i++ {
		portOffset := i + 10_000
		hostStr := fmt.Sprintf("localhost:%v", portOffset)

		addrs = append(addrs, universe.NewServerAddr(i+1, hostStr))
	}

	// With the set of addrs created, we'll now insert them all into the
	// database.
	err = fedDB.AddServers(ctx, addrs...)
	require.NoError(t, err)

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
