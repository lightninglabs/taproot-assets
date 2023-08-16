package tapdb

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

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
	for i := uint32(0); i < numServers; i++ {
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
