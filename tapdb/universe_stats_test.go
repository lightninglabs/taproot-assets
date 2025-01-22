package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

func newUniverseStatsWithDB(db *BaseDB, clock clock.Clock) (*UniverseStats,
	sqlc.Querier) {

	dbTxer := NewTransactionExecutor(
		db, func(tx *sql.Tx) UniverseStatsStore {
			return db.WithTx(tx)
		},
	)

	stats := NewUniverseStats(
		dbTxer, clock, WithStatsCacheDuration(0),
	)

	return stats, db
}

type uniStatsHarness struct {
	assetUniverses []*BaseUniverseTree
	universeLeaves []*universe.Proof
	leafIndex      map[asset.ID]*universe.Proof

	db *UniverseStats

	t *testing.T
}

func newUniStatsHarness(t *testing.T, numAssets int, db *BaseDB,
	statsDB *UniverseStats) *uniStatsHarness {

	stats := &uniStatsHarness{
		assetUniverses: make([]*BaseUniverseTree, numAssets),
		universeLeaves: make([]*universe.Proof, numAssets),
		leafIndex:      make(map[asset.ID]*universe.Proof),
		db:             statsDB,
		t:              t,
	}

	ctx := context.Background()
	for i := 0; i < numAssets; i++ {
		assetType := asset.Normal
		if rand.Int()%2 == 0 {
			assetType = asset.Collectible
		}

		randGen := asset.RandGenesis(t, assetType)

		id := randUniverseID(t, false)
		id.AssetID = randGen.ID()

		assetUniverse, _ := newTestUniverseWithDb(db, id)
		stats.assetUniverses[i] = assetUniverse

		uniLeaf, err := insertRandLeaf(
			t, ctx, assetUniverse, &randGen,
		)
		require.NoError(t, err)

		stats.universeLeaves[i] = uniLeaf
		stats.leafIndex[id.AssetID] = uniLeaf
	}

	return stats
}

func (u *uniStatsHarness) logProofEventByIndex(i int) {
	ctx := context.Background()
	err := u.db.LogNewProofEvent(
		ctx, u.assetUniverses[i].id, u.universeLeaves[i].LeafKey,
	)
	require.NoError(u.t, err)
}

func (u *uniStatsHarness) logSyncEventByIndex(i int) {
	ctx := context.Background()
	err := u.db.LogSyncEvent(
		ctx, u.assetUniverses[i].id, u.universeLeaves[i].LeafKey,
	)
	require.NoError(u.t, err)
}

func (u *uniStatsHarness) assertUniverseStatsEqual(t *testing.T,
	stats universe.AggregateStats) {

	var (
		uniStats universe.AggregateStats
		err      error
	)

	err = wait.NoError(func() error {
		uniStats, err = u.db.AggregateSyncStats(context.Background())
		if err != nil {
			return err
		}

		if uniStats != stats {
			return fmt.Errorf("expected %v, got %v",
				spew.Sdump(stats),
				spew.Sdump(uniStats))
		}

		return nil
	}, time.Second*2)
	require.NoError(t, err)
}

func (u *uniStatsHarness) addEvents(numAssets int) {
	// Next, we'll log 2 proof events, and a random amount of syncs for
	// each asset.
	for i := 0; i < numAssets; i++ {
		u.logProofEventByIndex(i)
		u.logProofEventByIndex(i)

		numSyncs := rand.Int() % 10
		for j := 0; j < numSyncs; j++ {
			u.logSyncEventByIndex(i)
		}
	}
}

// TestUniverseStatsEvents tests that we're able to properly insert, and also
// fetch information related to universe sync related events.
func TestUniverseStatsEvents(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)

	yesterday := time.Now().UTC().Add(-24 * time.Hour)
	testClock := clock.NewTestClock(yesterday)
	statsDB, _ := newUniverseStatsWithDB(db.BaseDB, testClock)

	ctx := context.Background()

	const numTranches = 3

	sh := newUniStatsHarness(t, numTranches, db.BaseDB, statsDB)

	// Record the number of groups in this asset.
	var numGroups uint64
	for i := 0; i < numTranches; i++ {
		if sh.universeLeaves[i].Leaf.GroupKey != nil {
			numGroups++
		}
	}

	// Before we insert anything into the DB, we should have all zeroes for
	// the main events.
	sh.assertUniverseStatsEqual(t, universe.AggregateStats{
		NumTotalAssets: numTranches,
		NumTotalGroups: numGroups,
		NumTotalProofs: 0,
		NumTotalSyncs:  0,
	})

	// Now that we have our assets, we'll insert a new sync event for each
	// asset above. We'll mark these each first as a new proof.
	for i := 0; i < numTranches; i++ {
		sh.logProofEventByIndex(i)

		// Increment the clock by a full day to ensure that the event
		// is grouped into its own day.
		testClock.SetTime(testClock.Now().Add(24 * time.Hour))
	}

	// We'll now query for the set of aggregate Universe stats. It should
	// show 3 assets, and one new proof for each of those assets.
	sh.assertUniverseStatsEqual(t, universe.AggregateStats{
		NumTotalAssets: numTranches,
		NumTotalGroups: numGroups,
		NumTotalProofs: numTranches,
		NumTotalSyncs:  0,
	})

	// Next, we'll simulate a new sync event for a random asset. If we
	// query again, then we should see that the number of syncs has
	// increased by one.
	assetToSync := rand.Int() % numTranches

	sh.logSyncEventByIndex(assetToSync)

	sh.assertUniverseStatsEqual(t, universe.AggregateStats{
		NumTotalAssets: numTranches,
		NumTotalGroups: numGroups,
		NumTotalProofs: numTranches,
		NumTotalSyncs:  1,
	})

	// We'll now query for the set of Universe events. There should be 4
	// total events: 3 new proofs, and one sync event. Each event should
	// match up with the set of items we inserted above.
	syncStats, err := statsDB.QuerySyncStats(
		ctx, universe.SyncStatsQuery{},
	)
	require.NoError(t, err)
	require.Len(t, syncStats.SyncStats, numTranches)

	// We should also be able to find summaries of each of the items above.
	// This should match the leaves we inserted above.
	for _, assetStat := range syncStats.SyncStats {
		leaf, ok := sh.leafIndex[assetStat.AssetID]
		require.True(t, ok)

		require.Equal(t, assetStat.TotalSupply, leaf.Leaf.Amt)

		if sh.universeLeaves[assetToSync].LeafKey == leaf.LeafKey {
			require.Equal(t, int(assetStat.TotalSyncs), 1)
		}

		require.Equal(t, int(assetStat.TotalProofs), 1)
	}

	timeStats, err := statsDB.QueryAssetStatsPerDay(
		ctx, universe.GroupedStatsQuery{
			StartTime: yesterday,
			EndTime:   testClock.Now(),
		},
	)
	require.NoError(t, err)

	// There should be 4 total time stats, three for the proofs, and one
	// for the sync event.
	require.Len(t, timeStats, 4)
	for idx, s := range timeStats {
		targetDate := yesterday.Add(time.Duration(idx) * 24 * time.Hour)
		targetDateStr := targetDate.Format("2006-01-02")
		require.Equal(t, targetDateStr, s.Date)

		if idx == 3 {
			require.NotZero(t, s.NumTotalSyncs)
		} else {
			require.NotZero(t, s.NumTotalProofs)
		}
	}

	// Finally, we should be able to delete a universe and all associated
	// events.
	_, err = sh.assetUniverses[assetToSync].DeleteUniverse(ctx)
	require.NoError(t, err)

	if sh.universeLeaves[assetToSync].Leaf.GroupKey != nil {
		numGroups--
	}
	sh.assertUniverseStatsEqual(t, universe.AggregateStats{
		NumTotalAssets: numTranches - 1,
		NumTotalGroups: numGroups,
		NumTotalProofs: numTranches - 1,
		NumTotalSyncs:  0,
	})
}

// TestUniverseStatsAsyncCache tests that the cache of the universe aggregate
// stats is asynchronously populated regardless of what the outcome of the
// RPC call is.
func TestUniverseStatsAsyncCache(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)

	yesterday := time.Now().UTC().Add(-24 * time.Hour)
	testClock := clock.NewTestClock(yesterday)
	statsDB, _ := newUniverseStatsWithDB(db.BaseDB, testClock)

	const numTranches = 3

	sh := newUniStatsHarness(t, numTranches, db.BaseDB, statsDB)

	// Record the number of groups in this asset.
	var numGroups uint64
	for i := 0; i < numTranches; i++ {
		if sh.universeLeaves[i].Leaf.GroupKey != nil {
			numGroups++
		}
	}

	// First let's make sure the cache is empty. This should be the case as
	// no calls have been made so far.
	val := sh.db.statsSnapshot.Load()
	require.Nil(t, val)

	const (
		quickTimeoutDuration = time.Microsecond * 1
		defaultTick          = time.Millisecond * 250
	)

	// We now create a client context with a very quick timeout. This is
	// meant to quickly fail the RPC call.
	ctx, cancel := context.WithTimeout(
		context.Background(), quickTimeoutDuration,
	)
	defer cancel()

	// The tiny timeout duration should make the following call result in a
	// context deadline related error.
	_, err := sh.db.AggregateSyncStats(ctx)
	require.ErrorContains(t, err, "context deadline exceeded")

	// Regardless of the above call failing, the cache should asynchronously
	// get updated in the background, so let's wait until a value is loaded.
	require.Eventually(t, func() bool {
		val := sh.db.statsSnapshot.Load()
		return val != nil
	}, DefaultStoreTimeout, defaultTick)
}

// TestUniverseQuerySyncStatsSorting tests that we're able to properly sort the
// response using any of the available params.
func TestUniverseQuerySyncStatsSorting(t *testing.T) {
	db := NewTestDB(t)

	testClock := clock.NewTestClock(time.Now())
	statsDB, _ := newUniverseStatsWithDB(db.BaseDB, testClock)

	ctx := context.Background()

	const numAssets = 5

	sh := newUniStatsHarness(t, numAssets, db.BaseDB, statsDB)

	// Next, we'll log 2 proof events, and a random amount of syncs for
	// each asset.
	sh.addEvents(numAssets)

	// sortCheck is used to generate an IsSorted func bound to the
	// response, for each sort type below.
	type sortCheck func([]universe.AssetSyncSnapshot,
		universe.SortDirection) func(i, j int) bool

	// isSortedWithDirection is a helper function that returns a function
	// that can be used to check if the response is sorted in the given
	// direction.
	isSortedWithDirection := func(s []universe.AssetSyncSnapshot,
		t universe.SyncStatsSort,
		d universe.SortDirection) func(i, j int) bool {

		asc := d == universe.SortAscending
		desc := d == universe.SortDescending

		return func(i, j int) bool {
			switch {
			case t == universe.SortByAssetName && asc:
				return s[i].AssetName < s[j].AssetName
			case t == universe.SortByAssetName && desc:
				return s[i].AssetName > s[j].AssetName
			case t == universe.SortByAssetType && asc:
				return s[i].AssetType < s[j].AssetType
			case t == universe.SortByAssetType && desc:
				return s[i].AssetType > s[j].AssetType
			case t == universe.SortByAssetID && asc:
				return bytes.Compare(s[i].AssetID[:],
					s[j].AssetID[:]) < 0
			case t == universe.SortByAssetID && desc:
				return bytes.Compare(s[i].AssetID[:],
					s[j].AssetID[:]) > 0
			case t == universe.SortByTotalSyncs && asc:
				return s[i].TotalSyncs < s[j].TotalSyncs
			case t == universe.SortByTotalSyncs && desc:
				return s[i].TotalSyncs > s[j].TotalSyncs
			case t == universe.SortByTotalProofs && asc:
				return s[i].TotalProofs < s[j].TotalProofs
			case t == universe.SortByTotalProofs && desc:
				return s[i].TotalProofs > s[j].TotalProofs
			case t == universe.SortByGenesisHeight && asc:
				return s[i].GenesisHeight < s[j].GenesisHeight
			case t == universe.SortByGenesisHeight && desc:
				return s[i].GenesisHeight > s[j].GenesisHeight
			case t == universe.SortByTotalSupply && asc:
				return s[i].TotalSupply < s[j].TotalSupply
			case t == universe.SortByTotalSupply && desc:
				return s[i].TotalSupply > s[j].TotalSupply
			}
			panic("unknown sort type")
		}
	}

	// With the events above logged, we'll now make sure we can properly
	// retrieve each of the events by their sorted order.
	var tests = []struct {
		name         string
		sortType     universe.SyncStatsSort
		direction    universe.SortDirection
		isSortedFunc sortCheck
	}{
		{
			name:      "asset name sort ascending",
			sortType:  universe.SortByAssetName,
			direction: universe.SortAscending,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
				d universe.SortDirection) func(i, j int) bool {

				return isSortedWithDirection(
					s, universe.SortByAssetName, d)
			},
		},
		{
			name:      "asset name sort descending",
			sortType:  universe.SortByAssetName,
			direction: universe.SortDescending,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
				d universe.SortDirection) func(i, j int) bool {

				return isSortedWithDirection(
					s, universe.SortByAssetName, d)
			},
		},
		{
			name:      "asset type sort ascending",
			sortType:  universe.SortByAssetType,
			direction: universe.SortAscending,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
				d universe.SortDirection) func(i, j int) bool {

				return isSortedWithDirection(
					s, universe.SortByAssetType, d)
			},
		},
		{
			name:      "asset type sort descending",
			sortType:  universe.SortByAssetType,
			direction: universe.SortDescending,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
				d universe.SortDirection) func(i, j int) bool {

				return isSortedWithDirection(
					s, universe.SortByAssetType, d)
			},
		},
		{
			name:      "asset id ascending",
			sortType:  universe.SortByAssetID,
			direction: universe.SortAscending,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
				d universe.SortDirection) func(i, j int) bool {

				return isSortedWithDirection(
					s, universe.SortByAssetID, d)
			},
		},
		{
			name:      "asset id descending",
			sortType:  universe.SortByAssetID,
			direction: universe.SortDescending,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
				d universe.SortDirection) func(i, j int) bool {

				return isSortedWithDirection(
					s, universe.SortByAssetID, d)
			},
		},
		{
			name:      "total sync ascending",
			sortType:  universe.SortByTotalSyncs,
			direction: universe.SortAscending,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
				d universe.SortDirection) func(i, j int) bool {

				return isSortedWithDirection(
					s, universe.SortByTotalSyncs, d)
			},
		},
		{
			name:      "total sync descending",
			sortType:  universe.SortByTotalSyncs,
			direction: universe.SortDescending,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
				d universe.SortDirection) func(i, j int) bool {

				return isSortedWithDirection(
					s, universe.SortByTotalSyncs, d)
			},
		},
		{
			name:      "total proofs ascending",
			sortType:  universe.SortByTotalProofs,
			direction: universe.SortAscending,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
				d universe.SortDirection) func(i, j int) bool {

				return isSortedWithDirection(
					s, universe.SortByTotalProofs, d)
			},
		},
		{
			name:      "total proofs descending",
			sortType:  universe.SortByTotalProofs,
			direction: universe.SortDescending,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
				d universe.SortDirection) func(i, j int) bool {

				return isSortedWithDirection(
					s, universe.SortByTotalProofs, d)
			},
		},
		{
			name:      "genesis height ascending",
			sortType:  universe.SortByGenesisHeight,
			direction: universe.SortAscending,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
				d universe.SortDirection) func(i, j int) bool {

				return isSortedWithDirection(
					s, universe.SortByGenesisHeight, d)
			},
		},
		{
			name:      "genesis height descending",
			sortType:  universe.SortByGenesisHeight,
			direction: universe.SortDescending,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
				d universe.SortDirection) func(i, j int) bool {

				return isSortedWithDirection(
					s, universe.SortByGenesisHeight, d)
			},
		},
		{
			name:      "total supply descending",
			sortType:  universe.SortByTotalSupply,
			direction: universe.SortDescending,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
				d universe.SortDirection) func(i, j int) bool {

				return isSortedWithDirection(
					s, universe.SortByTotalSupply, d)
			},
		},
		{
			name:      "total supply ascending",
			sortType:  universe.SortByTotalSupply,
			direction: universe.SortAscending,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
				d universe.SortDirection) func(i, j int) bool {

				return isSortedWithDirection(
					s, universe.SortByTotalSupply, d)
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			syncStats, err := statsDB.QuerySyncStats(
				ctx, universe.SyncStatsQuery{
					SortBy:        testCase.sortType,
					SortDirection: testCase.direction,
				},
			)
			require.NoError(t, err)
			require.Len(t, syncStats.SyncStats, numAssets)

			require.True(t, sort.SliceIsSorted(
				syncStats.SyncStats,
				testCase.isSortedFunc(syncStats.SyncStats,
					testCase.direction),
			))
		})
	}
}

// TestUniverseQuerySyncFilters tests that we're able to properly fetch the
// asset snapshot for the set of assets given one or more of the possible
// filters.
func TestUniverseQuerySyncFilters(t *testing.T) {
	db := NewTestDB(t)

	testClock := clock.NewTestClock(time.Now())
	statsDB, _ := newUniverseStatsWithDB(db.BaseDB, testClock)

	ctx := context.Background()

	const numAssets = 5

	sh := newUniStatsHarness(t, numAssets, db.BaseDB, statsDB)

	// Next, we'll log 2 proof events, and a random amount of syncs for
	// each asset.
	for i := 0; i < numAssets; i++ {
		sh.logProofEventByIndex(i)
		sh.logProofEventByIndex(i)

		numSyncs := rand.Int() % 10
		for j := 0; j < numSyncs; j++ {
			sh.logSyncEventByIndex(i)
		}
	}

	// For each test case, we define a filter, then a function that can
	// check to see if the query adhered to the filter or not.
	var testCases = []struct {
		name string

		nameFilter string
		idFilter   asset.ID
		typeFilter *asset.Type

		queryCheck func(*universe.AssetSyncStats) bool
	}{
		{
			name:       "name",
			nameFilter: sh.universeLeaves[rand.Int()%numAssets].Leaf.Tag,
			queryCheck: func(s *universe.AssetSyncStats) bool {
				return len(s.SyncStats) == 1 &&
					s.SyncStats[0].AssetName ==
						s.Query.AssetNameFilter
			},
		},
		{
			name:     "asset id",
			idFilter: sh.universeLeaves[rand.Int()%numAssets].Leaf.ID(),
			queryCheck: func(s *universe.AssetSyncStats) bool {
				return len(s.SyncStats) == 1 &&
					s.SyncStats[0].AssetID ==
						s.Query.AssetIDFilter
			},
		},
		{
			name:       "type",
			typeFilter: fn.Ptr(asset.Type(rand.Int() % 2)),
			queryCheck: func(s *universe.AssetSyncStats) bool {
				typeCount := fn.Reduce(sh.universeLeaves,
					func(acc int, p *universe.Proof) int {
						if p.Leaf.Type == *s.Query.AssetTypeFilter {
							return acc + 1
						}
						return acc
					},
				)

				return len(s.SyncStats) == typeCount
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			syncStats, err := statsDB.QuerySyncStats(
				ctx, universe.SyncStatsQuery{
					AssetNameFilter: testCase.nameFilter,
					AssetIDFilter:   testCase.idFilter,
					AssetTypeFilter: testCase.typeFilter,
				},
			)
			require.NoError(t, err)

			require.True(t, testCase.queryCheck(syncStats))
		})
	}
}
