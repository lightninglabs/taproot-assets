package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"math/rand"
	"sort"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/stretchr/testify/require"
)

func newUniverseStatsWithDB(t *testing.T,
	db *BaseDB) (*UniverseStats, sqlc.Querier) {

	dbTxer := NewTransactionExecutor(
		db, func(tx *sql.Tx) UniverseStatsStore {
			return db.WithTx(tx)
		},
	)

	return NewUniverseStats(dbTxer), db
}

type uniStatsHarness struct {
	assetUniverses []*BaseUniverseTree
	universeLeaves []*universe.IssuanceProof
	leafIndex      map[asset.ID]*universe.IssuanceProof

	db *UniverseStats

	t *testing.T
}

func newUniStatsHarness(t *testing.T, numAssets int, db *BaseDB,
	statsDB *UniverseStats) *uniStatsHarness {

	stats := &uniStatsHarness{
		assetUniverses: make([]*BaseUniverseTree, numAssets),
		universeLeaves: make([]*universe.IssuanceProof, numAssets),
		leafIndex:      make(map[asset.ID]*universe.IssuanceProof),
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

		assetUniverse, _ := newTestUniverseWithDb(t, db, id)
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
		ctx, u.assetUniverses[i].id, u.universeLeaves[i].MintingKey,
	)
	require.NoError(u.t, err)
}

func (u *uniStatsHarness) logSyncEventByIndex(i int) {
	ctx := context.Background()
	err := u.db.LogSyncEvent(
		ctx, u.assetUniverses[i].id, u.universeLeaves[i].MintingKey,
	)
	require.NoError(u.t, err)
}

func (u *uniStatsHarness) assertUniverseStatsEqual(t *testing.T,
	stats universe.AggregateStats) {

	uniStats, err := u.db.AggregateSyncStats(context.Background())
	require.NoError(t, err)

	require.Equal(t, uniStats, stats)
}

// TestUniverseStatsEvents tests that we're able to properly insert, and also
// fetch information related to universe sync related events.
func TestUniverseStatsEvents(t *testing.T) {
	t.Parallel()

	db := NewTestDB(t)

	statsDB, _ := newUniverseStatsWithDB(t, db.BaseDB)

	ctx := context.Background()

	const numAssets = 3

	sh := newUniStatsHarness(t, numAssets, db.BaseDB, statsDB)

	// Before we insert anything into the DB, we should have all zeroes for
	// the main set of stats.
	sh.assertUniverseStatsEqual(t, universe.AggregateStats{
		NumTotalAssets: 0,
		NumTotalProofs: 0,
		NumTotalSyncs:  0,
	})

	// Now that we have our assets, we'll insert a new sync event for each
	// asset above. We'll mark these each first as a new proof.
	for i := 0; i < numAssets; i++ {
		sh.logProofEventByIndex(i)
	}

	// We'll now query for the set of aggregate Universe stats. It should
	// show 3 assets, and one new proof for each of those assets.
	sh.assertUniverseStatsEqual(t, universe.AggregateStats{
		NumTotalAssets: numAssets,
		NumTotalProofs: numAssets,
		NumTotalSyncs:  0,
	})

	// Next, we'll simulate a new sync event for a random asset. If we
	// query again, then we should see that the number of proofs has
	// increased by one.
	assetToSync := rand.Int() % numAssets

	sh.logSyncEventByIndex(assetToSync)

	sh.assertUniverseStatsEqual(t, universe.AggregateStats{
		NumTotalAssets: numAssets,
		NumTotalProofs: numAssets,
		NumTotalSyncs:  1,
	})

	// We'll now query for the set of Universe events. There should be 4
	// total events: 3 new proofs, and one sync event. Each event should
	// match up with the set of items we inserted above.
	syncStats, err := statsDB.QuerySyncStats(
		ctx, universe.SyncStatsQuery{},
	)
	require.NoError(t, err)
	require.Len(t, syncStats.SyncStats, numAssets)

	// We should also be able to find summaries of each of the items above.
	// This should match the leaves we inserted above.
	for _, assetStat := range syncStats.SyncStats {
		leaf, ok := sh.leafIndex[assetStat.AssetID]
		require.True(t, ok)

		require.Equal(t, assetStat.TotalSupply, leaf.Leaf.Amt)

		if sh.universeLeaves[assetToSync].MintingKey ==
			leaf.MintingKey {

			require.Equal(t, int(assetStat.TotalSyncs), 1)
		}

		require.Equal(t, int(assetStat.TotalProofs), 1)
	}

	// Finally, we should be able to delete a universe and all associated
	// events.
	_, err = sh.assetUniverses[assetToSync].DeleteUniverse(ctx)
	require.NoError(t, err)

	sh.assertUniverseStatsEqual(t, universe.AggregateStats{
		NumTotalAssets: numAssets - 1,
		NumTotalProofs: numAssets - 1,
		NumTotalSyncs:  0,
	})
}

// TestUniverseQuerySyncStatsSorting tests that we're able to properly sort the
// response using any of the available params.
func TestUniverseQuerySyncStatsSorting(t *testing.T) {
	db := NewTestDB(t)

	statsDB, _ := newUniverseStatsWithDB(t, db.BaseDB)

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

	// sortCheck is used to generate an IsSorted func bound to the
	// response, for each sort type below.
	type sortCheck func([]universe.AssetSyncSnapshot) func(i, j int) bool

	// With the events above logged, we'll now make sure we can properly
	// retrieve each of the events by their sorted order.
	var tests = []struct {
		name         string
		sortType     universe.SyncStatsSort
		isSortedFunc sortCheck
	}{
		{
			name:     "asset name",
			sortType: universe.SortByAssetName,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
			) func(i, j int) bool {

				return func(i, j int) bool {
					return s[i].AssetName < s[j].AssetName
				}
			},
		},
		{
			name:     "asset type",
			sortType: universe.SortByAssetType,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
			) func(i, j int) bool {

				return func(i, j int) bool {
					return s[i].AssetType < s[j].AssetType
				}
			},
		},
		{
			name:     "asset id",
			sortType: universe.SortByAssetID,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
			) func(i, j int) bool {

				return func(i, j int) bool {
					return bytes.Compare(s[i].AssetID[:],
						s[j].AssetID[:]) < 0
				}
			},
		},
		{
			name:     "total sync",
			sortType: universe.SortByTotalSyncs,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
			) func(i, j int) bool {

				return func(i, j int) bool {
					return s[i].TotalSyncs < s[j].TotalSyncs
				}
			},
		},
		{
			name:     "total proofs",
			sortType: universe.SortByTotalProofs,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
			) func(i, j int) bool {

				return func(i, j int) bool {
					return s[i].TotalProofs <
						s[j].TotalProofs
				}
			},
		},
		{
			name:     "genesis height",
			sortType: universe.SortByGenesisHeight,
			isSortedFunc: func(s []universe.AssetSyncSnapshot,
			) func(i, j int) bool {

				return func(i, j int) bool {
					return s[i].GenesisHeight <
						s[j].GenesisHeight
				}
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			syncStats, err := statsDB.QuerySyncStats(
				ctx, universe.SyncStatsQuery{
					SortBy: testCase.sortType,
				},
			)
			require.NoError(t, err)
			require.Len(t, syncStats.SyncStats, numAssets)

			require.True(t, sort.SliceIsSorted(
				syncStats.SyncStats,
				testCase.isSortedFunc(syncStats.SyncStats),
			))
		})
	}
}

// TestUniverseQuerySyncFilters tests that we're able to properly fetch the
// asset snapshot for the set of assets given one or more of the possible
// filters.
func TestUniverseQuerySyncFilters(t *testing.T) {
	db := NewTestDB(t)

	statsDB, _ := newUniverseStatsWithDB(t, db.BaseDB)

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
					func(acc int, p *universe.IssuanceProof) int {
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
