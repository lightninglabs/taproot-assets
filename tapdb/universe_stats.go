package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/neutrino/cache/lru"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/clock"
)

type (
	// NewProofEvent is used to create a new event that logs insertion of a
	// new proof.
	NewProofEvent = sqlc.InsertNewProofEventParams

	// NewSyncEvent is used to create a new event that logs a new Universe
	// leaf sync.
	NewSyncEvent = sqlc.InsertNewSyncEventParams

	// UniverseStatsQuery is used to query the stats for a given universe.
	UniverseStatsQuery = sqlc.QueryUniverseAssetStatsParams

	// UniverseStatsResp is used to return the stats for a given universe.
	UniverseStatsResp = sqlc.QueryUniverseAssetStatsRow

	// AggregateStats is used to return the aggregate stats for the entire
	// Universe.
	AggregateStats = sqlc.QueryUniverseStatsRow

	// AssetStatsPerDay is the assets stats record for a given day.
	AssetStatsPerDay = sqlc.QueryAssetStatsPerDaySqliteRow

	// AssetStatsPerDayPg is the assets stats record for a given day (for
	// Postgres).
	AssetStatsPerDayPg = sqlc.QueryAssetStatsPerDayPostgresRow

	// AssetStatsPerDayQuery is the query used to fetch the asset stats for
	// a given day.
	AssetStatsPerDayQuery = sqlc.QueryAssetStatsPerDaySqliteParams

	// AssetStatsPerDayQueryPg is the query used to fetch the asset stats
	// for a given day (for Postgres).
	AssetStatsPerDayQueryPg = sqlc.QueryAssetStatsPerDayPostgresParams
)

// UniverseStatsStore is an interface that defines the methods required to
// implement the universe.Telemetry interface.
type UniverseStatsStore interface {
	// InsertNewProofEvent inserts a new proof event into the database.
	InsertNewProofEvent(ctx context.Context, arg NewProofEvent) error

	// InsertNewSyncEvent inserts a new sync event into the database.
	InsertNewSyncEvent(ctx context.Context, arg NewSyncEvent) error

	// QueryUniverseStats returns the aggregated stats for the entire
	QueryUniverseStats(ctx context.Context) (AggregateStats, error)

	// QueryUniverseAssetStats returns the stats for a given asset within a
	// universe/
	QueryUniverseAssetStats(ctx context.Context,
		arg UniverseStatsQuery) ([]UniverseStatsResp, error)

	// QueryAssetStatsPerDaySqlite returns the stats for a given asset
	// grouped by day in a SQLite specific format.
	QueryAssetStatsPerDaySqlite(ctx context.Context,
		q AssetStatsPerDayQuery) ([]AssetStatsPerDay, error)

	// QueryAssetStatsPerDayPostgres returns the stats for a given asset
	// grouped by day in a Postgres specific format.
	QueryAssetStatsPerDayPostgres(ctx context.Context,
		q AssetStatsPerDayQueryPg) ([]AssetStatsPerDayPg, error)
}

// UniverseStatsOptions defines the set of txn options for the universe stats.
type UniverseStatsOptions struct {
	readOnly bool
}

// ReadOnly returns true if the transaction is read-only.
func (u *UniverseStatsOptions) ReadOnly() bool {
	return u.readOnly
}

// NewUniverseStatsReadTx creates a new read-only transaction for the universe
// stats instance.
func NewUniverseStatsReadTx() UniverseStatsOptions {
	return UniverseStatsOptions{
		readOnly: true,
	}
}

// BatchedUniverseStats is a wrapper around the set of UniverseSyncEvents that
// supports batched DB operations.
type BatchedUniverseStats interface {
	UniverseStatsStore

	BatchedTx[UniverseStatsStore]
}

// eventQuery is used to query for events within a given time range.
type eventQuery struct {
	// startTime is the start time of the query.
	startTime int64

	// endTime is the end time of the query.
	endTime int64
}

// eventQueryBucket is the interval that we'll use to bucket similar queries
// into.
const eventQueryBucket = time.Hour

// newEventQuery creates a new event query from the given query.
func newEventQuery(q universe.GroupedStatsQuery) eventQuery {
	// For both the start and time time, we'll round down to the nearest
	// hour. This'll serve to bucket queries into hourly buckets.
	startTime := q.StartTime.UTC().Truncate(eventQueryBucket).Unix()
	endTime := q.EndTime.UTC().Truncate(eventQueryBucket).Unix()

	return eventQuery{
		startTime: startTime,
		endTime:   endTime,
	}
}

// cachedAssetEvents is a cached set of asset events.
type cachedAssetEvents []*universe.GroupedStats

// Size returns the number of events cached for this value.
func (c cachedAssetEvents) Size() (uint64, error) {
	return uint64(len(c)), nil
}

// eventQueryCacheSize is the total number of queries that we'll cache.
const eventQueryCacheSize = 1000

// assetEventCache is a cache of queries into a timeslice of the set of asset
// events.
type assetEventsCache = *lru.Cache[eventQuery, cachedAssetEvents]

// statsQueryCacheSize is the total number of asset query responses that we'll
// hold inside the cache.
const statsQueryCacheSize = 80_000

// cachedSyncStats is a cached set of sync stats.
type cachedSyncStats []universe.AssetSyncSnapshot

// Size returns the number of events cached for this value. We'll have the
// cache be limited by the number of assets returned for each query.
func (c cachedSyncStats) Size() (uint64, error) {
	return uint64(len(c)), nil
}

// syncStatsQuery is a wrapper around the SyncStatsQuery that uses an explicit
// value for the asset type. This enables is to properly use it as a cache key.
type syncStatsQuery struct {
	universe.SyncStatsQuery

	assetType asset.Type
}

// syncStatsCache is a cache of queries into the set of sync stats.
type syncStatsCache = lru.Cache[syncStatsQuery, cachedSyncStats]

// atomicAssetEventsCache is an atomic wrapper around the asset events cache.
type atomicSyncStatsCache struct {
	atomic.Pointer[syncStatsCache]

	*cacheLogger
}

func newAtomicSyncStatsCache() *atomicSyncStatsCache {
	return &atomicSyncStatsCache{
		cacheLogger: newCacheLogger("sync stats"),
	}
}

// wipe can be used to both wipe and init the stats cache.
func (a *atomicSyncStatsCache) wipe() {
	statsCache := lru.NewCache[syncStatsQuery, cachedSyncStats](
		statsQueryCacheSize,
	)

	a.Store(statsCache)
}

// fetchQuery attempts to fetch the query from the cache.
func (a *atomicSyncStatsCache) fetchQuery(q universe.SyncStatsQuery,
) cachedSyncStats {

	assetType := func() asset.Type {
		if q.AssetTypeFilter != nil {
			return *q.AssetTypeFilter
		}

		return asset.Type(math.MaxUint8)
	}()

	newQuery := q

	// Set this to nil so the map doesn't try to use the memory address as
	// part of the key.
	newQuery.AssetTypeFilter = nil

	// First make the wrapper around the struct, using a value of the max
	// asset type to signal that no asset type was requested.
	query := syncStatsQuery{
		SyncStatsQuery: newQuery,
		assetType:      assetType,
	}

	// Now, we'll attempt to fetch the query from the cache.
	statsCache := a.Load()
	if statsCache == nil {
		a.Miss()
		return nil
	}

	cachedResult, err := statsCache.Get(query)
	if err == nil {
		a.Hit()
		return cachedResult
	}

	a.Miss()

	return nil
}

// storeQuery stores the given query in the cache.
func (a *atomicSyncStatsCache) storeQuery(q universe.SyncStatsQuery,
	resp []universe.AssetSyncSnapshot) {

	assetType := func() asset.Type {
		if q.AssetTypeFilter != nil {
			return *q.AssetTypeFilter
		}

		return asset.Type(math.MaxUint8)
	}()

	newQuery := q

	// Set this to nil so the map doesn't try to use the memory address as
	// part of the key.
	newQuery.AssetTypeFilter = nil

	// First make the wrapper around the struct, using a value of the max
	// asset type to signal that no asset type was requested.
	query := syncStatsQuery{
		SyncStatsQuery: newQuery,
		assetType:      assetType,
	}

	statsCache := a.Load()

	log.Debugf("Storing asset stats query: %v", spew.Sdump(q))

	_, _ = statsCache.Put(query, cachedSyncStats(resp))
}

// UniverseStats is an implementation of the universe.Telemetry interface that
// is backed by the on-disk Universe event and MS-SMT tree store.
type UniverseStats struct {
	opts statsOpts

	db BatchedUniverseStats

	clock clock.Clock

	statsMtx         sync.Mutex
	statsSnapshot    atomic.Pointer[universe.AggregateStats]
	statsCacheLogger *cacheLogger
	statsRefresh     *time.Timer

	eventsMtx         sync.Mutex
	assetEventsCache  assetEventsCache
	eventsCacheLogger *cacheLogger

	syncStatsMtx     sync.Mutex
	syncStatsCache   *atomicSyncStatsCache
	syncStatsRefresh *time.Timer
}

// statsOpts defines the set of options that can be used to configure the
// universe stats db.
type statsOpts struct {
	// cacheDuration is the duration that the stats will be cached for.
	cacheDuration time.Duration
}

// UniverseStatOption is a functional option that can be used to modify the way
// that the UniverseStats struct is created.
type UniverseStatsOption func(*statsOpts)

// defaultStatsOpts returns a set of default options for the universe stats.
func defaultStatsOpts() statsOpts {
	return statsOpts{
		cacheDuration: StatsCacheDuration,
	}
}

// WithStatsCacheDuration is a functional option that can be used to set the
// amount of time the stats are cached for.
func WithStatsCacheDuration(d time.Duration) UniverseStatsOption {
	return func(o *statsOpts) {
		o.cacheDuration = d
	}
}

// NewUniverseStats creates a new instance of the UniverseStats backed by the
// database.
func NewUniverseStats(db BatchedUniverseStats, clock clock.Clock,
	options ...UniverseStatsOption) *UniverseStats {

	opts := defaultStatsOpts()
	for _, o := range options {
		o(&opts)
	}

	atomicStatsCache := newAtomicSyncStatsCache()
	atomicStatsCache.wipe()

	return &UniverseStats{
		db:               db,
		clock:            clock,
		opts:             opts,
		statsCacheLogger: newCacheLogger("total_universe_stats"),
		assetEventsCache: lru.NewCache[eventQuery, cachedAssetEvents](
			eventQueryCacheSize,
		),
		eventsCacheLogger: newCacheLogger("universe_asset_events"),
		syncStatsCache:    atomicStatsCache,
	}
}

// LogSyncEvent logs a sync event for the target universe.
func (u *UniverseStats) LogSyncEvent(ctx context.Context,
	uniID universe.Identifier, key universe.LeafKey) error {

	var writeTxOpts UniverseStatsOptions
	return u.db.ExecTx(ctx, &writeTxOpts, func(db UniverseStatsStore) error {
		var groupKeyXOnly []byte
		if uniID.GroupKey != nil {
			groupKeyXOnly = schnorr.SerializePubKey(uniID.GroupKey)
		}

		return db.InsertNewSyncEvent(ctx, NewSyncEvent{
			EventTime:      u.clock.Now().UTC(),
			EventTimestamp: u.clock.Now().UTC().Unix(),
			AssetID:        uniID.AssetID[:],
			GroupKeyXOnly:  groupKeyXOnly,
			ProofType:      uniID.ProofType.String(),
		})
	})
}

// LogSyncEvents logs sync events for the target universe.
func (u *UniverseStats) LogSyncEvents(ctx context.Context,
	uniIDs ...universe.Identifier) error {

	var writeOpts UniverseStatsOptions
	return u.db.ExecTx(ctx, &writeOpts, func(db UniverseStatsStore) error {
		for idx := range uniIDs {
			uniID := uniIDs[idx]

			var groupKeyXOnly []byte
			if uniID.GroupKey != nil {
				groupKeyXOnly = schnorr.SerializePubKey(
					uniID.GroupKey,
				)
			}

			err := db.InsertNewSyncEvent(ctx, NewSyncEvent{
				EventTime:      u.clock.Now().UTC(),
				EventTimestamp: u.clock.Now().UTC().Unix(),
				AssetID:        uniID.AssetID[:],
				GroupKeyXOnly:  groupKeyXOnly,
				ProofType:      uniID.ProofType.String(),
			})
			if err != nil {
				return err
			}
		}

		return nil
	})
}

// LogNewProofEvent logs a new proof insertion event for the target universe.
func (u *UniverseStats) LogNewProofEvent(ctx context.Context,
	uniID universe.Identifier, key universe.LeafKey) error {

	var writeTxOpts UniverseStatsOptions
	return u.db.ExecTx(ctx, &writeTxOpts, func(db UniverseStatsStore) error {
		var groupKeyXOnly []byte
		if uniID.GroupKey != nil {
			groupKeyXOnly = schnorr.SerializePubKey(uniID.GroupKey)
		}

		return db.InsertNewProofEvent(ctx, NewProofEvent{
			EventTime:      u.clock.Now().UTC(),
			EventTimestamp: u.clock.Now().UTC().Unix(),
			AssetID:        uniID.AssetID[:],
			GroupKeyXOnly:  groupKeyXOnly,
			ProofType:      uniID.ProofType.String(),
		})
	})
}

// LogNewProofEvents logs new proof insertion events for the target universe.
func (u *UniverseStats) LogNewProofEvents(ctx context.Context,
	uniIDs ...universe.Identifier) error {

	var writeTxOpts UniverseStatsOptions
	return u.db.ExecTx(ctx, &writeTxOpts, func(db UniverseStatsStore) error {
		for idx := range uniIDs {
			uniID := uniIDs[idx]
			var groupKeyXOnly []byte
			if uniID.GroupKey != nil {
				groupKeyXOnly = schnorr.SerializePubKey(
					uniID.GroupKey,
				)
			}

			err := db.InsertNewProofEvent(ctx, NewProofEvent{
				EventTime:      u.clock.Now().UTC(),
				EventTimestamp: u.clock.Now().UTC().Unix(),
				AssetID:        uniID.AssetID[:],
				GroupKeyXOnly:  groupKeyXOnly,
				ProofType:      uniID.ProofType.String(),
			})
			if err != nil {
				return err
			}
		}

		return nil
	})
}

// querySyncStats is a helper function that's used to query the sync stats for
// the Universe db.
func (u *UniverseStats) querySyncStats(ctx context.Context,
) (universe.AggregateStats, error) {

	var dbStats universe.AggregateStats

	readTx := NewUniverseStatsReadTx()
	err := u.db.ExecTx(ctx, &readTx, func(db UniverseStatsStore) error {
		uniStats, err := db.QueryUniverseStats(ctx)
		if err != nil {
			return err
		}

		// We'll need to do a type cast here as sqlite will give us a
		// NULL value as an int, while postgres will give us a "0"
		// string.
		dbStats.NumTotalSyncs, err = parseCoalesceNumericType[uint64](
			uniStats.TotalSyncs,
		)
		if err != nil {
			return err
		}
		dbStats.NumTotalProofs, err = parseCoalesceNumericType[uint64](
			uniStats.TotalProofs,
		)
		if err != nil {
			return err
		}
		dbStats.NumTotalGroups, err = parseCoalesceNumericType[uint64](
			uniStats.TotalNumGroups,
		)
		if err != nil {
			return err
		}
		dbStats.NumTotalAssets, err = parseCoalesceNumericType[uint64](
			uniStats.TotalNumAssets,
		)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return universe.AggregateStats{}, err
	}

	return dbStats, nil
}

// populateSyncStatsCache is used to populate the sync stats cache
// periodically.
//
// NOTE: This MUST be run as the call back of a time.AfterFunc.
func (u *UniverseStats) populateSyncStatsCache() {
	log.Infof("Refreshing stats cache, duration=%v", u.opts.cacheDuration)

	// If this is a test, then we'll just purge the items.
	if u.opts.cacheDuration == 0 {
		log.Debugf("nil state cache duration, wiping cache")
		u.statsSnapshot.Store(nil)
		return
	}

	now := time.Now()

	// To ensure the stats endpoint is always available, we'll repopulate
	// it async ourselves here. This ensures after the first miss, the
	// stats are always populated.
	ctx := context.Background()
	dbStats, err := u.querySyncStats(ctx)
	if err != nil {
		log.Warnf("Unable to refresh stats cache: %v", err)
		return
	}

	log.Debugf("Refreshed stats cache, interval=%v, took=%v",
		u.opts.cacheDuration, time.Since(now))

	u.statsSnapshot.Store(&dbStats)

	// Reset the timer so we'll refresh again after the cache duration.
	if !u.statsRefresh.Stop() {
		select {
		case <-u.statsRefresh.C:
		default:
		}
	}

	u.statsRefresh.Reset(u.opts.cacheDuration)
}

// AggregateSyncStats returns stats aggregated over all assets within the
// Universe.
func (u *UniverseStats) AggregateSyncStats(
	ctx context.Context) (universe.AggregateStats, error) {

	stats := u.statsSnapshot.Load()
	if stats != nil {
		u.statsCacheLogger.Hit()
		return *stats, nil
	}

	u.statsMtx.Lock()
	defer u.statsMtx.Unlock()

	// Check to see if the stats were loaded in while we were waiting for
	// the mutex.
	stats = u.statsSnapshot.Load()
	if stats != nil {
		u.statsCacheLogger.Hit()
		return *stats, nil
	}

	u.statsCacheLogger.Miss()

	log.Debugf("Populating aggregate sync stats")

	dbStats, err := u.querySyncStats(ctx)
	if err != nil {
		return dbStats, err
	}

	// We'll store the DB stats then start our time after function to wipe
	// the stats pointer so we'll refresh it after a period of time.
	u.statsSnapshot.Store(&dbStats)

	// Reset the timer so we'll refresh again after the cache duration.
	if u.statsRefresh != nil && !u.statsRefresh.Stop() {
		select {
		case <-u.statsRefresh.C:
		default:
		}
	}
	u.statsRefresh = time.AfterFunc(
		u.opts.cacheDuration, u.populateSyncStatsCache,
	)

	return dbStats, nil
}

// sortTypeToOrderBy converts the given sort type to the corresponding SQL
// order by param name.
func sortTypeToOrderBy(s universe.SyncStatsSort) string {
	switch s {
	case universe.SortByAssetName:
		return "asset_name"

	case universe.SortByAssetType:
		return "asset_type"

	case universe.SortByAssetID:
		return "asset_id"

	case universe.SortByTotalSyncs:
		return "total_syncs"

	case universe.SortByTotalProofs:
		return "total_proofs"

	case universe.SortByGenesisHeight:
		return "genesis_height"

	case universe.SortByTotalSupply:
		return "total_supply"

	default:
		return ""
	}
}

// QueryAssetStatsPerDay returns the stats for all assets grouped by day.
func (u *UniverseStats) QueryAssetStatsPerDay(ctx context.Context,
	q universe.GroupedStatsQuery) ([]*universe.GroupedStats, error) {

	// First, we'll check to see if we already have a cached result for
	// this query.
	query := newEventQuery(q)
	cachedResult, err := u.assetEventsCache.Get(query)
	if err == nil {
		u.eventsCacheLogger.Hit()
		return cachedResult, nil
	}

	// Otherwise, we'll go to query the DB, then cache the result.
	u.eventsMtx.Lock()
	defer u.eventsMtx.Unlock()

	// Check to see if the cache was populated while we were waiting on the
	// mutex.
	cachedResult, err = u.assetEventsCache.Get(query)
	if err == nil {
		u.eventsCacheLogger.Hit()
		return cachedResult, nil
	}

	u.eventsCacheLogger.Miss()

	var (
		readTx  = NewUniverseStatsReadTx()
		results []*universe.GroupedStats
	)
	dbErr := u.db.ExecTx(ctx, &readTx, func(db UniverseStatsStore) error {
		switch u.db.Backend() {
		case sqlc.BackendTypeSqlite:
			var err error
			stats, err := db.QueryAssetStatsPerDaySqlite(
				ctx, AssetStatsPerDayQuery{
					StartTime: q.StartTime.UTC().Unix(),
					EndTime:   q.EndTime.UTC().Unix(),
				},
			)
			if err != nil {
				return err
			}

			results = make([]*universe.GroupedStats, len(stats))
			for idx := range stats {
				s := stats[idx]
				results[idx] = &universe.GroupedStats{
					Date: s.Day,
					AggregateStats: universe.AggregateStats{
						NumTotalSyncs: uint64(
							s.SyncEvents,
						),
						NumTotalProofs: uint64(
							s.NewProofEvents,
						),
					},
				}
			}

			return nil

		case sqlc.BackendTypePostgres:
			stats, err := db.QueryAssetStatsPerDayPostgres(
				ctx, AssetStatsPerDayQueryPg{
					StartTime: q.StartTime.UTC().Unix(),
					EndTime:   q.EndTime.UTC().Unix(),
				},
			)
			if err != nil {
				return err
			}

			results = make([]*universe.GroupedStats, len(stats))
			for idx := range stats {
				s := stats[idx]
				results[idx] = &universe.GroupedStats{
					Date: s.Day,
					AggregateStats: universe.AggregateStats{
						NumTotalSyncs: uint64(
							s.SyncEvents,
						),
						NumTotalProofs: uint64(
							s.NewProofEvents,
						),
					},
				}
			}

			return nil

		default:
			return fmt.Errorf("unknown backend type: %v",
				u.db.Backend())
		}
	})
	if dbErr != nil {
		return nil, dbErr
	}

	// We have a fresh result, so we'll cache it now.
	_, _ = u.assetEventsCache.Put(query, results)

	return results, nil
}

// QuerySyncStats attempts to query the stats for the target universe.  For a
// given asset ID, tag, or type, the set of universe stats is returned which
// lists information such as the total number of syncs and known proofs for a
// given Universe server instance.
func (u *UniverseStats) QuerySyncStats(ctx context.Context,
	q universe.SyncStatsQuery) (*universe.AssetSyncStats, error) {

	resp := &universe.AssetSyncStats{
		Query: q,
	}

	// First, check the cache to see if we already have a cached result for
	// this query.
	syncSnapshots := u.syncStatsCache.fetchQuery(q)
	if syncSnapshots != nil {
		resp.SyncStats = syncSnapshots
		return resp, nil
	}

	// Otherwise, we'll grab the main mutex so we can qury the db then
	// cache the result.
	u.syncStatsMtx.Lock()
	defer u.syncStatsMtx.Unlock()

	// Check again to see if the value was loaded in while we were waiting.
	syncSnapshots = u.syncStatsCache.fetchQuery(q)
	if syncSnapshots != nil {
		resp.SyncStats = syncSnapshots
		return resp, nil
	}

	// First, we'll map the external query to our SQL specific struct.
	// We'll need to use the proper null types so the query works as
	// expected.
	query := UniverseStatsQuery{
		AssetName: sqlStr(q.AssetNameFilter),
		AssetType: func() sql.NullInt16 {
			if q.AssetTypeFilter == nil {
				return sql.NullInt16{}
			}

			return sqlInt16(*q.AssetTypeFilter)
		}(),
		SortBy:        sqlStr(sortTypeToOrderBy(q.SortBy)),
		SortDirection: sqlInt16(q.SortDirection),
		NumOffset:     int32(q.Offset),
		NumLimit: func() int32 {
			if q.Limit == 0 {
				return int32(math.MaxInt32)
			}

			return int32(q.Limit)
		}(),
	}

	// In order for the narg clause to work properly, we'll only
	// apply the asset ID if it's set.
	var zeroID asset.ID
	if q.AssetIDFilter != zeroID {
		query.AssetID = q.AssetIDFilter[:]
	}

	readTx := NewUniverseStatsReadTx()
	err := u.db.ExecTx(ctx, &readTx, func(db UniverseStatsStore) error {
		// With the query constructed above, we'll now query the DB for
		// the set of stats for each universe.
		assetStats, err := db.QueryUniverseAssetStats(ctx, query)
		if err != nil {
			return err
		}

		resp.SyncStats = make(
			[]universe.AssetSyncSnapshot, 0, len(assetStats),
		)

		for _, assetStat := range assetStats {
			stats := universe.AssetSyncSnapshot{
				TotalSupply: uint64(assetStat.AssetSupply),
				AssetID: fn.ToArray[asset.ID](
					assetStat.AssetID,
				),
				AssetName: assetStat.AssetName,
				AssetType: asset.Type(assetStat.AssetType),
				GenesisHeight: uint32(
					assetStat.GenesisHeight.Int32,
				),
				TotalSyncs:  uint64(assetStat.TotalSyncs),
				TotalProofs: uint64(assetStat.TotalProofs),
				GroupSupply: uint64(assetStat.GroupSupply.Int64),
			}

			if len(assetStat.GroupKey) > 0 {
				stats.GroupKey, err = btcec.ParsePubKey(
					assetStat.GroupKey,
				)
				if err != nil {
					return err
				}
			}

			if err := readOutPoint(
				bytes.NewReader(assetStat.GenesisPrevOut), 0, 0,
				&stats.GenesisPoint,
			); err != nil {
				return fmt.Errorf("unable to read outpoint: %w",
					err)
			}

			hash, err := chainhash.NewHash(assetStat.AnchorTxid[:])
			if err != nil {
				return err
			}

			stats.AnchorPoint = wire.OutPoint{
				Hash:  *hash,
				Index: uint32(assetStat.AnchorIndex),
			}

			resp.SyncStats = append(resp.SyncStats, stats)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Now we'll insert the result in the cache.
	u.syncStatsCache.storeQuery(q, resp.SyncStats)

	// Finally, we'll create the time after function that'll wipe the
	// cache, forcing a refresh.
	//
	// If we already have a timer active, then stop it, so we only have a
	// single timer going at any given time.
	if u.syncStatsRefresh != nil && !u.syncStatsRefresh.Stop() {
		select {
		case <-u.syncStatsRefresh.C:
		default:
		}
	}

	u.syncStatsRefresh = time.AfterFunc(u.opts.cacheDuration, func() {
		log.Infof("Purging sync stats cache, duration=%v",
			u.opts.cacheDuration)

		u.syncStatsCache.wipe()
	})

	return resp, nil
}

var _ universe.Telemetry = (*UniverseStats)(nil)
