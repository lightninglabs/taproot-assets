package tapdb

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"math"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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

// UniverseStats is an implementation of the universe.Telemetry interface that
// is backed by the on-disk Universe event and MS-SMT tree store.
type UniverseStats struct {
	db BatchedUniverseStats

	clock clock.Clock
}

// NewUniverseStats creates a new instance of the UniverseStats backed by the
// database.
func NewUniverseStats(db BatchedUniverseStats,
	clock clock.Clock) *UniverseStats {

	return &UniverseStats{
		db:    db,
		clock: clock,
	}
}

// LogSyncEvent logs a sync event for the target universe.
func (u *UniverseStats) LogSyncEvent(ctx context.Context,
	uniID universe.Identifier, key universe.BaseKey) error {

	var writeTxOpts UniverseStatsOptions
	return u.db.ExecTx(ctx, &writeTxOpts, func(db UniverseStatsStore) error {
		var groupKeyXOnly []byte
		if uniID.GroupKey != nil {
			groupKeyXOnly = schnorr.SerializePubKey(uniID.GroupKey)
		}

		return db.InsertNewSyncEvent(ctx, NewSyncEvent{
			EventTime:      u.clock.Now(),
			EventTimestamp: u.clock.Now().UTC().Unix(),
			AssetID:        uniID.AssetID[:],
			GroupKeyXOnly:  groupKeyXOnly,
		})
	})
}

// LogNewProofEvent logs a new proof insertion event for the target universe.
func (u *UniverseStats) LogNewProofEvent(ctx context.Context,
	uniID universe.Identifier, key universe.BaseKey) error {

	var writeTxOpts UniverseStatsOptions
	return u.db.ExecTx(ctx, &writeTxOpts, func(db UniverseStatsStore) error {
		var groupKeyXOnly []byte
		if uniID.GroupKey != nil {
			groupKeyXOnly = schnorr.SerializePubKey(uniID.GroupKey)
		}

		return db.InsertNewProofEvent(ctx, NewProofEvent{
			EventTime:      u.clock.Now(),
			EventTimestamp: u.clock.Now().UTC().Unix(),
			AssetID:        uniID.AssetID[:],
			GroupKeyXOnly:  groupKeyXOnly,
		})
	})
}

// AggregateSyncStats returns stats aggregated over all assets within the
// Universe.
func (u *UniverseStats) AggregateSyncStats(
	ctx context.Context) (universe.AggregateStats, error) {

	var stats universe.AggregateStats

	readTx := NewUniverseStatsReadTx()
	err := u.db.ExecTx(ctx, &readTx, func(db UniverseStatsStore) error {
		uniStats, err := db.QueryUniverseStats(ctx)
		if err != nil {
			return err
		}

		stats.NumTotalAssets = uint64(uniStats.TotalNumAssets)

		// We'll need to do a type cast here as sqlite will give us a
		// NULL value as an int, while postgres will give us a "0"
		// string.
		switch numSyncs := uniStats.TotalSyncs.(type) {
		case int64:
			stats.NumTotalSyncs = uint64(numSyncs)

		case string:
			numSyncsInt, err := strconv.ParseInt(numSyncs, 10, 64)
			if err != nil {
				return fmt.Errorf("unable to parse total "+
					"syncs: %v", err)
			}

			stats.NumTotalSyncs = uint64(numSyncsInt)
		}

		switch numProofs := uniStats.TotalProofs.(type) {
		case int64:
			stats.NumTotalProofs = uint64(numProofs)

		case string:
			numProofsInt, err := strconv.ParseInt(numProofs, 10, 64)
			if err != nil {
				return fmt.Errorf("unable to parse total "+
					"proofs: %v", err)
			}

			stats.NumTotalProofs = uint64(numProofsInt)
		}

		return nil
	})
	if err != nil {
		return stats, err
	}

	return stats, nil
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

	default:
		return ""
	}
}

// QueryAssetStatsPerDay returns the stats for all assets grouped by day.
func (u *UniverseStats) QueryAssetStatsPerDay(ctx context.Context,
	q universe.GroupedStatsQuery) ([]*universe.GroupedStats, error) {

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

	readTx := NewUniverseStatsReadTx()
	err := u.db.ExecTx(ctx, &readTx, func(db UniverseStatsStore) error {
		// First, we'll map the external query to our SQL specific
		// struct. We'll need to use the proper null types so the query
		// works as expected.
		query := UniverseStatsQuery{
			AssetName: sqlStr(q.AssetNameFilter),
			AssetType: func() sql.NullInt16 {
				if q.AssetTypeFilter == nil {
					return sql.NullInt16{}
				}

				return sqlInt16(*q.AssetTypeFilter)
			}(),
			SortBy:    sqlStr(sortTypeToOrderBy(q.SortBy)),
			NumOffset: int32(q.Offset),
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

			resp.SyncStats = append(resp.SyncStats, stats)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

var _ universe.Telemetry = (*UniverseStats)(nil)
