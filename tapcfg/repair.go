package tapcfg

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightningnetwork/lnd/signal"
)

// RunRepairTool inspects the configured database for batches that
// violate the singleton "≤ 1 in {Pending, Frozen}" invariant added
// in migration 000060, and cancels all but the most recent. The
// preserved batch is the one with the latest CreationTime; cancelled
// batches transition to BatchStateSeedlingCancelled, leaving their
// row and seedlings on disk for later inspection.
//
// The function opens the database with migrations skipped, so it can
// run against a legacy database whose state would otherwise fail the
// migration.
//
// NOTE: With migration 000061's self-heal in place, restarting tapd
// normally will cancel the duplicates as part of applying the
// migration. This tool is retained as a diagnostic that surfaces the
// same repair outside the migration stream (e.g. after operator
// intervention that re-introduces duplicates).
func RunRepairTool(cfg *Config, cfgLogger btclog.Logger,
	shutdownInterceptor signal.Interceptor) error {

	// Derive a cancellable context that trips on shutdown. Without
	// this, a Ctrl+C mid-repair would leave partial state behind
	// (some batches cancelled, others not).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-shutdownInterceptor.ShutdownChannel():
			cancel()
		case <-ctx.Done():
		}
	}()

	// Open the database with migrations skipped. We want to inspect
	// and repair a database whose state would otherwise prevent
	// migration 000060 from applying; running migrations as part of
	// opening the DB would defeat the purpose.
	var (
		db  tapdb.DatabaseBackend
		err error
	)
	switch cfg.DatabaseBackend {
	case DatabaseBackendSqlite:
		sqliteCfg := *cfg.Sqlite
		sqliteCfg.SkipMigrations = true
		cfgLogger.Infof("repair: opening sqlite3 database at %v "+
			"(migrations skipped)",
			sqliteCfg.DatabaseFileName)
		db, err = tapdb.NewSqliteStore(&sqliteCfg)

	case DatabaseBackendPostgres:
		pgCfg := *cfg.Postgres
		pgCfg.SkipMigrations = true
		cfgLogger.Infof("repair: opening postgres database " +
			"(migrations skipped)")
		db, err = tapdb.NewPostgresStore(&pgCfg)

	default:
		return fmt.Errorf("unknown database backend: %s",
			cfg.DatabaseBackend)
	}
	if err != nil {
		return fmt.Errorf("repair: unable to open database: %w", err)
	}

	mintingExec := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.PendingAssetStore {
			return db.WithTx(tx)
		},
	)
	store := tapdb.NewAssetMintingStore(mintingExec)

	nonFinal, err := store.FetchNonFinalBatches(ctx)
	if err != nil {
		return fmt.Errorf("repair: unable to fetch non-final "+
			"batches: %w", err)
	}

	var preBroadcast []*tapgarden.MintingBatch
	for _, batch := range nonFinal {
		switch batch.State() {
		case tapgarden.BatchStatePending,
			tapgarden.BatchStateFrozen:

			preBroadcast = append(preBroadcast, batch)

		default:
			// Only pre-broadcast states are constrained by
			// the singleton index; ignore everything else.
		}
	}

	if len(preBroadcast) <= 1 {
		cfgLogger.Infof("repair: nothing to do; found %d batches "+
			"in pre-broadcast state", len(preBroadcast))
		return nil
	}

	// Sort newest-first by CreationTime; preserve [0], cancel the
	// rest. SliceStable gives a deterministic winner when two
	// batches share a timestamp -- the input order (from
	// FetchNonFinalBatches) then acts as the tiebreak.
	sort.SliceStable(preBroadcast, func(i, j int) bool {
		return preBroadcast[i].CreationTime.After(
			preBroadcast[j].CreationTime,
		)
	})

	preserved := preBroadcast[0]
	cfgLogger.Infof("repair: preserving most recent pre-broadcast "+
		"batch %x (state=%v, created=%s)",
		preserved.BatchKey.PubKey.SerializeCompressed(),
		preserved.State(),
		preserved.CreationTime.Format(time.RFC3339))

	for _, batch := range preBroadcast[1:] {
		cfgLogger.Warnf("repair: cancelling pre-broadcast batch "+
			"%x (state=%v, created=%s)",
			batch.BatchKey.PubKey.SerializeCompressed(),
			batch.State(),
			batch.CreationTime.Format(time.RFC3339))

		err := store.UpdateBatchState(
			ctx, batch, tapgarden.BatchStateSeedlingCancelled,
		)
		if err != nil {
			return fmt.Errorf("repair: unable to cancel batch "+
				"%x: %w",
				batch.BatchKey.PubKey.SerializeCompressed(),
				err)
		}
	}

	cfgLogger.Infof("repair: complete; cancelled %d duplicate "+
		"batches, preserved 1.", len(preBroadcast)-1)
	return nil
}
