package tarodb

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	sqlite_migrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/httpfs"
	"github.com/lightninglabs/taro/tarodb/sqlite"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite" // Register relevant drivers.
)

const (
	// sqliteOptionPrefix is the string prefix sqlite uses to set various
	// options. This is used in the following format:
	//   * sqliteOptionPrefix || option_name = option_value.
	sqliteOptionPrefix = "_pragma"
)

// SqliteConfig holds all the config arguments needed to interact with our
// sqlite DB.
type SqliteConfig struct {
	// CreateTables if true, then all the tables will be created on start
	// up if they don't already exist.
	CreateTables bool

	// DatabaseFileName is the full file path where the database file can be
	// found.
	DatabaseFileName string
}

// SqliteStore is a sqlite3 based database for the taro daemon.
//
// TODO(roasbeef): can type params out the main interface and db here to also
// support postgres?
type SqliteStore struct {
	cfg *SqliteConfig

	*sql.DB

	*sqlite.Queries
}

// NewSqliteStore attempts to open a new sqlite database based on the passed
// config.
func NewSqliteStore(cfg *SqliteConfig) (*SqliteStore, error) {
	// The set of pragma options are accepted using query options. For now
	// we only want to ensure that foreign key constraints are properly
	// enforced.
	pragmaOptions := []struct {
		name  string
		value string
	}{
		{
			name:  "foreign_keys",
			value: "on",
		},
		{
			name:  "journal_mode",
			value: "WAL",
		},
	}
	sqliteOptions := make(url.Values)
	for _, option := range pragmaOptions {
		sqliteOptions.Add(
			sqliteOptionPrefix,
			fmt.Sprintf("%v=%v", option.name, option.value),
		)
	}

	// Construct the DSN which is just the database file name, appended
	// with the series of pragma options as a query URL string. For more
	// details on the formatting here, see the modernc.org/sqlite docs:
	// https://pkg.go.dev/modernc.org/sqlite#Driver.Open.
	dsn := fmt.Sprintf(
		"%v?%v", cfg.DatabaseFileName, sqliteOptions.Encode(),
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	if cfg.CreateTables {
		// Now that the database is open, populate the database with
		// our set of schemas based on our embedded in-memory file
		// system.
		//
		// First, we'll need to open up a new migration instance for
		// our current target database: sqlite.
		driver, err := sqlite_migrate.WithInstance(
			db, &sqlite_migrate.Config{},
		)
		if err != nil {
			return nil, err
		}

		// With the migrate instance open, we'll create a new migration
		// source using the embedded file system stored in sqlSchemas.
		// The library we're using can't handle a raw file system
		// interface, so we wrap it in this intermediate layer.
		migrateFileServer, err := httpfs.New(
			http.FS(sqlSchemas), "sqlite/migrations",
		)
		if err != nil {
			return nil, err
		}

		// Finally, we'll run the migration with our driver above based
		// on the open DB, and also the migration source stored in the
		// file system above.
		sqlMigrate, err := migrate.NewWithInstance(
			"migrations", migrateFileServer, "sqlite", driver,
		)
		if err != nil {
			return nil, err
		}
		err = sqlMigrate.Up()
		if err != nil && err != migrate.ErrNoChange {
			return nil, err
		}
	}

	queries := sqlite.New(db)

	return &SqliteStore{
		DB:      db,
		cfg:     cfg,
		Queries: queries,
	}, nil
}

// BeginTx wraps the normal sql specific BeginTx method with the TxOptions
// interface. This interface is then mapped to the concrete sql tx options
// struct.
func (s *SqliteStore) BeginTx(ctx context.Context, opts TxOptions) (Tx, error) {
	sqlOptions := sql.TxOptions{
		ReadOnly: opts.ReadOnly(),
	}
	return s.DB.BeginTx(ctx, &sqlOptions)
}

// NewTestSqliteDB is a helper function that creates
func NewTestSqliteDB(t *testing.T) *SqliteStore {
	// TODO(roasbeef): if we pass :memory: for the file name, then we get
	// an in mem version to speed up tests
	dbFileName := filepath.Join(t.TempDir(), "tmp.db")
	sqlDB, err := NewSqliteStore(&SqliteConfig{
		DatabaseFileName: dbFileName,
		CreateTables:     true,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, sqlDB.DB.Close())
	})

	return sqlDB
}
