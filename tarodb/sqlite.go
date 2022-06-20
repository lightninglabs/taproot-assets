package tarodb

import (
	"context"
	"database/sql"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	sqlite_migrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/httpfs"
	"github.com/lightninglabs/taro/tarodb/sqlite"

	_ "modernc.org/sqlite"
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
	db, err := sql.Open("sqlite", cfg.DatabaseFileName)
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
		if err := sqlMigrate.Up(); err != nil {
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

// newTestSqliteDB is a helper function that creates
func newTestSqliteDB(t *testing.T) (*SqliteStore, func()) {
	dir, err := ioutil.TempDir("", "sqlite-test-")
	if err != nil {
		t.Fatal(err)
	}

	// TODO(roasbeef): if we pass :memory: for the file name, then we get
	// an in mem version to speed up tests
	dbFileName := filepath.Join(dir, "tmp.db")
	sqlDB, err := NewSqliteStore(&SqliteConfig{
		DatabaseFileName: dbFileName,
		CreateTables:     true,
	})
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}

	cleanUp := func() {
		sqlDB.DB.Close()
		os.RemoveAll(dir)
	}

	return sqlDB, cleanUp
}
