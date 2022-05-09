package tarodb

import (
	"context"
	"database/sql"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/lightninglabs/taro/tarodb/sqlite"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// SqliteConfig holds all the config arguments needed to interact with our
// sqlite DB.
type SqliteConfig struct {
	// DatabaseFileName is the full file path where the database file can be
	// found.
	DatabaseFileName string
}

// SqliteStore is the
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
	})
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}

	cleanUp := func() {
		sqlDB.DB.Close()
		os.RemoveAll(dir)
	}

	// Now that the database is open, populate the database with our set of
	// schemas.
	schemas, err := filepath.Glob("sqlite/migrations/*.up.sql")
	require.NoError(t, err)
	for _, schemaFile := range schemas {
		blob, err := os.ReadFile(schemaFile)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sqlDB.DB.Exec(string(blob)); err != nil {
			t.Fatalf("%s: %s", filepath.Base(schemaFile), err)
		}
	}

	return sqlDB, cleanUp
}
