//go:build !test_db_postgres

package tapdb

import (
	"testing"
)

const activeTestDB = "sqlite3"

// NewTestDB is a helper function that creates an SQLite database for testing.
func NewTestDB(t *testing.T) *SqliteStore {
	return NewTestSqliteDB(t)
}

// NewTestDbHandleFromPath is a helper function that creates a new handle to an
// existing SQLite database for testing.
func NewTestDbHandleFromPath(t *testing.T, dbPath string) *SqliteStore {
	return NewTestSqliteDbHandleFromPath(t, dbPath)
}

// NewDbHandleFromPath is a helper function that creates a new handle to an
// existing SQLite database for testing. This version returns an error if an
// issue is encountered during init.
func NewDbHandleFromPath(dbPath string) (*SqliteStore, error) {
	return NewSqliteDbHandleFromPath(dbPath)
}

// NewTestDBWithVersion is a helper function that creates an SQLite database for
// testing and migrates it to the given version.
func NewTestDBWithVersion(t *testing.T, version uint) *SqliteStore {
	return NewTestSqliteDBWithVersion(t, version)
}
