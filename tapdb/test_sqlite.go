//go:build !test_db_postgres

package tapdb

import (
	"testing"
)

// NewTestDB is a helper function that creates an SQLite database for testing.
func NewTestDB(t testing.TB) *SqliteStore {
	return NewTestSqliteDB(t)
}

// NewTestDbHandleFromPath is a helper function that creates a new handle to an
// existing SQLite database for testing.
func NewTestDbHandleFromPath(t testing.TB, dbPath string) *SqliteStore {
	return NewTestSqliteDbHandleFromPath(t, dbPath)
}

// NewTestDBWithVersion is a helper function that creates an SQLite database for
// testing and migrates it to the given version.
func NewTestDBWithVersion(t testing.TB, version uint) *SqliteStore {
	return NewTestSqliteDBWithVersion(t, version)
}
