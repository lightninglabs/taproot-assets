//go:build test_db_postgres

package tapdb

import (
	"testing"
)

// NewTestDB is a helper function that creates a Postgres database for testing.
func NewTestDB(t *testing.T) *PostgresStore {
	return NewTestPostgresDB(t)
}

// NewTestDbHandleFromPath is a helper function that creates a new handle to an
// existing SQLite database for testing.
func NewTestDbHandleFromPath(t *testing.T, dbPath string) *PostgresStore {
	return NewTestPostgresDB(t)
}

// NewTestDBWithVersion is a helper function that creates a Postgres database
// for testing and migrates it to the given version.
func NewTestDBWithVersion(t *testing.T, version uint) *PostgresStore {
	return NewTestPostgresDBWithVersion(t, version)
}
