//go:build test_db_postgres

package tapdb

import (
	"testing"
)

const activeTestDB = "postgres"

// NewTestDB is a helper function that creates a Postgres database for testing.
func NewTestDB(t *testing.T) *PostgresStore {
	return NewTestPostgresDB(t)
}

// NewTestDbHandleFromPath is a helper function that creates a new handle to an
// existing Postgres database for testing.
func NewTestDbHandleFromPath(t *testing.T, dbPath string) *PostgresStore {
	return NewTestPostgresDB(t)
}

// NewDbHandleFromPath is a helper function that creates a new handle to an
// existing Postgres database for testing. This version returns an error if an
// an issue is hit during init.
func NewDbHandleFromPath(dbPath string) (*PostgresStore, error) {
	return NewPostgresDB()
}

// NewTestDBWithVersion is a helper function that creates a Postgres database
// for testing and migrates it to the given version.
func NewTestDBWithVersion(t *testing.T, version uint) *PostgresStore {
	return NewTestPostgresDBWithVersion(t, version)
}
