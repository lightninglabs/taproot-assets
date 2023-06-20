//go:build test_db_postgres

package tapdb

import (
	"testing"
)

// NewTestDB is a helper function that creates a Postgres database for testing.
func NewTestDB(t *testing.T) *PostgresStore {
	return NewTestPostgresDB(t)
}
