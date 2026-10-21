package tapdb

import (
	"fmt"
	"testing"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// TestMapPostgresSerializationError checks that wrapped pgx v5 conflicts
// remain eligible for the transaction executor's serialization retry.
func TestMapPostgresSerializationError(t *testing.T) {
	t.Parallel()

	driverErr := &pgconn.PgError{Code: pgerrcode.SerializationFailure}
	err := MapSQLError(fmt.Errorf("commit failed: %w", driverErr))
	require.True(t, IsSerializationError(err))
	require.ErrorIs(t, err, driverErr)
}
