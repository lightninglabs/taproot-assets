//go:build test_db_postgres

package tapdb

import (
	"context"
	"database/sql"
	"testing"

	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/stretchr/testify/require"
)

// TestPostgresErrorSanitization tests that we can handle a Postgres connection
// error gracefully, without leaking sensitive information.
func TestPostgresErrorSanitization(t *testing.T) {
	t.Parallel()

	// We first create a Postgres fixture and a DB that will run the
	// migration scripts.
	sqlFixture := NewTestPgFixture(t, DefaultPostgresFixtureLifetime, true)
	_, err := NewPostgresStore(sqlFixture.GetConfig())
	require.NoError(t, err)

	// Now we create a connection config that won't work because of the
	// wrong password.
	config := sqlFixture.GetConfig()
	config.Password = "different"
	config.SkipMigrations = true

	store, err := NewPostgresStore(config)
	require.NoError(t, err)

	rksDB := NewTransactionExecutor(store, func(tx *sql.Tx) KeyStore {
		return store.WithTx(tx)
	})
	rks := NewRootKeyStore(rksDB)

	ctx := context.Background()
	rootKeyCtx := macaroons.ContextWithRootKeyID(ctx, []byte("kek"))
	_, _, err = rks.RootKey(rootKeyCtx)
	require.Error(t, err)
	require.Equal(
		t, "unknown postgres error: database connection failed",
		err.Error(),
	)
}
