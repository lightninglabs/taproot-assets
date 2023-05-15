package tapdb

import (
	"context"
	"database/sql"
	"testing"

	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/stretchr/testify/require"
)

// TestRootKeyStore tests that we're able to properly fetch and insert macaroon
// root keys into the database.
func TestRootKeyStore(t *testing.T) {
	t.Parallel()

	// First, Make a new test database.
	db := NewTestDB(t)

	// Make a new root key store from the database.
	rksDB := NewTransactionExecutor(db, func(tx *sql.Tx) KeyStore {
		return db.WithTx(tx)
	})
	rks := NewRootKeyStore(rksDB)
	ctx := context.Background()

	// With our database open, attempt to get a root key for an ID that
	// doesn't exist.
	fakeID := []byte("kek")
	_, err := rks.Get(ctx, fakeID)
	require.Equal(t, sql.ErrNoRows, err)

	// Now query for the root key via the RootKey method. This should
	// detect that it doesn't exist, and create+return a new one.
	rootKeyCtx := macaroons.ContextWithRootKeyID(ctx, fakeID)
	rootKey, id, err := rks.RootKey(rootKeyCtx)
	require.NoError(t, err)

	// The ID should match the one we referenced above.
	require.Equal(t, fakeID, id)

	// If we fetch the root key manually we should get the same root key.
	dbRootKey, err := rks.Get(ctx, fakeID)
	require.NoError(t, err)
	require.Equal(t, rootKey, dbRootKey)

	// If we fetch again via the RootKey method, we should get the same
	// root key.
	rootKey2, id2, err := rks.RootKey(rootKeyCtx)
	require.NoError(t, err)
	require.Equal(t, id2, fakeID)
	require.Equal(t, rootKey2, rootKey)
}
