package tapdb

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMigrationSteps is an example test that illustrates how to test database
// migrations by selectively applying only some migrations, inserting dummy data
// and then applying the remaining migrations.
func TestMigrationSteps(t *testing.T) {
	ctx := context.Background()

	// As a first step, we create a new database but only migrate to
	// version 1, which only contains the macaroon tables.
	db := NewTestDBWithVersion(t, 1)

	// If we create an assets store now, there should be no tables for the
	// assets yet.
	_, assetStore := newAssetStoreFromDB(db.BaseDB)
	_, err := assetStore.FetchAllAssets(ctx, true, true, nil)
	require.True(t, IsSchemaError(MapSQLError(err)))

	// We now migrate to a later but not yet latest version.
	err = db.ExecuteMigrations(TargetVersion(11))
	require.NoError(t, err)

	// Now there should be an asset table.
	_, err = assetStore.FetchAllAssets(ctx, true, true, nil)
	require.NoError(t, err)

	// Assuming the next version does some changes to the data within the
	// asset table, we now add some dummy data to the assets related tables,
	// so we could then test that migration.
	InsertTestdata(t, db.BaseDB, "migrations_test_00011_dummy_data.sql")

	// Make sure we now have actual assets in the database.
	dbAssets, err := assetStore.FetchAllAssets(ctx, true, true, nil)
	require.NoError(t, err)
	require.Len(t, dbAssets, 4)

	// And now that we have test data inserted, we can migrate to the latest
	// version.
	err = db.ExecuteMigrations(TargetLatest)
	require.NoError(t, err)

	// Here we would now test that the migration to the latest version did
	// what we expected it to do. But this is just an example, illustrating
	// the steps that can be taken to test migrations, so we are done for
	// this test.
}
