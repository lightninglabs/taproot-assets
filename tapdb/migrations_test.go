package tapdb

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/wire"
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
	// managed UTXOs yet.
	newAssetStoreFromDB(db.BaseDB)

	// Use a narrow query that should always be valid, independent of
	// changes to the managed_utxos table or the related queries.
	fetchManagedUtxoIds := func() ([]int64, error) {
		utxoIdQuery := `
	                SELECT utxo_id
                        FROM managed_utxos utxos
                        JOIN internal_keys keys
                            ON utxos.internal_key_id = keys.key_id
			`

		rows, err := db.QueryContext(ctx, utxoIdQuery)
		if err != nil {
			return nil, err
		}

		defer rows.Close()
		var utxoIds []int64
		for rows.Next() {
			var utxoId int64
			if err = rows.Scan(&utxoId); err != nil {
				return nil, err
			}
			utxoIds = append(utxoIds, utxoId)
		}
		if err = rows.Close(); err != nil {
			return nil, err
		}
		if err = rows.Err(); err != nil {
			return nil, err
		}

		return utxoIds, nil
	}

	_, err := fetchManagedUtxoIds()
	require.True(t, IsSchemaError(MapSQLError(err)))

	// We now migrate to a later but not yet latest version.
	err = db.ExecuteMigrations(TargetVersion(11))
	require.NoError(t, err)

	// Now there should be a managed UTXOs table.
	_, err = fetchManagedUtxoIds()
	require.NoError(t, err)

	// Assuming the next version does some changes to the data within the
	// asset table, we now add some dummy data to the assets related tables,
	// so we could then test that migration.
	InsertTestdata(t, db.BaseDB, "migrations_test_00011_dummy_data.sql")

	// Make sure we now have actual UTXOs in the database.
	utxoIds, err := fetchManagedUtxoIds()
	require.NoError(t, err)
	require.Len(t, utxoIds, 2)

	// And now that we have test data inserted, we can migrate to the latest
	// version.
	err = db.ExecuteMigrations(TargetLatest)
	require.NoError(t, err)

	// Here we would now test that the migration to the latest version did
	// what we expected it to do. But this is just an example, illustrating
	// the steps that can be taken to test migrations, so we are done for
	// this test.
}

// TestMigration15 tests that the migration to version 15 works as expected.
func TestMigration15(t *testing.T) {
	ctx := context.Background()

	db := NewTestDBWithVersion(t, 14)

	// We need to insert some test data that will be affected by the
	// migration number 15.
	InsertTestdata(t, db.BaseDB, "migrations_test_00015_dummy_data.sql")

	// And now that we have test data inserted, we can migrate to the latest
	// version.
	err := db.ExecuteMigrations(TargetLatest)
	require.NoError(t, err)

	// Make sure the single asset that was inserted actually has two
	// witnesses with the correct order.
	_, assetStore := newAssetStoreFromDB(db.BaseDB)
	assets, err := assetStore.FetchAllAssets(ctx, false, false, nil)
	require.NoError(t, err)

	require.Len(t, assets, 1)
	require.Len(t, assets[0].PrevWitnesses, 2)
	require.Equal(
		t, wire.TxWitness{{0xaa}}, assets[0].PrevWitnesses[0].TxWitness,
	)
	require.Equal(
		t, wire.TxWitness{{0xbb}}, assets[0].PrevWitnesses[1].TxWitness,
	)
}

// TestMigrationDowngrade tests that downgrading the database is prevented.
func TestMigrationDowngrade(t *testing.T) {
	// For this test, with the current hard coded latest version.
	db := NewTestDBWithVersion(t, LatestMigrationVersion)

	// We'll now attempt to execute migrations, targeting the latest
	// version. But we'll have the DB think the latest version is actually
	// less than the current version. This simulates downgrading.
	err := db.ExecuteMigrations(TargetLatest, WithLatestVersion(1))
	require.ErrorIs(t, err, ErrMigrationDowngrade)
}
