package tapdb

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
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

// findDbBackupFilePath walks the directory of the given database file path and
// returns the path to the backup file.
func findDbBackupFilePath(t *testing.T, dbFilePath string) string {
	var dbBackupFilePath string
	dir := filepath.Dir(dbFilePath)

	err := filepath.Walk(
		dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			hasSuffix := strings.HasSuffix(info.Name(), ".backup")
			if !info.IsDir() && hasSuffix {
				dbBackupFilePath = path
			}
			return nil
		},
	)
	require.NoError(t, err)

	return dbBackupFilePath
}

// TestSqliteMigrationBackup tests that the sqlite database backup and migration
// functionality works.
//
// In this test we will load from file a database that is at version 14. The
// on file database is already populated with asset data. We will create a
// database backup, migrate the source db, and then check the following:
//
// 1. The asset data is present in the migrated database.
// 2. The asset data is present in the backup database.
func TestSqliteMigrationBackup(t *testing.T) {
	ctx := context.Background()

	db := NewTestSqliteDBWithVersion(t, 14)

	// We need to insert some test data that will be affected by the
	// migration number 15.
	InsertTestdata(t, db.BaseDB, "migrations_test_00015_dummy_data.sql")

	// And now that we have test data inserted, we can create a backup and
	// migrate to the latest version.
	err := db.ExecuteMigrations(db.backupAndMigrate)
	require.NoError(t, err)

	// Inspect the migrated database. Make sure the single asset that was
	// inserted actually has two witnesses with the correct order.
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

	// Now we will inspect the backup database (which should not have been
	// modified by the migration).
	//
	// Find the backup database file.
	dbBackupFilePath := findDbBackupFilePath(t, db.cfg.DatabaseFileName)

	// Construct a new database handle for the backup database.
	backupDb := NewTestSqliteDbHandleFromPath(t, dbBackupFilePath)
	require.NoError(t, err)

	// Inspect the backup database.
	_, assetStore = newAssetStoreFromDB(backupDb.BaseDB)
	assets, err = assetStore.FetchAllAssets(ctx, false, false, nil)
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

// TestMigration20 tests that the migration to version 20 works as expected.
// We start at version 19, then insert some test data that simulate duplicated
// assets that might have been created for certain users due to TAP address self
// transfers. The migration with version 20 is then applied, which contains
// SQL queries to de-duplicate the assets, with the goal of then applying a new
// unique constraint on the asset table.
func TestMigration20(t *testing.T) {
	ctx := context.Background()

	db := NewTestDBWithVersion(t, 19)

	// We need to insert some test data that will be affected by the
	// migration number 20.
	InsertTestdata(t, db.BaseDB, "migrations_test_00020_dummy_data.sql")

	// And now that we have test data inserted, we can migrate to the latest
	// version.
	err := db.ExecuteMigrations(TargetLatest)
	require.NoError(t, err)

	// The migration should have de-duplicated the assets, so we should now
	// only have two valid/distinct assets with two witnesses and one proof
	// each. So we're just asserting the expected state _after_ the
	// migration has run.
	_, assetStore := newAssetStoreFromDB(db.BaseDB)
	assets, err := assetStore.FetchAllAssets(ctx, true, false, nil)
	require.NoError(t, err)

	require.Len(t, assets, 2)
	require.Len(t, assets[0].PrevWitnesses, 2)
	require.False(t, assets[0].IsSpent)
	require.Equal(
		t, wire.TxWitness{{0xaa}}, assets[0].PrevWitnesses[0].TxWitness,
	)
	require.Equal(
		t, wire.TxWitness{{0xbb}}, assets[0].PrevWitnesses[1].TxWitness,
	)

	require.Len(t, assets[1].PrevWitnesses, 2)
	require.True(t, assets[1].IsSpent)
	require.Equal(
		t, wire.TxWitness{{0xcc}}, assets[1].PrevWitnesses[0].TxWitness,
	)
	require.Equal(
		t, wire.TxWitness{{0xdd}}, assets[1].PrevWitnesses[1].TxWitness,
	)

	asset1Locator := proof.Locator{
		ScriptKey: *assets[0].ScriptKey.PubKey,
	}
	asset1Key := asset.ToSerialized(&asset1Locator.ScriptKey)
	asset2Locator := proof.Locator{
		ScriptKey: *assets[1].ScriptKey.PubKey,
	}
	asset2Key := asset.ToSerialized(&asset2Locator.ScriptKey)

	p1, err := assetStore.FetchAssetProofs(ctx, asset1Locator)
	require.NoError(t, err)

	require.Contains(t, p1, asset1Key)
	blob1 := p1[asset1Key]
	require.Equal(t, []byte{0xaa, 0xaa}, []byte(blob1))

	p2, err := assetStore.FetchAssetProofs(ctx, asset2Locator)
	require.NoError(t, err)

	require.Contains(t, p2, asset2Key)
	blob2 := p2[asset2Key]
	require.Equal(t, []byte{0xee, 0xee}, []byte(blob2))
}
