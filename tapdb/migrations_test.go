package tapdb

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/stretchr/testify/require"
)

// transformByteLiterals converts SQLite hex literal formatting in a SQL query
// into Postgres-compatible hex literal formatting if the configured database
// backend is Postgres. In particular, it transforms occurrences of hex literals
// formatted as X'...' into the format '\x...'.
func transformByteLiterals(t *testing.T, db *BaseDB, query string) string {
	if db.Backend() == sqlc.BackendTypePostgres {
		re := regexp.MustCompile(`X'([0-9A-Fa-f]+?)'`)
		query = re.ReplaceAllString(query, `'\x$1'`)
	}
	return query
}

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

// TestMigration29 tests that the migration to version 29 works as expected.
// It verifies the migration of existing data and the insertion of new rows
// using the new proof types "burn" and "ignore".
func TestMigration29(t *testing.T) {
	ctx := context.Background()

	// Create a test database at a version prior to migration 29 (e.g.
	// version 28).
	db := NewTestDBWithVersion(t, 28)

	// Insert dummy data representing the pre-migration state.
	// This should minimally populate the tables that will be affected by
	InsertTestdata(t, db.BaseDB, "migrations_test_00029_dummy_data.sql")

	// Run the migration to the latest version.
	err := db.ExecuteMigrations(TargetLatest)
	require.NoError(t, err)

	// First, we'll Verify pre-existing dummy data was migrated correctly.

	// Check universe_roots: the dummy row should keep its original
	// proof_type.
	var proofType string
	err = db.QueryRowContext(ctx, `
		SELECT proof_type FROM universe_roots WHERE id = 1
	`).Scan(&proofType)
	require.NoError(t, err)
	require.Equal(t, "issuance", proofType)

	// Check federation_global_sync_config dummy data.
	err = db.QueryRowContext(ctx, `
		SELECT proof_type
		FROM federation_global_sync_config LIMIT 1
	`).Scan(&proofType)
	require.NoError(t, err)
	require.Equal(t, "transfer", proofType)

	// Check federation_uni_sync_config dummy data.
	err = db.QueryRowContext(ctx, `
		SELECT proof_type 
		FROM federation_uni_sync_config LIMIT 1
	`).Scan(&proofType)
	require.NoError(t, err)
	require.Equal(t, "issuance", proofType)

	// Next, we'll insert new rows that use the newly allowed values "burn"
	// and "ignore".
	//
	// For the 'burn' proof type:
	//   - Insert a unique mssmt_nodes row and a corresponding mssmt_roots
	//   row with namespace 'ns_burn'.
	//
	//   - Then insert a universe_roots row referencing namespace 'ns_burn'
	_, err = db.ExecContext(ctx, transformByteLiterals(t, db.BaseDB, ` 
	  INSERT INTO mssmt_nodes (
	      hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
	  )
	  VALUES (
	    X'1111111111111111111111111111111111111111111111111111111111111111',
	    NULL, NULL, X'00', X'00', 0, 'ns_burn'
	  )
	`))
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, transformByteLiterals(t, db.BaseDB, `
	  INSERT INTO mssmt_roots (namespace, root_hash)
	  VALUES (
	    'ns_burn', 
	    X'1111111111111111111111111111111111111111111111111111111111111111')
	`))
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, transformByteLiterals(t, db.BaseDB, ` 
	  INSERT INTO universe_roots (
		id, namespace_root, asset_id, group_key, proof_type)
	  VALUES (
	    2,'ns_burn', NULL, 
	    X'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
	    'burn')
	`))
	require.NoError(t, err)

	// For the 'ignore' proof type:
	//
	//   - Insert a unique mssmt_nodes row and a corresponding mssmt_roots
	//   row with namespace 'ns_ignore'.
	//
	//   - Then insert a universe_roots row referencing namespace
	//   'ns_ignore' with proof_type 'ignore'.
	_, err = db.ExecContext(ctx, transformByteLiterals(t, db.BaseDB, `
	  INSERT INTO mssmt_nodes (
	      hash_key, l_hash_key, r_hash_key, key, value, sum, namespace
	  )
	  VALUES (
	    X'2222222222222222222222222222222222222222222222222222222222222222',
	    NULL, NULL, X'00', X'00', 0, 'ns_ignore'
	  )
	`))
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, transformByteLiterals(t, db.BaseDB, `
	  INSERT INTO mssmt_roots (namespace, root_hash)
	  VALUES (
	    'ns_ignore', 
	    X'2222222222222222222222222222222222222222222222222222222222222222')
	`))
	require.NoError(t, err)
	//nolint:lll
	_, err = db.ExecContext(ctx, transformByteLiterals(t, db.BaseDB, `
	  INSERT INTO universe_roots (
		id, namespace_root, asset_id, group_key, proof_type)
	  VALUES (
	    3,'ns_ignore', NULL, 
	    X'00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF', 
	    'ignore')
	`))
	require.NoError(t, err)

	// Verify that the two newly inserted rows exist.
	var count int
	err = db.QueryRowContext(ctx, `
	  SELECT COUNT(*) FROM universe_roots 
		WHERE proof_type IN ('burn', 'ignore')
	`).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 2, count)

	// For federation_global_sync_config, insert a new row with proof_type
	// "burn".
	_, err = db.ExecContext(ctx, `
	  INSERT INTO federation_global_sync_config (
		proof_type, allow_sync_insert, allow_sync_export)
	  VALUES ('burn', true, false)
	`)
	require.NoError(t, err)
	err = db.QueryRowContext(ctx, `
	  SELECT proof_type FROM federation_global_sync_config 
		WHERE proof_type = 'burn'
	`).Scan(&proofType)
	require.NoError(t, err)
	require.Equal(t, "burn", proofType)

	// For federation_uni_sync_config, insert a new row with proof_type
	// "ignore". Note: The schema requires a valid 33-byte group_key. Here
	// we use a hard-coded hex value.
	_, err = db.ExecContext(ctx, transformByteLiterals(t, db.BaseDB, `
	  INSERT INTO federation_uni_sync_config (
		namespace, group_key, proof_type, allow_sync_insert, 
		allow_sync_export)
	  VALUES (
	  'test', 
	  X'00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00',
	  'ignore', false, true)
	`))
	require.NoError(t, err)
	err = db.QueryRowContext(ctx, `
	  SELECT proof_type FROM federation_uni_sync_config 
		WHERE proof_type = 'ignore' LIMIT 1
	`).Scan(&proofType)
	require.NoError(t, err)
	require.Equal(t, "ignore", proofType)
}

// TestMigration31 tests the migration that changes the UNIQUE index on the
// universe_leaves table from two columns (minting_point, script_key_bytes) to
// three columns (minting_point, script_key_bytes, leaf_node_namespace).
func TestMigration31(t *testing.T) {
	ctx := context.Background()

	// Create a test DB at the pre-migration state (version 30).
	db := NewTestDBWithVersion(t, 30)

	// Insert test data from file.
	InsertTestdata(t, db.BaseDB, "migrations_test_00031_dummy_data.sql")

	// Attempt to insert a duplicate leaf row (same minting_point and
	// script_key_bytes) but with a different leaf_node_namespace "test_ns".
	// Under the old unique constraint, this should error.
	//
	//nolint:lll
	const dupLeafStmt = `
	INSERT INTO universe_leaves (
		id, asset_genesis_id, minting_point, script_key_bytes,
		universe_root_id, leaf_node_key, leaf_node_namespace
	) VALUES (
		%d, 1, X'0A0B0C', X'00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF',
		999, X'BB', 'test_ns'
	)
	`

	dupQuery := transformByteLiterals(
		t, db.BaseDB, fmt.Sprintf(dupLeafStmt, 101),
	)
	_, err := db.ExecContext(ctx, dupQuery)
	require.Error(
		t, err,
		"duplicate insert should fail under the old unique constraint",
	)

	// Check error message, which differs between SQLite and Postgres
	errMsg := err.Error()
	switch db.Backend() {
	case sqlc.BackendTypeSqlite:
		require.Contains(
			t, errMsg,
			"constraint failed: UNIQUE constraint failed: "+
				"universe_leaves.minting_point, "+
				"universe_leaves.script_key_bytes",
			"SQLite error should contain the expected unique "+
				"constraint failure")
	case sqlc.BackendTypePostgres:
		require.Contains(
			t, errMsg, "duplicate key value violates unique "+
				"constraint", "postgres error should mention "+
				"duplicate key violation")
	default:
		t.Fatalf("unknown database backend: %v", db.Backend())
	}

	// Run migration 31 (apply the up migration that updates the unique
	// constraint).
	err = db.ExecuteMigrations(TargetVersion(31))
	require.NoError(t, err)

	// Verify that the dummy row inserted from the testdata file was
	// migrated properly.
	var ns string
	err = db.QueryRowContext(ctx, transformByteLiterals(t, db.BaseDB, `
		SELECT leaf_node_namespace FROM universe_leaves WHERE id = 100
	`)).Scan(&ns)
	require.NoError(t, err)
	require.Equal(
		t, "old_ns", ns, "pre-existing leaf should have its namespace "+
			"unchanged",
	)

	// Now, with the new three-column unique constraint in place, attempting
	// to insert a row with the same minting_point and script_key_bytes but
	// a different namespace ("test_ns") should succeed.
	dupQuery2 := transformByteLiterals(
		t, db.BaseDB, fmt.Sprintf(dupLeafStmt, 102),
	)
	_, err = db.ExecContext(ctx, dupQuery2)
	require.NoError(
		t, err,
		"duplicate insert should now succeed with the new unique "+
			"constraint",
	)
}

// TestMigration33 tests that the Golang based post migration check for the
// script key type detection works as expected. It verifies that the script key
// types are detected correctly and that the migration to version 31 works as
// expected.
func TestMigration33(t *testing.T) {
	ctx := context.Background()

	db := NewTestDBWithVersion(t, 32)

	// We need to insert some test data that will be affected by the
	// migration number 31.
	InsertTestdata(t, db.BaseDB, "migrations_test_00033_dummy_data.sql")

	// And now that we have test data inserted, we can migrate to the latest
	// version.
	err := db.ExecuteMigrations(TargetLatest, WithPostStepCallbacks(
		makePostStepCallbacks(db, postMigrationChecks),
	))
	require.NoError(t, err)

	// The migration should have de-duplicated the assets, so we should now
	// only have two valid/distinct assets with two witnesses and one proof
	// each. So we're just asserting the expected state _after_ the
	// migration has run.
	unknownKey, _ := hex.DecodeString(
		"039c571fffcac1a1a7cd3372bd202ad8562f28e48b90f8a4eb714eca062f" +
			"576ee6",
	)
	unknownScriptKey, err := db.BaseDB.FetchScriptKeyByTweakedKey(
		ctx, unknownKey,
	)
	require.NoError(t, err)
	require.Equal(
		t, asset.ScriptKeyUnknown, extractSqlInt16[asset.ScriptKeyType](
			unknownScriptKey.ScriptKey.KeyType,
		),
	)

	bip86Key, _ := hex.DecodeString(
		"029c571fffcac1a1a7cd3372bd202ad8562f28e48b90f8a4eb714eca062f" +
			"576ee6",
	)
	bip86ScriptKey, err := db.BaseDB.FetchScriptKeyByTweakedKey(
		ctx, bip86Key,
	)
	require.NoError(t, err)
	require.EqualValues(
		t, asset.ScriptKeyBip86,
		extractSqlInt16[asset.ScriptKeyType](
			bip86ScriptKey.ScriptKey.KeyType,
		),
	)

	scriptedKey, _ := hex.DecodeString(
		"03f9cdf1ff7c9fbb0ea3c8533cd7048994f41ea20a79764469c22aa18aa6" +
			"696169",
	)
	scriptedScriptKey, err := db.BaseDB.FetchScriptKeyByTweakedKey(
		ctx, scriptedKey,
	)
	require.NoError(t, err)
	require.EqualValues(
		t, asset.ScriptKeyScriptPathExternal,
		extractSqlInt16[asset.ScriptKeyType](
			scriptedScriptKey.ScriptKey.KeyType,
		),
	)

	tombstoneKey, _ := hex.DecodeString(
		"027c79b9b26e463895eef5679d8558942c86c4ad2233adef01bc3e6d540b" +
			"3653fe",
	)
	tombstoneScriptKey, err := db.BaseDB.FetchScriptKeyByTweakedKey(
		ctx, tombstoneKey,
	)
	require.NoError(t, err)
	require.EqualValues(
		t, asset.ScriptKeyTombstone,
		extractSqlInt16[asset.ScriptKeyType](
			tombstoneScriptKey.ScriptKey.KeyType,
		),
	)

	channelKey, _ := hex.DecodeString(
		"0350aaeb166f4234650d84a2d8a130987aeaf6950206e0905401ee74ff3f" +
			"8d18e6",
	)
	channelScriptKey, err := db.BaseDB.FetchScriptKeyByTweakedKey(
		ctx, channelKey,
	)
	require.NoError(t, err)
	require.EqualValues(
		t, asset.ScriptKeyScriptPathChannel,
		extractSqlInt16[asset.ScriptKeyType](
			channelScriptKey.ScriptKey.KeyType,
		),
	)

	burnKey, _ := hex.DecodeString(
		"02248bca7dbb12dcf0b490263a1d521691691aa2541842b7472c83acac0e" +
			"88443b",
	)
	burnScriptKey, err := db.BaseDB.FetchScriptKeyByTweakedKey(
		ctx, burnKey,
	)
	require.NoError(t, err)
	require.EqualValues(
		t, asset.ScriptKeyBurn,
		extractSqlInt16[asset.ScriptKeyType](
			burnScriptKey.ScriptKey.KeyType,
		),
	)
}
