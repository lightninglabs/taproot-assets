//go:build test_db_postgres

package tapdb

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/mssmt"
)

func init() {
	driver := mssmt.TreeStoreDriver{
		Name: "postgres",
		New: func(args ...any) (mssmt.TreeStore,
			error) {

			if len(args) < 3 {
				return nil, fmt.Errorf("invalid "+
					"number of arguments: "+
					"want 3, got %d",
					len(args))
			}

			namespace, ok := args[1].(string)
			if !ok {
				return nil, fmt.Errorf("invalid "+
					"namespace: want string, "+
					"got %T", args[1])
			}
			t, ok := args[2].(testing.TB)
			if !ok {
				return nil, fmt.Errorf("invalid "+
					"testing.TB: got %T",
					args[2])
			}

			sqlDB := NewTestPostgresDB(t)

			txCreator := func(tx *sql.Tx) TreeStore {
				return sqlDB.WithTx(tx)
			}
			treeDB := NewTransactionExecutor(
				sqlDB, txCreator,
			)

			return NewTaprootAssetTreeStore(
				treeDB, namespace,
			), nil
		},
	}
	if err := mssmt.RegisterTreeStore(&driver); err != nil {
		panic(fmt.Errorf("failed to register tree "+
			"store db=postgres: %v", err))
	}
}

// NewTestDB is a helper function that creates a Postgres database
// for testing.
func NewTestDB(t testing.TB) *PostgresStore {
	return NewTestPostgresDB(t)
}

// NewTestDbHandleFromPath is a helper function that creates a new
// handle to an existing Postgres database for testing.
func NewTestDbHandleFromPath(t testing.TB,
	dbPath string) *PostgresStore {

	return NewTestPostgresDB(t)
}

// NewTestDBWithVersion is a helper function that creates a Postgres
// database for testing and migrates it to the given version.
func NewTestDBWithVersion(t testing.TB,
	version uint) *PostgresStore {

	return NewTestPostgresDBWithVersion(t, version)
}
