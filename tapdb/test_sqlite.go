//go:build !test_db_postgres

package tapdb

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/mssmt"
)

func init() {
	driver := mssmt.TreeStoreDriver{
		Name: "sqlite3",
		New: func(args ...any) (mssmt.TreeStore,
			error) {

			if len(args) < 3 {
				return nil, fmt.Errorf("invalid "+
					"number of arguments: "+
					"want 3, got %d",
					len(args))
			}

			dbPath, ok := args[0].(string)
			if !ok {
				return nil, fmt.Errorf("invalid "+
					"db path: want string, "+
					"got %T", args[0])
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

			sqlDB := NewTestSqliteDbHandleFromPath(
				t, dbPath,
			)

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
			"store db=sqlite3: %v", err))
	}
}

// NewTestDB is a helper function that creates an SQLite database
// for testing.
func NewTestDB(t testing.TB) *SqliteStore {
	return NewTestSqliteDB(t)
}

// NewTestDbHandleFromPath is a helper function that creates a new
// handle to an existing SQLite database for testing.
func NewTestDbHandleFromPath(t testing.TB,
	dbPath string) *SqliteStore {

	return NewTestSqliteDbHandleFromPath(t, dbPath)
}

// NewTestDBWithVersion is a helper function that creates an SQLite
// database for testing and migrates it to the given version.
func NewTestDBWithVersion(t testing.TB,
	version uint) *SqliteStore {

	return NewTestSqliteDBWithVersion(t, version)
}
