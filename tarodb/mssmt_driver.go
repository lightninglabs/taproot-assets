package tarodb

import (
	"database/sql"
	"fmt"

	"github.com/lightninglabs/taro/mssmt"
)

const (
	// SqliteTreeStoreName is the name of the tree store backed by sqlite3.
	SqliteTreeStoreName = "sqlite3"
)

// createSqliteTreeStore creates a new mssmt.TreeStore from the name of the
// file where the sqlite DB is intended to be stored at.
func createSqliteTreeStore(args ...any) (mssmt.TreeStore, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("only two args accepted, %v found",
			len(args))
	}

	// TODO(bhandras): what's a more modern way of achieving this whole
	// driver concept?
	dbFileName, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("first argument must be a string")
	}
	namespace, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("second argument must be a string " +
			"(the namespace)")
	}

	// TODO(bhandras): mainly used for tests so doesn't matter that creates
	// a new DB entirely?
	db, err := NewSqliteStore(&SqliteConfig{
		DatabaseFileName: dbFileName,
		CreateTables:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to open tree store: %w", err)
	}

	// TODO(bhandras): also need to handle closing the db?
	txCreator := func(tx Tx) TreeStore {
		sqlTx, _ := tx.(*sql.Tx)
		return db.WithTx(sqlTx)
	}

	treeDB := NewTransactionExecutor[TreeStore, TxOptions](
		db, txCreator,
	)

	return NewTaroTreeStore(treeDB, namespace), nil
}

// TODO(bhandras): also eventually register the postgres version here as well.
func init() {
	treeStore := &mssmt.TreeStoreDriver{
		Name: SqliteTreeStoreName,
		New:  createSqliteTreeStore,
	}
	err := mssmt.RegisterTreeStore(treeStore)
	if err != nil {
		panic(fmt.Sprintf("failed to register tree store: %v", err))
	}
}
