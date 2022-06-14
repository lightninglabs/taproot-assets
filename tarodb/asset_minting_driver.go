package tarodb

import (
	"database/sql"
	"fmt"

	"github.com/lightninglabs/taro/tarogarden"
)

const (
	// SqliteMintingStoreName is the name of the minting store backed by
	// sqlite3.
	SqliteMintingStoreName = "sqlite3"
)

// createSqliteMintingStore creates a new minting store from the name of the
// file where the sqlite DB is intended to be stored at.
func createSqliteMintingStore(args ...any) (tarogarden.MintingStore, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("only one arg accepted, %v found", len(args))
	}

	// TODO(roasbeef): what's a more modern way of achieving this whole
	// drive concept?
	dbFileName, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("first argument must be a string")
	}

	// TODO(roasbeef): mainly used for tests so doesn't matter that creates
	// a new DB entirely?
	db, err := NewSqliteStore(&SqliteConfig{
		DatabaseFileName: dbFileName,
		CreateTables:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to open minting store: %w", err)
	}

	// TODO(roasbeef): also need to handle closing the db?

	txCreator := func(tx Tx) PendingAssetStore {
		sqlTx, _ := tx.(*sql.Tx)
		return db.WithTx(sqlTx)
	}

	assetDB := NewTransactionExecutor[PendingAssetStore, TxOptions](
		db, txCreator,
	)
	return NewAssetMintingStore(assetDB), nil
}

// TODO(roasbeef): also eventually register the postgres version here as well
func init() {
	mintingStore := &tarogarden.MintingStoreDriver{
		Name: SqliteMintingStoreName,
		New:  createSqliteMintingStore,
	}
	err := tarogarden.RegisterMintingStore(mintingStore)
	if err != nil {
		panic(fmt.Sprintf("failed to register minting store: %v", err))
	}
}
