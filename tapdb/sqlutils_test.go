package tapdb

import (
	"database/sql"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightningnetwork/lnd/clock"
)

// DbHandler is a helper struct that contains all the database stores.
type DbHandler struct {
	// UniverseFederationStore is a handle to the universe federation store.
	UniverseFederationStore *UniverseFederationDB

	// MultiverseStore is a handle to the multiverse store.
	MultiverseStore *MultiverseStore

	// AssetMintingStore is a handle to the pending (minting) assets store.
	AssetMintingStore *AssetMintingStore

	// AssetStore is a handle to the active assets store.
	AssetStore *AssetStore

	// DirectQuery is a handle to the underlying database that can be used
	// to query the database directly.
	DirectQuery sqlc.Querier
}

// NewDbHandle creates a new store and query handle to the test database.
func NewDbHandle(t *testing.T) *DbHandler {
	// Create a new test database.
	db := NewTestDB(t)

	testClock := clock.NewTestClock(time.Now())

	// Gain a handle to the pending (minting) universe federation store.
	universeServerTxCreator := NewTransactionExecutor(
		db, func(tx *sql.Tx) UniverseServerStore {
			return db.WithTx(tx)
		},
	)
	fedStore := NewUniverseFederationDB(universeServerTxCreator, testClock)

	// Gain a handle to the multiverse store.
	multiverseTxCreator := NewTransactionExecutor(db,
		func(tx *sql.Tx) BaseMultiverseStore {
			return db.WithTx(tx)
		},
	)
	multiverseStore := NewMultiverseStore(multiverseTxCreator)

	// Gain a handle to the pending (minting) assets store.
	assetMintingDB := NewTransactionExecutor(
		db, func(tx *sql.Tx) PendingAssetStore {
			return db.WithTx(tx)
		},
	)
	assetMintingStore := NewAssetMintingStore(assetMintingDB)

	// Gain a handle to the active assets store.
	assetsDB := NewTransactionExecutor(
		db, func(tx *sql.Tx) ActiveAssetsStore {
			return db.WithTx(tx)
		},
	)
	activeAssetsStore := NewAssetStore(assetsDB, testClock)

	return &DbHandler{
		UniverseFederationStore: fedStore,
		MultiverseStore:         multiverseStore,
		AssetMintingStore:       assetMintingStore,
		AssetStore:              activeAssetsStore,
		DirectQuery:             db,
	}
}
