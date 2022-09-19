package tarodb

import (
	"context"
	"database/sql"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// newAddrBook makes a new instance of the TaroAddressBook book.
func newAddrBook(t *testing.T) (*TaroAddressBook, *SqliteStore) {
	db := NewTestSqliteDB(t)

	txCreator := func(tx Tx) AddrBook {
		sqlTx, _ := tx.(*sql.Tx)
		return db.WithTx(sqlTx)
	}

	addrTx := NewTransactionExecutor[AddrBook, TxOptions](
		db, txCreator,
	)
	return NewTaroAddressBook(addrTx), db
}

func randAddr(t *testing.T) *address.AddrWithKeyInfo {
	scriptKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	internalKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	var assetID [32]byte
	_, err = rand.Read(assetID[:])
	require.NoError(t, err)

	var famKey *btcec.PublicKey
	if rand.Int31()%2 == 0 {
		famKeyPriv, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		famKey = famKeyPriv.PubKey()
	}

	scriptKeyPub := txscript.ComputeTaprootKeyNoScript(
		scriptKey.PubKey(),
	)

	return &address.AddrWithKeyInfo{
		Taro: &address.Taro{
			Version:     asset.Version(rand.Int31()),
			ID:          assetID,
			FamilyKey:   famKey,
			ScriptKey:   *scriptKeyPub,
			InternalKey: *internalKey.PubKey(),
			Amount:      uint64(rand.Int63()),
			Type:        asset.Type(rand.Int31n(2)),
		},
		ScriptKeyTweak: asset.TweakedScriptKey{
			RawKey: keychain.KeyDescriptor{
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamily(rand.Int31()),
					Index:  uint32(rand.Int31()),
				},
				PubKey: scriptKey.PubKey(),
			},
		},
		InternalKeyDesc: keychain.KeyDescriptor{
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamily(rand.Int31()),
				Index:  uint32(rand.Int31()),
			},
			PubKey: internalKey.PubKey(),
		},
		CreationTime: time.Now(),
	}
}

// assertEqualAddrs makes sure the given actual addresses match the expected
// ones.
func assertEqualAddrs(t *testing.T, expected, actual []address.AddrWithKeyInfo) {
	require.Len(t, actual, len(expected))
	for idx := range actual {
		// Time values cannot be compared based on their struct contents
		// since the same time can be represented in different ways.
		// We compare the addresses without the timestamps and then
		// compare the unix timestamps separately.
		actualTime := actual[idx].CreationTime
		expectedTime := expected[idx].CreationTime

		actual[idx].CreationTime = time.Time{}
		expected[idx].CreationTime = time.Time{}

		require.Equal(t, expected[idx], actual[idx])
		require.Equal(t, expectedTime.Unix(), actualTime.Unix())

		actual[idx].CreationTime = actualTime
		expected[idx].CreationTime = expectedTime
	}
}

// TestAddressInsertion tests that we're always able to retrieve an address we
// inserted into the DB.
func TestAddressInsertion(t *testing.T) {
	t.Parallel()

	// First, make a new addr book instance we'll use in the test below.
	addrBook, _ := newAddrBook(t)

	// Make a series of new addrs, then insert them into the DB.
	const numAddrs = 5
	addrs := make([]address.AddrWithKeyInfo, numAddrs)
	for i := 0; i < numAddrs; i++ {
		addrs[i] = *randAddr(t)
	}
	ctx := context.Background()
	require.NoError(t, addrBook.InsertAddrs(ctx, addrs...))

	// Now we should be able to fetch the complete set of addresses with
	// the query method without specifying any special params.
	dbAddrs, err := addrBook.QueryAddrs(ctx, address.QueryParams{})
	require.NoError(t, err)

	// The returned addresses should match up exactly.
	require.Len(t, dbAddrs, numAddrs)
	assertEqualAddrs(t, addrs, dbAddrs)
}

// TestAddressQuery tests that we're able to properly retrieve rows based on
// various combinations of the query parameters.
func TestAddressQuery(t *testing.T) {
	t.Parallel()

	// First, make a new addr book instance we'll use in the test below.
	addrBook, _ := newAddrBook(t)

	// Make a series of new addrs, then insert them into the DB.
	const numAddrs = 5
	addrs := make([]address.AddrWithKeyInfo, numAddrs)
	for i := 0; i < numAddrs; i++ {
		addrs[i] = *randAddr(t)
	}
	ctx := context.Background()
	require.NoError(t, addrBook.InsertAddrs(ctx, addrs...))

	tests := []struct {
		name string

		createdAfter  time.Time
		createdBefore time.Time
		limit         int32
		offset        int32

		numAddrs   int
		firstIndex int
	}{
		// No params, all rows should be returned.
		{
			name: "no params",

			numAddrs: numAddrs,
		},

		// Limit value should be respected.
		{
			name: "limit",

			limit:    2,
			numAddrs: 2,
		},

		// We should be able to offset from the limit.
		{
			name: "limit+offset",

			limit:  2,
			offset: 1,

			numAddrs:   2,
			firstIndex: 1,
		},

		// Created after in the future should return no rows.
		{
			name: "created after",

			createdAfter: time.Now().Add(time.Hour * 24),
			numAddrs:     0,
		},

		// Created before in the future should return all the rows.
		{
			name: "created before",

			createdBefore: time.Now().Add(time.Hour * 24),
			numAddrs:      numAddrs,
		},

		// Created before in the past should return all the rows.
		{
			name: "created before past",

			createdBefore: time.Now().Add(-time.Hour * 24),
			numAddrs:      0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dbAddrs, err := addrBook.QueryAddrs(ctx, address.QueryParams{
				CreatedAfter:  test.createdAfter,
				CreatedBefore: test.createdBefore,
				Offset:        test.offset,
				Limit:         test.limit,
			})
			require.NoError(t, err)
			require.Len(t, dbAddrs, test.numAddrs)
		})
	}
}
