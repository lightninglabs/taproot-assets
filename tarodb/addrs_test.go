package tarodb

import (
	"context"
	"database/sql"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
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
	scriptKeyPriv, err := btcec.NewPrivateKey()
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

	scriptKey := asset.NewScriptKeyBIP0086(keychain.KeyDescriptor{
		PubKey: scriptKeyPriv.PubKey(),
	})

	taprootOutputKey, _ := schnorr.ParsePubKey(schnorr.SerializePubKey(
		txscript.ComputeTaprootOutputKey(internalKey.PubKey(), nil),
	))

	return &address.AddrWithKeyInfo{
		Taro: &address.Taro{
			Version:     asset.Version(rand.Int31()),
			ID:          assetID,
			FamilyKey:   famKey,
			ScriptKey:   *scriptKey.PubKey,
			InternalKey: *internalKey.PubKey(),
			Amount:      uint64(rand.Int63()),
			Type:        asset.Type(rand.Int31n(2)),
		},
		ScriptKeyTweak: *scriptKey.TweakedScriptKey,
		InternalKeyDesc: keychain.KeyDescriptor{
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamily(rand.Int31()),
				Index:  uint32(rand.Int31()),
			},
			PubKey: internalKey.PubKey(),
		},
		TaprootOutputKey: *taprootOutputKey,
		CreationTime:     time.Now(),
	}
}

// assertEqualAddrs makes sure the given actual addresses match the expected
// ones.
func assertEqualAddrs(t *testing.T, expected, actual []address.AddrWithKeyInfo) {
	require.Len(t, actual, len(expected))
	for idx := range actual {
		assertEqualAddr(t, expected[idx], actual[idx])
	}
}

// assertEqualAddr makes sure the given actual address matches the expected
// one
func assertEqualAddr(t *testing.T, expected, actual address.AddrWithKeyInfo) {
	// Time values cannot be compared based on their struct contents
	// since the same time can be represented in different ways.
	// We compare the addresses without the timestamps and then
	// compare the unix timestamps separately.
	actualTime := actual.CreationTime
	expectedTime := expected.CreationTime

	actual.CreationTime = time.Time{}
	expected.CreationTime = time.Time{}

	require.Equal(t, expected, actual)
	require.Equal(t, expectedTime.Unix(), actualTime.Unix())
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

	// Make sure that we can fetch each address by its Taproot output key as
	// well.
	for _, addr := range addrs {
		dbAddr, err := addrBook.AddrByTaprootOutput(
			ctx, &addr.TaprootOutputKey,
		)
		require.NoError(t, err)
		assertEqualAddr(t, addr, *dbAddr)
	}

	// All addresses should be unmanaged at this point.
	dbAddrs, err = addrBook.QueryAddrs(ctx, address.QueryParams{
		UnmanagedOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, dbAddrs, numAddrs)
	assertEqualAddrs(t, addrs, dbAddrs)

	// Declare the first two addresses as managed.
	managedFrom := time.Now()
	err = addrBook.SetAddrManaged(ctx, &dbAddrs[0], managedFrom)
	require.NoError(t, err)
	err = addrBook.SetAddrManaged(ctx, &dbAddrs[1], managedFrom)
	require.NoError(t, err)

	// Make sure the unmanaged are now distinct from the rest.
	dbAddrs, err = addrBook.QueryAddrs(ctx, address.QueryParams{
		UnmanagedOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, dbAddrs, 3)

	// But a query with no filter still returns all addresses.
	dbAddrs, err = addrBook.QueryAddrs(ctx, address.QueryParams{})
	require.NoError(t, err)
	require.Len(t, dbAddrs, numAddrs)

	require.Equal(t, managedFrom.Unix(), dbAddrs[0].ManagedAfter.Unix())
	require.Equal(t, managedFrom.Unix(), dbAddrs[1].ManagedAfter.Unix())
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
		unmanagedOnly bool

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

		// Unmanaged only, which is the full list.
		{
			name: "unmanaged only",

			unmanagedOnly: true,
			numAddrs:      numAddrs,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dbAddrs, err := addrBook.QueryAddrs(
				ctx, address.QueryParams{
					CreatedAfter:  test.createdAfter,
					CreatedBefore: test.createdBefore,
					Offset:        test.offset,
					Limit:         test.limit,
					UnmanagedOnly: test.unmanagedOnly,
				},
			)
			require.NoError(t, err)
			require.Len(t, dbAddrs, test.numAddrs)
		})
	}
}
