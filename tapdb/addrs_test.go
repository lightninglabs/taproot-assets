package tapdb

import (
	"context"
	"database/sql"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/stretchr/testify/require"
)

var (
	chainParams = &address.RegressionNetTap
)

// newAddrBook makes a new instance of the TapAddressBook book.
func newAddrBook(t *testing.T,
	clock clock.Clock) (*TapAddressBook, sqlc.Querier) {

	db := NewTestDB(t)

	txCreator := func(tx *sql.Tx) AddrBook {
		return db.WithTx(tx)
	}

	addrTx := NewTransactionExecutor(db, txCreator)
	return NewTapAddressBook(addrTx, chainParams, clock), db
}

func confirmTx(tx *lndclient.Transaction) {
	blockHash := test.RandHash()
	tx.Confirmations = rand.Int31n(50) + 1
	tx.BlockHash = blockHash.String()
	tx.BlockHeight = rand.Int31n(700_000)
}

func randWalletTx() *lndclient.Transaction {
	tx := &lndclient.Transaction{
		Tx:        wire.NewMsgTx(2),
		Timestamp: time.Now(),
	}
	numInputs := rand.Intn(10) + 1
	numOutputs := rand.Intn(5) + 1

	for idx := 0; idx < numInputs; idx++ {
		in := &wire.TxIn{}
		_, _ = rand.Read(in.PreviousOutPoint.Hash[:])
		in.PreviousOutPoint.Index = rand.Uint32()
		tx.Tx.AddTxIn(in)
		tx.PreviousOutpoints = append(
			tx.PreviousOutpoints, &lnrpc.PreviousOutPoint{
				Outpoint:    in.PreviousOutPoint.String(),
				IsOurOutput: rand.Int31()%2 == 0,
			},
		)
	}
	for idx := 0; idx < numOutputs; idx++ {
		out := &wire.TxOut{
			Value: rand.Int63n(5000000),
		}
		out.PkScript = make([]byte, 34)
		_, _ = rand.Read(out.PkScript)
		tx.Tx.AddTxOut(out)
		tx.OutputDetails = append(
			tx.OutputDetails, &lnrpc.OutputDetail{
				Amount:       out.Value,
				IsOurAddress: rand.Int31()%2 == 0,
			},
		)
	}

	return tx
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
	t.Helper()

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

// assertEqualAddrEvents makes sure the given actual address events match the
// expected ones.
func assertEqualAddrEvents(t *testing.T, expected, actual []*address.Event) {
	require.Len(t, actual, len(expected))
	for idx := range actual {
		assertEqualAddrEvent(t, *expected[idx], *actual[idx])
	}
}

// assertEqualAddrEvent makes sure the given actual address event matches the
// expected one.
func assertEqualAddrEvent(t *testing.T, expected, actual address.Event) {
	assertEqualAddr(t, *expected.Addr, *actual.Addr)
	actual.Addr = nil
	expected.Addr = nil

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
	testClock := clock.NewTestClock(time.Now())
	addrBook, _ := newAddrBook(t, testClock)
	ctx := context.Background()

	var writeTxOpts AddrBookTxOptions

	// Make a series of new addrs, then insert them into the DB.
	const numAddrs = 5
	proofCourierAddr := address.RandProofCourierAddr(t)
	addrs := make([]address.AddrWithKeyInfo, numAddrs)
	for i := 0; i < numAddrs; i++ {
		addr, assetGen, assetGroup := address.RandAddr(
			t, chainParams, proofCourierAddr,
		)

		addrs[i] = *addr

		err := addrBook.db.ExecTx(
			ctx, &writeTxOpts,
			insertFullAssetGen(ctx, assetGen, assetGroup),
		)
		require.NoError(t, err)
	}
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

		// Also make sure the script key for this address was inserted
		// correctly.
		scriptKey, err := addrBook.FetchScriptKey(ctx, &addr.ScriptKey)
		require.NoError(t, err)
		require.NotNil(t, scriptKey.RawKey.PubKey)
		require.False(t, scriptKey.RawKey.IsEmpty())
		require.Equal(t, addr.ScriptKeyTweak.RawKey, scriptKey.RawKey)

		// And the internal key as well.
		internalKeyLoc, err := addrBook.FetchInternalKeyLocator(
			ctx, &addr.InternalKey,
		)
		require.NoError(t, err)
		require.False(t, internalKeyLoc.IsEmpty())
		require.Equal(
			t, addr.InternalKeyDesc.KeyLocator, internalKeyLoc,
		)
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

	// The ORDER BY clause should make sure the unmanaged addresses are
	// actually the last three.
	assertEqualAddr(t, addrs[2], dbAddrs[0])
	assertEqualAddr(t, addrs[3], dbAddrs[1])
	assertEqualAddr(t, addrs[4], dbAddrs[2])

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
	testClock := clock.NewTestClock(time.Now())
	addrBook, _ := newAddrBook(t, testClock)

	var writeTxOpts AddrBookTxOptions

	ctx := context.Background()

	// Make a series of new addrs, then insert them into the DB.
	const numAddrs = 5
	proofCourierAddr := address.RandProofCourierAddr(t)
	addrs := make([]address.AddrWithKeyInfo, numAddrs)
	for i := 0; i < numAddrs; i++ {
		addr, assetGen, assetGroup := address.RandAddr(
			t, chainParams, proofCourierAddr,
		)

		err := addrBook.db.ExecTx(
			ctx, &writeTxOpts,
			insertFullAssetGen(ctx, assetGen, assetGroup),
		)
		require.NoError(t, err)

		addrs[i] = *addr
	}
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
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dbAddrs, err := addrBook.QueryAddrs(
				ctx, address.QueryParams{
					CreatedAfter:  tc.createdAfter,
					CreatedBefore: tc.createdBefore,
					Offset:        tc.offset,
					Limit:         tc.limit,
					UnmanagedOnly: tc.unmanagedOnly,
				},
			)
			require.NoError(t, err)
			require.Len(t, dbAddrs, tc.numAddrs)
		})
	}
}

// TestAddrEventStatusDBEnum makes sure we cannot insert an event with an
// invalid status into the database.
func TestAddrEventStatusDBEnum(t *testing.T) {
	t.Parallel()

	// First, make a new addr book instance we'll use in the test below.
	testClock := clock.NewTestClock(time.Now())
	addrBook, _ := newAddrBook(t, testClock)

	ctx := context.Background()

	// Make sure an event with an invalid status cannot be created. This
	// should be protected by a CHECK constraint on the column. If this
	// fails, you need to update that constraint in the DB!
	proofCourierAddr := address.RandProofCourierAddr(t)
	addr, assetGen, assetGroup := address.RandAddr(
		t, chainParams, proofCourierAddr,
	)

	var writeTxOpts AddrBookTxOptions
	err := addrBook.db.ExecTx(
		ctx, &writeTxOpts, insertFullAssetGen(ctx, assetGen, assetGroup),
	)
	require.NoError(t, err)

	err = addrBook.InsertAddrs(ctx, *addr)
	require.NoError(t, err)

	txn := randWalletTx()
	outputIndex := rand.Intn(len(txn.Tx.TxOut))

	_, err = addrBook.GetOrCreateEvent(
		ctx, address.Status(4), addr, txn, uint32(outputIndex),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "constraint")
}

// TestAddrEventCreation tests that address events can be created and updated
// correctly.
func TestAddrEventCreation(t *testing.T) {
	t.Parallel()

	// First, make a new addr book instance we'll use in the test below.
	testClock := clock.NewTestClock(time.Now())
	addrBook, _ := newAddrBook(t, testClock)

	ctx := context.Background()

	// Create 5 addresses and then events with unconfirmed transactions.
	const numAddrs = 5
	proofCourierAddr := address.RandProofCourierAddr(t)
	txns := make([]*lndclient.Transaction, numAddrs)
	events := make([]*address.Event, numAddrs)
	for i := 0; i < numAddrs; i++ {
		addr, assetGen, assetGroup := address.RandAddr(
			t, chainParams, proofCourierAddr,
		)

		var writeTxOpts AddrBookTxOptions
		err := addrBook.db.ExecTx(
			ctx, &writeTxOpts,
			insertFullAssetGen(ctx, assetGen, assetGroup),
		)
		require.NoError(t, err)

		err = addrBook.InsertAddrs(ctx, *addr)
		require.NoError(t, err)

		txns[i] = randWalletTx()
		outputIndex := rand.Intn(len(txns[i].Tx.TxOut))

		event, err := addrBook.GetOrCreateEvent(
			ctx, address.StatusTransactionDetected, addr, txns[i],
			uint32(outputIndex),
		)
		require.NoError(t, err)

		events[i] = event

		// We need to advance the test clock a tiny bit to make our
		// event timestamps unique.
		testClock.SetTime(testClock.Now().Add(time.Millisecond))
	}

	// All 5 events should be returned when querying pending events.
	pendingEvents, err := addrBook.QueryAddrEvents(
		ctx, address.EventQueryParams{},
	)
	require.NoError(t, err)
	assertEqualAddrEvents(t, events, pendingEvents)

	// When querying by timestamp of the 3rd event, we should only get that
	// event and all events that were created after it.
	timedEvents, err := addrBook.QueryAddrEvents(
		ctx, address.EventQueryParams{
			CreationTimeFrom: &events[2].CreationTime,
		},
	)
	require.NoError(t, err)
	assertEqualAddrEvents(t, events[2:], timedEvents)

	// If we try to create the same events again, we should just get the
	// exact same event back.
	for idx := range events {
		actual, err := addrBook.GetOrCreateEvent(
			ctx, address.StatusTransactionDetected,
			events[idx].Addr, txns[idx], events[idx].Outpoint.Index,
		)
		require.NoError(t, err)

		assertEqualAddrEvent(t, *events[idx], *actual)
	}

	// Now we update the status of our event, make the transaction confirmed
	// and set the tapscript sibling to nil for all of them.
	for idx := range events {
		confirmTx(txns[idx])
		events[idx].Status = address.StatusTransactionConfirmed
		events[idx].ConfirmationHeight = uint32(txns[idx].BlockHeight)

		actual, err := addrBook.GetOrCreateEvent(
			ctx, address.StatusTransactionConfirmed,
			events[idx].Addr, txns[idx], events[idx].Outpoint.Index,
		)
		require.NoError(t, err)

		assertEqualAddrEvent(t, *events[idx], *actual)
	}
}

// TestAddressEventQuery tests that we're able to properly retrieve rows based
// on various combinations of the query parameters.
func TestAddressEventQuery(t *testing.T) {
	t.Parallel()

	// First, make a new addr book instance we'll use in the test below.
	testClock := clock.NewTestClock(time.Now())
	addrBook, _ := newAddrBook(t, testClock)

	ctx := context.Background()

	var writeTxOpts AddrBookTxOptions

	// Make a series of new addrs, then insert them into the DB.
	const numAddrs = 5
	proofCourierAddr := address.RandProofCourierAddr(t)
	addrs := make([]address.AddrWithKeyInfo, numAddrs)
	for i := 0; i < numAddrs; i++ {
		addr, assetGen, assetGroup := address.RandAddr(
			t, chainParams, proofCourierAddr,
		)

		err := addrBook.db.ExecTx(
			ctx, &writeTxOpts,
			insertFullAssetGen(ctx, assetGen, assetGroup),
		)
		require.NoError(t, err)

		require.NoError(t, addrBook.InsertAddrs(ctx, *addr))

		txn := randWalletTx()
		outputIndex := rand.Intn(len(txn.Tx.TxOut))

		// Make sure we use all states at least once.
		status := address.Status(i % int(address.StatusCompleted+1))
		event, err := addrBook.GetOrCreateEvent(
			ctx, status, addr, txn, uint32(outputIndex),
		)
		require.NoError(t, err)
		require.EqualValues(t, i+1, event.ID)

		addrs[i] = *addr
	}

	var (
		confirmed = address.StatusTransactionConfirmed
		invalid   = address.Status(123)
	)

	tests := []struct {
		name string

		addrTaprootKey []byte
		stateFrom      *address.Status
		stateTo        *address.Status

		numAddrs int
		firstID  int
	}{
		// No params, all rows should be returned.
		{
			name: "no params",

			numAddrs: numAddrs,
		},

		// Invalid status.
		{
			name: "invalid status",

			stateFrom: &invalid,
			numAddrs:  0,
		},

		// Invalid key.
		{
			name: "invalid address taproot key",

			addrTaprootKey: []byte{99, 99},
			numAddrs:       0,
		},

		// Exactly one status.
		{
			name:      "single status",
			stateFrom: &confirmed,
			stateTo:   &confirmed,

			numAddrs: 1,
			firstID:  2,
		},

		// Empty taproot key slice.
		{
			name: "empty address taproot key",

			addrTaprootKey: []byte{},
			numAddrs:       5,
		},

		// Correct key.
		{
			name: "correct address taproot key",

			addrTaprootKey: schnorr.SerializePubKey(
				&addrs[4].TaprootOutputKey,
			),
			numAddrs: 1,
			firstID:  5,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc
			dbAddrs, err := addrBook.QueryAddrEvents(
				ctx, address.EventQueryParams{
					AddrTaprootOutputKey: tc.addrTaprootKey,
					StatusFrom:           tc.stateFrom,
					StatusTo:             tc.stateTo,
				},
			)
			require.NoError(t, err)
			require.Len(t, dbAddrs, tc.numAddrs)

			if tc.firstID > 0 {
				require.EqualValues(
					t, dbAddrs[0].ID, tc.firstID,
				)
			}

			// Make sure we get the correct error if we're querying
			// for an invalid status.
			_, err = addrBook.QueryEvent(
				ctx, &addrs[0], wire.OutPoint{},
			)
			require.ErrorIs(t, err, address.ErrNoEvent)

			// If we did get any events returned in the first query,
			// make sure we can also fetch them using the QueryEvent
			// method.
			for _, dbEvent := range dbAddrs {
				event, err := addrBook.QueryEvent(
					ctx, dbEvent.Addr, dbEvent.Outpoint,
				)
				require.NoError(t, err)
				assertEqualAddrEvent(t, *dbEvent, *event)
			}
		})
	}
}

// randScriptKey makes a random script key with a tweak.
func randScriptKey(t *testing.T) asset.ScriptKey {
	scriptKey := asset.RandScriptKey(t)
	scriptKey.TweakedScriptKey = &asset.TweakedScriptKey{
		RawKey: keychain.KeyDescriptor{
			PubKey: asset.RandScriptKey(t).PubKey,
		},
	}

	return scriptKey
}

func assertKeyKnowledge(t *testing.T, ctx context.Context,
	addrBook *TapAddressBook, scriptKey asset.ScriptKey,
	keyType asset.ScriptKeyType) {

	dbScriptKey, err := addrBook.FetchScriptKey(ctx, scriptKey.PubKey)
	require.NoError(t, err)
	require.Equal(t, keyType, dbScriptKey.Type)
}

func assertTweak(t *testing.T, ctx context.Context, addrBook *TapAddressBook,
	scriptKey asset.ScriptKey, tweak []byte) {

	dbScriptKey, err := addrBook.FetchScriptKey(ctx, scriptKey.PubKey)
	require.NoError(t, err)
	require.Equal(t, tweak, dbScriptKey.Tweak)
}

// TestScriptKeyTweakUpsert tests that we can insert a script key, then insert
// it again when we know the tweak for it.
func TestScriptKeyTweakUpsert(t *testing.T) {
	t.Parallel()

	// First, make a new addr book instance we'll use in the test below.
	testClock := clock.NewTestClock(time.Now())
	addrBook, _ := newAddrBook(t, testClock)

	ctx := context.Background()

	// In this test, we insert the tweak as NULL, and make sure we overwrite
	// it with an actual value again later.
	t.Run("null_to_value", func(t *testing.T) {
		scriptKey := randScriptKey(t)
		scriptKey.Tweak = nil

		// We'll insert a random script key into the database. We won't
		// declare it as known though, and it doesn't have the tweak.
		err := addrBook.InsertScriptKey(
			ctx, scriptKey, asset.ScriptKeyUnknown,
		)
		require.NoError(t, err)

		// We'll fetch the script key and confirm that it's not known.
		assertKeyKnowledge(
			t, ctx, addrBook, scriptKey, asset.ScriptKeyUnknown,
		)
		assertTweak(t, ctx, addrBook, scriptKey, nil)

		randTweak := test.RandBytes(32)
		scriptKey.Tweak = randTweak

		// We'll now insert it again, but this time declare it as known
		// and also know the tweak.
		err = addrBook.InsertScriptKey(
			ctx, scriptKey, asset.ScriptKeyScriptPathExternal,
		)
		require.NoError(t, err)

		// We'll fetch the script key and confirm that it's known.
		assertKeyKnowledge(
			t, ctx, addrBook, scriptKey,
			asset.ScriptKeyScriptPathExternal,
		)
		assertTweak(t, ctx, addrBook, scriptKey, randTweak)
	})
}

// TestScriptKeyTypeUpsert tests that we can insert a script key, then insert
// it again when we know the type for it.
func TestScriptKeyTypeUpsert(t *testing.T) {
	t.Parallel()

	// First, make a new addr book instance we'll use in the test below.
	testClock := clock.NewTestClock(time.Now())
	addrBook, _ := newAddrBook(t, testClock)

	ctx := context.Background()

	// In this test, we insert the type as unknown, and make sure we
	// overwrite it with an actual value again later.
	t.Run("null_to_value", func(t *testing.T) {
		scriptKey := randScriptKey(t)
		scriptKey.Tweak = nil

		// We'll insert a random script key into the database. It is
		// declared as known, but doesn't have a known type.
		err := addrBook.InsertScriptKey(
			ctx, scriptKey, asset.ScriptKeyUnknown,
		)
		require.NoError(t, err)

		// We'll fetch the script key and confirm that it's not known.
		assertKeyKnowledge(
			t, ctx, addrBook, scriptKey, asset.ScriptKeyUnknown,
		)
		assertTweak(t, ctx, addrBook, scriptKey, nil)

		// We'll now insert it again, but this time declare it as known
		// and also know the tweak.
		err = addrBook.InsertScriptKey(
			ctx, scriptKey, asset.ScriptKeyBip86,
		)
		require.NoError(t, err)

		// We'll fetch the script key and confirm that it's known.
		assertKeyKnowledge(
			t, ctx, addrBook, scriptKey, asset.ScriptKeyBip86,
		)
	})
}
