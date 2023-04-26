package tarogarden_test

import (
	"context"
	"database/sql"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/tarodb"
	"github.com/lightninglabs/taro/tarodb/sqlc"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/stretchr/testify/require"
)

var (
	testPollInterval = 20 * time.Millisecond
	testTimeout      = 1 * time.Second
	chainParams      = &address.RegressionNetTaro

	txTypeTaproot = lnrpc.OutputScriptType_SCRIPT_TYPE_WITNESS_V1_TAPROOT
)

// newAddrBook creates a new instance of the TaroAddressBook book.
func newAddrBook(t *testing.T, keyRing *tarogarden.MockKeyRing) (*address.Book,
	*tarodb.TaroAddressBook, sqlc.Querier) {

	db := tarodb.NewTestDB(t)

	txCreator := func(tx *sql.Tx) tarodb.AddrBook {
		return db.WithTx(tx)
	}

	addrTx := tarodb.NewTransactionExecutor(db, txCreator)
	tarodbBook := tarodb.NewTaroAddressBook(addrTx, chainParams)
	book := address.NewBook(address.BookConfig{
		Store:        tarodbBook,
		StoreTimeout: testTimeout,
		Chain:        *chainParams,
		KeyRing:      keyRing,
	})
	return book, tarodbBook, db
}

// newProofArchive creates a new instance of the MultiArchiver.
func newProofArchive(t *testing.T) (*proof.MultiArchiver, *tarodb.AssetStore) {
	db := tarodb.NewTestDB(t)

	txCreator := func(tx *sql.Tx) tarodb.ActiveAssetsStore {
		return db.WithTx(tx)
	}

	assetDB := tarodb.NewTransactionExecutor(
		db, txCreator,
	)
	assetStore := tarodb.NewAssetStore(assetDB)

	proofArchive := proof.NewMultiArchiver(
		proof.NewMockVerifier(t), tarodb.DefaultStoreTimeout,
		assetStore,
	)

	return proofArchive, assetStore
}

type custodianHarness struct {
	t            *testing.T
	c            *tarogarden.Custodian
	cfg          *tarogarden.CustodianConfig
	chainBridge  *tarogarden.MockChainBridge
	walletAnchor *tarogarden.MockWalletAnchor
	keyRing      *tarogarden.MockKeyRing
	tarodbBook   *tarodb.TaroAddressBook
	addrBook     *address.Book
	assetDB      *tarodb.AssetStore
	proofArchive *proof.MultiArchiver
}

// assertStartup makes sure the custodian was started correctly.
func (h *custodianHarness) assertStartup() {
	// Make sure SubscribeTransactions is called on startup.
	_, err := chanutils.RecvOrTimeout(
		h.walletAnchor.SubscribeTxSignal, testTimeout,
	)
	require.NoError(h.t, err)

	// Make sure ListTransactions is called on startup.
	_, err = chanutils.RecvOrTimeout(
		h.walletAnchor.ListTxnsSignal, testTimeout,
	)
	require.NoError(h.t, err)
}

// eventually is a shortcut for require.Eventually with the timeout and poll
// interval pre-set.
func (h *custodianHarness) eventually(fn func() bool) {
	require.Eventually(h.t, fn, testTimeout, testPollInterval)
}

// assertAddrsRegistered makes sure that for each of the given addresses a
// pubkey was imported into the wallet.
func (h *custodianHarness) assertAddrsRegistered(
	addrs ...*address.AddrWithKeyInfo) {

	for _, addr := range addrs {
		pubKey, err := chanutils.RecvOrTimeout(
			h.walletAnchor.ImportPubKeySignal, testTimeout,
		)
		require.NoError(h.t, err)
		require.Equal(
			h.t, schnorr.SerializePubKey(&addr.TaprootOutputKey),
			schnorr.SerializePubKey(*pubKey),
		)
	}
}

func newHarness(t *testing.T,
	initialAddrs []*address.AddrWithKeyInfo) *custodianHarness {

	chainBridge := tarogarden.NewMockChainBridge()
	walletAnchor := tarogarden.NewMockWalletAnchor()
	keyRing := tarogarden.NewMockKeyRing()
	addrBook, tarodbBook, _ := newAddrBook(t, keyRing)
	proofArchive, assetDB := newProofArchive(t)

	ctxb := context.Background()
	for _, initialAddr := range initialAddrs {
		err := tarodbBook.InsertAddrs(ctxb, *initialAddr)
		require.NoError(t, err)
	}

	cfg := &tarogarden.CustodianConfig{
		ChainParams:   chainParams,
		ChainBridge:   chainBridge,
		WalletAnchor:  walletAnchor,
		AddrBook:      addrBook,
		ProofArchive:  proofArchive,
		ProofNotifier: assetDB,
		ErrChan:       make(chan error, 1),
	}
	return &custodianHarness{
		t:            t,
		c:            tarogarden.NewCustodian(cfg),
		cfg:          cfg,
		chainBridge:  chainBridge,
		walletAnchor: walletAnchor,
		keyRing:      keyRing,
		tarodbBook:   tarodbBook,
		addrBook:     addrBook,
		assetDB:      assetDB,
		proofArchive: proofArchive,
	}
}

func randAddr(h *custodianHarness) *address.AddrWithKeyInfo {
	addr, genesis := address.RandAddr(h.t, &address.RegressionNetTaro)

	err := h.tarodbBook.InsertAssetGen(context.Background(), genesis)
	require.NoError(h.t, err)

	return addr
}

func randWalletTx(addr *address.AddrWithKeyInfo) (int, *lndclient.Transaction) {
	tx := &lndclient.Transaction{
		Tx:        wire.NewMsgTx(2),
		Timestamp: time.Now(),
	}
	numInputs := rand.Intn(10) + 1
	numOutputs := rand.Intn(5) + 1
	taprootOutput := rand.Intn(numOutputs)

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
			PkScript: test.RandBytes(34),
			Value:    rand.Int63n(5000000),
		}
		detail := &lnrpc.OutputDetail{
			Amount:       out.Value,
			IsOurAddress: rand.Int31()%2 == 0,
		}

		// We've randomly chosen an index where we place our Taproot
		// output key of the address.
		if addr != nil && idx == taprootOutput {
			out.PkScript, _ = taroscript.PayToTaprootScript(
				&addr.TaprootOutputKey,
			)
			detail.OutputType = txTypeTaproot
			detail.IsOurAddress = true
		}

		tx.Tx.AddTxOut(out)
		tx.OutputDetails = append(tx.OutputDetails, detail)
	}

	return taprootOutput, tx
}

// TestCustodianNewAddr makes sure that a new address is imported into the
// wallet and watched on-chain if a new one is added to the address book.,
func TestCustodianNewAddr(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil)
	require.NoError(t, h.c.Start())
	t.Cleanup(func() {
		require.NoError(t, h.c.Stop())
	})
	h.assertStartup()

	// Store a new random address to the store. We need to acknowledge the
	// creation of two keys in a goroutine to unblock the underlying key
	// ring.
	go func() {
		<-h.keyRing.ReqKeys
		<-h.keyRing.ReqKeys
	}()
	ctx := context.Background()
	addr := randAddr(h)
	dbAddr, err := h.addrBook.NewAddress(ctx, addr.AssetID, addr.Amount)
	require.NoError(t, err)

	h.assertAddrsRegistered(dbAddr)

	h.eventually(func() bool {
		addrs, err := h.tarodbBook.QueryAddrs(
			ctx, address.QueryParams{},
		)
		require.NoError(t, err)
		require.Len(t, addrs, 1)

		return !addrs[0].ManagedAfter.IsZero()
	})
}

func TestTransactionHandling(t *testing.T) {
	h := newHarness(t, nil)

	// Before we start the custodian, we create a few random addresses and a
	// corresponding wallet transaction for the first of them.
	ctx := context.Background()

	const numAddrs = 5
	addrs := make([]*address.AddrWithKeyInfo, numAddrs)
	for i := 0; i < numAddrs; i++ {
		addrs[i] = randAddr(h)
		err := h.tarodbBook.InsertAddrs(ctx, *addrs[i])
		require.NoError(t, err)
	}

	outputIdx, tx := randWalletTx(addrs[0])
	h.walletAnchor.Transactions = append(h.walletAnchor.Transactions, *tx)

	require.NoError(t, h.c.Start())
	t.Cleanup(func() {
		require.NoError(t, h.c.Stop())
	})
	h.assertStartup()

	// We expect all addresses to be watched by the wallet now.
	h.assertAddrsRegistered(addrs...)

	// Only one event should be registered though, as we've only created one
	// transaction.
	h.eventually(func() bool {
		events, err := h.tarodbBook.QueryAddrEvents(
			ctx, address.EventQueryParams{},
		)
		require.NoError(t, err)

		if len(events) != 1 {
			t.Logf("Got %d events", len(events))
			return false
		}

		require.EqualValues(t, outputIdx, events[0].Outpoint.Index)

		return true
	})
}

func mustMakeAddr(t *testing.T,
	gen asset.Genesis, groupKey *btcec.PublicKey,
	scriptKey btcec.PublicKey) *address.Taro {

	var p btcec.PublicKey
	addr, err := address.New(
		gen, groupKey, scriptKey, p, 1, &address.TestNet3Taro,
	)
	require.NoError(t, err)

	return addr
}

// TestAddrMatchesAsset tests that the AddrMatchesAsset function works
// correctly.
func TestAddrMatchesAsset(t *testing.T) {
	t.Parallel()

	randKey1, randKey2 := test.RandPubKey(t), test.RandPubKey(t)
	randGen1 := asset.RandGenesis(t, asset.Normal)
	randGen2 := asset.RandGenesis(t, asset.Normal)

	var blankKey btcec.PublicKey

	testCases := []struct {
		name   string
		addr   *address.AddrWithKeyInfo
		a      *asset.Asset
		result bool
	}{{
		name: "both group keys nil",
		addr: &address.AddrWithKeyInfo{
			Taro: mustMakeAddr(t, randGen1, nil, blankKey),
		},
		a: &asset.Asset{
			Genesis: randGen1,
			ScriptKey: asset.ScriptKey{
				PubKey: &btcec.PublicKey{},
			},
		},
		result: true,
	}, {
		name: "no group key nil",
		addr: &address.AddrWithKeyInfo{
			Taro: mustMakeAddr(t, randGen1, randKey1, blankKey),
		},
		a: &asset.Asset{
			Genesis: randGen1,
			GroupKey: &asset.GroupKey{
				GroupPubKey: *randKey1,
			},
			ScriptKey: asset.ScriptKey{
				PubKey: &btcec.PublicKey{},
			},
		},
		result: true,
	}, {
		name: "no group key nil but mismatch",
		addr: &address.AddrWithKeyInfo{
			Taro: &address.Taro{
				GroupKey: randKey1,
			},
		},
		a: &asset.Asset{
			GroupKey: &asset.GroupKey{
				GroupPubKey: *randKey2,
			},
			ScriptKey: asset.ScriptKey{
				PubKey: &btcec.PublicKey{},
			},
		},
		result: false,
	}, {
		name: "one group key nil",
		addr: &address.AddrWithKeyInfo{
			Taro: &address.Taro{},
		},
		a: &asset.Asset{
			GroupKey: &asset.GroupKey{
				GroupPubKey: *randKey1,
			},
			ScriptKey: asset.ScriptKey{
				PubKey: &btcec.PublicKey{},
			},
		},
		result: false,
	}, {
		name: "id mismatch",
		addr: &address.AddrWithKeyInfo{
			Taro: mustMakeAddr(t, randGen1, randKey1, *randKey1),
		},
		a: &asset.Asset{
			Genesis: randGen2,
			GroupKey: &asset.GroupKey{
				GroupPubKey: *randKey1,
			},
			ScriptKey: asset.ScriptKey{
				PubKey: &btcec.PublicKey{},
			},
		},
		result: false,
	}, {
		name: "script key mismatch",
		addr: &address.AddrWithKeyInfo{
			Taro: mustMakeAddr(t, randGen1, randKey1, *randKey1),
		},
		a: &asset.Asset{
			Genesis: randGen1,
			GroupKey: &asset.GroupKey{
				GroupPubKey: *randKey1,
			},
			ScriptKey: asset.ScriptKey{
				PubKey: randKey2,
			},
		},
		result: false,
	}, {
		name: "all match",
		addr: &address.AddrWithKeyInfo{
			Taro: mustMakeAddr(t, randGen1, randKey1, *randKey2),
		},
		a: &asset.Asset{
			Genesis: randGen1,
			GroupKey: &asset.GroupKey{
				GroupPubKey: *randKey1,
			},
			ScriptKey: asset.ScriptKey{
				PubKey: randKey2,
			},
		},
		result: true,
	}}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()

			require.Equal(
				tt, tc.result, tarogarden.AddrMatchesAsset(
					tc.addr, tc.a,
				),
			)
		})
	}
}
