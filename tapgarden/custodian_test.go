package tapgarden_test

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
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/stretchr/testify/require"
)

var (
	testPollInterval = 20 * time.Millisecond
	testTimeout      = 1 * time.Second
	chainParams      = &address.RegressionNetTap

	txTypeTaproot = lnrpc.OutputScriptType_SCRIPT_TYPE_WITNESS_V1_TAPROOT
)

// newAddrBook creates a new instance of the TapAddressBook book.
func newAddrBook(t *testing.T, keyRing *tapgarden.MockKeyRing,
	syncer *tapgarden.MockAssetSyncer) (*address.Book,
	*tapdb.TapAddressBook, sqlc.Querier) {

	db := tapdb.NewTestDB(t)

	txCreator := func(tx *sql.Tx) tapdb.AddrBook {
		return db.WithTx(tx)
	}

	addrTx := tapdb.NewTransactionExecutor(db, txCreator)
	testClock := clock.NewTestClock(time.Now())
	tapdbBook := tapdb.NewTapAddressBook(addrTx, chainParams, testClock)
	book := address.NewBook(address.BookConfig{
		Store:        tapdbBook,
		Syncer:       syncer,
		StoreTimeout: testTimeout,
		Chain:        *chainParams,
		KeyRing:      keyRing,
	})
	return book, tapdbBook, db
}

// newProofArchive creates a new instance of the MultiArchiver.
func newProofArchive(t *testing.T) (*proof.MultiArchiver, *tapdb.AssetStore) {
	db := tapdb.NewTestDB(t)

	txCreator := func(tx *sql.Tx) tapdb.ActiveAssetsStore {
		return db.WithTx(tx)
	}

	assetDB := tapdb.NewTransactionExecutor(
		db, txCreator,
	)
	testClock := clock.NewTestClock(time.Now())
	assetStore := tapdb.NewAssetStore(assetDB, testClock)

	proofArchive := proof.NewMultiArchiver(
		proof.NewMockVerifier(t), tapdb.DefaultStoreTimeout,
		assetStore,
	)

	return proofArchive, assetStore
}

type custodianHarness struct {
	t            *testing.T
	c            *tapgarden.Custodian
	cfg          *tapgarden.CustodianConfig
	chainBridge  *tapgarden.MockChainBridge
	walletAnchor *tapgarden.MockWalletAnchor
	keyRing      *tapgarden.MockKeyRing
	tapdbBook    *tapdb.TapAddressBook
	addrBook     *address.Book
	syncer       *tapgarden.MockAssetSyncer
	assetDB      *tapdb.AssetStore
	proofArchive *proof.MultiArchiver
}

// assertStartup makes sure the custodian was started correctly.
func (h *custodianHarness) assertStartup() {
	// Make sure SubscribeTransactions is called on startup.
	_, err := fn.RecvOrTimeout(
		h.walletAnchor.SubscribeTxSignal, testTimeout,
	)
	require.NoError(h.t, err)

	// Make sure ListTransactions is called on startup.
	_, err = fn.RecvOrTimeout(
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
		pubKey, err := fn.RecvOrTimeout(
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

	chainBridge := tapgarden.NewMockChainBridge()
	walletAnchor := tapgarden.NewMockWalletAnchor()
	keyRing := tapgarden.NewMockKeyRing()
	syncer := tapgarden.NewMockAssetSyncer()
	addrBook, tapdbBook, _ := newAddrBook(t, keyRing, syncer)
	proofArchive, assetDB := newProofArchive(t)

	ctxb := context.Background()
	for _, initialAddr := range initialAddrs {
		err := tapdbBook.InsertAddrs(ctxb, *initialAddr)
		require.NoError(t, err)
	}

	cfg := &tapgarden.CustodianConfig{
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
		c:            tapgarden.NewCustodian(cfg),
		cfg:          cfg,
		chainBridge:  chainBridge,
		walletAnchor: walletAnchor,
		keyRing:      keyRing,
		tapdbBook:    tapdbBook,
		addrBook:     addrBook,
		syncer:       syncer,
		assetDB:      assetDB,
		proofArchive: proofArchive,
	}
}

func randAddr(h *custodianHarness) *address.AddrWithKeyInfo {
	proofCourierAddr := address.RandProofCourierAddr(h.t)
	addr, genesis, group := address.RandAddr(
		h.t, &address.RegressionNetTap, proofCourierAddr,
	)

	err := h.tapdbBook.InsertAssetGen(context.Background(), genesis, group)
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
			out.PkScript, _ = tapscript.PayToTaprootScript(
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

// insertAssetInfo starts a background goroutine that receives asset info that
// was fetched from the asset syncer, and stores it in the address book. This
// simulates asset bootstrapping that would occur during universe sync.
func insertAssetInfo(t *testing.T, ctx context.Context, quit <-chan struct{},
	book *tapdb.TapAddressBook, syncer *tapgarden.MockAssetSyncer) {

	go func() {
		for {
			select {
			case <-ctx.Done():
				return

			case <-quit:
				return

			case newAsset := <-syncer.FetchedAssets:
				err := book.InsertAssetGen(
					ctx, newAsset.Genesis,
					newAsset.GroupKey,
				)
				require.NoError(t, err)

			default:
			}
		}
	}()
}

// TestCustodianNewAddr makes sure that a new address is imported into the
// wallet and watched on-chain if a new one is added to the address book.
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
	proofCourierAddr := address.RandProofCourierAddr(t)
	dbAddr, err := h.addrBook.NewAddress(
		ctx, addr.AssetID, addr.Amount, nil, proofCourierAddr,
	)
	require.NoError(t, err)

	h.assertAddrsRegistered(dbAddr)

	h.eventually(func() bool {
		addrs, err := h.tapdbBook.QueryAddrs(
			ctx, address.QueryParams{},
		)
		require.NoError(t, err)
		require.Len(t, addrs, 1)

		return !addrs[0].ManagedAfter.IsZero()
	})
}

// TestBookAssetSyncer makes sure that addresses can be created for assets
// not yet known to the address book.
func TestBookAssetSyncer(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil)
	require.NoError(t, h.c.Start())
	t.Cleanup(func() {
		require.NoError(t, h.c.Stop())
	})
	h.assertStartup()

	ctx := context.Background()
	proofCourierAddr := address.RandProofCourierAddr(t)

	// Start a background goroutine to add assets that have been
	// fetched from the asset syncer to the address book, to mimic a
	// universe sync.
	quitAssetWatcher := make(chan struct{})
	insertAssetInfo(
		t, ctx, quitAssetWatcher, h.tapdbBook, h.syncer,
	)

	// Address creation should fail for unknown assets.
	newAsset := asset.RandAsset(t, asset.Type(test.RandInt31n(2)))
	_, err := h.addrBook.NewAddress(
		ctx, newAsset.ID(), 1, nil, proofCourierAddr,
	)
	require.ErrorContains(t, err, "unknown asset")

	// If we add the asset to the asset syncer, address creation should
	// succeed.
	h.syncer.AddAsset(*newAsset)
	go func() {
		<-h.keyRing.ReqKeys
		<-h.keyRing.ReqKeys
	}()
	newAddr, err := h.addrBook.NewAddress(
		ctx, newAsset.ID(), 1, nil, proofCourierAddr,
	)
	require.NoError(t, err)
	require.NotNil(t, newAddr)

	numAddrs := 1
	validAddrs := fn.MakeSlice(newAddr)

	// TODO(jhb): remove asset from syncer, assert that address creation
	// for the same asset works

	// If the asset syncer returns an error, that should propogate up to
	// the address creator.
	h.syncer.FetchErrs = true

	secondAsset := asset.RandAsset(t, asset.Type(test.RandInt31n(2)))
	_, err = h.addrBook.NewAddress(
		ctx, secondAsset.ID(), 1, nil, proofCourierAddr,
	)
	require.ErrorContains(t, err, "failed to fetch asset info")

	h.assertAddrsRegistered(validAddrs...)

	h.eventually(func() bool {
		addrs, err := h.tapdbBook.QueryAddrs(
			ctx, address.QueryParams{},
		)
		require.NoError(t, err)
		require.Len(t, addrs, numAddrs)

		return !addrs[0].ManagedAfter.IsZero()
	})

	close(quitAssetWatcher)
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
		err := h.tapdbBook.InsertAddrs(ctx, *addrs[i])
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
		events, err := h.tapdbBook.QueryAddrEvents(
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
	groupWitness wire.TxWitness, scriptKey btcec.PublicKey) *address.Tap {

	var p btcec.PublicKey
	proofCourierAddr := address.RandProofCourierAddr(t)
	addr, err := address.New(
		address.V0, gen, groupKey, groupWitness, scriptKey,
		p, 1, nil, &address.TestNet3Tap, proofCourierAddr,
	)
	require.NoError(t, err)

	return addr
}

// TestAddrMatchesAsset tests that the AddrMatchesAsset function works
// correctly.
func TestAddrMatchesAsset(t *testing.T) {
	t.Parallel()

	randKey1, randKey2 := test.RandPubKey(t), test.RandPubKey(t)
	randScriptKey1, randScriptKey2 := test.RandPubKey(t), test.RandPubKey(t)
	randGen1 := asset.RandGenesis(t, asset.Normal)
	randGen2 := asset.RandGenesis(t, asset.Normal)
	protoAsset1 := asset.RandAssetWithValues(
		t, randGen1, nil, asset.NewScriptKey(randScriptKey1),
	)
	protoAsset2 := asset.RandAssetWithValues(
		t, randGen2, nil, asset.NewScriptKey(randScriptKey2),
	)
	randGroup1 := asset.RandGroupKey(t, randGen1, protoAsset1)
	randGroup2 := asset.RandGroupKey(t, randGen2, protoAsset2)

	var blankKey btcec.PublicKey

	testCases := []struct {
		name   string
		addr   *address.AddrWithKeyInfo
		a      *asset.Asset
		result bool
	}{{
		name: "both group keys nil",
		addr: &address.AddrWithKeyInfo{
			Tap: mustMakeAddr(t, randGen1, nil, nil, blankKey),
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
			Tap: mustMakeAddr(
				t, randGen1, &randGroup1.GroupPubKey,
				randGroup1.Witness, blankKey,
			),
		},
		a: &asset.Asset{
			Genesis:  randGen1,
			GroupKey: randGroup1,
			ScriptKey: asset.ScriptKey{
				PubKey: &btcec.PublicKey{},
			},
		},
		result: true,
	}, {
		name: "no group key nil but mismatch",
		addr: &address.AddrWithKeyInfo{
			Tap: &address.Tap{
				GroupKey: &randGroup1.GroupPubKey,
			},
		},
		a: &asset.Asset{
			GroupKey: randGroup2,
			ScriptKey: asset.ScriptKey{
				PubKey: &btcec.PublicKey{},
			},
		},
		result: false,
	}, {
		name: "one group key nil",
		addr: &address.AddrWithKeyInfo{
			Tap: &address.Tap{},
		},
		a: &asset.Asset{
			GroupKey: randGroup1,
			ScriptKey: asset.ScriptKey{
				PubKey: &btcec.PublicKey{},
			},
		},
		result: false,
	}, {
		name: "id mismatch",
		addr: &address.AddrWithKeyInfo{
			Tap: mustMakeAddr(
				t, randGen1, &randGroup1.GroupPubKey,
				randGroup1.Witness, *randKey1,
			),
		},
		a: &asset.Asset{
			Genesis:  randGen2,
			GroupKey: randGroup1,
			ScriptKey: asset.ScriptKey{
				PubKey: &btcec.PublicKey{},
			},
		},
		result: false,
	}, {
		name: "script key mismatch",
		addr: &address.AddrWithKeyInfo{
			Tap: mustMakeAddr(
				t, randGen1, &randGroup1.GroupPubKey,
				randGroup1.Witness, *randKey1,
			),
		},
		a: &asset.Asset{
			Genesis:  randGen1,
			GroupKey: randGroup1,
			ScriptKey: asset.ScriptKey{
				PubKey: randKey2,
			},
		},
		result: false,
	}, {
		name: "all match",
		addr: &address.AddrWithKeyInfo{
			Tap: mustMakeAddr(
				t, randGen1, &randGroup1.GroupPubKey,
				randGroup1.Witness, *randKey2,
			),
		},
		a: &asset.Asset{
			Genesis:  randGen1,
			GroupKey: randGroup1,
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
				tt, tc.result, tapgarden.AddrMatchesAsset(
					tc.addr, tc.a,
				),
			)
		})
	}
}
