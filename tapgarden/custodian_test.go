package tapgarden_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"math/rand"
	"net/url"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/lndclient"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

var (
	testPollInterval = 20 * time.Millisecond
	testTimeout      = 1 * time.Second
	chainParams      = &address.RegressionNetTap

	txTypeTaproot = lnrpc.OutputScriptType_SCRIPT_TYPE_WITNESS_V1_TAPROOT
)

// newAddrBook creates a new instance of the TapAddressBook book.
func newAddrBookForDB(db *tapdb.BaseDB, keyRing *tapgarden.MockKeyRing,
	syncer *tapgarden.MockAssetSyncer) (*address.Book,
	*tapdb.TapAddressBook) {

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
	return book, tapdbBook
}

type mockVerifier struct {
	t *testing.T
}

func newMockVerifier(t *testing.T) *mockVerifier {
	return &mockVerifier{
		t: t,
	}
}

func (m *mockVerifier) Verify(_ context.Context, r io.Reader,
	_ proof.VerifierCtx) (*proof.AssetSnapshot, error) {

	f := &proof.File{}
	err := f.Decode(r)
	require.NoError(m.t, err)

	lastProof, err := f.LastProof()
	require.NoError(m.t, err)

	ac, err := commitment.NewAssetCommitment(&lastProof.Asset)
	require.NoError(m.t, err)
	tc, err := commitment.NewTapCommitment(nil, ac)
	require.NoError(m.t, err)

	return &proof.AssetSnapshot{
		Asset:           &lastProof.Asset,
		OutPoint:        lastProof.OutPoint(),
		OutputIndex:     lastProof.InclusionProof.OutputIndex,
		AnchorBlockHash: lastProof.BlockHeader.BlockHash(),
		AnchorTx:        &lastProof.AnchorTx,
		InternalKey:     lastProof.InclusionProof.InternalKey,
		ScriptRoot:      tc,
	}, nil
}

// newProofArchive creates a new instance of the MultiArchiver.
func newProofArchiveForDB(t *testing.T, db *tapdb.BaseDB) (*proof.MultiArchiver,
	*tapdb.AssetStore, *tapdb.MultiverseStore) {

	txCreator := func(tx *sql.Tx) tapdb.ActiveAssetsStore {
		return db.WithTx(tx)
	}

	metaTxCreator := func(tx *sql.Tx) tapdb.MetaStore {
		return db.WithTx(tx)
	}

	assetDB := tapdb.NewTransactionExecutor(
		db, txCreator,
	)

	metaDB := tapdb.NewTransactionExecutor(
		db, metaTxCreator,
	)

	testClock := clock.NewTestClock(time.Now())
	assetStore := tapdb.NewAssetStore(
		assetDB, metaDB, testClock, db.Backend(),
	)

	proofArchive := proof.NewMultiArchiver(
		proof.NewMockVerifier(t), tapdb.DefaultStoreTimeout,
		assetStore,
	)

	multiverseDB := tapdb.NewTransactionExecutor(
		db, func(tx *sql.Tx) tapdb.BaseMultiverseStore {
			return db.WithTx(tx)
		},
	)
	multiverse := tapdb.NewMultiverseStore(
		multiverseDB, tapdb.DefaultMultiverseStoreConfig(),
	)

	return proofArchive, assetStore, multiverse
}

type custodianHarness struct {
	t            *testing.T
	c            *tapgarden.Custodian
	cfg          *tapgarden.CustodianConfig
	errChan      chan error
	chainBridge  *tapgarden.MockChainBridge
	walletAnchor *tapgarden.MockWalletAnchor
	keyRing      *tapgarden.MockKeyRing
	tapdbBook    *tapdb.TapAddressBook
	addrBook     *address.Book
	syncer       *tapgarden.MockAssetSyncer
	assetDB      *tapdb.AssetStore
	multiverse   *tapdb.MultiverseStore
	courier      *proof.MockProofCourier
}

// assertStartup makes sure the custodian was started correctly.
func (h *custodianHarness) assertStartup() {
	// Make sure SubscribeTransactions is called on startup.
	_, err := fn.RecvOrTimeout(
		h.walletAnchor.SubscribeTxSignal, testTimeout,
	)
	require.NoError(h.t, err)

	// Make sure we don't have an error on startup.
	select {
	case err := <-h.errChan:
		require.NoError(h.t, err)

	case <-time.After(testPollInterval):
	}

	// Make sure ListTransactions is called on startup.
	_, err = fn.RecvOrTimeout(
		h.walletAnchor.ListTxnsSignal, testTimeout,
	)
	require.NoError(h.t, err)

	// Make sure we don't have an error on startup.
	select {
	case err := <-h.errChan:
		require.NoError(h.t, err)

	case <-time.After(testPollInterval):
	}
}

// eventually is a shortcut for require.Eventually with the timeout and poll
// interval pre-set.
func (h *custodianHarness) eventually(fn func() bool) {
	require.Eventually(h.t, fn, testTimeout, testPollInterval)
}

// assertEventsPresent makes sure that the given number of events is present in
// the address book, then returns those events.
func (h *custodianHarness) assertEventsPresent(numEvents int,
	status address.Status) []*address.Event {

	ctx := context.Background()
	ctxt, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	// Only one event should be registered though, as we've only created one
	// transaction.
	var finalEvents []*address.Event
	err := wait.NoError(func() error {
		events, err := h.tapdbBook.QueryAddrEvents(
			ctxt, address.EventQueryParams{},
		)
		if err != nil {
			return err
		}

		if len(events) != numEvents {
			return fmt.Errorf("wanted %d events but got %d",
				numEvents, len(events))
		}

		for idx, event := range events {
			if event.Status != status {
				return fmt.Errorf("event %d has status %v "+
					"but wanted %v", idx, event.Status,
					status)
			}
		}

		finalEvents = events

		return nil
	}, testTimeout)
	require.NoError(h.t, err)

	return finalEvents
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

// addProofFileToMultiverse adds the given proof to the multiverse store.
func (h *custodianHarness) addProofFileToMultiverse(p *proof.AnnotatedProof) {
	f := &proof.File{}
	err := f.Decode(bytes.NewReader(p.Blob))
	require.NoError(h.t, err)

	ctx := context.Background()
	ctxt, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	for i := uint32(0); i < uint32(f.NumProofs()); i++ {
		transition, err := f.ProofAt(i)
		require.NoError(h.t, err)

		rawTransition, err := f.RawProofAt(i)
		require.NoError(h.t, err)

		id := universe.NewUniIDFromAsset(transition.Asset)
		key := universe.BaseLeafKey{
			OutPoint: transition.OutPoint(),
			ScriptKey: fn.Ptr(asset.NewScriptKey(
				transition.Asset.ScriptKey.PubKey,
			)),
		}
		leaf := &universe.Leaf{
			GenesisWithGroup: universe.GenesisWithGroup{
				Genesis:  transition.Asset.Genesis,
				GroupKey: transition.Asset.GroupKey,
			},
			RawProof: rawTransition,
			Asset:    &transition.Asset,
			Amt:      transition.Asset.Amount,
		}
		h.t.Logf("Importing proof with script key %x and outpoint %v "+
			"into multiverse",
			key.ScriptKey.PubKey.SerializeCompressed(),
			key.OutPoint)
		_, err = h.multiverse.UpsertProofLeaf(ctxt, id, key, leaf, nil)
		require.NoError(h.t, err)
	}
}

func newHarness(t *testing.T,
	initialAddrs []*address.AddrWithKeyInfo) *custodianHarness {

	chainBridge := tapgarden.NewMockChainBridge()
	walletAnchor := tapgarden.NewMockWalletAnchor()
	keyRing := tapgarden.NewMockKeyRing()
	syncer := tapgarden.NewMockAssetSyncer()
	db := tapdb.NewTestDB(t)
	addrBook, tapdbBook := newAddrBookForDB(db.BaseDB, keyRing, syncer)

	_, assetDB, multiverse := newProofArchiveForDB(t, db.BaseDB)
	notifier := proof.NewMultiArchiveNotifier(assetDB, multiverse)

	courier := proof.NewMockProofCourier()
	courierDispatch := &proof.MockProofCourierDispatcher{
		Courier: courier,
	}
	proofWatcher := &tapgarden.MockProofWatcher{}

	ctxb := context.Background()
	for _, initialAddr := range initialAddrs {
		err := tapdbBook.InsertAddrs(ctxb, *initialAddr)
		require.NoError(t, err)
	}

	archive := proof.NewMultiArchiver(
		newMockVerifier(t), testTimeout, assetDB,
	)

	errChan := make(chan error, 1)
	cfg := &tapgarden.CustodianConfig{
		ChainParams:            chainParams,
		ChainBridge:            chainBridge,
		WalletAnchor:           walletAnchor,
		AddrBook:               addrBook,
		ProofArchive:           archive,
		ProofNotifier:          notifier,
		ProofCourierDispatcher: courierDispatch,
		ProofWatcher:           proofWatcher,
		ErrChan:                errChan,
	}
	return &custodianHarness{
		t:            t,
		c:            tapgarden.NewCustodian(cfg),
		cfg:          cfg,
		errChan:      errChan,
		chainBridge:  chainBridge,
		walletAnchor: walletAnchor,
		keyRing:      keyRing,
		tapdbBook:    tapdbBook,
		addrBook:     addrBook,
		syncer:       syncer,
		assetDB:      assetDB,
		multiverse:   multiverse,
		courier:      courier,
	}
}

func randAddr(h *custodianHarness) (*address.AddrWithKeyInfo, *asset.Genesis) {
	addr, genesis, group := address.RandAddr(
		h.t, &address.RegressionNetTap, url.URL{
			Scheme: "mock",
		},
	)

	err := h.tapdbBook.InsertAssetGen(context.Background(), genesis, group)
	require.NoError(h.t, err)

	return addr, genesis
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
		in := &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  test.RandHash(),
				Index: rand.Uint32(),
			},
		}
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
			out.PkScript, _ = txscript.PayToTaprootScript(
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

func randProof(t *testing.T, outputIndex int, tx *wire.MsgTx,
	genesis *asset.Genesis,
	addr *address.AddrWithKeyInfo) *proof.AnnotatedProof {

	a := asset.Asset{
		Version:   asset.V0,
		Genesis:   *genesis,
		Amount:    addr.Amount,
		ScriptKey: asset.NewScriptKey(&addr.ScriptKey),
		PrevWitnesses: []asset.Witness{
			{
				PrevID: &asset.PrevID{},
			},
		},
	}
	if addr.GroupKey != nil {
		a.GroupKey = &asset.GroupKey{
			GroupPubKey: *addr.GroupKey,
		}
	}

	p := &proof.Proof{
		PrevOut: wire.OutPoint{},
		BlockHeader: wire.BlockHeader{
			Timestamp: time.Unix(rand.Int63(), 0),
		},
		AnchorTx:      *tx,
		TxMerkleProof: proof.TxMerkleProof{},
		Asset:         a,
		InclusionProof: proof.TaprootProof{
			InternalKey: test.RandPubKey(t),
			OutputIndex: uint32(outputIndex),
		},
	}

	f, err := proof.NewFile(proof.V0, *p)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, f.Encode(&buf))

	ac, err := commitment.NewAssetCommitment(&a)
	require.NoError(t, err)
	tc, err := commitment.NewTapCommitment(nil, ac)
	require.NoError(t, err)

	op := wire.OutPoint{
		Hash:  tx.TxHash(),
		Index: uint32(outputIndex),
	}

	return &proof.AnnotatedProof{
		Locator: proof.Locator{
			AssetID:   fn.Ptr(genesis.ID()),
			GroupKey:  addr.GroupKey,
			ScriptKey: addr.ScriptKey,
			OutPoint:  &op,
		},
		Blob: buf.Bytes(),
		AssetSnapshot: &proof.AssetSnapshot{
			Asset:       &a,
			OutPoint:    op,
			AnchorTx:    tx,
			OutputIndex: uint32(outputIndex),
			InternalKey: test.RandPubKey(t),
			ScriptRoot:  tc,
		},
	}
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

	ctx := context.Background()
	addr, _ := randAddr(h)
	proofCourierAddr := address.RandProofCourierAddr(t)
	addrVersion := test.RandFlip(address.V0, address.V1)
	dbAddr, err := h.addrBook.NewAddress(
		ctx, addrVersion, addr.AssetID, addr.Amount, nil,
		proofCourierAddr,
	)
	require.NoError(t, err)

	h.keyRing.AssertNumberOfCalls(t, "DeriveNextTaprootAssetKey", 2)

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
	addrVersion := test.RandFlip(address.V0, address.V1)
	_, err := h.addrBook.NewAddress(
		ctx, addrVersion, newAsset.ID(), 1, nil, proofCourierAddr,
	)
	require.ErrorContains(t, err, "unknown asset")

	// If we add the asset to the asset syncer, address creation should
	// succeed.
	h.syncer.AddAsset(*newAsset)

	// Fetch the asset from the syncer. This should trigger the
	// background goroutine to add the asset to the address book.
	_, err = h.syncer.FetchAsset(newAsset.ID())
	require.NoError(t, err)

	// Eventually, the asset should be registered and we should be able to
	// create a new address for it.
	var newAddr *address.AddrWithKeyInfo
	addrVersion = test.RandFlip(address.V0, address.V1)

	require.Eventually(t, func() bool {
		newAddr, err = h.addrBook.NewAddress(
			ctx, addrVersion, newAsset.ID(), 1, nil,
			proofCourierAddr,
		)
		if err != nil {
			return false
		}

		return newAddr != nil
	}, defaultTimeout, wait.PollInterval)

	h.keyRing.AssertNumberOfCalls(t, "DeriveNextTaprootAssetKey", 2)

	numAddrs := 1
	validAddrs := fn.MakeSlice(newAddr)

	// TODO(jhb): remove asset from syncer, assert that address creation
	// for the same asset works

	// If the asset syncer returns an error, that should propagate up to
	// the address creator.
	h.syncer.FetchErrs = true

	secondAsset := asset.RandAsset(t, asset.Type(test.RandInt31n(2)))
	addrVersion = test.RandFlip(address.V0, address.V1)
	_, err = h.addrBook.NewAddress(
		ctx, addrVersion, secondAsset.ID(), 1, nil, proofCourierAddr,
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

// TestTransactionHandling tests that the custodian correctly handles incoming
// transactions.
func TestTransactionHandling(t *testing.T) {
	h := newHarness(t, nil)

	// Before we start the custodian, we create a few random addresses and a
	// corresponding wallet transaction for the first of them.
	ctx := context.Background()

	const numAddrs = 5
	addrs := make([]*address.AddrWithKeyInfo, numAddrs)
	genesis := make([]*asset.Genesis, numAddrs)
	for i := 0; i < numAddrs; i++ {
		addrs[i], genesis[i] = randAddr(h)
		err := h.tapdbBook.InsertAddrs(ctx, *addrs[i])
		require.NoError(t, err)
	}

	outputIdx, tx := randWalletTx(addrs[0])
	tx.Confirmations = 1
	h.walletAnchor.Transactions = append(h.walletAnchor.Transactions, *tx)

	mockProof := randProof(t, outputIdx, tx.Tx, genesis[0], addrs[0])
	recipient := proof.Recipient{}
	err := h.courier.DeliverProof(nil, recipient, mockProof)
	require.NoError(t, err)

	require.NoError(t, h.c.Start())
	t.Cleanup(func() {
		require.NoError(t, h.c.Stop())
	})
	h.assertStartup()

	// We expect all addresses to be watched by the wallet now.
	h.assertAddrsRegistered(addrs...)

	// Only one event should be registered though, as we've only created one
	// transaction.
	events := h.assertEventsPresent(1, address.StatusCompleted)
	require.EqualValues(t, outputIdx, events[0].Outpoint.Index)

	dbProof, err := h.assetDB.FetchProof(ctx, mockProof.Locator)
	require.NoError(t, err)
	require.EqualValues(t, mockProof.Blob, dbProof)
}

// TestTransactionConfirmedOnly tests that the custodian only starts the proof
// courier once a transaction has been confirmed. We also test that it correctly
// re-tries fetching proofs using a proof courier after it has been restarted.
func TestTransactionConfirmedOnly(t *testing.T) {
	t.Parallel()

	runTransactionConfirmedOnlyTest(t, false)
	runTransactionConfirmedOnlyTest(t, true)
}

// runTransactionConfirmedOnlyTest runs the transaction confirmed only test,
// optionally restarting the custodian in the middle.
func runTransactionConfirmedOnlyTest(t *testing.T, withRestart bool) {
	h := newHarness(t, nil)

	// Before we start the custodian, we create a few random addresses.
	ctx := context.Background()

	const numAddrs = 5
	addrs := make([]*address.AddrWithKeyInfo, numAddrs)
	genesis := make([]*asset.Genesis, numAddrs)
	for i := 0; i < numAddrs; i++ {
		addrs[i], genesis[i] = randAddr(h)
		err := h.tapdbBook.InsertAddrs(ctx, *addrs[i])
		require.NoError(t, err)
	}

	// We start the custodian and make sure it's started up correctly. This
	// should add pending events for each of the addresses.
	require.NoError(t, h.c.Start())
	t.Cleanup(func() {
		require.NoError(t, h.c.Stop())
	})
	h.assertStartup()

	// We expect all addresses to be watched by the wallet now.
	h.assertAddrsRegistered(addrs...)

	// To make sure the custodian adds address events for each address, we
	// need to signal an unconfirmed transaction for each of them now.
	outputIndexes := make([]int, numAddrs)
	transactions := make([]*lndclient.Transaction, numAddrs)
	recipient := proof.Recipient{}
	for idx := range addrs {
		outputIndex, tx := randWalletTx(addrs[idx])
		outputIndexes[idx] = outputIndex
		transactions[idx] = tx
		h.walletAnchor.SubscribeTx <- *tx

		// We also simulate that the proof courier has all the proofs
		// it needs.
		mockProof := randProof(
			t, outputIndexes[idx], tx.Tx, genesis[idx], addrs[idx],
		)
		_ = h.courier.DeliverProof(nil, recipient, mockProof)
	}

	// We want events to be created for each address, they should be in the
	// state where they detected a transaction.
	h.assertEventsPresent(numAddrs, address.StatusTransactionDetected)

	// In case we're testing with a restart, we now restart the custodian.
	if withRestart {
		require.NoError(t, h.c.Stop())

		h.c = tapgarden.NewCustodian(h.cfg)
		require.NoError(t, h.c.Start())
		h.assertStartup()
	}

	// Now we confirm the transactions. This should trigger the custodian to
	// fetch the proof for each of the addresses.
	for idx := range transactions {
		tx := transactions[idx]
		tx.Confirmations = 1
		h.walletAnchor.SubscribeTx <- *tx
	}

	h.assertEventsPresent(numAddrs, address.StatusCompleted)
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

// TestProofInMultiverseOnly tests that the custodian imports a proof correctly
// into the local archive if it's only present in the multiverse.
func TestProofInMultiverseOnly(t *testing.T) {
	h := newHarness(t, nil)

	// Before we start the custodian, we create a random address and a
	// corresponding wallet transaction.
	ctx := context.Background()

	addr, genesis := randAddr(h)
	err := h.tapdbBook.InsertAddrs(ctx, *addr)
	require.NoError(t, err)

	// We now start the custodian and make sure it's started up correctly
	// and the pending event is registered.
	require.NoError(t, h.c.Start())
	h.assertStartup()
	h.assertAddrsRegistered(addr)

	// Receiving a TX for it should create a pending event and cause the
	// proof courier to attempt to fetch it. But the courier won't find it.
	outputIdx, tx := randWalletTx(addr)
	h.walletAnchor.SubscribeTx <- *tx
	h.assertEventsPresent(1, address.StatusTransactionDetected)

	// We now stop the custodian again.
	require.NoError(t, h.c.Stop())

	// The proof is only in the multiverse, not in the local archive. And we
	// add the proof to the multiverse before starting the custodian, so the
	// notification for it doesn't trigger.
	mockProof := randProof(t, outputIdx, tx.Tx, genesis, addr)
	h.addProofFileToMultiverse(mockProof)

	// And a new start should import the proof into the local archive.
	h.c = tapgarden.NewCustodian(h.cfg)
	require.NoError(t, h.c.Start())
	t.Cleanup(func() {
		require.NoError(t, h.c.Stop())
	})
	h.assertStartup()
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
