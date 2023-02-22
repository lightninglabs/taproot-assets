package tarogarden_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/lightninglabs/taro/tarodb"
	_ "github.com/lightninglabs/taro/tarodb" // Register relevant drivers.
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/ticker"
	"github.com/stretchr/testify/require"
)

// Default to a large interval so the planter never actually ticks and only
// rely on our manual ticks.
var defaultInterval = time.Hour * 24
var defaultTimeout = time.Second * 5

// newMintingStore creates a new instance of the TaroAddressBook book.
func newMintingStore(t *testing.T) tarogarden.MintingStore {
	db := tarodb.NewTestDB(t)

	txCreator := func(tx *sql.Tx) tarodb.PendingAssetStore {
		return db.WithTx(tx)
	}

	assetDB := tarodb.NewTransactionExecutor[tarodb.PendingAssetStore](
		db, txCreator,
	)
	return tarodb.NewAssetMintingStore(assetDB)
}

// mintingTestHarness holds and manages all the set of deplanes needed to
// create succinct and fully featured unit/systems tests for the batched asset
// minting process.
type mintingTestHarness struct {
	wallet *tarogarden.MockWalletAnchor

	chain *tarogarden.MockChainBridge

	store tarogarden.MintingStore

	keyRing *tarogarden.MockKeyRing

	genSigner *tarogarden.MockGenSigner

	ticker *ticker.Force

	planter *tarogarden.ChainPlanter

	batchKey *keychain.KeyDescriptor

	proofFiles *tarogarden.MockProofArchive

	*testing.T

	errChan chan error
}

// newMintingTestHarness creates a new test harness from an active minting
// store and an existing testing context.
func newMintingTestHarness(t *testing.T, store tarogarden.MintingStore,
	interval time.Duration) *mintingTestHarness {

	keyRing := tarogarden.NewMockKeyRing()
	genSigner := tarogarden.NewMockGenSigner(keyRing)

	return &mintingTestHarness{
		T:         t,
		store:     store,
		ticker:    ticker.NewForce(interval),
		wallet:    tarogarden.NewMockWalletAnchor(),
		chain:     tarogarden.NewMockChainBridge(),
		keyRing:   keyRing,
		genSigner: genSigner,
		errChan:   make(chan error, 10),
	}
}

// refreshChainPlanter creates a new test harness.
func (t *mintingTestHarness) refreshChainPlanter() {
	// If the old planter exists, then we'll stop it now to simulate a
	// normal shutdown.
	if t.planter != nil {
		require.NoError(t, t.planter.Stop())
	}

	t.planter = tarogarden.NewChainPlanter(tarogarden.PlanterConfig{
		GardenKit: tarogarden.GardenKit{
			Wallet:      t.wallet,
			ChainBridge: t.chain,
			Log:         t.store,
			KeyRing:     t.keyRing,
			GenSigner:   t.genSigner,
			ProofFiles:  t.proofFiles,
		},
		BatchTicker: t.ticker,
		ErrChan:     t.errChan,
	})
	require.NoError(t, t.planter.Start())
}

// newRandSeedlings creates numSeedlings amount of seedlings with random
// initialized values.
func (t *mintingTestHarness) newRandSeedlings(numSeedlings int) []*tarogarden.Seedling {
	seedlings := make([]*tarogarden.Seedling, numSeedlings)
	for i := 0; i < numSeedlings; i++ {
		var n [32]byte
		if _, err := rand.Read(n[:]); err != nil {
			t.Fatalf("unable to read str: %v", err)
		}

		assetName := hex.EncodeToString(n[:])
		seedlings[i] = &tarogarden.Seedling{
			AssetType:      asset.Type(rand.Int31n(2)),
			AssetName:      assetName,
			Metadata:       n[:],
			EnableEmission: test.RandBool(),
		}
		if seedlings[i].AssetType == asset.Normal {
			seedlings[i].Amount = uint64(rand.Int31())
		} else {
			seedlings[i].Amount = 1
		}
	}

	return seedlings
}

func (t *mintingTestHarness) assertKeyDerived() *keychain.KeyDescriptor {
	t.Helper()

	key, err := chanutils.RecvOrTimeout(t.keyRing.ReqKeys, defaultTimeout)
	require.NoError(t, err)

	return *key
}

// queueSeedlingsInBatch adds the series of seedlings to the batch, an error is
// raised if any of the seedlings aren't accepted.
func (t *mintingTestHarness) queueSeedlingsInBatch(
	seedlings ...*tarogarden.Seedling) {

	for i, seedling := range seedlings {
		seedling := seedling

		// Queue the new seedling for a batch.
		//
		// TODO(roasbeef): map of update chans?
		updates, err := t.planter.QueueNewSeedling(seedling)
		require.NoError(t, err)

		// For the first seedlings sent, we should get a new request
		if i == 0 {
			t.batchKey = t.assertKeyDerived()
		}

		// We should get an update from the update channel that the
		// seedling is now pending.
		update, err := chanutils.RecvOrTimeout(updates, defaultTimeout)
		require.NoError(t, err)

		// Make sure the seedling was planted without error.
		require.NoError(t, update.Error)

		// The received update should be a state of MintingStateSeed.
		require.Equal(t, tarogarden.MintingStateSeed, update.NewState)
	}
}

// assertPendingBatchExists asserts that a pending batch is found and it has
// numSeedlings assets registered.
func (t *mintingTestHarness) assertPendingBatchExists(numSeedlings int) {
	t.Helper()

	batch, err := t.planter.PendingBatch()
	require.NoError(t, err)
	require.NotNil(t, batch)
	require.Len(t, batch.Seedlings, numSeedlings)
}

// assertNoActiveBatch asserts that no pending batch exists.
func (t *mintingTestHarness) assertNoPendingBatch() {
	t.Helper()

	batch, err := t.planter.PendingBatch()
	require.NoError(t, err)
	require.Nil(t, batch)
}

// tickMintingBatch first the ticker that forces the planter to create a new
// batch.
func (t *mintingTestHarness) tickMintingBatch() {
	t.Helper()

	ticked, err := t.planter.ForceBatch()

	require.NoError(t, err)
	require.True(t, ticked)
}

// assertNumCaretakersActive asserts that the specified number of caretakers
// are active.
func (t *mintingTestHarness) assertNumCaretakersActive(n int) {
	t.Helper()

	err := wait.Predicate(func() bool {
		numBatches, err := t.planter.NumActiveBatches()
		require.NoError(t, err)
		return numBatches == n
	}, defaultTimeout)
	require.NoError(t, err)
}

// assertGenesisTxFunded asserts that a caretaker attempted to fund a new
// genesis transaction.
func (t *mintingTestHarness) assertGenesisTxFunded() *tarogarden.FundedPsbt {
	// In order to fund a transaction, we expect a call to estimate the
	// fee, followed by a request to fund a new PSBT packet.
	_, err := chanutils.RecvOrTimeout(
		t.chain.FeeEstimateSignal, defaultTimeout,
	)
	require.NoError(t, err)

	pkt, err := chanutils.RecvOrTimeout(
		t.wallet.FundPsbtSignal, defaultTimeout,
	)
	require.NoError(t, err)

	// Finally, we'll assert that the dummy output or a valid P2TR output
	// is found in the packet.
	var found bool
	for _, txOut := range (*pkt).Pkt.UnsignedTx.TxOut {
		txOut := txOut

		if txOut.Value == int64(tarogarden.GenesisAmtSats) {
			isP2TR := txscript.IsPayToTaproot(txOut.PkScript)
			isDummyScript := bytes.Equal(
				txOut.PkScript, tarogarden.GenesisDummyScript[:],
			)

			if isP2TR || isDummyScript {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("unable to find dummy tx out in genesis tx: %v",
			spew.Sdump(pkt))
	}

	return *pkt
}

// assertSeedlingsExist asserts that all the seedlings are present in the batch.
func (t *mintingTestHarness) assertSeedlingsExist(
	seedlings []*tarogarden.Seedling) {

	t.Helper()

	pendingBatches, err := t.store.FetchNonFinalBatches(context.Background())
	require.NoError(t, err)

	pendingBatch := pendingBatches[0]

	// The seedlings should match up properly.
	require.Len(t, pendingBatch.Seedlings, len(seedlings))

	for _, seedling := range seedlings {
		batchSeedling, ok := pendingBatch.Seedlings[seedling.AssetName]
		if !ok {
			t.Fatalf("seedling %v not found", seedling.AssetName)
		}

		require.Equal(t, seedling.AssetType, batchSeedling.AssetType)
		require.Equal(t, seedling.AssetName, batchSeedling.AssetName)
		require.Equal(t, seedling.Metadata, batchSeedling.Metadata)
		require.Equal(t, seedling.Amount, batchSeedling.Amount)
		require.Equal(
			t, seedling.EnableEmission, batchSeedling.EnableEmission,
		)
	}
}

// assertSeedlingsMatchSprouts asserts that the seedlings were properly matched
// into actual assets.
func (t *mintingTestHarness) assertSeedlingsMatchSprouts(
	seedlings []*tarogarden.Seedling) {

	t.Helper()

	// The caretaker is async, so we'll spin here until the batch read is
	// in the expected state.
	var pendingBatch *tarogarden.MintingBatch
	err := wait.Predicate(func() bool {
		pendingBatches, err := t.store.FetchNonFinalBatches(
			context.Background(),
		)
		require.NoError(t, err)
		require.Len(t, pendingBatches, 1)

		if pendingBatches[0].BatchState != tarogarden.BatchStateCommitted {
			return false
		}

		pendingBatch = pendingBatches[0]
		return true
	}, defaultTimeout)
	require.NoError(
		t, err, fmt.Errorf("unable to read pending batch: %v", err),
	)

	// The amount of assets committed to in the taro commitment should
	// match up
	dbAssets := pendingBatch.RootAssetCommitment.CommittedAssets()
	require.Len(t, dbAssets, len(seedlings))

	assetsByTag := make(map[string]*asset.Asset)
	for _, asset := range dbAssets {
		assetsByTag[asset.Genesis.Tag] = asset
	}

	for _, seedling := range seedlings {
		assetSprout, ok := assetsByTag[seedling.AssetName]
		if !ok {
			t.Fatalf("asset for seedling %v not found",
				seedling.AssetName)
		}

		// We expect the seedling to have been properly mapped onto an
		// asset.
		require.Equal(t, seedling.AssetType, assetSprout.Type)
		require.Equal(t, seedling.AssetName, assetSprout.Genesis.Tag)
		require.Equal(t, seedling.Metadata, assetSprout.Genesis.Metadata)
		require.Equal(t, seedling.Amount, assetSprout.Amount)
		require.Equal(
			t, seedling.EnableEmission, assetSprout.GroupKey != nil,
		)
	}
}

// assertGenesisPsbtFinalized asserts that a request to finalize the genesis
// transaction has been requested by a caretaker.
func (t *mintingTestHarness) assertGenesisPsbtFinalized() {
	t.Helper()

	// Ensure that a request to finalize the PSBt has come across.
	_, err := chanutils.RecvOrTimeout(
		t.wallet.SignPsbtSignal, defaultTimeout,
	)
	require.NoError(t, err, "psbt sign req not sent")

	// Next fetch the minting key of the batch.
	pendingBatches, err := t.store.FetchNonFinalBatches(
		context.Background(),
	)
	require.NoError(t, err)
	require.Len(t, pendingBatches, 1)

	// The minting key of the batch should match the public key
	// that was inserted into the wallet.
	batchKey, _, err := pendingBatches[0].MintingOutputKey()
	require.NoError(t, err)

	importedKey, err := chanutils.RecvOrTimeout(
		t.wallet.ImportPubKeySignal, defaultTimeout,
	)
	require.NoError(t, err, "pubkey import req not sent")
	require.True(t, (*importedKey).IsEqual(batchKey))
}

// assertTxPublished asserts that a transaction was published via the active
// chain bridge.
func (t *mintingTestHarness) assertTxPublished() *wire.MsgTx {
	t.Helper()

	tx, err := chanutils.RecvOrTimeout(t.chain.PublishReq, defaultTimeout)
	require.NoError(t, err)

	return *tx
}

// assertConfReqSent asserts that a confirmation request has been sent. If so,
// then a closure is returned that once called will send a confirmation
// notification.
func (t *mintingTestHarness) assertConfReqSent(tx *wire.MsgTx,
	block *wire.MsgBlock) func() {

	reqNo, err := chanutils.RecvOrTimeout(
		t.chain.ConfReqSignal, defaultTimeout,
	)
	require.NoError(t, err)

	return func() {
		t.chain.SendConfNtfn(*reqNo, &chainhash.Hash{}, 1, 0, block, tx)
	}
}

// assertNoError makes sure no error was sent on the global error channel.
func (t *mintingTestHarness) assertNoError() {
	select {
	case err := <-t.errChan:
		require.NoError(t, err)
	default:
	}
}

// testBasicAssetCreation tests that we're able to properly progress the state
// machine through the various stages of asset minting and creation.
//
// TODO(roasbeef): use wrapper/interceptor on the storage impl to have better
// assertions?
func testBasicAssetCreation(t *mintingTestHarness) {
	t.Helper()

	// First, create a new chain planter instance using the supplied test
	// harness.
	t.refreshChainPlanter()

	// Next make 5 new random seedlings, and queue each of them up within
	// the main state machine for batched minting.
	const numSeedlings = 5
	seedlings := t.newRandSeedlings(numSeedlings)
	t.queueSeedlingsInBatch(seedlings...)

	// At this point, there should be a single pending batch with 5
	// seedlings. The batch stored in the log should also match up exactly.
	t.assertPendingBatchExists(numSeedlings)
	t.assertSeedlingsExist(seedlings)

	// Now we'll now we'll force a batch tick which should kick off a new
	// caretaker that starts to progress the batch all the way to
	// broadcast.
	t.tickMintingBatch()

	// We'll now restart the planter to ensure that it's able to properly
	// resume all the caretakers. We need to sleep for a small amount to
	// allow the planter to get the batch tick signal.
	time.Sleep(time.Millisecond * 100)
	t.refreshChainPlanter()

	// Now that the planter is back up, a single caretaker should have been
	// launched as well. Next, assert that the caretaker has requested a
	// genesis tx to be funded.
	_ = t.assertGenesisTxFunded()
	t.assertNumCaretakersActive(1)

	// We'll now force yet another restart to ensure correctness of the
	// state machine, we expect the PSBT packet to be funded again as well,
	// since we didn't get a chance to write it to disk.
	t.refreshChainPlanter()
	_ = t.assertGenesisTxFunded()

	// For each seedling created above, we expect a new set of keys to be
	// created for the asset script key and an additional key if emission
	// was enabled.
	for i := 0; i < numSeedlings; i++ {
		t.assertKeyDerived()

		if seedlings[i].EnableEmission {
			t.assertKeyDerived()
		}
	}

	// Now that the batch has been ticked, and the caretaker started, there
	// should no longer be a pending batch.
	t.assertNoPendingBatch()

	// If we fetch the pending batch just created on disk, then it should
	// match up with the seedlings we specified, and also the genesis
	// transaction sent above.
	t.assertSeedlingsMatchSprouts(seedlings)

	// Before we proceed to the next phase, we'll restart the planter again
	// to ensure it can proceed with some bumps along the way.
	t.refreshChainPlanter()

	// We should now transition to the next state where we'll attempt to
	// sign this PSBT packet generated above.
	t.assertGenesisPsbtFinalized()

	// With the PSBT packet finalized for the caretaker, we should now
	// receive a request to publish a transaction followed by a
	// confirmation request.
	tx := t.assertTxPublished()

	// We'll now restart the daemon once again to simulate some downtime
	// after the transaction has been published.
	t.refreshChainPlanter()

	// Make sure any errors sent on the error channel from shutting down are
	// drained, so we don't see them later.
	select {
	case <-t.errChan:
	default:
	}

	// After the restart, the transaction should be published again.
	t.assertTxPublished()

	// With the transaction published, we should now receive a confirmation
	// request. To ensure the file proof is constructed properly, we'll
	// also make a "fake" block that includes our transaction.
	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(tx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	blockHeader := wire.NewBlockHeader(
		0, chaincfg.MainNetParams.GenesisHash, merkleRoot, 0, 0,
	)
	block := &wire.MsgBlock{
		Header:       *blockHeader,
		Transactions: []*wire.MsgTx{tx},
	}
	sendConfNtfn := t.assertConfReqSent(tx, block)

	// We'll now send the confirmation notification which should result in
	// the batch being finalized, and the caretaker being cleaned up.
	sendConfNtfn()

	// This time no error should be sent anywhere as we should've handled
	// all notifications.
	t.assertNoError()

	// At this point there should be no active caretakers.
	t.assertNumCaretakersActive(0)
}

func testMintingTicker(t *mintingTestHarness) {
	t.Helper()

	// First, create a new chain planter instance using the supplied test
	// harness.
	t.refreshChainPlanter()

	// Next make 5 new random seedlings, and queue each of them up within
	// the main state machine for batched minting.
	const numSeedlings = 5
	seedlings := t.newRandSeedlings(numSeedlings)
	t.queueSeedlingsInBatch(seedlings...)

	// At this point, there should be a single pending batch with 5
	// seedlings. The batch stored in the log should also match up exactly.
	t.assertPendingBatchExists(numSeedlings)
	t.assertSeedlingsExist(seedlings)

	// A single caretaker should have been
	// launched as well. Next, assert that the caretaker has requested a
	// genesis tx to be funded.
	_ = t.assertGenesisTxFunded()
	t.assertNumCaretakersActive(1)

	// For each seedling created above, we expect a new set of keys to be
	// created for the asset script key and an additional key if emission
	// was enabled.
	for i := 0; i < numSeedlings; i++ {
		t.assertKeyDerived()

		if seedlings[i].EnableEmission {
			t.assertKeyDerived()
		}
	}

	// Now that the batch has been ticked, and the caretaker started, there
	// should no longer be a pending batch.
	t.assertNoPendingBatch()

	// If we fetch the pending batch just created on disk, then it should
	// match up with the seedlings we specified, and also the genesis
	// transaction sent above.
	t.assertSeedlingsMatchSprouts(seedlings)

	// We should now transition to the next state where we'll attempt to
	// sign this PSBT packet generated above.
	t.assertGenesisPsbtFinalized()

	// With the PSBT packet finalized for the caretaker, we should now
	// receive a request to publish a transaction followed by a
	// confirmation request.
	tx := t.assertTxPublished()

	// With the transaction published, we should now receive a confirmation
	// request. To ensure the file proof is constructed properly, we'll
	// also make a "fake" block that includes our transaction.
	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(tx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	blockHeader := wire.NewBlockHeader(
		0, chaincfg.MainNetParams.GenesisHash, merkleRoot, 0, 0,
	)
	block := &wire.MsgBlock{
		Header:       *blockHeader,
		Transactions: []*wire.MsgTx{tx},
	}
	sendConfNtfn := t.assertConfReqSent(tx, block)

	// We'll now send the confirmation notification which should result in
	// the batch being finalized, and the caretaker being cleaned up.
	sendConfNtfn()

	// This time no error should be sent anywhere as we should've handled
	// all notifications.
	t.assertNoError()

	// At this point there should be no active caretakers.
	t.assertNumCaretakersActive(0)
}

// mintingStoreTestCase is used to programmatically run a series of test cases
// that are parametrized based on a fresh minting store.
type mintingStoreTestCase struct {
	name     string
	interval time.Duration
	testFunc func(t *mintingTestHarness)
}

// testCases houses the set of minting store test cases.
var testCases = []mintingStoreTestCase{
	{
		name:     "basic_asset_creation",
		interval: defaultInterval,
		testFunc: testBasicAssetCreation,
	},
	{
		name:     "creation_by_minting_ticker",
		interval: time.Second,
		testFunc: testMintingTicker,
	},
}

// TestBatchedAssetIssuance runs a test of tests to ensure that the set of
// registered minting stores can be used to properly implement batched asset
// minting.
func TestBatchedAssetIssuance(t *testing.T) {
	t.Helper()

	for _, testCase := range testCases {
		mintingStore := newMintingStore(t)
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			mintTest := newMintingTestHarness(
				t, mintingStore, testCase.interval,
			)
			testCase.testFunc(mintTest)
		})
	}
}

func init() {
	rand.Seed(time.Now().Unix())
}
