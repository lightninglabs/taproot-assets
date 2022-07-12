package tarogarden_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/ticker"
	"github.com/stretchr/testify/require"

	// Needed to register any relevant drivers.
	_ "github.com/lightninglabs/taro/tarodb"
)

var defaultTimeout = time.Second * 5

// mintingTestHarness holds and manages all the set of deplanes needed to
// create succinct and fully featured unit/systems tests for the batched asset
// minting process.
type mintingTestHarness struct {
	wallet *mockWalletAnchor

	chain *mockChainBridge

	store tarogarden.MintingStore

	keyRing *mockKeyRing

	genSigner *mockGenSigner

	ticker *ticker.Force

	planter *tarogarden.ChainPlanter

	batchKey *keychain.KeyDescriptor

	*testing.T
}

// newMintingTestHarness creates a new test harness from an active minting
// store and an existing testing context.
func newMintingTestHarness(t *testing.T, store tarogarden.MintingStore) *mintingTestHarness {
	keyRing := newMockKeyRing()
	genSigner := newMockGenSigner(keyRing)

	return &mintingTestHarness{
		T:     t,
		store: store,
		// Use a larger internal so it'll never actually tick and only
		// rely on our manual ticks.
		ticker:    ticker.NewForce(time.Hour * 24),
		wallet:    newMockWalletAnchor(),
		chain:     newMockChainBridge(),
		keyRing:   keyRing,
		genSigner: genSigner,
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
		},
		BatchTicker: t.ticker,
	})
	require.NoError(t, t.planter.Start())
}

// randBool rolls a random boolean.
func randBool() bool {
	return rand.Int()%2 == 0
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
			EnableEmission: randBool(),
		}
		if seedlings[i].AssetType == asset.Normal {
			seedlings[i].Amount = uint64(rand.Int63())
		} else {
			seedlings[i].Amount = 1
		}
	}

	return seedlings
}

func (t *mintingTestHarness) assertKeyDerived() *keychain.KeyDescriptor {
	t.Helper()

	key, err := chanutils.RecvOrTimeout(t.keyRing.reqKeys, defaultTimeout)
	require.NoError(t, err)

	return *key
}

// queueSeedlingsInBatch adds the series of seedlings to the batch, an error is
// reiased if any of the seedlings aren't accepted.
func (t *mintingTestHarness) queueSeedlingsInBatch(seedlings ...*tarogarden.Seedling) {
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
		require.NoError(
			t, err, fmt.Errorf("no update recv'd for seedling: %v", err),
		)

		// The received update should be a state of MintingStateSeed.
		require.Equal(t, update.NewState, tarogarden.MintingStateSeed)
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

	t.ticker.Force <- time.Time{}
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
		t.chain.feeEstimateSignal, defaultTimeout,
	)
	require.NoError(t, err)

	pkt, err := chanutils.RecvOrTimeout(
		t.wallet.fundPsbtSignal, defaultTimeout,
	)
	require.NoError(t, err)

	// Finally, we'll assert that the dummy output we added is found in the
	// packet.
	var found bool
	for _, txOut := range (*pkt).Pkt.UnsignedTx.TxOut {
		if bytes.Equal(txOut.PkScript, tarogarden.GenesisDummyScript[:]) &&
			txOut.Value == int64(tarogarden.GenesisAmtSats) {
			found = true
			break
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
			t, seedling.EnableEmission, assetSprout.FamilyKey != nil,
		)
	}
}

// assertGenesisPsbtFinalized asserts that a request to finalize the genesis
// transaction has been requested by a caretaker.
func (t *mintingTestHarness) assertGenesisPsbtFinalized() {
	t.Helper()

	// Ensure that a request to finalize the PSBt has come across.
	_, err := chanutils.RecvOrTimeout(
		t.wallet.signPsbtSignal, defaultTimeout,
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
		t.wallet.importPubKeySignal, defaultTimeout,
	)
	require.NoError(t, err, "pubkey import req not sent")
	require.True(t, (*importedKey).IsEqual(batchKey))
}

// assertTxPublished asserts that a transaction was published via the active
// chain bridge.
func (t *mintingTestHarness) assertTxPublished() {
	t.Helper()

	_, err := chanutils.RecvOrTimeout(t.chain.publishReq, defaultTimeout)
	require.NoError(t, err)
}

// assertConfReqSent asserts that a confirmation request has been sent. If so,
// then a closure is returned that once called will send a confirmation
// notification.
func (t *mintingTestHarness) assertConfReqSent() func() {
	reqNo, err := chanutils.RecvOrTimeout(t.chain.confReqSignal, defaultTimeout)
	require.NoError(t, err)

	return func() {
		t.chain.sendConfNtfn(*reqNo, &chainhash.Hash{}, 1, 10)
	}
}

// testBasicAssetCreation tests that we're able to properly progress the state
// machine through the various stages of asset minting and creation.
//
// TODO(roasbeef): use wrapper/interceptor on the storage impl to have better
// assertions?
func testBasicAssetCreation(t *mintingTestHarness) {
	t.Helper()

	// First, create a new chain planter instance using the supplied test harness.
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
	for i := 0; i < numSeedlings; i++ {
		// The seedlings requires on going emission, then we'll expect an
		// additional key to be derived.
		t.assertKeyDerived()

		if seedlings[i].EnableEmission {
			t.assertKeyDerived()
		}
	}

	// Now that the batch has been ticked, and the caretaker started, there
	// should no longer be an pending batch.
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
	t.assertTxPublished()

	// We'll now restart the daemon once again to simulate some downtime
	// after the transaction has been published.
	t.refreshChainPlanter()

	// After the restart, the transaction should be published again.
	t.assertTxPublished()

	// With the transaction published, we should now receive a confirmation
	// request.
	sendConfNtfn := t.assertConfReqSent()

	// We'll now send the confirmation notification which should result in
	// the batch being finalized, and the caretaker being cleaned up.
	sendConfNtfn()

	// At this point there should be no active caretakers.
	t.assertNumCaretakersActive(0)
}

// mintingStoreCreator is a function closure that is capable of creating a new
// minting store. A clean up function is also returned to garbage collect the
// old state.
type mintingStoreCreator func() (tarogarden.MintingStore, func(), error)

// mintingStoreTestCase is used to programmatically run a series of test cases
// that are parametrized based on a fresh minting store.
type mintingStoreTestCase struct {
	name     string
	testFunc func(t *mintingTestHarness)
}

// testCases houses the set of minting store test cases.
var testCases = []mintingStoreTestCase{
	{
		name:     "basic_asset_creation",
		testFunc: testBasicAssetCreation,
	},
}

// testBatchedAssetIssuance takes an active testing instance along with a
// minting store and then runs a series of test to exercise basic batched asset
// issuance.
func testBatchedAssetIssuance(t *testing.T, storeCreator mintingStoreCreator) {
	t.Helper()

	for _, testCase := range testCases {
		mintingStore, cleanUp, err := storeCreator()
		require.NoError(t, err)
		defer cleanUp()

		t.Run(testCase.name, func(t *testing.T) {
			mintTest := newMintingTestHarness(t, mintingStore)
			testCase.testFunc(mintTest)
		})
	}
}

// TestBatchedAssetIssuance runs a test of tests to ensure that the set of
// registered minting stores can be used to properly implement batched asset
// minting.
func TestBatchedAssetIssuance(t *testing.T) {
	t.Parallel()

	for _, mintingStoreDriver := range tarogarden.RegisteredMintingStores() {
		var mintingStoreFunc mintingStoreCreator

		// TODO(roasbeef): needed to avoid import cycle
		//  * alternatively can move the middleware logic here?
		switch mintingStoreDriver.Name {

		case "sqlite3":
			mintingStoreFunc = func() (tarogarden.MintingStore, func(), error) {
				dir, err := ioutil.TempDir("", "sqlite-test-")
				if err != nil {
					t.Fatal(err)
				}
				dbFileName := filepath.Join(dir, "tmp.db")

				mintingStore, err := mintingStoreDriver.New(
					dbFileName,
				)
				if err != nil {
					return nil, nil, fmt.Errorf("unable "+
						"to create new minting "+
						"store: %v", err)
				}

				cleanUp := func() {
					os.RemoveAll(dir)
				}

				return mintingStore, cleanUp, nil
			}
		default:
			t.Fatalf("unknown minting store: %v", mintingStoreDriver.Name)
		}

		testBatchedAssetIssuance(t, mintingStoreFunc)
	}
}

func init() {
	rand.Seed(time.Now().Unix())
}
