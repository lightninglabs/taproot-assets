package tarogarden_test

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/chanutils"
	"github.com/lightninglabs/taro/tarogarden"
	"github.com/lightningnetwork/lnd/keychain"
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
	return &mintingTestHarness{
		T:     t,
		store: store,
		// Use a larger internal so it'll never actually tick and only
		// rely on our manual ticks.
		ticker:  ticker.NewForce(time.Hour * 24),
		wallet:  &mockWalletAnchor{},
		chain:   &mockChainBridge{},
		keyRing: newMockKeyRing(),
	}
}

// refreshChainPlanter creates a new test harness.
func (t *mintingTestHarness) refreshChainPlanter() {
	t.planter = tarogarden.NewChainPlanter(&tarogarden.PlanterConfig{
		GardenKit: tarogarden.GardenKit{
			Wallet:      t.wallet,
			ChainBridge: t.chain,
			Log:         t.store,
			KeyRing:     t.keyRing,
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
			Amount:         uint64(rand.Int63()),
			EnableEmission: randBool(),
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
		fmt.Println("queue")
		updates, err := t.planter.QueueNewSeedling(seedling)
		require.NoError(t, err)

		// For the first seedlings sent, we should get a new request
		fmt.Println("sent")
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
	batch := t.planter.PendingBatch()
	require.NotNil(t, batch)
	require.Len(t, batch.Seedlings, numSeedlings)
}

// assertNoActiveBatch asserts that no active batch exists.
func (t *mintingTestHarness) assertNoActiveBatch() {
	batch := t.planter.PendingBatch()
	require.Nil(t, batch)
}

// tickMintingBatch first the ticker that forces the planter to create a new
// batch.
func (t *mintingTestHarness) tickMintingBatch() {
	t.ticker.Force <- time.Time{}
}

// testBasicAssetCreation tests that we're able to properly progress the state
// machine through the various stages of asset minting and creation.
//
// TODO(roasbeef): use wrapper/interceptor on the storage impl to have better
// assertions?
func testBasicAssetCreation(t *mintingTestHarness) {
	t.Helper()
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
