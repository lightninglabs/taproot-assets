package tapgarden_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btclog/v2"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/lndclient"
	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapdb"
	_ "github.com/lightninglabs/taproot-assets/tapdb" // Register relevant drivers.
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

// Default to a large interval so the planter never actually ticks and only
// rely on our manual ticks.
var (
	defaultTimeout    = time.Second * 10
	noCaretakerStates = fn.NewSet(
		tapgarden.BatchStatePending,
		tapgarden.BatchStateSeedlingCancelled,
		tapgarden.BatchStateSproutCancelled,
	)
	batchFrozenStates = fn.NewSet(
		tapgarden.BatchStateFrozen,
		tapgarden.BatchStateCommitted,
		tapgarden.BatchStateBroadcast,
		tapgarden.BatchStateConfirmed,
		tapgarden.BatchStateFinalized,
	)
	batchCommittedStates = fn.NewSet(
		tapgarden.BatchStateCommitted,
		tapgarden.BatchStateBroadcast,
		tapgarden.BatchStateConfirmed,
		tapgarden.BatchStateFinalized,
	)
)

// newMintingStore creates a new instance of the TapAddressBook book.
func newMintingStore(t *testing.T) tapgarden.MintingStore {
	db := tapdb.NewTestDB(t)

	txCreator := func(tx *sql.Tx) tapdb.PendingAssetStore {
		return db.WithTx(tx)
	}

	assetDB := tapdb.NewTransactionExecutor(db, txCreator)
	return tapdb.NewAssetMintingStore(assetDB)
}

// mintingTestHarness holds and manages all the set of deplanes needed to
// create succinct and fully featured unit/systems tests for the batched asset
// minting process.
type mintingTestHarness struct {
	wallet *tapgarden.MockWalletAnchor

	chain *tapgarden.MockChainBridge

	store tapgarden.MintingStore

	treeStore *tapgarden.FallibleTapscriptTreeMgr

	keyRing *tapgarden.MockKeyRing

	genSigner *tapgarden.MockGenSigner

	genTxBuilder asset.GenesisTxBuilder

	txValidator tapscript.TxValidator

	planter *tapgarden.ChainPlanter

	proofFiles *proof.MockProofArchive

	proofWatcher *tapgarden.MockProofWatcher

	*testing.T

	errChan chan error
}

// newMintingTestHarness creates a new test harness from an active minting
// store and an existing testing context.
func newMintingTestHarness(t *testing.T,
	store tapgarden.MintingStore) *mintingTestHarness {

	keyRing := tapgarden.NewMockKeyRing()
	genSigner := tapgarden.NewMockGenSigner(keyRing)
	treeMgr := tapgarden.NewFallibleTapscriptTreeMgr(store)
	archiver := proof.NewMockProofArchive()

	return &mintingTestHarness{
		T:            t,
		store:        store,
		treeStore:    &treeMgr,
		wallet:       tapgarden.NewMockWalletAnchor(),
		chain:        tapgarden.NewMockChainBridge(),
		proofFiles:   archiver,
		proofWatcher: &tapgarden.MockProofWatcher{},
		keyRing:      keyRing,
		genSigner:    genSigner,
		genTxBuilder: &tapscript.GroupTxBuilder{},
		txValidator:  &tap.ValidatorV0{},
		errChan:      make(chan error, 10),
	}
}

// refreshChainPlanter creates a new test harness.
func (t *mintingTestHarness) refreshChainPlanter() {
	// If the old planter exists, then we'll stop it now to simulate a
	// normal shutdown.
	if t.planter != nil {
		require.NoError(t, t.planter.Stop())
	}

	t.planter = tapgarden.NewChainPlanter(tapgarden.PlanterConfig{
		GardenKit: tapgarden.GardenKit{
			Wallet:       t.wallet,
			ChainBridge:  t.chain,
			Log:          t.store,
			TreeStore:    t.treeStore,
			KeyRing:      t.keyRing,
			GenSigner:    t.genSigner,
			GenTxBuilder: t.genTxBuilder,
			TxValidator:  t.txValidator,
			ProofFiles:   t.proofFiles,
			ProofWatcher: t.proofWatcher,
		},
		ChainParams:  *chainParams,
		ProofUpdates: t.proofFiles,
		ErrChan:      t.errChan,
	})
	require.NoError(t, t.planter.Start())
}

// newRandSeedlings creates numSeedlings amount of seedlings with random
// initialized values.
func (t *mintingTestHarness) newRandSeedlings(
	numSeedlings int) []*tapgarden.Seedling {

	seedlings := make([]*tapgarden.Seedling, numSeedlings)
	for i := 0; i < numSeedlings; i++ {
		var n [32]byte
		test.RandRead(t, n[:])
		assetName := hex.EncodeToString(n[:])
		seedlings[i] = &tapgarden.Seedling{
			AssetVersion: asset.Version(rand.Int31n(2)),
			AssetType:    asset.Type(rand.Int31n(2)),
			AssetName:    assetName,
			Meta: &proof.MetaReveal{
				Data: n[:],
			},
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

// assertBatchResumedBackground unblocks the fee estimation and PSBT funding
// that occur when a batch is resumed by the planter.
func (t *mintingTestHarness) assertBatchResumedBackground(wg *sync.WaitGroup,
	fee, fund bool) {

	t.Helper()

	wg.Add(1)
	go func() {
		defer wg.Done()

		if fee {
			_, _ = fn.RecvOrTimeout(
				t.chain.FeeEstimateSignal, defaultTimeout,
			)
		}

		if fund {
			_, _ = fn.RecvOrTimeout(
				t.wallet.FundPsbtSignal, defaultTimeout,
			)
		}
	}()
}

// createExternalBatch creates a new pending batch outside the planter, which
// can then be stored on disk.
func (t *mintingTestHarness) createExternalBatch(
	numSeedlings int) *tapgarden.MintingBatch {

	t.Helper()

	seedlings := t.newRandSeedlings(numSeedlings)
	seedlingsWithKeys := make(map[string]*tapgarden.Seedling)
	for _, seedling := range seedlings {
		scriptKeyInternalDesc, _ := test.RandKeyDesc(t)
		scriptKey := asset.NewScriptKeyBip86(scriptKeyInternalDesc)
		seedling.ScriptKey = scriptKey

		// The group internal key should be from the key ring since we
		// expect the caretaker to sign with it later.
		if seedling.EnableEmission {
			groupKey, err := t.keyRing.DeriveNextKey(
				context.Background(),
				asset.TaprootAssetsKeyFamily,
			)
			require.NoError(t, err)

			seedling.GroupInternalKey = &groupKey
		}

		seedlingsWithKeys[seedling.AssetName] = seedling
	}

	batchInternalKey, err := t.keyRing.DeriveNextKey(
		context.Background(), asset.TaprootAssetsKeyFamily,
	)
	require.NoError(t, err)

	newBatch := &tapgarden.MintingBatch{
		CreationTime: time.Now(),
		HeightHint:   0,
		BatchKey:     batchInternalKey,
		Seedlings:    seedlingsWithKeys,
		AssetMetas:   make(tapgarden.AssetMetas),
	}
	newBatch.UpdateState(tapgarden.BatchStatePending)

	return newBatch
}

// queueSeedlingsInBatch adds the series of seedlings to the batch, an error is
// raised if any of the seedlings aren't accepted.
func (t *mintingTestHarness) queueSeedlingsInBatch(isFunded bool,
	seedlings ...*tapgarden.Seedling) {

	for i, seedling := range seedlings {
		seedling := seedling
		keyCount := 0
		t.keyRing.Calls = nil

		// For the first seedling sent, we should get a new request,
		// representing the batch internal key.
		if i == 0 && !isFunded {
			keyCount++
		}

		// Seedlings without an external script key will have one
		// derived.
		if seedling.ScriptKey.PubKey == nil {
			keyCount++
		}

		// Seedlings with emission enabled and without an external
		// group internal key will have one derived.
		if seedling.EnableEmission && seedling.GroupInternalKey == nil {
			keyCount++
		}

		// Queue the new seedling for a batch.
		//
		// TODO(roasbeef): map of update chans?
		updates, err := t.planter.QueueNewSeedling(seedling)
		require.NoError(t, err)

		// We should get an update from the update channel that the
		// seedling is now pending.
		update, err := fn.RecvOrTimeout(updates, defaultTimeout)
		require.NoError(t, err)

		// Make sure the seedling was planted without error.
		require.NoError(t, update.Error)

		// The received update should be a state of MintingStateSeed.
		require.Equal(t, tapgarden.MintingStateSeed, update.NewState)

		require.Eventually(t, func() bool {
			// Assert that the key ring method DeriveNextKey was
			// called the expected number of times.
			count := 0
			for _, call := range t.keyRing.Calls {
				if call.Method == "DeriveNextKey" {
					count++
				}
			}

			return count == keyCount
		}, defaultTimeout, wait.PollInterval)
	}
}

// assertPendingBatchExists asserts that a pending batch is found and it has
// numSeedlings assets registered.
func (t *mintingTestHarness) assertPendingBatchExists(numSeedlings int) {
	t.Helper()

	// The planter is a state machine, so we need to wait until it has
	// reached the expected state.
	require.Eventually(t, func() bool {
		batch, err := t.planter.PendingBatch()
		require.NoError(t, err)

		require.NotNil(t, batch)
		return len(batch.Seedlings) == numSeedlings
	}, defaultTimeout, wait.PollInterval)
}

// assertNoActiveBatch asserts that no pending batch exists.
func (t *mintingTestHarness) assertNoPendingBatch() {
	t.Helper()

	batches, err := t.store.FetchAllBatches(context.Background())
	require.NoError(t, err)

	// Filter out batches still pending or already cancelled.
	require.Zero(t, fn.Count(batches,
		func(batch *tapgarden.MintingBatch) bool {
			return batch.State() == tapgarden.BatchStatePending
		},
	))
}

type FinalizeBatchResp struct {
	Batch *tapgarden.MintingBatch
	Err   error
}

// finalizeBatch uses the public FinalizeBatch planter call to start a caretaker
// for an existing batch. The caller must wait for the planter call to complete.
func (t *mintingTestHarness) finalizeBatch(wg *sync.WaitGroup,
	respChan chan *FinalizeBatchResp, params *tapgarden.FinalizeParams) {

	t.Helper()

	wg.Add(1)
	go func() {
		defer wg.Done()

		finalizeParams := tapgarden.FinalizeParams{
			FeeRate:        fn.None[chainfee.SatPerKWeight](),
			SiblingTapTree: fn.None[asset.TapscriptTreeNodes](),
		}

		if params != nil {
			finalizeParams = *params
		}

		frozenBatch, finalizeErr := t.planter.FinalizeBatch(
			finalizeParams,
		)
		resp := &FinalizeBatchResp{
			Batch: frozenBatch,
			Err:   finalizeErr,
		}

		respChan <- resp
	}()
}

func (t *mintingTestHarness) assertFinalizeBatch(wg *sync.WaitGroup,
	respChan chan *FinalizeBatchResp,
	errString string) *tapgarden.MintingBatch {

	t.Helper()

	wg.Wait()
	finalizeResp := <-respChan

	switch {
	case errString == "":
		require.NoError(t, finalizeResp.Err)
		return finalizeResp.Batch

	default:
		require.ErrorContains(t, finalizeResp.Err, errString)
		return nil
	}
}

type FundBatchResp = FinalizeBatchResp

// fundBatch uses the public FundBatch planter call to fund a minting batch.
// The caller must wait for the planter call to complete.
func (t *mintingTestHarness) fundBatch(wg *sync.WaitGroup,
	respChan chan *FundBatchResp, params *tapgarden.FundParams) {

	t.Helper()

	wg.Add(1)
	go func() {
		defer wg.Done()

		fundParams := tapgarden.FundParams{
			FeeRate:        fn.None[chainfee.SatPerKWeight](),
			SiblingTapTree: fn.None[asset.TapscriptTreeNodes](),
		}

		if params != nil {
			fundParams = *params
		}

		fundBatchResp, fundErr := t.planter.FundBatch(fundParams)
		if fundErr != nil {
			respChan <- &FundBatchResp{
				Err: fundErr,
			}

			return
		}

		respChan <- &FundBatchResp{
			Batch: fundBatchResp.Batch.MintingBatch,
		}
	}()
}

func (t *mintingTestHarness) assertFundBatch(wg *sync.WaitGroup,
	respChan chan *FundBatchResp,
	errString string) *tapgarden.MintingBatch {

	t.Helper()

	wg.Wait()
	fundResp := <-respChan

	switch {
	case errString == "":
		require.NoError(t, fundResp.Err)
		return fundResp.Batch

	default:
		require.ErrorContains(t, fundResp.Err, errString)
		return nil
	}
}

// progressCaretaker uses the mock interfaces to progress a caretaker from start
// to TX confirmation.
func (t *mintingTestHarness) progressCaretaker(isFunded bool,
	batchSibling *commitment.TapscriptPreimage,
	feeRate *chainfee.SatPerKWeight) func() {

	// Assert that the caretaker has requested a genesis TX to be funded.
	if !isFunded {
		_ = t.assertGenesisTxFunded(feeRate)
	}

	// We should now transition to the next state where we'll attempt to
	// sign this PSBT packet generated above.
	t.assertGenesisPsbtFinalized(batchSibling)

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

	return t.assertConfReqSent(tx, block)
}

// finalizeBatchAssertFrozen fires the ticker that forces the planter to create
// a new batch.
func (t *mintingTestHarness) finalizeBatchAssertFrozen(
	noBatch bool) *tapgarden.MintingBatch {

	t.Helper()

	// Before we tick the batch, we record all existing batches, so we can
	// make sure a new one was created.
	existingBatches, err := t.planter.ListBatches(
		tapgarden.ListBatchesParams{},
	)
	require.NoError(t, err)

	// We only want to know if a new batch gets to the frozen state. So the
	// list of existing batches should only contain the already frozen.
	var existingFrozenBatches []*tapgarden.MintingBatch
	fn.ForEach(existingBatches, func(batch *tapgarden.VerboseBatch) {
		if batch.State() == tapgarden.BatchStateFrozen {
			existingFrozenBatches = append(
				existingFrozenBatches, batch.ToMintingBatch(),
			)
		}
	})

	var (
		wg       sync.WaitGroup
		respChan = make(chan *FinalizeBatchResp, 1)
	)

	t.finalizeBatch(&wg, respChan, nil)

	if noBatch {
		t.assertNoPendingBatch()
		return nil
	}

	// Check that the batch was frozen and then funded.
	newBatch := t.assertNewBatchFrozen(existingFrozenBatches)
	_ = t.assertGenesisTxFunded(nil)

	// Fetch the batch again after funding.
	return t.fetchSingleBatch(newBatch.BatchKey.PubKey)
}

func (t *mintingTestHarness) assertNewBatchFrozen(
	existingBatches []*tapgarden.MintingBatch) *tapgarden.MintingBatch {

	batchExists := func(batch *tapgarden.MintingBatch) bool {
		return fn.Count(
			existingBatches, func(b *tapgarden.MintingBatch) bool {
				return b.BatchKey.PubKey.IsEqual(
					batch.BatchKey.PubKey,
				)
			},
		) > 0
	}

	var newBatches []*tapgarden.MintingBatch
	err := wait.NoError(func() error {
		currentBatches, err := t.store.FetchAllBatches(
			context.Background(),
		)
		if err != nil {
			return err
		}

		if len(currentBatches) > len(existingBatches) {
			for _, batch := range currentBatches {
				if !batchFrozenStates.Contains(batch.State()) {
					continue
				}

				if !batchExists(batch) {
					newBatches = append(newBatches, batch)
				}
			}
			return nil
		}

		return fmt.Errorf("no new batches created")
	}, defaultTimeout)
	require.NoError(t, err)

	require.Len(t, newBatches, 1)

	return newBatches[0]
}

func (t *mintingTestHarness) cancelMintingBatch(noBatch bool) *btcec.PublicKey {
	t.Helper()

	batchKey, err := t.planter.CancelBatch()
	if noBatch {
		require.ErrorContains(t, err, "no pending batch")
		require.Nil(t, batchKey)
		return nil
	}

	if batchKey == nil {
		require.NotNil(t, err)
		return nil
	}

	if err != nil {
		require.ErrorContains(t, err, "batch not cancellable")
		require.NotNil(t, batchKey)
		return batchKey
	}

	require.NoError(t, err)
	require.NotNil(t, batchKey)
	return batchKey
}

func (t *mintingTestHarness) assertBatchProgressing() *tapgarden.MintingBatch {
	// Exclude all states that the batch should not have when progressing
	// from frozen to finalized.
	var progressingBatches []*tapgarden.MintingBatch
	err := wait.Predicate(func() bool {
		batches, err := t.store.FetchAllBatches(context.Background())
		require.NoError(t, err)

		// Filter out batches still pending or already cancelled.
		progressingBatches = fn.Filter(batches,
			func(batch *tapgarden.MintingBatch) bool {
				return !noCaretakerStates.Contains(
					batch.State(),
				)
			})

		return len(progressingBatches) == 1
	}, defaultTimeout)
	require.NoError(t, err)

	return progressingBatches[0]
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
func (t *mintingTestHarness) assertGenesisTxFunded(
	manualFee *chainfee.SatPerKWeight) *tapsend.FundedPsbt {

	// In order to fund a transaction, we expect a call to estimate the
	// fee, followed by a request to fund a new PSBT packet.
	if manualFee == nil {
		_, err := fn.RecvOrTimeout(
			t.chain.FeeEstimateSignal, defaultTimeout,
		)
		require.NoError(t, err)
	}

	pkt, err := fn.RecvOrTimeout(
		t.wallet.FundPsbtSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.NotNil(t, pkt)

	// Our genesis TX in unit tests is always 1 P2TR in, 1 P2TR out &
	// 1 P2WSH out. This has a fixed size of 155 vB.
	const mintTxSize = 155
	txFee := t.assertBatchGenesisTx(*pkt)
	if manualFee != nil {
		expectedFee := manualFee.FeePerKVByte().FeeForVSize(mintTxSize)
		require.GreaterOrEqual(t, txFee, expectedFee)
	}

	return *pkt
}

// assertSeedlingsExist asserts that all the seedlings are present in the batch.
func (t *mintingTestHarness) assertSeedlingsExist(
	seedlings []*tapgarden.Seedling, batchKey *btcec.PublicKey) {

	t.Helper()
	var pendingBatch *tapgarden.MintingBatch

	pendingBatches, err := t.store.FetchNonFinalBatches(context.Background())
	require.NoError(t, err)
	require.True(t, len(pendingBatches) >= 1)

	matchingBatch := func(batch *tapgarden.MintingBatch) bool {
		targetKey := asset.ToSerialized(batchKey)
		candidateKey := asset.ToSerialized(batch.BatchKey.PubKey)

		return bytes.Equal(targetKey[:], candidateKey[:])
	}

	if batchKey == nil {
		isNotCancelledBatch := func(batch *tapgarden.MintingBatch) bool {
			return !isCancelledBatch(batch)
		}
		pendingBatch, err = fn.First(
			pendingBatches, isNotCancelledBatch,
		)
		require.NoError(t, err)
	}

	if batchKey != nil {
		var err error
		pendingBatch, err = fn.First(pendingBatches, matchingBatch)
		require.NoError(t, err)
	}

	// The seedlings should match up properly.
	require.Len(t, pendingBatch.Seedlings, len(seedlings))

	for _, seedling := range seedlings {
		batchSeedling, ok := pendingBatch.Seedlings[seedling.AssetName]
		if !ok {
			t.Fatalf("seedling %v not found", seedling.AssetName)
		}

		require.Equal(t, seedling.AssetVersion, batchSeedling.AssetVersion)
		require.Equal(t, seedling.AssetType, batchSeedling.AssetType)
		require.Equal(t, seedling.AssetName, batchSeedling.AssetName)
		require.Equal(t, seedling.Meta, batchSeedling.Meta)
		require.Equal(t, seedling.Amount, batchSeedling.Amount)
		require.Equal(
			t, seedling.EnableEmission, batchSeedling.EnableEmission,
		)
		require.Equal(
			t, seedling.GroupAnchor, batchSeedling.GroupAnchor,
		)
		require.NotNil(t, batchSeedling.ScriptKey.PubKey)
		require.Equal(
			t, seedling.GroupTapscriptRoot,
			batchSeedling.GroupTapscriptRoot,
		)

		if seedling.ScriptKey.PubKey != nil {
			require.True(
				t,
				seedling.ScriptKey.IsEqual(
					&batchSeedling.ScriptKey,
				))
		}

		if seedling.GroupInternalKey != nil {
			require.True(
				t, asset.EqualKeyDescriptors(
					*seedling.GroupInternalKey,
					*batchSeedling.GroupInternalKey,
				),
			)
		}

		if seedling.EnableEmission {
			require.NotNil(t, batchSeedling.GroupInternalKey)
		}
	}
}

func isCancelledBatch(batch *tapgarden.MintingBatch) bool {
	batchState := batch.State()
	return batchState == tapgarden.BatchStateSeedlingCancelled ||
		batchState == tapgarden.BatchStateSproutCancelled
}

func (t *mintingTestHarness) assertBatchState(batchKey *btcec.PublicKey,
	batchState tapgarden.BatchState) {

	batch := t.fetchSingleBatch(batchKey)
	require.Equal(t, batchState, batch.State())
}

func (t *mintingTestHarness) assertLastBatchState(numBatches int,
	batchState tapgarden.BatchState) {

	t.Helper()
	batches, err := t.planter.ListBatches(tapgarden.ListBatchesParams{})
	require.NoError(t, err)

	require.Len(t, batches, numBatches)
	require.Equal(t, batchState, batches[len(batches)-1].State())
}

func (t *mintingTestHarness) assertNumBatchesWithState(numBatches int,
	state tapgarden.BatchState) {

	t.Helper()

	batches, err := t.store.FetchAllBatches(context.Background())
	require.NoError(t, err)

	batchCount := fn.Count(batches, func(b *tapgarden.MintingBatch) bool {
		return b.State() == state
	})
	require.Equal(t, numBatches, batchCount)
}

func (t *mintingTestHarness) fetchSingleBatch(
	batchKey *btcec.PublicKey) *tapgarden.MintingBatch {

	t.Helper()
	if batchKey == nil {
		return t.assertBatchProgressing()
	}

	batch, err := t.store.FetchMintingBatch(context.Background(), batchKey)
	require.NoError(t, err)
	require.NotNil(t, batch)

	return batch
}

func (t *mintingTestHarness) fetchLastBatch() *tapgarden.MintingBatch {
	t.Helper()
	batches, err := t.store.FetchAllBatches(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, batches)

	return batches[len(batches)-1]
}

func (t *mintingTestHarness) assertBatchGenesisTx(
	pkt *tapsend.FundedPsbt) btcutil.Amount {

	t.Helper()

	// Finally, we'll assert that the dummy output or a valid P2TR output
	// is found in the packet.
	var (
		found    bool
		psbtBuf  bytes.Buffer
		psbtCopy *psbt.Packet
	)

	err := pkt.Pkt.Serialize(&psbtBuf)
	require.NoError(t, err)
	psbtCopy, err = psbt.NewFromRawBytes(&psbtBuf, false)
	require.NoError(t, err)

	for _, txOut := range psbtCopy.UnsignedTx.TxOut {
		txOut := txOut

		if txOut.Value == int64(tapgarden.GenesisAmtSats) {
			isP2TR := txscript.IsPayToTaproot(txOut.PkScript)
			isDummyScript := bytes.Equal(
				txOut.PkScript, tapsend.GenesisDummyScript[:],
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

	genesisTxFee, err := psbtCopy.GetTxFee()
	require.NoError(t, err)

	return genesisTxFee
}

// assertMintOutputKey asserts that the genesis output key for the batch was
// computed correctly during minting and includes a tapscript sibling.
func (t *mintingTestHarness) assertMintOutputKey(batch *tapgarden.MintingBatch,
	siblingHash *chainhash.Hash) {

	rootCommitment := batch.RootAssetCommitment
	require.NotNil(t, rootCommitment)

	scriptRoot := rootCommitment.TapscriptRoot(siblingHash)
	expectedOutputKey := txscript.ComputeTaprootOutputKey(
		batch.BatchKey.PubKey, scriptRoot[:],
	)

	outputKey, _, err := batch.MintingOutputKey(nil)
	require.NoError(t, err)
	require.True(t, expectedOutputKey.IsEqual(outputKey))
}

// assertSeedlingsMatchSprouts asserts that the seedlings were properly matched
// into actual assets.
func (t *mintingTestHarness) assertSeedlingsMatchSprouts(
	seedlings []*tapgarden.Seedling) {

	t.Helper()

	// The caretaker is async, so we'll spin here until the batch read is
	// in the expected state.
	var pendingBatch *tapgarden.MintingBatch
	err := wait.Predicate(func() bool {
		pendingBatches, err := t.store.FetchNonFinalBatches(
			context.Background(),
		)
		require.NoError(t, err)

		// Filter out any cancelled or frozen batches.
		isCommittedBatch := func(batch *tapgarden.MintingBatch) bool {
			return batchCommittedStates.Contains(batch.State())
		}
		batch, err := fn.First(pendingBatches, isCommittedBatch)
		if err != nil {
			return false
		}

		pendingBatch = batch
		return true
	}, defaultTimeout)
	require.NoError(
		t, err, fmt.Errorf("unable to read pending batch: %w", err),
	)

	// The amount of assets committed to in the Taproot Asset commitment
	// should match up.
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
		require.Equal(t, seedling.AssetVersion, assetSprout.Version)
		require.Equal(t, seedling.AssetType, assetSprout.Type)
		require.Equal(t, seedling.AssetName, assetSprout.Genesis.Tag)
		require.Equal(
			t, seedling.Meta.MetaHash(),
			assetSprout.Genesis.MetaHash,
		)
		require.Equal(t, seedling.Amount, assetSprout.Amount)
		require.True(
			t, seedling.ScriptKey.IsEqual(&assetSprout.ScriptKey),
		)

		if seedling.EnableEmission {
			require.NotNil(t, assetSprout.GroupKey)
		}

		if seedling.GroupInternalKey != nil {
			require.NotNil(t, assetSprout.GroupKey)
			require.True(t, asset.EqualKeyDescriptors(
				*seedling.GroupInternalKey,
				assetSprout.GroupKey.RawKey,
			))
		}

		if seedling.GroupTapscriptRoot != nil {
			require.NotNil(t, assetSprout.GroupKey)
			require.Equal(
				t, seedling.GroupTapscriptRoot,
				assetSprout.GroupKey.TapscriptRoot,
			)
		}

		if seedling.GroupAnchor != nil || seedling.GroupInfo != nil {
			require.NotNil(t, assetSprout.GroupKey)
		}
	}
}

// assertGenesisPsbtFinalized asserts that a request to finalize the genesis
// transaction has been requested by a caretaker.
func (t *mintingTestHarness) assertGenesisPsbtFinalized(
	sibling *commitment.TapscriptPreimage) {

	t.Helper()

	// Ensure that a request to finalize the PSBT has come across.
	_, err := fn.RecvOrTimeout(
		t.wallet.SignPsbtSignal, defaultTimeout,
	)
	require.NoError(t, err, "psbt sign req not sent")

	// TODO(jhb): fix for multibatch?
	// Next fetch the minting key of the batch.
	pendingBatches, err := t.store.FetchNonFinalBatches(
		context.Background(),
	)
	require.NoError(t, err)

	isNotCancelledBatch := func(batch *tapgarden.MintingBatch) bool {
		return !isCancelledBatch(batch)
	}
	pendingBatch, err := fn.Last(pendingBatches, isNotCancelledBatch)
	require.NoError(t, err)

	// The minting key of the batch should match the public key
	// that was inserted into the wallet.
	batchKey, _, err := pendingBatch.MintingOutputKey(sibling)
	require.NoError(t, err)

	importedKey, err := fn.RecvOrTimeout(
		t.wallet.ImportPubKeySignal, defaultTimeout,
	)
	require.NoError(t, err, "pubkey import req not sent")
	require.True(t, (*importedKey).IsEqual(batchKey))
}

// assertTxPublished asserts that a transaction was published via the active
// chain bridge.
func (t *mintingTestHarness) assertTxPublished() *wire.MsgTx {
	t.Helper()

	tx, err := fn.RecvOrTimeout(t.chain.PublishReq, defaultTimeout)
	require.NoError(t, err)

	return *tx
}

// assertConfReqSent asserts that a confirmation request has been sent. If so,
// then a closure is returned that once called will send a confirmation
// notification.
func (t *mintingTestHarness) assertConfReqSent(tx *wire.MsgTx,
	block *wire.MsgBlock) func() {

	reqNo, err := fn.RecvOrTimeout(
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

// queueInitialBatch queues a set of random seedlings for the planter.
func (t *mintingTestHarness) queueInitialBatch(
	numSeedlings int) []*tapgarden.Seedling {

	// Next make new random seedlings, and queue each of them up within
	// the main state machine for batched minting.
	seedlings := t.newRandSeedlings(numSeedlings)
	t.queueSeedlingsInBatch(false, seedlings...)

	// At this point, there should be a single pending batch with 5
	// seedlings. The batch stored in the log should also match up exactly.
	t.assertPendingBatchExists(numSeedlings)

	// Before we tick the batch, we record all existing batches, so we can
	// make sure a new one was created.
	existingBatches, err := t.planter.ListBatches(
		tapgarden.ListBatchesParams{},
	)
	require.NoError(t, err)

	// We only want to know if a new batch gets to the frozen state. So the
	// list of existing batches should only contain the already frozen.
	var pendingBatches []*tapgarden.MintingBatch
	fn.ForEach(existingBatches, func(batch *tapgarden.VerboseBatch) {
		if batch.State() == tapgarden.BatchStatePending {
			pendingBatches = append(
				pendingBatches, batch.ToMintingBatch(),
			)
		}
	})

	require.Len(t, pendingBatches, 1)
	batchKey := pendingBatches[0].BatchKey.PubKey

	t.assertSeedlingsExist(seedlings, batchKey)

	return seedlings
}

// testBasicAssetCreation tests that we're able to properly progress the state
// machine through the various stages of asset minting and creation.
//
// TODO(roasbeef): use wrapper/interceptor on the storage impl to have better
// assertions?
func testBasicAssetCreation(t *mintingTestHarness) {
	// First, create a new chain planter instance using the supplied test
	// harness.
	t.refreshChainPlanter()

	// Create an initial batch of 5 seedlings.
	const numSeedlings = 5
	seedlings := t.queueInitialBatch(numSeedlings)

	// Now we'll force a batch tick which should kick off a new caretaker
	// that starts to progress the batch all the way to broadcast.
	t.finalizeBatchAssertFrozen(false)

	// We'll now restart the planter to ensure that it's able to properly
	// resume all the caretakers. We need to sleep for a small amount to
	// allow the planter to get the batch tick signal.
	time.Sleep(time.Millisecond * 100)
	t.refreshChainPlanter()

	// Now that the planter is back up, a single caretaker should have been
	// launched as well. The batch should already be funded.
	batch := t.fetchSingleBatch(nil)
	t.assertBatchGenesisTx(&batch.GenesisPacket.FundedPsbt)
	t.assertNumCaretakersActive(1)

	// We'll now force yet another restart to ensure correctness of the
	// state machine. We expect the PSBT packet to still be funded.
	t.refreshChainPlanter()
	batch = t.fetchSingleBatch(nil)
	t.assertBatchGenesisTx(&batch.GenesisPacket.FundedPsbt)

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
	t.assertGenesisPsbtFinalized(nil)

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

// testMintingTicker tests that we can start batch finalization with the planter
// ticker, and finalize a batch after cancelling a batch.
func testMintingTicker(t *mintingTestHarness) {
	// First, create a new chain planter instance using the supplied test
	// harness.
	t.refreshChainPlanter()

	// Create an initial batch of 5 seedlings.
	const numSeedlings = 5
	_ = t.queueInitialBatch(numSeedlings)

	// If we cancel the current batch, the pending batch should be cleared,
	// but the seedlings should still exist on disk. Requesting batch
	// finalization should not change anything in the planter.
	t.cancelMintingBatch(false)
	t.assertNoPendingBatch()

	// Next, make another 5 seedlings and continue with minting.
	// One seedling is a duplicate of a seedling from the cancelled batch,
	// to ensure that we can store multiple versions of the same seedling.
	seedlings := t.newRandSeedlings(numSeedlings)
	t.queueSeedlingsInBatch(false, seedlings...)

	// Next, finalize the pending batch to continue with minting.
	_ = t.finalizeBatchAssertFrozen(false)

	// A single caretaker should have been launched as well. Next, assert
	// that the batch is already funded.
	t.assertBatchProgressing()
	currentBatch := t.fetchLastBatch()
	t.assertBatchGenesisTx(&currentBatch.GenesisPacket.FundedPsbt)

	// Now that the batch has been ticked, and the caretaker started, there
	// should no longer be a pending batch.
	t.assertNoPendingBatch()

	// If we fetch the pending batch just created on disk, then it should
	// match up with the seedlings we specified, and also the genesis
	// transaction sent above.
	t.assertSeedlingsMatchSprouts(seedlings)

	// We should now transition to the next state where we'll attempt to
	// sign this PSBT packet generated above.
	t.assertGenesisPsbtFinalized(nil)

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

// testBatchCancelFinalize tests that batches can be cancelled and finalized,
// and that the expected errors are returned when there is no pending batch
// or cancellation is not possible.
func testMintingCancelFinalize(t *mintingTestHarness) {
	// First, create a new chain planter instance using the supplied test
	// harness.
	t.refreshChainPlanter()

	// Create an initial batch of 5 seedlings.
	const numSeedlings = 5
	seedlings := t.queueInitialBatch(numSeedlings)
	firstSeedling := seedlings[0]

	// If we cancel the current batch, the pending batch should be cleared,
	// but the seedlings should still exist on disk.
	firstBatchKey := t.cancelMintingBatch(false)
	t.assertNoPendingBatch()
	t.assertBatchState(firstBatchKey, tapgarden.BatchStateSeedlingCancelled)
	t.assertSeedlingsExist(seedlings, firstBatchKey)

	// Requesting batch finalization or cancellation with no pending batch
	// should return an error without crashing the planter.
	t.finalizeBatchAssertFrozen(true)
	t.cancelMintingBatch(true)

	// Next, make another 5 random seedlings and continue with minting.
	seedlings = t.newRandSeedlings(numSeedlings)
	seedlings[0] = firstSeedling
	seedlings[0].ScriptKey = asset.ScriptKey{}
	if seedlings[0].EnableEmission {
		seedlings[0].GroupInternalKey = nil
	}
	t.queueSeedlingsInBatch(false, seedlings...)

	t.assertPendingBatchExists(numSeedlings)
	t.assertSeedlingsExist(seedlings, nil)

	// If we attempt to queue a seedling with the same name as a pending
	// seedling, the planter should reject it.
	updates, err := t.planter.QueueNewSeedling(firstSeedling)
	require.NoError(t, err)
	planterErr := <-updates
	require.NotNil(t, planterErr.Error)
	require.ErrorContains(t, planterErr.Error, "already in batch")

	// Now, finalize the pending batch to continue with minting.
	thirdBatch := t.finalizeBatchAssertFrozen(false)
	require.NotNil(t, thirdBatch)
	require.NotNil(t, thirdBatch.BatchKey.PubKey)
	thirdBatchKey := thirdBatch.BatchKey.PubKey

	t.assertBatchProgressing()
	thirdBatch = t.fetchLastBatch()
	t.assertBatchGenesisTx(&thirdBatch.GenesisPacket.FundedPsbt)

	// Now that the batch has been ticked, and the caretaker started, there
	// should no longer be a pending batch.
	t.assertNoPendingBatch()

	// If we fetch the pending batch just created on disk, then it should
	// match up with the seedlings we specified, and also the genesis
	// transaction sent above.
	t.assertSeedlingsMatchSprouts(seedlings)

	// We should now transition to the next state where we'll attempt to
	// sign this PSBT packet generated above.
	t.assertGenesisPsbtFinalized(nil)

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

	// Once the minting transaction has been published, trying to cancel the
	// batch should fail with an error from the caretaker.
	t.assertBatchState(thirdBatchKey, tapgarden.BatchStateBroadcast)
	cancelResp := t.cancelMintingBatch(false)

	batchKeyEquality := func(a, b *btcec.PublicKey) bool {
		aBytes := asset.ToSerialized(a)
		bBytes := asset.ToSerialized(b)
		return bytes.Equal(aBytes[:], bBytes[:])
	}

	// Verify that the batch we attempted to cancel is the batch that was
	// just broadcast.
	require.True(t, batchKeyEquality(thirdBatchKey, cancelResp))

	// We'll now send the confirmation notification which should result in
	// the batch being finalized, and the caretaker being cleaned up.
	sendConfNtfn()

	// Trying to cancel the batch after the confirmation has been sent
	// should also fail with an error from the caretaker.
	cancelResp = t.cancelMintingBatch(false)
	require.True(t, batchKeyEquality(thirdBatchKey, cancelResp))

	// This time no error should be sent anywhere as we should've handled
	// all notifications.
	t.assertNoError()

	// At this point there should be no active caretakers.
	t.assertNumCaretakersActive(0)
}

// testFinalizeBatch tests that the planter can recover from caretaker errors
// successfully when finalizing a batch, and that the planter state is properly
// reset after successful batch finalization.
func testFinalizeBatch(t *mintingTestHarness) {
	// First, create a new chain planter instance using the supplied test
	// harness.
	t.refreshChainPlanter()

	// Create an initial batch of 5 seedlings.
	const numSeedlings = 5
	_ = t.queueInitialBatch(numSeedlings)

	// Force fee estimation to fail so we crash the caretaker before the
	// batch can be frozen.
	t.chain.FailFeeEstimatesOnce()

	var (
		wg             sync.WaitGroup
		respChan       = make(chan *FinalizeBatchResp, 1)
		caretakerCount = 0
		batchCount     = 0
	)

	// Finalize the pending batch to start a caretaker.
	t.finalizeBatch(&wg, respChan, nil)
	batchCount++

	_, err := fn.RecvOrTimeout(
		t.chain.FeeEstimateSignal, defaultTimeout,
	)
	require.NoError(t, err)

	// The planter should fail to finalize the batch, so there should be no
	// active caretakers nor pending batch.
	t.assertNoPendingBatch()
	t.assertNumCaretakersActive(caretakerCount)
	t.assertLastBatchState(batchCount, tapgarden.BatchStateFrozen)
	t.assertFinalizeBatch(&wg, respChan, "unable to estimate fee")

	// Queue another batch, reset fee estimation behavior, and set TX
	// confirmation registration to fail.
	t.queueInitialBatch(numSeedlings)
	t.chain.FailConfOnce()

	// Finalize the pending batch to start a caretaker, and progress the
	// caretaker to TX confirmation. The finalize call should report no
	// error, but the caretaker should propagate the confirmation error to
	// the shared error channel.
	t.finalizeBatch(&wg, respChan, nil)
	batchCount++

	_ = t.progressCaretaker(false, nil, nil)
	caretakerCount++

	t.assertFinalizeBatch(&wg, respChan, "")
	caretakerErr := <-t.errChan
	require.ErrorContains(t, caretakerErr, "error getting confirmation")

	// The stopped caretaker will still exist but there should be no pending
	// batch. We will have two batches on disk, including the broadcasted
	// batch.
	t.assertNoPendingBatch()
	t.assertNumCaretakersActive(caretakerCount)
	t.assertLastBatchState(batchCount, tapgarden.BatchStateBroadcast)

	// Queue another batch, set TX confirmation to succeed, and set the
	// confirmation event to be empty.
	t.queueInitialBatch(numSeedlings)
	t.chain.EmptyConfOnce()

	// Start a new caretaker that should reach TX broadcast.
	t.finalizeBatch(&wg, respChan, nil)
	batchCount++

	sendConfNtfn := t.progressCaretaker(false, nil, nil)
	caretakerCount++

	// Trigger the confirmation event, which should cause the caretaker to
	// fail.
	sendConfNtfn()

	t.assertFinalizeBatch(&wg, respChan, "")
	caretakerErr = <-t.errChan
	require.ErrorContains(t, caretakerErr, "got empty confirmation")

	// The stopped caretaker will still exist but there should be no pending
	// batch. We will now have three batches on disk.
	t.assertNoPendingBatch()
	t.assertNumCaretakersActive(caretakerCount)
	t.assertLastBatchState(batchCount, tapgarden.BatchStateBroadcast)

	// If we try to finalize without a pending batch, the finalize call
	// should return an error.
	t.finalizeBatch(&wg, respChan, nil)
	t.assertFinalizeBatch(&wg, respChan, "no pending batch")
	t.assertNumCaretakersActive(caretakerCount)

	// Queue another batch and drive the caretaker to a successful minting.
	t.queueInitialBatch(numSeedlings)

	// Use a custom feerate and verify that the TX uses that feerate.
	manualFeeRate := chainfee.FeePerKwFloor * 2
	finalizeReq := tapgarden.FinalizeParams{
		FeeRate: fn.Some(manualFeeRate),
	}
	t.finalizeBatch(&wg, respChan, &finalizeReq)
	batchCount++

	sendConfNtfn = t.progressCaretaker(false, nil, &manualFeeRate)
	sendConfNtfn()

	t.assertFinalizeBatch(&wg, respChan, "")
	t.assertNoError()
	t.assertNoPendingBatch()
	t.assertNumCaretakersActive(caretakerCount)
	t.assertLastBatchState(batchCount, tapgarden.BatchStateFinalized)
}

func testFinalizeWithTapscriptTree(t *mintingTestHarness) {
	// First, create a new chain planter instance using the supplied test
	// harness.
	t.refreshChainPlanter()

	// Create an initial batch of 5 seedlings.
	const numSeedlings = 5
	t.queueInitialBatch(numSeedlings)

	var (
		wg          sync.WaitGroup
		respChan    = make(chan *FinalizeBatchResp, 1)
		finalizeReq tapgarden.FinalizeParams
		batchCount  = 0
	)

	// Build a standalone tapscript tree object, that matches the tree
	// created by other test helpers.
	sigLockKey := test.RandPubKey(t)
	hashLockWitness := []byte("foobar")
	hashLockLeaf := test.ScriptHashLock(t.T, hashLockWitness)
	sigLeaf := test.ScriptSchnorrSig(t.T, sigLockKey)
	tapTreePreimage, err := asset.TapTreeNodesFromLeaves(
		[]txscript.TapLeaf{hashLockLeaf, sigLeaf},
	)
	require.NoError(t, err)

	finalizeReq = tapgarden.FinalizeParams{
		SiblingTapTree: fn.Some(*tapTreePreimage),
	}

	// Force tapscript tree storage to fail, which should cause batch
	// finalization to fail.
	t.treeStore.FailStore = true
	t.finalizeBatch(&wg, respChan, &finalizeReq)
	finalizeErr := <-respChan
	require.ErrorContains(t, finalizeErr.Err, "unable to store")

	// Allow tapscript tree storage to succeed, but force tapscript tree
	// loading to fail.
	t.treeStore.FailStore = false
	t.treeStore.FailLoad = true

	// Finalize the batch with a tapscript tree sibling.
	t.finalizeBatch(&wg, respChan, &finalizeReq)
	batchCount++

	// The caretaker should fail when computing the Taproot output key.
	_ = t.assertGenesisTxFunded(nil)
	t.assertFinalizeBatch(&wg, respChan, "failed to load tapscript tree")
	t.assertLastBatchState(batchCount, tapgarden.BatchStateFrozen)
	t.assertNoPendingBatch()

	// Reset the tapscript tree store to not force load or store failures.
	t.treeStore.FailStore = false
	t.treeStore.FailLoad = false

	// Construct a tapscript tree with a single leaf that has the structure
	// of a TapLeaf computed from a TapCommitment. This should be rejected
	// by the caretaker, as the genesis TX for the batch should only commit
	// to one TapCommitment.
	var dummyRootSum [8]byte
	binary.BigEndian.PutUint64(dummyRootSum[:], test.RandInt[uint64]())
	dummyRootHashParts := [][]byte{
		{byte(asset.V0)}, commitment.TaprootAssetsMarker[:],
		fn.ByteSlice(test.RandHash()), dummyRootSum[:],
	}
	dummyTapCommitmentRootHash := bytes.Join(dummyRootHashParts, nil)
	dummyTapLeaf := txscript.NewBaseTapLeaf(dummyTapCommitmentRootHash)
	dummyTapCommitmentPreimage, err := asset.TapTreeNodesFromLeaves(
		[]txscript.TapLeaf{dummyTapLeaf},
	)
	require.NoError(t, err)

	finalizeReq.SiblingTapTree = fn.Some(*dummyTapCommitmentPreimage)

	// Queue another batch, and try to finalize with a sibling that is also
	// a Taproot asset commitment.
	t.queueInitialBatch(numSeedlings)
	t.finalizeBatch(&wg, respChan, &finalizeReq)
	batchCount++

	_ = t.assertGenesisTxFunded(nil)
	t.assertFinalizeBatch(
		&wg, respChan, "preimage is a Taproot Asset commitment",
	)
	t.assertNoPendingBatch()

	// Queue another batch, and provide a valid sibling tapscript tree.
	t.queueInitialBatch(numSeedlings)
	finalizeReq.SiblingTapTree = fn.Some(*tapTreePreimage)
	t.finalizeBatch(&wg, respChan, &finalizeReq)
	batchCount++

	// Verify that the final genesis TX uses the correct Taproot output key.
	treeRootChildren := test.BuildTapscriptTreeNoReveal(t.T, sigLockKey)
	siblingPreimage := commitment.NewPreimageFromBranch(treeRootChildren)
	sendConfNtfn := t.progressCaretaker(false, &siblingPreimage, nil)
	sendConfNtfn()

	// Once the TX is broadcast, the caretaker should run to completion,
	// storing issuance proofs and updating the batch state to finalized.
	batchWithSibling := t.assertFinalizeBatch(&wg, respChan, "")
	require.NotNil(t, batchWithSibling)
	t.assertNoError()
	t.assertNoPendingBatch()
	t.assertNumCaretakersActive(0)
	t.assertLastBatchState(batchCount, tapgarden.BatchStateFinalized)

	// Verify that the final minting output key matches what we would derive
	// manually.
	siblingHash, err := siblingPreimage.TapHash()
	require.NoError(t, err)
	t.assertMintOutputKey(batchWithSibling, siblingHash)
}

func testFundSealBeforeFinalize(t *mintingTestHarness) {
	// First, create a new chain planter instance using the supplied test
	// harness.
	t.refreshChainPlanter()

	// A pending batch should not exist yet. Therefore, `PendingBatch`
	// should return nil and no error.
	batch, err := t.planter.PendingBatch()
	require.Nil(t, batch)
	require.NoError(t, err)

	var (
		wg               sync.WaitGroup
		respChan         = make(chan *FundBatchResp, 1)
		finalizeRespChan = make(chan *FinalizeBatchResp, 1)
		fundReq          tapgarden.FundParams
	)

	// Derive a set of keys that we'll supply for specific seedlings. First,
	// a non-BIP86 script key.
	scriptKeyInternalKey := test.RandPubKey(t)
	scriptKeyTapTweak := test.RandBytes(32)
	tweakedScriptKey := txscript.ComputeTaprootOutputKey(
		scriptKeyInternalKey, scriptKeyTapTweak,
	)
	scriptTweakedKey := asset.ScriptKey{
		PubKey: tweakedScriptKey,
		TweakedScriptKey: &asset.TweakedScriptKey{
			RawKey: keychain.KeyDescriptor{
				PubKey: scriptKeyInternalKey,
			},
			Tweak: scriptKeyTapTweak,
		},
	}

	// Let's also make an internal key for an asset group. We need to supply
	// the private key so that the planter can produce an asset group
	// witness during batch sealing.
	groupInternalKeyDesc, groupInternalKeyPriv := test.RandKeyDesc(t)
	t.keyRing.Keys[groupInternalKeyDesc.KeyLocator] = groupInternalKeyPriv

	// We'll use the default test tapscript tree for both the batch
	// tapscript sibling and a tapscript root for one asset group.
	hashLockLeaf := test.ScriptHashLock(
		t.T, bytes.Clone(test.DefaultHashLockWitness),
	)
	sigLeaf := test.ScriptSchnorrSig(t.T, groupInternalKeyDesc.PubKey)
	tapTree := txscript.AssembleTaprootScriptTree(hashLockLeaf, sigLeaf)
	defaultTapBranch := txscript.NewTapBranch(
		tapTree.RootNode.Left(), tapTree.RootNode.Right(),
	)
	defaultTapTree := asset.TapTreeNodesFromBranch(defaultTapBranch)
	defaultPreimage := commitment.NewPreimageFromBranch(defaultTapBranch)
	defaultTapHash := defaultTapBranch.TapHash()

	// Make a set of 5 seedlings, which we'll modify manually.
	const numSeedlings = 5
	seedlings := t.newRandSeedlings(numSeedlings)

	// Set an external script key for the first seedling.
	seedlings[0].ScriptKey = scriptTweakedKey
	seedlings[0].EnableEmission = false

	// Set an external group key for the second seedling.
	seedlings[1].EnableEmission = true
	seedlings[1].GroupInternalKey = &groupInternalKeyDesc

	// Set a group tapscript root for the third seedling.
	seedlings[2].EnableEmission = true
	seedlings[2].GroupTapscriptRoot = defaultTapHash[:]
	secondSeedling := seedlings[2].AssetName

	// Set the fourth seedling to be a member of the second seedling's
	// asset group.
	seedlings[3].EnableEmission = false
	seedlings[3].GroupAnchor = &seedlings[1].AssetName
	seedlings[3].AssetType = seedlings[1].AssetType
	seedlings[3].Amount = 1

	// Set the final seedling to be ungrouped.
	seedlings[4].EnableEmission = false
	groupCount := 3

	// Fund a batch with a tapscript sibling and a manual feerate. This
	// should create a new batch.
	manualFee := chainfee.FeePerKwFloor * 2
	fundReq = tapgarden.FundParams{
		SiblingTapTree: fn.Some(defaultTapTree),
		FeeRate:        fn.Some(manualFee),
	}
	t.fundBatch(&wg, respChan, &fundReq)

	t.assertGenesisTxFunded(&manualFee)
	t.assertFundBatch(&wg, respChan, "")

	// After funding, the planter should have persisted the batch. The new
	// batch should be funded but have no seedlings.
	fundedBatches, err := t.planter.ListBatches(
		tapgarden.ListBatchesParams{},
	)
	require.NoError(t, err)
	require.Len(t, fundedBatches, 1)

	fundedEmptyBatch := fundedBatches[0]
	require.Len(t, fundedEmptyBatch.Seedlings, 0)
	require.NotNil(t, fundedEmptyBatch.GenesisPacket)
	t.assertBatchGenesisTx(&fundedEmptyBatch.GenesisPacket.FundedPsbt)
	require.Equal(t, defaultTapHash[:], fundedEmptyBatch.TapSibling())
	require.True(t, fundedEmptyBatch.State() == tapgarden.BatchStatePending)

	// Trying to fund a batch again should fail, as there is a pending batch
	// that is already funded.
	fundReq = tapgarden.FundParams{}
	t.fundBatch(&wg, respChan, &fundReq)
	t.assertFundBatch(&wg, respChan, "batch already funded")

	// Trying to finalize the batch with finalize parameters should also
	// fail, as those parameters should have been provided during batch
	// funding.
	finalizeReq := tapgarden.FinalizeParams{
		SiblingTapTree: fn.Some(defaultTapTree),
		FeeRate:        fn.Some(manualFee),
	}
	t.finalizeBatch(&wg, finalizeRespChan, &finalizeReq)
	t.assertFinalizeBatch(&wg, finalizeRespChan, "batch already funded")

	// Add the seedlings modified earlier to the batch, and check that they
	// were added correctly.
	t.queueSeedlingsInBatch(true, seedlings...)
	t.assertPendingBatchExists(numSeedlings)
	t.assertSeedlingsExist(seedlings, nil)

	verboseBatches, err := t.planter.ListBatches(
		tapgarden.ListBatchesParams{
			Verbose: true,
		},
	)
	require.NoError(t, err)
	require.Len(t, verboseBatches, 1)

	fundedBatch := verboseBatches[0]

	// Assert that ListBatches showed the correct number of asset groups.
	observedGroupCount := 0
	for _, seedling := range maps.Values(fundedBatch.UnsealedSeedlings) {
		if seedling.PendingAssetGroup != nil {
			observedGroupCount++
		}
	}

	require.Equal(t, groupCount, observedGroupCount)

	// Let's use the hash lock to authorize group membership for the second
	// seedling. First we need the seedling asset ID and group internal key.
	seedlingWithGroupTapscriptRoot := fundedBatch.
		UnsealedSeedlings[secondSeedling]
	seedlingAssetID := seedlingWithGroupTapscriptRoot.NewAsset.ID()
	derivedInternalKey := seedlingWithGroupTapscriptRoot.GroupInternalKey

	// Now we can build the control block for using the hash lock script.
	// The control block is built with the singly-tweaked group key, or the
	// group internal key tweaked with the seedling asset ID.
	groupSinglyTweakedKey := input.TweakPubKeyWithTweak(
		derivedInternalKey.PubKey, seedlingAssetID[:],
	)
	hashLockTapHash := hashLockLeaf.TapHash()
	hashLockTapscriptProof := tapTree.
		LeafMerkleProofs[tapTree.LeafProofIndex[hashLockTapHash]]
	hashLockTapScript := input.TapscriptPartialReveal(
		groupSinglyTweakedKey, hashLockLeaf,
		hashLockTapscriptProof.InclusionProof,
	)
	hashLockControlBlock, err := hashLockTapScript.ControlBlock.ToBytes()
	require.NoError(t, err)

	// With the control block, we can build the full group witness for the
	// seedling.
	hashLockWitness := wire.TxWitness{
		test.DefaultHashLockWitness, hashLockLeaf.Script,
		hashLockControlBlock,
	}
	seedlingWitness := tapgarden.PendingGroupWitness{
		GenID:   seedlingAssetID,
		Witness: hashLockWitness,
	}

	sealedBatch, err := t.planter.SealBatch(tapgarden.SealParams{
		GroupWitnesses: []tapgarden.PendingGroupWitness{
			seedlingWitness,
		},
	})
	require.NoError(t, err)

	// After batch sealing, we should have 3 asset groups, and the second
	// seedling should have the hash lock witness set.
	sealedGroupCount := 0
	for _, seedling := range sealedBatch.Seedlings {
		if seedling.GroupInfo != nil {
			sealedGroupCount++
		}
	}
	require.Equal(t, groupCount, sealedGroupCount)

	sealedSeedling := sealedBatch.Seedlings[secondSeedling]
	groupWithHashLock := sealedSeedling.GroupInfo
	require.Equal(
		t, defaultTapHash[:], groupWithHashLock.GroupKey.TapscriptRoot,
	)
	require.Equal(t, hashLockWitness, groupWithHashLock.GroupKey.Witness)

	// Trying to seal the batch again should fail.
	_, err = t.planter.SealBatch(tapgarden.SealParams{
		GroupWitnesses: []tapgarden.PendingGroupWitness{
			seedlingWitness,
		},
	})
	require.ErrorContains(t, err, "batch is already sealed")

	// Finally, finalize the batch and check that the resulting assets match
	// the seedlings.
	t.finalizeBatch(&wg, finalizeRespChan, nil)
	t.assertBatchProgressing()
	t.assertNoPendingBatch()

	sendConfNtfn := t.progressCaretaker(true, &defaultPreimage, &manualFee)
	mintedBatch := t.assertFinalizeBatch(&wg, finalizeRespChan, "")

	t.assertSeedlingsMatchSprouts(seedlings)

	sendConfNtfn()

	t.assertNumCaretakersActive(0)
	t.assertLastBatchState(1, tapgarden.BatchStateFinalized)
	t.assertMintOutputKey(mintedBatch, &defaultTapHash)
}

func testFundSealOnRestart(t *mintingTestHarness) {
	// First, create a new chain planter instance using the supplied test
	// harness.
	t.refreshChainPlanter()

	var (
		wg               sync.WaitGroup
		batchCount       = 0
		failedBatchCount = 0
	)

	// Create an initial batch of 5 seedlings. We'll re-use these seedlings
	// over multiple batches.
	const numSeedlings = 5
	seedlings := t.newRandSeedlings(numSeedlings)
	t.queueSeedlingsInBatch(false, seedlings...)
	batchCount++

	// Force fee estimation to fail so that batch funding fails.
	t.chain.FailFeeEstimatesOnce()
	failedBatchCount++

	// Restart the planter. The planter should try to fund the batch, and
	// fail. The batch should show as cancelled, and the pending batch
	// should be empty. The planter should still be running.
	t.assertBatchResumedBackground(&wg, true, false)
	t.refreshChainPlanter()
	wg.Wait()

	t.assertNoPendingBatch()
	t.assertNumCaretakersActive(0)
	t.assertNumBatchesWithState(
		failedBatchCount, tapgarden.BatchStateSeedlingCancelled,
	)

	// Allow batch funding to succeed, but set group key signing to fail so
	// that batch sealing fails.
	t.genSigner.FailSigningOnce()
	failedBatchCount++

	// Create a seedling with emission enabled, to ensure that batch sealing
	// will try to create an asset group witness.
	groupedSeedling := t.newRandSeedlings(1)[0]
	groupedSeedling.EnableEmission = true
	seedlings = append(seedlings, groupedSeedling)

	t.queueSeedlingsInBatch(false, seedlings...)
	batchCount++

	// Restart the planter. The planter should try to seal the batch, and
	// fail. The batch should show as cancelled, and the pending batch
	// should be empty. The planter should still be running.
	t.assertBatchResumedBackground(&wg, true, true)
	t.refreshChainPlanter()
	wg.Wait()

	t.assertNoPendingBatch()
	t.assertNumCaretakersActive(0)
	t.assertNumBatchesWithState(
		failedBatchCount, tapgarden.BatchStateSeedlingCancelled,
	)

	// Allow batch sealing to succeed. The planter should now be able to
	// start a caretaker for the batch on restart.
	t.queueSeedlingsInBatch(false, seedlings...)
	batchCount++

	t.assertBatchResumedBackground(&wg, true, true)
	t.refreshChainPlanter()
	wg.Wait()

	// With a caretaker started, the caretaker should broadcast the batch
	// as normal.
	t.assertNumCaretakersActive(1)
	t.assertNoPendingBatch()

	sendConfNtfn := t.progressCaretaker(true, nil, nil)
	t.assertLastBatchState(batchCount, tapgarden.BatchStateBroadcast)

	sendConfNtfn()
	t.assertNoError()
	t.assertNumCaretakersActive(0)
	t.assertLastBatchState(batchCount, tapgarden.BatchStateFinalized)

	// Submit another batch, which we'll leave as pending.
	secondSeedlings := t.newRandSeedlings(numSeedlings)
	t.queueSeedlingsInBatch(false, secondSeedlings...)
	batchCount++

	t.assertLastBatchState(batchCount, tapgarden.BatchStatePending)
	require.NoError(t, t.planter.Stop())
	t.planter = nil

	// We should also be able to resume one batch even when resuming another
	// batch fails. Since we can only queue one batch at a time, we'll
	// insert another pending batch on disk while the planter is shut down.
	dbBatch := t.createExternalBatch(numSeedlings)
	batchCount++
	err := t.store.CommitMintingBatch(context.Background(), dbBatch)
	require.NoError(t, err)

	// With two pending batches on disk, we want resume for the first batch
	// to fail. Resume for the second batch should succeed.
	t.chain.FailFeeEstimatesOnce()
	failedBatchCount++

	t.assertBatchResumedBackground(&wg, true, false)
	t.assertBatchResumedBackground(&wg, true, true)
	t.refreshChainPlanter()
	wg.Wait()

	t.assertNumCaretakersActive(1)
	t.assertNoPendingBatch()

	sendConfNtfn = t.progressCaretaker(true, nil, nil)
	t.assertLastBatchState(batchCount, tapgarden.BatchStateBroadcast)

	sendConfNtfn()
	t.assertNoError()
	t.assertNumCaretakersActive(0)
	t.assertNumBatchesWithState(
		failedBatchCount, tapgarden.BatchStateSeedlingCancelled,
	)
	t.assertLastBatchState(batchCount, tapgarden.BatchStateFinalized)
}

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
	{
		name:     "creation_by_minting_ticker",
		testFunc: testMintingTicker,
	},
	{
		name:     "minting_with_cancellation",
		testFunc: testMintingCancelFinalize,
	},
	{
		name:     "finalize_batch",
		testFunc: testFinalizeBatch,
	},
	{
		name:     "finalize_with_tapscript_tree",
		testFunc: testFinalizeWithTapscriptTree,
	},
	{
		name:     "fund_seal_before_finalize",
		testFunc: testFundSealBeforeFinalize,
	},
	{
		name:     "fund_seal_on_restart",
		testFunc: testFundSealOnRestart,
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
			mintTest := newMintingTestHarness(t, mintingStore)
			testCase.testFunc(mintTest)
		})
	}
}

// TestGroupKeyRevealV1WitnessWithCustomRoot tests the different possible spend
// paths for a group key reveal witness if there are custom scripts.
func TestGroupKeyRevealV1WitnessWithCustomRoot(t *testing.T) {
	var (
		ctx              = context.Background()
		mockKeyRing      = tapgarden.NewMockKeyRing()
		mockSigner       = tapgarden.NewMockGenSigner(mockKeyRing)
		txBuilder        = &tapscript.GroupTxBuilder{}
		txValidator      = &tap.ValidatorV0{}
		hashLockPreimage = []byte("foobar")
	)

	// The internal key is for the actual internal key of the group.
	internalKeyDesc, err := mockKeyRing.DeriveNextTaprootAssetKey(ctx)
	require.NoError(t, err)

	// The second key is used for a signature spend within a tapscript leaf
	// of the custom tapscript tree.
	secondKeyDesc, err := mockKeyRing.DeriveNextTaprootAssetKey(ctx)
	require.NoError(t, err)

	hashLockLeaf := test.ScriptHashLock(t, hashLockPreimage)
	schnorrSigLeaf := test.ScriptSchnorrSig(t, secondKeyDesc.PubKey)

	userRoot := txscript.AssembleTaprootScriptTree(
		hashLockLeaf, schnorrSigLeaf,
	).RootNode.TapHash()

	type testCase struct {
		name       string
		genWitness func(*testing.T, *asset.Asset,
			asset.GroupKeyRevealV1) wire.TxWitness
	}

	spendTestCases := []testCase{{
		name: "key spend",
		genWitness: func(t *testing.T, a *asset.Asset,
			gkr asset.GroupKeyRevealV1) wire.TxWitness {

			genTx, prevOut, err := txBuilder.BuildGenesisTx(a)
			require.NoError(t, err)

			witness, err := signGroupKeyV1(
				internalKeyDesc, gkr, genTx, prevOut,
				mockSigner, nil,
			)
			require.NoError(t, err)

			return witness
		},
	}, {
		name: "script spend with preimage",
		genWitness: func(t *testing.T, a *asset.Asset,
			gkr asset.GroupKeyRevealV1) wire.TxWitness {

			controlBlock, err := gkr.ScriptSpendControlBlock(
				a.ID(),
			)
			require.NoError(t, err)

			controlBlock.InclusionProof = bytes.Join([][]byte{
				fn.ByteSlice(schnorrSigLeaf.TapHash()),
				controlBlock.InclusionProof,
			}, nil)
			controlBlockBytes, err := controlBlock.ToBytes()
			require.NoError(t, err)

			// Witness is just the preimage, the script and the
			// control block.
			return wire.TxWitness{
				hashLockPreimage,
				hashLockLeaf.Script,
				controlBlockBytes,
			}
		},
	}, {
		name: "script spend with signature",
		genWitness: func(t *testing.T, a *asset.Asset,
			gkr asset.GroupKeyRevealV1) wire.TxWitness {

			genTx, prevOut, err := txBuilder.BuildGenesisTx(a)
			require.NoError(t, err)

			controlBlock, err := gkr.ScriptSpendControlBlock(
				a.ID(),
			)
			require.NoError(t, err)

			controlBlock.InclusionProof = bytes.Join([][]byte{
				fn.ByteSlice(hashLockLeaf.TapHash()),
				controlBlock.InclusionProof,
			}, nil)
			controlBlockBytes, err := controlBlock.ToBytes()
			require.NoError(t, err)

			leafToSign := &psbt.TaprootTapLeafScript{
				ControlBlock: controlBlockBytes,
				Script:       schnorrSigLeaf.Script,
				LeafVersion:  txscript.BaseLeafVersion,
			}

			witness, err := signGroupKeyV1(
				secondKeyDesc, gkr, genTx, prevOut, mockSigner,
				leafToSign,
			)
			require.NoError(t, err)

			return witness
		},
	}}

	runTestCase := func(tt *testing.T, tc testCase,
		version asset.NonSpendLeafVersion) {

		randAsset := asset.RandAsset(tt, asset.Normal)
		genAssetID := randAsset.ID()
		groupKeyReveal, err := asset.NewGroupKeyRevealV1(
			version, *internalKeyDesc.PubKey, genAssetID,
			fn.Some(userRoot),
		)
		require.NoError(tt, err)

		// Set the group key on the asset, since it's a randomly created
		// group key otherwise.
		groupPubKey, err := groupKeyReveal.GroupPubKey(genAssetID)
		require.NoError(tt, err)

		gkr := groupKeyReveal
		randAsset.GroupKey = &asset.GroupKey{
			RawKey:        internalKeyDesc,
			GroupPubKey:   *groupPubKey,
			TapscriptRoot: gkr.TapscriptRoot(),
		}
		randAsset.PrevWitnesses = []asset.Witness{
			{
				PrevID: &asset.PrevID{},
			},
		}

		witness := tc.genWitness(tt, randAsset, groupKeyReveal)
		randAsset.PrevWitnesses[0].TxWitness = witness

		err = txValidator.Execute(
			randAsset, nil, nil, proof.MockChainLookup,
		)
		require.NoError(tt, err)
	}

	gkrVersions := []asset.NonSpendLeafVersion{
		asset.OpReturnVersion,
		asset.PedersenVersion,
	}

	for _, tc := range spendTestCases {
		for _, version := range gkrVersions {
			name := fmt.Sprintf("%s:%v", tc.name, version)
			t.Run(name, func(tt *testing.T) {
				runTestCase(tt, tc, version)
			})
		}
	}
}

// TestGroupKeyRevealV1WitnessNoScripts tests the key spend path for a group key
// reveal witness if there are no custom scripts.
func TestGroupKeyRevealV1WitnessNoScripts(t *testing.T) {
	var (
		ctx         = context.Background()
		mockKeyRing = tapgarden.NewMockKeyRing()
		mockSigner  = tapgarden.NewMockGenSigner(mockKeyRing)
		txBuilder   = &tapscript.GroupTxBuilder{}
		txValidator = &tap.ValidatorV0{}
	)

	// The internal key is for the actual internal key of the group.
	internalKeyDesc, err := mockKeyRing.DeriveNextTaprootAssetKey(ctx)
	require.NoError(t, err)

	randAsset := asset.RandAsset(t, asset.Normal)
	genAssetID := randAsset.ID()
	groupKeyReveal, err := asset.NewGroupKeyRevealV1(
		asset.OpReturnVersion, *internalKeyDesc.PubKey, genAssetID,
		fn.None[chainhash.Hash](),
	)
	require.NoError(t, err)

	// Set the group key on the asset, since it's a randomly created group
	// key otherwise.
	groupPubKey, err := groupKeyReveal.GroupPubKey(genAssetID)
	require.NoError(t, err)
	randAsset.GroupKey = &asset.GroupKey{
		RawKey:        internalKeyDesc,
		GroupPubKey:   *groupPubKey,
		TapscriptRoot: groupKeyReveal.TapscriptRoot(),
	}
	randAsset.PrevWitnesses = []asset.Witness{
		{
			PrevID: &asset.PrevID{},
		},
	}

	genTx, prevOut, err := txBuilder.BuildGenesisTx(randAsset)
	require.NoError(t, err)

	witness, err := signGroupKeyV1(
		internalKeyDesc, groupKeyReveal, genTx, prevOut, mockSigner,
		nil,
	)
	require.NoError(t, err)

	randAsset.PrevWitnesses[0].TxWitness = witness

	err = txValidator.Execute(
		randAsset, nil, nil, proof.MockChainLookup,
	)
	require.NoError(t, err)
}

// signGroupKeyV1 is the equivalent for asset.DeriveGroupKey but for a V1 key.
func signGroupKeyV1(keyDesc keychain.KeyDescriptor, gk asset.GroupKeyRevealV1,
	genTx *wire.MsgTx, prevOut *wire.TxOut, signer asset.GenesisSigner,
	leafToSign *psbt.TaprootTapLeafScript) (wire.TxWitness, error) {

	signDesc := &lndclient.SignDescriptor{
		KeyDesc:    keyDesc,
		TapTweak:   gk.TapscriptRoot(),
		Output:     prevOut,
		HashType:   txscript.SigHashDefault,
		InputIndex: 0,
		SignMethod: input.TaprootKeySpendSignMethod,
	}

	if leafToSign != nil {
		signDesc.SignMethod = input.TaprootScriptSpendSignMethod
		signDesc.WitnessScript = leafToSign.Script
	}

	sig, err := signer.SignVirtualTx(signDesc, genTx, prevOut)
	if err != nil {
		return nil, err
	}

	witness := wire.TxWitness{sig.Serialize()}

	// If this was a script spend, we also have to add the script itself and
	// the control block to the witness, otherwise the verifier will reject
	// the generated witness.
	if signDesc.SignMethod == input.TaprootScriptSpendSignMethod &&
		leafToSign != nil {

		witness = append(
			witness, signDesc.WitnessScript,
			leafToSign.ControlBlock,
		)
	}

	return witness, nil
}

func init() {
	rand.Seed(time.Now().Unix())

	logger := btclog.NewSLogger(btclog.NewDefaultHandler(os.Stdout))
	tapgarden.UseLogger(logger.SubSystem(tapgarden.Subsystem))
}
