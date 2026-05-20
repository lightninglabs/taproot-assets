package tapgarden_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// restartPoint enumerates the deterministically-observable disk states
// at which we can simulate a daemon restart in the rapid harness. Each
// point is anchored to a well-defined synchronization signal (either a
// disk-state poll or a mock channel send) so the restart is not racy.
type restartPoint int

const (
	// rpAfterCommitted: disk state has reached BatchStateCommitted.
	// Restart re-enters the Committed branch, which re-signs, re-
	// imports, and re-writes the genesis tx.
	rpAfterCommitted restartPoint = iota

	// rpAfterPublish: the Broadcast branch has fired PublishReq.
	// Restart re-enters the Broadcast branch, which re-publishes and
	// re-registers the conf watcher.
	rpAfterPublish
)

var allRestartPoints = []restartPoint{
	rpAfterCommitted,
	rpAfterPublish,
}

// awaitBatchState polls FetchMintingBatch until the batch's state
// reaches target (a successor state also satisfies the predicate, so
// transient passes through target are tolerated).
func awaitBatchState(t *mintingTestHarness, batchKey *btcec.PublicKey,
	target tapgarden.BatchState) {

	t.Helper()
	err := wait.Predicate(func() bool {
		batch, err := t.store.FetchMintingBatch(
			context.Background(), batchKey,
		)
		require.NoError(t, err)
		return batch.State() >= target
	}, defaultTimeout)
	require.NoError(t, err, "batch never reached state %v", target)
}

// runMintWithRestarts drives a full mint flow for numSeedlings assets,
// injecting a daemon restart at each restartPoint marked true in
// restartAt. The flow must always end with one batch in the Finalized
// state regardless of the chosen restart subset; that is the §V
// idempotence-under-restart invariant the §I-§X work is meant to
// uphold.
func runMintWithRestarts(t *mintingTestHarness, numSeedlings int,
	restartAt map[restartPoint]bool) {

	t.refreshChainPlanter()
	_ = t.queueInitialBatch(numSeedlings)

	// Stage 1: Pending -> Frozen -> Committed.
	frozenBatch := t.finalizeBatchAssertFrozen(false)
	t.assertBatchCommitted(frozenBatch.BatchKey.PubKey)

	if restartAt[rpAfterCommitted] {
		t.refreshChainPlanter()
		drainErrors(t)
	}

	// Stage 2: Committed -> Broadcast (sign + import + commit_signed_tx).
	// The signals are consumed from whichever caretaker is currently
	// running (post-restart if rpAfterCommitted fired).
	t.assertGenesisPsbtFinalized(nil)

	// Stage 3: Broadcast publishes the tx. assertTxPublished is the
	// natural sync point for "publish has happened" -- the mock only
	// receives once the caretaker has called PublishTransaction.
	tx := t.assertTxPublished()

	if restartAt[rpAfterPublish] {
		t.refreshChainPlanter()
		drainErrors(t)

		// After restart, the Broadcast branch re-runs and
		// re-publishes the tx. lnd tolerates re-broadcast of an
		// already-known tx, so this is a benign re-fire.
		tx = t.assertTxPublished()
	}

	// Stage 4: Broadcast -> Confirmed -> Finalized.
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
	sendConfNtfn()

	// Wait for the caretaker goroutine to drive the batch all the way
	// through Confirmed -> Finalized and shut itself down.
	awaitBatchState(t, frozenBatch.BatchKey.PubKey,
		tapgarden.BatchStateFinalized)
	t.assertNumCaretakersActive(0)
	t.assertNoError()
	t.assertLastBatchState(1, tapgarden.BatchStateFinalized)
}

// drainErrors empties any errors queued on the test harness error
// channel during a restart. The caretaker reports cancellations as
// errors when its context unwinds during planter.Stop(); those are
// expected by-products of the restart, not real failures.
func drainErrors(t *mintingTestHarness) {
	select {
	case <-t.errChan:
	default:
	}
}

// TestCaretakerRestartRecoveryRapid is a property-test capstone for the
// §V idempotence audit. It samples every subset of the two
// well-synchronized restart points and asserts that the mint flow
// still ends with exactly one Finalized batch, regardless of when the
// daemon is restarted along the way. testBasicAssetCreation pins the
// "restart at every observable boundary" case in a fixed order; this
// test fans that out so a failure shrinks to the smallest restart
// subset that reproduces.
//
// Scope: this harness exercises crash recovery at boundaries *between*
// state-machine branches (the §II / §I concerns). The next layer --
// crashing *within* a branch, e.g. forcing a specific DB call to fail
// on the Nth attempt -- is the natural follow-up that would let this
// same property cover the §V "idempotent re-run of partial branch"
// case explicitly.
func TestCaretakerRestartRecoveryRapid(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		// Fresh DB and fresh mock-wallet/chain stack per iteration
		// so iterations don't share state.
		store := newMintingStore(t)
		h := newMintingTestHarness(t, store)

		restartAt := make(map[restartPoint]bool)
		for _, rp := range allRestartPoints {
			label := fmt.Sprintf("restart_after_%d", rp)
			if rapid.Bool().Draw(rt, label) {
				restartAt[rp] = true
			}
		}

		runMintWithRestarts(h, 5, restartAt)
	})
}
