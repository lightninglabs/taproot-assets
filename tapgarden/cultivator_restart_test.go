package tapgarden_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// restartPoint enumerates the deterministically-observable disk states
// at which TestCultivatorRestartRecovery simulates a daemon restart. Each
// point is anchored to a well-defined synchronization signal (either a
// disk-state poll or a mock channel send) so the restart is not racy.
type restartPoint int

const (
	// rpAfterCommitted: disk state has reached BatchStateCommitted.
	// At that instant the running cultivator is parked at the head of
	// the Committed branch (blocked on the mock wallet's sign signal,
	// no branch work done yet), so this point verifies that a batch
	// recovered at Committed is picked up again and driven through
	// the whole branch to completion. It does NOT land a crash
	// between the branch's individual steps (sign, import, state
	// write); see the Scope paragraph on the test's doc comment.
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
		drainRestartErrors(t)
	}

	// Stage 2: Committed -> Broadcast (sign + import + commit_signed_tx).
	// The signals are consumed from whichever cultivator is currently
	// running (post-restart if rpAfterCommitted fired).
	t.assertGenesisPsbtFinalized(nil)

	// Stage 3: Broadcast publishes the tx. assertTxPublished is the
	// natural sync point for "publish has happened" -- the mock only
	// receives once the cultivator has called PublishTransaction.
	tx := t.assertTxPublished()

	if restartAt[rpAfterPublish] {
		t.refreshChainPlanter()
		drainRestartErrors(t)

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

	// Wait for the cultivator goroutine to drive the batch all the way
	// through Confirmed -> Finalized and shut itself down.
	awaitBatchState(t, frozenBatch.BatchKey.PubKey,
		tapgarden.BatchStateFinalized)
	t.assertNumCultivatorsActive(0)
	t.assertNoError()
	t.assertLastBatchState(1, tapgarden.BatchStateFinalized)
}

// drainRestartErrors empties the harness error channel after a
// restart, asserting that everything drained is a by-product of the
// cultivator unwinding during planter.Stop() and not a genuine
// failure that happened to be queued at that moment. Two shapes are
// benign: "shutting down" (from the cultivator itself or the mock
// call it was parked on), and the empty confirmation event the conf
// watcher reports when its context dies mid-wait.
func drainRestartErrors(t *mintingTestHarness) {
	for {
		select {
		case err := <-t.errChan:
			msg := err.Error()
			require.True(
				t,
				strings.Contains(msg, "shutting down") ||
					strings.Contains(
						msg, "empty confirmation event",
					),
				"unexpected error during restart: %v", err,
			)
		default:
			return
		}
	}
}

// TestCultivatorRestartRecovery is the capstone for the §V idempotence
// audit. It runs the mint flow once for every subset of the two
// well-synchronized restart points and asserts that each run ends with
// exactly one Finalized batch. testBasicAssetCreation pins the
// "restart at every observable boundary" case in a fixed order.
//
// Scope: this harness exercises crash recovery at boundaries *between*
// state-machine branches (the §II / §I concerns). The next layer --
// crashing *within* a branch, e.g. forcing a specific DB call to fail
// on the Nth attempt -- is the natural follow-up that would let this
// same property cover the §V "idempotent re-run of partial branch"
// case explicitly.
func TestCultivatorRestartRecovery(t *testing.T) {
	t.Parallel()

	for mask := 0; mask < 1<<len(allRestartPoints); mask++ {
		restartAt := make(map[restartPoint]bool)
		for i, rp := range allRestartPoints {
			if mask&(1<<i) != 0 {
				restartAt[rp] = true
			}
		}

		name := fmt.Sprintf("restart_mask_%02b", mask)
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := newMintingStore(t)
			h := newMintingTestHarness(t, store)

			runMintWithRestarts(h, 5, restartAt)
		})
	}
}
