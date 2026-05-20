package tapgarden_test

import (
	"context"
	"flag"
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
	"pgregory.net/rapid"
)

// defaultRapidChecks is the number of iterations TestCaretakerRestart
// RecoveryRapid samples by default. The subset space being explored is
// small (4 cases: each restart point on/off), so 30 iterations already
// hits every case multiple times. Operators wanting deeper exploration
// can override via `-rapid.checks=N`.
const defaultRapidChecks = 30

// init lowers rapid's iteration count from its built-in default (100,
// which is gratuitous for the 4-element subset space and dominates the
// package's test runtime once batch.Copy does real work) to
// defaultRapidChecks. The write happens at package init -- before the
// testing package parses flags -- so it cannot race a running test,
// and an explicit -rapid.checks=N on the command line still wins
// because flag parsing runs afterwards.
func init() {
	if cf := flag.Lookup("rapid.checks"); cf != nil {
		_ = cf.Value.Set(fmt.Sprintf("%d", defaultRapidChecks))
	}
}

// rapidTB routes harness failures to the current rapid iteration while
// deferring everything else to the enclosing *testing.T. A require
// failure inside the property body then fails only that iteration,
// which is what lets rapid shrink to a minimal failing restart subset
// instead of aborting the whole test at the first failure. testing.TB
// cannot be implemented from scratch (it has an unexported method), so
// the adapter embeds the outer TB and overrides the failure and
// logging surface.
type rapidTB struct {
	testing.TB

	rt *rapid.T
}

func (r rapidTB) Error(args ...any) { r.rt.Error(args...) }
func (r rapidTB) Fail()             { r.rt.Fail() }
func (r rapidTB) FailNow()          { r.rt.FailNow() }
func (r rapidTB) Failed() bool      { return r.rt.Failed() }
func (r rapidTB) Fatal(args ...any) { r.rt.Fatal(args...) }
func (r rapidTB) Log(args ...any)   { r.rt.Log(args...) }

func (r rapidTB) Errorf(format string, args ...any) {
	r.rt.Errorf(format, args...)
}

func (r rapidTB) Fatalf(format string, args ...any) {
	r.rt.Fatalf(format, args...)
}

func (r rapidTB) Logf(format string, args ...any) {
	r.rt.Logf(format, args...)
}

// restartPoint enumerates the deterministically-observable disk states
// at which we can simulate a daemon restart in the rapid harness. Each
// point is anchored to a well-defined synchronization signal (either a
// disk-state poll or a mock channel send) so the restart is not racy.
type restartPoint int

const (
	// rpAfterCommitted: disk state has reached BatchStateCommitted.
	// At that instant the running caretaker is parked at the head of
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
	// The signals are consumed from whichever caretaker is currently
	// running (post-restart if rpAfterCommitted fired).
	t.assertGenesisPsbtFinalized(nil)

	// Stage 3: Broadcast publishes the tx. assertTxPublished is the
	// natural sync point for "publish has happened" -- the mock only
	// receives once the caretaker has called PublishTransaction.
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

	// Wait for the caretaker goroutine to drive the batch all the way
	// through Confirmed -> Finalized and shut itself down.
	awaitBatchState(t, frozenBatch.BatchKey.PubKey,
		tapgarden.BatchStateFinalized)
	t.assertNumCaretakersActive(0)
	t.assertNoError()
	t.assertLastBatchState(1, tapgarden.BatchStateFinalized)
}

// drainRestartErrors empties the harness error channel after a
// restart, asserting that everything drained is a by-product of the
// caretaker unwinding during planter.Stop() and not a genuine
// failure that happened to be queued at that moment. Two shapes are
// benign: "shutting down" (from the caretaker itself or the mock
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
		// so iterations don't share state. The store keeps the
		// outer t (its DB cleanup hooks need testing.T), while the
		// harness reports failures against the current iteration
		// through rt.
		store := newMintingStore(t)
		h := newMintingTestHarness(rapidTB{TB: t, rt: rt}, store)

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
