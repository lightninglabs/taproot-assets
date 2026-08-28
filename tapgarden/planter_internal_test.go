package tapgarden

import (
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// TestSignalCompletionNonBlocking pins the cultivator exit protocol
// against the cancel path. SignalCompletion must return even when the
// completion buffer is already full and the gardener is not draining
// it: the cultivator's Done() channel only closes after it returns,
// and cancelMintingBatch waits on Done() from inside a stateReq
// closure, during which the gardener cannot drain the buffer. A
// blocking send would therefore deadlock cancellation until shutdown.
// The signal also must not be dropped in that situation, since it is
// the gardener's only cue to stop the finished cultivator and remove
// it from the cultivator set.
func TestSignalCompletionNonBlocking(t *testing.T) {
	t.Parallel()

	c := NewChainPlanter(PlanterConfig{})

	batch := &MintingBatch{
		BatchKey: keychain.KeyDescriptor{
			PubKey: test.RandPubKey(t),
		},
	}
	cultivator := c.newCultivatorForBatch(batch, nil)
	batchKey := asset.ToSerialized(batch.BatchKey.PubKey)

	// Fill the buffer, simulating another cultivator's completion
	// that the gardener has not gotten to yet.
	otherKey := BatchKey{1}
	c.completionSignals <- otherKey

	// The cultivator's completion signal must not block its exit.
	signalled := make(chan struct{})
	go func() {
		cultivator.cfg.SignalCompletion()
		close(signalled)
	}()

	select {
	case <-signalled:
	case <-time.After(5 * time.Second):
		t.Fatal("SignalCompletion blocked on a full buffer")
	}

	// The overflow signal must not have been dropped: both keys
	// are eventually delivered, in either order.
	want := map[BatchKey]bool{otherKey: true, batchKey: true}
	for len(want) > 0 {
		select {
		case key := <-c.completionSignals:
			require.True(t, want[key], "unexpected key %x", key[:])
			delete(want, key)

		case <-time.After(5 * time.Second):
			t.Fatal("completion signal was dropped")
		}
	}

	// The overflow handoff goroutine is tracked by the planter's
	// wait group; it must have exited once its signal was drained.
	c.Wg.Wait()
}
