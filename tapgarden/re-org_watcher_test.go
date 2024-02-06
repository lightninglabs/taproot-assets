package tapgarden

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/stretchr/testify/require"
)

const (
	testPollInterval = 20 * time.Millisecond
	testTimeout      = 1 * time.Second

	testSafeDepth          = 4
	testInitialBlockHeight = 123_456
	testReOrgBlockHeight   = 123_654
)

type reOrgWatcherHarness struct {
	t           *testing.T
	w           *ReOrgWatcher
	cfg         *ReOrgWatcherConfig
	chainBridge *MockChainBridge
}

// assertStartup makes sure the custodian was started correctly.
func (h *reOrgWatcherHarness) assertStartup() {
	// Make sure RegisterBlockEpochNtfn is called on startup.
	_, err := fn.RecvOrTimeout(
		h.chainBridge.BlockEpochSignal, testTimeout,
	)
	require.NoError(h.t, err)
}

// eventually is a shortcut for require.Eventually with the timeout and poll
// interval pre-set.
func (h *reOrgWatcherHarness) eventually(fn func() bool) {
	require.Eventually(h.t, fn, testTimeout, testPollInterval)
}

func newReOrgWatcherHarness(t *testing.T) *reOrgWatcherHarness {
	chainBridge := NewMockChainBridge()
	cfg := &ReOrgWatcherConfig{
		ChainBridge:   chainBridge,
		GroupVerifier: GenMockGroupVerifier(),
		NonBuriedAssetFetcher: func(ctx context.Context,
			minHeight int32) ([]*asset.ChainAsset, error) {

			return nil, nil
		},
		SafeDepth: testSafeDepth,
		ErrChan:   make(chan error, 1),
	}
	return &reOrgWatcherHarness{
		t:           t,
		w:           NewReOrgWatcher(cfg),
		cfg:         cfg,
		chainBridge: chainBridge,
	}
}

func makeTx() *wire.MsgTx {
	anchorTx := wire.NewMsgTx(2)
	anchorTx.TxOut = []*wire.TxOut{{
		PkScript: test.RandBytes(32),
		Value:    100,
	}}

	return anchorTx
}

func makeProof(anchorTx *wire.MsgTx) *proof.Proof {
	return &proof.Proof{
		PrevOut: wire.OutPoint{
			Hash:  chainhash.Hash{},
			Index: test.RandInt[uint32](),
		},
		BlockHeader: wire.BlockHeader{
			Timestamp: time.Unix(test.RandInt[int64](), 0),
			Bits:      test.RandInt[uint32](),
			Nonce:     test.RandInt[uint32](),
		},
		BlockHeight: testInitialBlockHeight,
		AnchorTx:    *anchorTx,
	}
}

func makeBlock(secondTransaction *wire.MsgTx) *wire.MsgBlock {
	return &wire.MsgBlock{
		Header: wire.BlockHeader{
			Timestamp: time.Unix(test.RandInt[int64](), 0),
			Bits:      test.RandInt[uint32](),
			Nonce:     test.RandInt[uint32](),
		},
		Transactions: []*wire.MsgTx{makeTx(), secondTransaction},
	}
}

// TestWatchProofs makes sure that the re-org watcher can be started and stopped
// correctly and that proofs are being watched on chain.
func TestWatchProofs(t *testing.T) {
	t.Parallel()

	h := newReOrgWatcherHarness(t)
	require.NoError(t, h.w.Start())
	h.assertStartup()

	anchorTx1 := makeTx()
	anchorTx2 := makeTx()

	// The first two proofs are for the same anchor transaction, the third
	// proof is for a different anchor transaction.
	proofSlice1 := []*proof.Proof{makeProof(anchorTx1)}
	proofSlice2 := []*proof.Proof{makeProof(anchorTx1)}
	proofSlice3 := []*proof.Proof{makeProof(anchorTx2)}

	// We have a random block header and height in the above proofs. We'll
	// re-org the chain to include anchorTx1 in this new block later on.
	newBlock := makeBlock(anchorTx1)
	newBlockHash := newBlock.BlockHash()

	var cb1Called, cb2Called atomic.Int32
	cb1 := func(proofs []*proof.Proof) error {
		if cb1Called.Load() == 0 {
			require.Equal(
				t, proofSlice1[0].PrevOut, proofs[0].PrevOut,
			)
		} else {
			require.Equal(
				t, proofSlice2[0].PrevOut, proofs[0].PrevOut,
			)
		}

		// Make sure the proof contains the updated block header and
		// height.
		require.Equal(t, newBlock.Header, proofs[0].BlockHeader)
		require.EqualValues(
			t, testReOrgBlockHeight, proofs[0].BlockHeight,
		)

		cb1Called.Add(1)
		return nil
	}
	cb2 := func(proofs []*proof.Proof) error {
		cb2Called.Add(1)

		return nil
	}

	// Let's now register the three proof slices. The callbacks should be
	// called once per slice we submitted, not once per anchor TX.
	require.NoError(t, h.w.WatchProofs(proofSlice1, cb1))
	conf1, err := fn.RecvOrTimeout(h.chainBridge.ConfReqSignal, testTimeout)
	require.NoError(h.t, err)

	require.NoError(t, h.w.WatchProofs(proofSlice2, cb1))

	require.NoError(t, h.w.WatchProofs(proofSlice3, cb2))
	_, err = fn.RecvOrTimeout(h.chainBridge.ConfReqSignal, testTimeout)
	require.NoError(h.t, err)

	// Let's now re-org the chain for anchor TX 1.
	conf1Chan := h.chainBridge.ConfReqs[*conf1]
	conf1Chan.Confirmed <- &chainntnfs.TxConfirmation{
		BlockHash:   &newBlockHash,
		BlockHeight: testReOrgBlockHeight,
		TxIndex:     1,
		Tx:          anchorTx1,
		Block:       newBlock,
	}

	// The callback for TX1 should have been called twice, once per slice of
	// proofs we submitted.
	h.eventually(func() bool {
		return cb1Called.Load() == 2
	})

	// The anchor TX2 was not re-organized, so the callback for TX2 should
	// not have been called.
	require.EqualValues(t, 0, cb2Called.Load())

	// We now "mine" a block that is sufficiently higher than the safe depth
	// to cause the proofs to all be removed from the watcher.
	h.chainBridge.NewBlocks <- testReOrgBlockHeight + (testSafeDepth * 2)

	// We do have to stop the watcher before we can access the pending
	// proofs map, otherwise we'll run into a data race.
	require.NoError(t, h.w.Stop())
	h.eventually(func() bool {
		return len(h.w.pendingProofs) == 0
	})
}
