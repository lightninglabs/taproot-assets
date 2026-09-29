package fixture

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// MintDriver wraps a Mint fixture with a background pump that drains every
// signal channel the planter's cultivator emits during a mint flow and feeds
// back synthetic chain confirmations. The driver lets benchmarks call Mint(n)
// repeatedly without re-implementing the chain/wallet mock choreography.
//
// The pump is started in NewMintDriver and torn down via tb.Cleanup. All
// state belongs to the driver instance; Mint calls are safe to issue from
// the same goroutine that constructed it.
type MintDriver struct {
	*Mint

	pumpCancel context.CancelFunc
	pumpDone   chan struct{}
}

// NewMintDriver constructs a Mint fixture and a pump that responds to the
// planter's chain/wallet signals. The pump runs until the testing.TB
// cleanup fires.
func NewMintDriver(tb testing.TB) *MintDriver {
	tb.Helper()

	m := NewMint(tb)
	ctx, cancel := context.WithCancel(context.Background())
	d := &MintDriver{
		Mint:       m,
		pumpCancel: cancel,
		pumpDone:   make(chan struct{}),
	}

	go d.pump(ctx)
	tb.Cleanup(func() {
		cancel()
		<-d.pumpDone
	})

	return d
}

// pump drains every signal the planter cultivator is known to emit and
// synthesises the chain side of the conversation: each published
// genesis transaction is confirmed on the mock re-org watcher, its
// block is stored for the cultivator's witness-block fetch, and the
// cultivator waiting on the anchoring is woken the way the watcher's
// delivery listener does in production.
func (d *MintDriver) pump(ctx context.Context) {
	defer close(d.pumpDone)

	for {
		select {
		case <-ctx.Done():
			return

		case <-d.ChainBridge.FeeEstimateSignal:
		case <-d.Wallet.FundPsbtSignal:
		case <-d.Wallet.SignPsbtSignal:
		case <-d.Wallet.ImportPubKeySignal:
		case <-d.Wallet.SubscribeTxSignal:
		case <-d.Wallet.ListUnspentSignal:
		case <-d.Wallet.ListTxnsSignal:
		case <-d.ChainBridge.BlockEpochSignal:

		case tx := <-d.ChainBridge.PublishReq:
			d.confirm(ctx, tx)
		}
	}
}

// confirm confirms a published genesis transaction: its one-tx block is
// registered with the chain bridge so the cultivator's GetBlock call
// finds it, the anchoring staked on the transaction (before it was
// published) flips to witnessed on the mock watcher, and the planter's
// delivery listener wakes the cultivator waiting on it.
func (d *MintDriver) confirm(ctx context.Context, tx *wire.MsgTx) {
	block := buildBlockForTx(tx)
	blockHash := block.BlockHash()
	d.ChainBridge.SetBlock(blockHash, block)

	_, err := d.Registrar.ConfirmSpend(
		tx, blockHash, 1, 0, block.Header, proof.TxMerkleProof{
			Bits:  []bool{true},
			Nodes: []chainhash.Hash{blockHash},
		},
	)
	if err != nil {
		return
	}

	spent := make(map[wire.OutPoint]struct{}, len(tx.TxIn))
	for _, txIn := range tx.TxIn {
		spent[txIn.PreviousOutPoint] = struct{}{}
	}
	anchorings, err := d.Registrar.AllAnchorings(ctx, tapgarden.MintSiteID)
	if err != nil {
		return
	}
	for _, anchoring := range anchorings {
		for _, point := range anchoring.Triggers.OutPoints() {
			if _, ok := spent[point.OutPoint]; !ok {
				continue
			}
			d.Planter.OnAnchoringDelivered(
				anchoring.ID, tapgarden.MintSiteID,
				tapreorg.Witnessed{},
			)

			break
		}
	}
}

// EnqueueSeedlings queues n random Normal seedlings on the planter and
// waits for each to reach MintingStateSeed.
func (d *MintDriver) EnqueueSeedlings(tb testing.TB, n int) {
	tb.Helper()
	for i := 0; i < n; i++ {
		var nameBytes [16]byte
		// #nosec G404 -- bench fixture, throwaway seedling name.
		if _, err := rand.Read(nameBytes[:]); err != nil {
			tb.Fatalf("rand seedling name: %v", err)
		}
		seedling := &tapgarden.Seedling{
			AssetVersion: asset.V0,
			AssetType:    asset.Normal,
			AssetName:    hex.EncodeToString(nameBytes[:]),
			// #nosec G404 -- bench fixture, throwaway amount.
			Amount: uint64(rand.Int31() + 1),
			Meta: &proof.MetaReveal{
				Data: nameBytes[:],
			},
		}
		updates, err := d.Planter.QueueNewSeedling(seedling)
		require.NoError(tb, err)

		// Drain the MintingStateSeed update so the planter is ready
		// for the next request. Block until the update arrives.
		u := <-updates
		require.NoError(tb, u.Error)
	}
}

// FinalizeBatch fires FinalizeBatch and blocks until the pump has driven
// the cultivator through funding, publishing, and confirmation. The
// planter's FinalizeBatch returns on broadcast (BroadcastCompleteChan),
// not on confirmation; we then wait on the batch state to reach
// Confirmed so the caller has the full async confirmation/finalization
// cost in its timing window.
func (d *MintDriver) FinalizeBatch(tb testing.TB) {
	tb.Helper()

	batch, err := d.Planter.FinalizeBatch(tapgarden.FinalizeParams{})
	require.NoError(tb, err)
	require.NotNil(tb, batch)
	batchKey := batch.BatchKey.PubKey

	require.NoError(tb, wait.NoError(func() error {
		// Look up the specific batch we just finalized. Re-fetching
		// by key avoids races with other in-flight batches that
		// would otherwise be visible to a list call.
		batches, lErr := d.Planter.ListBatches(
			tapgarden.ListBatchesParams{
				BatchKey: batchKey,
			},
		)
		if lErr != nil {
			return lErr
		}
		for _, b := range batches {
			if b.State() >= tapgarden.BatchStateConfirmed {
				return nil
			}
		}
		return fmt.Errorf("batch not yet confirmed")
	}, 30*time.Second))
}

// MintOne runs one full mint of n assets: enqueue n seedlings, finalize
// the batch, let the pump drive it to confirmation. This is the unit a
// scenario bench cycles over.
//
// The method name avoids the embedded *Mint fixture's identifier.
func (d *MintDriver) MintOne(tb testing.TB, n int) {
	tb.Helper()
	d.EnqueueSeedlings(tb, n)
	d.FinalizeBatch(tb)
}

// FundPendingBatch drives the planter through the funding step on the
// current pending batch, leaving the batch in the frozen state ready
// for SealBatch. The chain pump consumes the fee/fund signals.
//
// This is exposed so per-RPC bench setup can stage state without going
// through the rpcserver.FundBatch handler (which needs cfg.Lnd).
func (d *MintDriver) FundPendingBatch(tb testing.TB) {
	tb.Helper()
	_, err := d.Planter.FundBatch(tapgarden.FundParams{})
	require.NoError(tb, err)
}

// buildBlockForTx wraps tx in a single-transaction block.
func buildBlockForTx(tx *wire.MsgTx) *wire.MsgBlock {
	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(tx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	hdr := wire.NewBlockHeader(
		0, chaincfg.MainNetParams.GenesisHash, merkleRoot, 0, 0,
	)
	return &wire.MsgBlock{
		Header:       *hdr,
		Transactions: []*wire.MsgTx{tx},
	}
}
