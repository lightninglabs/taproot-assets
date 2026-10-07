package tapgarden

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapnode"
	"github.com/lightninglabs/taproot-assets/tapnode/tapnodemock"
	"github.com/lightninglabs/taproot-assets/tapreorg"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// customWatcherFixture resumes a signed batch with a wallet input, a foreign
// input, and its asset anchor at output one. Only the wallet input is leased.
func customWatcherFixture(t *testing.T) (*Cultivator,
	*tapnodemock.ChainBridge, *trackedCustomAnchorWallet,
	*tapreorg.MockRegistrar) {

	t.Helper()
	pkt := testCustomAnchorPacket(t)
	foreign := wire.OutPoint{Hash: chainhash.Hash{2}, Index: 3}
	pkt.UnsignedTx.AddTxIn(wire.NewTxIn(&foreign, nil, nil))
	pkt.Inputs = append(pkt.Inputs, psbt.PInput{
		WitnessUtxo: wire.NewTxOut(2_000, []byte{0x51}),
	})
	pkt.UnsignedTx.TxOut = append([]*wire.TxOut{
		wire.NewTxOut(0, []byte{0x6a}),
	}, pkt.UnsignedTx.TxOut...)
	pkt.Outputs = append([]psbt.POutput{{}}, pkt.Outputs...)
	for i := range pkt.Inputs {
		pkt.Inputs[i].FinalScriptSig = []byte{}
	}
	locked := []wire.OutPoint{pkt.UnsignedTx.TxIn[0].PreviousOutPoint}
	SetCustomAnchorLockedUTXOs(pkt, locked)
	setCustomAnchorPublishState(pkt, customAnchorPublishPending)

	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	batch := &MintingBatch{
		BatchKey:   keychain.KeyDescriptor{PubKey: key.PubKey()},
		HeightHint: 100,
		GenesisPacket: &FundedMintAnchorPsbt{
			FundedPsbt: tapsend.FundedPsbt{
				Pkt: pkt, LockedUTXOs: locked,
			},
			AssetAnchorOutIdx: 1,
		},
	}
	batch.setState(BatchStateBroadcast)
	wallet := newTrackedCustomAnchorWallet()
	chain := tapnodemock.NewChainBridge()
	chain.PublishReq = make(chan *wire.MsgTx, 10)
	registrar := tapreorg.NewMockRegistrar()
	cultivator := NewCultivator(&CultivatorConfig{
		Batch: batch,
		GardenKit: &GardenKit{
			Wallet: wallet, ChainBridge: chain,
			AnchoringWatcher: registrar, AnchoringThreshold: 6,
		},
		AnchoringWaiters:      tapreorg.NewDeliveryWaiters(),
		BroadcastCompleteChan: make(chan struct{}, 1),
		BroadcastErrChan:      make(chan error, 1),
		CancelReqChan:         make(chan cancelReq, 1),
		ErrChan:               make(chan error, 1),
		SignalCompletion:      func() {},
		PublishMintEvent:      func(fn.Event) {},
	})
	t.Cleanup(func() { require.NoError(t, cultivator.Stop()) })
	return cultivator, chain, wallet, registrar
}

// TestCustomAnchorWatcherConfirmation pins the merge boundary: registration
// precedes retries, failures remain watched, and externally relayed bytes can
// confirm without using a second, legacy confirmation subscription.
func TestCustomAnchorWatcherConfirmation(t *testing.T) {
	failures := []string{"publication", "lease", "registration"}
	for _, failure := range failures {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			b, chain, wallet, registrar := customWatcherFixture(t)
			pkt := b.cfg.Batch.GenesisPacket.Pkt
			var before bytes.Buffer
			require.NoError(t, pkt.Serialize(&before))
			signed, err := psbt.Extract(pkt)
			require.NoError(t, err)
			chain.FailPublishOnce()
			if failure == "registration" {
				registrar.FailNextRegister(
					fmt.Errorf("registry offline"),
				)
				_, err := b.stateStep(BatchStateBroadcast)
				require.ErrorContains(
					t, err, "registry offline",
				)
				require.Empty(t, chain.PublishAttempts)
			}
			if failure == "lease" {
				op := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
				owner := tapnode.CustomAnchorLeaseID{1}
				wallet.leases[op] = owner
			}
			state, err := b.stateStep(BatchStateBroadcast)
			require.NoError(t, err)
			require.Equal(t, BatchStateBroadcast, state)
			require.False(t, b.customAnchorWalletAccepted)
			if failure == "lease" {
				require.Empty(t, chain.PublishAttempts)
			} else {
				require.Len(t, chain.PublishAttempts, 1)
				attempt := <-chain.PublishAttempts
				require.Equal(t, watcherTxBytes(t, signed),
					watcherTxBytes(t, attempt))
			}
			require.Zero(t, chain.ReqCount.Load())

			ctx := context.Background()
			txid := signed.TxHash()
			anchoring, err := registrar.LookupByMatchKey(
				ctx, MintSiteID, txid.CloneBytes(),
			)
			require.NoError(t, err)
			require.NotNil(t, anchoring)
			points := anchoring.Triggers.OutPoints()
			require.Len(t, points, 2)
			for _, point := range points {
				for i, input := range signed.TxIn {
					op := input.PreviousOutPoint
					if point.OutPoint != op {
						continue
					}
					prev := pkt.Inputs[i].WitnessUtxo
					require.Equal(t, prev.PkScript,
						point.PkScript)
				}
			}
			reply := make(chan CancelResp, 1)
			require.Error(t, b.Cancel(reply))
			require.False(t, (<-reply).cancelAttempted)

			block := &wire.MsgBlock{
				Header:       wire.BlockHeader{Nonce: 7},
				Transactions: []*wire.MsgTx{signed},
			}
			chain.SetBlock(block.BlockHash(), block)
			_, err = registrar.ConfirmSpend(
				signed, block.BlockHash(), 101, 0,
				block.Header, proof.TxMerkleProof{},
			)
			require.NoError(t, err)
			b.cfg.AnchoringWaiters.Nudge(anchoring.ID)
			select {
			case conf := <-b.confEvent:
				require.Equal(t, watcherTxBytes(t, signed),
					watcherTxBytes(t, conf.Tx))
				require.Equal(t, block.BlockHash(),
					*conf.BlockHash)
			case <-time.After(5 * time.Second):
				t.Fatal("custom anchor confirmation was lost")
			}
			var after bytes.Buffer
			require.NoError(t, pkt.Serialize(&after))
			require.Equal(t, before.Bytes(), after.Bytes())
		})
	}
}

// TestCustomAnchorWatcherRetryAbandonment covers retries after restart and
// terminal conflict delivery, lease ownership and packet immutability.
func TestCustomAnchorWatcherRetryAbandonment(t *testing.T) {
	t.Parallel()
	b, chain, wallet, registrar := customWatcherFixture(t)
	b.cfg.CustomAnchorLeaseRenewalInterval = 10 * time.Millisecond
	pkt := b.cfg.Batch.GenesisPacket.Pkt
	var before bytes.Buffer
	require.NoError(t, pkt.Serialize(&before))
	chain.FailPublishOnce()
	require.NoError(t, b.Start())
	var first *wire.MsgTx
	select {
	case first = <-chain.PublishAttempts:
	case <-time.After(5 * time.Second):
		t.Fatal("initial custom publication was not attempted")
	}
	select {
	case retry := <-chain.PublishReq:
		require.Equal(t, watcherTxBytes(t, first),
			watcherTxBytes(t, retry))
	case <-time.After(5 * time.Second):
		t.Fatal("custom publication was not retried")
	}
	txid := first.TxHash()
	anchoring, err := registrar.LookupByMatchKey(context.Background(),
		MintSiteID, txid.CloneBytes())
	require.NoError(t, err)
	require.NotNil(t, anchoring)
	foreign := first.Copy()
	foreign.TxOut[0].Value++
	require.NoError(t, registrar.Abandon(anchoring.ID, foreign,
		chainhash.Hash{9}, 107, 0))
	b.cfg.AnchoringWaiters.Nudge(anchoring.ID)
	select {
	case <-b.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("custom cultivator did not stop after abandonment")
	}
	require.Equal(t, BatchStateSproutCancelled, b.cfg.Batch.State())
	require.Empty(t, b.cfg.ErrChan)
	require.Zero(t, chain.ReqCount.Load())
	wallet.mu.Lock()
	defer wallet.mu.Unlock()
	require.Empty(t, wallet.leases)
	require.Equal(t, []customAnchorLeaseRequest{{
		leaseID: customAnchorLeaseID(b.cfg.Batch.BatchKey.PubKey),
		op:      pkt.UnsignedTx.TxIn[0].PreviousOutPoint,
	}}, wallet.releases)
	var after bytes.Buffer
	require.NoError(t, pkt.Serialize(&after))
	require.Equal(t, before.Bytes(), after.Bytes())
}

func watcherTxBytes(t *testing.T, tx *wire.MsgTx) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, tx.Serialize(&buf))
	return buf.Bytes()
}
