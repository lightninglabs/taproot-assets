package tapgarden_test

import (
	"bytes"
	"crypto/sha256"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// issue721Anchor constructs a caller-owned PSBT whose first output and all
// input metadata must survive mint preparation unchanged. Output one is the
// caller-selected asset anchor.
func issue721Anchor(t *testing.T) (*psbt.Packet, *btcec.PublicKey, []byte) {
	t.Helper()

	// A dropped witness element lets retry tests construct distinct, valid
	// witnesses for the same unsigned transaction.
	witnessScript := []byte{txscript.OP_DROP, txscript.OP_TRUE}
	witnessHash := sha256.Sum256(witnessScript)
	prevScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).AddData(witnessHash[:]).Script()
	require.NoError(t, err)

	priv, internalKey := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{7}, 32))
	require.NotNil(t, priv)
	anchorKey := txscript.ComputeTaprootKeyNoScript(internalKey)
	anchorScript, err := txscript.PayToTaprootScript(anchorKey)
	require.NoError(t, err)

	var prevHash chainhash.Hash
	copy(prevHash[:], bytes.Repeat([]byte{3}, 32))
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 9},
		Sequence:         12345,
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    2_000,
		PkScript: []byte{txscript.OP_RETURN, 0x01, 0x42},
	})
	tx.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: anchorScript})

	pkt, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	pkt.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value:    20_000,
		PkScript: prevScript,
	}
	pkt.Inputs[0].WitnessScript = witnessScript
	pkt.Inputs[0].SighashType = txscript.SigHashAll
	pkt.Inputs[0].Unknowns = []*psbt.Unknown{{
		Key: []byte{0x50}, Value: []byte("input-metadata"),
	}}
	pkt.Outputs[0].Unknowns = []*psbt.Unknown{{
		Key: []byte{0x51}, Value: []byte("output-metadata"),
	}}
	pkt.Outputs[1].TaprootInternalKey = schnorr.SerializePubKey(internalKey)
	pkt.Outputs[1].Unknowns = []*psbt.Unknown{{
		Key: []byte{0x52}, Value: []byte("anchor-metadata"),
	}}
	pkt.Unknowns = []*psbt.Unknown{{
		Key: []byte{0x53}, Value: []byte("global-metadata"),
	}}

	return pkt, internalKey, witnessScript
}

func issue721Seedling() *tapgarden.Seedling {
	return &tapgarden.Seedling{
		AssetVersion: asset.V0,
		AssetType:    asset.Normal,
		AssetName:    "issue-721-custom-anchor",
		Meta:         &proof.MetaReveal{Data: []byte("issue-721")},
		Amount:       100,
	}
}

func issue721Fund(t *testing.T, h *mintingTestHarness,
	pkt *psbt.Packet) *tapgarden.MintingBatch {

	t.Helper()
	resp, err := h.planter.FundBatch(tapgarden.FundParams{
		FeeRate:              fn.None[chainfee.SatPerKWeight](),
		SiblingTapTree:       fn.None[asset.TapscriptTreeNodes](),
		AnchorPsbt:           pkt,
		AssetAnchorOutIdx:    1,
		ChangeOutputIndex:    -1,
		PreCommitOutputIndex: fn.None[uint32](),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	return resp.Batch.ToMintingBatch()
}

func issue721FinalWitness(t *testing.T, witnessScript []byte) []byte {
	t.Helper()

	return issue721FinalWitnessWithItem(
		t, []byte{0x01}, witnessScript,
	)
}

func issue721FinalWitnessWithItem(t *testing.T, item,
	witnessScript []byte) []byte {

	t.Helper()

	var buf bytes.Buffer
	err := psbt.WriteTxWitness(
		&buf, wire.TxWitness{item, witnessScript},
	)
	require.NoError(t, err)

	return buf.Bytes()
}

// TestIssue721PrepareSignResume exercises the complete caller-owned anchor
// boundary: custom funding, synchronous commitment, restart pause, failed
// external witness retry, and successful broadcast with the original input and
// non-anchor output intact.
func TestIssue721PrepareSignResume(t *testing.T) {
	store := newMintingStore(t)
	h := newMintingTestHarness(t, store)
	h.refreshChainPlanter()
	t.Cleanup(func() {
		if h.planter != nil {
			_ = h.planter.Stop()
		}
	})

	seedling := issue721Seedling()
	h.queueSeedlingsInBatch(false, seedling)
	pkt, customInternalKey, witnessScript := issue721Anchor(t)
	original := clonePacket(t, pkt)

	funded := issue721Fund(t, h, pkt)
	require.Equal(t, tapgarden.BatchStatePending, funded.State())
	require.Equal(t, original.UnsignedTx.TxIn,
		funded.GenesisPacket.Pkt.UnsignedTx.TxIn)
	require.Equal(t, original.UnsignedTx.TxOut,
		funded.GenesisPacket.Pkt.UnsignedTx.TxOut)
	require.Equal(t, original.Inputs, funded.GenesisPacket.Pkt.Inputs)
	require.Equal(t, original.Outputs, funded.GenesisPacket.Pkt.Outputs)

	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)
	require.Equal(t, tapgarden.BatchStateCommitted, prepared.State())
	require.Equal(t, uint32(1), prepared.GenesisPacket.AssetAnchorOutIdx)

	preparedPkt := prepared.GenesisPacket.Pkt
	require.Equal(t, original.UnsignedTx.TxIn, preparedPkt.UnsignedTx.TxIn)
	require.Equal(t, original.UnsignedTx.TxOut[0],
		preparedPkt.UnsignedTx.TxOut[0])
	require.Equal(t, original.UnsignedTx.TxOut[1].Value,
		preparedPkt.UnsignedTx.TxOut[1].Value)
	require.NotEqual(t, original.UnsignedTx.TxOut[1].PkScript,
		preparedPkt.UnsignedTx.TxOut[1].PkScript)
	require.Equal(t, original.Inputs, preparedPkt.Inputs)
	require.Equal(t, original.Outputs, preparedPkt.Outputs)

	gotInternalKey, err := prepared.MintingInternalKey()
	require.NoError(t, err)
	require.True(t, gotInternalKey.IsEqual(customInternalKey))
	root := prepared.RootAssetCommitment.TapscriptRoot(nil)
	expectedOutputKey := txscript.ComputeTaprootOutputKey(
		customInternalKey, root[:],
	)
	outputKey, _, err := prepared.MintingOutputKey(nil)
	require.NoError(t, err)
	require.True(t, outputKey.IsEqual(expectedOutputKey))

	// A committed custom batch must remain pending for its external signer
	// across restart, with no caretaker attempting wallet signing.
	h.refreshChainPlanter()
	restored, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, tapgarden.BatchStateCommitted, restored.State())
	h.assertNumCaretakersActive(0)
	restoredInternalKey, err := restored.MintingInternalKey()
	require.NoError(t, err)
	require.True(t, restoredInternalKey.IsEqual(customInternalKey))

	// A corrupt witness must fail before the persisted prepared packet is
	// mutated, so a corrected external signature can be retried.
	corrupt := clonePacket(t, restored.GenesisPacket.Pkt)
	corrupt.Inputs[0].FinalScriptWitness = issue721FinalWitness(
		t, []byte{txscript.OP_FALSE},
	)
	_, err = h.planter.FinalizeBatch(tapgarden.FinalizeParams{
		SignedPsbt: corrupt,
	})
	require.ErrorContains(t, err, "externally signed PSBT is not fully valid")
	afterFailure, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, tapgarden.BatchStateCommitted, afterFailure.State())
	require.Empty(t,
		afterFailure.GenesisPacket.Pkt.Inputs[0].FinalScriptWitness)

	valid := clonePacket(t, afterFailure.GenesisPacket.Pkt)
	valid.Inputs[0].FinalScriptWitness = issue721FinalWitness(
		t, witnessScript,
	)
	var wg sync.WaitGroup
	respChan := make(chan *FinalizeBatchResp, 1)
	h.finalizeBatch(&wg, respChan, &tapgarden.FinalizeParams{
		SignedPsbt: valid,
	})
	importedKey, err := fn.RecvOrTimeout(
		h.wallet.ImportPubKeySignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.True(t, (*importedKey).IsEqual(expectedOutputKey))
	published := h.assertTxPublished()
	confReq, err := fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
	require.NoError(t, err)
	require.Equal(
		t, published.TxOut[1].PkScript, h.chain.ConfPkScripts[*confReq],
	)
	minted := h.assertFinalizeBatch(&wg, respChan, "")
	require.Equal(t, original.UnsignedTx.TxIn[0].PreviousOutPoint,
		published.TxIn[0].PreviousOutPoint)
	require.Equal(t, original.UnsignedTx.TxIn[0].Sequence,
		published.TxIn[0].Sequence)
	require.Equal(t, original.UnsignedTx.TxOut[0], published.TxOut[0])
	require.Equal(t, original.UnsignedTx.TxOut[1].Value,
		published.TxOut[1].Value)
	require.Equal(t, tapgarden.BatchStateBroadcast, minted.State())
}

// TestIssue721PublishRetry verifies a backend publication error leaves a
// caller-authored batch durably available for retry without re-preparation.
func TestIssue721PublishRetry(t *testing.T) {
	t.Run("same process", func(t *testing.T) {
		testIssue721PublishRetry(t, false)
	})
	t.Run("after restart", func(t *testing.T) {
		testIssue721PublishRetry(t, true)
	})
}

func testIssue721PublishRetry(t *testing.T, restartBeforeRetry bool) {
	store := newMintingStore(t)
	h := newMintingTestHarness(t, store)
	h.refreshChainPlanter()
	t.Cleanup(func() {
		if h.planter != nil {
			_ = h.planter.Stop()
		}
	})

	h.queueSeedlingsInBatch(false, issue721Seedling())
	pkt, _, witnessScript := issue721Anchor(t)
	issue721Fund(t, h, pkt)
	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)

	signed := clonePacket(t, prepared.GenesisPacket.Pkt)
	signed.Inputs[0].FinalScriptWitness = issue721FinalWitness(
		t, witnessScript,
	)

	h.chain.FailPublishOnce()
	var wg sync.WaitGroup
	respChan := make(chan *FinalizeBatchResp, 1)
	h.finalizeBatch(&wg, respChan, &tapgarden.FinalizeParams{
		SignedPsbt: signed,
	})
	_, err = fn.RecvOrTimeout(
		h.wallet.ImportPubKeySignal, defaultTimeout,
	)
	require.NoError(t, err)
	h.assertFinalizeBatch(&wg, respChan, "failed to publish transaction")
	firstAttempt, err := fn.RecvOrTimeout(
		h.chain.PublishAttempts, defaultTimeout,
	)
	require.NoError(t, err)

	pending, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, tapgarden.BatchStateBroadcast, pending.State())
	persisted := h.fetchSingleBatch(pending.BatchKey.PubKey)
	require.Equal(t, tapgarden.BatchStateBroadcast, persisted.State())
	_, err = h.planter.CancelBatch()
	require.ErrorContains(t, err, "not cancellable")

	if restartBeforeRetry {
		// A broadcast batch resumes automatically after restart without
		// returning to an externally cancellable pre-broadcast state.
		h.refreshChainPlanter()
		published := h.assertTxPublished()
		require.Equal(
			t, (*firstAttempt).WitnessHash(), published.WitnessHash(),
		)
		_, err = fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
		require.NoError(t, err)
		h.assertNumCaretakersActive(1)
		persisted = h.fetchSingleBatch(pending.BatchKey.PubKey)
		require.Equal(t, tapgarden.BatchStateBroadcast, persisted.State())

		return
	}

	// A Broadcast retry must not replace the transaction that was already
	// persisted before the ambiguous publication failure. Both witnesses are
	// valid and have the same txid, but the larger witness has a different
	// wtxid and weight.
	changedRetry := clonePacket(t, pending.GenesisPacket.Pkt)
	changedRetry.Inputs[0].FinalScriptWitness =
		issue721FinalWitnessWithItem(
			t, bytes.Repeat([]byte{0x02}, 500), witnessScript,
		)
	changedTx, err := psbt.Extract(changedRetry)
	require.NoError(t, err)
	require.Equal(t, (*firstAttempt).TxHash(), changedTx.TxHash())
	require.NotEqual(t, (*firstAttempt).WitnessHash(), changedTx.WitnessHash())

	_, err = h.planter.FinalizeBatch(tapgarden.FinalizeParams{
		SignedPsbt: changedRetry,
	})
	require.ErrorContains(
		t, err, "broadcast retry changes finalized transaction",
	)
	unchanged, err := h.planter.PendingBatch()
	require.NoError(t, err)
	unchangedTx, err := psbt.Extract(unchanged.GenesisPacket.Pkt)
	require.NoError(t, err)
	require.Equal(
		t, (*firstAttempt).WitnessHash(), unchangedTx.WitnessHash(),
	)

	retry := clonePacket(t, pending.GenesisPacket.Pkt)
	h.finalizeBatch(&wg, respChan, &tapgarden.FinalizeParams{
		SignedPsbt: retry,
	})
	published := h.assertTxPublished()
	require.Equal(
		t, (*firstAttempt).WitnessHash(), published.WitnessHash(),
	)
	_, err = fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
	require.NoError(t, err)
	minted := h.assertFinalizeBatch(&wg, respChan, "")
	require.Equal(t, tapgarden.BatchStateBroadcast, minted.State())
}

// TestIssue721ConfirmationRegistrationRetry ensures a successful publish
// followed by a transient notifier error remains retryable in the same process.
func TestIssue721ConfirmationRegistrationRetry(t *testing.T) {
	store := newMintingStore(t)
	h := newMintingTestHarness(t, store)
	h.refreshChainPlanter()
	t.Cleanup(func() {
		if h.planter != nil {
			_ = h.planter.Stop()
		}
	})

	h.queueSeedlingsInBatch(false, issue721Seedling())
	pkt, _, witnessScript := issue721Anchor(t)
	issue721Fund(t, h, pkt)
	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)
	signed := clonePacket(t, prepared.GenesisPacket.Pkt)
	signed.Inputs[0].FinalScriptWitness = issue721FinalWitness(
		t, witnessScript,
	)

	h.chain.FailConfRegistrationOnce()
	var wg sync.WaitGroup
	respChan := make(chan *FinalizeBatchResp, 1)
	h.finalizeBatch(&wg, respChan, &tapgarden.FinalizeParams{
		SignedPsbt: signed,
	})
	_, err = fn.RecvOrTimeout(
		h.wallet.ImportPubKeySignal, defaultTimeout,
	)
	require.NoError(t, err)
	h.assertTxPublished()
	h.assertFinalizeBatch(
		&wg, respChan, "failed to register confirmation",
	)

	pending, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, tapgarden.BatchStateBroadcast, pending.State())
	retry := clonePacket(t, pending.GenesisPacket.Pkt)
	h.finalizeBatch(&wg, respChan, &tapgarden.FinalizeParams{
		SignedPsbt: retry,
	})
	h.assertTxPublished()
	_, err = fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
	require.NoError(t, err)
	minted := h.assertFinalizeBatch(&wg, respChan, "")
	require.Equal(t, tapgarden.BatchStateBroadcast, minted.State())
}

// TestIssue721CancelPreparedBatch verifies a paused batch that already contains
// sprouts is cancelled using the sprout terminal state.
func TestIssue721CancelPreparedBatch(t *testing.T) {
	store := newMintingStore(t)
	h := newMintingTestHarness(t, store)
	h.refreshChainPlanter()
	t.Cleanup(func() {
		if h.planter != nil {
			_ = h.planter.Stop()
		}
	})

	h.queueSeedlingsInBatch(false, issue721Seedling())
	pkt, _, _ := issue721Anchor(t)
	issue721Fund(t, h, pkt)
	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)

	batchKey, err := h.planter.CancelBatch()
	require.NoError(t, err)
	require.True(t, batchKey.IsEqual(prepared.BatchKey.PubKey))
	cancelled := h.fetchSingleBatch(batchKey)
	require.Equal(t, tapgarden.BatchStateSproutCancelled, cancelled.State())
}

// TestIssue721LowFeeRejectsBeforeBroadcast verifies a caller-authored
// transaction that cannot meet the node's minimum relay fee remains in the
// prepared state, where it can still be cancelled and rebuilt.
func TestIssue721LowFeeRejectsBeforeBroadcast(t *testing.T) {
	store := newMintingStore(t)
	h := newMintingTestHarness(t, store)
	h.refreshChainPlanter()
	t.Cleanup(func() {
		if h.planter != nil {
			_ = h.planter.Stop()
		}
	})

	h.queueSeedlingsInBatch(false, issue721Seedling())
	pkt, _, witnessScript := issue721Anchor(t)
	pkt.Inputs[0].WitnessUtxo.Value = 12_000
	issue721Fund(t, h, pkt)
	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)

	signed := clonePacket(t, prepared.GenesisPacket.Pkt)
	signed.Inputs[0].FinalScriptWitness = issue721FinalWitness(
		t, witnessScript,
	)
	_, err = h.planter.FinalizeBatch(tapgarden.FinalizeParams{
		SignedPsbt: signed,
	})
	require.ErrorContains(t, err, "fee does not meet minrelayfee")

	pending, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, tapgarden.BatchStateCommitted, pending.State())
	h.assertNumCaretakersActive(0)

	batchKey, err := h.planter.CancelBatch()
	require.NoError(t, err)
	require.True(t, batchKey.IsEqual(prepared.BatchKey.PubKey))
	cancelled := h.fetchSingleBatch(batchKey)
	require.Equal(t, tapgarden.BatchStateSproutCancelled, cancelled.State())
}

// TestIssue721CustomRestartStates pins the startup distinction introduced by
// the external-signing flow: custom pending/frozen batches pause, while a
// legacy pending batch still resumes through the existing caretaker path.
func TestIssue721CustomRestartStates(t *testing.T) {
	for _, state := range []tapgarden.BatchState{
		tapgarden.BatchStatePending,
		tapgarden.BatchStateFrozen,
	} {
		state := state
		t.Run(state.String(), func(t *testing.T) {
			store := newMintingStore(t)
			h := newMintingTestHarness(t, store)
			h.refreshChainPlanter()
			t.Cleanup(func() {
				if h.planter != nil {
					_ = h.planter.Stop()
				}
			})

			h.queueSeedlingsInBatch(false, issue721Seedling())
			pkt, _, _ := issue721Anchor(t)
			batch := issue721Fund(t, h, pkt)
			if state == tapgarden.BatchStateFrozen {
				err := store.UpdateBatchState(
					t.Context(), batch.BatchKey.PubKey, state,
				)
				require.NoError(t, err)
			}

			h.refreshChainPlanter()
			restored, err := h.planter.PendingBatch()
			require.NoError(t, err)
			require.Equal(t, state, restored.State())
			h.assertNumCaretakersActive(0)
		})
	}

	t.Run("legacy pending resumes", func(t *testing.T) {
		store := newMintingStore(t)
		h := newMintingTestHarness(t, store)
		h.refreshChainPlanter()
		t.Cleanup(func() {
			if h.planter != nil {
				_ = h.planter.Stop()
			}
		})

		h.queueSeedlingsInBatch(false, issue721Seedling())
		var wg sync.WaitGroup
		h.assertBatchResumedBackground(&wg, true, true)
		h.refreshChainPlanter()
		wg.Wait()
		h.assertNumCaretakersActive(1)
	})
}

func clonePacket(t *testing.T, pkt *psbt.Packet) *psbt.Packet {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, pkt.Serialize(&buf))
	clone, err := psbt.NewFromRawBytes(&buf, false)
	require.NoError(t, err)

	return clone
}
