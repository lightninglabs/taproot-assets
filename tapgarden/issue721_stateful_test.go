package tapgarden_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type issue721FailSignedStore struct {
	tapgarden.MintingStore
	fail bool
}

type issue721FailStateStore struct {
	tapgarden.MintingStore
	fail bool
}

func (s *issue721FailStateStore) UpdateBatchState(ctx context.Context,
	batch *tapgarden.MintingBatch, state tapgarden.BatchState) error {

	if s.fail && state == tapgarden.BatchStateSproutCancelled {
		return fmt.Errorf("injected cancellation store failure")
	}

	return s.MintingStore.UpdateBatchState(ctx, batch, state)
}

func (s *issue721FailSignedStore) StoreSignedGenesisPsbt(ctx context.Context,
	batchKey *btcec.PublicKey, funded *tapsend.FundedPsbt) error {

	if s.fail {
		return fmt.Errorf("injected signed PSBT store failure")
	}

	return s.MintingStore.StoreSignedGenesisPsbt(ctx, batchKey, funded)
}

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
	keyDesc := keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: asset.TaprootAssetsKeyFamily,
			Index:  721,
		},
		PubKey: internalKey,
	}
	bip32Derivation, taprootDerivation :=
		tappsbt.Bip32DerivationFromKeyDesc(
			keyDesc, address.TestNet3Tap.HDCoinType,
		)
	pkt.Outputs[1].Bip32Derivation = []*psbt.Bip32Derivation{
		bip32Derivation,
	}
	pkt.Outputs[1].TaprootBip32Derivation =
		[]*psbt.TaprootBip32Derivation{taprootDerivation}
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
	anchorPriv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{7}, 32))
	h.keyRing.Keys[keychain.KeyLocator{
		Family: asset.TaprootAssetsKeyFamily,
		Index:  721,
	}] = anchorPriv
	h.keyRing.On(
		"IsLocalKey", mock.Anything, mock.Anything,
	).Maybe()
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

func TestIssue721RejectsNonLocalAnchorKey(t *testing.T) {
	store := newMintingStore(t)
	h := newMintingTestHarness(t, store)
	h.refreshChainPlanter()
	t.Cleanup(func() {
		_ = h.planter.Stop()
	})

	h.queueSeedlingsInBatch(false, issue721Seedling())
	pkt, _, _ := issue721Anchor(t)
	h.keyRing.On(
		"IsLocalKey", mock.Anything, mock.Anything,
	).Maybe()
	_, err := h.planter.FundBatch(tapgarden.FundParams{
		FeeRate:              fn.None[chainfee.SatPerKWeight](),
		SiblingTapTree:       fn.None[asset.TapscriptTreeNodes](),
		AnchorPsbt:           pkt,
		AssetAnchorOutIdx:    1,
		ChangeOutputIndex:    -1,
		PreCommitOutputIndex: fn.None[uint32](),
	})
	require.ErrorContains(t, err, "not controlled by the backing wallet")
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
	callerBytes := serializePacket(t, pkt)
	ownedInput := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	h.wallet.SetOwnedInput(ownedInput, true)

	funded := issue721Fund(t, h, pkt)
	initialLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *initialLease)
	require.Equal(t, tapgarden.BatchStatePending, funded.State())
	require.Equal(t, original.UnsignedTx.TxIn,
		funded.GenesisPacket.Pkt.UnsignedTx.TxIn)
	require.Equal(t, original.UnsignedTx.TxOut,
		funded.GenesisPacket.Pkt.UnsignedTx.TxOut)
	require.Equal(t, original.Inputs, funded.GenesisPacket.Pkt.Inputs)
	require.Equal(t, original.Outputs, funded.GenesisPacket.Pkt.Outputs)

	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)
	require.Equal(t, callerBytes, serializePacket(t, pkt))
	pkt.Unknowns[0].Value[0] ^= 1
	pendingAfterCallerMutation, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, original.Unknowns[0],
		pendingAfterCallerMutation.GenesisPacket.Pkt.Unknowns[0])
	require.Equal(t, tapgarden.BatchStateCommitted, prepared.State())
	require.Equal(t, uint32(1), prepared.GenesisPacket.AssetAnchorOutIdx)

	// Once the asset root is committed, no content-mutating entry point can
	// change the batch. The original batch must remain usable afterward.
	second := issue721Seedling()
	second.AssetName = "issue-721-too-late"
	updates, err := h.planter.QueueNewSeedling(second)
	require.NoError(t, err)
	update, err := fn.RecvOrTimeout(updates, defaultTimeout)
	require.NoError(t, err)
	require.ErrorContains(t, update.Error, "cannot accept new seedlings")
	_, err = h.planter.SealBatch(tapgarden.SealParams{})
	require.ErrorContains(t, err, "cannot be sealed")
	_, err = h.planter.PrepareBatch()
	require.ErrorContains(t, err, "not ready for preparation")
	_, err = h.planter.FundBatch(tapgarden.FundParams{})
	require.ErrorContains(t, err, "cannot be funded")
	preparedBytes := serializePacket(t, prepared.GenesisPacket.Pkt)
	preparedRoot := prepared.RootAssetCommitment.TapscriptRoot(nil)
	liveAfterMutations, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Len(t, liveAfterMutations.Seedlings, 1)
	require.Equal(t, preparedBytes,
		serializePacket(t, liveAfterMutations.GenesisPacket.Pkt))
	require.Equal(t, preparedRoot,
		liveAfterMutations.RootAssetCommitment.TapscriptRoot(nil))
	persistedAfterMutations := h.fetchSingleBatch(prepared.BatchKey.PubKey)
	require.Equal(t, tapgarden.BatchStateCommitted,
		persistedAfterMutations.State())
	require.Equal(t, preparedBytes,
		serializePacket(t, persistedAfterMutations.GenesisPacket.Pkt))
	require.Equal(t, preparedRoot,
		persistedAfterMutations.RootAssetCommitment.TapscriptRoot(nil))

	preparedPkt := prepared.GenesisPacket.Pkt
	require.Equal(t, original.UnsignedTx.TxIn, preparedPkt.UnsignedTx.TxIn)
	require.Equal(t, original.UnsignedTx.TxOut[0],
		preparedPkt.UnsignedTx.TxOut[0])
	require.Equal(t, original.UnsignedTx.TxOut[1].Value,
		preparedPkt.UnsignedTx.TxOut[1].Value)
	require.NotEqual(t, original.UnsignedTx.TxOut[1].PkScript,
		preparedPkt.UnsignedTx.TxOut[1].PkScript)
	require.Equal(t, original.Inputs, preparedPkt.Inputs)
	require.Equal(t, original.Outputs[0], preparedPkt.Outputs[0])
	require.Equal(t, original.Outputs[1].Bip32Derivation,
		preparedPkt.Outputs[1].Bip32Derivation)
	require.Equal(t, original.Outputs[1].Unknowns,
		preparedPkt.Outputs[1].Unknowns)
	require.Nil(t, preparedPkt.Outputs[1].TaprootInternalKey)
	require.Nil(t, preparedPkt.Outputs[1].TaprootBip32Derivation)

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
	restartLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *restartLease)
	restored, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, tapgarden.BatchStateCommitted, restored.State())
	require.Equal(t, preparedBytes,
		serializePacket(t, restored.GenesisPacket.Pkt))
	require.Equal(t, preparedRoot,
		restored.RootAssetCommitment.TapscriptRoot(nil))
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
	finalizeLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *finalizeLease)
	importedKey, err := fn.RecvOrTimeout(
		h.wallet.ImportPubKeySignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.True(t, (*importedKey).IsEqual(expectedOutputKey))
	confReq, err := fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
	require.NoError(t, err)
	published, err := psbt.Extract(valid)
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

// TestIssue721PublishRetry verifies a one-shot ambiguous initial submission is
// retried automatically from Broadcast and installs a confirmation watcher.
func TestIssue721PublishRetry(t *testing.T) {
	store := newMintingStore(t)
	h := newMintingTestHarness(t, store)
	h.leaseRenewalInterval = 100 * time.Millisecond
	h.refreshChainPlanter()
	t.Cleanup(func() {
		if h.planter != nil {
			_ = h.planter.Stop()
		}
	})

	h.queueSeedlingsInBatch(false, issue721Seedling())
	pkt, _, witnessScript := issue721Anchor(t)
	ownedInput := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	h.wallet.SetOwnedInput(ownedInput, true)
	issue721Fund(t, h, pkt)
	initialLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *initialLease)
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
	finalizeLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *finalizeLease)
	_, err = fn.RecvOrTimeout(
		h.wallet.ImportPubKeySignal, defaultTimeout,
	)
	require.NoError(t, err)
	firstAttempt, err := fn.RecvOrTimeout(
		h.chain.PublishAttempts, defaultTimeout,
	)
	require.NoError(t, err)

	// Degrade lease renewal before the first Broadcast retry. The watcher
	// must still be installed, while active publication is suppressed until
	// the recorded local input is protected again.
	h.wallet.SetLeaseError(
		ownedInput, fmt.Errorf("temporary broadcast renewal failure"),
	)
	_, err = fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
	require.NoError(t, err)
	minted := h.assertFinalizeBatch(&wg, respChan, "")
	require.Equal(t, tapgarden.BatchStateBroadcast, minted.State())
	select {
	case attempt := <-h.chain.PublishAttempts:
		t.Fatalf("published without a renewed lease: %v", attempt.TxHash())
	case published := <-h.chain.PublishReq:
		t.Fatalf("published without a renewed lease: %v", published.TxHash())
	case <-time.After(2 * h.leaseRenewalInterval):
	}

	batches, err := h.planter.ListBatches(tapgarden.ListBatchesParams{
		BatchKey: prepared.BatchKey.PubKey,
	})
	require.NoError(t, err)
	require.Len(t, batches, 1)
	require.Contains(
		t, batches[0].CustomAnchorLeaseError,
		"temporary broadcast renewal failure",
	)

	// Recovery first renews the local lease, then retries the exact persisted
	// transaction and clears the queryable degradation.
	h.wallet.SetLeaseError(ownedInput, nil)
	tickerLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *tickerLease)
	published := h.assertTxPublished()
	require.Equal(
		t, (*firstAttempt).WitnessHash(), published.WitnessHash(),
	)
	require.Eventually(t, func() bool {
		batches, err := h.planter.ListBatches(
			tapgarden.ListBatchesParams{
				BatchKey: prepared.BatchKey.PubKey,
			},
		)
		return err == nil && len(batches) == 1 &&
			batches[0].CustomAnchorLeaseError == ""
	}, defaultTimeout, 10*time.Millisecond)
}

// TestIssue721ClassifiedPublishFailureRemainsBroadcast verifies that reject
// classification is diagnostic only after WalletKit sees fully signed bytes.
// The caller may have relayed the transaction independently, so the exact tx
// remains watched/retried in Broadcast and its leases aren't released.
func TestIssue721ClassifiedPublishFailureRemainsBroadcast(t *testing.T) {
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
	ownedInput := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	h.wallet.SetOwnedInput(ownedInput, true)
	issue721Fund(t, h, pkt)
	initialLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *initialLease)
	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)

	signed := clonePacket(t, prepared.GenesisPacket.Pkt)
	signed.Inputs[0].FinalScriptWitness = issue721FinalWitness(
		t, witnessScript,
	)
	signedTx, err := psbt.Extract(signed)
	require.NoError(t, err)

	h.chain.FailPublishDefinitively()
	var wg sync.WaitGroup
	respChan := make(chan *FinalizeBatchResp, 1)
	h.finalizeBatch(&wg, respChan, &tapgarden.FinalizeParams{
		SignedPsbt: signed,
	})
	finalizeLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *finalizeLease)
	_, err = fn.RecvOrTimeout(
		h.wallet.ImportPubKeySignal, defaultTimeout,
	)
	require.NoError(t, err)
	attempt, err := fn.RecvOrTimeout(
		h.chain.PublishAttempts, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, signedTx.WitnessHash(), (*attempt).WitnessHash())

	// Before the byte-identical retry, the Broadcast watcher is installed
	// and the recorded local input lease is renewed.
	_, err = fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
	require.NoError(t, err)
	broadcastLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *broadcastLease)
	published := h.assertTxPublished()
	require.Equal(t, signedTx.WitnessHash(), published.WitnessHash())
	minted := h.assertFinalizeBatch(&wg, respChan, "")
	require.Equal(t, tapgarden.BatchStateBroadcast, minted.State())

	persisted := h.fetchSingleBatch(prepared.BatchKey.PubKey)
	require.Equal(t, tapgarden.BatchStateBroadcast, persisted.State())
	persistedTx, err := psbt.Extract(persisted.GenesisPacket.Pkt)
	require.NoError(t, err)
	require.Equal(t, signedTx.WitnessHash(), persistedTx.WitnessHash())
	h.assertNumCaretakersActive(1)
	_, err = h.planter.CancelBatch()
	require.ErrorContains(t, err, "not cancellable")
	select {
	case released := <-h.wallet.ReleaseInputSignal:
		t.Fatalf("broadcast input lease unexpectedly released: %v", released)
	default:
	}
}

// TestIssue721ImportRetry verifies that a transient wallet import failure is
// observed before publication and before the durable Broadcast transition.
func TestIssue721ImportRetry(t *testing.T) {
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

	h.wallet.SetImportError(fmt.Errorf("temporary import failure"))
	var wg sync.WaitGroup
	respChan := make(chan *FinalizeBatchResp, 1)
	h.finalizeBatch(&wg, respChan, &tapgarden.FinalizeParams{
		SignedPsbt: signed,
	})
	_, err = fn.RecvOrTimeout(
		h.wallet.ImportPubKeySignal, defaultTimeout,
	)
	require.NoError(t, err)
	h.assertFinalizeBatch(&wg, respChan, "temporary import failure")
	select {
	case <-h.chain.PublishAttempts:
		t.Fatal("transaction published before wallet import succeeded")
	default:
	}
	pending, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, tapgarden.BatchStateCommitted, pending.State())
	persisted := h.fetchSingleBatch(pending.BatchKey.PubKey)
	require.Equal(t, tapgarden.BatchStateCommitted, persisted.State())

	h.wallet.SetImportError(nil)
	retry := clonePacket(t, pending.GenesisPacket.Pkt)
	h.finalizeBatch(&wg, respChan, &tapgarden.FinalizeParams{
		SignedPsbt: retry,
	})
	_, err = fn.RecvOrTimeout(
		h.wallet.ImportPubKeySignal, defaultTimeout,
	)
	require.NoError(t, err)
	_, err = fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
	require.NoError(t, err)
	minted := h.assertFinalizeBatch(&wg, respChan, "")
	require.Equal(t, tapgarden.BatchStateBroadcast, minted.State())
}

func TestIssue721ImportRetryAfterRestart(t *testing.T) {
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
	ownedInput := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	h.wallet.SetOwnedInput(ownedInput, true)
	issue721Fund(t, h, pkt)
	initialLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *initialLease)
	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)
	signed := clonePacket(t, prepared.GenesisPacket.Pkt)
	signed.Inputs[0].FinalScriptWitness = issue721FinalWitness(
		t, witnessScript,
	)

	h.wallet.SetImportError(fmt.Errorf("temporary import failure"))
	var wg sync.WaitGroup
	respChan := make(chan *FinalizeBatchResp, 1)
	h.finalizeBatch(&wg, respChan, &tapgarden.FinalizeParams{
		SignedPsbt: signed,
	})
	finalizeLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *finalizeLease)
	_, err = fn.RecvOrTimeout(h.wallet.ImportPubKeySignal, defaultTimeout)
	require.NoError(t, err)
	h.assertFinalizeBatch(&wg, respChan, "temporary import failure")
	select {
	case <-h.chain.PublishAttempts:
		t.Fatal("transaction published before wallet import succeeded")
	default:
	}
	require.Equal(t, tapgarden.BatchStateCommitted,
		h.fetchSingleBatch(prepared.BatchKey.PubKey).State())

	// The signed, pre-publication packet resumes automatically. Import is
	// retried before the first publication attempt after restart.
	h.wallet.SetImportError(nil)
	h.refreshChainPlanter()
	restartLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *restartLease)
	_, err = fn.RecvOrTimeout(h.wallet.ImportPubKeySignal, defaultTimeout)
	require.NoError(t, err)
	_, err = fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
	require.NoError(t, err)
	h.assertNumCaretakersActive(1)
}

// TestIssue721ImportFailureAfterRestartIsAdopted verifies that a recovered
// import-pending caretaker owns the exclusive planter slot and that a second
// import failure returns the batch to a usable pending state instead of
// leaving a dead caretaker registered.
func TestIssue721ImportFailureAfterRestartIsAdopted(t *testing.T) {
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
	ownedInput := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	h.wallet.SetOwnedInput(ownedInput, true)
	issue721Fund(t, h, pkt)
	initialLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *initialLease)
	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)
	signed := clonePacket(t, prepared.GenesisPacket.Pkt)
	signed.Inputs[0].FinalScriptWitness = issue721FinalWitness(
		t, witnessScript,
	)

	// The first import failure durably leaves the signed packet in the
	// import-pending state.
	h.wallet.SetImportError(fmt.Errorf("temporary import failure"))
	var wg sync.WaitGroup
	respChan := make(chan *FinalizeBatchResp, 1)
	h.finalizeBatch(&wg, respChan, &tapgarden.FinalizeParams{
		SignedPsbt: signed,
	})
	finalizeLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *finalizeLease)
	_, err = fn.RecvOrTimeout(h.wallet.ImportPubKeySignal, defaultTimeout)
	require.NoError(t, err)
	h.assertFinalizeBatch(&wg, respChan, "temporary import failure")

	// Restart with the import failure still armed. The owned input is renewed
	// before the resumed caretaker attempts import.
	h.leaseRenewalInterval = 20 * time.Millisecond
	h.refreshChainPlanter()
	restartLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *restartLease)

	// The pending reservation is independent from the caretaker's mutable
	// batch. It remains safe to query, and the periodic renewal loop must not
	// compete with the active recovery caretaker.
	for i := 0; i < 10; i++ {
		reserved, err := h.planter.PendingBatch()
		require.NoError(t, err)
		require.Equal(t, tapgarden.BatchStateCommitted, reserved.State())
		require.Equal(t, prepared.BatchKey.PubKey.SerializeCompressed(),
			reserved.BatchKey.PubKey.SerializeCompressed())
	}
	select {
	case op := <-h.wallet.LeaseInputSignal:
		t.Fatalf("active startup recovery lease renewed by gardener: %v", op)
	case <-time.After(3 * h.leaseRenewalInterval):
	}

	// While the resumed caretaker is blocked on import, the recovered batch
	// occupies the exclusive slot. Mutations are rejected, and Cancel and
	// Finalize return promptly instead of targeting the running caretaker.
	second := issue721Seedling()
	second.AssetName = "issue-721-recovery-second"
	updates, err := h.planter.QueueNewSeedling(second)
	require.NoError(t, err)
	update, err := fn.RecvOrTimeout(updates, defaultTimeout)
	require.NoError(t, err)
	require.ErrorContains(t, update.Error, "cannot accept new seedlings")
	_, err = h.planter.FinalizeBatch(tapgarden.FinalizeParams{
		SignedPsbt: signed,
	})
	require.ErrorContains(t, err, "batch recovery is in progress")
	_, err = h.planter.CancelBatch()
	require.ErrorContains(t, err, "batch recovery is in progress")

	// Let the repeated import fail. The result monitor removes the exited
	// caretaker and retains the same Committed batch for retry.
	_, err = fn.RecvOrTimeout(h.wallet.ImportPubKeySignal, defaultTimeout)
	require.NoError(t, err)
	h.assertNumCaretakersActive(0)
	pending, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, tapgarden.BatchStateCommitted, pending.State())
	require.Equal(t, prepared.BatchKey.PubKey.SerializeCompressed(),
		pending.BatchKey.PubKey.SerializeCompressed())

	// Finalize remains usable after adoption cleanup. Exercise a further
	// failed retry, then cancel and verify the local lease is released.
	h.finalizeBatch(&wg, respChan, &tapgarden.FinalizeParams{
		SignedPsbt: clonePacket(t, pending.GenesisPacket.Pkt),
	})
	retryLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *retryLease)
	_, err = fn.RecvOrTimeout(h.wallet.ImportPubKeySignal, defaultTimeout)
	require.NoError(t, err)
	h.assertFinalizeBatch(&wg, respChan, "temporary import failure")
	h.assertNumCaretakersActive(0)

	batchKey, err := h.planter.CancelBatch()
	require.NoError(t, err)
	require.True(t, batchKey.IsEqual(prepared.BatchKey.PubKey))
	released, err := fn.RecvOrTimeout(
		h.wallet.ReleaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *released)
	cancelled := h.fetchSingleBatch(batchKey)
	require.Equal(t, tapgarden.BatchStateSproutCancelled, cancelled.State())
}

// TestIssue721PublishFailureAfterRestartIsAdopted verifies that a recovered
// publish-pending caretaker remains adopted after a classified backend reject,
// installs its watcher and retries without exposing cancellation or leases.
func TestIssue721PublishFailureAfterRestartIsAdopted(t *testing.T) {
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
	ownedInput := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	h.wallet.SetOwnedInput(ownedInput, true)
	issue721Fund(t, h, pkt)
	initialLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *initialLease)
	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)
	signed := clonePacket(t, prepared.GenesisPacket.Pkt)
	signed.Inputs[0].FinalScriptWitness = issue721FinalWitness(
		t, witnessScript,
	)

	// Simulate a crash after import succeeded and the signed PSBT crossed the
	// durable publication boundary.
	signed.Unknowns = append(signed.Unknowns, &psbt.Unknown{
		Key:   []byte{0xfc, 0x04, 't', 'a', 'p', 'd', 0x02},
		Value: []byte{1},
	})
	funded := prepared.GenesisPacket.FundedPsbt
	funded.Pkt = signed
	err = store.StoreSignedGenesisPsbt(
		t.Context(), prepared.BatchKey.PubKey, &funded,
	)
	require.NoError(t, err)

	h.chain.FailPublishDefinitively()
	h.refreshChainPlanter()
	restartLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *restartLease)

	_, err = h.planter.CancelBatch()
	require.ErrorContains(t, err, "batch recovery is in progress")
	_, err = fn.RecvOrTimeout(h.wallet.ImportPubKeySignal, defaultTimeout)
	require.NoError(t, err)
	preflightLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *preflightLease)
	firstAttempt, err := fn.RecvOrTimeout(
		h.chain.PublishAttempts, defaultTimeout,
	)
	require.NoError(t, err)
	_, err = fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
	require.NoError(t, err)
	retryLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *retryLease)
	published := h.assertTxPublished()
	require.Equal(t, (*firstAttempt).WitnessHash(), published.WitnessHash())
	require.Eventually(t, func() bool {
		return h.fetchSingleBatch(prepared.BatchKey.PubKey).State() ==
			tapgarden.BatchStateBroadcast
	}, defaultTimeout, 10*time.Millisecond)
	h.assertNumCaretakersActive(1)
	select {
	case op := <-h.wallet.ReleaseInputSignal:
		t.Fatalf("lease released after classified rejection: %v", op)
	default:
	}
}

// TestIssue721PublishPendingRestartLeaseFailure verifies that a retained
// publication marker crosses into durable Broadcast and installs its watcher
// even if the local lease can't be reacquired after restart. Active
// publication remains suppressed until renewal later succeeds.
func TestIssue721PublishPendingRestartLeaseFailure(t *testing.T) {
	store := newMintingStore(t)
	h := newMintingTestHarness(t, store)
	h.leaseRenewalInterval = 20 * time.Millisecond
	h.refreshChainPlanter()
	t.Cleanup(func() {
		if h.planter != nil {
			_ = h.planter.Stop()
		}
	})

	h.queueSeedlingsInBatch(false, issue721Seedling())
	pkt, _, witnessScript := issue721Anchor(t)
	ownedInput := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	h.wallet.SetOwnedInput(ownedInput, true)
	issue721Fund(t, h, pkt)
	_, err := fn.RecvOrTimeout(h.wallet.LeaseInputSignal, defaultTimeout)
	require.NoError(t, err)
	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)

	signed := clonePacket(t, prepared.GenesisPacket.Pkt)
	signed.Inputs[0].FinalScriptWitness = issue721FinalWitness(
		t, witnessScript,
	)
	signed.Unknowns = append(signed.Unknowns, &psbt.Unknown{
		Key:   []byte{0xfc, 0x04, 't', 'a', 'p', 'd', 0x02},
		Value: []byte{1},
	})
	funded := prepared.GenesisPacket.FundedPsbt
	funded.Pkt = signed
	require.NoError(t, store.StoreSignedGenesisPsbt(
		t.Context(), prepared.BatchKey.PubKey, &funded,
	))
	expected, err := psbt.Extract(signed)
	require.NoError(t, err)

	h.wallet.SetLeaseError(
		ownedInput, fmt.Errorf("restart lease unavailable"),
	)
	h.refreshChainPlanter()
	_, err = fn.RecvOrTimeout(h.wallet.ImportPubKeySignal, defaultTimeout)
	require.NoError(t, err)
	_, err = fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return h.fetchSingleBatch(prepared.BatchKey.PubKey).State() ==
			tapgarden.BatchStateBroadcast
	}, defaultTimeout, 10*time.Millisecond)

	select {
	case attempt := <-h.chain.PublishAttempts:
		t.Fatalf("publish attempted without restart lease: %v", attempt.TxHash())
	case published := <-h.chain.PublishReq:
		t.Fatalf("published without restart lease: %v", published.TxHash())
	case released := <-h.wallet.ReleaseInputSignal:
		t.Fatalf("publication-pending lease released: %v", released)
	case <-time.After(2 * h.leaseRenewalInterval):
	}
	_, err = h.planter.CancelBatch()
	require.ErrorContains(t, err, "not cancellable")

	batches, err := h.planter.ListBatches(tapgarden.ListBatchesParams{
		BatchKey: prepared.BatchKey.PubKey,
	})
	require.NoError(t, err)
	require.Len(t, batches, 1)
	require.Contains(t, batches[0].CustomAnchorLeaseError,
		"restart lease unavailable")

	h.wallet.SetLeaseError(ownedInput, nil)
	renewed, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *renewed)
	published := h.assertTxPublished()
	require.Equal(t, expected.WitnessHash(), published.WitnessHash())
	require.Eventually(t, func() bool {
		batches, err := h.planter.ListBatches(
			tapgarden.ListBatchesParams{
				BatchKey: prepared.BatchKey.PubKey,
			},
		)
		return err == nil && len(batches) == 1 &&
			batches[0].CustomAnchorLeaseError == ""
	}, defaultTimeout, 10*time.Millisecond)
}

// TestIssue721CorruptLeaseMarkerWatchesWithoutPublishing verifies malformed
// retained lease metadata never becomes an external-only fail-open. A prior
// publication boundary still reaches Broadcast and installs its watcher, but
// no active publication or cancellation is allowed until operator recovery.
func TestIssue721CorruptLeaseMarkerWatchesWithoutPublishing(t *testing.T) {
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
	ownedInput := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	h.wallet.SetOwnedInput(ownedInput, true)
	issue721Fund(t, h, pkt)
	_, err := fn.RecvOrTimeout(h.wallet.LeaseInputSignal, defaultTimeout)
	require.NoError(t, err)
	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)

	signed := clonePacket(t, prepared.GenesisPacket.Pkt)
	signed.Inputs[0].FinalScriptWitness = issue721FinalWitness(
		t, witnessScript,
	)
	for _, unknown := range signed.Unknowns {
		if bytes.Equal(unknown.Key,
			[]byte{0xfc, 0x04, 't', 'a', 'p', 'd', 0x01}) {

			unknown.Value = []byte{1, 1, 0, 0, 0}
		}
	}
	signed.Unknowns = append(signed.Unknowns, &psbt.Unknown{
		Key:   []byte{0xfc, 0x04, 't', 'a', 'p', 'd', 0x02},
		Value: []byte{1},
	})
	funded := prepared.GenesisPacket.FundedPsbt
	funded.Pkt = signed
	require.NoError(t, store.StoreSignedGenesisPsbt(
		t.Context(), prepared.BatchKey.PubKey, &funded,
	))

	h.refreshChainPlanter()
	_, err = fn.RecvOrTimeout(h.wallet.ImportPubKeySignal, defaultTimeout)
	require.NoError(t, err)
	_, err = fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return h.fetchSingleBatch(prepared.BatchKey.PubKey).State() ==
			tapgarden.BatchStateBroadcast
	}, defaultTimeout, 10*time.Millisecond)

	select {
	case leased := <-h.wallet.LeaseInputSignal:
		t.Fatalf("corrupt marker unexpectedly leased input: %v", leased)
	case attempt := <-h.chain.PublishAttempts:
		t.Fatalf("corrupt marker unexpectedly published: %v", attempt.TxHash())
	case published := <-h.chain.PublishReq:
		t.Fatalf("corrupt marker unexpectedly published: %v", published.TxHash())
	case released := <-h.wallet.ReleaseInputSignal:
		t.Fatalf("corrupt marker unexpectedly released input: %v", released)
	case <-time.After(100 * time.Millisecond):
	}

	batches, err := h.planter.ListBatches(tapgarden.ListBatchesParams{
		BatchKey: prepared.BatchKey.PubKey,
	})
	require.NoError(t, err)
	require.Len(t, batches, 1)
	require.Contains(t, batches[0].CustomAnchorLeaseError,
		"invalid custom anchor lease marker")
	_, err = h.planter.CancelBatch()
	require.ErrorContains(t, err, "not cancellable")
}

// TestIssue721RecoveredCaretakerFastConfirmation verifies that confirmation
// completion and the forwarded publication result can arrive in either order
// without leaving the startup recovery reservation behind.
func TestIssue721RecoveredCaretakerFastConfirmation(t *testing.T) {
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
	signed.Unknowns = append(signed.Unknowns, &psbt.Unknown{
		Key:   []byte{0xfc, 0x04, 't', 'a', 'p', 'd', 0x02},
		Value: []byte{1},
	})
	funded := prepared.GenesisPacket.FundedPsbt
	funded.Pkt = signed
	err = store.StoreSignedGenesisPsbt(
		t.Context(), prepared.BatchKey.PubKey, &funded,
	)
	require.NoError(t, err)

	h.refreshChainPlanter()
	_, err = fn.RecvOrTimeout(h.wallet.ImportPubKeySignal, defaultTimeout)
	require.NoError(t, err)
	published, err := psbt.Extract(signed)
	require.NoError(t, err)

	// A single-transaction block has the transaction ID as its merkle root.
	merkleRoot := published.TxHash()
	blockHeader := wire.NewBlockHeader(
		0, &chainhash.Hash{}, &merkleRoot, 0, 0,
	)
	block := &wire.MsgBlock{
		Header:       *blockHeader,
		Transactions: []*wire.MsgTx{published},
	}
	notify := h.assertConfReqSent(published, block)
	notify()

	h.assertNumCaretakersActive(0)
	pending, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Nil(t, pending)

	// The cleared recovery reservation permits the next batch immediately.
	second := issue721Seedling()
	second.AssetName = "issue-721-after-fast-confirmation"
	h.queueSeedlingsInBatch(false, second)
}

// TestIssue721CaretakerCancelReleasesAfterDurableState verifies the caretaker
// path never releases a custom input lease until the sprout cancellation has
// been committed. Once durable, lease release is best effort and cancellation
// remains terminal.
func TestIssue721CaretakerCancelReleasesAfterDurableState(t *testing.T) {
	store := &issue721FailStateStore{MintingStore: newMintingStore(t)}
	h := newMintingTestHarness(t, store)
	h.refreshChainPlanter()
	t.Cleanup(func() {
		if h.planter != nil {
			_ = h.planter.Stop()
		}
	})

	h.queueSeedlingsInBatch(false, issue721Seedling())
	pkt, _, _ := issue721Anchor(t)
	ownedInput := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	h.wallet.SetOwnedInput(ownedInput, true)
	issue721Fund(t, h, pkt)
	leased, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *leased)
	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)

	newCaretaker := func() *tapgarden.BatchCaretaker {
		return tapgarden.NewBatchCaretaker(&tapgarden.BatchCaretakerConfig{
			Batch: prepared,
			GardenKit: tapgarden.GardenKit{
				Wallet: h.wallet,
				Log:    store,
			},
			CancelRespChan: make(chan tapgarden.CancelResp, 1),
			PublishMintEvent: func(fn.Event) {
			},
		})
	}

	store.fail = true
	require.NoError(t, newCaretaker().Cancel())
	select {
	case op := <-h.wallet.ReleaseInputSignal:
		t.Fatalf("lease released before durable cancellation: %v", op)
	default:
	}
	persisted := h.fetchSingleBatch(prepared.BatchKey.PubKey)
	require.Equal(t, tapgarden.BatchStateCommitted, persisted.State())

	store.fail = false
	require.NoError(t, newCaretaker().Cancel())
	released, err := fn.RecvOrTimeout(
		h.wallet.ReleaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *released)
	persisted = h.fetchSingleBatch(prepared.BatchKey.PubKey)
	require.Equal(t, tapgarden.BatchStateSproutCancelled, persisted.State())
}

func TestIssue721ImportRestartLeaseFailurePauses(t *testing.T) {
	store := newMintingStore(t)
	h := newMintingTestHarness(t, store)
	h.leaseRenewalInterval = 20 * time.Millisecond
	h.refreshChainPlanter()
	t.Cleanup(func() {
		if h.planter != nil {
			_ = h.planter.Stop()
		}
	})

	h.queueSeedlingsInBatch(false, issue721Seedling())
	pkt, _, witnessScript := issue721Anchor(t)
	op := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	h.wallet.SetOwnedInput(op, true)
	issue721Fund(t, h, pkt)
	<-h.wallet.LeaseInputSignal
	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)
	signed := clonePacket(t, prepared.GenesisPacket.Pkt)
	signed.Inputs[0].FinalScriptWitness = issue721FinalWitness(
		t, witnessScript,
	)

	h.wallet.SetImportError(fmt.Errorf("temporary import failure"))
	var wg sync.WaitGroup
	respChan := make(chan *FinalizeBatchResp, 1)
	h.finalizeBatch(&wg, respChan, &tapgarden.FinalizeParams{
		SignedPsbt: signed,
	})
	<-h.wallet.LeaseInputSignal
	_, err = fn.RecvOrTimeout(h.wallet.ImportPubKeySignal, defaultTimeout)
	require.NoError(t, err)
	h.assertFinalizeBatch(&wg, respChan, "temporary import failure")

	h.wallet.SetImportError(nil)
	h.wallet.SetLeaseError(op, fmt.Errorf("lease no longer available"))
	h.refreshChainPlanter()
	pending, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, tapgarden.BatchStateCommitted, pending.State())
	h.assertNumCaretakersActive(0)
	batches, err := h.planter.ListBatches(tapgarden.ListBatchesParams{
		BatchKey: prepared.BatchKey.PubKey,
	})
	require.NoError(t, err)
	require.Len(t, batches, 1)
	require.Contains(
		t, batches[0].CustomAnchorLeaseError, "lease no longer available",
	)
	select {
	case <-h.wallet.ImportPubKeySignal:
		t.Fatal("wallet output imported after lease renewal failure")
	case <-h.chain.PublishAttempts:
		t.Fatal("transaction published after lease renewal failure")
	default:
	}

	h.wallet.SetLeaseError(op, nil)
	renewed, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, op, *renewed)
	require.Eventually(t, func() bool {
		batches, err := h.planter.ListBatches(
			tapgarden.ListBatchesParams{
				BatchKey: prepared.BatchKey.PubKey,
			},
		)
		return err == nil && len(batches) == 1 &&
			batches[0].CustomAnchorLeaseError == ""
	}, defaultTimeout, 10*time.Millisecond)
	_, err = h.planter.CancelBatch()
	require.NoError(t, err)
}

// TestIssue721RetryStoreFailureIsAtomic ensures signed packet and import marker
// updates never alias the prepared packet before the store commits.
func TestIssue721RetryStoreFailureIsAtomic(t *testing.T) {
	store := &issue721FailSignedStore{MintingStore: newMintingStore(t)}
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

	before, err := h.planter.PendingBatch()
	require.NoError(t, err)
	beforeBytes := serializePacket(t, before.GenesisPacket.Pkt)
	store.fail = true
	var wg sync.WaitGroup
	respChan := make(chan *FinalizeBatchResp, 1)
	h.finalizeBatch(&wg, respChan, &tapgarden.FinalizeParams{
		SignedPsbt: signed,
	})
	h.assertFinalizeBatch(
		&wg, respChan, "injected signed PSBT store failure",
	)
	after, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, beforeBytes, serializePacket(t, after.GenesisPacket.Pkt))
	require.Equal(t, tapgarden.BatchStateCommitted, after.State())
	select {
	case <-h.wallet.ImportPubKeySignal:
		t.Fatal("wallet import attempted after signed packet store failure")
	case <-h.chain.PublishAttempts:
		t.Fatal("publication attempted after signed packet store failure")
	default:
	}

	store.fail = false
	_, err = h.planter.CancelBatch()
	require.NoError(t, err)
}

// TestIssue721MixedInputLeaseLifecycle pins ownership-aware leasing: local
// inputs are leased, persisted and released, while external inputs and all
// caller-authored transaction/PSBT fields remain untouched.
func TestIssue721MixedInputLeaseLifecycle(t *testing.T) {
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
	local := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	var externalHash chainhash.Hash
	copy(externalHash[:], bytes.Repeat([]byte{8}, 32))
	external := wire.OutPoint{Hash: externalHash, Index: 3}
	pkt.UnsignedTx.AddTxIn(&wire.TxIn{PreviousOutPoint: external})
	pkt.Inputs = append(pkt.Inputs, psbt.PInput{
		WitnessUtxo: &wire.TxOut{
			Value: 5_000, PkScript: pkt.Inputs[0].WitnessUtxo.PkScript,
		},
		WitnessScript: pkt.Inputs[0].WitnessScript,
		SighashType:   txscript.SigHashAll,
		Unknowns: []*psbt.Unknown{{
			Key: []byte{0x54}, Value: []byte("external-input"),
		}},
	})
	original := clonePacket(t, pkt)
	h.wallet.SetOwnedInput(local, true)

	funded := issue721Fund(t, h, pkt)
	leased, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, local, *leased)
	require.Equal(t, []wire.OutPoint{local},
		funded.GenesisPacket.LockedUTXOs)
	require.Equal(t, original.UnsignedTx, funded.GenesisPacket.Pkt.UnsignedTx)
	require.Equal(t, original.Inputs, funded.GenesisPacket.Pkt.Inputs)
	require.Equal(t, original.Outputs, funded.GenesisPacket.Pkt.Outputs)
	require.Equal(t, original.Unknowns[0], funded.GenesisPacket.Pkt.Unknowns[0])

	h.refreshChainPlanter()
	renewed, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, local, *renewed)
	restored, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, []wire.OutPoint{local},
		restored.GenesisPacket.LockedUTXOs)

	_, err = h.planter.CancelBatch()
	require.NoError(t, err)
	released, err := fn.RecvOrTimeout(
		h.wallet.ReleaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, local, *released)
	select {
	case op := <-h.wallet.ReleaseInputSignal:
		t.Fatalf("external input unexpectedly released: %v", op)
	default:
	}
}

func TestIssue721PeriodicLeaseRenewal(t *testing.T) {
	store := newMintingStore(t)
	h := newMintingTestHarness(t, store)
	h.leaseRenewalInterval = 20 * time.Millisecond
	h.refreshChainPlanter()
	t.Cleanup(func() { _ = h.planter.Stop() })

	h.queueSeedlingsInBatch(false, issue721Seedling())
	pkt, _, _ := issue721Anchor(t)
	op := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	h.wallet.SetOwnedInput(op, true)
	issue721Fund(t, h, pkt)
	initial, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, op, *initial)
	h.wallet.SetLeaseError(op, fmt.Errorf("temporary renewal degradation"))
	require.Eventually(t, func() bool {
		pending, err := h.planter.PendingBatch()
		return err == nil && pending.CustomAnchorLeaseError != ""
	}, defaultTimeout, 10*time.Millisecond)

	// Status is queryable after the one-shot event and clears after a later
	// successful renewal, so late RPC clients don't depend on event replay.
	h.wallet.SetLeaseError(op, nil)
	renewed, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, op, *renewed)
	require.Eventually(t, func() bool {
		pending, err := h.planter.PendingBatch()
		return err == nil && pending.CustomAnchorLeaseError == ""
	}, defaultTimeout, 10*time.Millisecond)

	_, err = h.planter.CancelBatch()
	require.NoError(t, err)
}

// TestIssue721LeaseRenewalDoesNotBlockShutdown verifies that a slow lease
// renewal cannot wedge the gardener during shutdown. The wallet mock's signal
// channel models an RPC whose result consumer is temporarily unavailable.
func TestIssue721LeaseRenewalDoesNotBlockShutdown(t *testing.T) {
	store := newMintingStore(t)
	h := newMintingTestHarness(t, store)
	h.leaseRenewalInterval = time.Millisecond
	h.refreshChainPlanter()

	h.queueSeedlingsInBatch(false, issue721Seedling())
	pkt, _, _ := issue721Anchor(t)
	op := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	h.wallet.SetOwnedInput(op, true)
	issue721Fund(t, h, pkt)

	// Leave the lease notifications unread until the buffered mock RPC
	// blocks. Stop closes the planter context, which must release the call
	// and let the gardener exit promptly.
	require.Eventually(t, func() bool {
		return len(h.wallet.LeaseInputSignal) ==
			cap(h.wallet.LeaseInputSignal)
	}, defaultTimeout, time.Millisecond)

	stopResult := make(chan error, 1)
	go func() {
		stopResult <- h.planter.Stop()
	}()

	select {
	case err := <-stopResult:
		require.NoError(t, err)

	case <-time.After(defaultTimeout):
		t.Fatal("planter shutdown blocked on custom anchor lease renewal")
	}
}

func TestIssue721LeaseFailureAndCancelReleaseOrdering(t *testing.T) {
	t.Run("lease conflict rolls back funding", func(t *testing.T) {
		store := newMintingStore(t)
		h := newMintingTestHarness(t, store)
		h.refreshChainPlanter()
		t.Cleanup(func() { _ = h.planter.Stop() })

		h.queueSeedlingsInBatch(false, issue721Seedling())
		pkt, _, _ := issue721Anchor(t)
		anchorPriv, _ := btcec.PrivKeyFromBytes(
			bytes.Repeat([]byte{7}, 32),
		)
		h.keyRing.Keys[keychain.KeyLocator{
			Family: asset.TaprootAssetsKeyFamily, Index: 721,
		}] = anchorPriv
		h.keyRing.On(
			"IsLocalKey", mock.Anything, mock.Anything,
		).Maybe()
		first := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
		var secondHash chainhash.Hash
		copy(secondHash[:], bytes.Repeat([]byte{6}, 32))
		second := wire.OutPoint{Hash: secondHash, Index: 6}
		pkt.UnsignedTx.AddTxIn(&wire.TxIn{PreviousOutPoint: second})
		pkt.Inputs = append(pkt.Inputs, psbt.PInput{
			WitnessUtxo: &wire.TxOut{
				Value: 5_000, PkScript: pkt.Inputs[0].WitnessUtxo.PkScript,
			},
			WitnessScript: pkt.Inputs[0].WitnessScript,
		})
		h.wallet.SetOwnedInput(first, true)
		h.wallet.SetOwnedInput(second, true)
		h.wallet.SetLeaseError(second, fmt.Errorf("foreign lease conflict"))
		original := serializePacket(t, pkt)
		_, err := h.planter.FundBatch(tapgarden.FundParams{
			AnchorPsbt: pkt, AssetAnchorOutIdx: 1,
			ChangeOutputIndex: -1,
			FeeRate:           fn.None[chainfee.SatPerKWeight](),
			SiblingTapTree:    fn.None[asset.TapscriptTreeNodes](),
		})
		require.ErrorContains(t, err, "foreign lease conflict")
		require.Equal(t, first, <-h.wallet.LeaseInputSignal)
		require.Equal(t, first, <-h.wallet.ReleaseInputSignal)
		require.Equal(t, original, serializePacket(t, pkt))
		pending, err := h.planter.PendingBatch()
		require.NoError(t, err)
		require.Nil(t, pending.GenesisPacket)
	})

	t.Run("durable cancel attempts every local release", func(t *testing.T) {
		store := newMintingStore(t)
		h := newMintingTestHarness(t, store)
		h.refreshChainPlanter()
		t.Cleanup(func() { _ = h.planter.Stop() })

		h.queueSeedlingsInBatch(false, issue721Seedling())
		pkt, _, _ := issue721Anchor(t)
		first := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
		var secondHash chainhash.Hash
		copy(secondHash[:], bytes.Repeat([]byte{9}, 32))
		second := wire.OutPoint{Hash: secondHash, Index: 4}
		pkt.UnsignedTx.AddTxIn(&wire.TxIn{PreviousOutPoint: second})
		pkt.Inputs = append(pkt.Inputs, psbt.PInput{
			WitnessUtxo: &wire.TxOut{
				Value: 5_000, PkScript: pkt.Inputs[0].WitnessUtxo.PkScript,
			},
			WitnessScript: pkt.Inputs[0].WitnessScript,
		})
		h.wallet.SetOwnedInput(first, true)
		h.wallet.SetOwnedInput(second, true)
		issue721Fund(t, h, pkt)
		<-h.wallet.LeaseInputSignal
		<-h.wallet.LeaseInputSignal
		h.wallet.SetReleaseError(second, fmt.Errorf("release failed"))

		batchKey, err := h.planter.CancelBatch()
		require.NoError(t, err)
		require.Equal(t, first, <-h.wallet.ReleaseInputSignal)
		require.Equal(t, second, <-h.wallet.ReleaseInputSignal)
		cancelled := h.fetchSingleBatch(batchKey)
		require.Equal(t, tapgarden.BatchStateSeedlingCancelled,
			cancelled.State())
	})
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
	h.assertFinalizeBatch(
		&wg, respChan, "failed to register confirmation",
	)

	pending, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, tapgarden.BatchStateBroadcast, pending.State())
	published, err := psbt.Extract(pending.GenesisPacket.Pkt)
	require.NoError(t, err)
	changedRetry := clonePacket(t, pending.GenesisPacket.Pkt)
	changedRetry.Inputs[0].FinalScriptWitness =
		issue721FinalWitnessWithItem(
			t, bytes.Repeat([]byte{0x02}, 500), witnessScript,
		)
	changedTx, err := psbt.Extract(changedRetry)
	require.NoError(t, err)
	require.Equal(t, published.TxHash(), changedTx.TxHash())
	require.NotEqual(t, published.WitnessHash(), changedTx.WitnessHash())
	_, err = h.planter.FinalizeBatch(tapgarden.FinalizeParams{
		SignedPsbt: changedRetry,
	})
	require.ErrorContains(
		t, err, "broadcast retry changes finalized transaction",
	)

	retry := clonePacket(t, pending.GenesisPacket.Pkt)
	h.finalizeBatch(&wg, respChan, &tapgarden.FinalizeParams{
		SignedPsbt: retry,
	})
	_, err = fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
	require.NoError(t, err)
	h.assertTxPublished()
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
					t.Context(), batch, state,
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

	t.Run("committed publication attempt resumes", func(t *testing.T) {
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
		// This proprietary marker is the durable boundary written before
		// the publication RPC. A crash at that point must resume rather
		// than expose a cancellable signed transaction.
		signed.Unknowns = append(signed.Unknowns, &psbt.Unknown{
			Key:   []byte{0xfc, 0x04, 't', 'a', 'p', 'd', 0x02},
			Value: []byte{1},
		})
		funded := prepared.GenesisPacket.FundedPsbt
		funded.Pkt = signed
		err = store.StoreSignedGenesisPsbt(
			t.Context(), prepared.BatchKey.PubKey, &funded,
		)
		require.NoError(t, err)

		h.refreshChainPlanter()
		_, err = fn.RecvOrTimeout(
			h.wallet.ImportPubKeySignal, defaultTimeout,
		)
		require.NoError(t, err)
		_, err = fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
		require.NoError(t, err)
		h.assertNumCaretakersActive(1)
	})

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

func TestIssue721LegacyRawOnlyPreflightIsNonMutating(t *testing.T) {
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
			legacy := batch.GenesisPacket.Copy()
			legacy.Pkt.Outputs[1].Bip32Derivation = nil
			legacy.Pkt.Outputs[1].TaprootBip32Derivation = nil
			require.NoError(t, store.CommitBatchFunding(
				t.Context(), batch.BatchKey.PubKey, nil, *legacy,
			))
			if state == tapgarden.BatchStateFrozen {
				require.NoError(t, store.UpdateBatchState(
					t.Context(), batch, state,
				))
			}

			h.refreshChainPlanter()
			before, err := h.planter.PendingBatch()
			require.NoError(t, err)
			beforeBytes := serializePacket(t, before.GenesisPacket.Pkt)
			_, err = h.planter.PrepareBatch()
			require.ErrorIs(
				t, err, tapgarden.ErrLegacyCustomAnchorKeyLocator,
			)

			after, err := h.planter.PendingBatch()
			require.NoError(t, err)
			require.Equal(t, state, after.State())
			require.Equal(t, beforeBytes,
				serializePacket(t, after.GenesisPacket.Pkt))
			persisted := h.fetchSingleBatch(batch.BatchKey.PubKey)
			require.Equal(t, state, persisted.State())
			require.Equal(t, beforeBytes,
				serializePacket(t, persisted.GenesisPacket.Pkt))
		})
	}
}

func TestIssue721LegacyRawOnlyFinalizeRemainsCancellable(t *testing.T) {
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

	legacy := prepared.GenesisPacket.Copy()
	legacy.Pkt.Outputs[1].Bip32Derivation = nil
	legacy.Pkt.Outputs[1].TaprootInternalKey =
		fn.CopySlice(pkt.Outputs[1].TaprootInternalKey)
	require.NoError(t, store.StoreSignedGenesisPsbt(
		t.Context(), prepared.BatchKey.PubKey, &legacy.FundedPsbt,
	))
	h.refreshChainPlanter()

	pending, err := h.planter.PendingBatch()
	require.NoError(t, err)
	before := serializePacket(t, pending.GenesisPacket.Pkt)
	signed := clonePacket(t, pending.GenesisPacket.Pkt)
	signed.Inputs[0].FinalScriptWitness = issue721FinalWitness(
		t, witnessScript,
	)
	_, err = h.planter.FinalizeBatch(tapgarden.FinalizeParams{
		SignedPsbt: signed,
	})
	require.ErrorIs(t, err, tapgarden.ErrLegacyCustomAnchorKeyLocator)

	after, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Equal(t, tapgarden.BatchStateCommitted, after.State())
	require.Equal(t, before, serializePacket(t, after.GenesisPacket.Pkt))
	select {
	case <-h.wallet.ImportPubKeySignal:
		t.Fatal("legacy raw-only batch imported before key preflight")
	case <-h.chain.PublishAttempts:
		t.Fatal("legacy raw-only batch published before key preflight")
	default:
	}
	_, err = h.planter.CancelBatch()
	require.NoError(t, err)
}

func TestIssue721LegacyRejectedMarkerIsPublicationPending(t *testing.T) {
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
	ownedInput := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	h.wallet.SetOwnedInput(ownedInput, true)
	issue721Fund(t, h, pkt)
	_, err := fn.RecvOrTimeout(h.wallet.LeaseInputSignal, defaultTimeout)
	require.NoError(t, err)
	prepared, err := h.planter.PrepareBatch()
	require.NoError(t, err)

	signed := clonePacket(t, prepared.GenesisPacket.Pkt)
	signed.Inputs[0].FinalScriptWitness = issue721FinalWitness(
		t, witnessScript,
	)
	signed.Unknowns = append(signed.Unknowns, &psbt.Unknown{
		Key:   []byte{0xfc, 0x04, 't', 'a', 'p', 'd', 0x02},
		Value: []byte{2}, // Historical customAnchorPublishRejected.
	})
	funded := prepared.GenesisPacket.FundedPsbt
	funded.Pkt = signed
	require.NoError(t, store.StoreSignedGenesisPsbt(
		t.Context(), prepared.BatchKey.PubKey, &funded,
	))

	// The historical build already attempted these fully signed bytes. On
	// restart, treat them as ambiguous: retain the lease, deny cancellation,
	// install a watcher and retry the identical transaction.
	h.chain.FailPublishOnce()
	h.refreshChainPlanter()
	startupLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *startupLease)
	_, err = h.planter.CancelBatch()
	require.ErrorContains(t, err, "batch recovery is in progress")
	_, err = fn.RecvOrTimeout(h.wallet.ImportPubKeySignal, defaultTimeout)
	require.NoError(t, err)
	preflightLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *preflightLease)
	firstAttempt, err := fn.RecvOrTimeout(
		h.chain.PublishAttempts, defaultTimeout,
	)
	require.NoError(t, err)
	_, err = fn.RecvOrTimeout(h.chain.ConfReqSignal, defaultTimeout)
	require.NoError(t, err)
	retryLease, err := fn.RecvOrTimeout(
		h.wallet.LeaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *retryLease)
	published := h.assertTxPublished()
	require.Equal(t, (*firstAttempt).WitnessHash(), published.WitnessHash())
	require.Eventually(t, func() bool {
		return h.fetchSingleBatch(prepared.BatchKey.PubKey).State() ==
			tapgarden.BatchStateBroadcast
	}, defaultTimeout, 10*time.Millisecond)
	select {
	case released := <-h.wallet.ReleaseInputSignal:
		t.Fatalf("legacy rejected-marker lease released: %v", released)
	default:
	}
}

func clonePacket(t *testing.T, pkt *psbt.Packet) *psbt.Packet {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, pkt.Serialize(&buf))
	clone, err := psbt.NewFromRawBytes(&buf, false)
	require.NoError(t, err)

	return clone
}

func serializePacket(t *testing.T, pkt *psbt.Packet) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, pkt.Serialize(&buf))
	return buf.Bytes()
}
