//nolint:lll
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
	testMintingStore
	fail                  bool
	failCommit            bool
	commitAttempted       bool
	commitLockedOutpoints []wire.OutPoint
}

func (s *issue721FailSignedStore) CommitSignedGenesisTxWithKey(
	ctx context.Context, batch *tapgarden.MintingBatch,
	mintingInternalKey keychain.KeyDescriptor,
	genesisTx *tapsend.FundedPsbt, anchorOutputIndex uint32,
	merkleRoot, tapTreeRoot, tapSibling []byte) error {

	s.commitAttempted = true
	s.commitLockedOutpoints = fn.CopySlice(genesisTx.LockedUTXOs)
	if s.failCommit {
		return fmt.Errorf("injected signed genesis commit failure")
	}

	keyStore, ok := s.testMintingStore.(tapgarden.MintingInternalKeyStore)
	if !ok {
		return fmt.Errorf("minting store does not support internal keys")
	}

	return keyStore.CommitSignedGenesisTxWithKey(
		ctx, batch, mintingInternalKey, genesisTx, anchorOutputIndex,
		merkleRoot, tapTreeRoot, tapSibling,
	)
}

type issue721FailStateStore struct {
	testMintingStore
	fail bool
}

type issue721TimeoutFundingStore struct {
	testMintingStore
}

func (s *issue721TimeoutFundingStore) CommitBatchFunding(ctx context.Context,
	_ *tapgarden.MintingBatch, _ *chainhash.Hash,
	_ tapgarden.FundedMintAnchorPsbt,
	_ fn.Option[tapgarden.PreCommitBindData]) error {

	<-ctx.Done()
	return ctx.Err()
}

func (s *issue721FailStateStore) UpdateBatchState(ctx context.Context,
	batch *tapgarden.MintingBatch, state tapgarden.BatchState) error {

	if s.fail && state == tapgarden.BatchStateSproutCancelled {
		return fmt.Errorf("injected cancellation store failure")
	}

	return s.testMintingStore.UpdateBatchState(ctx, batch, state)
}

func (s *issue721FailSignedStore) StoreSignedGenesisPsbt(ctx context.Context,
	batchKey *btcec.PublicKey, funded *tapsend.FundedPsbt) error {

	if s.fail {
		return fmt.Errorf("injected signed PSBT store failure")
	}

	signedStore, ok := s.testMintingStore.(tapgarden.SignedGenesisPsbtStore)
	if !ok {
		return fmt.Errorf("minting store does not support signed PSBT persistence")
	}

	return signedStore.StoreSignedGenesisPsbt(ctx, batchKey, funded)
}

func issue721SignedStore(t *testing.T,
	store tapgarden.BatchStore) tapgarden.SignedGenesisPsbtStore {

	t.Helper()
	signedStore, ok := store.(tapgarden.SignedGenesisPsbtStore)
	require.True(t, ok, "test minting store must persist signed PSBTs")

	return signedStore
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

	batch, err := resp.ToMintingBatch()
	require.NoError(t, err)
	return batch
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
	h.assertNumCultivatorsActive(0)
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
	published, err := psbt.Extract(valid)
	require.NoError(t, err)
	h.assertAnchoringRegistered(published)
	anchorings, err := h.registrar.AllAnchorings(
		context.Background(), tapgarden.MintSiteID,
	)
	require.NoError(t, err)
	require.Len(t, anchorings, 1)
	points := anchorings[0].Triggers.OutPoints()
	require.Len(t, points, len(published.TxIn))
	require.Equal(t, published.TxIn[0].PreviousOutPoint, points[0].OutPoint)
	require.Equal(
		t, valid.Inputs[0].WitnessUtxo.PkScript, points[0].PkScript,
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
	available, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Nil(t, available)

	// A clean WalletKit acceptance clears the internal publication marker
	// before the signed packet is committed in Broadcast.
	persisted := h.fetchSingleBatch(prepared.BatchKey.PubKey)
	require.Equal(t, uint32(1), persisted.GenesisPacket.AssetAnchorOutIdx)
	for _, unknown := range persisted.GenesisPacket.Pkt.Unknowns {
		require.NotEqual(
			t, []byte{0xfc, 0x04, 't', 'a', 'p', 'd', 0x02},
			unknown.Key,
		)
	}
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

	// Registration returns only after release, so the lease failure is
	// visible to the Broadcast retry that follows it. The anchoring is
	// already stored when entered fires.
	entered, release := h.registrar.PauseNextRegister()
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
	select {
	case <-entered:
	case <-time.After(defaultTimeout):
		t.Fatal("mint anchoring was not registered before publish")
	}
	release()
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
	h.assertAnchoringRegistered(*firstAttempt)
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
func TestIssue721CaretakerCancelReleasesAfterDurableState(t *testing.T) {
	store := &issue721FailStateStore{testMintingStore: newMintingStore(t)}
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

	newCultivator := func() *tapgarden.Cultivator {
		return tapgarden.NewCultivator(&tapgarden.CultivatorConfig{
			Batch: prepared,
			GardenKit: &tapgarden.GardenKit{
				Wallet:     h.wallet,
				BatchStore: store,
			},
			PublishMintEvent: func(fn.Event) {
			},
		})
	}

	store.fail = true
	require.NoError(t, newCultivator().Cancel(
		make(chan tapgarden.CancelResp, 1),
	))
	select {
	case op := <-h.wallet.ReleaseInputSignal:
		t.Fatalf("lease released before durable cancellation: %v", op)
	default:
	}
	persisted := h.fetchSingleBatch(prepared.BatchKey.PubKey)
	require.Equal(t, tapgarden.BatchStateCommitted, persisted.State())

	store.fail = false
	require.NoError(t, newCultivator().Cancel(
		make(chan tapgarden.CancelResp, 1),
	))
	released, err := fn.RecvOrTimeout(
		h.wallet.ReleaseInputSignal, defaultTimeout,
	)
	require.NoError(t, err)
	require.Equal(t, ownedInput, *released)
	persisted = h.fetchSingleBatch(prepared.BatchKey.PubKey)
	require.Equal(t, tapgarden.BatchStateSproutCancelled, persisted.State())
}

func TestIssue721RetryStoreFailureIsAtomic(t *testing.T) {
	store := &issue721FailSignedStore{testMintingStore: newMintingStore(t)}
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
	require.ErrorContains(t, err, "not cancellable")
}

// TestIssue721PublishSuccessCommitFailureRetainsReservation verifies that a
// successful WalletKit submission cannot make the live Committed packet appear
// cancellable before its Broadcast transition is durable.
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

func TestIssue721PersistenceTimeoutRollsBackLease(t *testing.T) {
	store := &issue721TimeoutFundingStore{
		testMintingStore: newMintingStore(t),
	}
	h := newMintingTestHarness(t, store)
	h.refreshChainPlanter()
	t.Cleanup(func() { _ = h.planter.Stop() })

	h.queueSeedlingsInBatch(false, issue721Seedling())
	h.planter.DefaultTimeout = 50 * time.Millisecond
	pkt, _, _ := issue721Anchor(t)
	op := pkt.UnsignedTx.TxIn[0].PreviousOutPoint
	h.wallet.SetOwnedInput(op, true)
	anchorPriv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{7}, 32))
	h.keyRing.Keys[keychain.KeyLocator{
		Family: asset.TaprootAssetsKeyFamily,
		Index:  721,
	}] = anchorPriv
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
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, op, <-h.wallet.LeaseInputSignal)
	select {
	case released := <-h.wallet.ReleaseInputSignal:
		require.Equal(t, op, released)

	case <-time.After(time.Second):
		t.Fatal("persistence timeout did not roll back acquired lease")
	}
	select {
	case unlocked := <-h.wallet.UnlockInputSignal:
		t.Fatalf("custom input used wallet-funded unlock path: %v",
			unlocked)
	default:
	}

	pending, err := h.planter.PendingBatch()
	require.NoError(t, err)
	require.Nil(t, pending.GenesisPacket)
}

// TestIssue721ConfirmationRegistrationRetry ensures a successful publish
// followed by a transient notifier error remains retryable in the same process.
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
	_, err := h.planter.PrepareBatch()
	require.NoError(t, err)

	_, err = h.planter.CancelBatch()
	require.ErrorContains(t, err, "not cancellable")
}

// TestIssue721LowFeeRejectsBeforeBroadcast verifies a caller-authored
// transaction that cannot meet the node's minimum relay fee remains in the
// prepared state without advancing to broadcast.
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
	h.assertNumCultivatorsActive(0)

	_, err = h.planter.CancelBatch()
	require.ErrorContains(t, err, "not cancellable")
	require.Equal(t, tapgarden.BatchStateCommitted, pending.State())
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
			h.assertNumCultivatorsActive(0)
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
		err = issue721SignedStore(t, store).StoreSignedGenesisPsbt(
			t.Context(), prepared.BatchKey.PubKey, &funded,
		)
		require.NoError(t, err)

		h.refreshChainPlanter()
		_, err = fn.RecvOrTimeout(
			h.wallet.ImportPubKeySignal, defaultTimeout,
		)
		require.NoError(t, err)
		resumed, err := psbt.Extract(signed)
		require.NoError(t, err)
		h.assertAnchoringRegistered(resumed)
		h.assertNumCultivatorsActive(1)
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
		h.assertNumCultivatorsActive(1)
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

func serializePacket(t *testing.T, pkt *psbt.Packet) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, pkt.Serialize(&buf))
	return buf.Bytes()
}
