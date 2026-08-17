package proof

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/vm"
	"github.com/stretchr/testify/require"
)

func genTaprootKeySpend(t testing.TB, privKey btcec.PrivateKey,
	virtualTx *wire.MsgTx, input, newAsset *asset.Asset,
	idx uint32) wire.TxWitness {

	t.Helper()

	virtualTxCopy := asset.VirtualTxWithInput(
		virtualTx, newAsset.LockTime, newAsset.RelativeLockTime, idx,
		nil,
	)
	sigHash, err := tapscript.InputKeySpendSigHash(
		virtualTxCopy, input, newAsset, idx, txscript.SigHashDefault,
	)
	require.NoError(t, err)

	taprootPrivKey := txscript.TweakTaprootPrivKey(privKey, nil)
	sig, err := schnorr.Sign(taprootPrivKey, sigHash)
	require.NoError(t, err)

	return wire.TxWitness{sig.Serialize()}
}

// TestAppendTransition tests that a proof can be appended to an existing proof
// for an asset transition.
func TestAppendTransition(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		assetType       asset.Type
		amt             uint64
		withBip86Change bool
		withSplit       bool
		assetVersion    asset.Version
	}{
		{
			name:      "normal",
			assetType: asset.Normal,
			amt:       100,
		},
		{
			name:         "normal v1 asset version",
			assetType:    asset.Normal,
			amt:          100,
			assetVersion: asset.V1,
		},
		{
			name:            "normal with change",
			assetType:       asset.Normal,
			amt:             100,
			withBip86Change: true,
		},
		{
			name:      "normal with change (with split)",
			assetType: asset.Normal,
			amt:       100,
			withSplit: true,
		},
		{
			name:      "collectible",
			assetType: asset.Collectible,
			amt:       1,
		},
		{
			name:         "collectible v1 asset version",
			assetType:    asset.Collectible,
			amt:          1,
			assetVersion: asset.V1,
		},
		{
			name:            "collectible with change",
			assetType:       asset.Collectible,
			amt:             1,
			withBip86Change: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			runAppendTransitionTest(
				tt, tc.assetType, tc.amt, tc.withBip86Change,
				tc.withSplit, tc.assetVersion,
			)
		})
	}
}

// TestFinalProofSkipTimeLockCLTV ensures time lock validation is skipped for
// the final proof when a CLTV locktime is present.
func TestFinalProofSkipTimeLockCLTV(t *testing.T) {
	t.Parallel()

	f := buildTransitionProofFile(t, 500, 0)

	_, err := f.Verify(context.Background(), MockVerifierCtx)
	require.Error(t, err)
	var vmErr vm.Error
	require.True(t, errors.As(err, &vmErr))
	require.Equal(t, vm.ErrUnfinalizedAsset, vmErr.Kind)

	_, err = f.Verify(
		context.Background(), MockVerifierCtx,
		WithSkipTimeLockValidationForFinalProof(),
	)
	require.NoError(t, err)
}

// TestFinalProofSkipTimeLockCSV ensures time lock validation is skipped for the
// final proof when a CSV locktime is present.
func TestFinalProofSkipTimeLockCSV(t *testing.T) {
	t.Parallel()

	f := buildTransitionProofFile(t, 0, 6)

	_, err := f.Verify(context.Background(), MockVerifierCtx)
	require.Error(t, err)
	var vmErr vm.Error
	require.True(t, errors.As(err, &vmErr))
	require.Equal(t, vm.ErrUnfinalizedAsset, vmErr.Kind)

	_, err = f.Verify(
		context.Background(), MockVerifierCtx,
		WithSkipTimeLockValidationForFinalProof(),
	)
	require.NoError(t, err)
}

// TestVerifyProofSuffix ensures an unconfirmed proof suffix is verified
// against the fully verified histories of its inputs. The final chain data is
// intentionally skipped, while the input chain and asset VM remain enforced.
func makeSuffixInputFiles(t *testing.T,
	proofFile *File) (*Proof, map[asset.PrevID]*File) {

	t.Helper()

	require.Equal(t, 2, proofFile.NumProofs())
	inputProof, err := proofFile.ProofAt(0)
	require.NoError(t, err)
	suffix, err := proofFile.ProofAt(1)
	require.NoError(t, err)

	inputFile, err := NewFile(V0, *inputProof)
	require.NoError(t, err)
	prevID := asset.PrevID{
		OutPoint: inputProof.OutPoint(),
		ID:       inputProof.Asset.ID(),
		ScriptKey: asset.ToSerialized(
			inputProof.Asset.ScriptKey.PubKey,
		),
	}

	return suffix, map[asset.PrevID]*File{
		prevID: inputFile,
	}
}

func TestVerifyProofSuffix(t *testing.T) {
	t.Parallel()

	makeInputFiles := makeSuffixInputFiles

	t.Run("valid unconfirmed suffix", func(t *testing.T) {
		proofFile := buildTransitionProofFile(t, 0, 0)
		suffix, inputFiles := makeInputFiles(t, proofFile)

		// A proof suffix has no real block data until its anchor
		// confirms. Make that explicit and ensure the header verifier
		// is only called for the already confirmed input proof.
		suffix.BlockHeader = wire.BlockHeader{}
		suffix.BlockHeight = 0
		suffix.TxMerkleProof = TxMerkleProof{}

		headerCalls := 0
		vCtx := MockVerifierCtx
		vCtx.HeaderVerifier = func(header wire.BlockHeader,
			height uint32) error {

			headerCalls++
			require.NotEqual(t, wire.BlockHeader{}, header)
			require.NotZero(t, height)

			return nil
		}

		snapshot, err := VerifyProofSuffix(
			context.Background(), suffix, inputFiles,
			&BaseVerifier{}, vCtx,
		)
		require.NoError(t, err)
		require.True(t, suffix.Asset.DeepEqual(snapshot.Asset))
		require.Equal(t, 1, headerCalls)
	})

	t.Run("fabricated anchor input", func(t *testing.T) {
		proofFile := buildTransitionProofFile(t, 0, 0)
		suffix, inputFiles := makeInputFiles(t, proofFile)

		fakePrevOut := test.RandOp(t)
		suffix.PrevOut = fakePrevOut
		suffix.AnchorTx.TxIn[0].PreviousOutPoint = fakePrevOut

		// The old structural-only validation accepts this mutation
		// because the anchor transaction inputs and asset VM aren't
		// inspected.
		_, err := suffix.VerifyProofs()
		require.NoError(t, err)

		_, err = VerifyProofSuffix(
			context.Background(), suffix, inputFiles,
			&BaseVerifier{}, MockVerifierCtx,
		)
		require.ErrorContains(t, err, "does not match primary input")
	})

	t.Run("invalid asset witness", func(t *testing.T) {
		proofFile := buildTransitionProofFile(
			t, 0, 0, func(a *asset.Asset) {
				witnesses := a.Witnesses()
				witnesses[0].TxWitness[0][0] ^= 1
			},
		)
		suffix, inputFiles := makeInputFiles(t, proofFile)

		// The proof commits to the tampered asset, so its structural
		// proof remains valid. Only executing the VM detects the bad
		// witness.
		_, err := suffix.VerifyProofs()
		require.NoError(t, err)

		_, err = VerifyProofSuffix(
			context.Background(), suffix, inputFiles,
			&BaseVerifier{}, MockVerifierCtx,
		)
		require.Error(t, err)
		var vmErr vm.Error
		require.ErrorAs(t, err, &vmErr)
		require.Equal(t, vm.ErrInvalidTransferWitness, vmErr.Kind)
	})

	t.Run("peer-supplied additional inputs", func(t *testing.T) {
		proofFile := buildTransitionProofFile(t, 0, 0)
		suffix, inputFiles := makeInputFiles(t, proofFile)

		suffix.AdditionalInputs = []File{*proofFile}

		_, err := VerifyProofSuffix(
			context.Background(), suffix, inputFiles,
			&BaseVerifier{}, MockVerifierCtx,
		)
		require.ErrorContains(t, err, "carries additional inputs")
	})

	t.Run("valid multi-input suffix", func(t *testing.T) {
		suffix, inputFiles := buildMergeSuffix(t, false)

		snapshot, err := VerifyProofSuffix(
			context.Background(), suffix, inputFiles,
			&BaseVerifier{}, MockVerifierCtx,
		)
		require.NoError(t, err)
		require.Equal(t, suffix.OutPoint(), snapshot.OutPoint)
		require.Equal(t, suffix.Asset.Amount, snapshot.Asset.Amount)
		require.Equal(
			t, asset.ToSerialized(suffix.Asset.ScriptKey.PubKey),
			asset.ToSerialized(snapshot.Asset.ScriptKey.PubKey),
		)
	})

	t.Run("anchor omits additional input", func(t *testing.T) {
		suffix, inputFiles := buildMergeSuffix(t, false)

		// Drop the anchor transaction input that consumes the split
		// leaf. The asset level witnesses still verify, so only the
		// anchor input spending check can catch this.
		require.Len(t, suffix.AnchorTx.TxIn, 2)
		suffix.AnchorTx.TxIn = suffix.AnchorTx.TxIn[:1]

		_, err := VerifyProofSuffix(
			context.Background(), suffix, inputFiles,
			&BaseVerifier{}, MockVerifierCtx,
		)
		require.ErrorContains(t, err, "does not spend input")
	})

	t.Run("inputs sharing one anchor outpoint", func(t *testing.T) {
		suffix, inputFiles := buildMergeSuffix(t, true)

		// Both asset inputs reside in the same Bitcoin UTXO, which the
		// anchor transaction spends exactly once.
		require.Len(t, suffix.AnchorTx.TxIn, 1)

		snapshot, err := VerifyProofSuffix(
			context.Background(), suffix, inputFiles,
			&BaseVerifier{}, MockVerifierCtx,
		)
		require.NoError(t, err)
		require.Equal(t, suffix.OutPoint(), snapshot.OutPoint)
		require.Equal(t, suffix.Asset.Amount, snapshot.Asset.Amount)
	})
}

// runAppendTransitionTest runs the test that makes sure a proof can be appended
// to an existing proof for an asset transition of the given type and amount.
func runAppendTransitionTest(t *testing.T, assetType asset.Type, amt uint64,
	withBip86Change, withSplit bool, assetVersion asset.Version) {

	// Start with a minted genesis asset.
	genesisProof, senderPrivKey := genRandomGenesisWithProof(
		t, assetType, &amt, nil, true, nil, nil, nil, nil, assetVersion,
	)
	genesisBlob, err := EncodeAsProofFile(&genesisProof)
	require.NoError(t, err)

	// Transfer the asset to a new owner.
	recipientPrivKey := test.RandPrivKey()
	newAsset := *genesisProof.Asset.Copy()
	newAsset.ScriptKey = asset.NewScriptKeyBip86(
		test.PubToKeyDesc(recipientPrivKey.PubKey()),
	)
	recipientTaprootInternalKey := test.SchnorrPubKey(t, recipientPrivKey)

	// Sign the new asset over to the recipient.
	signAssetTransfer(t, &genesisProof, &newAsset, senderPrivKey, nil)

	assetCommitment, err := commitment.NewAssetCommitment(&newAsset)
	require.NoError(t, err)
	tapCommitment, err := commitment.NewTapCommitment(nil, assetCommitment)
	require.NoError(t, err)

	// Add some alt leaves to the commitment anchoring the asset transfer.
	altLeaves := asset.ToAltLeaves(asset.RandAltLeaves(t, true))

	// Commit to the stxo of the previous asset. Otherwise, the inclusion
	// proofs will fail.
	stxoAsset, err := asset.MakeSpentAsset(newAsset.PrevWitnesses[0])
	require.NoError(t, err)

	stxoLeaf := asset.ToAltLeaves([]*asset.Asset{stxoAsset})
	altLeaves = append(altLeaves, stxoLeaf...)
	err = tapCommitment.MergeAltLeaves(altLeaves)
	require.NoError(t, err)

	tapscriptRoot := tapCommitment.TapscriptRoot(nil)
	taprootKey := txscript.ComputeTaprootOutputKey(
		recipientTaprootInternalKey, tapscriptRoot[:],
	)
	taprootScript := test.ComputeTaprootScript(t, taprootKey)

	chainTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  genesisProof.AnchorTx.TxHash(),
				Index: 0,
			},
		}},
		TxOut: []*wire.TxOut{{
			PkScript: taprootScript,
			Value:    330,
		}},
	}

	// Add a P2TR change output to test the exclusion proof.
	var changeInternalKey *btcec.PublicKey
	if withBip86Change {
		changeInternalKey = test.RandPrivKey().PubKey()
		changeTaprootKey := txscript.ComputeTaprootKeyNoScript(
			changeInternalKey,
		)
		chainTx.TxOut = append(chainTx.TxOut, &wire.TxOut{
			PkScript: test.ComputeTaprootScript(
				t, changeTaprootKey,
			),
			Value: 333,
		})
	}

	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(chainTx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	genesisHash := genesisProof.BlockHeader.BlockHash()
	blockHeader := wire.NewBlockHeader(0, &genesisHash, merkleRoot, 0, 0)

	txMerkleProof, err := NewTxMerkleProof([]*wire.MsgTx{chainTx}, 0)
	require.NoError(t, err)

	transitionParams := &TransitionParams{
		BaseProofParams: BaseProofParams{
			Block: &wire.MsgBlock{
				Header:       *blockHeader,
				Transactions: []*wire.MsgTx{chainTx},
			},
			Tx:               chainTx,
			TxIndex:          0,
			OutputIndex:      0,
			InternalKey:      recipientTaprootInternalKey,
			TaprootAssetRoot: tapCommitment,
		},
		NewAsset: &newAsset,
	}

	// If we added a change output before, we now also need to add the
	// exclusion proof for it.
	if withBip86Change {
		transitionParams.ExclusionProofs = []TaprootProof{{
			OutputIndex: 1,
			InternalKey: changeInternalKey,
			TapscriptProof: &TapscriptProof{
				Bip86: true,
			},
		}}
	}

	// Append the new transition to the genesis blob.
	transitionBlob, transitionProof, err := AppendTransition(
		genesisBlob, transitionParams, MockVerifierCtx,
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)
	require.Greater(t, len(transitionBlob), len(genesisBlob))
	require.Equal(t, txMerkleProof, &transitionProof.TxMerkleProof)
	asset.CompareAltLeaves(t, altLeaves, transitionProof.AltLeaves)
	verifyBlob(t, transitionBlob)

	// Stop here if we don't test asset splitting.
	if !withSplit {
		return
	}

	// If we want to test splitting, we do that now, as a second transfer.
	split1PrivKey := test.RandPrivKey()
	split2PrivKey := test.RandPrivKey()
	split3PrivKey := test.RandPrivKey()
	transitionOutpoint := wire.OutPoint{
		Hash:  transitionProof.AnchorTx.TxHash(),
		Index: transitionProof.InclusionProof.OutputIndex,
	}
	rootLocator := &commitment.SplitLocator{
		OutputIndex: 0,
		AssetID:     newAsset.ID(),
		ScriptKey:   asset.ToSerialized(split1PrivKey.PubKey()),
		Amount:      40,
	}
	split2Locator := &commitment.SplitLocator{
		OutputIndex: 1,
		AssetID:     newAsset.ID(),
		ScriptKey:   asset.ToSerialized(split2PrivKey.PubKey()),
		Amount:      40,
	}
	split3Locator := &commitment.SplitLocator{
		OutputIndex: 2,
		AssetID:     newAsset.ID(),
		ScriptKey:   asset.ToSerialized(split3PrivKey.PubKey()),
		Amount:      20,
	}
	inputs := []commitment.SplitCommitmentInput{{
		Asset:    &newAsset,
		OutPoint: transitionOutpoint,
	}}
	splitCommitment, err := commitment.NewSplitCommitment(
		context.Background(), inputs, rootLocator, split2Locator,
		split3Locator,
	)
	require.NoError(t, err)
	split1Asset := splitCommitment.RootAsset
	split2Asset := &splitCommitment.SplitAssets[*split2Locator].Asset
	split3Asset := &splitCommitment.SplitAssets[*split3Locator].Asset

	split2AssetNoSplitProof := split2Asset.Copy()
	split2AssetNoSplitProof.PrevWitnesses[0].SplitCommitment = nil

	split3AssetNoSplitProof := split3Asset.Copy()
	split3AssetNoSplitProof.PrevWitnesses[0].SplitCommitment = nil

	// Sign the new (root) asset over to the recipient.
	signAssetTransfer(
		t, transitionProof, split1Asset, recipientPrivKey,
		[]*asset.Asset{split2Asset, split3Asset},
	)

	split1Commitment, err := commitment.NewAssetCommitment(split1Asset)
	require.NoError(t, err)
	split2Commitment, err := commitment.NewAssetCommitment(
		split2AssetNoSplitProof,
	)
	require.NoError(t, err)
	split3Commitment, err := commitment.NewAssetCommitment(
		split3AssetNoSplitProof,
	)
	require.NoError(t, err)
	split1AltLeaves := asset.ToAltLeaves(asset.RandAltLeaves(t, true))
	split2AltLeaves := asset.ToAltLeaves(asset.RandAltLeaves(t, true))
	split3AltLeaves := asset.ToAltLeaves(asset.RandAltLeaves(t, true))
	tap1Commitment, err := commitment.NewTapCommitment(
		nil, split1Commitment,
	)
	require.NoError(t, err)

	// Commit to the stxo of the previous asset. Otherwise, the inclusion
	// proofs will fail. With splits this is only needed for the root asset.
	stxoAsset1, err := asset.MakeSpentAsset(split1Asset.PrevWitnesses[0])
	require.NoError(t, err)

	stxoLeaf1 := asset.ToAltLeaves([]*asset.Asset{stxoAsset1})
	split1AltLeaves = append(split1AltLeaves, stxoLeaf1...)
	err = tap1Commitment.MergeAltLeaves(split1AltLeaves)
	require.NoError(t, err)

	tap2Commitment, err := commitment.NewTapCommitment(
		nil, split2Commitment,
	)
	require.NoError(t, err)
	err = tap2Commitment.MergeAltLeaves(split2AltLeaves)
	require.NoError(t, err)
	tap3Commitment, err := commitment.NewTapCommitment(
		nil, split3Commitment,
	)
	require.NoError(t, err)
	err = tap3Commitment.MergeAltLeaves(split3AltLeaves)
	require.NoError(t, err)

	tapscript1Root := tap1Commitment.TapscriptRoot(nil)
	tapscript2Root := tap2Commitment.TapscriptRoot(nil)
	tapscript3Root := tap3Commitment.TapscriptRoot(nil)
	internalKey1 := test.RandPubKey(t)
	internalKey2 := test.RandPubKey(t)
	internalKey3 := test.RandPubKey(t)
	taproot1Key := txscript.ComputeTaprootOutputKey(
		internalKey1, tapscript1Root[:],
	)
	taproot2Key := txscript.ComputeTaprootOutputKey(
		internalKey2, tapscript2Root[:],
	)
	taproot3Key := txscript.ComputeTaprootOutputKey(
		internalKey3, tapscript3Root[:],
	)

	splitTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  transitionProof.AnchorTx.TxHash(),
				Index: 0,
			},
		}},
		TxOut: []*wire.TxOut{{
			PkScript: test.ComputeTaprootScript(t, taproot1Key),
			Value:    330,
		}, {
			PkScript: test.ComputeTaprootScript(t, taproot2Key),
			Value:    330,
		}, {
			PkScript: test.ComputeTaprootScript(t, taproot3Key),
			Value:    330,
		}},
	}

	splitMerkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(splitTx)}, false,
	)
	splitMerkleRoot := splitMerkleTree[len(merkleTree)-1]
	transitionHash := transitionProof.BlockHeader.BlockHash()
	splitBlockHeader := wire.NewBlockHeader(
		0, &transitionHash, splitMerkleRoot, 0, 0,
	)

	splitTxMerkleProof, err := NewTxMerkleProof([]*wire.MsgTx{splitTx}, 0)
	require.NoError(t, err)

	_, split1In2ExclusionProof, err := tap2Commitment.Proof(
		split1Asset.TapCommitmentKey(),
		split1Asset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	// For the transfer root we also need to the stxo exclusion proofs.
	_, stxo1In2exclusionProof, err := tap2Commitment.Proof(
		stxoAsset1.TapCommitmentKey(),
		stxoAsset1.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	stxoID := asset.ToSerialized(stxoAsset1.ScriptKey.PubKey)
	stxo1In2Proofs := make(map[asset.SerializedKey]commitment.Proof, 1)
	stxo1In2Proofs[stxoID] = *stxo1In2exclusionProof

	_, split1In3ExclusionProof, err := tap3Commitment.Proof(
		split1Asset.TapCommitmentKey(),
		split1Asset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	// For the transfer root we also need to the stxo exclusion proofs.
	_, stxo1In3exclusionProof, err := tap3Commitment.Proof(
		stxoAsset1.TapCommitmentKey(),
		stxoAsset1.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	stxo1In3Proofs := make(map[asset.SerializedKey]commitment.Proof, 1)
	stxo1In3Proofs[stxoID] = *stxo1In3exclusionProof

	_, split2In1ExclusionProof, err := tap1Commitment.Proof(
		split2Asset.TapCommitmentKey(),
		split2Asset.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	_, split2In3ExclusionProof, err := tap3Commitment.Proof(
		split2Asset.TapCommitmentKey(),
		split2Asset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	_, split3In1ExclusionProof, err := tap1Commitment.Proof(
		split3Asset.TapCommitmentKey(),
		split3Asset.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	_, split3In2ExclusionProof, err := tap2Commitment.Proof(
		split3Asset.TapCommitmentKey(),
		split3Asset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	// Create and verify the proof for the first split output (the sender or
	// change output).
	split1Params := &TransitionParams{
		BaseProofParams: BaseProofParams{
			Block: &wire.MsgBlock{
				Header:       *splitBlockHeader,
				Transactions: []*wire.MsgTx{splitTx},
			},
			Tx:               splitTx,
			TxIndex:          0,
			OutputIndex:      0,
			InternalKey:      internalKey1,
			TaprootAssetRoot: tap1Commitment,
			ExclusionProofs: []TaprootProof{{
				OutputIndex: 1,
				InternalKey: internalKey2,
				CommitmentProof: &CommitmentProof{
					Proof:      *split1In2ExclusionProof,
					STXOProofs: stxo1In2Proofs,
				},
			}, {
				OutputIndex: 2,
				InternalKey: internalKey3,
				CommitmentProof: &CommitmentProof{
					Proof:      *split1In3ExclusionProof,
					STXOProofs: stxo1In3Proofs,
				},
			}},
		},
		NewAsset: split1Asset,
	}

	split1Blob, split1Proof, err := AppendTransition(
		transitionBlob, split1Params, MockVerifierCtx,
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)
	require.Greater(t, len(split1Blob), len(transitionBlob))
	require.Equal(t, splitTxMerkleProof, &split1Proof.TxMerkleProof)
	asset.CompareAltLeaves(t, split1AltLeaves, split1Proof.AltLeaves)
	split1Snapshot := verifyBlob(t, split1Blob)
	require.False(t, split1Snapshot.SplitAsset)

	// And now for the second split (the recipient output).
	split2Params := &TransitionParams{
		BaseProofParams: BaseProofParams{
			Block: &wire.MsgBlock{
				Header:       *splitBlockHeader,
				Transactions: []*wire.MsgTx{splitTx},
			},
			Tx:               splitTx,
			TxIndex:          0,
			OutputIndex:      1,
			InternalKey:      internalKey2,
			TaprootAssetRoot: tap2Commitment,
			ExclusionProofs: []TaprootProof{{
				OutputIndex: 0,
				InternalKey: internalKey1,
				CommitmentProof: &CommitmentProof{
					Proof: *split2In1ExclusionProof,
				},
			}, {
				OutputIndex: 2,
				InternalKey: internalKey3,
				CommitmentProof: &CommitmentProof{
					Proof: *split2In3ExclusionProof,
				},
			}},
		},
		NewAsset:             split2Asset,
		RootInternalKey:      internalKey1,
		RootOutputIndex:      0,
		RootTaprootAssetTree: tap1Commitment,
	}

	split2Blob, split2Proof, err := AppendTransition(
		transitionBlob, split2Params, MockVerifierCtx,
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)
	require.Greater(t, len(split2Blob), len(transitionBlob))
	require.Equal(t, splitTxMerkleProof, &split2Proof.TxMerkleProof)
	asset.CompareAltLeaves(t, split2AltLeaves, split2Proof.AltLeaves)
	split2Snapshot := verifyBlob(t, split2Blob)

	require.True(t, split2Snapshot.SplitAsset)

	// And finally for the third split (the second recipient output).
	split3Params := &TransitionParams{
		BaseProofParams: BaseProofParams{
			Block: &wire.MsgBlock{
				Header:       *splitBlockHeader,
				Transactions: []*wire.MsgTx{splitTx},
			},
			Tx:               splitTx,
			TxIndex:          0,
			OutputIndex:      2,
			InternalKey:      internalKey3,
			TaprootAssetRoot: tap3Commitment,
			ExclusionProofs: []TaprootProof{{
				OutputIndex: 0,
				InternalKey: internalKey1,
				CommitmentProof: &CommitmentProof{
					Proof: *split3In1ExclusionProof,
				},
			}, {
				OutputIndex: 1,
				InternalKey: internalKey2,
				CommitmentProof: &CommitmentProof{
					Proof: *split3In2ExclusionProof,
				},
			}},
		},
		NewAsset:             split3Asset,
		RootInternalKey:      internalKey1,
		RootOutputIndex:      0,
		RootTaprootAssetTree: tap1Commitment,
	}

	split3Blob, split3Proof, err := AppendTransition(
		transitionBlob, split3Params, MockVerifierCtx,
		WithVersion(TransitionV1),
	)
	require.NoError(t, err)
	require.Greater(t, len(split3Blob), len(transitionBlob))
	require.Equal(t, splitTxMerkleProof, &split3Proof.TxMerkleProof)
	asset.CompareAltLeaves(t, split3AltLeaves, split3Proof.AltLeaves)
	split3Snapshot := verifyBlob(t, split3Blob)

	require.True(t, split3Snapshot.SplitAsset)
}

// buildTransitionProofFile constructs a proof file with a genesis proof and a
// single transfer proof that uses the given lock times.
func buildTransitionProofFile(t *testing.T, lockTime,
	relativeLockTime uint64, assetMutators ...func(*asset.Asset)) *File {

	t.Helper()

	amt := uint64(100)
	genesisProof, senderPrivKey := genRandomGenesisWithProof(
		t, asset.Normal, &amt, nil, true, nil, nil, nil, nil, asset.V0,
	)

	recipientPrivKey := test.RandPrivKey()
	newAsset := *genesisProof.Asset.Copy()
	newAsset.ScriptKey = asset.NewScriptKeyBip86(
		test.PubToKeyDesc(recipientPrivKey.PubKey()),
	)
	newAsset.LockTime = lockTime
	newAsset.RelativeLockTime = relativeLockTime

	signAssetTransfer(t, &genesisProof, &newAsset, senderPrivKey, nil)
	for _, mutate := range assetMutators {
		mutate(&newAsset)
	}

	assetCommitment, err := commitment.NewAssetCommitment(&newAsset)
	require.NoError(t, err)
	tapCommitment, err := commitment.NewTapCommitment(nil, assetCommitment)
	require.NoError(t, err)

	altLeaves := asset.ToAltLeaves(asset.RandAltLeaves(t, true))
	stxoAsset, err := asset.MakeSpentAsset(newAsset.PrevWitnesses[0])
	require.NoError(t, err)

	stxoLeaf := asset.ToAltLeaves([]*asset.Asset{stxoAsset})
	altLeaves = append(altLeaves, stxoLeaf...)
	require.NoError(t, tapCommitment.MergeAltLeaves(altLeaves))

	recipientTaprootInternalKey := test.SchnorrPubKey(t, recipientPrivKey)
	tapscriptRoot := tapCommitment.TapscriptRoot(nil)
	taprootKey := txscript.ComputeTaprootOutputKey(
		recipientTaprootInternalKey, tapscriptRoot[:],
	)
	taprootScript := test.ComputeTaprootScript(t, taprootKey)

	chainTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  genesisProof.AnchorTx.TxHash(),
				Index: 0,
			},
		}},
		TxOut: []*wire.TxOut{{
			PkScript: taprootScript,
			Value:    330,
		}},
	}

	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(chainTx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	genesisHash := genesisProof.BlockHeader.BlockHash()
	blockHeader := wire.NewBlockHeader(0, &genesisHash, merkleRoot, 0, 0)

	transitionParams := &TransitionParams{
		BaseProofParams: BaseProofParams{
			Block: &wire.MsgBlock{
				Header:       *blockHeader,
				Transactions: []*wire.MsgTx{chainTx},
			},
			Tx:               chainTx,
			TxIndex:          0,
			OutputIndex:      0,
			InternalKey:      recipientTaprootInternalKey,
			TaprootAssetRoot: tapCommitment,
		},
		NewAsset: &newAsset,
	}

	lastPrevOut := wire.OutPoint{
		Hash:  genesisProof.AnchorTx.TxHash(),
		Index: genesisProof.InclusionProof.OutputIndex,
	}
	transitionProof, err := CreateTransitionProof(
		lastPrevOut, transitionParams, WithVersion(TransitionV1),
	)
	require.NoError(t, err)

	f := NewEmptyFile(V0)
	require.NoError(t, f.AppendProof(genesisProof))
	require.NoError(t, f.AppendProof(*transitionProof))
	return f
}

// buildMergeSuffix constructs an unconfirmed two-input merge suffix. A
// genesis asset is split into a transfer root and a split leaf, which are
// then merged back into a single output by the suffix. If sharedAnchorOut is
// true, both split outputs are committed to the same anchor output, so the
// merge spends two asset inputs that share one Bitcoin outpoint.
func buildMergeSuffix(t *testing.T, sharedAnchorOut bool) (*Proof,
	map[asset.PrevID]*File) {

	t.Helper()

	amt := uint64(100)
	genesisProof, senderPrivKey := genRandomGenesisWithProof(
		t, asset.Normal, &amt, nil, true, nil, nil, nil, nil, asset.V0,
	)
	genesisBlob, err := EncodeAsProofFile(&genesisProof)
	require.NoError(t, err)

	// Split the genesis asset into a transfer root and a split leaf.
	rootPrivKey := test.RandPrivKey()
	leafPrivKey := test.RandPrivKey()
	rootScriptKey := asset.NewScriptKeyBip86(
		test.PubToKeyDesc(rootPrivKey.PubKey()),
	)
	leafScriptKey := asset.NewScriptKeyBip86(
		test.PubToKeyDesc(leafPrivKey.PubKey()),
	)

	leafOutputIndex := uint32(1)
	if sharedAnchorOut {
		leafOutputIndex = 0
	}

	assetID := genesisProof.Asset.ID()
	rootLocator := &commitment.SplitLocator{
		OutputIndex: 0,
		AssetID:     assetID,
		ScriptKey:   asset.ToSerialized(rootScriptKey.PubKey),
		Amount:      60,
	}
	leafLocator := &commitment.SplitLocator{
		OutputIndex: leafOutputIndex,
		AssetID:     assetID,
		ScriptKey:   asset.ToSerialized(leafScriptKey.PubKey),
		Amount:      40,
	}
	genesisOutpoint := wire.OutPoint{
		Hash:  genesisProof.AnchorTx.TxHash(),
		Index: genesisProof.InclusionProof.OutputIndex,
	}
	splitCommitment, err := commitment.NewSplitCommitment(
		context.Background(), []commitment.SplitCommitmentInput{{
			Asset:    &genesisProof.Asset,
			OutPoint: genesisOutpoint,
		}}, rootLocator, leafLocator,
	)
	require.NoError(t, err)

	rootAsset := splitCommitment.RootAsset
	leafAsset := &splitCommitment.SplitAssets[*leafLocator].Asset
	leafAssetNoSplitProof := leafAsset.Copy()
	leafAssetNoSplitProof.PrevWitnesses[0].SplitCommitment = nil

	signAssetTransfer(
		t, &genesisProof, rootAsset, senderPrivKey,
		[]*asset.Asset{leafAsset},
	)

	// Commit the split outputs to their anchor output(s).
	var rootTap, leafTap *commitment.TapCommitment
	if sharedAnchorOut {
		sharedAssetCommitment, err := commitment.NewAssetCommitment(
			rootAsset, leafAssetNoSplitProof,
		)
		require.NoError(t, err)
		rootTap, err = commitment.NewTapCommitment(
			nil, sharedAssetCommitment,
		)
		require.NoError(t, err)
		leafTap = rootTap
	} else {
		rootAssetCommitment, err := commitment.NewAssetCommitment(
			rootAsset,
		)
		require.NoError(t, err)
		rootTap, err = commitment.NewTapCommitment(
			nil, rootAssetCommitment,
		)
		require.NoError(t, err)

		leafAssetCommitment, err := commitment.NewAssetCommitment(
			leafAssetNoSplitProof,
		)
		require.NoError(t, err)
		leafTap, err = commitment.NewTapCommitment(
			nil, leafAssetCommitment,
		)
		require.NoError(t, err)
	}

	rootInternalKey := test.RandPubKey(t)
	leafInternalKey := rootInternalKey
	if !sharedAnchorOut {
		leafInternalKey = test.RandPubKey(t)
	}

	rootTapscriptRoot := rootTap.TapscriptRoot(nil)
	rootTaprootKey := txscript.ComputeTaprootOutputKey(
		rootInternalKey, rootTapscriptRoot[:],
	)
	splitTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: genesisOutpoint,
		}},
		TxOut: []*wire.TxOut{{
			PkScript: test.ComputeTaprootScript(t, rootTaprootKey),
			Value:    330,
		}},
	}
	if !sharedAnchorOut {
		leafTapscriptRoot := leafTap.TapscriptRoot(nil)
		leafTaprootKey := txscript.ComputeTaprootOutputKey(
			leafInternalKey, leafTapscriptRoot[:],
		)
		splitTx.TxOut = append(splitTx.TxOut, &wire.TxOut{
			PkScript: test.ComputeTaprootScript(t, leafTaprootKey),
			Value:    330,
		})
	}

	splitMerkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(splitTx)}, false,
	)
	splitMerkleRoot := splitMerkleTree[len(splitMerkleTree)-1]
	genesisHash := genesisProof.BlockHeader.BlockHash()
	splitBlockHeader := wire.NewBlockHeader(
		0, &genesisHash, splitMerkleRoot, 0, 0,
	)
	splitBlock := &wire.MsgBlock{
		Header:       *splitBlockHeader,
		Transactions: []*wire.MsgTx{splitTx},
	}

	// With two anchor outputs, each proof needs an exclusion proof for the
	// respective other output.
	var rootExclusions, leafExclusions []TaprootProof
	if !sharedAnchorOut {
		_, rootInLeafExclusion, err := leafTap.Proof(
			rootAsset.TapCommitmentKey(),
			rootAsset.AssetCommitmentKey(),
		)
		require.NoError(t, err)
		rootExclusions = []TaprootProof{{
			OutputIndex: 1,
			InternalKey: leafInternalKey,
			CommitmentProof: &CommitmentProof{
				Proof: *rootInLeafExclusion,
			},
		}}

		_, leafInRootExclusion, err := rootTap.Proof(
			leafAsset.TapCommitmentKey(),
			leafAsset.AssetCommitmentKey(),
		)
		require.NoError(t, err)
		leafExclusions = []TaprootProof{{
			OutputIndex: 0,
			InternalKey: rootInternalKey,
			CommitmentProof: &CommitmentProof{
				Proof: *leafInRootExclusion,
			},
		}}
	}

	rootParams := &TransitionParams{
		BaseProofParams: BaseProofParams{
			Block:            splitBlock,
			Tx:               splitTx,
			TxIndex:          0,
			OutputIndex:      0,
			InternalKey:      rootInternalKey,
			TaprootAssetRoot: rootTap,
			ExclusionProofs:  rootExclusions,
		},
		NewAsset: rootAsset,
	}
	rootBlob, _, err := AppendTransition(
		genesisBlob, rootParams, MockVerifierCtx,
		WithVersion(TransitionV0), WithNoSTXOProofs(),
	)
	require.NoError(t, err)

	leafParams := &TransitionParams{
		BaseProofParams: BaseProofParams{
			Block:            splitBlock,
			Tx:               splitTx,
			TxIndex:          0,
			OutputIndex:      int(leafOutputIndex),
			InternalKey:      leafInternalKey,
			TaprootAssetRoot: leafTap,
			ExclusionProofs:  leafExclusions,
		},
		NewAsset:             leafAsset,
		RootInternalKey:      rootInternalKey,
		RootOutputIndex:      0,
		RootTaprootAssetTree: rootTap,
	}
	leafBlob, _, err := AppendTransition(
		genesisBlob, leafParams, MockVerifierCtx,
		WithVersion(TransitionV0), WithNoSTXOProofs(),
	)
	require.NoError(t, err)

	// Now merge the two split outputs back into a single asset output with
	// an unconfirmed suffix.
	rootPrevID := &asset.PrevID{
		OutPoint: wire.OutPoint{
			Hash:  splitTx.TxHash(),
			Index: 0,
		},
		ID:        assetID,
		ScriptKey: asset.ToSerialized(rootScriptKey.PubKey),
	}
	leafPrevID := &asset.PrevID{
		OutPoint: wire.OutPoint{
			Hash:  splitTx.TxHash(),
			Index: leafOutputIndex,
		},
		ID:        assetID,
		ScriptKey: asset.ToSerialized(leafScriptKey.PubKey),
	}

	mergePrivKey := test.RandPrivKey()
	mergedAsset := genesisProof.Asset.Copy()
	mergedAsset.Amount = amt
	mergedAsset.ScriptKey = asset.NewScriptKeyBip86(
		test.PubToKeyDesc(mergePrivKey.PubKey()),
	)
	mergedAsset.PrevWitnesses = []asset.Witness{
		{PrevID: rootPrevID}, {PrevID: leafPrevID},
	}

	mergeInputs := commitment.InputSet{
		*rootPrevID: rootAsset,
		*leafPrevID: leafAsset,
	}
	virtualTx, _, err := tapscript.VirtualTx(mergedAsset, mergeInputs)
	require.NoError(t, err)
	mergedAsset.PrevWitnesses[0].TxWitness = genTaprootKeySpend(
		t, *rootPrivKey, virtualTx, rootAsset, mergedAsset, 0,
	)
	mergedAsset.PrevWitnesses[1].TxWitness = genTaprootKeySpend(
		t, *leafPrivKey, virtualTx, leafAsset, mergedAsset, 1,
	)

	mergeAssetCommitment, err := commitment.NewAssetCommitment(mergedAsset)
	require.NoError(t, err)
	mergeTap, err := commitment.NewTapCommitment(nil, mergeAssetCommitment)
	require.NoError(t, err)

	mergeInternalKey := test.RandPubKey(t)
	mergeTapscriptRoot := mergeTap.TapscriptRoot(nil)
	mergeTaprootKey := txscript.ComputeTaprootOutputKey(
		mergeInternalKey, mergeTapscriptRoot[:],
	)
	mergeTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: rootPrevID.OutPoint,
		}},
		TxOut: []*wire.TxOut{{
			PkScript: test.ComputeTaprootScript(t, mergeTaprootKey),
			Value:    330,
		}},
	}
	if !sharedAnchorOut {
		mergeTx.TxIn = append(mergeTx.TxIn, &wire.TxIn{
			PreviousOutPoint: leafPrevID.OutPoint,
		})
	}

	mergeMerkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(mergeTx)}, false,
	)
	mergeMerkleRoot := mergeMerkleTree[len(mergeMerkleTree)-1]
	splitHash := splitBlockHeader.BlockHash()
	mergeBlockHeader := wire.NewBlockHeader(
		0, &splitHash, mergeMerkleRoot, 0, 0,
	)

	mergeParams := &TransitionParams{
		BaseProofParams: BaseProofParams{
			Block: &wire.MsgBlock{
				Header:       *mergeBlockHeader,
				Transactions: []*wire.MsgTx{mergeTx},
			},
			Tx:               mergeTx,
			TxIndex:          0,
			OutputIndex:      0,
			InternalKey:      mergeInternalKey,
			TaprootAssetRoot: mergeTap,
		},
		NewAsset: mergedAsset,
	}
	suffix, err := CreateTransitionProof(
		rootPrevID.OutPoint, mergeParams, WithVersion(TransitionV0),
		WithNoSTXOProofs(),
	)
	require.NoError(t, err)

	rootFile := NewEmptyFile(V0)
	require.NoError(t, rootFile.Decode(bytes.NewReader(rootBlob)))
	leafFile := NewEmptyFile(V0)
	require.NoError(t, leafFile.Decode(bytes.NewReader(leafBlob)))

	return suffix, map[asset.PrevID]*File{
		*rootPrevID: rootFile,
		*leafPrevID: leafFile,
	}
}

// signAssetTransfer creates a virtual transaction for an asset transfer and
// signs it with the given sender private key. Then we add the generated witness
// to the root asset and all split asset's root asset references.
func signAssetTransfer(t testing.TB, prevProof *Proof, newAsset *asset.Asset,
	senderPrivKey *btcec.PrivateKey, splitAssets []*asset.Asset) {

	prevOutpoint := wire.OutPoint{
		Hash:  prevProof.AnchorTx.TxHash(),
		Index: prevProof.InclusionProof.OutputIndex,
	}
	prevID := &asset.PrevID{
		OutPoint: prevOutpoint,
		ID:       prevProof.Asset.ID(),
		ScriptKey: asset.ToSerialized(
			prevProof.Asset.ScriptKey.PubKey,
		),
	}
	newAsset.PrevWitnesses = []asset.Witness{{
		PrevID: prevID,
	}}
	inputs := commitment.InputSet{
		*prevID: &prevProof.Asset,
	}

	virtualTx, _, err := tapscript.VirtualTx(newAsset, inputs)
	require.NoError(t, err)
	newWitness := genTaprootKeySpend(
		t, *senderPrivKey, virtualTx, &prevProof.Asset, newAsset, 0,
	)
	require.NoError(t, err)
	newAsset.PrevWitnesses[0].TxWitness = newWitness

	// Because we need the root asset in the split commitment to match the
	// actual root asset that we commit to in the tree to match exactly, we
	// need to add the witness there as well.
	for idx := range splitAssets {
		prevWitness := splitAssets[idx].PrevWitnesses[0]
		require.NotNil(t, prevWitness.SplitCommitment)

		splitCommitment := prevWitness.SplitCommitment
		splitCommitment.RootAsset.PrevWitnesses[0].TxWitness = newWitness
	}
}

func verifyBlob(t testing.TB, blob Blob) *AssetSnapshot {
	// Decode the proof blob into a proper file structure first.
	f := NewEmptyFile(V0)
	require.NoError(t, f.Decode(bytes.NewReader(blob)))

	finalSnapshot, err := f.Verify(context.Background(), MockVerifierCtx)
	require.NoError(t, err)

	return finalSnapshot
}
