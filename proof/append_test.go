package proof

import (
	"bytes"
	"context"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tapscript"
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
			name:      "normal with change",
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
	_, split1In3ExclusionProof, err := tap3Commitment.Proof(
		split1Asset.TapCommitmentKey(),
		split1Asset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

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
					Proof: *split1In2ExclusionProof,
				},
			}, {
				OutputIndex: 2,
				InternalKey: internalKey3,
				CommitmentProof: &CommitmentProof{
					Proof: *split1In3ExclusionProof,
				},
			}},
		},
		NewAsset: split1Asset,
	}

	split1Blob, split1Proof, err := AppendTransition(
		transitionBlob, split1Params, MockVerifierCtx,
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
	)
	require.NoError(t, err)
	require.Greater(t, len(split3Blob), len(transitionBlob))
	require.Equal(t, splitTxMerkleProof, &split3Proof.TxMerkleProof)
	asset.CompareAltLeaves(t, split3AltLeaves, split3Proof.AltLeaves)
	split3Snapshot := verifyBlob(t, split3Blob)

	require.True(t, split3Snapshot.SplitAsset)
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
