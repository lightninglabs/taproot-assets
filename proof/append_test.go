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
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/stretchr/testify/require"
)

func genTaprootKeySpend(t testing.TB, privKey btcec.PrivateKey,
	virtualTx *wire.MsgTx, input *asset.Asset, idx uint32) wire.TxWitness {

	t.Helper()

	virtualTxCopy := taroscript.VirtualTxWithInput(
		virtualTx, input, idx, nil,
	)
	sigHash, err := taroscript.InputKeySpendSigHash(
		virtualTxCopy, input, idx, txscript.SigHashDefault,
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
	}{{
		name:      "normal",
		assetType: asset.Normal,
		amt:       100,
	}, {
		name:            "normal with change",
		assetType:       asset.Normal,
		amt:             100,
		withBip86Change: true,
	}, {
		name:      "normal with change",
		assetType: asset.Normal,
		amt:       100,
		withSplit: true,
	}, {
		name:      "collectible",
		assetType: asset.Collectible,
		amt:       1,
	}, {
		name:            "collectible with change",
		assetType:       asset.Collectible,
		amt:             1,
		withBip86Change: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			runAppendTransitionTest(
				tt, tc.assetType, tc.amt, tc.withBip86Change,
				tc.withSplit,
			)
		})
	}
}

// runAppendTransitionTest runs the test that makes sure a proof can be appended
// to an existing proof for an asset transition of the given type and amount.
func runAppendTransitionTest(t *testing.T, assetType asset.Type, amt uint64,
	withBip86Change, withSplit bool) {

	// Start with a minted genesis asset.
	genesisProof, senderPrivKey := genRandomGenesisWithProof(
		t, assetType, &amt, nil,
	)
	genesisBlob, err := encodeAsProofFile(&genesisProof)
	require.NoError(t, err)

	// Transfer the asset to a new owner.
	recipientPrivKey := test.RandPrivKey(t)
	newAsset := *genesisProof.Asset.Copy()
	newAsset.ScriptKey = asset.NewScriptKeyBIP0086(
		test.PubToKeyDesc(recipientPrivKey.PubKey()),
	)
	recipientTaprootInternalKey := test.SchnorrPubKey(t, recipientPrivKey)

	// Sign the new asset over to the recipient.
	signAssetTransfer(t, &genesisProof, &newAsset, senderPrivKey, nil)

	assetCommitment, err := commitment.NewAssetCommitment(&newAsset)
	require.NoError(t, err)
	taroCommitment, err := commitment.NewTaroCommitment(assetCommitment)
	require.NoError(t, err)

	tapscriptRoot := taroCommitment.TapscriptRoot(nil)
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
		changeInternalKey = test.RandPrivKey(t).PubKey()
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
			Tx:          chainTx,
			TxIndex:     0,
			OutputIndex: 0,
			InternalKey: recipientTaprootInternalKey,
			TaroRoot:    taroCommitment,
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
				BIP86: true,
			},
		}}
	}

	// Append the new transition to the genesis blob.
	transitionBlob, transitionProof, err := AppendTransition(
		genesisBlob, transitionParams, MockHeaderVerifier,
	)
	require.NoError(t, err)
	require.Greater(t, len(transitionBlob), len(genesisBlob))
	require.Equal(t, txMerkleProof, &transitionProof.TxMerkleProof)
	verifyBlob(t, transitionBlob)

	// Stop here if we don't test asset splitting.
	if !withSplit {
		return
	}

	// If we want to test splitting, we do that now, as a second transfer.
	split1PrivKey := test.RandPrivKey(t)
	split2PrivKey := test.RandPrivKey(t)
	transitionOutpoint := wire.OutPoint{
		Hash:  transitionProof.AnchorTx.TxHash(),
		Index: transitionProof.InclusionProof.OutputIndex,
	}
	rootLocator := &commitment.SplitLocator{
		OutputIndex: 0,
		AssetID:     newAsset.ID(),
		ScriptKey:   asset.ToSerialized(split1PrivKey.PubKey()),
		Amount:      50,
	}
	split2Locator := &commitment.SplitLocator{
		OutputIndex: 1,
		AssetID:     newAsset.ID(),
		ScriptKey:   asset.ToSerialized(split2PrivKey.PubKey()),
		Amount:      50,
	}
	splitCommitment, err := commitment.NewSplitCommitment(
		&newAsset, transitionOutpoint, rootLocator, split2Locator,
	)
	require.NoError(t, err)
	split1Asset := splitCommitment.RootAsset
	split2Asset := &splitCommitment.SplitAssets[*split2Locator].Asset

	split2AssetNoSplitProof := split2Asset.Copy()
	split2AssetNoSplitProof.PrevWitnesses[0].SplitCommitment = nil

	// Sign the new (root) asset over to the recipient.
	signAssetTransfer(
		t, transitionProof, split1Asset, recipientPrivKey,
		[]*asset.Asset{split2Asset},
	)

	split1Commitment, err := commitment.NewAssetCommitment(split1Asset)
	require.NoError(t, err)
	split2Commitment, err := commitment.NewAssetCommitment(
		split2AssetNoSplitProof,
	)
	require.NoError(t, err)
	taro1Commitment, err := commitment.NewTaroCommitment(split1Commitment)
	require.NoError(t, err)
	taro2Commitment, err := commitment.NewTaroCommitment(split2Commitment)
	require.NoError(t, err)

	tapscript1Root := taro1Commitment.TapscriptRoot(nil)
	tapscript2Root := taro2Commitment.TapscriptRoot(nil)
	internalKey1 := test.RandPubKey(t)
	internalKey2 := test.RandPubKey(t)
	taproot1Key := txscript.ComputeTaprootOutputKey(
		internalKey1, tapscript1Root[:],
	)
	taproot2Key := txscript.ComputeTaprootOutputKey(
		internalKey2, tapscript2Root[:],
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

	_, split1ExclusionProof, err := taro2Commitment.Proof(
		split1Asset.TaroCommitmentKey(),
		split1Asset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	_, split2ExclusionProof, err := taro1Commitment.Proof(
		split2Asset.TaroCommitmentKey(),
		split2Asset.AssetCommitmentKey(),
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
			Tx:          splitTx,
			TxIndex:     0,
			OutputIndex: 0,
			InternalKey: internalKey1,
			TaroRoot:    taro1Commitment,
			ExclusionProofs: []TaprootProof{{
				OutputIndex: 1,
				InternalKey: internalKey2,
				CommitmentProof: &CommitmentProof{
					Proof: *split1ExclusionProof,
				},
			}},
		},
		NewAsset: split1Asset,
	}

	split1Blob, split1Proof, err := AppendTransition(
		transitionBlob, split1Params, MockHeaderVerifier,
	)
	require.NoError(t, err)
	require.Greater(t, len(split1Blob), len(transitionBlob))
	require.Equal(t, splitTxMerkleProof, &split1Proof.TxMerkleProof)
	split1Snapshot := verifyBlob(t, split1Blob)
	require.False(t, split1Snapshot.SplitAsset)

	// And now for the second split (the recipient output).
	split2Params := &TransitionParams{
		BaseProofParams: BaseProofParams{
			Block: &wire.MsgBlock{
				Header:       *splitBlockHeader,
				Transactions: []*wire.MsgTx{splitTx},
			},
			Tx:          splitTx,
			TxIndex:     0,
			OutputIndex: 1,
			InternalKey: internalKey2,
			TaroRoot:    taro2Commitment,
			ExclusionProofs: []TaprootProof{{
				OutputIndex: 0,
				InternalKey: internalKey1,
				CommitmentProof: &CommitmentProof{
					Proof: *split2ExclusionProof,
				},
			}},
		},
		NewAsset:        split2Asset,
		RootInternalKey: internalKey1,
		RootOutputIndex: 0,
		RootTaroTree:    taro1Commitment,
	}

	split2Blob, split2Proof, err := AppendTransition(
		transitionBlob, split2Params, MockHeaderVerifier,
	)
	require.NoError(t, err)
	require.Greater(t, len(split2Blob), len(transitionBlob))
	require.Equal(t, splitTxMerkleProof, &split2Proof.TxMerkleProof)
	split2Snapshot := verifyBlob(t, split2Blob)

	require.True(t, split2Snapshot.SplitAsset)
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
		*prevID: prevProof.Asset,
	}

	virtualTx, _, err := taroscript.VirtualTx(newAsset, inputs)
	require.NoError(t, err)
	newWitness := genTaprootKeySpend(
		t, *senderPrivKey, virtualTx, prevProof.Asset, 0,
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

	finalSnapshot, err := f.Verify(context.Background(), MockHeaderVerifier)
	require.NoError(t, err)

	return finalSnapshot
}
