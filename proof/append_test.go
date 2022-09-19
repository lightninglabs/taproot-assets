package proof

import (
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/stretchr/testify/require"
)

func genTaprootKeySpend(t *testing.T, privKey btcec.PrivateKey,
	virtualTx *wire.MsgTx, input *asset.Asset, idx uint32) wire.TxWitness {

	t.Helper()

	virtualTxCopy := taroscript.VirtualTxWithInput(
		virtualTx, input, idx, nil,
	)
	sigHash, err := taroscript.InputKeySpendSigHash(
		virtualTxCopy, input, idx,
	)
	require.NoError(t, err)

	taprootPrivKey := txscript.TweakTaprootPrivKey(&privKey, nil)
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
			)
		})
	}
}

// runAppendTransitionTest runs the test that makes sure a proof can be appended
// to an existing proof for an asset transition of the given type and amount.
func runAppendTransitionTest(t *testing.T, assetType asset.Type, amt uint64,
	withBip86Change bool) {

	// Start with a minted genesis asset.
	genesisProof, senderPrivKey := genRandomGenesisWithProof(
		t, assetType, &amt,
	)
	genesisBlob, err := encodeAsProofFile(&genesisProof)
	require.NoError(t, err)

	// Transfer the asset to a new owner.
	recipientPrivKey := randPrivKey(t)
	newAsset := *genesisProof.Asset.Copy()
	newAsset.ScriptKey = asset.NewScriptKeyBIP0086(
		pubToKeyDesc(recipientPrivKey.PubKey()),
	)
	recipientTaprootInternalKey := schnorrPubKey(t, recipientPrivKey)

	// Sign the new asset over to the recipient.
	signAssetTransfer(t, &genesisProof, &newAsset, senderPrivKey)

	assetCommitment, err := commitment.NewAssetCommitment(&newAsset)
	require.NoError(t, err)
	taroCommitment, err := commitment.NewTaroCommitment(assetCommitment)
	require.NoError(t, err)

	tapscriptRoot := taroCommitment.TapscriptRoot(nil)
	taprootKey := txscript.ComputeTaprootOutputKey(
		recipientTaprootInternalKey, tapscriptRoot[:],
	)
	taprootScript := computeTaprootScript(t, taprootKey)

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
		changeInternalKey = randPrivKey(t).PubKey()
		changeTaprootKey := txscript.ComputeTaprootKeyNoScript(
			changeInternalKey,
		)
		chainTx.TxOut = append(chainTx.TxOut, &wire.TxOut{
			PkScript: computeTaprootScript(t, changeTaprootKey),
			Value:    333,
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
		genesisBlob, transitionParams,
	)
	require.NoError(t, err)
	require.Greater(t, len(transitionBlob), len(genesisBlob))
	require.Equal(t, txMerkleProof, &transitionProof.TxMerkleProof)
}

// signAssetTransfer creates a virtual transaction for an asset transfer and
// signs it with the given sender private key.
func signAssetTransfer(t *testing.T, prevProof *Proof, newAsset *asset.Asset,
	senderPrivKey *btcec.PrivateKey) {

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

	virtualTx, _, err := taroscript.VirtualTx(newAsset, inputs)
	require.NoError(t, err)
	newWitness := genTaprootKeySpend(
		t, *senderPrivKey, virtualTx, &prevProof.Asset, 0,
	)
	require.NoError(t, err)
	newAsset.PrevWitnesses[0].TxWitness = newWitness
}
