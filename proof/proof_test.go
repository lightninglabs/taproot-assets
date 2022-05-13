package proof

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/stretchr/testify/require"
)

var (
	testOutPoint = wire.OutPoint{
		Hash:  *(*[32]byte)(bytes.Repeat([]byte{1}, 32)),
		Index: 1,
	}
)

func randPrivKey(t *testing.T) *btcec.PrivateKey {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return privKey
}

func schnorrPubKey(t *testing.T, privKey *btcec.PrivateKey) *btcec.PublicKey {
	key, err := schnorr.ParsePubKey(schnorr.SerializePubKey(privKey.PubKey()))
	require.NoError(t, err)
	return key
}

func randPubKey(t *testing.T) *btcec.PublicKey {
	return schnorrPubKey(t, randPrivKey(t))
}

func randGenesis(t *testing.T) *asset.Genesis {
	metadata := make([]byte, rand.Uint32()%32+1)
	_, err := rand.Read(metadata)
	require.NoError(t, err)

	return &asset.Genesis{
		FirstPrevOut: testOutPoint,
		Tag:          "kek",
		Metadata:     metadata,
		OutputIndex:  rand.Uint32(),
	}
}

func randFamilyKey(t *testing.T, genesis *asset.Genesis) *asset.FamilyKey {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	familyKey, err := asset.DeriveFamilyKey(privKey, genesis)
	require.NoError(t, err)
	return familyKey
}

func computeTaprootScript(t *testing.T, taprootKey *btcec.PublicKey) []byte {
	script, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(schnorr.SerializePubKey(taprootKey)).
		Script()
	require.NoError(t, err)
	return script
}

func assertEqualCommitmentProof(t *testing.T, expected, actual *CommitmentProof) {
	require.Equal(t, expected.Proof.AssetProof.Version, actual.Proof.AssetProof.Version)
	require.Equal(t, expected.Proof.AssetProof.AssetID, actual.Proof.AssetProof.AssetID)
	require.Equal(t, expected.Proof.AssetProof.Proof, actual.Proof.AssetProof.Proof)
	require.Equal(t, expected.Proof.TaroProof.Version, actual.Proof.TaroProof.Version)
	require.Equal(t, expected.Proof.TaroProof.Proof, actual.Proof.TaroProof.Proof)
	require.Equal(t, expected.TapSiblingPreimage, actual.TapSiblingPreimage)
}

func assertEqualTaprootProof(t *testing.T, expected, actual *TaprootProof) {
	t.Helper()
	require.Equal(t, expected.OutputIndex, actual.OutputIndex)
	require.Equal(t, expected.InternalKey, actual.InternalKey)
	if expected.CommitmentProof == nil {
		require.Nil(t, actual.CommitmentProof)
	} else {
		assertEqualCommitmentProof(
			t, expected.CommitmentProof, actual.CommitmentProof,
		)
	}
	if expected.TapscriptProof == nil {
		require.Nil(t, actual.TapscriptProof)
	} else {
		require.Equal(t, expected.TapscriptProof, actual.TapscriptProof)
	}
}

func assertEqualProof(t *testing.T, expected, actual *Proof) {
	t.Helper()
	require.Equal(t, expected.PrevOut, actual.PrevOut)
	require.Equal(t, expected.BlockHeader, actual.BlockHeader)
	require.Equal(t, expected.AnchorTx, actual.AnchorTx)
	require.Equal(t, expected.TxMerkleProof, actual.TxMerkleProof)
	require.Equal(t, expected.Asset, actual.Asset)
	assertEqualTaprootProof(t, &expected.InclusionProof, &actual.InclusionProof)
	for i := range expected.ExclusionProofs {
		assertEqualTaprootProof(
			t, &expected.ExclusionProofs[i], &actual.ExclusionProofs[i],
		)
	}
	require.Equal(t, expected.ExclusionProofs, actual.ExclusionProofs)
	for i := range expected.AdditionalInputs {
		require.Equal(
			t, expected.AdditionalInputs[i].Version,
			actual.AdditionalInputs[i].Version,
		)
		for j := range expected.AdditionalInputs[i].Proofs {
			assertEqualProof(
				t, &expected.AdditionalInputs[i].Proofs[j],
				&actual.AdditionalInputs[i].Proofs[j],
			)
		}
	}
}

func TestProofEncoding(t *testing.T) {
	t.Parallel()

	txMerkleProof, err := NewTxMerkleProof(oddTxBlock.Transactions, 0)
	require.NoError(t, err)

	genesis := randGenesis(t)
	familyKey := randFamilyKey(t, genesis)
	commitment, assets, err := commitment.Mint(
		genesis, familyKey, &commitment.AssetDetails{
			Type:             asset.Collectible,
			ScriptKey:        *randPubKey(t),
			Amount:           nil,
			LockTime:         1337,
			RelativeLockTime: 6,
		},
	)
	require.NoError(t, err)
	asset := assets[0]
	_, commitmentProof := commitment.Proof(
		asset.TaroCommitmentKey(), asset.AssetCommitmentKey(),
	)

	proof := Proof{
		PrevOut:       testOutPoint,
		BlockHeader:   oddTxBlock.Header,
		AnchorTx:      *oddTxBlock.Transactions[0],
		TxMerkleProof: *txMerkleProof,
		Asset:         *asset,
		InclusionProof: TaprootProof{
			OutputIndex: 1,
			InternalKey: *randPubKey(t),
			CommitmentProof: &CommitmentProof{
				Proof:              *commitmentProof,
				TapSiblingPreimage: []byte{1},
			},
			TapscriptProof: nil,
		},
		ExclusionProofs: []TaprootProof{
			{
				OutputIndex: 2,
				InternalKey: *randPubKey(t),
				CommitmentProof: &CommitmentProof{
					Proof:              *commitmentProof,
					TapSiblingPreimage: []byte{1},
				},
				TapscriptProof: nil,
			},
			{
				OutputIndex:     3,
				InternalKey:     *randPubKey(t),
				CommitmentProof: nil,
				TapscriptProof: &TapscriptProof{
					TapPreimage1: []byte{1},
					TapPreimage2: []byte{2},
				},
			},
		},
		AdditionalInputs: []File{},
	}
	file := File{Version: V0, Proofs: []Proof{proof, proof}}
	proof.AdditionalInputs = []File{file, file}

	var buf bytes.Buffer
	require.NoError(t, proof.Encode(&buf))
	var decodedProof Proof
	require.NoError(t, decodedProof.Decode(&buf))

	assertEqualProof(t, &proof, &decodedProof)
}

func TestGenesisProofVerification(t *testing.T) {
	t.Parallel()

	genesisPrivKey := randPrivKey(t)
	genesisScriptKey := txscript.ComputeTaprootKeyNoScript(
		genesisPrivKey.PubKey(),
	)
	assetGenesis := randGenesis(t)
	assetFamilyKey := randFamilyKey(t, assetGenesis)
	commitment, assets, err := commitment.Mint(
		assetGenesis, assetFamilyKey, &commitment.AssetDetails{
			Type:             asset.Collectible,
			ScriptKey:        *genesisScriptKey,
			Amount:           nil,
			LockTime:         0,
			RelativeLockTime: 0,
		},
	)
	require.NoError(t, err)
	genesisAsset := assets[0]
	_, commitmentProof := commitment.Proof(
		genesisAsset.TaroCommitmentKey(),
		genesisAsset.AssetCommitmentKey(),
	)

	internalKey := schnorrPubKey(t, genesisPrivKey)
	tapscriptRoot := commitment.TapscriptRoot(nil)
	taprootKey := txscript.ComputeTaprootOutputKey(
		internalKey, tapscriptRoot[:],
	)
	taprootScript := computeTaprootScript(t, taprootKey)
	genesisTx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{
			PkScript: taprootScript,
			Value:    330,
		}},
	}
	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(genesisTx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	blockHeader := wire.NewBlockHeader(
		0, chaincfg.MainNetParams.GenesisHash, merkleRoot, 0, 0,
	)

	txMerkleProof, err := NewTxMerkleProof([]*wire.MsgTx{genesisTx}, 0)
	require.NoError(t, err)

	proof := Proof{
		PrevOut:       genesisTx.TxIn[0].PreviousOutPoint,
		BlockHeader:   *blockHeader,
		AnchorTx:      *genesisTx,
		TxMerkleProof: *txMerkleProof,
		Asset:         *genesisAsset,
		InclusionProof: TaprootProof{
			OutputIndex: 0,
			InternalKey: *internalKey,
			CommitmentProof: &CommitmentProof{
				Proof:              *commitmentProof,
				TapSiblingPreimage: nil,
			},
			TapscriptProof: nil,
		},
		ExclusionProofs:  nil,
		AdditionalInputs: nil,
	}
	_, err = proof.Verify(nil)
	require.NoError(t, err)
}
