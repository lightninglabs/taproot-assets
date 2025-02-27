package proof

import (
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

// TestNewMintingBlobs tests that the NewMintingBlobs creates a valid Taproot
// Asset proof file given valid data.
func TestNewMintingBlobs(t *testing.T) {
	t.Parallel()

	// First, we'll create a fake, but legit looking set of minting params
	// to generate a proof with.
	genesisPrivKey := test.RandPrivKey()
	genesisScriptKey := test.PubToKeyDesc(genesisPrivKey.PubKey())

	// We'll modify the returned genesis to instead commit to some actual
	// metadata (known pre-image).
	var metaBlob [100]byte
	_, err := rand.Read(metaBlob[:])
	require.NoError(t, err)
	metaReveal := &MetaReveal{
		Data: metaBlob[:],
	}
	assetGenesis := asset.RandGenesis(t, asset.Collectible)
	assetGenesis.MetaHash = metaReveal.MetaHash()
	assetGenesis.OutputIndex = 0
	commitVersion := commitment.RandTapCommitVersion()
	tapCommitment, _, err := commitment.Mint(
		commitVersion, assetGenesis, nil, &commitment.AssetDetails{
			Type:             asset.Collectible,
			ScriptKey:        genesisScriptKey,
			Amount:           nil,
			LockTime:         0,
			RelativeLockTime: 0,
		},
	)
	require.NoError(t, err)

	// Add a group anchor with a custom tapscript root to the set of minted
	// assets. We cannot make this type of asset with commitment.Mint, so
	// we create it manually and then insert it into the tap commitment.
	groupedGenesis := asset.RandGenesis(t, asset.Normal)
	groupedGenesis.FirstPrevOut = assetGenesis.FirstPrevOut
	groupedGenesis.MetaHash = metaReveal.MetaHash()
	groupedGenesis.OutputIndex = 0
	groupedAsset := asset.AssetCustomGroupKey(
		t, test.RandBool(), false, false, true, groupedGenesis,
	)

	groupedAssetTree, err := commitment.NewAssetCommitment(groupedAsset)
	require.NoError(t, err)
	err = tapCommitment.Upsert(groupedAssetTree)
	require.NoError(t, err)

	internalKey := test.SchnorrPubKey(t, genesisPrivKey)
	tapscriptRoot := tapCommitment.TapscriptRoot(nil)
	taprootKey := txscript.ComputeTaprootOutputKey(
		internalKey, tapscriptRoot[:],
	)
	taprootScript := test.ComputeTaprootScript(t, taprootKey)

	changeInternalKey := test.RandPrivKey().PubKey()
	changeTaprootKey := txscript.ComputeTaprootKeyNoScript(
		changeInternalKey,
	)

	genesisTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: assetGenesis.FirstPrevOut,
		}},
		TxOut: []*wire.TxOut{{
			PkScript: taprootScript,
			Value:    330,
		}, {
			PkScript: test.ComputeTaprootScript(
				t, changeTaprootKey,
			),
			Value: 333,
		}},
	}

	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(genesisTx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	blockHeader := wire.NewBlockHeader(
		0, chaincfg.MainNetParams.GenesisHash, merkleRoot, 0, 0,
	)

	assetScriptKey := asset.NewScriptKeyBip86(genesisScriptKey)
	metaReveals := map[asset.SerializedKey]*MetaReveal{
		asset.ToSerialized(assetScriptKey.PubKey):         metaReveal,
		asset.ToSerialized(groupedAsset.ScriptKey.PubKey): metaReveal,
	}

	// The NewMintingBlobs will return an error if the generated proof is
	// invalid. We'll also add the optional meta reveal data as well
	_, err = NewMintingBlobs(&MintParams{
		BaseProofParams: BaseProofParams{
			Block: &wire.MsgBlock{
				Header:       *blockHeader,
				Transactions: []*wire.MsgTx{genesisTx},
			},
			Tx:               genesisTx,
			TxIndex:          0,
			OutputIndex:      0,
			InternalKey:      internalKey,
			TaprootAssetRoot: tapCommitment,
			ExclusionProofs: []TaprootProof{{
				OutputIndex: 1,
				InternalKey: changeInternalKey,
				TapscriptProof: &TapscriptProof{
					Bip86: true,
				},
			}},
		},
		GenesisPoint: genesisTx.TxIn[0].PreviousOutPoint,
	}, MockVerifierCtx, WithAssetMetaReveals(metaReveals))
	require.NoError(t, err)
}
