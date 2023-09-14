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
	genesisPrivKey := test.RandPrivKey(t)
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
	protoAsset := asset.AssetNoErr(
		t, assetGenesis, 1, 0, 0,
		asset.NewScriptKeyBip86(genesisScriptKey), nil,
	)

	assetGroupKey := asset.RandGroupKey(t, assetGenesis, protoAsset)
	tapCommitment, _, err := commitment.Mint(
		assetGenesis, assetGroupKey, &commitment.AssetDetails{
			Type:             asset.Collectible,
			ScriptKey:        genesisScriptKey,
			Amount:           nil,
			LockTime:         0,
			RelativeLockTime: 0,
		},
	)
	require.NoError(t, err)

	internalKey := test.SchnorrPubKey(t, genesisPrivKey)
	tapscriptRoot := tapCommitment.TapscriptRoot(nil)
	taprootKey := txscript.ComputeTaprootOutputKey(
		internalKey, tapscriptRoot[:],
	)
	taprootScript := test.ComputeTaprootScript(t, taprootKey)

	changeInternalKey := test.RandPrivKey(t).PubKey()
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

	newAsset := tapCommitment.CommittedAssets()[0]
	assetScriptKey := newAsset.ScriptKey

	metaReveals := map[asset.SerializedKey]*MetaReveal{
		asset.ToSerialized(assetScriptKey.PubKey): metaReveal,
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
	}, MockHeaderVerifier, WithAssetMetaReveals(metaReveals))
	require.NoError(t, err)
}
