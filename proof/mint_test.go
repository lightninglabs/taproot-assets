package proof

import (
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/stretchr/testify/require"
)

// TestNewMintingBlobs tests that the NewMintingBlobs creates a valid taro
// proof file given valid data.
func TestNewMintingBlobs(t *testing.T) {
	t.Parallel()

	// First, we'll create a fake, but legit looking set of minting params
	// to generate a proof with.
	genesisPrivKey := randPrivKey(t)
	genesisScriptKey := txscript.ComputeTaprootKeyNoScript(
		genesisPrivKey.PubKey(),
	)
	assetGenesis := randGenesis(t, asset.Collectible)
	assetFamilyKey := randFamilyKey(t, assetGenesis)
	commitment, _, err := commitment.Mint(
		*assetGenesis, assetFamilyKey, &commitment.AssetDetails{
			Type:             asset.Collectible,
			ScriptKey:        pubToKeyDesc(genesisScriptKey),
			Amount:           nil,
			LockTime:         0,
			RelativeLockTime: 0,
		},
	)
	require.NoError(t, err)

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

	// The NewMintingBlobs will return an error if the generated proof is
	// invalid.
	_, err = NewMintingBlobs(&MintParams{
		BaseProofParams: BaseProofParams{
			Block: &wire.MsgBlock{
				Header:       *blockHeader,
				Transactions: []*wire.MsgTx{genesisTx},
			},
			Tx:          genesisTx,
			TxIndex:     0,
			OutputIndex: 0,
			InternalKey: internalKey,
			TaroRoot:    commitment,
		},
		GenesisPoint: genesisTx.TxIn[0].PreviousOutPoint,
	})
	require.NoError(t, err)
}
