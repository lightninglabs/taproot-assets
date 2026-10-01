package proof

import (
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/vm"
	"github.com/stretchr/testify/require"
)

// TestTransitionAssetIdentity ensures that a proof file only verifies if its
// transitions preserve the asset ID and group key of the asset. Each
// transition is validly signed and anchored, and only differs from an honest
// transfer in the genesis or group key the new asset claims.
func TestTransitionAssetIdentity(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		alter func(a *asset.Asset, gen asset.Genesis,
			groupKey *asset.GroupKey)
		err error
	}{{
		name: "same asset",
		alter: func(*asset.Asset, asset.Genesis,
			*asset.GroupKey) {
		},
	}, {
		name: "foreign asset id within group",
		alter: func(a *asset.Asset, gen asset.Genesis,
			_ *asset.GroupKey) {

			a.Genesis = gen
		},
		err: vm.Error{Kind: vm.ErrIDMismatch},
	}, {
		name: "foreign ungrouped asset",
		alter: func(a *asset.Asset, gen asset.Genesis,
			_ *asset.GroupKey) {

			a.Genesis = gen
			a.GroupKey = nil
		},
		err: vm.Error{Kind: vm.ErrIDMismatch},
	}, {
		name: "foreign grouped asset",
		alter: func(a *asset.Asset, gen asset.Genesis,
			groupKey *asset.GroupKey) {

			a.Genesis = gen
			a.GroupKey = groupKey
		},
		err: vm.Error{Kind: vm.ErrIDMismatch},
	}, {
		name: "foreign group key",
		alter: func(a *asset.Asset, _ asset.Genesis,
			groupKey *asset.GroupKey) {

			a.GroupKey = groupKey
		},
		err: vm.Error{Kind: vm.ErrIDMismatch},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			amt := uint64(100)
			genesisProof, privKey := genRandomGenesisWithProof(
				t, asset.Normal, &amt, nil, true, nil, nil, nil,
				nil, asset.V0,
			)
			genesisBlob, err := EncodeAsProofFile(&genesisProof)
			require.NoError(t, err)

			newAsset := genesisProof.Asset.Copy()
			otherGen := asset.RandGenesis(t, asset.Normal)
			otherGroupKey := asset.RandGroupKey(
				t, otherGen, asset.NewAssetNoErr(
					t, otherGen, amt, 0, 0,
					newAsset.ScriptKey, nil,
				),
			)
			tc.alter(newAsset, otherGen, otherGroupKey)

			_, _, err = appendSignedTransition(
				t, genesisBlob, &genesisProof, newAsset,
				privKey,
			)
			require.ErrorIs(t, err, tc.err)
		})
	}
}

// appendSignedTransition signs a full value transfer of the asset of the
// previous proof into the given new asset, anchors it together with the STXO
// of its input, and appends the resulting transition to the proof file.
func appendSignedTransition(t *testing.T, blob Blob, prevProof *Proof,
	newAsset *asset.Asset, senderPrivKey *btcec.PrivateKey) (Blob, *Proof,
	error) {

	newAsset.ScriptKey = asset.NewScriptKeyBip86(
		test.PubToKeyDesc(test.RandPrivKey().PubKey()),
	)
	signAssetTransfer(t, prevProof, newAsset, senderPrivKey, nil)

	assetCommitment, err := commitment.NewAssetCommitment(newAsset)
	require.NoError(t, err)
	tapCommitment, err := commitment.NewTapCommitment(nil, assetCommitment)
	require.NoError(t, err)

	stxoAsset, err := asset.MakeSpentAsset(newAsset.PrevWitnesses[0])
	require.NoError(t, err)
	err = tapCommitment.MergeAltLeaves(
		asset.ToAltLeaves([]*asset.Asset{stxoAsset}),
	)
	require.NoError(t, err)

	internalKey := test.SchnorrPubKey(t, test.RandPrivKey())
	tapscriptRoot := tapCommitment.TapscriptRoot(nil)
	taprootKey := txscript.ComputeTaprootOutputKey(
		internalKey, tapscriptRoot[:],
	)

	chainTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  prevProof.AnchorTx.TxHash(),
				Index: 0,
			},
		}},
		TxOut: []*wire.TxOut{{
			PkScript: test.ComputeTaprootScript(t, taprootKey),
			Value:    330,
		}},
	}

	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(chainTx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	prevHash := prevProof.BlockHeader.BlockHash()
	blockHeader := wire.NewBlockHeader(0, &prevHash, merkleRoot, 0, 0)

	params := &TransitionParams{
		BaseProofParams: BaseProofParams{
			Block: &wire.MsgBlock{
				Header:       *blockHeader,
				Transactions: []*wire.MsgTx{chainTx},
			},
			Tx:               chainTx,
			TxIndex:          0,
			OutputIndex:      0,
			InternalKey:      internalKey,
			TaprootAssetRoot: tapCommitment,
		},
		NewAsset: newAsset,
	}

	return AppendTransition(
		blob, params, MockVerifierCtx, WithVersion(TransitionV1),
	)
}
