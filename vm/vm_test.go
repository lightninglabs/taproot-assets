package vm

import (
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

func randKey(t *testing.T) *btcec.PrivateKey {
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return key
}

func randGenesis(t *testing.T, assetType asset.Type) asset.Genesis {
	return asset.Genesis{
		FirstPrevOut: wire.OutPoint{},
		Tag:          "",
		Metadata:     nil,
		OutputIndex:  rand.Uint32(),
		Type:         assetType,
	}
}

func randFamilyKey(t *testing.T, genesis asset.Genesis) *asset.FamilyKey {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	genSigner := asset.NewRawKeyGenesisSigner(privKey)

	familyKey, err := asset.DeriveFamilyKey(
		genSigner, toKeyDesc(privKey.PubKey()), genesis,
	)
	require.NoError(t, err)

	return familyKey
}

func toKeyDesc(p *btcec.PublicKey) keychain.KeyDescriptor {
	return keychain.KeyDescriptor{
		PubKey: p,
	}
}

func randAsset(t *testing.T, assetType asset.Type,
	scriptKey btcec.PublicKey) *asset.Asset {

	t.Helper()

	genesis := randGenesis(t, assetType)
	familyKey := randFamilyKey(t, genesis)

	var units uint64
	switch assetType {
	case asset.Normal:
		units = rand.Uint64() + 1

	case asset.Collectible:
		units = 1

	default:
		t.Fatal("unhandled asset type", assetType)
		return nil // unreachable
	}

	a, err := asset.New(
		genesis, units, 0, 0, asset.NewScriptKey(&scriptKey), familyKey,
	)
	require.NoError(t, err)
	return a
}

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

func genTaprootScriptSpend(t *testing.T, privKey btcec.PrivateKey,
	virtualTx *wire.MsgTx, input *asset.Asset, idx uint32,
	tapTree *txscript.IndexedTapScriptTree,
	tapLeaf *txscript.TapLeaf) wire.TxWitness {

	t.Helper()

	leafProof := tapTree.
		LeafMerkleProofs[tapTree.LeafProofIndex[tapLeaf.TapHash()]]
	controlBlock := leafProof.ToControlBlock(privKey.PubKey())
	controlBlockBytes, err := controlBlock.ToBytes()
	require.NoError(t, err)

	virtualTxCopy := taroscript.VirtualTxWithInput(virtualTx, input, idx, nil)
	sigHash, err := taroscript.InputScriptSpendSigHash(
		virtualTxCopy, input, idx, tapLeaf,
	)
	require.NoError(t, err)
	sig, err := schnorr.Sign(&privKey, sigHash)
	require.NoError(t, err)

	return wire.TxWitness{sig.Serialize(), tapLeaf.Script, controlBlockBytes}
}

type stateTransitionFunc = func(t *testing.T) (*asset.Asset,
	commitment.SplitSet, commitment.InputSet)

func genesisStateTransition(t *testing.T, assetType asset.Type,
	valid bool) stateTransitionFunc {

	return func(t *testing.T) (*asset.Asset, commitment.SplitSet,
		commitment.InputSet) {

		scriptKey := randKey(t).PubKey()
		a := randAsset(t, assetType, *scriptKey)

		if assetType == asset.Collectible && !valid {
			inputSet := commitment.InputSet{asset.PrevID{}: a.Copy()}
			return a, nil, inputSet
		}

		if assetType == asset.Normal && !valid {
			splitSet := commitment.SplitSet{
				commitment.SplitLocator{}: &commitment.SplitAsset{},
			}
			return a, splitSet, nil
		}

		return a, nil, nil
	}
}

func collectibleStateTransition(t *testing.T) (*asset.Asset,
	commitment.SplitSet, commitment.InputSet) {

	privKey := randKey(t)
	scriptKey := txscript.ComputeTaprootKeyNoScript(privKey.PubKey())

	genesisOutPoint := wire.OutPoint{}
	genesisAsset := randAsset(t, asset.Collectible, *scriptKey)

	prevID := &asset.PrevID{
		OutPoint:  genesisOutPoint,
		ID:        genesisAsset.Genesis.ID(),
		ScriptKey: asset.ToSerialized(genesisAsset.ScriptKey.PubKey),
	}
	newAsset := genesisAsset.Copy()
	newAsset.ScriptKey = asset.NewScriptKey(randKey(t).PubKey())
	newAsset.PrevWitnesses = []asset.Witness{{
		PrevID:          prevID,
		TxWitness:       nil,
		SplitCommitment: nil,
	}}

	inputs := commitment.InputSet{*prevID: genesisAsset}
	virtualTx, _, err := taroscript.VirtualTx(newAsset, inputs)
	require.NoError(t, err)
	newWitness := genTaprootKeySpend(
		t, *privKey, virtualTx, genesisAsset, 0,
	)
	require.NoError(t, err)
	newAsset.PrevWitnesses[0].TxWitness = newWitness

	return newAsset, nil, inputs
}

// TODO(roasbeef): need to add 1:1 spend
func normalStateTransition(t *testing.T) (*asset.Asset, commitment.SplitSet,
	commitment.InputSet) {

	privKey1 := randKey(t)
	scriptKey1 := txscript.ComputeTaprootKeyNoScript(privKey1.PubKey())

	const csv = 6
	privKey2 := randKey(t)
	leafScript, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(privKey2.PubKey())).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddInt64(csv).
		AddOp(txscript.OP_CHECKSEQUENCEVERIFY).
		Script()
	require.NoError(t, err)
	tapLeaf := txscript.NewBaseTapLeaf(leafScript)
	tapTree := txscript.AssembleTaprootScriptTree(tapLeaf)
	tapTreeRoot := tapTree.RootNode.TapHash()
	scriptKey2 := txscript.ComputeTaprootOutputKey(
		privKey2.PubKey(), tapTreeRoot[:],
	)

	genesisOutPoint := wire.OutPoint{}
	genesisAsset1 := randAsset(t, asset.Normal, *scriptKey1)
	genesisAsset2 := randAsset(t, asset.Normal, *scriptKey2)
	genesisAsset2.RelativeLockTime = csv

	prevID1 := &asset.PrevID{
		OutPoint:  genesisOutPoint,
		ID:        genesisAsset1.Genesis.ID(),
		ScriptKey: asset.ToSerialized(genesisAsset1.ScriptKey.PubKey),
	}
	prevID2 := &asset.PrevID{
		OutPoint:  genesisOutPoint,
		ID:        genesisAsset2.Genesis.ID(),
		ScriptKey: asset.ToSerialized(genesisAsset2.ScriptKey.PubKey),
	}

	newAsset := genesisAsset1.Copy()
	newAsset.Amount = genesisAsset1.Amount + genesisAsset2.Amount
	newAsset.ScriptKey = asset.NewScriptKey(randKey(t).PubKey())
	newAsset.PrevWitnesses = []asset.Witness{{
		PrevID:          prevID1,
		TxWitness:       nil,
		SplitCommitment: nil,
	}, {
		PrevID:          prevID2,
		TxWitness:       nil,
		SplitCommitment: nil,
	}}

	inputs := commitment.InputSet{
		*prevID1: genesisAsset1,
		*prevID2: genesisAsset2,
	}
	virtualTx, _, err := taroscript.VirtualTx(newAsset, inputs)
	require.NoError(t, err)
	newWitness := genTaprootKeySpend(
		t, *privKey1, virtualTx, genesisAsset1, 0,
	)
	require.NoError(t, err)
	newAsset.PrevWitnesses[0].TxWitness = newWitness
	newAsset.PrevWitnesses[1].TxWitness = genTaprootScriptSpend(
		t, *privKey2, virtualTx, genesisAsset2, 1, tapTree, &tapLeaf,
	)

	return newAsset, nil, inputs
}

func splitStateTransition(t *testing.T) (*asset.Asset, commitment.SplitSet,
	commitment.InputSet) {

	privKey := randKey(t)
	scriptKey := txscript.ComputeTaprootKeyNoScript(privKey.PubKey())

	genesisOutPoint := wire.OutPoint{}
	genesisAsset := randAsset(t, asset.Normal, *scriptKey)
	genesisAsset.Amount = 3

	assetID := genesisAsset.Genesis.ID()
	rootLocator := &commitment.SplitLocator{
		OutputIndex: 0,
		AssetID:     assetID,
		ScriptKey:   asset.ToSerialized(genesisAsset.ScriptKey.PubKey),
		Amount:      1,
	}
	externalLocators := []*commitment.SplitLocator{{
		OutputIndex: 1,
		AssetID:     assetID,
		ScriptKey:   asset.ToSerialized(randKey(t).PubKey()),
		Amount:      1,
	}, {

		OutputIndex: 2,
		AssetID:     assetID,
		ScriptKey:   asset.ToSerialized(randKey(t).PubKey()),
		Amount:      1,
	}}
	splitCommitment, err := commitment.NewSplitCommitment(
		genesisAsset, genesisOutPoint, rootLocator, externalLocators...,
	)
	require.NoError(t, err)

	virtualTx, _, err := taroscript.VirtualTx(
		splitCommitment.RootAsset, splitCommitment.PrevAssets,
	)
	require.NoError(t, err)
	newWitness := genTaprootKeySpend(
		t, *privKey, virtualTx, genesisAsset, 0,
	)
	require.NoError(t, err)
	splitCommitment.RootAsset.PrevWitnesses[0].TxWitness = newWitness

	return splitCommitment.RootAsset, splitCommitment.SplitAssets,
		splitCommitment.PrevAssets
}

func TestVM(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		f    stateTransitionFunc
		err  error
	}{
		{
			name: "collectible genesis",
			f:    genesisStateTransition(t, asset.Collectible, true),
			err:  nil,
		},
		{
			name: "invalid collectible genesis",
			f:    genesisStateTransition(t, asset.Collectible, false),
			err:  newErrKind(ErrInvalidGenesisStateTransition),
		},
		{
			name: "normal genesis",
			f:    genesisStateTransition(t, asset.Normal, true),
			err:  nil,
		},
		{
			name: "invalid normal genesis",
			f:    genesisStateTransition(t, asset.Normal, false),
			err:  newErrKind(ErrInvalidGenesisStateTransition),
		},
		{
			name: "collectible state transition",
			f:    collectibleStateTransition,
			err:  nil,
		},
		{
			name: "normal state transition",
			f:    normalStateTransition,
			err:  nil,
		},
		{
			name: "split state transition",
			f:    splitStateTransition,
			err:  nil,
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			newAsset, splitSet, inputSet := testCase.f(t)
			verify := func(splitAsset *commitment.SplitAsset) {
				vm, err := New(newAsset, splitAsset, inputSet)
				if err != nil {
					if testCase.err != nil {
						require.Equal(
							t, testCase.err, err,
						)
					} else {
						t.Fatal(err)
					}
				}
				err = vm.Execute()
				require.Equal(t, testCase.err, err)
			}
			if len(splitSet) == 0 {
				verify(nil)
				return
			}
			for _, splitAsset := range splitSet {
				verify(splitAsset)
			}
		})
		if !success {
			return
		}
	}
}
