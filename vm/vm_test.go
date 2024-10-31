package vm

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

var (
	generatedTestVectorName = "vm_validation_generated.json"
	errorTestVectorName     = "vm_validation_generated_error_cases.json"

	allTestVectorFiles = []string{
		generatedTestVectorName,
		errorTestVectorName,
	}

	invalidHashLockErr = newErrInner(
		ErrInvalidTransferWitness, txscript.Error{
			ErrorCode:   txscript.ErrEqualVerify,
			Description: "OP_EQUALVERIFY failed",
		},
	)
	invalidSigErr = newErrInner(
		ErrInvalidTransferWitness, txscript.Error{
			ErrorCode: txscript.ErrNullFail,
			Description: "signature not empty on " +
				"failed checksig",
		},
	)
	cleanStackErr = newErrInner(
		ErrInvalidTransferWitness, txscript.Error{
			ErrorCode: txscript.ErrCleanStack,
			Description: "stack must contain exactly " +
				"one item (contains 2)",
		},
	)

	// mockInputTxBlockHeight is the block height the mock returns for an
	// input transaction, when checking CSV time locks.
	mockInputTxBlockHeight = uint32(234)

	// mockChainLookupMeantime is a Unix timestamp in seconds that
	// represents the time 2024-06-09T17:46:43Z.
	mockChainLookupMeanTime int64 = 1_717_955_203
)

func randAsset(t *testing.T, assetType asset.Type,
	scriptKeyPub *btcec.PublicKey) *asset.Asset {

	t.Helper()

	genesis := asset.RandGenesis(t, assetType)
	scriptKey := asset.NewScriptKey(scriptKeyPub)
	protoAsset := asset.RandAssetWithValues(t, genesis, nil, scriptKey)
	groupKey := asset.RandGroupKey(t, genesis, protoAsset)

	return asset.NewAssetNoErr(
		t, genesis, protoAsset.Amount, protoAsset.LockTime,
		protoAsset.RelativeLockTime, scriptKey, groupKey,
		asset.WithAssetVersion(protoAsset.Version),
	)
}

func genTaprootKeySpend(t *testing.T, privKey btcec.PrivateKey,
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

func genTaprootScriptSpend(t *testing.T, privKey btcec.PrivateKey,
	virtualTx *wire.MsgTx, input, newAsset *asset.Asset, idx uint32,
	sigHashType txscript.SigHashType, controlBlock *txscript.ControlBlock,
	tapLeaf *txscript.TapLeaf, scriptWitness []byte) wire.TxWitness {

	t.Helper()

	controlBlockBytes, err := controlBlock.ToBytes()
	require.NoError(t, err)

	if scriptWitness == nil {
		virtualTxCopy := asset.VirtualTxWithInput(
			virtualTx, newAsset.LockTime, newAsset.RelativeLockTime,
			idx, nil,
		)
		sigHash, err := tapscript.InputScriptSpendSigHash(
			virtualTxCopy, input, newAsset, idx, sigHashType,
			tapLeaf,
		)
		require.NoError(t, err)

		sig, err := schnorr.Sign(&privKey, sigHash)
		require.NoError(t, err)

		scriptWitness = sig.Serialize()
		if sigHashType != txscript.SigHashDefault {
			scriptWitness = append(scriptWitness, byte(sigHashType))
		}
	}

	return wire.TxWitness{
		scriptWitness, tapLeaf.Script, controlBlockBytes,
	}
}

type stateTransitionFunc = func(t *testing.T) (*asset.Asset,
	commitment.SplitSet, commitment.InputSet, uint32)

func genesisStateTransition(assetType asset.Type,
	valid, grouped bool) stateTransitionFunc {

	return func(t *testing.T) (*asset.Asset, commitment.SplitSet,
		commitment.InputSet, uint32) {

		var (
			inputSet commitment.InputSet
			splitSet commitment.SplitSet
			a        = asset.RandAsset(t, assetType)
		)

		if !grouped {
			a = asset.NewAssetNoErr(
				t, a.Genesis, a.Amount, a.LockTime,
				a.RelativeLockTime, a.ScriptKey, nil,
				asset.WithAssetVersion(a.Version),
			)
		}

		if !valid && assetType == asset.Collectible {
			inputSet = commitment.InputSet{
				asset.PrevID{}: a.Copy(),
			}
		}

		if !valid && assetType == asset.Normal {
			splitSet = commitment.SplitSet{
				{}: &commitment.SplitAsset{},
			}
		}

		return a, splitSet, inputSet, 0
	}
}

func invalidGenesisStateTransitionWitness(assetType asset.Type,
	grouped bool) stateTransitionFunc {

	return func(t *testing.T) (*asset.Asset, commitment.SplitSet,
		commitment.InputSet, uint32) {

		a := asset.RandAsset(t, assetType)
		if grouped {
			a.PrevWitnesses[0].TxWitness = nil

			return a, nil, nil, 0
		}

		a.GroupKey = nil

		return a, nil, nil, 0
	}
}

func collectibleStateTransition(t *testing.T) (*asset.Asset,
	commitment.SplitSet, commitment.InputSet, uint32) {

	privKey := test.RandPrivKey()
	scriptKey := txscript.ComputeTaprootKeyNoScript(privKey.PubKey())

	genesisOutPoint := wire.OutPoint{}
	genesisAsset := randAsset(t, asset.Collectible, scriptKey)

	prevID := &asset.PrevID{
		OutPoint:  genesisOutPoint,
		ID:        genesisAsset.Genesis.ID(),
		ScriptKey: asset.ToSerialized(genesisAsset.ScriptKey.PubKey),
	}
	newAsset := genesisAsset.Copy()
	newAsset.ScriptKey = asset.NewScriptKey(test.RandPrivKey().PubKey())
	newAsset.PrevWitnesses = []asset.Witness{{
		PrevID:          prevID,
		TxWitness:       nil,
		SplitCommitment: nil,
	}}

	inputs := commitment.InputSet{*prevID: genesisAsset}
	virtualTx, _, err := tapscript.VirtualTx(newAsset, inputs)
	require.NoError(t, err)
	newWitness := genTaprootKeySpend(
		t, *privKey, virtualTx, genesisAsset, newAsset, 0,
	)
	require.NoError(t, err)
	newAsset.PrevWitnesses[0].TxWitness = newWitness

	return newAsset, nil, inputs, 0
}

// genNormalStateTransition returns a state transition function that creates a
// normal state transition that the vm will evaluate at block height
// `currentHeight`.
func genNormalStateTransition(currentHeight uint32, sequence,
	lockTime uint64, addCsvScript, addCltvScript bool) stateTransitionFunc {

	return func(t *testing.T) (*asset.Asset, commitment.SplitSet,
		commitment.InputSet, uint32) {

		return normalStateTransition(
			t, currentHeight, sequence, lockTime, addCsvScript,
			addCltvScript,
		)
	}
}

func normalStateTransition(t *testing.T, currentHeight uint32, sequence,
	lockTime uint64, addCsvScript, addCltvScript bool) (*asset.Asset,
	commitment.SplitSet, commitment.InputSet, uint32) {

	privKey1 := test.RandPrivKey()
	scriptKey1 := txscript.ComputeTaprootKeyNoScript(
		privKey1.PubKey(),
	)

	privKey2 := test.RandPrivKey()
	builder := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(privKey2.PubKey())).
		AddOp(txscript.OP_CHECKSIG)
	if addCsvScript {
		builder = builder.AddOp(txscript.OP_DROP).
			AddInt64(int64(sequence)).
			AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	}
	if addCltvScript {
		builder = builder.AddOp(txscript.OP_DROP).
			AddInt64(int64(lockTime)).
			AddOp(txscript.OP_CHECKLOCKTIMEVERIFY)
	}

	leafScript, err := builder.Script()
	require.NoError(t, err)

	tapLeaf := txscript.NewBaseTapLeaf(leafScript)
	tapTree := txscript.AssembleTaprootScriptTree(tapLeaf)
	tapTreeRoot := tapTree.RootNode.TapHash()
	scriptKey2 := txscript.ComputeTaprootOutputKey(
		privKey2.PubKey(), tapTreeRoot[:],
	)

	genesisOutPoint := wire.OutPoint{}
	genesisAsset1 := randAsset(t, asset.Normal, scriptKey1)
	genesisAsset2 := randAsset(t, asset.Normal, scriptKey2)

	prevID1 := &asset.PrevID{
		OutPoint: genesisOutPoint,
		ID:       genesisAsset1.Genesis.ID(),
		ScriptKey: asset.ToSerialized(
			genesisAsset1.ScriptKey.PubKey,
		),
	}
	prevID2 := &asset.PrevID{
		OutPoint: genesisOutPoint,
		ID:       genesisAsset2.Genesis.ID(),
		ScriptKey: asset.ToSerialized(
			genesisAsset2.ScriptKey.PubKey,
		),
	}

	newAsset := genesisAsset1.Copy()
	newAsset.Amount = genesisAsset1.Amount + genesisAsset2.Amount
	newAsset.ScriptKey = asset.NewScriptKey(test.RandPubKey(t))
	newAsset.PrevWitnesses = []asset.Witness{{
		PrevID:          prevID1,
		TxWitness:       nil,
		SplitCommitment: nil,
	}, {
		PrevID:          prevID2,
		TxWitness:       nil,
		SplitCommitment: nil,
	}}

	if sequence > 0 {
		newAsset.RelativeLockTime = sequence
	}
	if lockTime > 0 {
		newAsset.LockTime = lockTime
	}

	inputs := commitment.InputSet{
		*prevID1: genesisAsset1,
		*prevID2: genesisAsset2,
	}
	virtualTx, _, err := tapscript.VirtualTx(newAsset, inputs)
	require.NoError(t, err)
	newWitness := genTaprootKeySpend(
		t, *privKey1, virtualTx, genesisAsset1, newAsset, 0,
	)
	require.NoError(t, err)
	newAsset.PrevWitnesses[0].TxWitness = newWitness

	leafIdx := tapTree.LeafProofIndex[tapLeaf.TapHash()]
	leafProof := tapTree.LeafMerkleProofs[leafIdx]
	controlBlock := leafProof.ToControlBlock(privKey2.PubKey())

	newAsset.PrevWitnesses[1].TxWitness = genTaprootScriptSpend(
		t, *privKey2, virtualTx, genesisAsset2, newAsset, 1,
		txscript.SigHashDefault, &controlBlock, &tapLeaf, nil,
	)

	return newAsset, nil, inputs, currentHeight
}

// genCustomScriptStateTransition returns a state transition function that
// creates a normal state transition that the vm will evaluate at block height
// `currentHeight`.
func genCustomScriptStateTransition(currentHeight uint32, sequence,
	lockTime uint64, tapLeaf txscript.TapLeaf) stateTransitionFunc {

	return func(t *testing.T) (*asset.Asset, commitment.SplitSet,
		commitment.InputSet, uint32) {

		return customScriptStateTransition(
			t, currentHeight, sequence, lockTime, tapLeaf,
		)
	}
}

func customScriptStateTransition(t *testing.T, currentHeight uint32, sequence,
	lockTime uint64, tapLeaf txscript.TapLeaf) (*asset.Asset,
	commitment.SplitSet, commitment.InputSet, uint32) {

	privKey := test.RandPrivKey()
	tapTree := txscript.AssembleTaprootScriptTree(tapLeaf)
	tapTreeRoot := tapTree.RootNode.TapHash()
	scriptKey := txscript.ComputeTaprootOutputKey(
		privKey.PubKey(), tapTreeRoot[:],
	)

	genesisOutPoint := wire.OutPoint{}
	genesisAsset := randAsset(t, asset.Normal, scriptKey)

	prevID := &asset.PrevID{
		OutPoint: genesisOutPoint,
		ID:       genesisAsset.Genesis.ID(),
		ScriptKey: asset.ToSerialized(
			genesisAsset.ScriptKey.PubKey,
		),
	}

	newAsset := genesisAsset.Copy()
	newAsset.Amount = genesisAsset.Amount
	newAsset.ScriptKey = asset.NewScriptKey(test.RandPubKey(t))
	newAsset.PrevWitnesses = []asset.Witness{{
		PrevID:          prevID,
		TxWitness:       nil,
		SplitCommitment: nil,
	}}

	if sequence > 0 {
		newAsset.RelativeLockTime = sequence
	}
	if lockTime > 0 {
		newAsset.LockTime = lockTime
	}

	inputs := commitment.InputSet{
		*prevID: genesisAsset,
	}

	leafIdx := tapTree.LeafProofIndex[tapLeaf.TapHash()]
	leafProof := tapTree.LeafMerkleProofs[leafIdx]
	controlBlock := leafProof.ToControlBlock(privKey.PubKey())
	controlBlockBytes, err := controlBlock.ToBytes()
	require.NoError(t, err)

	newWitness := [][]byte{
		tapLeaf.Script, controlBlockBytes,
	}
	require.NoError(t, err)

	newAsset.PrevWitnesses[0].TxWitness = newWitness

	return newAsset, nil, inputs, currentHeight
}

func splitStateTransition(t *testing.T) (*asset.Asset, commitment.SplitSet,
	commitment.InputSet, uint32) {

	privKey := test.RandPrivKey()
	scriptKey := txscript.ComputeTaprootKeyNoScript(privKey.PubKey())

	genesisOutPoint := wire.OutPoint{}
	genesisAsset := randAsset(t, asset.Normal, scriptKey)
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
		ScriptKey:   asset.RandSerializedKey(t),
		Amount:      1,
	}, {
		OutputIndex: 2,
		AssetID:     assetID,
		ScriptKey:   asset.RandSerializedKey(t),
		Amount:      1,
	}}
	inputs := []commitment.SplitCommitmentInput{{
		Asset:    genesisAsset,
		OutPoint: genesisOutPoint,
	}}
	splitCommitment, err := commitment.NewSplitCommitment(
		context.Background(), inputs, rootLocator,
		externalLocators...,
	)
	require.NoError(t, err)

	virtualTx, _, err := tapscript.VirtualTx(
		splitCommitment.RootAsset, splitCommitment.PrevAssets,
	)
	require.NoError(t, err)
	newWitness := genTaprootKeySpend(
		t, *privKey, virtualTx, genesisAsset, splitCommitment.RootAsset,
		0,
	)
	require.NoError(t, err)
	splitCommitment.RootAsset.PrevWitnesses[0].TxWitness = newWitness

	return splitCommitment.RootAsset, splitCommitment.SplitAssets,
		splitCommitment.PrevAssets, 0
}

func splitFullValueStateTransition(validRootLocator,
	validRoot bool) stateTransitionFunc {

	return func(t *testing.T) (*asset.Asset, commitment.SplitSet,
		commitment.InputSet, uint32) {

		privKey := test.RandPrivKey()
		scriptKey := txscript.ComputeTaprootKeyNoScript(privKey.PubKey())

		genesisOutPoint := wire.OutPoint{}
		genesisAsset := randAsset(t, asset.Normal, scriptKey)
		genesisAsset.Amount = 3

		assetID := genesisAsset.Genesis.ID()
		rootLocator := &commitment.SplitLocator{
			OutputIndex: 0,
			AssetID:     assetID,
			ScriptKey:   asset.NUMSCompressedKey,
			Amount:      0,
		}
		externalLocators := []*commitment.SplitLocator{{
			OutputIndex: 1,
			AssetID:     assetID,
			ScriptKey:   asset.RandSerializedKey(t),
			Amount:      3,
		}}
		inputs := []commitment.SplitCommitmentInput{{
			Asset:    genesisAsset,
			OutPoint: genesisOutPoint,
		}}
		splitCommitment, err := commitment.NewSplitCommitment(
			context.Background(), inputs, rootLocator,
			externalLocators...,
		)
		require.NoError(t, err)

		if !validRoot {
			splitCommitment.RootAsset.ScriptKey =
				asset.NewScriptKey(genesisAsset.ScriptKey.PubKey)
		}

		if !validRootLocator {
			splitCommitment.SplitAssets[*rootLocator].Asset.ScriptKey =
				genesisAsset.ScriptKey
		}

		virtualTx, _, err := tapscript.VirtualTx(
			splitCommitment.RootAsset, splitCommitment.PrevAssets,
		)
		require.NoError(t, err)
		newWitness := genTaprootKeySpend(
			t, *privKey, virtualTx, genesisAsset,
			splitCommitment.RootAsset, 0,
		)
		require.NoError(t, err)
		splitCommitment.RootAsset.PrevWitnesses[0].TxWitness = newWitness

		return splitCommitment.RootAsset, splitCommitment.SplitAssets,
			splitCommitment.PrevAssets, 0
	}
}

func splitCollectibleStateTransition(validRoot bool) stateTransitionFunc {
	return func(t *testing.T) (*asset.Asset, commitment.SplitSet,
		commitment.InputSet, uint32) {

		privKey := test.RandPrivKey()
		scriptKey := txscript.ComputeTaprootKeyNoScript(privKey.PubKey())

		genesisOutPoint := wire.OutPoint{}
		genesisAsset := randAsset(t, asset.Collectible, scriptKey)

		assetID := genesisAsset.Genesis.ID()
		rootLocator := &commitment.SplitLocator{
			OutputIndex: 0,
			AssetID:     assetID,
			ScriptKey:   asset.NUMSCompressedKey,
			Amount:      0,
		}
		externalLocators := []*commitment.SplitLocator{{
			OutputIndex: 1,
			AssetID:     assetID,
			ScriptKey:   asset.RandSerializedKey(t),
			Amount:      genesisAsset.Amount,
		}}
		inputs := []commitment.SplitCommitmentInput{{
			Asset:    genesisAsset,
			OutPoint: genesisOutPoint,
		}}
		splitCommitment, err := commitment.NewSplitCommitment(
			context.Background(), inputs, rootLocator,
			externalLocators...,
		)
		require.NoError(t, err)

		virtualTx, _, err := tapscript.VirtualTx(
			splitCommitment.RootAsset, splitCommitment.PrevAssets,
		)
		require.NoError(t, err)
		newWitness := genTaprootKeySpend(
			t, *privKey, virtualTx, genesisAsset,
			splitCommitment.RootAsset, 0,
		)
		require.NoError(t, err)
		splitCommitment.RootAsset.PrevWitnesses[0].TxWitness = newWitness

		if !validRoot {
			splitCommitment.RootAsset.Type = asset.Normal
		}

		return splitCommitment.RootAsset, splitCommitment.SplitAssets,
			splitCommitment.PrevAssets, 0
	}
}

func groupAnchorStateTransition(useHashLock, BIP86, keySpend, valid bool,
	assetType asset.Type) stateTransitionFunc {

	return func(t *testing.T) (*asset.Asset, commitment.SplitSet,
		commitment.InputSet, uint32) {

		gen := asset.RandGenesis(t, assetType)
		return asset.AssetCustomGroupKey(
			t, useHashLock, BIP86, keySpend, valid, gen,
		), nil, nil, 0
	}
}

func scriptTreeSpendStateTransition(t *testing.T, useHashLock,
	valid bool, sigHashType txscript.SigHashType) stateTransitionFunc {

	scriptPrivKey := test.RandPrivKey()
	usedLeaf, testTapScript, _, _, scriptWitness := test.BuildTapscriptTree(
		t, useHashLock, valid, scriptPrivKey.PubKey(),
	)
	scriptKey, err := testTapScript.TaprootKey()
	require.NoError(t, err)

	genesisOutPoint := wire.OutPoint{}
	genesisAsset := randAsset(t, asset.Normal, scriptKey)
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
		ScriptKey:   asset.RandSerializedKey(t),
		Amount:      1,
	}, {
		OutputIndex: 2,
		AssetID:     assetID,
		ScriptKey:   asset.RandSerializedKey(t),
		Amount:      1,
	}}

	return func(t *testing.T) (*asset.Asset, commitment.SplitSet,
		commitment.InputSet, uint32) {

		inputs := []commitment.SplitCommitmentInput{{
			Asset:    genesisAsset,
			OutPoint: genesisOutPoint,
		}}
		splitCommitment, err := commitment.NewSplitCommitment(
			context.Background(), inputs, rootLocator,
			externalLocators...,
		)
		require.NoError(t, err)

		virtualTx, _, err := tapscript.VirtualTx(
			splitCommitment.RootAsset, splitCommitment.PrevAssets,
		)
		require.NoError(t, err)
		newWitness := genTaprootScriptSpend(
			t, *scriptPrivKey, virtualTx, genesisAsset,
			splitCommitment.RootAsset, 0, sigHashType,
			testTapScript.ControlBlock, usedLeaf, scriptWitness,
		)
		require.NoError(t, err)
		splitCommitment.RootAsset.PrevWitnesses[0].TxWitness = newWitness

		// If the signature is not committing to the outputs, let's
		// change things up a bit.
		if sigHashType == txscript.SigHashNone {
			// Now we pay 2 units to the root output and 1 unit to
			// the split output.
			rootLocator := &commitment.SplitLocator{
				OutputIndex: 0,
				AssetID:     assetID,
				ScriptKey: asset.ToSerialized(
					genesisAsset.ScriptKey.PubKey,
				),
				Amount: 2,
			}
			externalLocators := []*commitment.SplitLocator{{
				OutputIndex: 1,
				AssetID:     assetID,
				ScriptKey:   asset.RandSerializedKey(t),
				Amount:      1,
			}}

			splitCommitment, err = commitment.NewSplitCommitment(
				context.Background(), inputs, rootLocator,
				externalLocators...,
			)
			require.NoError(t, err)

			// We need to recover the previously generated witness.
			splitCommitment.RootAsset.PrevWitnesses[0].TxWitness =
				newWitness
		}

		return splitCommitment.RootAsset, splitCommitment.SplitAssets,
			splitCommitment.PrevAssets, 0
	}
}

type mockChainLookup struct {
}

func (m *mockChainLookup) CurrentHeight(_ context.Context) (uint32, error) {
	return 0, nil
}

// TxBlockHeight returns the block height that the given transaction was
// included in.
func (m *mockChainLookup) TxBlockHeight(context.Context,
	chainhash.Hash) (uint32, error) {

	return mockInputTxBlockHeight, nil
}

// MeanBlockTimestamp returns the timestamp of the block at the given height as
// a Unix timestamp in seconds, taking into account the mean time elapsed over
// the previous 10 blocks.
func (m *mockChainLookup) MeanBlockTimestamp(context.Context,
	uint32) (time.Time, error) {

	return time.Unix(mockChainLookupMeanTime, 0).UTC(), nil
}

func TestVM(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		f    stateTransitionFunc
		err  error
	}{
		{
			name: "collectible group anchor",
			f: genesisStateTransition(
				asset.Collectible, true, true,
			),
			err: nil,
		},
		{
			name: "collectible genesis",
			f: genesisStateTransition(
				asset.Collectible, true, false,
			),
			err: nil,
		},
		{
			name: "invalid collectible group anchor",
			f: genesisStateTransition(
				asset.Collectible, false, true,
			),
			err: newErrKind(ErrInvalidGenesisStateTransition),
		},
		{
			name: "invalid collectible genesis",
			f: genesisStateTransition(
				asset.Collectible, false, false,
			),
			err: newErrKind(ErrInvalidGenesisStateTransition),
		},
		{
			name: "collectible genesis invalid witness",
			f: invalidGenesisStateTransitionWitness(
				asset.Collectible, false,
			),
			err: ErrNoInputs,
		},
		{
			name: "collectible group anchor invalid witness",
			f: invalidGenesisStateTransitionWitness(
				asset.Collectible, true,
			),
			err: newErrKind(ErrInvalidGenesisStateTransition),
		},
		{
			name: "collectible group anchor BIP86 key",
			f: groupAnchorStateTransition(
				true, true, false, false, asset.Collectible,
			),
			err: nil,
		},
		{
			name: "normal group anchor key spend",
			f: groupAnchorStateTransition(
				true, false, true, true, asset.Normal,
			),
			err: nil,
		},
		{
			name: "normal group anchor hash lock witness",
			f: groupAnchorStateTransition(
				true, false, false, true, asset.Normal,
			),
			err: nil,
		},
		{
			name: "collectible group anchor sig script witness",
			f: groupAnchorStateTransition(
				false, false, false, true, asset.Collectible,
			),
			err: nil,
		},
		{
			name: "collectible group anchor invalid hash lock",
			f: groupAnchorStateTransition(
				true, false, false, false, asset.Collectible,
			),
			err: invalidHashLockErr,
		},
		{
			name: "normal group anchor invalid sig",
			f: groupAnchorStateTransition(
				false, false, false, false, asset.Normal,
			),
			err: invalidSigErr,
		},
		{
			name: "invalid split collectible input",
			f:    splitCollectibleStateTransition(false),
			err:  newErrKind(ErrInvalidSplitAssetType),
		},
		{
			name: "normal group anchor",
			f:    genesisStateTransition(asset.Normal, true, true),
			err:  nil,
		},
		{
			name: "normal genesis",
			f:    genesisStateTransition(asset.Normal, true, false),
			err:  nil,
		},
		{
			name: "invalid normal group anchor",
			f: genesisStateTransition(
				asset.Normal, false, true,
			),
			err: newErrKind(ErrInvalidGenesisStateTransition),
		},
		{
			name: "invalid normal genesis",
			f: genesisStateTransition(
				asset.Normal, false, false,
			),
			err: newErrKind(ErrInvalidGenesisStateTransition),
		},
		{
			name: "normal genesis invalid witness",
			f: invalidGenesisStateTransitionWitness(
				asset.Normal, false,
			),
			err: ErrNoInputs,
		},
		{
			name: "normal group anchor invalid witness",
			f: invalidGenesisStateTransitionWitness(
				asset.Normal, true,
			),
			err: newErrKind(ErrInvalidGenesisStateTransition),
		},
		{
			name: "collectible state transition",
			f:    collectibleStateTransition,
			err:  nil,
		},
		{
			name: "normal state transition",
			f:    genNormalStateTransition(6, 0, 0, false, false),
			err:  nil,
		},
		{
			name: "normal state transition with csv locked asset",
			f:    genNormalStateTransition(3, 6, 0, true, false),
			err:  newErrKind(ErrUnfinalizedAsset),
		},
		{
			name: "normal state transition with timestamp based " +
				"csv locked asset",
			f: genNormalStateTransition(
				3, wire.SequenceLockTimeIsSeconds|123, 0,
				true, false,
			),
			err: newErrKind(ErrUnfinalizedAsset),
		},
		{
			name: "normal state transition with cltv locked asset",
			f:    genNormalStateTransition(3, 0, 6, false, true),
			err:  newErrKind(ErrUnfinalizedAsset),
		},
		{
			name: "normal state transition with timestamp based " +
				"cltv locked asset",
			f: genNormalStateTransition(
				3, 0, uint64(mockChainLookupMeanTime+123),
				false, true,
			),
			err: newErrKind(ErrUnfinalizedAsset),
		},
		{
			name: "normal state transition with cltv and csv " +
				"locked asset",
			f:   genNormalStateTransition(3, 6, 6, true, true),
			err: newErrKind(ErrUnfinalizedAsset),
		},
		{
			name: "normal state transition with csv locked " +
				"asset, sufficient block height",
			f: genNormalStateTransition(
				6+mockInputTxBlockHeight, 6, 6, true, false,
			),
			err: nil,
		},
		{
			name: "normal state transition with timestamp based " +
				"csv locked asset, sufficient time passed",
			f: genNormalStateTransition(
				6+mockInputTxBlockHeight,
				wire.SequenceLockTimeIsSeconds, 6, true, false,
			),
			err: nil,
		},
		{
			name: "normal state transition with cltv locked " +
				"asset, sufficient block height",
			f:   genNormalStateTransition(6, 0, 6, false, true),
			err: nil,
		},
		{
			name: "normal state transition with timestamp based " +
				"cltv locked asset, sufficient time passed",
			f: genNormalStateTransition(
				6, 0, uint64(mockChainLookupMeanTime), false,
				true,
			),
			err: nil,
		},
		{
			name: "normal state transition with cltv and csv " +
				"locked asset, sufficient block height",
			f: genNormalStateTransition(
				6+mockInputTxBlockHeight, 6, 6, true, true,
			),
			err: nil,
		},
		{
			name: "cltv by-height locks, with argument == 0" +
				" and tx nLockTime == 0",
			f: genCustomScriptStateTransition(
				0, 0, 0,
				test.ScriptCltv0(t),
			),
			err: cleanStackErr,
		},
		{
			name: "cltv by-height locks, with argument == " +
				"499999999 and tx nLockTime == 499999999",
			f: genCustomScriptStateTransition(
				499999999, 0, 499999999,
				test.ScriptCltv(t, 499999999),
			),
			err: nil,
		},
		{
			name: "cltv by-height locks, with argument == 0" +
				" and tx nLockTime == 499999999",
			f: genCustomScriptStateTransition(
				499999999, 0, 499999999,
				test.ScriptCltv0(t),
			),
			err: cleanStackErr,
		},
		{
			name: "csv by-height locks, with argument == 0" +
				" and  txin.nSequence == 0",
			f: genCustomScriptStateTransition(
				0+mockInputTxBlockHeight, 0, 0,
				test.ScriptCsv0(t),
			),
			err: cleanStackErr,
		},
		{
			name: "csv by-height locks, with argument == 65535" +
				" and  txin.nSequence == 65535",
			f: genCustomScriptStateTransition(
				65535+mockInputTxBlockHeight, 65535, 0,
				test.ScriptCsv(t, 65535),
			),
			err: nil,
		},
		{
			name: "csv by-height locks, with argument == 65535" +
				" and  txin.nSequence == 2143289343",
			f: genCustomScriptStateTransition(
				2143289343, 2143289343, 0,
				test.ScriptCsv(t, 65535),
			),
			err: nil,
		},
		{
			name: "csv by-height locks, with argument == 0" +
				" and  txin.nSequence == 2143289343",
			f: genCustomScriptStateTransition(
				2143289343, 2143289343, 0,
				test.ScriptCsv0(t),
			),
			err: cleanStackErr,
		},
		{
			name: "split state transition",
			f:    splitStateTransition,
			err:  nil,
		},
		{
			name: "split full value state transition",
			f:    splitFullValueStateTransition(true, true),
			err:  nil,
		},
		{
			name: "invalid un-spendable root asset",
			f:    splitFullValueStateTransition(true, false),
			err:  newErrKind(ErrInvalidRootAsset),
		},
		{
			name: "invalid un-spendable root locator",
			f:    splitFullValueStateTransition(false, true),
			err:  newErrKind(ErrInvalidRootAsset),
		},
		{
			name: "split collectible state transition",
			f:    splitCollectibleStateTransition(true),
			err:  nil,
		},
		{
			name: "script tree spend state transition valid hash " +
				"lock",
			f:   scriptTreeSpendStateTransition(t, true, true, 999),
			err: nil,
		},
		{
			name: "script tree spend state transition invalid " +
				"hash lock",
			f: scriptTreeSpendStateTransition(
				t, true, false, 999,
			),
			err: invalidHashLockErr,
		},
		{
			name: "script tree spend state transition valid sig " +
				"sighash default",
			f: scriptTreeSpendStateTransition(
				t, false, true, txscript.SigHashDefault,
			),
			err: nil,
		},
		{
			name: "script tree spend state transition valid sig " +
				"sighash single",
			f: scriptTreeSpendStateTransition(
				t, false, true, txscript.SigHashSingle,
			),
			err: nil,
		},
		{
			name: "script tree spend state transition valid sig " +
				"sighash single",
			f: scriptTreeSpendStateTransition(
				t, false, true, txscript.SigHashSingle,
			),
			err: nil,
		},
		{
			name: "script tree spend state transition valid sig " +
				"sighash none",
			f: scriptTreeSpendStateTransition(
				t, false, true, txscript.SigHashNone,
			),
			err: nil,
		},
		{
			name: "script tree spend state transition invalid " +
				"sig",
			f: scriptTreeSpendStateTransition(
				t, false, false, 999,
			),
			err: invalidSigErr,
		},
	}

	var (
		validVectors = &TestVectors{}
		errorVectors = &TestVectors{}
	)
	for _, testCase := range testCases {

		success := t.Run(testCase.name, func(t *testing.T) {
			newAsset, splitSet, inputSet, blockHeight := testCase.f(
				t,
			)

			tv := &ValidTestCase{
				Asset: asset.NewTestFromAsset(t, newAsset),
				SplitSet: commitment.NewTestFromSplitSet(
					t, splitSet,
				),
				InputSet: commitment.NewTestFromInputSet(
					t, inputSet,
				),
				Comment:     testCase.name,
				BlockHeight: blockHeight,
			}
			if testCase.err == nil {
				validVectors.ValidTestCases = append(
					validVectors.ValidTestCases, tv,
				)
			} else {
				errorString := testCase.err.Error()
				errorVectors.ErrorTestCases = append(
					errorVectors.ErrorTestCases,
					&ErrorTestCase{
						Asset:       tv.Asset,
						SplitSet:    tv.SplitSet,
						InputSet:    tv.InputSet,
						Error:       errorString,
						Comment:     tv.Comment,
						BlockHeight: blockHeight,
					},
				)
			}

			verifyTestCase(
				t, testCase.err, true, newAsset, splitSet,
				inputSet, blockHeight,
			)
		})
		if !success {
			return
		}
	}

	// Write test vectors to file. This is a no-op if the "gen_test_vectors"
	// build tag is not set.
	test.WriteTestVectors(t, generatedTestVectorName, validVectors)
	test.WriteTestVectors(t, errorTestVectorName, errorVectors)
}

// verifyTestCase verifies the test case by creating a new virtual machine
// and executing it.
func verifyTestCase(t testing.TB, expectedErr error, compareErrString bool,
	newAsset *asset.Asset, splitSet commitment.SplitSet,
	inputSet commitment.InputSet, currentHeight uint32) {

	// When feeding in the test vectors, we don't have structured errors
	// anymore, just strings. So we need to compare the error strings
	// instead of the errors themselves.
	checkErr := func(err error) {
		if compareErrString {
			if expectedErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorContains(
					t, err, expectedErr.Error(),
				)
			}
		} else {
			require.ErrorIs(t, err, expectedErr)
		}
	}

	verify := func(splitAssets []*commitment.SplitAsset) error {
		opts := []NewEngineOpt{
			WithChainLookup(&mockChainLookup{}),
			WithBlockHeight(currentHeight),
		}
		vm, err := New(newAsset, splitAssets, inputSet, opts...)
		if err != nil {
			if expectedErr != nil {
				checkErr(err)
			} else {
				t.Fatal(err)
			}
		}
		return vm.Execute()
	}
	if len(splitSet) == 0 {
		err := verify(nil)
		checkErr(err)
		return
	}

	// For splits, sort by ascending value so that we fail
	// early on invalid zero-value locators.
	splitAssets := maps.Values(splitSet)
	sort.Slice(splitAssets, func(i, j int) bool {
		return splitAssets[i].Asset.Amount <
			splitAssets[j].Asset.Amount
	})
	err := verify(splitAssets)
	checkErr(err)
}

// TestBIPTestVectors tests that the BIP test vectors are passing.
func TestBIPTestVectors(t *testing.T) {
	t.Parallel()

	for idx := range allTestVectorFiles {
		var (
			fileName    = allTestVectorFiles[idx]
			testVectors = &TestVectors{}
		)
		test.ParseTestVectors(t, fileName, &testVectors)
		t.Run(fileName, func(tt *testing.T) {
			tt.Parallel()

			runBIPTestVector(tt, testVectors)
		})
	}
}

// runBIPTestVector runs the tests in a single BIP test vector file.
func runBIPTestVector(t *testing.T, testVectors *TestVectors) {
	for _, validCase := range testVectors.ValidTestCases {
		validCase := validCase

		t.Run(validCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			a := validCase.Asset.ToAsset(tt)
			ss := validCase.SplitSet.ToSplitSet(tt)
			is := validCase.InputSet.ToInputSet(tt)
			bh := validCase.BlockHeight

			verifyTestCase(tt, nil, false, a, ss, is, bh)
		})
	}

	for _, invalidCase := range testVectors.ErrorTestCases {
		invalidCase := invalidCase

		t.Run(invalidCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			a := invalidCase.Asset.ToAsset(tt)
			ss := invalidCase.SplitSet.ToSplitSet(tt)
			is := invalidCase.InputSet.ToInputSet(tt)
			bh := invalidCase.BlockHeight
			err := errors.New(invalidCase.Error)

			verifyTestCase(tt, err, true, a, ss, is, bh)
		})
	}
}
