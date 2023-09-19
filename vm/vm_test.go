package vm

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightningnetwork/lnd/input"
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
)

func randAsset(t *testing.T, assetType asset.Type,
	scriptKeyPub *btcec.PublicKey) *asset.Asset {

	t.Helper()

	genesis := asset.RandGenesis(t, assetType)
	scriptKey := asset.NewScriptKey(scriptKeyPub)
	protoAsset := asset.RandAssetWithValues(t, genesis, nil, scriptKey)
	groupKey := asset.RandGroupKey(t, genesis, protoAsset)

	fullAsset := protoAsset.Copy()
	fullAsset.GroupKey = groupKey
	return fullAsset
}

func genTaprootKeySpend(t *testing.T, privKey btcec.PrivateKey,
	virtualTx *wire.MsgTx, input *asset.Asset, idx uint32) wire.TxWitness {

	t.Helper()

	virtualTxCopy := tapscript.VirtualTxWithInput(
		virtualTx, input, idx, nil,
	)
	sigHash, err := tapscript.InputKeySpendSigHash(
		virtualTxCopy, input, idx, txscript.SigHashDefault,
	)
	require.NoError(t, err)

	taprootPrivKey := txscript.TweakTaprootPrivKey(privKey, nil)
	sig, err := schnorr.Sign(taprootPrivKey, sigHash)
	require.NoError(t, err)

	return wire.TxWitness{sig.Serialize()}
}

func genTaprootScriptSpend(t *testing.T, privKey btcec.PrivateKey,
	virtualTx *wire.MsgTx, input *asset.Asset, idx uint32,
	sigHashType txscript.SigHashType, controlBlock *txscript.ControlBlock,
	tapLeaf *txscript.TapLeaf, scriptWitness []byte) wire.TxWitness {

	t.Helper()

	controlBlockBytes, err := controlBlock.ToBytes()
	require.NoError(t, err)

	if scriptWitness == nil {
		virtualTxCopy := tapscript.VirtualTxWithInput(
			virtualTx, input, idx, nil,
		)
		sigHash, err := tapscript.InputScriptSpendSigHash(
			virtualTxCopy, input, idx, sigHashType, tapLeaf,
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
	commitment.SplitSet, commitment.InputSet)

func genesisStateTransition(assetType asset.Type,
	valid bool) stateTransitionFunc {

	return func(t *testing.T) (*asset.Asset, commitment.SplitSet,
		commitment.InputSet) {

		a := asset.RandAsset(t, assetType)
		if assetType == asset.Collectible && !valid {
			inputSet := commitment.InputSet{
				asset.PrevID{}: a.Copy(),
			}
			return a, nil, inputSet
		}

		if assetType == asset.Normal && !valid {
			splitSet := commitment.SplitSet{
				{}: &commitment.SplitAsset{},
			}
			return a, splitSet, nil
		}

		return a, nil, nil
	}
}

func collectibleStateTransition(t *testing.T) (*asset.Asset,
	commitment.SplitSet, commitment.InputSet) {

	privKey := test.RandPrivKey(t)
	scriptKey := txscript.ComputeTaprootKeyNoScript(privKey.PubKey())

	genesisOutPoint := wire.OutPoint{}
	genesisAsset := randAsset(t, asset.Collectible, scriptKey)

	prevID := &asset.PrevID{
		OutPoint:  genesisOutPoint,
		ID:        genesisAsset.Genesis.ID(),
		ScriptKey: asset.ToSerialized(genesisAsset.ScriptKey.PubKey),
	}
	newAsset := genesisAsset.Copy()
	newAsset.ScriptKey = asset.NewScriptKey(test.RandPrivKey(t).PubKey())
	newAsset.PrevWitnesses = []asset.Witness{{
		PrevID:          prevID,
		TxWitness:       nil,
		SplitCommitment: nil,
	}}

	inputs := commitment.InputSet{*prevID: genesisAsset}
	virtualTx, _, err := tapscript.VirtualTx(newAsset, inputs)
	require.NoError(t, err)
	newWitness := genTaprootKeySpend(
		t, *privKey, virtualTx, genesisAsset, 0,
	)
	require.NoError(t, err)
	newAsset.PrevWitnesses[0].TxWitness = newWitness

	return newAsset, nil, inputs
}

func normalStateTransition(t *testing.T) (*asset.Asset, commitment.SplitSet,
	commitment.InputSet) {

	privKey1 := test.RandPrivKey(t)
	scriptKey1 := txscript.ComputeTaprootKeyNoScript(privKey1.PubKey())

	const csv = 6
	privKey2 := test.RandPrivKey(t)
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
	genesisAsset1 := randAsset(t, asset.Normal, scriptKey1)
	genesisAsset2 := randAsset(t, asset.Normal, scriptKey2)
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

	inputs := commitment.InputSet{
		*prevID1: genesisAsset1,
		*prevID2: genesisAsset2,
	}
	virtualTx, _, err := tapscript.VirtualTx(newAsset, inputs)
	require.NoError(t, err)
	newWitness := genTaprootKeySpend(
		t, *privKey1, virtualTx, genesisAsset1, 0,
	)
	require.NoError(t, err)
	newAsset.PrevWitnesses[0].TxWitness = newWitness

	leafIdx := tapTree.LeafProofIndex[tapLeaf.TapHash()]
	leafProof := tapTree.LeafMerkleProofs[leafIdx]
	controlBlock := leafProof.ToControlBlock(privKey2.PubKey())

	newAsset.PrevWitnesses[1].TxWitness = genTaprootScriptSpend(
		t, *privKey2, virtualTx, genesisAsset2, 1,
		txscript.SigHashDefault, &controlBlock, &tapLeaf, nil,
	)

	return newAsset, nil, inputs
}

func splitStateTransition(t *testing.T) (*asset.Asset, commitment.SplitSet,
	commitment.InputSet) {

	privKey := test.RandPrivKey(t)
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
		t, *privKey, virtualTx, genesisAsset, 0,
	)
	require.NoError(t, err)
	splitCommitment.RootAsset.PrevWitnesses[0].TxWitness = newWitness

	return splitCommitment.RootAsset, splitCommitment.SplitAssets,
		splitCommitment.PrevAssets
}

func splitFullValueStateTransition(validRootLocator,
	validRoot bool) stateTransitionFunc {

	return func(t *testing.T) (*asset.Asset, commitment.SplitSet,
		commitment.InputSet) {

		privKey := test.RandPrivKey(t)
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
			t, *privKey, virtualTx, genesisAsset, 0,
		)
		require.NoError(t, err)
		splitCommitment.RootAsset.PrevWitnesses[0].TxWitness = newWitness

		return splitCommitment.RootAsset, splitCommitment.SplitAssets,
			splitCommitment.PrevAssets
	}
}

func splitCollectibleStateTransition(validRoot bool) stateTransitionFunc {
	return func(t *testing.T) (*asset.Asset, commitment.SplitSet,
		commitment.InputSet) {

		privKey := test.RandPrivKey(t)
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
			t, *privKey, virtualTx, genesisAsset, 0,
		)
		require.NoError(t, err)
		splitCommitment.RootAsset.PrevWitnesses[0].TxWitness = newWitness

		if !validRoot {
			splitCommitment.RootAsset.Type = asset.Normal
		}

		return splitCommitment.RootAsset, splitCommitment.SplitAssets,
			splitCommitment.PrevAssets
	}
}

func scriptTreeSpendStateTransition(t *testing.T, useHashLock,
	valid bool, sigHashType txscript.SigHashType) stateTransitionFunc {

	scriptPrivKey := test.RandPrivKey(t)
	scriptInternalKey := scriptPrivKey.PubKey()

	// Let's create a taproot asset script now. This is a hash lock with a
	// simple preimage of "foobar".
	leaf1 := test.ScriptHashLock(t, []byte("foobar"))

	// Let's add a second script output as well to test the partial reveal.
	leaf2 := test.ScriptSchnorrSig(t, scriptInternalKey)

	var (
		usedLeaf      *txscript.TapLeaf
		testTapScript *waddrmgr.Tapscript
		scriptWitness []byte
	)
	if useHashLock {
		usedLeaf = &leaf1
		inclusionProof := leaf2.TapHash()
		testTapScript = input.TapscriptPartialReveal(
			scriptInternalKey, leaf1, inclusionProof[:],
		)
		scriptWitness = []byte("foobar")

		if !valid {
			scriptWitness = []byte("not-foobar")
		}
	} else {
		usedLeaf = &leaf2
		inclusionProof := leaf1.TapHash()
		testTapScript = input.TapscriptPartialReveal(
			scriptInternalKey, leaf2, inclusionProof[:],
		)

		// If we leave the scriptWitness nil, the genTaprootScriptSpend
		// function will automatically create a signature for us.
		// We only need to create a witness if we want an invalid
		// signature.
		if !valid {
			scriptWitness = make([]byte, 64)
		}
	}

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
		commitment.InputSet) {

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
			t, *scriptPrivKey, virtualTx, genesisAsset, 0,
			sigHashType, testTapScript.ControlBlock, usedLeaf,
			scriptWitness,
		)
		require.NoError(t, err)
		splitCommitment.RootAsset.PrevWitnesses[0].TxWitness = newWitness

		return splitCommitment.RootAsset, splitCommitment.SplitAssets,
			splitCommitment.PrevAssets
	}
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
			f:    genesisStateTransition(asset.Collectible, true),
			err:  nil,
		},
		{
			name: "invalid collectible genesis",
			f:    genesisStateTransition(asset.Collectible, false),
			err:  newErrKind(ErrInvalidGenesisStateTransition),
		},
		{
			name: "invalid split collectible input",
			f:    splitCollectibleStateTransition(false),
			err:  newErrKind(ErrInvalidSplitAssetType),
		},
		{
			name: "normal genesis",
			f:    genesisStateTransition(asset.Normal, true),
			err:  nil,
		},
		{
			name: "invalid normal genesis",
			f:    genesisStateTransition(asset.Normal, false),
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
			f: scriptTreeSpendStateTransition(t, true, false, 999),
			err: newErrInner(
				ErrInvalidTransferWitness, txscript.Error{
					ErrorCode:   txscript.ErrEqualVerify,
					Description: "OP_EQUALVERIFY failed",
				},
			),
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
			name: "script tree spend state transition invalid " +
				"sig",
			f: scriptTreeSpendStateTransition(t, false, false, 999),
			err: newErrInner(
				ErrInvalidTransferWitness, txscript.Error{
					ErrorCode: txscript.ErrNullFail,
					Description: "signature not empty on " +
						"failed checksig",
				},
			),
		},
	}

	var (
		validVectors = &TestVectors{}
		errorVectors = &TestVectors{}
	)
	for _, testCase := range testCases {
		testCase := testCase

		success := t.Run(testCase.name, func(t *testing.T) {
			newAsset, splitSet, inputSet := testCase.f(t)

			tv := &ValidTestCase{
				Asset: asset.NewTestFromAsset(t, newAsset),
				SplitSet: commitment.NewTestFromSplitSet(
					t, splitSet,
				),
				InputSet: commitment.NewTestFromInputSet(
					t, inputSet,
				),
				Comment: testCase.name,
			}
			if testCase.err == nil {
				validVectors.ValidTestCases = append(
					validVectors.ValidTestCases, tv,
				)
			} else {
				errorVectors.ErrorTestCases = append(
					errorVectors.ErrorTestCases,
					&ErrorTestCase{
						Asset:    tv.Asset,
						SplitSet: tv.SplitSet,
						InputSet: tv.InputSet,
						Error:    testCase.err.Error(),
						Comment:  tv.Comment,
					},
				)
			}

			verifyTestCase(
				t, testCase.err, false, newAsset, splitSet,
				inputSet,
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
	inputSet commitment.InputSet) {

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
			require.Equal(t, expectedErr, err)
		}
	}

	verify := func(splitAssets []*commitment.SplitAsset) error {
		vm, err := New(newAsset, splitAssets, inputSet)
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

			verifyTestCase(tt, nil, false, a, ss, is)
		})
	}

	for _, invalidCase := range testVectors.ErrorTestCases {
		invalidCase := invalidCase

		t.Run(invalidCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			a := invalidCase.Asset.ToAsset(tt)
			ss := invalidCase.SplitSet.ToSplitSet(tt)
			is := invalidCase.InputSet.ToInputSet(tt)
			err := errors.New(invalidCase.Error)

			verifyTestCase(tt, err, true, a, ss, is)
		})
	}
}
