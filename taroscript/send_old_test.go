package taroscript_test

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightninglabs/taro/vm"
	"github.com/stretchr/testify/require"
)

func checkPreparedSplitSpend(t *testing.T, spend *taroscript.SpendDelta,
	addr address.Taro, prevInput asset.PrevID, scriptKey btcec.PublicKey) {

	t.Helper()

	require.NotNil(t, spend.SplitCommitment)
	require.Equal(t, *spend.NewAsset.ScriptKey.PubKey, scriptKey)
	require.Equal(
		t, spend.NewAsset.Amount,
		spend.InputAssets[prevInput].Amount-addr.Amount,
	)
	if spend.InputAssets[prevInput].Amount == addr.Amount {
		require.True(t, spend.NewAsset.IsUnspendable())
	}
	receiverStateKey := addr.AssetCommitmentKey()
	receiverLocator, ok := spend.Locators[receiverStateKey]
	require.True(t, ok)
	receiverAsset, ok := spend.SplitCommitment.SplitAssets[receiverLocator]
	require.True(t, ok)
	require.Equal(t, receiverAsset.Asset.Amount, addr.Amount)
	require.Equal(t,
		*receiverAsset.Asset.ScriptKey.PubKey, addr.ScriptKey,
	)
}

func checkPreparedCompleteSpend(t *testing.T, spend *taroscript.SpendDelta,
	addr address.Taro, prevInput asset.PrevID) {

	t.Helper()

	require.Nil(t, spend.SplitCommitment)
	require.Equal(t,
		*spend.NewAsset.ScriptKey.PubKey, addr.ScriptKey,
	)
	require.Equal(t, *spend.NewAsset.PrevWitnesses[0].PrevID, prevInput)
	require.Nil(t, spend.NewAsset.PrevWitnesses[0].TxWitness)
	require.Nil(t, spend.NewAsset.PrevWitnesses[0].SplitCommitment)
}

func checkValidateSpend(t *testing.T, a, b *asset.Asset, split bool) {
	t.Helper()

	require.Equal(t, a.Version, b.Version)
	require.Equal(t, a.Genesis, b.Genesis)
	require.Equal(t, a.Type, b.Type)
	require.Equal(t, a.Amount, b.Amount)
	require.Equal(t, a.LockTime, b.LockTime)
	require.Equal(t, a.RelativeLockTime, b.RelativeLockTime)
	require.Equal(t, len(a.PrevWitnesses), len(b.PrevWitnesses))
	require.NotNil(t, b.PrevWitnesses[0].TxWitness)
	if split {
		require.NotNil(t, b.SplitCommitmentRoot)
	}

	require.Equal(t, a.ScriptVersion, b.ScriptVersion)
	require.Equal(t,
		a.ScriptKey.PubKey, b.ScriptKey.PubKey,
	)
	require.Equal(t, a.GroupKey, b.GroupKey)
}

func checkSpendCommitments(t *testing.T, senderKey, receiverKey [32]byte,
	prevInput asset.PrevID, spend *taroscript.SpendDelta,
	newCommmitments taroscript.SpendCommitments, isSplit bool) {

	t.Helper()

	// Assert deletion of the input asset and possible deletion
	// of the matching AssetCommitment tree.
	senderTree, ok := newCommmitments[senderKey]
	require.True(t, ok)
	receiverTree, ok := newCommmitments[receiverKey]
	require.True(t, ok)

	includesAssetCommitment := true
	senderCommitments := senderTree.Commitments()
	_, ok = senderCommitments[spend.InputAssets[prevInput].
		TaroCommitmentKey()]
	if !ok {
		includesAssetCommitment = false
	}

	inputMatchingAsset := !isSplit

	// If our spend creates an unspenable root, no asset should exist
	// at the location of the input asset.
	if spend.NewAsset.IsUnspendable() && isSplit {
		inputMatchingAsset = true
	}

	// Input asset should always be excluded.
	checkTaroCommitment(
		t, []*asset.Asset{spend.InputAssets[prevInput]}, &senderTree,
		false, includesAssetCommitment, inputMatchingAsset,
	)

	// Assert inclusion of the validated asset in the receiver tree
	// when not splitting.
	if !isSplit {
		checkTaroCommitment(
			t, []*asset.Asset{&spend.NewAsset}, &receiverTree,
			true, true, true,
		)
	} else {
		// For splits, assert inclusion for the validated asset in
		// the sender tree, and for the receiver split asset in
		// the receiver tree.
		checkTaroCommitment(
			t, []*asset.Asset{&spend.NewAsset}, &senderTree,
			true, true, true,
		)
		receiverLocator := spend.Locators[receiverKey]
		receiverAsset, ok := spend.SplitCommitment.SplitAssets[receiverLocator]
		require.True(t, ok)

		// Before we go to compare the commitments, we'll remove the
		// split commitment witness from the receiver asset, since the
		// actual tree doesn't explicitly commit to this value.
		receiverAsset.PrevWitnesses[0].SplitCommitment = nil

		checkTaroCommitment(
			t, []*asset.Asset{&receiverAsset.Asset}, &receiverTree,
			true, true, true,
		)
	}
}

func checkSpendOutputs(t *testing.T, addr address.Taro,
	internalKey, scriptKey btcec.PublicKey,
	senderAsset, receiverAsset *asset.Asset,
	commitments taroscript.SpendCommitments,
	locators taroscript.SpendLocators,
	spendingPsbt *psbt.Packet, isSplit bool) {

	t.Helper()

	// Build a TaprootProof for each receiver to prove inclusion
	// or exclusion for each output.
	senderStateKey := asset.AssetCommitmentKey(
		addr.ID(), &scriptKey, addr.GroupKey == nil,
	)
	senderIndex := locators[senderStateKey].OutputIndex
	senderTaroTree := commitments[senderStateKey]
	senderProofAsset, senderTaroProof, err := senderTaroTree.Proof(
		senderAsset.TaroCommitmentKey(),
		senderAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	if senderProofAsset != nil {
		require.True(t, senderAsset.DeepEqual(senderProofAsset))
	}
	senderProof := &proof.TaprootProof{
		OutputIndex: senderIndex,
		InternalKey: &internalKey,
		CommitmentProof: &proof.CommitmentProof{
			Proof:              *senderTaroProof,
			TapSiblingPreimage: nil,
		},
		TapscriptProof: nil,
	}

	receiverStateKey := addr.AssetCommitmentKey()
	receiverIndex := locators[receiverStateKey].OutputIndex
	receiverTaroTree := commitments[receiverStateKey]
	receiverProofAsset, receiverTaroProof, err := receiverTaroTree.Proof(
		receiverAsset.TaroCommitmentKey(),
		receiverAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	// For this assertion, we unset the split commitment, since the leaf in
	// the receivers tree doesn't have this value.
	receiverAsset.PrevWitnesses[0].SplitCommitment = nil
	require.True(t, receiverAsset.DeepEqual(receiverProofAsset))

	receiverProof := &proof.TaprootProof{
		OutputIndex: receiverIndex,
		InternalKey: &addr.InternalKey,
		CommitmentProof: &proof.CommitmentProof{
			Proof:              *receiverTaroProof,
			TapSiblingPreimage: nil,
		},
		TapscriptProof: nil,
	}

	// The sender proof should prove inclusion of the split commitment root
	// if there was an asset split, and exclusion of the input asset
	// otherwise.
	var senderProofKey *btcec.PublicKey
	if isSplit {
		senderProofKey, _, err = senderProof.DeriveByAssetInclusion(
			senderAsset,
		)
		require.NoError(t, err)
	} else {
		senderProofKey, err = senderProof.DeriveByAssetExclusion(
			senderAsset.AssetCommitmentKey(),
			senderAsset.TaroCommitmentKey(),
		)
		require.NoError(t, err)
	}

	receiverProofKey, _, err := receiverProof.DeriveByAssetInclusion(
		receiverAsset,
	)
	require.NoError(t, err)

	senderPsbtKey := spendingPsbt.UnsignedTx.TxOut[senderIndex].PkScript[2:]
	receiverPsbtKey := spendingPsbt.UnsignedTx.TxOut[receiverIndex].
		PkScript[2:]

	require.Equal(
		t, schnorr.SerializePubKey(receiverProofKey), receiverPsbtKey,
	)
	require.Equal(
		t, schnorr.SerializePubKey(senderProofKey), senderPsbtKey,
	)
}

// TestPrepareAssetSplitSpend tests the creating of split commitment data with
// different sets of split locators. The validity of locators is assumed to be
// checked earlier via areValidIndexes().
func TestPrepareAssetSplitSpend(t *testing.T) {
	t.Parallel()

	for _, testCase := range prepareAssetSplitSpendTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f(t)
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
}

type prepareAssetSplitSpendTestCase struct {
	name string
	f    func(t *testing.T) error
	err  error
}

var prepareAssetSplitSpendTestCases = []prepareAssetSplitSpendTestCase{
	{
		name: "asset split with custom locators",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset2InputAssets,
			}

			spenderStateKey := asset.AssetCommitmentKey(
				state.asset2.ID(),
				&state.spenderScriptKey, true,
			)
			receiverStateKey := state.address1StateKey

			spend.Locators = make(taroscript.SpendLocators)
			spend.Locators[spenderStateKey] = commitment.
				SplitLocator{OutputIndex: 0}
			spend.Locators[receiverStateKey] = commitment.
				SplitLocator{OutputIndex: 2}
			spendPrepared, err := taroscript.PrepareAssetSplitSpend(
				state.address1, state.asset2PrevID,
				state.spenderScriptKey, spend,
			)
			require.NoError(t, err)

			checkPreparedSplitSpend(
				t, spendPrepared, state.address1,
				state.asset2PrevID, state.spenderScriptKey,
			)
			return nil
		},
		err: nil,
	},
	{
		name: "asset split with mock locators",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset2InputAssets,
			}
			spendPrepared, err := taroscript.PrepareAssetSplitSpend(
				state.address1, state.asset2PrevID,
				state.spenderScriptKey, spend,
			)
			require.NoError(t, err)

			checkPreparedSplitSpend(
				t, spendPrepared, state.address1,
				state.asset2PrevID, state.spenderScriptKey,
			)
			return nil
		},
		err: nil,
	},
	{
		name: "asset split with unspendable change",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset2InputAssets,
			}
			state.spenderScriptKey = *asset.NUMSPubKey
			spendPrepared, err := taroscript.PrepareAssetSplitSpend(
				state.address2, state.asset2PrevID,
				state.spenderScriptKey, spend,
			)
			require.NoError(t, err)

			checkPreparedSplitSpend(
				t, spendPrepared, state.address2,
				state.asset2PrevID, state.spenderScriptKey,
			)
			return nil
		},
		err: nil,
	},
	{
		name: "asset split with collectible",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset1CollectGroupInputAssets,
			}
			state.spenderScriptKey = *asset.NUMSPubKey
			spendPrepared, err := taroscript.PrepareAssetSplitSpend(
				state.address1CollectGroup,
				state.asset1CollectGroupPrevID,
				state.spenderScriptKey, spend,
			)
			require.NoError(t, err)

			checkPreparedSplitSpend(
				t, spendPrepared, state.address1CollectGroup,
				state.asset1CollectGroupPrevID,
				state.spenderScriptKey,
			)
			return nil
		},
		err: nil,
	},
	{
		name: "asset split with incorrect script key",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset2InputAssets,
			}
			_, err := taroscript.PrepareAssetSplitSpend(
				state.address2, state.asset2PrevID,
				state.spenderScriptKey, spend,
			)
			return err
		},
		err: commitment.ErrInvalidScriptKey,
	},
}

// TestPrepareAssetCompleteSpend tests the two cases where an asset is spent
// completely, asserting that new asset leaves are correctly created.
func TestPrepareAssetCompleteSpend(t *testing.T) {
	t.Parallel()

	for _, testCase := range prepareAssetCompleteSpendTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f(t)
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
}

type prepareAssetCompleteSpendTestCase struct {
	name string
	f    func(t *testing.T) error
	err  error
}

var prepareAssetCompleteSpendTestCases = []prepareAssetCompleteSpendTestCase{
	{
		name: "collectible with group key",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.
					asset1CollectGroupInputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1CollectGroup,
				state.asset1CollectGroupPrevID, spend,
			)
			checkPreparedCompleteSpend(
				t, spendPrepared, state.address1CollectGroup,
				state.asset1CollectGroupPrevID,
			)
			return nil
		},
		err: nil,
	},
	{
		name: "normal asset without split",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset1InputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1, state.asset1PrevID, spend,
			)
			checkPreparedCompleteSpend(
				t, spendPrepared, state.address1,
				state.asset1PrevID,
			)
			return nil
		},
		err: nil,
	},
}

// TestCompleteAssetSpend tests edge cases around signing a witness for
// an asset transfer and validating that transfer with the Taro VM.
func TestCompleteAssetSpend(t *testing.T) {
	t.Parallel()

	for _, testCase := range completeAssetSpendTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f(t)
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
}

type completeAssetSpendTestCase struct {
	name string
	f    func(t *testing.T) error
	err  error
}

var completeAssetSpendTestCases = []completeAssetSpendTestCase{
	{
		name: "validate with invalid InputAsset",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset1InputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1, state.asset1PrevID, spend,
			)
			spendPrepared.InputAssets[state.asset1PrevID].
				Genesis = state.genesis1collect
			_, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			spendPrepared.InputAssets[state.asset1PrevID].
				Genesis = state.genesis1
			return err
		},
		err: vm.Error{Kind: vm.ErrIDMismatch},
	},
	{
		name: "validate with invalid NewAsset",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset1InputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1, state.asset1PrevID, spend,
			)
			spendPrepared.NewAsset.PrevWitnesses[0].
				PrevID.OutPoint.Index = 1337
			_, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			return err
		},
		err: vm.ErrNoInputs,
	},
	{
		name: "validate with empty InputAssets",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset1InputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1, state.asset1PrevID, spend,
			)
			delete(
				spendPrepared.InputAssets, state.asset1PrevID,
			)
			_, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			return err
		},
		err: taroscript.ErrNoInputs,
	},
	{
		name: "validate collectible with group key",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.
					asset1CollectGroupInputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1CollectGroup,
				state.asset1CollectGroupPrevID, spend,
			)
			unvalidatedAsset := spendPrepared.NewAsset
			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			checkValidateSpend(
				t, &unvalidatedAsset,
				&spendCompleted.NewAsset, false,
			)
			return nil
		},
		err: nil,
	},
	{
		name: "validate normal asset without split",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset1InputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1, state.asset1PrevID, spend,
			)
			unvalidatedAsset := spendPrepared.NewAsset
			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			checkValidateSpend(
				t, &unvalidatedAsset,
				&spendCompleted.NewAsset, false,
			)
			return nil
		},
	},
	{
		name: "validate asset split",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset2InputAssets,
			}
			spendPrepared, err := taroscript.PrepareAssetSplitSpend(
				state.address1, state.asset2PrevID,
				state.spenderScriptKey, spend,
			)
			require.NoError(t, err)

			unvalidatedAsset := spendPrepared.NewAsset
			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			checkValidateSpend(
				t, &unvalidatedAsset,
				&spendCompleted.NewAsset, true,
			)
			return nil
		},
	},
	{
		name: "validate full value asset split",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset2InputAssets,
			}
			state.spenderScriptKey = *asset.NUMSPubKey
			spendPrepared, err := taroscript.PrepareAssetSplitSpend(
				state.address2, state.asset2PrevID,
				state.spenderScriptKey, spend,
			)
			require.NoError(t, err)

			unvalidatedAsset := spendPrepared.NewAsset
			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			checkValidateSpend(
				t, &unvalidatedAsset,
				&spendCompleted.NewAsset, true,
			)
			return nil
		},
	},
	{
		name: "validate split collectible with group key",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.
					asset1CollectGroupInputAssets,
			}
			state.spenderScriptKey = *asset.NUMSPubKey
			spendPrepared, err := taroscript.PrepareAssetSplitSpend(
				state.address1CollectGroup,
				state.asset1CollectGroupPrevID,
				state.spenderScriptKey, spend,
			)
			require.NoError(t, err)

			unvalidatedAsset := spendPrepared.NewAsset
			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			checkValidateSpend(
				t, &unvalidatedAsset,
				&spendCompleted.NewAsset, false,
			)
			return nil
		},
		err: nil,
	},
}

// TestCreateSpendCommitments tests edge cases around creating TaroCommitments
// to represent an asset transfer.
func TestCreateSpendCommitments(t *testing.T) {
	t.Parallel()

	for _, testCase := range createSpendCommitmentsTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f(t)
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
}

type createSpendCommitmentsTestCase struct {
	name string
	f    func(t *testing.T) error
	err  error
}

var createSpendCommitmentsTestCases = []createSpendCommitmentsTestCase{
	{
		name: "missing input asset commitment",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset1InputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1, state.asset1PrevID, spend,
			)
			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			inputCommitments := state.asset1TaroTree.Commitments()
			senderCommitment, ok :=
				inputCommitments[state.asset1.
					TaroCommitmentKey()]
			require.True(t, ok)

			senderTaroCommitment := state.asset1TaroTree
			err = senderTaroCommitment.Delete(senderCommitment)
			require.NoError(t, err)

			_, err = taroscript.CreateSpendCommitments(
				&senderTaroCommitment,
				state.asset1PrevID, *spendCompleted,
				state.address1, state.spenderScriptKey,
			)
			return err
		},
		err: taroscript.ErrMissingAssetCommitment,
	},
	{
		name: "missing input asset",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset1InputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1, state.asset1PrevID, spend,
			)
			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			inputCommitments := state.asset1TaroTree.Commitments()
			senderCommitment, ok :=
				inputCommitments[state.asset1.
					TaroCommitmentKey()]
			require.True(t, ok)

			err = senderCommitment.Delete(&state.asset1)
			require.NoError(t, err)

			senderTaroCommitment := state.asset1TaroTree
			err = senderTaroCommitment.Upsert(senderCommitment)
			require.NoError(t, err)

			_, err = taroscript.CreateSpendCommitments(
				&senderTaroCommitment,
				state.asset1PrevID, *spendCompleted,
				state.address1, state.spenderScriptKey,
			)
			return err
		},
		err: taroscript.ErrMissingInputAsset,
	},
	{
		name: "missing locator for receiver split asset",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset2InputAssets,
			}
			spendPrepared, err := taroscript.PrepareAssetSplitSpend(
				state.address1, state.asset2PrevID,
				state.spenderScriptKey, spend,
			)
			require.NoError(t, err)

			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			receiverStateKey := state.address1StateKey
			receiverLocator, ok := spendCompleted.
				Locators[receiverStateKey]
			require.True(t, ok)

			delete(
				spendCompleted.SplitCommitment.SplitAssets,
				receiverLocator,
			)
			_, err = taroscript.CreateSpendCommitments(
				&state.asset2TaroTree,
				state.asset2PrevID, *spendCompleted,
				state.address1, state.spenderScriptKey,
			)
			return err
		},
		err: taroscript.ErrMissingSplitAsset,
	},
	{
		name: "collectible with group key",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.
					asset1CollectGroupInputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1CollectGroup,
				state.asset1CollectGroupPrevID, spend,
			)
			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			spendCommitments, err := taroscript.CreateSpendCommitments(
				&state.asset1CollectGroupTaroTree,
				state.asset1CollectGroupPrevID,
				*spendCompleted, state.address1CollectGroup,
				state.spenderScriptKey,
			)
			require.NoError(t, err)

			senderStateKey := asset.AssetCommitmentKey(
				state.address1CollectGroup.ID(),
				&state.spenderScriptKey,
				false,
			)
			receiverStateKey := state.address1CollectGroupStateKey
			checkSpendCommitments(
				t, senderStateKey, receiverStateKey,
				state.asset1CollectGroupPrevID,
				spendCompleted, spendCommitments, false,
			)
			return nil
		},
		err: nil,
	},
	{
		name: "normal asset without split",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset1InputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1, state.asset1PrevID, spend,
			)
			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			spendCommitments, err := taroscript.CreateSpendCommitments(
				&state.asset1TaroTree, state.asset1PrevID,
				*spendCompleted, state.address1,
				state.spenderScriptKey,
			)
			require.NoError(t, err)

			senderStateKey := asset.AssetCommitmentKey(
				state.address1.ID(),
				&state.spenderScriptKey, true,
			)
			receiverStateKey := state.address1StateKey
			checkSpendCommitments(
				t, senderStateKey, receiverStateKey,
				state.asset1PrevID, spendCompleted,
				spendCommitments, false,
			)
			return nil
		},
		err: nil,
	},
	{
		name: "asset split",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset2InputAssets,
			}
			spendPrepared, err := taroscript.PrepareAssetSplitSpend(
				state.address1, state.asset2PrevID,
				state.spenderScriptKey, spend,
			)
			require.NoError(t, err)

			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			spendCommitments, err := taroscript.CreateSpendCommitments(
				&state.asset2TaroTree, state.asset2PrevID,
				*spendCompleted, state.address1,
				state.spenderScriptKey,
			)
			require.NoError(t, err)

			senderStateKey := asset.AssetCommitmentKey(
				state.asset2.ID(),
				&state.spenderScriptKey, true,
			)
			receiverStateKey := state.address1StateKey
			checkSpendCommitments(
				t, senderStateKey, receiverStateKey,
				state.asset2PrevID, spendCompleted,
				spendCommitments, true,
			)
			return nil
		},
		err: nil,
	},
	{
		name: "full value asset split",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset2InputAssets,
			}
			state.spenderScriptKey = *asset.NUMSPubKey
			spendPrepared, err := taroscript.PrepareAssetSplitSpend(
				state.address2, state.asset2PrevID,
				state.spenderScriptKey, spend,
			)
			require.NoError(t, err)

			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			spendCommitments, err := taroscript.CreateSpendCommitments(
				&state.asset2TaroTree, state.asset2PrevID,
				*spendCompleted, state.address2,
				state.spenderScriptKey,
			)
			require.NoError(t, err)

			senderStateKey := asset.AssetCommitmentKey(
				state.asset2.ID(),
				&state.spenderScriptKey, true,
			)
			receiverStateKey := state.address2StateKey
			checkSpendCommitments(
				t, senderStateKey, receiverStateKey,
				state.asset2PrevID, spendCompleted,
				spendCommitments, true,
			)
			return nil
		},
		err: nil,
	},
	{
		name: "split collectible with group key",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.
					asset1CollectGroupInputAssets,
			}
			state.spenderScriptKey = *asset.NUMSPubKey
			spendPrepared, err := taroscript.PrepareAssetSplitSpend(
				state.address1CollectGroup,
				state.asset1CollectGroupPrevID,
				state.spenderScriptKey, spend,
			)
			require.NoError(t, err)

			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			spendCommitments, err := taroscript.CreateSpendCommitments(
				&state.asset1CollectGroupTaroTree,
				state.asset1CollectGroupPrevID,
				*spendCompleted, state.address1CollectGroup,
				state.spenderScriptKey,
			)
			require.NoError(t, err)

			senderStateKey := asset.AssetCommitmentKey(
				state.address1CollectGroup.ID(),
				&state.spenderScriptKey,
				false,
			)
			receiverStateKey := state.address1CollectGroupStateKey
			checkSpendCommitments(
				t, senderStateKey, receiverStateKey,
				state.asset1CollectGroupPrevID,
				spendCompleted, spendCommitments, true,
			)
			return nil
		},
		err: nil,
	},
}

// TestCreateSpendOutputs tests edge cases around creating Bitcoin outputs
// that embed TaroCommitments.
func TestCreateSpendOutputs(t *testing.T) {
	t.Parallel()

	for _, testCase := range createSpendOutputsTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f(t)
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
}

type createSpendOutputsTestCase struct {
	name string
	f    func(t *testing.T) error
	err  error
}

var createSpendOutputsTestCases = []createSpendOutputsTestCase{
	{
		name: "missing change commitment",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset1InputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1, state.asset1PrevID, spend,
			)
			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			spendCommitments, err := taroscript.CreateSpendCommitments(
				&state.asset1TaroTree, state.asset1PrevID,
				*spendCompleted, state.address1,
				state.spenderScriptKey,
			)
			require.NoError(t, err)

			senderStateKey := asset.AssetCommitmentKey(
				state.address1.ID(),
				&state.spenderScriptKey, true,
			)
			delete(spendCommitments, senderStateKey)
			receiverStateKey := state.address1CollectGroupStateKey
			locators := taroscript.CreateDummyLocators(
				[][32]byte{senderStateKey, receiverStateKey},
			)
			spendPsbt, err := taroscript.CreateTemplatePsbt(locators)
			require.NoError(t, err)
			err = taroscript.CreateSpendOutputs(
				state.address1, spendCompleted.Locators,
				state.spenderPubKey, state.spenderScriptKey,
				spendCommitments, spendPsbt,
			)
			return err
		},
		err: taroscript.ErrMissingTaroCommitment,
	},
	{
		name: "missing receiver commitment",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset1InputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1, state.asset1PrevID, spend,
			)
			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			spendCommitments, err := taroscript.CreateSpendCommitments(
				&state.asset1TaroTree, state.asset1PrevID,
				*spendCompleted, state.address1,
				state.spenderScriptKey,
			)
			require.NoError(t, err)

			receiverStateKey := state.address1StateKey
			delete(spendCommitments, receiverStateKey)
			senderStateKey := asset.AssetCommitmentKey(
				state.address1.ID(),
				&state.spenderScriptKey, true,
			)
			locators := taroscript.CreateDummyLocators(
				[][32]byte{senderStateKey, receiverStateKey},
			)
			spendPsbt, err := taroscript.CreateTemplatePsbt(locators)
			require.NoError(t, err)
			err = taroscript.CreateSpendOutputs(
				state.address1, spendCompleted.Locators,
				state.spenderPubKey, state.spenderScriptKey,
				spendCommitments, spendPsbt,
			)
			return err
		},
		err: taroscript.ErrMissingTaroCommitment,
	},
	{
		name: "collectible with group key",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.
					asset1CollectGroupInputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1CollectGroup,
				state.asset1CollectGroupPrevID, spend,
			)
			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			spendCommitments, err := taroscript.CreateSpendCommitments(
				&state.asset1CollectGroupTaroTree,
				state.asset1CollectGroupPrevID,
				*spendCompleted,
				state.address1CollectGroup,
				state.spenderScriptKey,
			)
			require.NoError(t, err)

			senderStateKey := asset.AssetCommitmentKey(
				state.address1CollectGroup.ID(),
				&state.spenderScriptKey, false,
			)
			receiverStateKey := state.address1CollectGroupStateKey
			spendCompleted.Locators = taroscript.CreateDummyLocators(
				[][32]byte{senderStateKey, receiverStateKey},
			)
			spendPsbt, err := taroscript.CreateTemplatePsbt(
				spendCompleted.Locators,
			)
			require.NoError(t, err)
			err = taroscript.CreateSpendOutputs(
				state.address1CollectGroup,
				spendCompleted.Locators,
				state.spenderPubKey, state.spenderScriptKey,
				spendCommitments, spendPsbt,
			)
			require.NoError(t, err)

			senderAsset := spendCompleted.InputAssets[state.
				asset1CollectGroupPrevID]
			checkSpendOutputs(
				t, state.address1CollectGroup,
				state.spenderPubKey, state.spenderScriptKey,
				senderAsset, &spendCompleted.NewAsset,
				spendCommitments, spendCompleted.Locators,
				spendPsbt, false,
			)
			return nil
		},
		err: nil,
	},
	{
		name: "normal asset without split",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset1InputAssets,
			}
			spendPrepared := taroscript.PrepareAssetCompleteSpend(
				state.address1, state.asset1PrevID, spend,
			)
			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			spendCommitments, err := taroscript.CreateSpendCommitments(
				&state.asset1TaroTree, state.asset1PrevID,
				*spendCompleted, state.address1,
				state.spenderScriptKey,
			)
			require.NoError(t, err)

			senderStateKey := asset.AssetCommitmentKey(
				state.address1.ID(),
				&state.spenderScriptKey, true,
			)
			receiverStateKey := state.address1StateKey
			spendCompleted.Locators = taroscript.CreateDummyLocators(
				[][32]byte{senderStateKey, receiverStateKey},
			)
			spendPsbt, err := taroscript.CreateTemplatePsbt(
				spendCompleted.Locators,
			)
			require.NoError(t, err)
			err = taroscript.CreateSpendOutputs(
				state.address1, spendCompleted.Locators,
				state.spenderPubKey, state.spenderScriptKey,
				spendCommitments, spendPsbt,
			)
			require.NoError(t, err)

			senderAsset := spendCompleted.InputAssets[state.
				asset1PrevID]
			checkSpendOutputs(
				t, state.address1, state.spenderPubKey,
				state.spenderScriptKey,
				senderAsset, &spendCompleted.NewAsset,
				spendCommitments, spendCompleted.Locators,
				spendPsbt, false,
			)
			return nil
		},
		err: nil,
	},
	{
		name: "asset split",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset2InputAssets,
			}
			spendPrepared, err := taroscript.PrepareAssetSplitSpend(
				state.address1, state.asset2PrevID,
				state.spenderScriptKey, spend,
			)
			require.NoError(t, err)

			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			spendCommitments, err := taroscript.CreateSpendCommitments(
				&state.asset2TaroTree, state.asset2PrevID,
				*spendCompleted, state.address1,
				state.spenderScriptKey,
			)
			require.NoError(t, err)

			receiverStateKey := state.address1StateKey
			receiverLocator := spendCompleted.
				Locators[receiverStateKey]
			receiverAsset := spendCompleted.SplitCommitment.
				SplitAssets[receiverLocator].Asset
			spendPsbt, err := taroscript.CreateTemplatePsbt(
				spendCompleted.Locators,
			)
			require.NoError(t, err)
			err = taroscript.CreateSpendOutputs(
				state.address1, spendCompleted.Locators,
				state.spenderPubKey, state.spenderScriptKey,
				spendCommitments, spendPsbt,
			)
			require.NoError(t, err)

			checkSpendOutputs(
				t, state.address1, state.spenderPubKey,
				state.spenderScriptKey,
				&spendCompleted.NewAsset, &receiverAsset,
				spendCommitments, spendCompleted.Locators,
				spendPsbt, true,
			)
			return nil
		},
		err: nil,
	},
	{
		name: "full value asset split",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.asset2InputAssets,
			}
			state.spenderScriptKey = *asset.NUMSPubKey
			spendPrepared, err := taroscript.PrepareAssetSplitSpend(
				state.address2, state.asset2PrevID,
				state.spenderScriptKey, spend,
			)
			require.NoError(t, err)

			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			spendCommitments, err := taroscript.CreateSpendCommitments(
				&state.asset2TaroTree, state.asset2PrevID,
				*spendCompleted, state.address2,
				state.spenderScriptKey,
			)
			require.NoError(t, err)

			receiverStateKey := state.address2StateKey
			receiverLocator := spendCompleted.
				Locators[receiverStateKey]
			receiverAsset := spendCompleted.SplitCommitment.
				SplitAssets[receiverLocator].Asset
			spendPsbt, err := taroscript.CreateTemplatePsbt(
				spendCompleted.Locators,
			)
			require.NoError(t, err)
			err = taroscript.CreateSpendOutputs(
				state.address2, spendCompleted.Locators,
				state.spenderPubKey, state.spenderScriptKey,
				spendCommitments, spendPsbt,
			)
			require.NoError(t, err)

			checkSpendOutputs(
				t, state.address2, state.spenderPubKey,
				state.spenderScriptKey,
				&spendCompleted.NewAsset, &receiverAsset,
				spendCommitments, spendCompleted.Locators,
				spendPsbt, true,
			)
			return nil
		},
		err: nil,
	},
	{
		name: "split collectible with group key",
		f: func(t *testing.T) error {
			state := initSpendScenario(t)
			spend := taroscript.SpendDelta{
				InputAssets: state.
					asset1CollectGroupInputAssets,
			}
			state.spenderScriptKey = *asset.NUMSPubKey
			spendPrepared, err := taroscript.PrepareAssetSplitSpend(
				state.address1CollectGroup,
				state.asset1CollectGroupPrevID,
				state.spenderScriptKey, spend,
			)
			require.NoError(t, err)

			spendCompleted, err := taroscript.CompleteAssetSpend(
				state.spenderPubKey, *spendPrepared,
				state.signer, state.validator,
			)
			require.NoError(t, err)

			spendCommitments, err := taroscript.CreateSpendCommitments(
				&state.asset1CollectGroupTaroTree,
				state.asset1CollectGroupPrevID,
				*spendCompleted,
				state.address1CollectGroup,
				state.spenderScriptKey,
			)
			require.NoError(t, err)

			receiverStateKey := state.address1CollectGroupStateKey
			receiverLocator := spendCompleted.
				Locators[receiverStateKey]
			receiverAsset := spendCompleted.SplitCommitment.
				SplitAssets[receiverLocator].Asset
			spendPsbt, err := taroscript.CreateTemplatePsbt(
				spendCompleted.Locators,
			)
			require.NoError(t, err)

			err = taroscript.CreateSpendOutputs(
				state.address1CollectGroup,
				spendCompleted.Locators,
				state.spenderPubKey, state.spenderScriptKey,
				spendCommitments, spendPsbt,
			)
			require.NoError(t, err)

			checkSpendOutputs(
				t, state.address1CollectGroup,
				state.spenderPubKey, state.spenderScriptKey,
				&spendCompleted.NewAsset, &receiverAsset,
				spendCommitments, spendCompleted.Locators,
				spendPsbt, true,
			)
			return nil
		},
		err: nil,
	},
}
