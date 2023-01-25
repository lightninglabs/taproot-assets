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
	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightninglabs/taro/vm"
	"github.com/stretchr/testify/require"
)

var (
	receiverExternalIdx uint32 = 2
)

type testCase struct {
	name string
	f    func(t *testing.T) error
	err  error
}

func createPacket(addr address.Taro, prevInput asset.PrevID,
	scriptKey btcec.PublicKey,
	inputSet commitment.InputSet) *taropsbt.VPacket {

	inputAsset := inputSet[prevInput]
	input := &taropsbt.VInput{
		PrevID: prevInput,
	}
	outputs := []*taropsbt.VOutput{{
		Amount:            inputAsset.Amount - addr.Amount,
		ScriptKey:         asset.NewScriptKey(&scriptKey),
		AnchorOutputIndex: 0,
		IsChange:          true,
	}, {
		Amount:            addr.Amount,
		ScriptKey:         asset.NewScriptKey(&addr.ScriptKey),
		AnchorOutputIndex: receiverExternalIdx,
	}}

	vPacket := &taropsbt.VPacket{
		Input:       input,
		Outputs:     outputs,
		ChainParams: &address.RegressionNetTaro,
	}
	vPacket.SetInputAsset(inputAsset)

	return vPacket
}

func checkPreparedOutputsNonInteractive(t *testing.T, packet *taropsbt.VPacket,
	addr address.Taro, scriptKey btcec.PublicKey) {

	t.Helper()

	input := packet.Input
	change := packet.Outputs[0]
	receiver := packet.Outputs[1]

	require.True(t, input.IsSplit)
	require.Equal(t, *change.Asset.ScriptKey.PubKey, scriptKey)
	require.Equal(t, change.Asset.Amount, input.Asset().Amount-addr.Amount)
	if input.Asset().Amount == addr.Amount {
		require.True(t, change.Asset.IsUnspendable())
	}

	require.Equal(t, receiver.Asset.Amount, addr.Amount)
	require.Equal(t, *receiver.Asset.ScriptKey.PubKey, addr.ScriptKey)
}

func checkPreparedOutputsInteractive(t *testing.T, packet *taropsbt.VPacket,
	addr address.Taro, prevInput asset.PrevID) {

	t.Helper()

	receiver := packet.Outputs[1]
	receiverAsset := receiver.Asset

	require.Equal(t,
		*receiver.ScriptKey.PubKey, addr.ScriptKey,
	)
	require.Equal(t, receiverAsset.Amount, addr.Amount)
	require.Equal(t,
		*receiverAsset.ScriptKey.PubKey, addr.ScriptKey,
	)
	require.Equal(t, *receiverAsset.PrevWitnesses[0].PrevID, prevInput)
	require.Nil(t, receiverAsset.PrevWitnesses[0].TxWitness)
	require.Nil(t, receiverAsset.PrevWitnesses[0].SplitCommitment)
}

func checkSignedAsset(t *testing.T, raw, signed *asset.Asset, split bool) {
	t.Helper()

	require.Equal(t, raw.Version, signed.Version)
	require.Equal(t, raw.Genesis, signed.Genesis)
	require.Equal(t, raw.Type, signed.Type)
	require.Equal(t, raw.Amount, signed.Amount)
	require.Equal(t, raw.LockTime, signed.LockTime)
	require.Equal(t, raw.RelativeLockTime, signed.RelativeLockTime)
	require.Equal(t, len(raw.PrevWitnesses), len(signed.PrevWitnesses))

	// The signed asset should have a single signature in the witness stack.
	require.NotNil(t, signed.PrevWitnesses[0].TxWitness)
	require.Len(t, signed.PrevWitnesses[0].TxWitness, 1)
	require.Len(t, signed.PrevWitnesses[0].TxWitness[0], 64)
	if split {
		require.NotNil(t, signed.SplitCommitmentRoot)
	}

	require.Equal(t, raw.ScriptVersion, signed.ScriptVersion)
	require.Equal(t, raw.ScriptKey.PubKey, signed.ScriptKey.PubKey)
	require.Equal(t, raw.GroupKey, signed.GroupKey)
}

func checkOutputCommitments(t *testing.T, input *taropsbt.VInput,
	outputs []*taropsbt.VOutput,
	outputCommitments []*commitment.TaroCommitment, isSplit bool) {

	t.Helper()

	// Assert deletion of the input asset and possible deletion of the
	// matching AssetCommitment tree.
	senderTree := outputCommitments[0]
	receiverTree := outputCommitments[1]
	inputAsset := input.Asset()

	newAsset := outputs[1].Asset
	if input.IsSplit {
		newAsset = outputs[0].Asset
	}

	includesAssetCommitment := true
	senderCommitments := senderTree.Commitments()
	_, ok := senderCommitments[inputAsset.TaroCommitmentKey()]
	if !ok {
		includesAssetCommitment = false
	}

	inputMatchingAsset := !isSplit

	// If our spend creates an unspenable root, no asset should exist
	// at the location of the input asset.
	if newAsset.IsUnspendable() && isSplit {
		inputMatchingAsset = true
	}

	// Input asset should always be excluded.
	checkTaroCommitment(
		t, []*asset.Asset{inputAsset}, senderTree,
		false, includesAssetCommitment, inputMatchingAsset,
	)

	// Assert inclusion of the validated asset in the receiver tree
	// when not splitting.
	if !isSplit {
		checkTaroCommitment(
			t, []*asset.Asset{newAsset}, receiverTree,
			true, true, true,
		)
	} else {
		// For splits, assert inclusion for the validated asset in the
		// sender tree, and for the receiver split asset in the receiver
		// tree.
		receiver := outputs[1].Asset
		checkTaroCommitment(
			t, []*asset.Asset{newAsset}, senderTree,
			true, true, true,
		)

		// Before we go to compare the commitments, we'll remove the
		// split commitment witness from the receiver asset, since the
		// actual tree doesn't explicitly commit to this value.
		receiver.PrevWitnesses[0].SplitCommitment = nil

		checkTaroCommitment(
			t, []*asset.Asset{receiver}, receiverTree,
			true, true, true,
		)
	}
}

func checkTaprootOutputs(t *testing.T, outputs []*taropsbt.VOutput,
	outputCommitments []*commitment.TaroCommitment,
	spendingPsbt *psbt.Packet, senderAsset *asset.Asset, isSplit bool) {

	t.Helper()

	receiverAsset := outputs[1].Asset

	// Build a TaprootProof for each receiver to prove inclusion or
	// exclusion for each output.
	senderIndex := outputs[0].AnchorOutputIndex
	senderTaroTree := outputCommitments[0]
	senderProofAsset, senderTaroProof, err := senderTaroTree.Proof(
		senderAsset.TaroCommitmentKey(),
		senderAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	if senderProofAsset != nil {
		if !senderAsset.DeepEqual(senderProofAsset) {
			require.Equal(t, senderAsset, senderProofAsset)
			require.Fail(t, "sender asset mismatch")
		}
	}

	senderInternalKey, err := schnorr.ParsePubKey(
		spendingPsbt.Outputs[senderIndex].TaprootInternalKey,
	)
	require.NoError(t, err)

	senderProof := &proof.TaprootProof{
		OutputIndex: senderIndex,
		InternalKey: senderInternalKey,
		CommitmentProof: &proof.CommitmentProof{
			Proof:              *senderTaroProof,
			TapSiblingPreimage: nil,
		},
		TapscriptProof: nil,
	}

	receiverIndex := outputs[1].AnchorOutputIndex
	receiverTaroTree := outputCommitments[1]
	receiverProofAsset, receiverTaroProof, err := receiverTaroTree.Proof(
		receiverAsset.TaroCommitmentKey(),
		receiverAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	// For this assertion, we unset the split commitment, since the leaf in
	// the receivers tree doesn't have this value.
	receiverAsset.PrevWitnesses[0].SplitCommitment = nil
	require.True(t, receiverAsset.DeepEqual(receiverProofAsset))

	receiverInternalKey, err := schnorr.ParsePubKey(
		spendingPsbt.Outputs[receiverIndex].TaprootInternalKey,
	)
	require.NoError(t, err)
	receiverProof := &proof.TaprootProof{
		OutputIndex: receiverIndex,
		InternalKey: receiverInternalKey,
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

	unsignedTxOut := spendingPsbt.UnsignedTx.TxOut
	senderPsbtKey := unsignedTxOut[senderIndex].PkScript[2:]
	receiverPsbtKey := unsignedTxOut[receiverIndex].PkScript[2:]

	require.Equal(
		t, schnorr.SerializePubKey(receiverProofKey), receiverPsbtKey,
	)
	require.Equal(
		t, schnorr.SerializePubKey(senderProofKey), senderPsbtKey,
	)
}

// TestPrepareOutputAssets tests the creating of split commitment data with
// different sets of split locators. The validity of locators is assumed to be
// checked earlier via areValidIndexes().
func TestPrepareOutputAssets(t *testing.T) {
	t.Parallel()

	for _, testCase := range prepareOutputAssetsTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f(t)
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
}

var prepareOutputAssetsTestCases = []testCase{{
	name: "asset split with custom locators",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			state.address1, state.asset2PrevID,
			state.spenderScriptKey, state.asset2InputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)

		checkPreparedOutputsNonInteractive(
			t, pkt, state.address1, state.spenderScriptKey,
		)
		return nil
	},
	err: nil,
}, {
	name: "full asset non-interactive send with un-spendable change",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address2, state.asset2PrevID,
			state.spenderScriptKey, state.asset2InputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)

		checkPreparedOutputsNonInteractive(
			t, pkt, state.address2, state.spenderScriptKey,
		)
		return nil
	},
	err: nil,
}, {
	name: "full asset interactive send with un-spendable change",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address2, state.asset2PrevID,
			state.spenderScriptKey, state.asset2InputAssets,
		)
		pkt.Outputs[1].Interactive = true
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)

		checkPreparedOutputsInteractive(
			t, pkt, state.address2, state.asset2PrevID,
		)
		return nil
	},
	err: nil,
}, {
	name: "full asset send with collectible",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID,
			state.spenderScriptKey,
			state.asset1CollectGroupInputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)

		checkPreparedOutputsNonInteractive(
			t, pkt, state.address1CollectGroup,
			state.spenderScriptKey,
		)
		return nil
	},
	err: nil,
}, {
	name: "asset split with incorrect script key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			state.address2, state.asset2PrevID,
			state.spenderScriptKey, state.asset2InputAssets,
		)
		return taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
	},
	err: commitment.ErrInvalidScriptKey,
}}

// TestSignVirtualTransaction tests edge cases around signing a witness for
// an asset transfer and validating that transfer with the Taro VM.
func TestSignVirtualTransaction(t *testing.T) {
	t.Parallel()

	for _, testCase := range signVirtualTransactionTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f(t)
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
}

var signVirtualTransactionTestCases = []testCase{{
	name: "validate with invalid InputAsset",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1, state.asset1PrevID,
			state.spenderScriptKey, state.asset1InputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)

		pkt.Input.Asset().Genesis = state.genesis1collect
		return taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
	},
	err: vm.Error{Kind: vm.ErrIDMismatch},
}, {
	name: "validate with invalid NewAsset",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1, state.asset1PrevID,
			state.spenderScriptKey, state.asset1InputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)

		firstPrevID := pkt.Outputs[0].Asset.PrevWitnesses[0].PrevID
		firstPrevID.OutPoint.Index = 1337

		return taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
	},
	err: vm.ErrNoInputs,
}, {
	name: "validate non-interactive collectible with group key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state.spenderScriptKey,
			state.asset1CollectGroupInputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[0].Asset.Copy()
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		checkSignedAsset(
			t, unvalidatedAsset, pkt.Outputs[0].Asset, false,
		)
		return nil
	},
	err: nil,
}, {
	name: "validate interactive collectible with group key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state.spenderScriptKey,
			state.asset1CollectGroupInputAssets,
		)
		pkt.Outputs[1].Interactive = true
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[1].Asset.Copy()
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		checkSignedAsset(
			t, unvalidatedAsset, pkt.Outputs[1].Asset, false,
		)
		return nil
	},
	err: nil,
}, {
	name: "validate interactive normal asset full send",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1, state.asset1PrevID,
			state.spenderScriptKey, state.asset1InputAssets,
		)
		pkt.Outputs[1].Interactive = true
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[1].Asset.Copy()
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		checkSignedAsset(
			t, unvalidatedAsset, pkt.Outputs[1].Asset, false,
		)
		return nil
	},
}, {
	name: "validate asset split",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			state.address1, state.asset2PrevID,
			state.spenderScriptKey, state.asset2InputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[0].Asset.Copy()
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		checkSignedAsset(
			t, unvalidatedAsset, pkt.Outputs[0].Asset, true,
		)
		return nil
	},
}, {
	name: "validate non-interactive collectible with group key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state.spenderScriptKey,
			state.asset1CollectGroupInputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[0].Asset.Copy()
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		checkSignedAsset(
			t, unvalidatedAsset, pkt.Outputs[0].Asset, false,
		)
		return nil
	},
	err: nil,
}}

// TestCreateOutputCommitments tests edge cases around creating TaroCommitments
// to represent an asset transfer.
func TestCreateOutputCommitments(t *testing.T) {
	t.Parallel()

	for _, testCase := range createOutputCommitmentsTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f(t)
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
}

var createOutputCommitmentsTestCases = []testCase{{
	name: "missing input asset commitment",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1, state.asset1PrevID,
			state.spenderScriptKey, state.asset1InputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1TaroTree
		inputCommitments := inputCommitment.Commitments()
		asset1Key := state.asset1.TaroCommitmentKey()
		senderCommitment, ok := inputCommitments[asset1Key]
		require.True(t, ok)

		err = inputCommitment.Update(senderCommitment, true)
		require.NoError(t, err)

		_, err = taroscript.CreateOutputCommitments(
			inputCommitment, pkt.Input, pkt.Outputs,
		)
		return err
	},
	err: taroscript.ErrMissingAssetCommitment,
}, {
	name: "missing input asset",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1, state.asset1PrevID,
			state.spenderScriptKey, state.asset1InputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1TaroTree
		inputCommitments := inputCommitment.Commitments()
		asset1Key := state.asset1.TaroCommitmentKey()
		senderCommitment, ok := inputCommitments[asset1Key]
		require.True(t, ok)

		err = senderCommitment.Update(&state.asset1, true)
		require.NoError(t, err)

		err = inputCommitment.Update(senderCommitment, false)
		require.NoError(t, err)

		_, err = taroscript.CreateOutputCommitments(
			inputCommitment, pkt.Input, pkt.Outputs,
		)
		return err
	},
	err: taroscript.ErrMissingInputAsset,
}, {
	name: "non-interactive collectible with group key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state.spenderScriptKey,
			state.asset1CollectGroupInputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1CollectGroupTaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt.Input, pkt.Outputs,
		)
		require.NoError(t, err)

		checkOutputCommitments(
			t, pkt.Input, pkt.Outputs, outputCommitments, true,
		)
		return nil
	},
	err: nil,
}, {
	name: "interactive normal asset full value",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1, state.asset1PrevID,
			state.spenderScriptKey, state.asset1InputAssets,
		)
		pkt.Outputs[1].Interactive = true
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt.Input, pkt.Outputs,
		)
		require.NoError(t, err)

		checkOutputCommitments(
			t, pkt.Input, pkt.Outputs, outputCommitments, false,
		)
		return nil
	},
	err: nil,
}, {
	name: "non-interactive normal asset split",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			state.address1, state.asset2PrevID,
			state.spenderScriptKey, state.asset2InputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset2TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt.Input, pkt.Outputs,
		)
		require.NoError(t, err)

		checkOutputCommitments(
			t, pkt.Input, pkt.Outputs, outputCommitments, true,
		)
		return nil
	},
	err: nil,
}, {
	name: "non-interactive normal asset full value",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address2, state.asset2PrevID,
			state.spenderScriptKey, state.asset2InputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset2TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt.Input, pkt.Outputs,
		)
		require.NoError(t, err)

		checkOutputCommitments(
			t, pkt.Input, pkt.Outputs, outputCommitments, true,
		)
		return nil
	},
	err: nil,
}, {
	name: "non-interactive collectible with group key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state.spenderScriptKey,
			state.asset1CollectGroupInputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1CollectGroupTaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt.Input, pkt.Outputs,
		)
		require.NoError(t, err)

		checkOutputCommitments(
			t, pkt.Input, pkt.Outputs, outputCommitments, true,
		)
		return nil
	},
	err: nil,
}}

// TestUpdateTaprootOutputKeys tests edge cases around creating Bitcoin outputs
// that embed TaroCommitments.
func TestUpdateTaprootOutputKeys(t *testing.T) {
	t.Parallel()

	for _, testCase := range updateTaprootOutputKeysTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f(t)
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
}

var updateTaprootOutputKeysTestCases = []testCase{{
	name: "missing change commitment",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1, state.asset1PrevID,
			state.spenderScriptKey, state.asset1InputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt.Input, pkt.Outputs,
		)
		require.NoError(t, err)

		btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
		require.NoError(t, err)

		btcPkt.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(
			&state.spenderPubKey,
		)
		outputCommitments[0] = nil

		return taroscript.UpdateTaprootOutputKeys(
			btcPkt, pkt.Outputs, outputCommitments,
		)
	},
	err: taroscript.ErrMissingTaroCommitment,
}, {
	name: "missing receiver commitment",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1, state.asset1PrevID,
			state.spenderScriptKey, state.asset1InputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt.Input, pkt.Outputs,
		)
		require.NoError(t, err)

		btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
		require.NoError(t, err)

		btcPkt.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(
			&state.spenderPubKey,
		)
		receiverBtcOutput := &btcPkt.Outputs[receiverExternalIdx]
		receiverBtcOutput.TaprootInternalKey = schnorr.SerializePubKey(
			&state.address1.InternalKey,
		)
		outputCommitments[1] = nil

		return taroscript.UpdateTaprootOutputKeys(
			btcPkt, pkt.Outputs, outputCommitments,
		)
	},
	err: taroscript.ErrMissingTaroCommitment,
}, {
	name: "interactive collectible with group key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state.spenderScriptKey,
			state.asset1CollectGroupInputAssets,
		)
		pkt.Outputs[1].Interactive = true
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1CollectGroupTaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt.Input, pkt.Outputs,
		)
		require.NoError(t, err)

		btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
		require.NoError(t, err)

		btcPkt.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(
			&state.spenderPubKey,
		)
		receiverBtcOutput := &btcPkt.Outputs[receiverExternalIdx]
		receiverBtcOutput.TaprootInternalKey = schnorr.SerializePubKey(
			&state.address1CollectGroup.InternalKey,
		)

		err = taroscript.UpdateTaprootOutputKeys(
			btcPkt, pkt.Outputs, outputCommitments,
		)
		require.NoError(t, err)

		checkTaprootOutputs(
			t, pkt.Outputs, outputCommitments, btcPkt,
			&state.asset1CollectGroup, false,
		)
		return nil
	},
	err: nil,
}, {
	name: "interactive normal asset full value",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1, state.asset1PrevID,
			state.spenderScriptKey, state.asset1InputAssets,
		)
		pkt.Outputs[1].Interactive = true
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt.Input, pkt.Outputs,
		)
		require.NoError(t, err)

		btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
		require.NoError(t, err)

		btcPkt.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(
			&state.spenderPubKey,
		)
		receiverBtcOutput := &btcPkt.Outputs[receiverExternalIdx]
		receiverBtcOutput.TaprootInternalKey = schnorr.SerializePubKey(
			&state.address1.InternalKey,
		)

		err = taroscript.UpdateTaprootOutputKeys(
			btcPkt, pkt.Outputs, outputCommitments,
		)
		require.NoError(t, err)

		checkTaprootOutputs(
			t, pkt.Outputs, outputCommitments, btcPkt,
			&state.asset1, false,
		)
		return nil
	},
	err: nil,
}, {
	name: "non-interactive normal asset split",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			state.address1, state.asset2PrevID,
			state.spenderScriptKey, state.asset2InputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset2TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt.Input, pkt.Outputs,
		)
		require.NoError(t, err)

		btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
		require.NoError(t, err)

		btcPkt.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(
			&state.spenderPubKey,
		)
		receiverBtcOutput := &btcPkt.Outputs[receiverExternalIdx]
		receiverBtcOutput.TaprootInternalKey = schnorr.SerializePubKey(
			&state.address1.InternalKey,
		)

		err = taroscript.UpdateTaprootOutputKeys(
			btcPkt, pkt.Outputs, outputCommitments,
		)
		require.NoError(t, err)

		checkTaprootOutputs(
			t, pkt.Outputs, outputCommitments, btcPkt,
			pkt.Outputs[0].Asset, true,
		)
		return nil
	},
	err: nil,
}, {
	name: "non-interactive normal asset full value",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address2, state.asset2PrevID,
			state.spenderScriptKey, state.asset2InputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset2TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt.Input, pkt.Outputs,
		)
		require.NoError(t, err)

		btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
		require.NoError(t, err)

		btcPkt.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(
			&state.spenderPubKey,
		)
		receiverBtcOutput := &btcPkt.Outputs[receiverExternalIdx]
		receiverBtcOutput.TaprootInternalKey = schnorr.SerializePubKey(
			&state.address2.InternalKey,
		)

		err = taroscript.UpdateTaprootOutputKeys(
			btcPkt, pkt.Outputs, outputCommitments,
		)
		require.NoError(t, err)

		checkTaprootOutputs(
			t, pkt.Outputs, outputCommitments, btcPkt,
			pkt.Outputs[0].Asset, true,
		)
		return nil
	},
	err: nil,
}, {
	name: "non-interactive collectible with group key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state.spenderScriptKey,
			state.asset1CollectGroupInputAssets,
		)
		err := taroscript.PrepareOutputAssets(pkt.Input, pkt.Outputs)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt.Input, pkt.Outputs, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1CollectGroupTaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt.Input, pkt.Outputs,
		)
		require.NoError(t, err)

		btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
		require.NoError(t, err)

		btcPkt.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(
			&state.spenderPubKey,
		)
		receiverBtcOutput := &btcPkt.Outputs[receiverExternalIdx]
		receiverBtcOutput.TaprootInternalKey = schnorr.SerializePubKey(
			&state.address1CollectGroup.InternalKey,
		)

		err = taroscript.UpdateTaprootOutputKeys(
			btcPkt, pkt.Outputs, outputCommitments,
		)
		require.NoError(t, err)

		checkTaprootOutputs(
			t, pkt.Outputs, outputCommitments, btcPkt,
			pkt.Outputs[0].Asset, true,
		)
		return nil
	},
	err: nil,
}}
