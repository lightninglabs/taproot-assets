package tapsend_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	tap "github.com/lightninglabs/taproot-assets"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tappsbt"
	"github.com/lightninglabs/taproot-assets/tapscript"
	"github.com/lightninglabs/taproot-assets/tapsend"
	"github.com/lightninglabs/taproot-assets/vm"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

var (
	key1Bytes, _ = hex.DecodeString(
		"a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e" +
			"078e",
	)
	key2Bytes, _ = hex.DecodeString(
		"a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e" +
			"078d",
	)

	receiverExternalIdx uint32 = 2
)

// spendData represents the collection of structs needed to begin a spend.
type spendData struct {
	collectAmt                    uint64
	normalAmt1                    uint64
	normalAmt2                    uint64
	genesis1                      asset.Genesis
	genesis1collect               asset.Genesis
	spenderPrivKey                btcec.PrivateKey
	spenderPubKey                 btcec.PublicKey
	spenderScriptKey              btcec.PublicKey
	spenderDescriptor             keychain.KeyDescriptor
	receiverPrivKey               btcec.PrivateKey
	receiverPubKey                btcec.PublicKey
	groupKey                      asset.GroupKey
	address1                      address.Tap
	address1CollectGroup          address.Tap
	address2                      address.Tap
	address1StateKey              [32]byte
	address1CollectGroupStateKey  [32]byte
	address2StateKey              [32]byte
	asset1                        asset.Asset
	asset1CollectGroup            asset.Asset
	asset2                        asset.Asset
	asset1PrevID                  asset.PrevID
	asset1CollectGroupPrevID      asset.PrevID
	asset2PrevID                  asset.PrevID
	asset1InputAssets             commitment.InputSet
	asset1CollectGroupInputAssets commitment.InputSet
	asset2InputAssets             commitment.InputSet
	asset1TapTree                 commitment.TapCommitment
	asset1CollectGroupTapTree     commitment.TapCommitment
	asset2TapTree                 commitment.TapCommitment
	asset2GenesisTx               wire.MsgTx
	asset2GenesisProof            proof.Proof
	validator                     tapscript.TxValidator
	witnessValidator              tapscript.WitnessValidator
	signer                        *tapscript.MockSigner
}

type testCase struct {
	name string
	f    func(t *testing.T) error
	err  error
}

func initSpendScenario(t *testing.T) spendData {
	t.Helper()

	// Amounts and geneses, needed for addresses and assets. We need both
	// a normal and collectible asset, and three amounts to test splits.
	state := spendData{
		collectAmt:      1,
		normalAmt1:      2,
		normalAmt2:      5,
		genesis1:        asset.RandGenesis(t, asset.Normal),
		genesis1collect: asset.RandGenesis(t, asset.Collectible),
	}

	// We don't have a meta reveal for these assets.
	state.genesis1.MetaHash = [32]byte{}
	state.genesis1collect.MetaHash = [32]byte{}

	// Our mock genesis TXs always use an output index of 0.
	state.genesis1.OutputIndex = 0

	// Keys for sender, receiver, and group. Default to keypath spend
	// for the spender ScriptKey.
	spenderPrivKey, spenderPubKey := btcec.PrivKeyFromBytes(key1Bytes)
	state.spenderPrivKey = *spenderPrivKey
	state.spenderPubKey = *spenderPubKey
	state.spenderDescriptor = keychain.KeyDescriptor{
		PubKey: &state.spenderPubKey,
	}

	spenderScriptKey := asset.NewScriptKeyBip86(state.spenderDescriptor)
	state.spenderScriptKey = *spenderScriptKey.PubKey

	receiverPrivKey, receiverPubKey := btcec.PrivKeyFromBytes(key2Bytes)
	state.receiverPrivKey = *receiverPrivKey
	state.receiverPubKey = *receiverPubKey

	genesis1collectProtoAsset := asset.NewAssetNoErr(
		t, state.genesis1collect, 1, 0, 0, spenderScriptKey, nil,
	)
	groupKey := asset.RandGroupKey(
		t, state.genesis1collect, genesis1collectProtoAsset,
	)
	state.groupKey = *groupKey

	// Addresses to cover both asset types and all three asset values.
	// Store the receiver StateKeys as well.
	proofCourierAddr := address.RandProofCourierAddr(t)

	address1, err := address.New(
		address.V0, state.genesis1, nil, nil, state.receiverPubKey,
		state.receiverPubKey, state.normalAmt1, nil,
		&address.MainNetTap, proofCourierAddr,
	)
	require.NoError(t, err)
	state.address1 = *address1
	state.address1StateKey = state.address1.AssetCommitmentKey()

	address1CollectGroup, err := address.New(
		address.V0, state.genesis1collect, &state.groupKey.GroupPubKey,
		state.groupKey.Witness, state.receiverPubKey,
		state.receiverPubKey, state.collectAmt, nil,
		&address.TestNet3Tap, proofCourierAddr,
	)
	require.NoError(t, err)
	state.address1CollectGroup = *address1CollectGroup
	state.address1CollectGroupStateKey = state.address1CollectGroup.
		AssetCommitmentKey()

	address2, err := address.New(
		address.V0, state.genesis1, nil, nil, state.receiverPubKey,
		state.receiverPubKey, state.normalAmt2, nil,
		&address.MainNetTap, proofCourierAddr,
	)
	require.NoError(t, err)
	state.address2 = *address2
	state.address2StateKey = state.address2.AssetCommitmentKey()

	// Generate matching assets and PrevIDs.
	updateScenarioAssets(t, &state)

	// Generate matching TapCommitments.
	updateScenarioCommitments(t, &state)

	// Validator instance needed to call the Taproot Asset VM.
	state.validator = &tap.ValidatorV0{}

	// VPsbtValidator helper method of the VM is needed for signing vPSBTs.
	state.witnessValidator = &tap.WitnessValidatorV0{}

	// Signer needed to generate a witness for the spend.
	state.signer = tapscript.NewMockSigner(&state.spenderPrivKey)

	return state
}

func updateScenarioAssets(t *testing.T, state *spendData) {
	t.Helper()

	require.NotNil(t, state)

	locktime := uint64(0)
	relLocktime := uint64(0)

	// Assets to cover both asset types and all three asset values.
	asset1, err := asset.New(
		state.genesis1, state.normalAmt1, locktime,
		relLocktime, asset.NewScriptKeyBip86(state.spenderDescriptor),
		nil,
	)
	require.NoError(t, err)
	state.asset1 = *asset1

	asset1CollectGroup, err := asset.New(
		state.genesis1collect, state.collectAmt, locktime,
		relLocktime, asset.NewScriptKeyBip86(state.spenderDescriptor),
		&state.groupKey,
	)
	require.NoError(t, err)
	state.asset1CollectGroup = *asset1CollectGroup

	asset2, err := asset.New(
		state.genesis1, state.normalAmt2, locktime,
		relLocktime, asset.NewScriptKeyBip86(state.spenderDescriptor),
		nil,
	)
	require.NoError(t, err)
	state.asset2 = *asset2

	// Asset PrevIDs, required to represent an input asset for a spend.
	state.asset1PrevID = asset.PrevID{
		OutPoint:  wire.OutPoint{},
		ID:        state.asset1.ID(),
		ScriptKey: asset.ToSerialized(&state.spenderScriptKey),
	}
	state.asset1CollectGroupPrevID = asset.PrevID{
		OutPoint:  wire.OutPoint{},
		ID:        state.asset1CollectGroup.ID(),
		ScriptKey: asset.ToSerialized(&state.spenderScriptKey),
	}
	state.asset2PrevID = asset.PrevID{
		OutPoint:  wire.OutPoint{},
		ID:        state.asset2.ID(),
		ScriptKey: asset.ToSerialized(&state.spenderScriptKey),
	}

	state.asset1InputAssets = commitment.InputSet{
		state.asset1PrevID: &state.asset1,
	}
	state.asset1CollectGroupInputAssets = commitment.InputSet{
		state.asset1CollectGroupPrevID: &state.asset1CollectGroup,
	}
	state.asset2InputAssets = commitment.InputSet{
		state.asset2PrevID: &state.asset2,
	}
}

func updateScenarioCommitments(t *testing.T, state *spendData) {
	t.Helper()

	require.NotNil(t, state)

	// TapCommitments for each asset.
	asset1AssetTree, err := commitment.NewAssetCommitment(&state.asset1)
	require.NoError(t, err)
	asset1TapTree, err := commitment.NewTapCommitment(nil, asset1AssetTree)
	require.NoError(t, err)
	state.asset1TapTree = *asset1TapTree

	asset1CollectGroupAssetTree, err := commitment.NewAssetCommitment(
		&state.asset1CollectGroup,
	)
	require.NoError(t, err)
	asset1CollectGroupTapTree, err := commitment.NewTapCommitment(
		nil, asset1CollectGroupAssetTree,
	)
	require.NoError(t, err)
	state.asset1CollectGroupTapTree = *asset1CollectGroupTapTree

	asset2AssetTree, err := commitment.NewAssetCommitment(&state.asset2)
	require.NoError(t, err)
	asset2TapTree, err := commitment.NewTapCommitment(nil, asset2AssetTree)
	require.NoError(t, err)
	state.asset2TapTree = *asset2TapTree
	require.NoError(t, err)
}

func createGenesisProof(t *testing.T, state *spendData) {
	t.Helper()

	// Only making a proof for asset2, to test split asset proofs.
	senderScript, err := tapscript.PayToAddrScript(
		state.spenderPubKey, nil, state.asset2TapTree,
	)
	require.NoError(t, err)
	asset2GenesisTx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: state.genesis1.FirstPrevOut,
		}},
		TxOut: []*wire.TxOut{{
			PkScript: senderScript,
			Value:    330,
		}},
	}
	state.asset2GenesisTx = *asset2GenesisTx

	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(asset2GenesisTx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	blockHeader := wire.NewBlockHeader(
		0, chaincfg.MainNetParams.GenesisHash, merkleRoot, 0, 0,
	)

	txMerkleProof, err := proof.NewTxMerkleProof(
		[]*wire.MsgTx{asset2GenesisTx}, 0,
	)
	require.NoError(t, err)

	_, asset2CommitmentProof, err := state.asset2TapTree.Proof(
		state.asset2.TapCommitmentKey(),
		state.asset2.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	asset2GenesisProof := proof.Proof{
		PrevOut:       state.asset2GenesisTx.TxIn[0].PreviousOutPoint,
		BlockHeader:   *blockHeader,
		AnchorTx:      state.asset2GenesisTx,
		TxMerkleProof: *txMerkleProof,
		Asset:         state.asset2,
		InclusionProof: proof.TaprootProof{
			OutputIndex: 0,
			InternalKey: &state.spenderPubKey,
			CommitmentProof: &proof.CommitmentProof{
				Proof: *asset2CommitmentProof,
			},
		},
		GenesisReveal: &state.asset2.Genesis,
	}

	state.asset2GenesisProof = asset2GenesisProof
}

func createPacket(t *testing.T, addr address.Tap, prevInput asset.PrevID,
	state spendData, inputSet commitment.InputSet,
	fullValueInteractive bool) *tappsbt.VPacket {

	inputAsset := inputSet[prevInput]
	inputs := []*tappsbt.VInput{{
		PrevID: prevInput,
	}}
	outputs := []*tappsbt.VOutput{{
		Amount: inputAsset.Amount - addr.Amount,
		ScriptKey: asset.NewScriptKey(
			&state.spenderScriptKey,
		),
		AnchorOutputIndex:       0,
		Type:                    tappsbt.TypeSplitRoot,
		AnchorOutputInternalKey: &state.spenderPubKey,
	}, {
		Amount:                  addr.Amount,
		ScriptKey:               asset.NewScriptKey(&addr.ScriptKey),
		AnchorOutputIndex:       receiverExternalIdx,
		AnchorOutputInternalKey: &addr.InternalKey,
	}}

	if fullValueInteractive {
		outputs = []*tappsbt.VOutput{{
			Interactive: true,
			Amount:      addr.Amount,
			ScriptKey: asset.NewScriptKey(
				&addr.ScriptKey,
			),
			AnchorOutputIndex:       receiverExternalIdx,
			AnchorOutputInternalKey: &state.receiverPubKey,
		}}
	}

	vPacket := &tappsbt.VPacket{
		Inputs:      inputs,
		Outputs:     outputs,
		ChainParams: addr.ChainParams,
		Version:     test.RandFlip(tappsbt.V0, tappsbt.V1),
	}
	vPacket.SetInputAsset(0, inputAsset)

	makeAltLeaves := func() []*asset.Asset {
		numAltLeaves := (test.RandInt[uint8]() % 4)
		if numAltLeaves == 0 {
			return nil
		}

		innerAltLeaves := make([]*asset.Asset, 0, numAltLeaves)
		for range numAltLeaves {
			scriptKey := asset.NewScriptKey(test.RandPubKey(t))
			baseLeaf, err := asset.NewAltLeaf(
				scriptKey, asset.ScriptV0,
			)
			require.NoError(t, err)

			innerAltLeaves = append(innerAltLeaves, baseLeaf)
		}

		return innerAltLeaves
	}

	for outputIdx := range len(vPacket.Outputs) {
		err := vPacket.Outputs[outputIdx].SetAltLeaves(makeAltLeaves())
		require.NoError(t, err)
	}

	return vPacket
}

func checkPreparedOutputsNonInteractive(t *testing.T, packet *tappsbt.VPacket,
	addr address.Tap, scriptKey btcec.PublicKey) {

	t.Helper()

	input := packet.Inputs[0]
	change := packet.Outputs[0]
	receiver := packet.Outputs[1]

	hasSplitCommitment, err := packet.HasSplitCommitment()
	require.NoError(t, err)
	require.True(t, hasSplitCommitment)
	require.Equal(t, *change.Asset.ScriptKey.PubKey, scriptKey)
	require.Equal(t, change.Asset.Amount, input.Asset().Amount-addr.Amount)
	if input.Asset().Amount == addr.Amount {
		require.True(t, change.Asset.IsUnSpendable())
	}

	require.Equal(t, receiver.Asset.Amount, addr.Amount)
	require.Equal(t, *receiver.Asset.ScriptKey.PubKey, addr.ScriptKey)
}

func checkPreparedOutputsInteractive(t *testing.T, packet *tappsbt.VPacket,
	addr address.Tap, prevInput asset.PrevID) {

	t.Helper()

	// If we only have one output, it must be a full value interactive send.
	receiver := packet.Outputs[0]
	if len(packet.Outputs) > 1 {
		receiver = packet.Outputs[1]
	}

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

func checkSignedAsset(t *testing.T, raw, signed *asset.Asset, split,
	fullValue bool) {

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

		// If this is a full value non-interactive send, we expect the
		// signed asset to be the change asset, which should have a
		// non-spendable script key.
		if fullValue {
			require.True(t, signed.IsUnSpendable())
		}
	}

	require.Equal(t, raw.ScriptVersion, signed.ScriptVersion)
	require.Equal(t, raw.ScriptKey.PubKey, signed.ScriptKey.PubKey)
	require.Equal(t, raw.GroupKey, signed.GroupKey)
}

func checkTapCommitment(t *testing.T, assets []*asset.Asset,
	inputCommitment *commitment.TapCommitment,
	includesAsset, includesAssetCommitment, matchingAsset bool) {

	t.Helper()

	for _, asset := range assets {
		proofAsset, proof, err := inputCommitment.Proof(
			asset.TapCommitmentKey(),
			asset.AssetCommitmentKey(),
		)
		require.NoError(t, err)

		if includesAsset {
			// Check the included asset is equal to the one
			// provided.
			require.NotNil(t, proofAsset)
			if !proofAsset.DeepEqual(asset) {
				require.Equal(t, asset, proofAsset)
				require.Fail(t, "asset mismatch")
			}
		} else {
			if !matchingAsset {
				// Check the included asset is not equal to
				// the one provided; used for the sender tree
				// when the asset was split and the script key
				// is reused.
				require.NotNil(t, proofAsset)
				require.NotEqual(t, *proofAsset, *asset)
			} else {
				require.Nil(t, proofAsset)
			}
		}

		if includesAssetCommitment {
			require.NotNil(t, proof.AssetProof)
		} else {
			require.Nil(t, proof.AssetProof)
		}

		// Different root hash if asset is mismatched.
		if !matchingAsset {
			continue
		}

		var tapCommitment *commitment.TapCommitment
		switch {
		case includesAsset && includesAssetCommitment:
			tapCommitment, err = proof.DeriveByAssetInclusion(
				asset,
			)

		case includesAssetCommitment:
			tapCommitment, err = proof.DeriveByAssetExclusion(
				asset.AssetCommitmentKey(),
			)

		default:
			tapCommitment, err = proof.
				DeriveByAssetCommitmentExclusion(
					asset.TapCommitmentKey(),
				)
		}
		require.NoError(t, err)

		require.Equal(
			t, inputCommitment.TapLeaf(), tapCommitment.TapLeaf(),
		)
	}
}

func checkOutputCommitments(t *testing.T, vPkt *tappsbt.VPacket,
	outputCommitments tappsbt.OutputCommitments, isSplit bool) {

	t.Helper()

	// Assert deletion of the input asset and possible deletion of the
	// matching AssetCommitment tree.
	senderIdx := vPkt.Outputs[0].AnchorOutputIndex
	senderTree := outputCommitments[senderIdx]
	receiverTree := outputCommitments[senderIdx]

	// If there are multiple outputs, the receiver should be the second one.
	if len(vPkt.Outputs) > 1 {
		receiverIdx := vPkt.Outputs[1].AnchorOutputIndex
		receiverTree = outputCommitments[receiverIdx]
	}

	input := vPkt.Inputs[0]
	outputs := vPkt.Outputs
	inputAsset := input.Asset()

	newAsset := outputs[0].Asset

	pkgIsSplit, err := vPkt.HasSplitCommitment()
	require.NoError(t, err)

	require.Equal(t, isSplit, pkgIsSplit)

	includesAssetCommitment := true
	senderCommitments := senderTree.Commitments()
	_, ok := senderCommitments[inputAsset.TapCommitmentKey()]
	if !ok {
		includesAssetCommitment = false
	}

	// Check the state of the AltCommitment for each vOutput.
	for _, vOut := range vPkt.Outputs {
		hasAltLeaves := len(vOut.AltLeaves) > 0
		anchorCommitment := outputCommitments[vOut.AnchorOutputIndex]
		anchorAssetCommits := anchorCommitment.Commitments()
		altCommitment, ok := anchorAssetCommits[asset.EmptyGenesisID]

		// If there were any AltLeaves, there must be a non-empty
		// AltCommitment. Otherwise, there must be no AltCommitment
		// root.
		require.Equal(t, hasAltLeaves, ok)
		if !ok {
			continue
		}

		// For each AltLeaf of a vOutput, there must be an equivalent
		// asset leaf in the AltCommitment.
		matchingAltLeaf := func(a asset.AltLeaf[asset.Asset]) bool {
			leafKey := a.AssetCommitmentKey()
			altLeaf, _, err := altCommitment.AssetProof(leafKey)
			require.NoError(t, err)
			require.NotNil(t, altLeaf)

			leaf := a.(*asset.Asset)
			return leaf.DeepEqual(altLeaf)
		}

		require.True(t, fn.All(vOut.AltLeaves, matchingAltLeaf))
	}

	inputMatchingAsset := !isSplit

	// If our spend creates an un-spendable root, no asset should exist
	// at the location of the input asset. The same goes for an interactive
	// full value send, which is only a single output.
	if newAsset.IsUnSpendable() && isSplit {
		inputMatchingAsset = true
	}

	// Input asset should always be excluded.
	checkTapCommitment(
		t, []*asset.Asset{inputAsset}, senderTree,
		false, includesAssetCommitment, inputMatchingAsset,
	)

	// Assert inclusion of the validated asset in the receiver tree
	// when not splitting.
	if !isSplit {
		checkTapCommitment(
			t, []*asset.Asset{newAsset}, receiverTree,
			true, true, true,
		)
	} else {
		// For splits, assert inclusion for the validated asset in the
		// sender tree, and for the receiver split asset in the receiver
		// tree.
		receiver := outputs[1].Asset
		checkTapCommitment(
			t, []*asset.Asset{newAsset}, senderTree,
			true, true, true,
		)

		// Before we go to compare the commitments, we'll remove the
		// split commitment witness from the receiver asset, since the
		// actual tree doesn't explicitly commit to this value.
		receiver.PrevWitnesses[0].SplitCommitment = nil

		checkTapCommitment(
			t, []*asset.Asset{receiver}, receiverTree,
			true, true, true,
		)
	}

	// Assert that the commitment version matches the VPacket version.
	commitments := maps.Values(outputCommitments)
	switch vPkt.Version {
	case tappsbt.V0:
		isValid := func(c *commitment.TapCommitment) bool {
			return c.Version == commitment.TapCommitmentV0 ||
				c.Version == commitment.TapCommitmentV1
		}
		require.True(t, fn.All(commitments, isValid))
	case tappsbt.V1:
		isValid := func(c *commitment.TapCommitment) bool {
			return c.Version == commitment.TapCommitmentV2
		}
		require.True(t, fn.All(commitments, isValid))
	default:
		require.Fail(t, "unknown vPacket version")
	}
}

func checkTaprootOutputs(t *testing.T, outputs []*tappsbt.VOutput,
	outputCommitments tappsbt.OutputCommitments, spendingPsbt *psbt.Packet,
	senderAsset *asset.Asset, isSplit bool) {

	t.Helper()

	receiverAsset := outputs[0].Asset
	receiverIndex := outputs[0].AnchorOutputIndex
	receiverTapTree := outputCommitments[receiverIndex]
	if len(outputs) > 1 {
		receiverAsset = outputs[1].Asset
		receiverIndex = outputs[1].AnchorOutputIndex
		receiverTapTree = outputCommitments[receiverIndex]
	}

	// Build a TaprootProof for each receiver to prove inclusion or
	// exclusion for each output.
	senderIndex := outputs[0].AnchorOutputIndex
	senderTapTree := outputCommitments[senderIndex]
	senderProofAsset, senderTapProof, err := senderTapTree.Proof(
		senderAsset.TapCommitmentKey(),
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
			Proof:              *senderTapProof,
			TapSiblingPreimage: nil,
		},
		TapscriptProof: nil,
	}

	receiverProofAsset, receiverTapProof, err := receiverTapTree.Proof(
		receiverAsset.TapCommitmentKey(),
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
			Proof:              *receiverTapProof,
			TapSiblingPreimage: nil,
		},
		TapscriptProof: nil,
	}

	// The sender proof should prove inclusion of the split commitment root
	// if there was an asset split, and exclusion of the input asset
	// otherwise.
	var senderProofKeys proof.ProofCommitmentKeys
	if isSplit {
		senderProofKeys, err = senderProof.DeriveByAssetInclusion(
			senderAsset, nil,
		)
		require.NoError(t, err)
	} else {
		senderProofKeys, err = senderProof.DeriveByAssetExclusion(
			senderAsset.AssetCommitmentKey(),
			senderAsset.TapCommitmentKey(),
		)
		require.NoError(t, err)
	}

	recvProofKeys, err := receiverProof.DeriveByAssetInclusion(
		receiverAsset, nil,
	)
	require.NoError(t, err)

	unsignedTxOut := spendingPsbt.UnsignedTx.TxOut
	senderPsbtKey := unsignedTxOut[senderIndex].PkScript[2:]
	recvPsbtKey := unsignedTxOut[receiverIndex].PkScript[2:]

	isMatchFoundRecv := fn.Any(
		maps.Keys(recvProofKeys), func(t asset.SerializedKey) bool {
			return bytes.Equal(t.SchnorrSerialized(), recvPsbtKey)
		},
	)
	require.True(t, isMatchFoundRecv)

	isMatchFoundSender := fn.Any(
		maps.Keys(senderProofKeys), func(t asset.SerializedKey) bool {
			return bytes.Equal(t.SchnorrSerialized(), senderPsbtKey)
		},
	)
	require.True(t, isMatchFoundSender)
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
			t, state.address1, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)

		checkPreparedOutputsNonInteractive(
			t, pkt, state.address1, state.spenderScriptKey,
		)
		return nil
	},
	err: nil,
}, {
	name: "asset split with missing root locator",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			t, state.address1, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)

		pkt.Outputs[0].Type = tappsbt.TypeSimple

		return tapsend.PrepareOutputAssets(context.Background(), pkt)
	},
	err: tapsend.ErrNoRootLocator,
}, {
	name: "full value non-interactive send with un-spendable change",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			t, state.address2, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)

		checkPreparedOutputsNonInteractive(
			t, pkt, state.address2, state.spenderScriptKey,
		)
		return nil
	},
	err: nil,
}, {
	name: "full value interactive send with un-spendable change",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.address2.ScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			t, state.address2, state.asset2PrevID,
			state, state.asset2InputAssets, true,
		)
		return tapsend.PrepareOutputAssets(context.Background(), pkt)
	},
	err: commitment.ErrInvalidScriptKey,
}, {
	name: "full value interactive send with spendable change",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			t, state.address2, state.asset2PrevID,
			state, state.asset2InputAssets, true,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)

		checkPreparedOutputsInteractive(
			t, pkt, state.address2, state.asset2PrevID,
		)
		return nil
	},
	err: nil,
}, {
	name: "full value non-interactive send with collectible",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			t, state.address1CollectGroup,
			state.asset1CollectGroupPrevID,
			state, state.asset1CollectGroupInputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
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
			t, state.address2, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)
		return tapsend.PrepareOutputAssets(context.Background(), pkt)
	},
	err: commitment.ErrInvalidScriptKey,
}, {
	name: "asset split interactive send with collectible",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			t, state.address1CollectGroup,
			state.asset1CollectGroupPrevID,
			state, state.asset1CollectGroupInputAssets, false,
		)

		// A split root cannot be interactive in the case of a
		// collectible. Because then we wouldn't need to have a split
		// root in the first place.
		pkt.Outputs[0].Interactive = true

		// We expect an error because an interactive output cannot be
		// un-spendable.
		return tapsend.PrepareOutputAssets(context.Background(), pkt)
	},
	err: commitment.ErrInvalidScriptKey,
}}

// TestSignVirtualTransaction tests edge cases around signing a witness for
// an asset transfer and validating that transfer with the Taproot Asset VM.
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
			t, state.address1, state.asset1PrevID,
			state, state.asset1InputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)

		pkt.Inputs[0].Asset().Genesis = state.genesis1collect
		return tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
	},
	err: vm.Error{Kind: vm.ErrIDMismatch},
}, {
	name: "validate with invalid NewAsset",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			t, state.address1, state.asset1PrevID,
			state, state.asset1InputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)

		firstPrevID := pkt.Outputs[0].Asset.PrevWitnesses[0].PrevID
		firstPrevID.OutPoint.Index = 1337

		return tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
	},
	err: vm.ErrNoInputs,
}, {
	name: "validate non-interactive collectible with group key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			t, state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state,
			state.asset1CollectGroupInputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[0].Asset.Copy()
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		checkSignedAsset(
			t, unvalidatedAsset, pkt.Outputs[0].Asset, true, true,
		)
		return nil
	},
	err: nil,
}, {
	name: "validate interactive collectible with group key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			t, state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state,
			state.asset1CollectGroupInputAssets, true,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[0].Asset.Copy()
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		checkSignedAsset(
			t, unvalidatedAsset, pkt.Outputs[0].Asset, false, false,
		)
		return nil
	},
	err: nil,
}, {
	name: "validate interactive normal asset full value send",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			t, state.address1, state.asset1PrevID,
			state, state.asset1InputAssets, true,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[0].Asset.Copy()
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		checkSignedAsset(
			t, unvalidatedAsset, pkt.Outputs[0].Asset, false, false,
		)
		return nil
	},
}, {
	name: "validate non-interactive asset split",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			t, state.address1, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[0].Asset.Copy()
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		checkSignedAsset(
			t, unvalidatedAsset, pkt.Outputs[0].Asset, true, false,
		)
		return nil
	},
}, {
	name: "validate non-interactive collectible with group key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			t, state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state,
			state.asset1CollectGroupInputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[0].Asset.Copy()
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		checkSignedAsset(
			t, unvalidatedAsset, pkt.Outputs[0].Asset, true, true,
		)
		return nil
	},
	err: nil,
}}

// TestCreateOutputCommitments tests edge cases around creating TapCommitments
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
	name: "non-identical anchor output information",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			t, state.address1, state.asset1PrevID,
			state, state.asset1InputAssets, false,
		)
		tpl := pkt.Outputs[1]

		testPreimage, err := commitment.NewPreimageFromLeaf(
			txscript.TapLeaf{
				LeafVersion: txscript.BaseLeafVersion,
				Script:      []byte("not a valid script"),
			},
		)
		require.NoError(t, err)
		pkt.Outputs = append(pkt.Outputs, &tappsbt.VOutput{
			AnchorOutputIndex:            tpl.AnchorOutputIndex,
			AnchorOutputTapscriptSibling: testPreimage,
		})

		_, err = tapsend.CreateOutputCommitments(
			[]*tappsbt.VPacket{pkt},
		)
		return err
	},
	err: tapsend.ErrInvalidAnchorOutputInfo,
}, {
	name: "incompatible alt leaves",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			t, state.address1, state.asset1PrevID,
			state, state.asset1InputAssets, false,
		)
		tpl := pkt.Outputs[1]

		altLeafScriptKey := asset.NewScriptKey(test.RandPubKey(t))
		newAltLeaf, err := asset.NewAltLeaf(
			altLeafScriptKey, asset.ScriptV0,
		)
		require.NoError(t, err)

		pkt.Outputs[1].AltLeaves = append(
			pkt.Outputs[1].AltLeaves, newAltLeaf,
		)

		require.NoError(t, err)
		pkt.Outputs = append(pkt.Outputs, &tappsbt.VOutput{
			AnchorOutputIndex:       tpl.AnchorOutputIndex,
			AnchorOutputInternalKey: tpl.AnchorOutputInternalKey,
			AltLeaves: []asset.AltLeaf[asset.Asset]{
				newAltLeaf,
			},
		})

		_, err = tapsend.CreateOutputCommitments(
			[]*tappsbt.VPacket{pkt},
		)
		return err
	},
	err: asset.ErrDuplicateAltLeafKey,
}, {
	name: "non-interactive collectible with group key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			t, state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state,
			state.asset1CollectGroupInputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		outputCommitments, err := tapsend.CreateOutputCommitments(
			[]*tappsbt.VPacket{pkt},
		)
		require.NoError(t, err)

		checkOutputCommitments(t, pkt, outputCommitments, true)
		return nil
	},
	err: nil,
}, {
	name: "interactive normal asset full value send",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			t, state.address1, state.asset1PrevID,
			state, state.asset1InputAssets, true,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		outputCommitments, err := tapsend.CreateOutputCommitments(
			[]*tappsbt.VPacket{pkt},
		)
		require.NoError(t, err)

		checkOutputCommitments(t, pkt, outputCommitments, false)
		return nil
	},
	err: nil,
}, {
	name: "non-interactive normal asset split",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			t, state.address1, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		outputCommitments, err := tapsend.CreateOutputCommitments(
			[]*tappsbt.VPacket{pkt},
		)
		require.NoError(t, err)

		checkOutputCommitments(t, pkt, outputCommitments, true)
		return nil
	},
	err: nil,
}, {
	name: "non-interactive normal asset full value send",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			t, state.address2, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		outputCommitments, err := tapsend.CreateOutputCommitments(
			[]*tappsbt.VPacket{pkt},
		)
		require.NoError(t, err)

		checkOutputCommitments(t, pkt, outputCommitments, true)
		return nil
	},
	err: nil,
}, {
	name: "non-interactive collectible with group key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			t, state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state,
			state.asset1CollectGroupInputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		outputCommitments, err := tapsend.CreateOutputCommitments(
			[]*tappsbt.VPacket{pkt},
		)
		require.NoError(t, err)

		checkOutputCommitments(t, pkt, outputCommitments, true)
		return nil
	},
	err: nil,
}}

// TestUpdateTaprootOutputKeys tests edge cases around creating Bitcoin outputs
// that embed TapCommitments.
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
			t, state.address1, state.asset1PrevID,
			state, state.asset1InputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		outputCommitments, err := tapsend.CreateOutputCommitments(
			[]*tappsbt.VPacket{pkt},
		)
		require.NoError(t, err)

		btcPkt, err := tapsend.CreateAnchorTx([]*tappsbt.VPacket{pkt})
		require.NoError(t, err)

		outputCommitments[0] = nil

		err = tapsend.UpdateTaprootOutputKeys(
			btcPkt, pkt, outputCommitments,
		)
		return err
	},
	err: tapsend.ErrMissingTapCommitment,
}, {
	name: "missing receiver commitment",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			t, state.address1, state.asset1PrevID,
			state, state.asset1InputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		outputCommitments, err := tapsend.CreateOutputCommitments(
			[]*tappsbt.VPacket{pkt},
		)
		require.NoError(t, err)

		btcPkt, err := tapsend.CreateAnchorTx([]*tappsbt.VPacket{pkt})
		require.NoError(t, err)

		outputCommitments[receiverExternalIdx] = nil

		err = tapsend.UpdateTaprootOutputKeys(
			btcPkt, pkt, outputCommitments,
		)
		return err
	},
	err: tapsend.ErrMissingTapCommitment,
}, {
	name: "interactive collectible with group key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			t, state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state,
			state.asset1CollectGroupInputAssets, true,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		outputCommitments, err := tapsend.CreateOutputCommitments(
			[]*tappsbt.VPacket{pkt},
		)
		require.NoError(t, err)

		btcPkt, err := tapsend.CreateAnchorTx([]*tappsbt.VPacket{pkt})
		require.NoError(t, err)

		err = tapsend.UpdateTaprootOutputKeys(
			btcPkt, pkt, outputCommitments,
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
	name: "interactive normal asset full value send",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			t, state.address1, state.asset1PrevID,
			state, state.asset1InputAssets, true,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		outputCommitments, err := tapsend.CreateOutputCommitments(
			[]*tappsbt.VPacket{pkt},
		)
		require.NoError(t, err)

		btcPkt, err := tapsend.CreateAnchorTx([]*tappsbt.VPacket{pkt})
		require.NoError(t, err)

		err = tapsend.UpdateTaprootOutputKeys(
			btcPkt, pkt, outputCommitments,
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
			t, state.address1, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		outputCommitments, err := tapsend.CreateOutputCommitments(
			[]*tappsbt.VPacket{pkt},
		)
		require.NoError(t, err)

		btcPkt, err := tapsend.CreateAnchorTx([]*tappsbt.VPacket{pkt})
		require.NoError(t, err)

		err = tapsend.UpdateTaprootOutputKeys(
			btcPkt, pkt, outputCommitments,
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
	name: "non-interactive normal asset full value send",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			t, state.address2, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		outputCommitments, err := tapsend.CreateOutputCommitments(
			[]*tappsbt.VPacket{pkt},
		)
		require.NoError(t, err)

		btcPkt, err := tapsend.CreateAnchorTx([]*tappsbt.VPacket{pkt})
		require.NoError(t, err)

		err = tapsend.UpdateTaprootOutputKeys(
			btcPkt, pkt, outputCommitments,
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
			t, state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state,
			state.asset1CollectGroupInputAssets, false,
		)
		err := tapsend.PrepareOutputAssets(context.Background(), pkt)
		require.NoError(t, err)
		err = tapsend.SignVirtualTransaction(
			pkt, state.signer, state.witnessValidator,
		)
		require.NoError(t, err)

		outputCommitments, err := tapsend.CreateOutputCommitments(
			[]*tappsbt.VPacket{pkt},
		)
		require.NoError(t, err)

		btcPkt, err := tapsend.CreateAnchorTx([]*tappsbt.VPacket{pkt})
		require.NoError(t, err)

		err = tapsend.UpdateTaprootOutputKeys(
			btcPkt, pkt, outputCommitments,
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

func createSpend(t *testing.T, state *spendData, inputSet commitment.InputSet,
	full bool) (*psbt.Packet, *tappsbt.VPacket, tappsbt.OutputCommitments) {

	spendAddress := state.address1

	if full {
		spendAddress = state.address2
		state.spenderScriptKey = *asset.NUMSPubKey
	}

	pkt := createPacket(
		t, spendAddress, state.asset2PrevID, *state, inputSet, false,
	)

	// For all other tests it's okay to test external indexes that are
	// different from the output index. But here we create an actual TX that
	// will be inspected by the proof verification, so we need to have
	// correct outputs.
	pkt.Outputs[1].AnchorOutputIndex = 1

	err := tapsend.PrepareOutputAssets(context.Background(), pkt)
	require.NoError(t, err)
	err = tapsend.SignVirtualTransaction(
		pkt, state.signer, state.witnessValidator,
	)
	require.NoError(t, err)

	outputCommitments, err := tapsend.CreateOutputCommitments(
		[]*tappsbt.VPacket{pkt},
	)
	require.NoError(t, err)

	btcPkt, err := tapsend.CreateAnchorTx([]*tappsbt.VPacket{pkt})
	require.NoError(t, err)

	err = tapsend.UpdateTaprootOutputKeys(btcPkt, pkt, outputCommitments)
	require.NoError(t, err)

	return btcPkt, pkt, outputCommitments
}

func createProofParams(t *testing.T, genesisTxIn wire.TxIn, state spendData,
	btcPkt *psbt.Packet, pkt *tappsbt.VPacket,
	outputCommitments tappsbt.OutputCommitments) []proof.TransitionParams {

	btcPkt.UnsignedTx.AddTxIn(&genesisTxIn)
	spendTx := btcPkt.UnsignedTx.Copy()
	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(spendTx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	genesisHash := state.asset2GenesisProof.BlockHeader.BlockHash()
	blockHeader := wire.NewBlockHeader(0, &genesisHash, merkleRoot, 0, 0)

	senderAsset := pkt.Outputs[0].Asset
	receiverAsset := pkt.Outputs[1].Asset
	senderTapTree := outputCommitments[pkt.Outputs[0].AnchorOutputIndex]
	receiverTapTree := outputCommitments[pkt.Outputs[1].AnchorOutputIndex]

	_, senderExclusionProof, err := receiverTapTree.Proof(
		senderAsset.TapCommitmentKey(),
		senderAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	_, receiverExclusionProof, err := senderTapTree.Proof(
		receiverAsset.TapCommitmentKey(),
		receiverAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	senderParams := proof.TransitionParams{
		BaseProofParams: proof.BaseProofParams{
			Block: &wire.MsgBlock{
				Header:       *blockHeader,
				Transactions: []*wire.MsgTx{spendTx},
			},
			BlockHeight:      2,
			Tx:               spendTx,
			TxIndex:          0,
			OutputIndex:      0,
			InternalKey:      &state.spenderPubKey,
			TaprootAssetRoot: senderTapTree,
			ExclusionProofs: []proof.TaprootProof{{
				OutputIndex: 1,
				InternalKey: &state.receiverPubKey,
				CommitmentProof: &proof.CommitmentProof{
					Proof: *senderExclusionProof,
				},
			}},
		},
		NewAsset: senderAsset,
	}

	receiverParams := proof.TransitionParams{
		BaseProofParams: proof.BaseProofParams{
			Block: &wire.MsgBlock{
				Header:       *blockHeader,
				Transactions: []*wire.MsgTx{spendTx},
			},
			BlockHeight:      3,
			Tx:               spendTx,
			TxIndex:          0,
			OutputIndex:      1,
			InternalKey:      &state.receiverPubKey,
			TaprootAssetRoot: receiverTapTree,
			ExclusionProofs: []proof.TaprootProof{{
				OutputIndex: 0,
				InternalKey: &state.spenderPubKey,
				CommitmentProof: &proof.CommitmentProof{
					Proof: *receiverExclusionProof,
				},
			}},
		},
		NewAsset:             receiverAsset,
		RootOutputIndex:      0,
		RootInternalKey:      &state.spenderPubKey,
		RootTaprootAssetTree: senderTapTree,
	}

	return []proof.TransitionParams{senderParams, receiverParams}
}

// TestProofVerify tests that a split spend can be used to append to a
// proof file and produce a valid updated proof file.
func TestProofVerify(t *testing.T) {
	t.Parallel()

	state := initSpendScenario(t)

	// Create a proof for the genesis of asset 2.
	createGenesisProof(t, &state)

	genesisProofFile, err := proof.NewFile(
		proof.V0, state.asset2GenesisProof,
	)
	require.NoError(t, err)

	var b bytes.Buffer
	err = genesisProofFile.Encode(&b)
	require.NoError(t, err)
	genesisProofBlob := b.Bytes()

	// Add a PrevID to represent our fake genesis TX.
	genesisOutPoint := &wire.OutPoint{
		Hash:  state.asset2GenesisProof.AnchorTx.TxHash(),
		Index: state.asset2GenesisProof.InclusionProof.OutputIndex,
	}
	state.asset2PrevID = asset.PrevID{
		OutPoint:  *genesisOutPoint,
		ID:        state.asset2.ID(),
		ScriptKey: asset.ToSerialized(&state.spenderScriptKey),
	}
	state.asset2InputAssets = commitment.InputSet{
		state.asset2PrevID: &state.asset2,
	}

	// Perform a split spend of asset 2.
	btcPkt, pkt, outputCommitments := createSpend(
		t, &state, state.asset2InputAssets, false,
	)

	genesisTxIn := wire.TxIn{PreviousOutPoint: *genesisOutPoint}

	proofParams := createProofParams(
		t, genesisTxIn, state, btcPkt, pkt, outputCommitments,
	)

	// Create a proof for each receiver and verify it.
	senderBlob, _, err := proof.AppendTransition(
		genesisProofBlob, &proofParams[0], proof.MockVerifierCtx,
	)
	require.NoError(t, err)
	senderFile := proof.NewEmptyFile(proof.V0)
	require.NoError(t, senderFile.Decode(bytes.NewReader(senderBlob)))
	_, err = senderFile.Verify(
		context.TODO(), proof.MockVerifierCtx,
	)
	require.NoError(t, err)

	receiverBlob, _, err := proof.AppendTransition(
		genesisProofBlob, &proofParams[1], proof.MockVerifierCtx,
	)
	require.NoError(t, err)
	receiverFile, err := proof.NewFile(proof.V0)
	require.NoError(t, err)
	require.NoError(t, receiverFile.Decode(bytes.NewReader(receiverBlob)))
	_, err = receiverFile.Verify(context.TODO(), proof.MockVerifierCtx)
	require.NoError(t, err)
}

func TestProofVerifyFullValueSplit(t *testing.T) {
	t.Parallel()

	state := initSpendScenario(t)

	// Create a proof for the genesis of asset 2.
	createGenesisProof(t, &state)

	genesisProofFile, err := proof.NewFile(
		proof.V0, state.asset2GenesisProof,
	)
	require.NoError(t, err)
	var b bytes.Buffer
	err = genesisProofFile.Encode(&b)
	require.NoError(t, err)
	genesisProofBlob := b.Bytes()

	// Add a PrevID to represent our fake genesis TX.
	genesisOutPoint := &wire.OutPoint{
		Hash:  state.asset2GenesisProof.AnchorTx.TxHash(),
		Index: state.asset2GenesisProof.InclusionProof.OutputIndex,
	}
	state.asset2PrevID = asset.PrevID{
		OutPoint:  *genesisOutPoint,
		ID:        state.asset2.ID(),
		ScriptKey: asset.ToSerialized(&state.spenderScriptKey),
	}
	state.asset2InputAssets = commitment.InputSet{
		state.asset2PrevID: &state.asset2,
	}

	// Perform a full value split spend of asset 2.
	state.spenderScriptKey = *asset.NUMSPubKey

	btcPkt, pkt, outputCommitments := createSpend(
		t, &state, state.asset2InputAssets, true,
	)

	genesisTxIn := wire.TxIn{PreviousOutPoint: *genesisOutPoint}

	proofParams := createProofParams(
		t, genesisTxIn, state, btcPkt, pkt, outputCommitments,
	)

	// Create a proof for each receiver and verify it.
	senderBlob, _, err := proof.AppendTransition(
		genesisProofBlob, &proofParams[0], proof.MockVerifierCtx,
	)
	require.NoError(t, err)
	senderFile, err := proof.NewFile(proof.V0)
	require.NoError(t, err)
	require.NoError(t, senderFile.Decode(bytes.NewReader(senderBlob)))
	_, err = senderFile.Verify(context.TODO(), proof.MockVerifierCtx)
	require.NoError(t, err)

	receiverBlob, _, err := proof.AppendTransition(
		genesisProofBlob, &proofParams[1], proof.MockVerifierCtx,
	)
	require.NoError(t, err)
	receiverFile := proof.NewEmptyFile(proof.V0)
	require.NoError(t, receiverFile.Decode(bytes.NewReader(receiverBlob)))
	_, err = receiverFile.Verify(context.TODO(), proof.MockVerifierCtx)
	require.NoError(t, err)
}

// TestPayToAddrScript tests edge cases around creating a P2TR script with
// PayToAddrScript.
func TestPayToAddrScript(t *testing.T) {
	t.Parallel()

	const (
		normalAmt1 = 5
		sendAmt    = 2
	)
	gen := asset.RandGenesis(t, asset.Normal)
	ownerDescriptor := test.PubToKeyDesc(test.RandPrivKey().PubKey())

	internalKey := test.RandPrivKey().PubKey()
	recipientScriptKey := asset.NewScriptKeyBip86(test.PubToKeyDesc(
		test.RandPrivKey().PubKey(),
	))

	// Create an asset and derive a commitment for sending 2 of the 5 asset
	// units.
	inputAsset1, err := asset.New(
		gen, uint64(normalAmt1), 1, 1,
		asset.NewScriptKeyBip86(ownerDescriptor), nil,
	)
	require.NoError(t, err)
	inputAsset1AssetTree := sendCommitment(
		t, inputAsset1, sendAmt, recipientScriptKey,
	)
	inputAsset1TapTree, err := commitment.NewTapCommitment(
		nil, inputAsset1AssetTree,
	)
	require.NoError(t, err)

	scriptNoSibling, err := tapscript.PayToAddrScript(
		*internalKey, nil, *inputAsset1TapTree,
	)
	require.NoError(t, err)
	require.Equal(t, scriptNoSibling[0], byte(txscript.OP_1))
	require.Equal(t, scriptNoSibling[1], byte(sha256.Size))

	// Create an address for receiving the 2 units and make sure it matches
	// the script above.
	addr1, err := address.New(
		address.V0, gen, nil, nil, *recipientScriptKey.PubKey,
		*internalKey, sendAmt, nil, &address.RegressionNetTap,
		address.RandProofCourierAddr(t),
	)
	require.NoError(t, err)

	addrOutputKey, err := addr1.TaprootOutputKey()
	require.NoError(t, err)
	require.Equal(
		t, scriptNoSibling[2:], schnorr.SerializePubKey(addrOutputKey),
	)

	// And now the same with an address that has a tapscript sibling.
	sibling, err := commitment.NewPreimageFromLeaf(txscript.NewBaseTapLeaf(
		[]byte("not a valid script"),
	))
	require.NoError(t, err)
	addr2, err := address.New(
		address.V0, gen, nil, nil, *recipientScriptKey.PubKey,
		*internalKey, sendAmt, sibling, &address.RegressionNetTap,
		address.RandProofCourierAddr(t),
	)
	require.NoError(t, err)

	siblingHash, err := sibling.TapHash()
	require.NoError(t, err)
	scriptWithSibling, err := tapscript.PayToAddrScript(
		*internalKey, siblingHash, *inputAsset1TapTree,
	)
	require.NoError(t, err)
	require.Equal(t, scriptWithSibling[0], byte(txscript.OP_1))
	require.Equal(t, scriptWithSibling[1], byte(sha256.Size))

	addrOutputKeySibling, err := addr2.TaprootOutputKey()
	require.NoError(t, err)
	require.Equal(
		t, scriptWithSibling[2:],
		schnorr.SerializePubKey(addrOutputKeySibling),
	)
}

func sendCommitment(t *testing.T, a *asset.Asset, sendAmt btcutil.Amount,
	recipientScriptKey asset.ScriptKey) *commitment.AssetCommitment {

	key := asset.AssetCommitmentKey(a.ID(), recipientScriptKey.PubKey, true)
	tree := mssmt.NewCompactedTree(mssmt.NewDefaultStore())

	sendAsset := a.Copy()
	sendAsset.Amount = uint64(sendAmt)
	sendAsset.ScriptKey = recipientScriptKey
	sendAsset.LockTime = 0
	sendAsset.RelativeLockTime = 0

	var buf bytes.Buffer
	require.NoError(t, sendAsset.Encode(&buf))
	leaf := mssmt.NewLeafNode(buf.Bytes(), uint64(sendAmt))

	// We use the default, in-memory store that doesn't actually use the
	// context.
	updatedTree, err := tree.Insert(context.Background(), key, leaf)
	require.NoError(t, err)

	root, err := updatedTree.Root(context.Background())
	require.NoError(t, err)

	return &commitment.AssetCommitment{
		Version:  a.Version,
		TapKey:   a.TapCommitmentKey(),
		TreeRoot: root,
	}
}

// TestAssertOutputAnchorsEqual tests that invalid output anchor information in
// virtual packets are detected correctly.
func TestAssertOutputAnchorsEqual(t *testing.T) {
	packetWithOutputs := func(outs ...*tappsbt.VOutput) *tappsbt.VPacket {
		return &tappsbt.VPacket{
			Outputs: outs,
		}
	}

	var (
		key1 = test.RandPubKey(t)
		key2 = test.RandPubKey(t)
	)

	testCases := []struct {
		name        string
		packets     []*tappsbt.VPacket
		expectedErr error
	}{
		{
			name: "valid, different anchor output index in same " +
				"packet",
			packets: []*tappsbt.VPacket{
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex: 0,
				}, &tappsbt.VOutput{
					AnchorOutputIndex: 1,
				}),
			},
		},
		{
			name: "valid, identical empty anchors",
			packets: []*tappsbt.VPacket{
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex: 0,
				}, &tappsbt.VOutput{
					AnchorOutputIndex: 0,
				}),
			},
		},
		{
			name: "valid, identical empty anchors in two packets",
			packets: []*tappsbt.VPacket{
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex: 0,
				}),
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex: 0,
				}),
			},
		},
		{
			name: "valid, different anchor output index in two " +
				"packets",
			packets: []*tappsbt.VPacket{
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex: 0,
				}),
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex: 1,
				}),
			},
		},
		{
			name: "invalid, different key",
			packets: []*tappsbt.VPacket{
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex:       0,
					AnchorOutputInternalKey: key1,
				}, &tappsbt.VOutput{
					AnchorOutputIndex:       0,
					AnchorOutputInternalKey: key2,
				}),
			},
			expectedErr: tapsend.ErrInvalidAnchorOutputInfo,
		},
		{
			name: "invalid, different key in two packets",
			packets: []*tappsbt.VPacket{
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex:       0,
					AnchorOutputInternalKey: key1,
				}),
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex:       0,
					AnchorOutputInternalKey: key2,
				}),
			},
			expectedErr: tapsend.ErrInvalidAnchorOutputInfo,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tapsend.AssertOutputAnchorsEqual(tc.packets)
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

// TestAssertInputAnchorsEqual tests that invalid input anchor information in
// virtual packets are detected correctly.
func TestAssertInputAnchorsEqual(t *testing.T) {
	packetWithInputs := func(ins ...*tappsbt.VInput) *tappsbt.VPacket {
		return &tappsbt.VPacket{
			Inputs: ins,
		}
	}

	var (
		op1  = wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
		op2  = wire.OutPoint{Hash: chainhash.Hash{2}, Index: 1}
		key1 = test.RandPubKey(t)
		key2 = test.RandPubKey(t)
	)

	testCases := []struct {
		name        string
		packets     []*tappsbt.VPacket
		expectedErr error
	}{
		{
			name: "valid, different anchor inputs in same packet",
			packets: []*tappsbt.VPacket{
				packetWithInputs(&tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
				}, &tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op2,
					},
				}),
			},
		},
		{
			name: "valid, identical empty anchors",
			packets: []*tappsbt.VPacket{
				packetWithInputs(&tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
				}, &tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
				}),
			},
		},
		{
			name: "valid, identical empty anchors in two packets",
			packets: []*tappsbt.VPacket{
				packetWithInputs(&tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
				}),
				packetWithInputs(&tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
				}),
			},
		},
		{
			name: "valid, different anchor inputs in two packets",
			packets: []*tappsbt.VPacket{
				packetWithInputs(&tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
				}),
				packetWithInputs(&tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op2,
					},
				}),
			},
		},
		{
			name: "invalid, different key",
			packets: []*tappsbt.VPacket{
				packetWithInputs(&tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
					Anchor: tappsbt.Anchor{
						InternalKey: key1,
					},
				}, &tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
					Anchor: tappsbt.Anchor{
						InternalKey: key2,
					},
				}),
			},
			expectedErr: tapsend.ErrInvalidAnchorInputInfo,
		},
		{
			name: "invalid, different key in two packets",
			packets: []*tappsbt.VPacket{
				packetWithInputs(&tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
					Anchor: tappsbt.Anchor{
						InternalKey: key1,
					},
				}),
				packetWithInputs(&tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
					Anchor: tappsbt.Anchor{
						InternalKey: key2,
					},
				}),
			},
			expectedErr: tapsend.ErrInvalidAnchorInputInfo,
		},
		{
			name: "invalid, different pk script in two packets",
			packets: []*tappsbt.VPacket{
				packetWithInputs(&tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
					Anchor: tappsbt.Anchor{
						InternalKey: key1,
						MerkleRoot:  []byte("foo"),
					},
				}),
				packetWithInputs(&tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
					Anchor: tappsbt.Anchor{
						InternalKey: key1,
						MerkleRoot:  []byte("bar"),
					},
				}),
			},
			expectedErr: tapsend.ErrInvalidAnchorInputInfo,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tapsend.AssertInputAnchorsEqual(tc.packets)
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

// TestAssertOutputAnchorsEqual tests that invalid output anchor information in
// virtual packets are detected correctly.
func TestValidateAnchorOutputs(t *testing.T) {
	psbtWithOutputs := func(outs ...psbt.POutput) *psbt.Packet {
		return &psbt.Packet{
			Outputs: outs,
		}
	}
	withTxOuts := func(p *psbt.Packet, txOuts ...*wire.TxOut) *psbt.Packet {
		p.UnsignedTx = &wire.MsgTx{TxOut: txOuts}
		return p
	}
	packetWithOutputs := func(outs ...*tappsbt.VOutput) *tappsbt.VPacket {
		return &tappsbt.VPacket{
			Outputs: outs,
		}
	}

	sibling, err := commitment.NewPreimageFromLeaf(txscript.NewBaseTapLeaf(
		[]byte("not a valid script"),
	))
	require.NoError(t, err)

	var (
		key1        = test.RandPubKey(t)
		key2        = test.RandPubKey(t)
		asset1      = asset.RandAsset(t, asset.RandAssetType(t))
		altLeaves   = asset.ToAltLeaves(asset.RandAltLeaves(t, true))
		emptyProof  = &proof.CommitmentProof{}
		vOutSibling = &tappsbt.VOutput{
			AnchorOutputIndex:            0,
			AnchorOutputInternalKey:      key1,
			Asset:                        asset1,
			AnchorOutputTapscriptSibling: sibling,
			ProofSuffix: &proof.Proof{
				InclusionProof: proof.TaprootProof{
					CommitmentProof: emptyProof,
				},
			},
			AltLeaves: altLeaves,
		}
		vOutNoSibling = &tappsbt.VOutput{
			AnchorOutputIndex:       0,
			AnchorOutputInternalKey: key1,
			Asset:                   asset1,
			ProofSuffix: &proof.Proof{
				InclusionProof: proof.TaprootProof{
					CommitmentProof: emptyProof,
				},
			},
			AltLeaves: altLeaves,
		}
		keyRoot = tappsbt.PsbtKeyTypeOutputTaprootMerkleRoot
	)
	asset1Commitment, err := commitment.FromAssets(nil, asset1)
	require.NoError(t, err)

	err = asset1Commitment.MergeAltLeaves(altLeaves)
	require.NoError(t, err)

	vOutCommitmentProof := proof.CommitmentProof{
		Proof: commitment.Proof{
			TaprootAssetProof: commitment.TaprootAssetProof{
				Version: asset1Commitment.Version,
			},
		},
	}
	vOutProofSuffix := proof.Proof{
		InclusionProof: proof.TaprootProof{
			CommitmentProof: &vOutCommitmentProof,
		},
	}
	vOutSibling.ProofSuffix = &vOutProofSuffix
	vOutNoSibling.ProofSuffix = &vOutProofSuffix

	scriptSibling, rootSibling, _, err := tapsend.AnchorOutputScript(
		key1, sibling, asset1Commitment,
	)
	require.NoError(t, err)
	scriptNoSibling, rootNoSibling, _, err := tapsend.AnchorOutputScript(
		key1, nil, asset1Commitment,
	)
	require.NoError(t, err)

	testCases := []struct {
		name         string
		anchor       *psbt.Packet
		packets      []*tappsbt.VPacket
		expectedErr  error
		errSubstring string
		expectedRoot *chainhash.Hash
	}{
		{
			name: "invalid, wrong anchor output index",
			anchor: &psbt.Packet{
				Outputs: nil,
			},
			packets: []*tappsbt.VPacket{
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex: 1,
				}),
			},
			expectedErr:  tapsend.ErrInvalidOutputIndexes,
			errSubstring: "output index 1 is invalid",
		},
		{
			name:   "invalid, missing anchor internal key",
			anchor: psbtWithOutputs(psbt.POutput{}),
			packets: []*tappsbt.VPacket{
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex: 0,
				}),
			},
			expectedErr:  tapsend.ErrInvalidAnchorOutputInfo,
			errSubstring: "internal key missing",
		},
		{
			name: "invalid, different anchor internal key",
			anchor: psbtWithOutputs(psbt.POutput{
				TaprootInternalKey: schnorr.SerializePubKey(
					key1,
				),
			}),
			packets: []*tappsbt.VPacket{
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex:       0,
					AnchorOutputInternalKey: key2,
				}),
			},
			expectedErr:  tapsend.ErrInvalidAnchorOutputInfo,
			errSubstring: "internal key mismatch",
		},
		{
			name: "invalid, different bip32 derivation",
			anchor: psbtWithOutputs(psbt.POutput{
				TaprootInternalKey: schnorr.SerializePubKey(
					key1,
				),
				Bip32Derivation: []*psbt.Bip32Derivation{
					{},
					{},
				},
			}),
			packets: []*tappsbt.VPacket{
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex:       0,
					AnchorOutputInternalKey: key1,
				}),
			},
			expectedErr:  tapsend.ErrInvalidAnchorOutputInfo,
			errSubstring: "bip32 derivation",
		},
		{
			name: "invalid, asset missing",
			anchor: psbtWithOutputs(psbt.POutput{
				TaprootInternalKey: schnorr.SerializePubKey(
					key1,
				),
			}),
			packets: []*tappsbt.VPacket{
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex:       0,
					AnchorOutputInternalKey: key1,
				}),
			},
			expectedErr: tapsend.ErrAssetMissing,
		},
		{
			name: "invalid, asset has no witness",
			anchor: psbtWithOutputs(psbt.POutput{
				TaprootInternalKey: schnorr.SerializePubKey(
					key1,
				),
			}),
			packets: []*tappsbt.VPacket{
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex:       0,
					AnchorOutputInternalKey: key1,
					Asset:                   &asset.Asset{},
				}),
			},
			expectedErr: tapsend.ErrAssetNotSigned,
		},
		{
			name: "invalid, asset not signed",
			anchor: psbtWithOutputs(psbt.POutput{
				TaprootInternalKey: schnorr.SerializePubKey(
					key1,
				),
			}),
			packets: []*tappsbt.VPacket{
				packetWithOutputs(&tappsbt.VOutput{
					AnchorOutputIndex:       0,
					AnchorOutputInternalKey: key1,
					Asset: &asset.Asset{
						PrevWitnesses: []asset.Witness{
							{},
						},
					},
				}),
			},
			expectedErr: tapsend.ErrAssetNotSigned,
		},
		{
			name: "invalid, invalid script",
			anchor: withTxOuts(psbtWithOutputs(psbt.POutput{
				TaprootInternalKey: schnorr.SerializePubKey(
					key1,
				),
			}), &wire.TxOut{
				PkScript: bytes.Repeat([]byte{0x00}, 32),
			}),
			packets: []*tappsbt.VPacket{
				packetWithOutputs(vOutNoSibling),
			},
			expectedErr:  tapsend.ErrInvalidAnchorOutputInfo,
			errSubstring: "output script mismatch for anchor",
		},
		{
			name: "valid, no sibling",
			anchor: withTxOuts(psbtWithOutputs(psbt.POutput{
				TaprootInternalKey: schnorr.SerializePubKey(
					key1,
				),
			}), &wire.TxOut{
				PkScript: scriptNoSibling,
			}),
			packets: []*tappsbt.VPacket{
				packetWithOutputs(vOutNoSibling),
			},
			expectedRoot: &rootNoSibling,
		},
		{
			name: "valid, with sibling",
			anchor: withTxOuts(psbtWithOutputs(psbt.POutput{
				TaprootInternalKey: schnorr.SerializePubKey(
					key1,
				),
			}), &wire.TxOut{
				PkScript: scriptSibling,
			}),
			packets: []*tappsbt.VPacket{
				packetWithOutputs(vOutSibling),
			},
			expectedRoot: &rootSibling,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tapsend.ValidateAnchorOutputs(
				tc.anchor, tc.packets, true,
			)
			require.ErrorIs(t, err, tc.expectedErr)

			if tc.expectedErr != nil {
				require.ErrorContains(t, err, tc.errSubstring)
			}

			if tc.expectedRoot != nil {
				require.NoError(t, err)
				root := tappsbt.ExtractCustomField(
					tc.anchor.Outputs[0].Unknowns, keyRoot,
				)
				require.Equal(t, tc.expectedRoot[:], root)
			}
		})
	}
}

// TestValidateAnchorInputs tests that invalid input anchor information in
// virtual packets are detected correctly.
func TestValidateAnchorInputs(t *testing.T) {
	psbtWithInputs := func(ins ...psbt.PInput) *psbt.Packet {
		return &psbt.Packet{
			Inputs: ins,
		}
	}
	withTxIns := func(p *psbt.Packet, txIns ...*wire.TxIn) *psbt.Packet {
		p.UnsignedTx = &wire.MsgTx{TxIn: txIns}
		return p
	}
	packetWithInput := func(in tappsbt.VInput,
		a *asset.Asset) *tappsbt.VPacket {

		vPkt := &tappsbt.VPacket{
			ChainParams: &address.RegressionNetTap,
			Inputs: []*tappsbt.VInput{
				&in,
			},
		}
		if a != nil {
			vPkt.SetInputAsset(0, a)
		}

		return vPkt
	}

	sibling, err := commitment.NewPreimageFromLeaf(txscript.NewBaseTapLeaf(
		[]byte("not a valid script"),
	))
	require.NoError(t, err)
	siblingBytes, _, err := commitment.MaybeEncodeTapscriptPreimage(sibling)
	require.NoError(t, err)

	var (
		op1        = wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
		op2        = wire.OutPoint{Hash: chainhash.Hash{2}, Index: 1}
		key1       = test.RandPubKey(t)
		key2       = test.RandPubKey(t)
		key1Bytes  = schnorr.SerializePubKey(key1)
		asset1     = asset.RandAsset(t, asset.RandAssetType(t))
		vInSibling = tappsbt.VInput{
			PrevID: asset.PrevID{
				OutPoint: op1,
			},
			Anchor: tappsbt.Anchor{
				InternalKey:      key1,
				TapscriptSibling: siblingBytes,
			},
		}
		vInNoSibling = tappsbt.VInput{
			PrevID: asset.PrevID{
				OutPoint: op1,
			},
			Anchor: tappsbt.Anchor{
				InternalKey: key1,
			},
		}
	)
	asset1Commitment, err := commitment.FromAssets(nil, asset1)
	require.NoError(t, err)

	scriptSibling, rootSibling, _, err := tapsend.AnchorOutputScript(
		key1, sibling, asset1Commitment,
	)
	require.NoError(t, err)
	scriptNoSibling, rootNoSibling, _, err := tapsend.AnchorOutputScript(
		key1, nil, asset1Commitment,
	)
	require.NoError(t, err)

	packetSibling := packetWithInput(vInSibling, asset1)
	packetSibling.Inputs[0].Anchor.MerkleRoot = rootSibling[:]

	packetNoSibling := packetWithInput(vInNoSibling, asset1)
	packetNoSibling.Inputs[0].Anchor.MerkleRoot = rootNoSibling[:]

	testCases := []struct {
		name         string
		anchor       *psbt.Packet
		packets      []*tappsbt.VPacket
		expectedErr  error
		errSubstring string
	}{
		{
			name:   "invalid, empty inputs",
			anchor: withTxIns(psbtWithInputs()),
			packets: []*tappsbt.VPacket{
				packetWithInput(tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op2,
					},
				}, nil),
			},
			expectedErr:  tapsend.ErrInvalidAnchorInputInfo,
			errSubstring: "prev ID outpoint",
		},
		{
			name: "invalid, wrong inputs",
			anchor: withTxIns(
				psbtWithInputs(psbt.PInput{}), &wire.TxIn{},
			),
			packets: []*tappsbt.VPacket{
				packetWithInput(tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op2,
					},
				}, nil),
			},
			expectedErr:  tapsend.ErrInvalidAnchorInputInfo,
			errSubstring: "prev ID outpoint",
		},
		{
			name: "invalid, missing internal key",
			anchor: withTxIns(
				psbtWithInputs(psbt.PInput{}), &wire.TxIn{
					PreviousOutPoint: op1,
				},
			),
			packets: []*tappsbt.VPacket{
				packetWithInput(tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
				}, nil),
			},
			expectedErr:  tapsend.ErrInvalidAnchorInputInfo,
			errSubstring: "internal key missing",
		},
		{
			name: "invalid, invalid internal key",
			anchor: withTxIns(
				psbtWithInputs(psbt.PInput{
					TaprootInternalKey: []byte("invalid"),
				}), &wire.TxIn{
					PreviousOutPoint: op1,
				},
			),
			packets: []*tappsbt.VPacket{
				packetWithInput(tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
					Anchor: tappsbt.Anchor{
						InternalKey: key2,
					},
				}, nil),
			},
			expectedErr:  tapsend.ErrInvalidAnchorInputInfo,
			errSubstring: "error parsing internal key",
		},
		{
			name: "invalid, wrong internal key",
			anchor: withTxIns(
				psbtWithInputs(psbt.PInput{
					TaprootInternalKey: key1Bytes,
				}), &wire.TxIn{
					PreviousOutPoint: op1,
				},
			),
			packets: []*tappsbt.VPacket{
				packetWithInput(tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
					Anchor: tappsbt.Anchor{
						InternalKey: key2,
					},
				}, nil),
			},
			expectedErr:  tapsend.ErrInvalidAnchorInputInfo,
			errSubstring: "internal key mismatch",
		},
		{
			name: "invalid, invalid sibling preimage",
			anchor: withTxIns(
				psbtWithInputs(psbt.PInput{
					TaprootInternalKey: key1Bytes,
				}), &wire.TxIn{
					PreviousOutPoint: op1,
				},
			),
			packets: []*tappsbt.VPacket{
				packetWithInput(tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
					Anchor: tappsbt.Anchor{
						InternalKey: key1,
						TapscriptSibling: []byte(
							"invalid",
						),
					},
				}, nil),
			},
			expectedErr: tapsend.ErrInvalidAnchorInputInfo,
			errSubstring: "error parsing anchor input tapscript " +
				"sibling",
		},
		{
			name: "invalid, missing utxo info",
			anchor: withTxIns(
				psbtWithInputs(psbt.PInput{
					TaprootInternalKey: key1Bytes,
				}), &wire.TxIn{
					PreviousOutPoint: op1,
				},
			),
			packets: []*tappsbt.VPacket{
				packetWithInput(tappsbt.VInput{
					PrevID: asset.PrevID{
						OutPoint: op1,
					},
					Anchor: tappsbt.Anchor{
						InternalKey:      key1,
						TapscriptSibling: siblingBytes,
					},
				}, nil),
			},
			expectedErr:  tapsend.ErrInvalidAnchorInputInfo,
			errSubstring: "witness UTXO missing",
		},
		{
			name: "invalid, incorrect pk script",
			anchor: withTxIns(
				psbtWithInputs(psbt.PInput{
					TaprootInternalKey: key1Bytes,
					WitnessUtxo: &wire.TxOut{
						PkScript: []byte("invalid"),
					},
				}), &wire.TxIn{
					PreviousOutPoint: op1,
				},
			),
			packets: []*tappsbt.VPacket{
				packetWithInput(vInSibling, asset1),
			},
			expectedErr:  tapsend.ErrInvalidAnchorInputInfo,
			errSubstring: "anchor input script mismatch",
		},
		{
			name: "invalid, invalid merkle root",
			anchor: withTxIns(
				psbtWithInputs(psbt.PInput{
					TaprootInternalKey: key1Bytes,
					WitnessUtxo: &wire.TxOut{
						PkScript: scriptSibling,
					},
				}), &wire.TxIn{
					PreviousOutPoint: op1,
				},
			),
			packets: []*tappsbt.VPacket{
				packetWithInput(vInSibling, asset1),
			},
			expectedErr:  tapsend.ErrInvalidAnchorInputInfo,
			errSubstring: "merkle root mismatch for anchor",
		},
		{
			name: "valid, no sibling",
			anchor: withTxIns(
				psbtWithInputs(psbt.PInput{
					TaprootInternalKey: key1Bytes,
					WitnessUtxo: &wire.TxOut{
						PkScript: scriptNoSibling,
					},
					TaprootMerkleRoot: rootNoSibling[:],
				}), &wire.TxIn{
					PreviousOutPoint: op1,
				},
			),
			packets: []*tappsbt.VPacket{
				packetNoSibling,
			},
		},
		{
			name: "valid, with sibling",
			anchor: withTxIns(
				psbtWithInputs(psbt.PInput{
					TaprootInternalKey: key1Bytes,
					WitnessUtxo: &wire.TxOut{
						PkScript: scriptSibling,
					},
					TaprootMerkleRoot: rootSibling[:],
				}), &wire.TxIn{
					PreviousOutPoint: op1,
				},
			),
			packets: []*tappsbt.VPacket{
				packetSibling,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tapsend.ValidateAnchorInputs(
				tc.anchor, tc.packets, nil,
			)
			require.ErrorIs(t, err, tc.expectedErr)

			if tc.expectedErr != nil {
				require.ErrorContains(t, err, tc.errSubstring)
			}
		})
	}
}

// TestValidateCommitmentKeysUnique tests that the commitment keys in a set of
// virtual packets are unique per TAP commitment key.
func TestValidateCommitmentKeysUnique(t *testing.T) {
	groupPubKey1 := test.RandPubKey(t)
	groupPubKey2 := test.RandPubKey(t)
	groupKey1 := &asset.GroupKey{
		GroupPubKey: *groupPubKey1,
	}
	groupKey2 := &asset.GroupKey{
		GroupPubKey: *groupPubKey2,
	}
	assetID1 := asset.ID{1, 2, 3}
	assetID2 := asset.ID{2, 3, 4}

	scriptKey1 := asset.NewScriptKey(test.RandPubKey(t))
	scriptKey2 := asset.NewScriptKey(test.RandPubKey(t))
	scriptKey3 := asset.NewScriptKey(test.RandPubKey(t))

	makeVPacket := func(assetID asset.ID, groupKey *asset.GroupKey,
		outputKeys []asset.ScriptKey) *tappsbt.VPacket {

		vPkt := &tappsbt.VPacket{
			ChainParams: &address.RegressionNetTap,
			Inputs: []*tappsbt.VInput{
				{
					PrevID: asset.PrevID{
						ID: assetID,
					},
				},
			},
			Outputs: make([]*tappsbt.VOutput, len(outputKeys)),
		}
		var a asset.Asset
		if groupKey != nil {
			a.GroupKey = groupKey
		}
		vPkt.SetInputAsset(0, &a)

		for i, outputKey := range outputKeys {
			vPkt.Outputs[i] = &tappsbt.VOutput{
				ScriptKey: outputKey,
			}
		}

		return vPkt
	}

	tests := []struct {
		name      string
		vPackets  []*tappsbt.VPacket
		expectErr bool
	}{
		{
			name: "no collision, single packet, unique keys",
			vPackets: []*tappsbt.VPacket{
				makeVPacket(
					assetID1, groupKey1,
					[]asset.ScriptKey{
						scriptKey1, scriptKey2,
					},
				),
			},
		},
		{
			name: "no collision, multi group packets, same keys",
			vPackets: []*tappsbt.VPacket{
				makeVPacket(
					assetID1, groupKey1,
					[]asset.ScriptKey{
						scriptKey1, scriptKey2,
					},
				),
				makeVPacket(
					assetID1, nil,
					[]asset.ScriptKey{
						scriptKey1, scriptKey2,
					},
				),
			},
		},
		{
			name: "no collision, multi group packets 2, same keys",
			vPackets: []*tappsbt.VPacket{
				makeVPacket(
					assetID1, groupKey1,
					[]asset.ScriptKey{
						scriptKey1, scriptKey2,
					},
				),
				makeVPacket(
					assetID1, groupKey2,
					[]asset.ScriptKey{
						scriptKey1, scriptKey2,
					},
				),
			},
		},
		{
			name: "no collision, same group packets, unique keys",
			vPackets: []*tappsbt.VPacket{
				makeVPacket(
					assetID1, groupKey1,
					[]asset.ScriptKey{
						scriptKey1, scriptKey2,
					},
				),
				makeVPacket(
					assetID2, groupKey1,
					[]asset.ScriptKey{
						scriptKey3,
					},
				),
			},
		},
		{
			name: "no collision, different asset packets, same " +
				"keys",
			vPackets: []*tappsbt.VPacket{
				makeVPacket(
					assetID1, groupKey1,
					[]asset.ScriptKey{
						scriptKey1, scriptKey2,
					},
				),
				makeVPacket(
					assetID2, groupKey1,
					[]asset.ScriptKey{
						scriptKey1, scriptKey2,
					},
				),
			},
		},
		{
			name: "collision, same asset packets, same keys",
			vPackets: []*tappsbt.VPacket{
				makeVPacket(
					assetID1, nil,
					[]asset.ScriptKey{
						scriptKey1, scriptKey2,
					},
				),
				makeVPacket(
					assetID1, nil,
					[]asset.ScriptKey{
						scriptKey1, scriptKey2,
					},
				),
			},
			expectErr: true,
		},
		{
			name: "no collision, multi asset packets, same keys",
			vPackets: []*tappsbt.VPacket{
				makeVPacket(
					assetID1, nil,
					[]asset.ScriptKey{
						scriptKey1,
					},
				),
				makeVPacket(
					assetID2, nil,
					[]asset.ScriptKey{
						scriptKey1,
					},
				),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tapsend.ValidateCommitmentKeysUnique(tt.vPackets)
			if tt.expectErr {
				require.ErrorIs(
					t, err, tapsend.ErrDuplicateScriptKeys,
				)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
