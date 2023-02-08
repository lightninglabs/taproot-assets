package taroscript_test

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
	"github.com/lightninglabs/taro"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/internal/test"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/taropsbt"
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightninglabs/taro/vm"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
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
	hashBytes1 = [32]byte{
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	}

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
	address1                      address.Taro
	address1CollectGroup          address.Taro
	address2                      address.Taro
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
	asset1TaroTree                commitment.TaroCommitment
	asset1CollectGroupTaroTree    commitment.TaroCommitment
	asset2TaroTree                commitment.TaroCommitment
	asset2GenesisTx               wire.MsgTx
	asset2GenesisProof            proof.Proof
	validator                     taroscript.TxValidator
	signer                        *taroscript.MockSigner
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

	// Keys for sender, receiver, and group. Default to keypath spend
	// for the spender ScriptKey.
	spenderPrivKey, spenderPubKey := btcec.PrivKeyFromBytes(key1Bytes)
	state.spenderPrivKey = *spenderPrivKey
	state.spenderPubKey = *spenderPubKey
	state.spenderDescriptor = keychain.KeyDescriptor{
		PubKey: &state.spenderPubKey,
	}

	spenderScriptKey := asset.NewScriptKeyBIP0086(state.spenderDescriptor)
	state.spenderScriptKey = *spenderScriptKey.PubKey

	receiverPrivKey, receiverPubKey := btcec.PrivKeyFromBytes(key2Bytes)
	state.receiverPrivKey = *receiverPrivKey
	state.receiverPubKey = *receiverPubKey

	groupKey := asset.RandGroupKey(t, state.genesis1collect)
	state.groupKey = *groupKey

	// Addresses to cover both asset types and all three asset values.
	// Store the receiver StateKeys as well.
	address1, err := address.New(
		state.genesis1, nil, state.receiverPubKey, state.receiverPubKey,
		state.normalAmt1, &address.MainNetTaro,
	)
	require.NoError(t, err)
	state.address1 = *address1
	state.address1StateKey = state.address1.AssetCommitmentKey()

	address1CollectGroup, err := address.New(
		state.genesis1collect, &state.groupKey.GroupPubKey,
		state.receiverPubKey, state.receiverPubKey, state.collectAmt,
		&address.TestNet3Taro,
	)
	require.NoError(t, err)
	state.address1CollectGroup = *address1CollectGroup
	state.address1CollectGroupStateKey = state.address1CollectGroup.
		AssetCommitmentKey()

	address2, err := address.New(
		state.genesis1, nil, state.receiverPubKey, state.receiverPubKey,
		state.normalAmt2, &address.MainNetTaro,
	)
	require.NoError(t, err)
	state.address2 = *address2
	state.address2StateKey = state.address2.AssetCommitmentKey()

	// Generate matching assets and PrevIDs.
	updateScenarioAssets(t, &state)

	// Generate matching TaroCommitments.
	updateScenarioCommitments(t, &state)

	// Validator instance needed to call the Taro VM.
	state.validator = &taro.ValidatorV0{}

	// Signer needed to generate a witness for the spend.
	state.signer = taroscript.NewMockSigner(&state.spenderPrivKey)

	return state
}

func updateScenarioAssets(t *testing.T, state *spendData) {
	t.Helper()

	require.NotNil(t, state)

	locktime := uint64(1)
	relLocktime := uint64(1)

	// Assets to cover both asset types and all three asset values.
	asset1, err := asset.New(
		state.genesis1, state.normalAmt1, locktime,
		relLocktime, asset.NewScriptKeyBIP0086(state.spenderDescriptor),
		nil,
	)
	require.NoError(t, err)
	state.asset1 = *asset1

	asset1CollectGroup, err := asset.New(
		state.genesis1collect, state.collectAmt, locktime,
		relLocktime, asset.NewScriptKeyBIP0086(state.spenderDescriptor),
		&state.groupKey,
	)
	require.NoError(t, err)
	state.asset1CollectGroup = *asset1CollectGroup

	asset2, err := asset.New(
		state.genesis1, state.normalAmt2, locktime,
		relLocktime, asset.NewScriptKeyBIP0086(state.spenderDescriptor),
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

	// TaroCommitments for each asset.
	asset1AssetTree, err := commitment.NewAssetCommitment(&state.asset1)
	require.NoError(t, err)
	asset1TaroTree, err := commitment.NewTaroCommitment(asset1AssetTree)
	require.NoError(t, err)
	state.asset1TaroTree = *asset1TaroTree

	asset1CollectGroupAssetTree, err := commitment.NewAssetCommitment(
		&state.asset1CollectGroup,
	)
	require.NoError(t, err)
	asset1CollectGroupTaroTree, err := commitment.NewTaroCommitment(
		asset1CollectGroupAssetTree,
	)
	require.NoError(t, err)
	state.asset1CollectGroupTaroTree = *asset1CollectGroupTaroTree

	asset2AssetTree, err := commitment.NewAssetCommitment(&state.asset2)
	require.NoError(t, err)
	asset2TaroTree, err := commitment.NewTaroCommitment(asset2AssetTree)
	require.NoError(t, err)
	state.asset2TaroTree = *asset2TaroTree
	require.NoError(t, err)
}

func createGenesisProof(t *testing.T, state *spendData) {
	t.Helper()

	// Only making a proof for asset2, to test split asset proofs.
	senderScript, err := taroscript.PayToAddrScript(
		state.spenderPubKey, nil, state.asset2TaroTree,
	)
	require.NoError(t, err)
	asset2GenesisTx := &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{}},
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

	_, asset2CommitmentProof, err := state.asset2TaroTree.Proof(
		state.asset2.TaroCommitmentKey(),
		state.asset2.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	asset2GenesisProof := proof.Proof{
		PrevOut:       state.asset2GenesisTx.TxIn[0].PreviousOutPoint,
		BlockHeader:   *blockHeader,
		AnchorTx:      state.asset2GenesisTx,
		TxMerkleProof: *txMerkleProof,
		Asset:         &state.asset2,
		InclusionProof: proof.TaprootProof{
			OutputIndex: 0,
			InternalKey: &state.spenderPubKey,
			CommitmentProof: &proof.CommitmentProof{
				Proof: *asset2CommitmentProof,
			},
		},
	}

	state.asset2GenesisProof = asset2GenesisProof
}

func createPacket(addr address.Taro, prevInput asset.PrevID,
	state spendData, inputSet commitment.InputSet,
	fullValueInteractive bool) *taropsbt.VPacket {

	inputAsset := inputSet[prevInput]
	inputs := []*taropsbt.VInput{{
		PrevID: prevInput,
	}}
	outputs := []*taropsbt.VOutput{{
		Amount: inputAsset.Amount - addr.Amount,
		ScriptKey: asset.NewScriptKey(
			&state.spenderScriptKey,
		),
		AnchorOutputIndex:       0,
		IsSplitRoot:             true,
		AnchorOutputInternalKey: &state.spenderPubKey,
	}, {
		Amount:                  addr.Amount,
		ScriptKey:               asset.NewScriptKey(&addr.ScriptKey),
		AnchorOutputIndex:       receiverExternalIdx,
		AnchorOutputInternalKey: &addr.InternalKey,
	}}

	if fullValueInteractive {
		outputs = []*taropsbt.VOutput{{
			Interactive: true,
			Amount:      addr.Amount,
			ScriptKey: asset.NewScriptKey(
				&addr.ScriptKey,
			),
			AnchorOutputIndex:       receiverExternalIdx,
			AnchorOutputInternalKey: &state.receiverPubKey,
		}}
	}

	vPacket := &taropsbt.VPacket{
		Inputs:      inputs,
		Outputs:     outputs,
		ChainParams: addr.ChainParams,
	}
	vPacket.SetInputAsset(0, inputAsset, nil)

	return vPacket
}

func checkPreparedOutputsNonInteractive(t *testing.T, packet *taropsbt.VPacket,
	addr address.Taro, scriptKey btcec.PublicKey) {

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
		require.True(t, change.Asset.IsUnspendable())
	}

	require.Equal(t, receiver.Asset.Amount, addr.Amount)
	require.Equal(t, *receiver.Asset.ScriptKey.PubKey, addr.ScriptKey)
}

func checkPreparedOutputsInteractive(t *testing.T, packet *taropsbt.VPacket,
	addr address.Taro, prevInput asset.PrevID) {

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
			require.True(t, signed.IsUnspendable())
		}
	}

	require.Equal(t, raw.ScriptVersion, signed.ScriptVersion)
	require.Equal(t, raw.ScriptKey.PubKey, signed.ScriptKey.PubKey)
	require.Equal(t, raw.GroupKey, signed.GroupKey)
}

func checkTaroCommitment(t *testing.T, assets []*asset.Asset,
	inputCommitment *commitment.TaroCommitment,
	includesAsset, includesAssetCommitment, matchingAsset bool) {

	t.Helper()

	for _, asset := range assets {
		proofAsset, proof, err := inputCommitment.Proof(
			asset.TaroCommitmentKey(),
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

		var taroCommitment *commitment.TaroCommitment
		switch {
		case includesAsset && includesAssetCommitment:
			taroCommitment, err = proof.DeriveByAssetInclusion(
				asset,
			)

		case includesAssetCommitment:
			taroCommitment, err = proof.DeriveByAssetExclusion(
				asset.AssetCommitmentKey(),
			)

		default:
			taroCommitment, err = proof.
				DeriveByAssetCommitmentExclusion(
					asset.TaroCommitmentKey(),
				)
		}
		require.NoError(t, err)

		require.Equal(
			t, inputCommitment.TapLeaf(), taroCommitment.TapLeaf(),
		)
	}
}

func checkOutputCommitments(t *testing.T, vPkt *taropsbt.VPacket,
	outputCommitments []*commitment.TaroCommitment, isSplit bool) {

	t.Helper()

	// Assert deletion of the input asset and possible deletion of the
	// matching AssetCommitment tree.
	senderTree := outputCommitments[0]
	receiverTree := outputCommitments[0]

	// If there are multiple outputs, the receiver should be the second one.
	if len(vPkt.Outputs) > 1 {
		receiverTree = outputCommitments[1]
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
	_, ok := senderCommitments[inputAsset.TaroCommitmentKey()]
	if !ok {
		includesAssetCommitment = false
	}

	inputMatchingAsset := !isSplit

	// If our spend creates an un-spendable root, no asset should exist
	// at the location of the input asset. The same goes for an interactive
	// full value send, which is only a single output.
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

	receiverAsset := outputs[0].Asset
	receiverIndex := outputs[0].AnchorOutputIndex
	receiverTaroTree := outputCommitments[0]
	if len(outputs) > 1 {
		receiverAsset = outputs[1].Asset
		receiverIndex = outputs[1].AnchorOutputIndex
		receiverTaroTree = outputCommitments[1]
	}

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
			state, state.asset2InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)

		checkPreparedOutputsNonInteractive(
			t, pkt, state.address1, state.spenderScriptKey,
		)
		return nil
	},
	err: nil,
}, {
	name: "full value non-interactive send with un-spendable change",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address2, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
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
			state.address2, state.asset2PrevID,
			state, state.asset2InputAssets, true,
		)
		return taroscript.PrepareOutputAssets(pkt)
	},
	err: commitment.ErrInvalidScriptKey,
}, {
	name: "full value interactive send with spendable change",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			state.address2, state.asset2PrevID,
			state, state.asset2InputAssets, true,
		)
		err := taroscript.PrepareOutputAssets(pkt)
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
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID,
			state, state.asset1CollectGroupInputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
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
			state, state.asset2InputAssets, false,
		)
		return taroscript.PrepareOutputAssets(pkt)
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
			state, state.asset1InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)

		pkt.Inputs[0].Asset().Genesis = state.genesis1collect
		return taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
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
			state, state.asset1InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)

		firstPrevID := pkt.Outputs[0].Asset.PrevWitnesses[0].PrevID
		firstPrevID.OutPoint.Index = 1337

		return taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
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
			state.asset1CollectGroupPrevID, state,
			state.asset1CollectGroupInputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[0].Asset.Copy()
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
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
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state,
			state.asset1CollectGroupInputAssets, true,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[0].Asset.Copy()
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
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
			state.address1, state.asset1PrevID,
			state, state.asset1InputAssets, true,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[0].Asset.Copy()
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
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
			state.address1, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[0].Asset.Copy()
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
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
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state,
			state.asset1CollectGroupInputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)

		unvalidatedAsset := pkt.Outputs[0].Asset.Copy()
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		checkSignedAsset(
			t, unvalidatedAsset, pkt.Outputs[0].Asset, true, true,
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
			state, state.asset1InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1TaroTree
		inputCommitments := inputCommitment.Commitments()
		asset1Key := state.asset1.TaroCommitmentKey()
		senderCommitment, ok := inputCommitments[asset1Key]
		require.True(t, ok)

		err = inputCommitment.Delete(senderCommitment)
		require.NoError(t, err)

		_, err = taroscript.CreateOutputCommitments(
			inputCommitment, pkt,
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
			state, state.asset1InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1TaroTree
		inputCommitments := inputCommitment.Commitments()
		asset1Key := state.asset1.TaroCommitmentKey()
		senderCommitment, ok := inputCommitments[asset1Key]
		require.True(t, ok)

		err = senderCommitment.Delete(&state.asset1)
		require.NoError(t, err)

		err = inputCommitment.Upsert(senderCommitment)
		require.NoError(t, err)

		_, err = taroscript.CreateOutputCommitments(
			inputCommitment, pkt,
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
			state.asset1CollectGroupPrevID, state,
			state.asset1CollectGroupInputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1CollectGroupTaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt,
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
			state.address1, state.asset1PrevID,
			state, state.asset1InputAssets, true,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt,
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
			state.address1, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset2TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt,
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
			state.address2, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset2TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt,
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
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state,
			state.asset1CollectGroupInputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1CollectGroupTaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt,
		)
		require.NoError(t, err)

		checkOutputCommitments(t, pkt, outputCommitments, true)
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
			state, state.asset1InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt,
		)
		require.NoError(t, err)

		btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
		require.NoError(t, err)

		outputCommitments[0] = nil

		_, err = taroscript.UpdateTaprootOutputKeys(
			btcPkt, pkt, outputCommitments,
		)
		return err
	},
	err: taroscript.ErrMissingTaroCommitment,
}, {
	name: "missing receiver commitment",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)
		state.spenderScriptKey = *asset.NUMSPubKey

		pkt := createPacket(
			state.address1, state.asset1PrevID,
			state, state.asset1InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt,
		)
		require.NoError(t, err)

		btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
		require.NoError(t, err)

		outputCommitments[1] = nil

		_, err = taroscript.UpdateTaprootOutputKeys(
			btcPkt, pkt, outputCommitments,
		)
		return err
	},
	err: taroscript.ErrMissingTaroCommitment,
}, {
	name: "interactive collectible with group key",
	f: func(t *testing.T) error {
		state := initSpendScenario(t)

		pkt := createPacket(
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state,
			state.asset1CollectGroupInputAssets, true,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1CollectGroupTaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt,
		)
		require.NoError(t, err)

		btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
		require.NoError(t, err)

		_, err = taroscript.UpdateTaprootOutputKeys(
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
			state.address1, state.asset1PrevID,
			state, state.asset1InputAssets, true,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt,
		)
		require.NoError(t, err)

		btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
		require.NoError(t, err)

		_, err = taroscript.UpdateTaprootOutputKeys(
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
			state.address1, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset2TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt,
		)
		require.NoError(t, err)

		btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
		require.NoError(t, err)

		_, err = taroscript.UpdateTaprootOutputKeys(
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
			state.address2, state.asset2PrevID,
			state, state.asset2InputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset2TaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt,
		)
		require.NoError(t, err)

		btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
		require.NoError(t, err)

		_, err = taroscript.UpdateTaprootOutputKeys(
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
			state.address1CollectGroup,
			state.asset1CollectGroupPrevID, state,
			state.asset1CollectGroupInputAssets, false,
		)
		err := taroscript.PrepareOutputAssets(pkt)
		require.NoError(t, err)
		err = taroscript.SignVirtualTransaction(
			pkt, 0, state.signer, state.validator,
		)
		require.NoError(t, err)

		inputCommitment := &state.asset1CollectGroupTaroTree
		outputCommitments, err := taroscript.CreateOutputCommitments(
			inputCommitment, pkt,
		)
		require.NoError(t, err)

		btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
		require.NoError(t, err)

		_, err = taroscript.UpdateTaprootOutputKeys(
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
	full bool) (*psbt.Packet, *taropsbt.VPacket,
	[]*commitment.TaroCommitment) {

	spendAddress := state.address1

	if full {
		spendAddress = state.address2
		state.spenderScriptKey = *asset.NUMSPubKey
	}

	pkt := createPacket(
		spendAddress, state.asset2PrevID, *state, inputSet, false,
	)

	// For all other tests it's okay to test external indexes that are
	// different from the output index. But here we create an actual TX that
	// will be inspected by the proof verification, so we need to have
	// correct outputs.
	pkt.Outputs[1].AnchorOutputIndex = 1

	err := taroscript.PrepareOutputAssets(pkt)
	require.NoError(t, err)
	err = taroscript.SignVirtualTransaction(
		pkt, 0, state.signer, state.validator,
	)
	require.NoError(t, err)

	inputCommitment := &state.asset2TaroTree
	outputCommitments, err := taroscript.CreateOutputCommitments(
		inputCommitment, pkt,
	)
	require.NoError(t, err)

	btcPkt, err := taroscript.CreateAnchorTx(pkt.Outputs)
	require.NoError(t, err)

	_, err = taroscript.UpdateTaprootOutputKeys(
		btcPkt, pkt, outputCommitments,
	)
	require.NoError(t, err)

	return btcPkt, pkt, outputCommitments
}

func createProofParams(t *testing.T, genesisTxIn wire.TxIn, state spendData,
	btcPkt *psbt.Packet, pkt *taropsbt.VPacket,
	outputCommitments []*commitment.TaroCommitment) []proof.TransitionParams {

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
	senderTaroTree := outputCommitments[0]
	receiverTaroTree := outputCommitments[1]

	_, senderExclusionProof, err := receiverTaroTree.Proof(
		senderAsset.TaroCommitmentKey(),
		senderAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	_, receiverExclusionProof, err := senderTaroTree.Proof(
		receiverAsset.TaroCommitmentKey(),
		receiverAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)

	senderParams := proof.TransitionParams{
		BaseProofParams: proof.BaseProofParams{
			Block: &wire.MsgBlock{
				Header:       *blockHeader,
				Transactions: []*wire.MsgTx{spendTx},
			},
			Tx:          spendTx,
			TxIndex:     0,
			OutputIndex: 0,
			InternalKey: &state.spenderPubKey,
			TaroRoot:    senderTaroTree,
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
			Tx:          spendTx,
			TxIndex:     0,
			OutputIndex: 1,
			InternalKey: &state.receiverPubKey,
			TaroRoot:    receiverTaroTree,
			ExclusionProofs: []proof.TaprootProof{{
				OutputIndex: 0,
				InternalKey: &state.spenderPubKey,
				CommitmentProof: &proof.CommitmentProof{
					Proof: *receiverExclusionProof,
				},
			}},
		},
		NewAsset:        receiverAsset,
		RootOutputIndex: 0,
		RootInternalKey: &state.spenderPubKey,
		RootTaroTree:    senderTaroTree,
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
		Index: state.asset2GenesisProof.PrevOut.Index,
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
		genesisProofBlob, &proofParams[0], proof.MockHeaderVerifier,
	)
	require.NoError(t, err)
	senderFile := proof.NewEmptyFile(proof.V0)
	require.NoError(t, senderFile.Decode(bytes.NewReader(senderBlob)))
	_, err = senderFile.Verify(context.TODO(), proof.MockHeaderVerifier)
	require.NoError(t, err)

	receiverBlob, _, err := proof.AppendTransition(
		genesisProofBlob, &proofParams[1], proof.MockHeaderVerifier,
	)
	require.NoError(t, err)
	receiverFile, err := proof.NewFile(proof.V0)
	require.NoError(t, err)
	require.NoError(t, receiverFile.Decode(bytes.NewReader(receiverBlob)))
	_, err = receiverFile.Verify(context.TODO(), proof.MockHeaderVerifier)
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
		Index: state.asset2GenesisProof.PrevOut.Index,
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
		genesisProofBlob, &proofParams[0], proof.MockHeaderVerifier,
	)
	require.NoError(t, err)
	senderFile, err := proof.NewFile(proof.V0)
	require.NoError(t, err)
	require.NoError(t, senderFile.Decode(bytes.NewReader(senderBlob)))
	_, err = senderFile.Verify(context.TODO(), proof.MockHeaderVerifier)
	require.NoError(t, err)

	receiverBlob, _, err := proof.AppendTransition(
		genesisProofBlob, &proofParams[1], proof.MockHeaderVerifier,
	)
	require.NoError(t, err)
	receiverFile := proof.NewEmptyFile(proof.V0)
	require.NoError(t, receiverFile.Decode(bytes.NewReader(receiverBlob)))
	_, err = receiverFile.Verify(context.TODO(), proof.MockHeaderVerifier)
	require.NoError(t, err)
}

// TestAreValidAnchorOutputIndexes tests various sets of asset locators to
// assert that we can detect an incomplete set of locators, and sets that form a
// valid Bitcoin transaction.
func TestAreValidAnchorOutputIndexes(t *testing.T) {
	t.Parallel()

	outputs := []*taropsbt.VOutput{}

	// Reject groups of outputs smaller than 1.
	taroOnlySpend, err := taroscript.AreValidAnchorOutputIndexes(outputs)
	require.False(t, taroOnlySpend)
	require.ErrorIs(t, err, taroscript.ErrInvalidOutputIndexes)

	// Insert a locator for the sender and for the receiver, that would form
	// a Taro-only spend.
	outputs = []*taropsbt.VOutput{{
		AnchorOutputIndex: 0,
	}, {
		AnchorOutputIndex: 1,
	}}

	taroOnlySpend, err = taroscript.AreValidAnchorOutputIndexes(outputs)
	require.True(t, taroOnlySpend)
	require.NoError(t, err)

	// Modify the receiver locator so the indexes are no longer continuous.
	outputs[1].AnchorOutputIndex = 2

	taroOnlySpend, err = taroscript.AreValidAnchorOutputIndexes(outputs)
	require.False(t, taroOnlySpend)
	require.NoError(t, err)

	// Check for correctness with more than 2 outputs.
	outputs = append(outputs, &taropsbt.VOutput{
		AnchorOutputIndex: 1,
	})

	taroOnlySpend, err = taroscript.AreValidAnchorOutputIndexes(outputs)
	require.True(t, taroOnlySpend)
	require.NoError(t, err)
}

// TestAddressValidInput tests edge cases around validating inputs for asset
// transfers with isValidInput.
func TestAddressValidInput(t *testing.T) {
	t.Parallel()

	for _, testCase := range addressValidInputTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			inputAsset, checkedInputAsset, err := testCase.f(t)
			require.ErrorIs(t, err, testCase.err)
			if testCase.err == nil {
				require.True(t, inputAsset.DeepEqual(
					checkedInputAsset,
				))
			}
		})
		if !success {
			return
		}
	}
}

func addrToFundDesc(addr address.Taro) *taroscript.FundingDescriptor {
	return &taroscript.FundingDescriptor{
		ID:       addr.ID(),
		GroupKey: addr.GroupKey,
		Amount:   addr.Amount,
	}
}

type addressValidInputTestCase struct {
	name string
	f    func(t *testing.T) (*asset.Asset, *asset.Asset, error)
	err  error
}

var addressValidInputTestCases = []addressValidInputTestCase{{
	name: "valid normal",
	f: func(t *testing.T) (*asset.Asset, *asset.Asset, error) {
		state := initSpendScenario(t)
		inputAsset, fullValue, err := taroscript.IsValidInput(
			&state.asset1TaroTree, addrToFundDesc(state.address1),
			state.spenderScriptKey,
		)
		require.True(t, fullValue)
		return &state.asset1, inputAsset, err
	},
	err: nil,
}, {
	name: "valid collectible with group key",
	f: func(t *testing.T) (*asset.Asset, *asset.Asset, error) {
		state := initSpendScenario(t)
		inputAsset, fullValue, err := taroscript.IsValidInput(
			&state.asset1CollectGroupTaroTree,
			addrToFundDesc(state.address1CollectGroup),
			state.spenderScriptKey,
		)
		require.True(t, fullValue)
		return &state.asset1CollectGroup, inputAsset, err
	},
	err: nil,
}, {
	name: "valid asset split",
	f: func(t *testing.T) (*asset.Asset, *asset.Asset, error) {
		state := initSpendScenario(t)
		inputAsset, fullValue, err := taroscript.IsValidInput(
			&state.asset2TaroTree, addrToFundDesc(state.address1),
			state.spenderScriptKey,
		)
		require.False(t, fullValue)
		return &state.asset2, inputAsset, err
	},
	err: nil,
}, {
	name: "normal with insufficient amount",
	f: func(t *testing.T) (*asset.Asset, *asset.Asset, error) {
		state := initSpendScenario(t)
		inputAsset, fullValue, err := taroscript.IsValidInput(
			&state.asset1TaroTree, addrToFundDesc(state.address2),
			state.spenderScriptKey,
		)
		require.False(t, fullValue)
		return &state.asset1, inputAsset, err
	},
	err: taroscript.ErrInsufficientInputAsset,
}, {
	name: "collectible with missing input asset",
	f: func(t *testing.T) (*asset.Asset, *asset.Asset, error) {
		state := initSpendScenario(t)
		inputAsset, fullValue, err := taroscript.IsValidInput(
			&state.asset1TaroTree,
			addrToFundDesc(state.address1CollectGroup),
			state.spenderScriptKey,
		)
		require.False(t, fullValue)
		return &state.asset1, inputAsset, err
	},
	err: taroscript.ErrMissingInputAsset,
}, {
	name: "normal with bad sender script key",
	f: func(t *testing.T) (*asset.Asset, *asset.Asset, error) {
		state := initSpendScenario(t)
		address1testnet, err := address.New(
			state.genesis1, nil, state.receiverPubKey,
			state.receiverPubKey, state.normalAmt1,
			&address.TestNet3Taro,
		)
		require.NoError(t, err)
		inputAsset, fullValue, err := taroscript.IsValidInput(
			&state.asset1TaroTree, addrToFundDesc(*address1testnet),
			state.receiverPubKey,
		)
		require.False(t, fullValue)
		return &state.asset1, inputAsset, err
	},
	err: taroscript.ErrMissingInputAsset,
}}

// TestPayToAddrScript tests edge cases around creating a P2TR script with
// PayToAddrScript.
func TestPayToAddrScript(t *testing.T) {
	t.Parallel()

	const (
		normalAmt1 = 5
		sendAmt    = 2
	)
	gen := asset.RandGenesis(t, asset.Normal)
	ownerDescriptor := test.PubToKeyDesc(test.RandPrivKey(t).PubKey())

	internalKey := test.RandPrivKey(t).PubKey()
	recipientScriptKey := asset.NewScriptKeyBIP0086(test.PubToKeyDesc(
		test.RandPrivKey(t).PubKey(),
	))

	// Create an asset and derive a commitment for sending 2 of the 5 asset
	// units.
	inputAsset1, err := asset.New(
		gen, uint64(normalAmt1), 1, 1,
		asset.NewScriptKeyBIP0086(ownerDescriptor), nil,
	)
	require.NoError(t, err)
	inputAsset1AssetTree := sendCommitment(
		t, inputAsset1, sendAmt, recipientScriptKey,
	)
	inputAsset1TaroTree, err := commitment.NewTaroCommitment(
		inputAsset1AssetTree,
	)
	require.NoError(t, err)

	scriptNoSibling, err := taroscript.PayToAddrScript(
		*internalKey, nil, *inputAsset1TaroTree,
	)
	require.NoError(t, err)
	require.Equal(t, scriptNoSibling[0], byte(txscript.OP_1))
	require.Equal(t, scriptNoSibling[1], byte(sha256.Size))

	// Create an address for receiving the 2 units and make sure it matches
	// the script above.
	addr1, err := address.New(
		gen, nil, *recipientScriptKey.PubKey, *internalKey, sendAmt,
		&address.RegressionNetTaro,
	)
	require.NoError(t, err)

	addrOutputKey, err := addr1.TaprootOutputKey(nil)
	require.NoError(t, err)
	require.Equal(
		t, scriptNoSibling[2:], schnorr.SerializePubKey(addrOutputKey),
	)

	sibling, err := chainhash.NewHash(hashBytes1[:])
	require.NoError(t, err)
	scriptWithSibling, err := taroscript.PayToAddrScript(
		*internalKey, sibling, *inputAsset1TaroTree,
	)
	require.NoError(t, err)
	require.Equal(t, scriptWithSibling[0], byte(txscript.OP_1))
	require.Equal(t, scriptWithSibling[1], byte(sha256.Size))

	addrOutputKeySibling, err := addr1.TaprootOutputKey(sibling)
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
		AssetID:  a.ID(),
		TreeRoot: root,
	}
}
