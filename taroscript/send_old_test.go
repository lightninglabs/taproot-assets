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
	"github.com/lightninglabs/taro/taroscript"
	"github.com/lightninglabs/taro/vm"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
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

var (
	key1Bytes, _ = hex.DecodeString(
		"a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e" +
			"078e",
	)
	key2Bytes, _ = hex.DecodeString(
		"a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e" +
			"078d",
	)
	hashBytes1 = [32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
)

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
		Asset:         state.asset2,
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

func createSpend(t *testing.T, state *spendData, spend taroscript.SpendDelta,
	full bool) (psbt.Packet, [32]byte, taroscript.SpendDelta,
	taroscript.SpendCommitments) {

	var (
		spendAddress     address.Taro
		receiverStateKey [32]byte
	)

	if full {
		spendAddress = state.address2
		receiverStateKey = state.address2StateKey
	} else {
		spendAddress = state.address1
		receiverStateKey = state.address1StateKey
	}

	spendPrepared, err := taroscript.PrepareAssetSplitSpend(
		spendAddress, state.asset2PrevID,
		state.spenderScriptKey, spend,
	)
	require.NoError(t, err)

	spendCompleted, err := taroscript.CompleteAssetSpend(
		state.spenderPubKey, *spendPrepared, state.signer,
		state.validator,
	)
	require.NoError(t, err)

	spendCommitments, err := taroscript.CreateSpendCommitments(
		&state.asset2TaroTree, state.asset2PrevID,
		*spendCompleted, spendAddress,
		state.spenderScriptKey,
	)
	require.NoError(t, err)

	spendPsbt, err := taroscript.CreateTemplatePsbt(
		spendCompleted.Locators,
	)
	require.NoError(t, err)
	err = taroscript.CreateSpendOutputs(
		spendAddress, spendCompleted.Locators,
		state.spenderPubKey, state.spenderScriptKey,
		spendCommitments, spendPsbt,
	)
	require.NoError(t, err)

	return *spendPsbt, receiverStateKey, *spendCompleted, spendCommitments
}

func createProofParams(t *testing.T, genesisTxIn wire.TxIn, state spendData,
	spendCompleted taroscript.SpendDelta, spendPsbt psbt.Packet,
	receiverStateKey [32]byte,
	spendCommitments taroscript.SpendCommitments) []proof.TransitionParams {

	spendPsbt.UnsignedTx.AddTxIn(&genesisTxIn)
	spendTx := spendPsbt.UnsignedTx.Copy()
	merkleTree := blockchain.BuildMerkleTreeStore(
		[]*btcutil.Tx{btcutil.NewTx(spendTx)}, false,
	)
	merkleRoot := merkleTree[len(merkleTree)-1]
	genesisHash := state.asset2GenesisProof.BlockHeader.BlockHash()
	blockHeader := wire.NewBlockHeader(0, &genesisHash, merkleRoot, 0, 0)

	receiverLocator := spendCompleted.
		Locators[receiverStateKey]
	receiverAsset := spendCompleted.SplitCommitment.
		SplitAssets[receiverLocator].Asset
	senderStateKey := asset.AssetCommitmentKey(
		state.address1.ID(),
		&state.spenderScriptKey, true,
	)
	senderTaroTree := spendCommitments[senderStateKey]
	receiverTaroTree := spendCommitments[receiverStateKey]

	_, senderExclusionProof, err := receiverTaroTree.Proof(
		spendCompleted.NewAsset.TaroCommitmentKey(),
		spendCompleted.NewAsset.AssetCommitmentKey(),
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
			TaroRoot:    &senderTaroTree,
			ExclusionProofs: []proof.TaprootProof{{
				OutputIndex: 1,
				InternalKey: &state.receiverPubKey,
				CommitmentProof: &proof.CommitmentProof{
					Proof: *senderExclusionProof,
				},
			}},
		},
		NewAsset: &spendCompleted.NewAsset,
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
			TaroRoot:    &receiverTaroTree,
			ExclusionProofs: []proof.TaprootProof{{
				OutputIndex: 0,
				InternalKey: &state.spenderPubKey,
				CommitmentProof: &proof.CommitmentProof{
					Proof: *receiverExclusionProof,
				},
			}},
		},
		NewAsset:        &receiverAsset,
		RootOutputIndex: 0,
		RootInternalKey: &state.spenderPubKey,
		RootTaroTree:    &senderTaroTree,
	}

	return []proof.TransitionParams{senderParams, receiverParams}
}

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
			// Check the included asset is equal to the one provided
			require.NotNil(t, proofAsset)
			require.True(t, proofAsset.DeepEqual(asset))
		} else {
			if !matchingAsset {
				// Check the included asset is not equal to
				// the one provided; used for the sender tree
				// when the asset was split and the script key
				// is reused
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

		var (
			taroCommitment *commitment.TaroCommitment
		)
		if includesAsset && includesAssetCommitment {
			taroCommitment, err = proof.DeriveByAssetInclusion(
				asset,
			)
		} else if includesAssetCommitment {
			taroCommitment, err = proof.DeriveByAssetExclusion(
				asset.AssetCommitmentKey(),
			)
		} else {
			taroCommitment, err = proof.
				DeriveByAssetCommitmentExclusion(
					asset.TaroCommitmentKey(),
				)
		}
		require.NoError(t, err)
		// different root hash if asset is mismatched
		if matchingAsset {
			require.Equal(
				t, inputCommitment.TapLeaf(),
				taroCommitment.TapLeaf(),
			)
		}
	}
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
	spend := taroscript.SpendDelta{
		InputAssets: state.asset2InputAssets,
	}

	spendPsbt, receiverStateKey, spendCompleted, spendCommitments := createSpend(
		t, &state, spend, false,
	)

	genesisTxIn := wire.TxIn{PreviousOutPoint: *genesisOutPoint}

	proofParams := createProofParams(
		t, genesisTxIn, state, spendCompleted, spendPsbt,
		receiverStateKey, spendCommitments,
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

	genesisProofFile, err := proof.NewFile(proof.V0, state.asset2GenesisProof)
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
	spend := taroscript.SpendDelta{
		InputAssets: state.asset2InputAssets,
	}

	state.spenderScriptKey = *asset.NUMSPubKey

	spendPsbt, receiverStateKey, spendCompleted, spendCommitments := createSpend(
		t, &state, spend, true,
	)

	genesisTxIn := wire.TxIn{PreviousOutPoint: *genesisOutPoint}

	proofParams := createProofParams(
		t, genesisTxIn, state, spendCompleted, spendPsbt,
		receiverStateKey, spendCommitments,
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

// TestValidIndexes tests various sets of asset locators to assert that we can
// detect an incomplete set of locators, and sets that form a valid Bitcoin
// transaction.
func TestValidIndexes(t *testing.T) {
	t.Parallel()

	state := initSpendScenario(t)

	spenderStateKey := asset.AssetCommitmentKey(
		state.asset1.ID(), &state.spenderScriptKey, true,
	)
	receiverStateKey := state.address1.AssetCommitmentKey()
	receiver2StateKey := state.address2.AssetCommitmentKey()

	locators := make(taroscript.SpendLocators)

	// Insert a locator for the sender.
	locators[spenderStateKey] = commitment.SplitLocator{
		OutputIndex: 0,
	}

	// Reject groups of locators smaller than 2.
	taroOnlySpend, err := taroscript.AreValidIndexes(locators)
	require.False(t, taroOnlySpend)
	require.ErrorIs(t, err, taroscript.ErrInvalidOutputIndexes)

	// Insert a locator for the receiver, that would form a Taro-only spend.
	locators[receiverStateKey] = commitment.SplitLocator{
		OutputIndex: 1,
	}

	taroOnlySpend, err = taroscript.AreValidIndexes(locators)
	require.True(t, taroOnlySpend)
	require.NoError(t, err)

	// Modify the receiver locator so the indexes are no longer continuous.
	locators[receiverStateKey] = commitment.SplitLocator{
		OutputIndex: 2,
	}

	taroOnlySpend, err = taroscript.AreValidIndexes(locators)
	require.False(t, taroOnlySpend)
	require.NoError(t, err)

	// Check for correctness with more than 2 locators.
	locators[receiver2StateKey] = commitment.SplitLocator{
		OutputIndex: 1,
	}

	taroOnlySpend, err = taroscript.AreValidIndexes(locators)
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

type addressValidInputTestCase struct {
	name string
	f    func(t *testing.T) (*asset.Asset, *asset.Asset, error)
	err  error
}

var addressValidInputTestCases = []addressValidInputTestCase{
	{
		name: "valid normal",
		f: func(t *testing.T) (*asset.Asset, *asset.Asset, error) {
			state := initSpendScenario(t)
			inputAsset, fullValue, err := taroscript.IsValidInput(
				&state.asset1TaroTree, state.address1,
				state.spenderScriptKey, address.MainNetTaro,
			)
			require.True(t, fullValue)
			return &state.asset1, inputAsset, err
		},
		err: nil,
	},
	{
		name: "valid collectible with group key",
		f: func(t *testing.T) (*asset.Asset, *asset.Asset, error) {
			state := initSpendScenario(t)
			inputAsset, fullValue, err := taroscript.IsValidInput(
				&state.asset1CollectGroupTaroTree,
				state.address1CollectGroup,
				state.spenderScriptKey, address.TestNet3Taro,
			)
			require.True(t, fullValue)
			return &state.asset1CollectGroup, inputAsset, err
		},
		err: nil,
	},
	{
		name: "valid asset split",
		f: func(t *testing.T) (*asset.Asset, *asset.Asset, error) {
			state := initSpendScenario(t)
			inputAsset, fullValue, err := taroscript.IsValidInput(
				&state.asset2TaroTree, state.address1,
				state.spenderScriptKey, address.MainNetTaro,
			)
			require.False(t, fullValue)
			return &state.asset2, inputAsset, err
		},
		err: nil,
	},
	{
		name: "normal with insufficient amount",
		f: func(t *testing.T) (*asset.Asset, *asset.Asset, error) {
			state := initSpendScenario(t)
			inputAsset, fullValue, err := taroscript.IsValidInput(
				&state.asset1TaroTree, state.address2,
				state.spenderScriptKey, address.MainNetTaro,
			)
			require.False(t, fullValue)
			return &state.asset1, inputAsset, err
		},
		err: taroscript.ErrInsufficientInputAsset,
	},
	{
		name: "collectible with missing input asset",
		f: func(t *testing.T) (*asset.Asset, *asset.Asset, error) {
			state := initSpendScenario(t)
			inputAsset, fullValue, err := taroscript.IsValidInput(
				&state.asset1TaroTree,
				state.address1CollectGroup,
				state.spenderScriptKey, address.TestNet3Taro,
			)
			require.False(t, fullValue)
			return &state.asset1, inputAsset, err
		},
		err: taroscript.ErrMissingInputAsset,
	},
	{
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
				&state.asset1TaroTree, *address1testnet,
				state.receiverPubKey, address.TestNet3Taro,
			)
			require.False(t, fullValue)
			return &state.asset1, inputAsset, err
		},
		err: taroscript.ErrMissingInputAsset,
	},
	{
		name: "normal with mismatched network",
		f: func(t *testing.T) (*asset.Asset, *asset.Asset, error) {
			state := initSpendScenario(t)
			address1testnet, err := address.New(
				state.genesis1, nil, state.receiverPubKey,
				state.receiverPubKey, state.normalAmt1,
				&address.TestNet3Taro,
			)
			require.NoError(t, err)
			inputAsset, fullValue, err := taroscript.IsValidInput(
				&state.asset1TaroTree, *address1testnet,
				state.receiverPubKey, address.MainNetTaro,
			)
			require.False(t, fullValue)
			return &state.asset1, inputAsset, err
		},
		err: address.ErrMismatchedHRP,
	},
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
