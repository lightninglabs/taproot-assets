package taroscript

import (
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightninglabs/taro/proof"
	"github.com/lightninglabs/taro/vm"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// spendData represents the collection of structs needed to begin a spend.
type spendData struct {
	collectAmt                     uint64
	normalAmt1                     uint64
	normalAmt2                     uint64
	genesis1                       asset.Genesis
	genesis1collect                asset.Genesis
	spenderPrivKey                 btcec.PrivateKey
	spenderPubKey                  btcec.PublicKey
	spenderScriptKey               btcec.PublicKey
	spenderDescriptor              keychain.KeyDescriptor
	receiverPrivKey                btcec.PrivateKey
	receiverPubKey                 btcec.PublicKey
	familyKey                      asset.FamilyKey
	address1                       address.Taro
	address1CollectFamily          address.Taro
	address2                       address.Taro
	address1StateKey               [32]byte
	address1CollectFamilyStateKey  [32]byte
	address2StateKey               [32]byte
	asset1                         asset.Asset
	asset1CollectFamily            asset.Asset
	asset2                         asset.Asset
	asset1PrevID                   asset.PrevID
	asset1CollectFamilyPrevID      asset.PrevID
	asset2PrevID                   asset.PrevID
	asset1InputAssets              commitment.InputSet
	asset1CollectFamilyInputAssets commitment.InputSet
	asset2InputAssets              commitment.InputSet
	asset1TaroTree                 commitment.TaroCommitment
	asset1CollectFamilyTaroTree    commitment.TaroCommitment
	asset2TaroTree                 commitment.TaroCommitment
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
)

func randKey(t *testing.T) *btcec.PrivateKey {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	return key
}

func randGenesis(t *testing.T, assetType asset.Type) asset.Genesis {
	t.Helper()

	return asset.Genesis{
		FirstPrevOut: wire.OutPoint{},
		Tag:          "",
		Metadata:     []byte{},
		OutputIndex:  rand.Uint32(),
		Type:         assetType,
	}
}

func randFamilyKey(t *testing.T, genesis asset.Genesis) *asset.FamilyKey {
	t.Helper()
	privKey := randKey(t)
	genSigner := asset.NewRawKeyGenesisSigner(privKey)
	fakeKeyDesc := keychain.KeyDescriptor{
		PubKey: privKey.PubKey(),
	}
	familyKey, err := asset.DeriveFamilyKey(genSigner, fakeKeyDesc, genesis)
	require.NoError(t, err)

	return familyKey
}

func initSpendScenario(t *testing.T) spendData {
	t.Helper()

	// Amounts and genesises, needed for addresses and assets. We need both
	// a normal and collectible asset, and three amounts to test splits.
	state := spendData{
		collectAmt:      1,
		normalAmt1:      2,
		normalAmt2:      5,
		genesis1:        randGenesis(t, asset.Normal),
		genesis1collect: randGenesis(t, asset.Collectible),
	}

	// Keys for sender, receiver, and family. Default to keypath spend
	// for the spender ScriptKey.
	spenderPrivKey, spenderPubKey := btcec.PrivKeyFromBytes(key1Bytes)
	state.spenderPrivKey = *spenderPrivKey
	state.spenderPubKey = *spenderPubKey
	spenderScriptKey := *txscript.ComputeTaprootKeyNoScript(
		&state.spenderPubKey,
	)
	state.spenderScriptKey = spenderScriptKey
	state.spenderDescriptor = keychain.KeyDescriptor{
		PubKey: &state.spenderScriptKey,
	}
	receiverPrivKey, receiverPubKey := btcec.PrivKeyFromBytes(key2Bytes)
	state.receiverPrivKey = *receiverPrivKey
	state.receiverPubKey = *receiverPubKey
	familyKey := randFamilyKey(t, state.genesis1collect)
	state.familyKey = *familyKey

	// Addesses to cover both asset types and all three asset values.
	// Store the receiver StateKeys as well.
	address1, err := address.New(
		state.genesis1.ID(), nil, state.receiverPubKey,
		state.receiverPubKey, state.normalAmt1,
		asset.Normal, &address.MainNetTaro,
	)
	require.NoError(t, err)
	state.address1 = *address1
	state.address1StateKey = state.address1.AssetCommitmentKey()

	address1CollectFamily, err := address.New(
		state.genesis1collect.ID(), &state.familyKey.FamKey,
		state.receiverPubKey, state.receiverPubKey, state.collectAmt,
		asset.Collectible, &address.TestNet3Taro,
	)
	require.NoError(t, err)
	state.address1CollectFamily = *address1CollectFamily
	state.address1CollectFamilyStateKey = state.address1CollectFamily.
		AssetCommitmentKey()

	address2, err := address.New(
		state.genesis1.ID(), nil, state.receiverPubKey,
		state.receiverPubKey, state.normalAmt2,
		asset.Normal, &address.MainNetTaro,
	)
	require.NoError(t, err)
	state.address2 = *address2
	state.address2StateKey = state.address2.AssetCommitmentKey()

	// Generate matching assets and PrevIDs.
	updateScenarioAssets(t, &state)

	// Generate matching TaroCommitments.
	updateScenarioCommitments(t, &state)

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
		relLocktime, state.spenderDescriptor, nil,
	)
	require.NoError(t, err)
	state.asset1 = *asset1

	asset1CollectFamily, err := asset.New(
		state.genesis1collect, state.collectAmt, locktime,
		relLocktime, state.spenderDescriptor, &state.familyKey,
	)
	require.NoError(t, err)
	state.asset1CollectFamily = *asset1CollectFamily

	asset2, err := asset.New(
		state.genesis1, state.normalAmt2, locktime,
		relLocktime, state.spenderDescriptor, nil,
	)
	require.NoError(t, err)
	state.asset2 = *asset2

	// Asset PrevIDs, required to represent an input asset for a spend.
	state.asset1PrevID = asset.PrevID{
		OutPoint:  wire.OutPoint{},
		ID:        state.asset1.ID(),
		ScriptKey: state.spenderScriptKey,
	}
	state.asset1CollectFamilyPrevID = asset.PrevID{
		OutPoint:  wire.OutPoint{},
		ID:        state.asset1CollectFamily.ID(),
		ScriptKey: state.spenderScriptKey,
	}
	state.asset2PrevID = asset.PrevID{
		OutPoint:  wire.OutPoint{},
		ID:        state.asset2.ID(),
		ScriptKey: state.spenderScriptKey,
	}

	state.asset1InputAssets = commitment.InputSet{
		state.asset1PrevID: &state.asset1,
	}
	state.asset1CollectFamilyInputAssets = commitment.InputSet{
		state.asset1CollectFamilyPrevID: &state.asset1CollectFamily,
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

	asset1CollectFamilyAssetTree, err := commitment.NewAssetCommitment(
		&state.asset1CollectFamily,
	)
	require.NoError(t, err)
	asset1CollectFamilyTaroTree, err := commitment.NewTaroCommitment(
		asset1CollectFamilyAssetTree,
	)
	require.NoError(t, err)
	state.asset1CollectFamilyTaroTree = *asset1CollectFamilyTaroTree

	asset2AssetTree, err := commitment.NewAssetCommitment(&state.asset2)
	require.NoError(t, err)
	asset2TaroTree, err := commitment.NewTaroCommitment(asset2AssetTree)
	require.NoError(t, err)
	state.asset2TaroTree = *asset2TaroTree
	require.NoError(t, err)
}

func assertAssetEqual(t *testing.T, a, b *asset.Asset) {
	t.Helper()

	require.Equal(t, a.Version, b.Version)
	require.Equal(t, a.Genesis, b.Genesis)
	require.Equal(t, a.Type, b.Type)
	require.Equal(t, a.Amount, b.Amount)
	require.Equal(t, a.LockTime, b.LockTime)
	require.Equal(t, a.RelativeLockTime, b.RelativeLockTime)
	require.Equal(t, len(a.PrevWitnesses), len(b.PrevWitnesses))

	for i := range a.PrevWitnesses {
		witA, witB := a.PrevWitnesses[i], b.PrevWitnesses[i]
		require.Equal(t, witA.PrevID, witB.PrevID)
		require.Equal(t, witA.TxWitness, witB.TxWitness)
		splitA, splitB := witA.SplitCommitment, witB.SplitCommitment

		if witA.SplitCommitment != nil && witB.SplitCommitment != nil {
			require.Equal(
				t, len(splitA.Proof.Nodes),
				len(splitB.Proof.Nodes),
			)
			for i := range splitA.Proof.Nodes {
				nodeA := splitA.Proof.Nodes[i]
				nodeB := splitB.Proof.Nodes[i]
				require.True(t, mssmt.IsEqualNode(nodeA, nodeB))
			}
			require.Equal(t, splitA.RootAsset, splitB.RootAsset)
		} else {
			require.Equal(t, splitA, splitB)
		}
	}

	require.Equal(t, a.SplitCommitmentRoot, b.SplitCommitmentRoot)
	require.Equal(t, a.ScriptVersion, b.ScriptVersion)
	require.Equal(t, a.ScriptKey, b.ScriptKey)
	require.Equal(t, a.FamilyKey, b.FamilyKey)
}

func checkPreparedSplitSpend(t *testing.T, spend *SpendDelta, addr address.Taro,
	prevInput asset.PrevID, scriptKey btcec.PublicKey) {

	t.Helper()

	require.NotNil(t, spend.SplitCommitment)
	require.Equal(t, *spend.NewAsset.ScriptKey.PubKey, scriptKey)
	require.Equal(
		t, spend.NewAsset.Amount,
		spend.InputAssets[prevInput].Amount-addr.Amount,
	)

	receiverStateKey := addr.AssetCommitmentKey()
	receiverLocator, ok := spend.Locators[receiverStateKey]
	require.True(t, ok)
	receiverAsset, ok := spend.SplitCommitment.SplitAssets[receiverLocator]
	require.True(t, ok)
	require.Equal(t, receiverAsset.Asset.Amount, addr.Amount)
	require.Equal(t, *receiverAsset.Asset.ScriptKey.PubKey, addr.ScriptKey)
}

func checkPreparedCompleteSpend(t *testing.T, spend *SpendDelta,
	addr address.Taro, prevInput asset.PrevID) {

	t.Helper()

	require.Nil(t, spend.SplitCommitment)
	require.Equal(t, *spend.NewAsset.ScriptKey.PubKey, addr.ScriptKey)
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
	require.Equal(t, *a.ScriptKey.PubKey, *b.ScriptKey.PubKey)
	require.Equal(t, a.FamilyKey, b.FamilyKey)
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
			assertAssetEqual(t, proofAsset, asset)
		} else {
			if !matchingAsset {
				// Check the included asset is not equal to
				// the one provided; used for the sender tree
				// when the asset was split
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
	prevInput asset.PrevID, spend *SpendDelta,
	newCommmitments SpendCommitments, isSplit bool) {

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

	// Input asset should always be excluded.
	checkTaroCommitment(
		t, []*asset.Asset{spend.InputAssets[prevInput]}, &senderTree,
		false, includesAssetCommitment, !isSplit,
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
		receiverAsset, ok := spend.SplitCommitment.
			SplitAssets[receiverLocator]
		require.True(t, ok)
		checkTaroCommitment(
			t, []*asset.Asset{&receiverAsset.Asset}, &receiverTree,
			true, true, true,
		)
	}
}

func checkSpendOutputs(t *testing.T, addr address.Taro,
	internalKey, scriptKey btcec.PublicKey,
	senderAsset, receiverAsset *asset.Asset,
	commitments SpendCommitments, locators SpendLocators,
	spendingPsbt *psbt.Packet, isSplit bool) {

	t.Helper()

	// Build a TaprootProof for each receiver to prove inclusion
	// or exclusion for each output.
	senderStateKey := asset.AssetCommitmentKey(
		addr.ID, &scriptKey, addr.FamilyKey == nil,
	)
	senderIndex := locators[senderStateKey].OutputIndex
	senderTaroTree := commitments[senderStateKey]
	senderProofAsset, senderTaroProof, err := senderTaroTree.Proof(
		senderAsset.TaroCommitmentKey(),
		senderAsset.AssetCommitmentKey(),
	)
	require.NoError(t, err)
	if senderProofAsset != nil {
		assertAssetEqual(t, senderAsset, senderProofAsset)
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
	assertAssetEqual(t, receiverAsset, receiverProofAsset)
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

	prepareAssetSplitSpendTestCases := []struct {
		name string
		f    func() error
		err  error
	}{
		{
			name: "asset split with custom locators",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset2InputAssets,
				}

				spenderStateKey := asset.AssetCommitmentKey(
					state.asset2.ID(),
					&state.spenderScriptKey, true,
				)
				receiverStateKey := state.address1StateKey

				spend.Locators = make(SpendLocators)
				spend.Locators[spenderStateKey] = commitment.
					SplitLocator{OutputIndex: 0}
				spend.Locators[receiverStateKey] = commitment.
					SplitLocator{OutputIndex: 2}
				spendPrepared, err := prepareAssetSplitSpend(
					state.address1, state.asset2PrevID,
					state.spenderScriptKey, spend,
				)
				require.NoError(t, err)

				checkPreparedSplitSpend(
					t, spendPrepared, state.address1,
					state.asset2PrevID,
					state.spenderScriptKey,
				)
				return nil
			},
			err: nil,
		},
		{
			name: "asset split with mock locators",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset2InputAssets,
				}
				spendPrepared, err := prepareAssetSplitSpend(
					state.address1, state.asset2PrevID,
					state.spenderScriptKey, spend,
				)
				require.NoError(t, err)

				checkPreparedSplitSpend(
					t, spendPrepared, state.address1,
					state.asset2PrevID,
					state.spenderScriptKey,
				)
				return nil
			},
			err: nil,
		},
	}

	for _, testCase := range prepareAssetSplitSpendTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f()
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
}

// TestPrepareAssetCompleteSpend tests the two cases where an asset is spent
// completely, asserting that new asset leaves are correctly created.
func TestPrepareAssetCompleteSpend(t *testing.T) {
	t.Parallel()

	prepareAssetCompleteSpendTestCases := []struct {
		name string
		f    func() error
		err  error
	}{
		{
			name: "collectible with family key",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.
						asset1CollectFamilyInputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1CollectFamily,
					state.asset1CollectFamilyPrevID, spend,
				)
				checkPreparedCompleteSpend(
					t, spendPrepared,
					state.address1CollectFamily,
					state.asset1CollectFamilyPrevID,
				)
				return nil
			},
			err: nil,
		},
		{
			name: "normal asset without split",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset1InputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1, state.asset1PrevID,
					spend,
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

	for _, testCase := range prepareAssetCompleteSpendTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f()
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
}

// TestCompleteAssetSpend tests edge cases around signing a witness for
// an asset transfer and validating that transfer with the Taro VM.
func TestCompleteAssetSpend(t *testing.T) {
	t.Parallel()

	completeAssetSpendTestCases := []struct {
		name string
		f    func() error
		err  error
	}{
		{
			name: "validate with invalid InputAsset",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset1InputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1, state.asset1PrevID,
					spend,
				)
				spendPrepared.InputAssets[state.asset1PrevID].
					Genesis = state.genesis1collect
				_, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset1PrevID, *spendPrepared,
				)
				spendPrepared.InputAssets[state.asset1PrevID].
					Genesis = state.genesis1
				return err
			},
			err: vm.Error{Kind: vm.ErrIDMismatch},
		},
		{
			name: "validate with invalid NewAsset",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset1InputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1, state.asset1PrevID,
					spend,
				)
				spendPrepared.NewAsset.PrevWitnesses[0].PrevID =
					&asset.PrevID{}
				_, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset1PrevID, *spendPrepared,
				)
				return err
			},
			err: vm.Error{Kind: vm.ErrNoInputs},
		},
		{
			name: "validate with empty InputAssets",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset1InputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1, state.asset1PrevID,
					spend,
				)
				delete(
					spendPrepared.InputAssets,
					state.asset1PrevID,
				)
				_, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset1PrevID, *spendPrepared,
				)
				return err
			},
			err: vm.Error{Kind: vm.ErrNoInputs},
		},
		{
			name: "validate collectible with family key",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.
						asset1CollectFamilyInputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1CollectFamily,
					state.asset1CollectFamilyPrevID, spend,
				)
				unvalidatedAsset := spendPrepared.NewAsset
				spendCompleted, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset1CollectFamilyPrevID,
					*spendPrepared,
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
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset1InputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1, state.asset1PrevID,
					spend,
				)
				unvalidatedAsset := spendPrepared.NewAsset
				spendCompleted, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset1PrevID, *spendPrepared,
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
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset2InputAssets,
				}
				spendPrepared, err := prepareAssetSplitSpend(
					state.address1, state.asset2PrevID,
					state.spenderScriptKey, spend,
				)
				require.NoError(t, err)

				unvalidatedAsset := spendPrepared.NewAsset
				spendCompleted, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset2PrevID, *spendPrepared,
				)
				require.NoError(t, err)

				checkValidateSpend(
					t, &unvalidatedAsset,
					&spendCompleted.NewAsset, true,
				)
				return nil
			},
		},
	}

	for _, testCase := range completeAssetSpendTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f()
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
}

// TestCreateSpendCommitments tests edge cases around creating TaroCommitments
// to represent an asset transfer.
func TestCreateSpendCommitments(t *testing.T) {
	t.Parallel()

	createSpendCommitmentsTestCases := []struct {
		name string
		f    func() error
		err  error
	}{
		{
			name: "missing input asset commitment",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset1InputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1, state.asset1PrevID,
					spend,
				)
				spendCompleted, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset1PrevID, *spendPrepared,
				)
				require.NoError(t, err)

				inputCommitments := state.asset1TaroTree.
					Commitments()
				senderCommitment, ok :=
					inputCommitments[state.asset1.
						TaroCommitmentKey()]
				require.True(t, ok)

				senderTaroCommitment := state.asset1TaroTree
				err = senderTaroCommitment.Update(
					senderCommitment, true,
				)
				require.NoError(t, err)

				_, err = createSpendCommitments(
					senderTaroCommitment,
					state.asset1PrevID, *spendCompleted,
					state.address1, state.spenderScriptKey,
				)
				return err
			},
			err: ErrMissingAssetCommitment,
		},
		{
			name: "missing input asset",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset1InputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1, state.asset1PrevID,
					spend,
				)
				spendCompleted, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset1PrevID, *spendPrepared,
				)
				require.NoError(t, err)

				inputCommitments := state.asset1TaroTree.
					Commitments()
				senderCommitment, ok :=
					inputCommitments[state.asset1.
						TaroCommitmentKey()]
				require.True(t, ok)

				err = senderCommitment.Update(
					&state.asset1, true,
				)
				require.NoError(t, err)

				senderTaroCommitment := state.asset1TaroTree
				err = senderTaroCommitment.Update(
					senderCommitment, false,
				)
				require.NoError(t, err)

				_, err = createSpendCommitments(
					senderTaroCommitment,
					state.asset1PrevID, *spendCompleted,
					state.address1, state.spenderScriptKey,
				)
				return err
			},
			err: ErrMissingInputAsset,
		},
		{
			name: "missing locator for receiver split asset",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset2InputAssets,
				}
				spendPrepared, err := prepareAssetSplitSpend(
					state.address1, state.asset2PrevID,
					state.spenderScriptKey, spend,
				)
				require.NoError(t, err)

				spendCompleted, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset2PrevID, *spendPrepared,
				)
				require.NoError(t, err)

				receiverStateKey := state.address1StateKey
				receiverLocator, ok := spendCompleted.
					Locators[receiverStateKey]
				require.True(t, ok)

				delete(
					spendCompleted.SplitCommitment.
						SplitAssets,
					receiverLocator,
				)
				_, err = createSpendCommitments(
					state.asset2TaroTree,
					state.asset2PrevID, *spendCompleted,
					state.address1, state.spenderScriptKey,
				)
				return err
			},
			err: ErrMissingSplitAsset,
		},
		{
			name: "collectible with family key",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.
						asset1CollectFamilyInputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1CollectFamily,
					state.asset1CollectFamilyPrevID, spend,
				)
				spendCompleted, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset1CollectFamilyPrevID,
					*spendPrepared,
				)
				require.NoError(t, err)

				spendCommitments, err := createSpendCommitments(
					state.asset1CollectFamilyTaroTree,
					state.asset1CollectFamilyPrevID,
					*spendCompleted,
					state.address1CollectFamily,
					state.spenderScriptKey,
				)
				require.NoError(t, err)

				senderStateKey := asset.AssetCommitmentKey(
					state.address1CollectFamily.ID,
					&state.spenderScriptKey,
					false,
				)
				receiverStateKey := state.
					address1CollectFamilyStateKey
				checkSpendCommitments(
					t, senderStateKey, receiverStateKey,
					state.asset1CollectFamilyPrevID,
					spendCompleted, spendCommitments, false,
				)
				return nil
			},
			err: nil,
		},
		{
			name: "normal asset without split",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset1InputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1, state.asset1PrevID,
					spend,
				)
				spendCompleted, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset1PrevID, *spendPrepared,
				)
				require.NoError(t, err)

				spendCommitments, err := createSpendCommitments(
					state.asset1TaroTree,
					state.asset1PrevID, *spendCompleted,
					state.address1, state.spenderScriptKey,
				)
				require.NoError(t, err)

				senderStateKey := asset.AssetCommitmentKey(
					state.address1.ID,
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
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset2InputAssets,
				}
				spendPrepared, err := prepareAssetSplitSpend(
					state.address1, state.asset2PrevID,
					state.spenderScriptKey, spend,
				)
				require.NoError(t, err)

				spendCompleted, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset2PrevID, *spendPrepared,
				)
				require.NoError(t, err)

				spendCommitments, err := createSpendCommitments(
					state.asset2TaroTree,
					state.asset2PrevID, *spendCompleted,
					state.address1, state.spenderScriptKey,
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
	}

	for _, testCase := range createSpendCommitmentsTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f()
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
}

// TestCreateSpendOutputs tests edge cases around creating Bitcoin outputs
// that embed TaroCommitments.
func TestCreateSpendOutputs(t *testing.T) {
	t.Parallel()

	createSpendOutputsTestCases := []struct {
		name string
		f    func() error
		err  error
	}{
		{
			name: "missing change commitment",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset1InputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1, state.asset1PrevID,
					spend,
				)
				spendCompleted, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset1PrevID, *spendPrepared,
				)
				require.NoError(t, err)

				spendCommitments, err := createSpendCommitments(
					state.asset1TaroTree,
					state.asset1PrevID, *spendCompleted,
					state.address1, state.spenderScriptKey,
				)
				require.NoError(t, err)

				senderStateKey := asset.AssetCommitmentKey(
					state.address1.ID,
					&state.spenderScriptKey, true,
				)
				delete(spendCommitments, senderStateKey)
				_, err = createSpendOutputs(
					state.address1, spendCompleted.Locators,
					state.spenderPubKey,
					state.spenderScriptKey,
					spendCommitments,
				)
				return err
			},
			err: ErrMissingTaroCommitment,
		},
		{
			name: "missing receciver commitment",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset1InputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1, state.asset1PrevID,
					spend,
				)
				spendCompleted, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset1PrevID, *spendPrepared,
				)
				require.NoError(t, err)

				spendCommitments, err := createSpendCommitments(
					state.asset1TaroTree,
					state.asset1PrevID, *spendCompleted,
					state.address1, state.spenderScriptKey,
				)
				require.NoError(t, err)

				receiverStateKey := state.address1StateKey
				delete(spendCommitments, receiverStateKey)
				_, err = createSpendOutputs(
					state.address1, spendCompleted.Locators,
					state.spenderPubKey,
					state.spenderScriptKey,
					spendCommitments,
				)
				return err
			},
			err: ErrMissingTaroCommitment,
		},
		{
			name: "collectible with family key",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.
						asset1CollectFamilyInputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1CollectFamily,
					state.asset1CollectFamilyPrevID, spend,
				)
				spendCompleted, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset1CollectFamilyPrevID,
					*spendPrepared,
				)
				require.NoError(t, err)

				spendCommitments, err := createSpendCommitments(
					state.asset1CollectFamilyTaroTree,
					state.asset1CollectFamilyPrevID,
					*spendCompleted,
					state.address1CollectFamily,
					state.spenderScriptKey,
				)
				require.NoError(t, err)

				senderStateKey := asset.AssetCommitmentKey(
					state.address1.ID,
					&state.spenderScriptKey, false,
				)
				receiverStateKey := state.
					address1CollectFamilyStateKey
				spendCompleted.Locators = createDummyLocators(
					[][32]byte{
						senderStateKey,
						receiverStateKey,
					},
				)
				spendPsbt, err := createSpendOutputs(
					state.address1CollectFamily,
					spendCompleted.Locators,
					state.spenderPubKey,
					state.spenderScriptKey,
					spendCommitments,
				)
				require.NoError(t, err)

				senderAsset := spendCompleted.
					InputAssets[state.
					asset1CollectFamilyPrevID]
				checkSpendOutputs(
					t, state.address1CollectFamily,
					state.spenderPubKey,
					state.spenderScriptKey,
					senderAsset, &spendCompleted.NewAsset,
					spendCommitments,
					spendCompleted.Locators,
					spendPsbt, false,
				)
				return nil
			},
			err: nil,
		},
		{
			name: "normal asset without split",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset1InputAssets,
				}
				spendPrepared := prepareAssetCompleteSpend(
					state.address1,
					state.asset1PrevID, spend,
				)
				spendCompleted, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset1PrevID, *spendPrepared,
				)
				require.NoError(t, err)

				spendCommitments, err := createSpendCommitments(
					state.asset1TaroTree,
					state.asset1PrevID, *spendCompleted,
					state.address1, state.spenderScriptKey,
				)
				require.NoError(t, err)

				senderStateKey := asset.AssetCommitmentKey(
					state.address1.ID,
					&state.spenderScriptKey, true,
				)
				receiverStateKey := state.address1StateKey
				spendCompleted.Locators = createDummyLocators(
					[][32]byte{
						senderStateKey,
						receiverStateKey,
					},
				)
				spendPsbt, err := createSpendOutputs(
					state.address1, spendCompleted.Locators,
					state.spenderPubKey,
					state.spenderScriptKey,
					spendCommitments,
				)
				require.NoError(t, err)

				senderAsset := spendCompleted.
					InputAssets[state.asset1PrevID]
				checkSpendOutputs(
					t, state.address1, state.spenderPubKey,
					state.spenderScriptKey,
					senderAsset, &spendCompleted.NewAsset,
					spendCommitments,
					spendCompleted.Locators,
					spendPsbt, false,
				)
				return nil
			},
			err: nil,
		},
		{
			name: "asset split",
			f: func() error {
				state := initSpendScenario(t)
				spend := SpendDelta{
					InputAssets: state.asset2InputAssets,
				}
				spendPrepared, err := prepareAssetSplitSpend(
					state.address1, state.asset2PrevID,
					state.spenderScriptKey, spend,
				)
				require.NoError(t, err)

				spendCompleted, err := completeAssetSpend(
					state.spenderPrivKey,
					state.asset2PrevID, *spendPrepared,
				)
				require.NoError(t, err)

				spendCommitments, err := createSpendCommitments(
					state.asset2TaroTree,
					state.asset2PrevID, *spendCompleted,
					state.address1, state.spenderScriptKey,
				)
				require.NoError(t, err)

				receiverStateKey := state.address1StateKey
				receiverLocator := spendCompleted.
					Locators[receiverStateKey]
				receiverAsset := spendCompleted.SplitCommitment.
					SplitAssets[receiverLocator].Asset
				spendPsbt, err := createSpendOutputs(
					state.address1, spendCompleted.Locators,
					state.spenderPubKey,
					state.spenderScriptKey,
					spendCommitments,
				)
				require.NoError(t, err)

				checkSpendOutputs(
					t, state.address1, state.spenderPubKey,
					state.spenderScriptKey,
					&spendCompleted.NewAsset,
					&receiverAsset, spendCommitments,
					spendCompleted.Locators,
					spendPsbt, true,
				)
				return nil
			},
			err: nil,
		},
	}

	for _, testCase := range createSpendOutputsTestCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			err := testCase.f()
			require.ErrorIs(t, err, testCase.err)
		})
		if !success {
			return
		}
	}
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

	locators := make(SpendLocators)

	// Insert a locator for the sender.
	locators[spenderStateKey] = commitment.SplitLocator{
		OutputIndex: 0,
	}

	// Reject groups of locators smaller than 2.
	taroOnlySpend, err := areValidIndexes(locators)
	require.False(t, taroOnlySpend)
	require.ErrorIs(t, err, ErrInvalidOutputIndexes)

	// Insert a locator for the receiver, that would form a Taro-only spend.
	locators[receiverStateKey] = commitment.SplitLocator{
		OutputIndex: 1,
	}

	taroOnlySpend, err = areValidIndexes(locators)
	require.True(t, taroOnlySpend)
	require.NoError(t, err)

	// Modify the receiver locator so the indexes are no longer continuous.
	locators[receiverStateKey] = commitment.SplitLocator{
		OutputIndex: 2,
	}

	taroOnlySpend, err = areValidIndexes(locators)
	require.False(t, taroOnlySpend)
	require.NoError(t, err)

	// Check for correctness with more than 2 locators.
	locators[receiver2StateKey] = commitment.SplitLocator{
		OutputIndex: 1,
	}

	taroOnlySpend, err = areValidIndexes(locators)
	require.True(t, taroOnlySpend)
	require.NoError(t, err)
}

// TestAddressValidInput tests edge cases around validating inputs for asset
// transfers with isValidInput.
func TestAddressValidInput(t *testing.T) {
	t.Parallel()

	state := initSpendScenario(t)

	address1testnet, err := address.New(
		state.genesis1.ID(), nil, state.receiverPubKey,
		state.receiverPubKey, state.normalAmt1, asset.Normal,
		&address.TestNet3Taro,
	)
	require.NoError(t, err)

	testCases := []struct {
		name string
		f    func() (*asset.Asset, *asset.Asset, error)
		err  error
	}{
		{
			name: "valid normal",
			f: func() (*asset.Asset, *asset.Asset, error) {
				inputAsset, needsSplit, err := isValidInput(
					state.asset1TaroTree, state.address1,
					state.spenderScriptKey,
					address.MainNetTaro,
				)
				require.False(t, needsSplit)
				return &state.asset1, inputAsset, err
			},
			err: nil,
		},
		{
			name: "valid collectible with family key",
			f: func() (*asset.Asset, *asset.Asset, error) {
				inputAsset, needsSplit, err := isValidInput(
					state.asset1CollectFamilyTaroTree,
					state.address1CollectFamily,
					state.spenderScriptKey,
					address.TestNet3Taro,
				)
				require.False(t, needsSplit)
				return &state.asset1CollectFamily,
					inputAsset, err
			},
			err: nil,
		},
		{
			name: "valid asset split",
			f: func() (*asset.Asset, *asset.Asset, error) {
				inputAsset, needsSplit, err := isValidInput(
					state.asset2TaroTree, state.address1,
					state.spenderScriptKey,
					address.MainNetTaro,
				)
				require.True(t, needsSplit)
				return &state.asset2, inputAsset, err
			},
			err: nil,
		},
		{
			name: "normal with insufficient amount",
			f: func() (*asset.Asset, *asset.Asset, error) {
				inputAsset, needsSplit, err := isValidInput(
					state.asset1TaroTree, state.address2,
					state.spenderScriptKey,
					address.MainNetTaro,
				)
				require.False(t, needsSplit)
				return &state.asset1, inputAsset, err
			},
			err: ErrInsufficientInputAsset,
		},
		{
			name: "collectible with missing input asset",
			f: func() (*asset.Asset, *asset.Asset, error) {
				inputAsset, needsSplit, err := isValidInput(
					state.asset1TaroTree,
					state.address1CollectFamily,
					state.spenderScriptKey,
					address.TestNet3Taro,
				)
				require.False(t, needsSplit)
				return &state.asset1, inputAsset, err
			},
			err: ErrMissingInputAsset,
		},
		{
			name: "normal with bad sender script key",
			f: func() (*asset.Asset, *asset.Asset, error) {
				inputAsset, needsSplit, err := isValidInput(
					state.asset1TaroTree,
					*address1testnet,
					state.receiverPubKey,
					address.TestNet3Taro,
				)
				require.False(t, needsSplit)
				return &state.asset1, inputAsset, err
			},
			err: ErrMissingInputAsset,
		},
		{
			name: "normal with mismatched network",
			f: func() (*asset.Asset, *asset.Asset, error) {
				inputAsset, needsSplit, err := isValidInput(
					state.asset1TaroTree,
					*address1testnet,
					state.receiverPubKey,
					address.MainNetTaro,
				)
				require.False(t, needsSplit)
				return &state.asset1, inputAsset, err
			},
			err: address.ErrMismatchedHRP,
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			inputAsset, checkedInputAsset, err := testCase.f()
			require.ErrorIs(t, err, testCase.err)
			if testCase.err == nil {
				assertAssetEqual(
					t, inputAsset, checkedInputAsset,
				)
			}
		})
		if !success {
			return
		}
	}
}
