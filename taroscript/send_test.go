package taroscript

import (
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taro/address"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
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
