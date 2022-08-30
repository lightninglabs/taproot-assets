package address

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taro/asset"
	"github.com/lightninglabs/taro/commitment"
	"github.com/lightninglabs/taro/mssmt"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

var (
	hashBytes1 = [32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	invalidHrp     = "bc"
	invalidNet     = ChainParams{&chaincfg.MainNetParams, invalidHrp}
	pubKeyBytes, _ = hex.DecodeString(
		"a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e078f",
	)
	pubKey, _ = schnorr.ParsePubKey(pubKeyBytes)
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
		Metadata:     nil,
		OutputIndex:  rand.Uint32(),
		Type:         assetType,
	}
}

func randFamilyKey(t *testing.T, genesis asset.Genesis) *asset.FamilyKey {
	t.Helper()
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	genSigner := asset.NewRawKeyGenesisSigner(privKey)
	fakeKeyDesc := keychain.KeyDescriptor{
		PubKey: privKey.PubKey(),
	}
	familyKey, err := asset.DeriveFamilyKey(genSigner, fakeKeyDesc, genesis)
	require.NoError(t, err)

	return familyKey
}

func randAddress(t *testing.T, net *ChainParams, famKey bool,
	amt *uint64, assetType asset.Type) (*Taro, error) {

	t.Helper()

	var amount uint64
	amount = 1
	if amt != nil {
		amount = *amt
	}

	if amt == nil && assetType == asset.Normal {
		amount = rand.Uint64()
	}

	var familyKey *btcec.PublicKey
	if famKey {
		familyKey = pubKey
	}

	pubKeyCopy1 := *pubKey
	pubKeyCopy2 := *pubKey

	return New(
		hashBytes1, familyKey, pubKeyCopy1, pubKeyCopy2, amount,
		assetType, net,
	)
}

func randEncodedAddress(t *testing.T, net *ChainParams, famKey bool,
	assetType asset.Type) (*Taro, string, error) {

	t.Helper()

	var amount uint64
	if assetType == asset.Normal {
		amount = rand.Uint64()
	}

	var familyKey *btcec.PublicKey
	if famKey {
		familyKey = pubKey
	}

	pubKeyCopy1 := *pubKey
	pubKeyCopy2 := *pubKey

	newAddr := Taro{
		ChainParams: net,
		Version:     asset.Version(TaroScriptVersion),
		ID:          hashBytes1,
		FamilyKey:   familyKey,
		ScriptKey:   pubKeyCopy1,
		InternalKey: pubKeyCopy2,
		Amount:      amount,
		Type:        asset.Normal,
	}

	encodedAddr, err := newAddr.EncodeAddress()

	return &newAddr, encodedAddr, err
}

func assertAddressEqual(t *testing.T, a, b *Taro) {
	t.Helper()

	require.Equal(t, a.Version, b.Version)
	require.Equal(t, a.ID, b.ID)
	require.Equal(t, a.FamilyKey, b.FamilyKey)
	require.Equal(t, a.ScriptKey, b.ScriptKey)
	require.Equal(t, a.InternalKey, b.InternalKey)
	require.Equal(t, a.Amount, b.Amount)
	require.Equal(t, a.Type, b.Type)
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
				t, len(splitA.Proof.Nodes), len(splitB.Proof.Nodes),
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

// TestNewAddress tests edge cases around creating a new address.
func TestNewAddress(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		f    func() (*Taro, error)
		err  error
	}{
		{
			name: "normal address",
			f: func() (*Taro, error) {
				return randAddress(
					t, &TestNet3Taro, false, nil,
					asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "collectible address with family key",
			f: func() (*Taro, error) {
				return randAddress(
					t, &MainNetTaro, true, nil,
					asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "invalid normal asset value",
			f: func() (*Taro, error) {
				zeroAmt := uint64(0)
				return randAddress(
					t, &TestNet3Taro, false, &zeroAmt,
					asset.Normal,
				)
			},
			err: ErrInvalidAmountNormal,
		},
		{
			name: "invalid collectible asset value",
			f: func() (*Taro, error) {
				badAmt := uint64(2)
				return randAddress(
					t, &TestNet3Taro, false, &badAmt,
					asset.Collectible,
				)
			},
			err: ErrInvalidAmountCollectible,
		},
		{
			name: "invalid hrp",
			f: func() (*Taro, error) {
				return randAddress(
					t, &invalidNet, false, nil, asset.Normal,
				)
			},
			err: ErrUnsupportedHRP,
		},
		{
			name: "invalid asset type",
			f: func() (*Taro, error) {
				pubKeyCopy1 := *pubKey
				pubKeyCopy2 := *pubKey
				return New(
					hashBytes1, nil, pubKeyCopy1, pubKeyCopy2,
					rand.Uint64(), 2, &MainNetTaro,
				)
			},
			err: ErrUnsupportedAssetType,
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			address, err := testCase.f()
			require.Equal(t, testCase.err, err)

			if testCase.err == nil {
				require.NotNil(t, address)
			} else {
				require.Nil(t, address)
			}
		})
		if !success {
			return
		}
	}
}

// TestAddressValidInput tests edge cases around validating inputs for asset
// transfers with isValidInput.
func TestAddressValidInput(t *testing.T) {
	t.Parallel()

	// Amounts and geneses, needed for addresses and assets.
	collectAmt := 1
	normalAmt1 := 5
	normalAmt2 := 2
	genesis1 := randGenesis(t, asset.Normal)
	genesis1collect := randGenesis(t, asset.Collectible)

	// Keys for sender, receiver, and family.
	spenderKey1 := randKey(t)
	spenderKey2 := randKey(t)
	spenderPubKey1 := spenderKey1.PubKey()
	spenderPubKey2 := spenderKey2.PubKey()
	spender1Descriptor := keychain.KeyDescriptor{
		PubKey: spenderPubKey1,
	}
	familyKey1 := randFamilyKey(t, genesis1collect)
	familyKey1pubkey := familyKey1.FamKey

	// Address for both asset types and networks.
	address1, err := New(
		genesis1.ID(), nil, *spenderPubKey2, *spenderPubKey2,
		uint64(normalAmt1), asset.Normal, &MainNetTaro,
	)
	require.NoError(t, err)
	address1testnet, err := New(
		genesis1.ID(), nil, *spenderPubKey2, *spenderPubKey2,
		uint64(normalAmt1), asset.Normal, &TestNet3Taro,
	)
	require.NoError(t, err)
	address1collectFamily, err := New(
		genesis1collect.ID(), &familyKey1pubkey, *spenderPubKey2,
		*spenderPubKey2, uint64(collectAmt), asset.Collectible,
		&TestNet3Taro,
	)
	require.NoError(t, err)

	// Sender assets of both types.
	inputAsset1, err := asset.New(
		genesis1, uint64(normalAmt1), 1, 1, spender1Descriptor, nil,
	)
	require.NoError(t, err)
	inputAsset1collectFamily, err := asset.New(
		genesis1collect, uint64(collectAmt), 1,
		1, spender1Descriptor, familyKey1,
	)
	require.NoError(t, err)
	inputAsset2, err := asset.New(
		genesis1, uint64(normalAmt2), 1, 1, spender1Descriptor, nil,
	)
	require.NoError(t, err)

	// Sender TaroCommitments for each asset.
	inputAsset1AssetTree, err := commitment.NewAssetCommitment(inputAsset1)
	require.NoError(t, err)
	inputAsset1TaroTree, err := commitment.NewTaroCommitment(
		inputAsset1AssetTree,
	)
	require.NoError(t, err)
	inputAsset1CollectFamilyAssetTree, err := commitment.NewAssetCommitment(
		inputAsset1collectFamily,
	)
	require.NoError(t, err)
	inputAsset1CollectFamilyTaroTree, err := commitment.NewTaroCommitment(
		inputAsset1CollectFamilyAssetTree,
	)
	require.NoError(t, err)
	inputAsset2AssetTree, err := commitment.NewAssetCommitment(inputAsset2)
	require.NoError(t, err)
	inputAsset2TaroTree, err := commitment.NewTaroCommitment(
		inputAsset2AssetTree,
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
				checkedInputAsset, err := isValidInput(
					inputAsset1TaroTree, *address1,
					*spenderPubKey1, &MainNetTaro,
				)
				return inputAsset1, checkedInputAsset, err
			},
			err: nil,
		},
		{
			name: "valid collectible with family key",
			f: func() (*asset.Asset, *asset.Asset, error) {
				checkedInputAsset, err := isValidInput(
					inputAsset1CollectFamilyTaroTree,
					*address1collectFamily, *spenderPubKey1,
					&TestNet3Taro,
				)
				return inputAsset1collectFamily, checkedInputAsset, err
			},
			err: nil,
		},
		{
			name: "normal with insufficient amount",
			f: func() (*asset.Asset, *asset.Asset, error) {
				checkedInputAsset, err := isValidInput(
					inputAsset2TaroTree, *address1,
					*spenderPubKey1, &MainNetTaro,
				)
				return inputAsset2, checkedInputAsset, err
			},
			err: ErrInsufficientInputAsset,
		},
		{
			name: "collectible with missing input asset",
			f: func() (*asset.Asset, *asset.Asset, error) {
				checkedInputAsset, err := isValidInput(
					inputAsset2TaroTree, *address1collectFamily,
					*spenderPubKey1, &TestNet3Taro,
				)
				return inputAsset2, checkedInputAsset, err
			},
			err: ErrMissingInputAsset,
		},
		{
			name: "normal with bad sender script key",
			f: func() (*asset.Asset, *asset.Asset, error) {
				checkedInputAsset, err := isValidInput(
					inputAsset1TaroTree, *address1testnet,
					*spenderPubKey2, &TestNet3Taro,
				)
				return inputAsset1, checkedInputAsset, err
			},
			err: ErrMissingInputAsset,
		},
		{
			name: "normal with mismatched network",
			f: func() (*asset.Asset, *asset.Asset, error) {
				checkedInputAsset, err := isValidInput(
					inputAsset1TaroTree, *address1testnet,
					*spenderPubKey2, &MainNetTaro,
				)
				return inputAsset1, checkedInputAsset, err
			},
			err: ErrMismatchedHRP,
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			inputAsset, checkedInputAsset, err := testCase.f()
			require.Equal(t, testCase.err, err)
			if testCase.err == nil {
				assertAssetEqual(t, inputAsset, checkedInputAsset)
			}
		})
		if !success {
			return
		}
	}
}

// TestPayToAddrScript tests edge cases around creating a P2TR script with
// PayToAddrScript.
func TestPayToAddrScript(t *testing.T) {
	t.Parallel()

	normalAmt1 := 5
	genesis1 := randGenesis(t, asset.Normal)
	receiverKey1 := randKey(t)
	receiverPubKey1 := receiverKey1.PubKey()
	receiver1Descriptor := keychain.KeyDescriptor{PubKey: receiverPubKey1}

	inputAsset1, err := asset.New(
		genesis1, uint64(normalAmt1), 1, 1, receiver1Descriptor, nil,
	)
	require.NoError(t, err)
	inputAsset1AssetTree, err := commitment.NewAssetCommitment(inputAsset1)
	require.NoError(t, err)
	inputAsset1TaroTree, err := commitment.NewTaroCommitment(
		inputAsset1AssetTree,
	)
	require.NoError(t, err)

	scriptNoSibling, err := PayToAddrScript(
		*receiverPubKey1, nil, *inputAsset1TaroTree,
	)
	require.NoError(t, err)
	require.Equal(t, scriptNoSibling[0], byte(txscript.OP_1))
	require.Equal(t, scriptNoSibling[1], byte(sha256.Size))

	sibling, err := chainhash.NewHash(hashBytes1[:])
	require.NoError(t, err)
	scriptWithSibling, err := PayToAddrScript(
		*receiverPubKey1, sibling, *inputAsset1TaroTree,
	)
	require.NoError(t, err)
	require.Equal(t, scriptWithSibling[0], byte(txscript.OP_1))
	require.Equal(t, scriptWithSibling[1], byte(sha256.Size))
}

func TestAddressEncoding(t *testing.T) {
	t.Parallel()

	assetAddressEncoding := func(a *Taro) {
		t.Helper()

		assertAddressEqual(t, a, a.Copy())
		addr, err := a.EncodeAddress()
		require.NoError(t, err)
		net, err := a.Net()
		require.NoError(t, err)
		b, err := DecodeAddress(addr, net)
		require.NoError(t, err)
		assertAddressEqual(t, a, b)
	}

	testCases := []struct {
		name string
		f    func() (*Taro, string, error)
		err  error
	}{
		{
			name: "valid address",
			f: func() (*Taro, string, error) {
				return randEncodedAddress(
					t, &RegressionNetTaro, false, asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "family collectible",
			f: func() (*Taro, string, error) {
				return randEncodedAddress(
					t, &SigNetTaro, true, asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "simnet collectible",
			f: func() (*Taro, string, error) {
				return randEncodedAddress(
					t, &SimNetTaro, false, asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "unsupported hrp",
			f: func() (*Taro, string, error) {
				return randEncodedAddress(
					t, &invalidNet, true, asset.Collectible,
				)
			},
			err: ErrUnsupportedHRP,
		},
		{
			name: "mismatched hrp",
			f: func() (*Taro, string, error) {
				newAddr, encodedAddr, _ := randEncodedAddress(
					t, &TestNet3Taro, true, asset.Collectible,
				)
				_, err := DecodeAddress(encodedAddr, &MainNetTaro)
				return newAddr, "", err
			},
			err: ErrMismatchedHRP,
		},
		{
			name: "missing hrp",
			f: func() (*Taro, string, error) {
				newAddr, encodedAddr, _ := randEncodedAddress(
					t, &TestNet3Taro, true, asset.Collectible,
				)
				encodedAddr = encodedAddr[4:]
				_, err := DecodeAddress(encodedAddr[4:], &TestNet3Taro)
				return newAddr, "", err
			},
			err: ErrInvalidBech32m,
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			addr, _, err := testCase.f()
			require.Equal(t, testCase.err, err)
			if testCase.err == nil {
				assetAddressEncoding(addr)
			}
		})
		if !success {
			return
		}
	}
}
