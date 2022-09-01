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
		Metadata:     []byte{},
		OutputIndex:  rand.Uint32(),
		Type:         assetType,
	}
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
