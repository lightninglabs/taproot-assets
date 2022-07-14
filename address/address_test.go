package address

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightninglabs/taro/asset"
	"github.com/stretchr/testify/require"
)

var (
	hashBytes1     = [32]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	invalidHrp     = "bc"
	invalidNet     = ChainParams{&chaincfg.MainNetParams, invalidHrp}
	pubKeyBytes, _ = hex.DecodeString(
		"a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e078f",
	)
	pubKey, _ = schnorr.ParsePubKey(pubKeyBytes)
)

func randAddress(t *testing.T, net *ChainParams, famkey bool,
	amt *uint64, assetType asset.Type) (*AddressTaro, error) {

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
	if famkey {
		familyKey = pubKey
	}

	pubKeyCopy1 := *pubKey
	pubKeyCopy2 := *pubKey

	return New(hashBytes1, familyKey, pubKeyCopy1,
		pubKeyCopy2, amount, assetType, net)
}

// TODO: Use network
func randEncodedAddress(t *testing.T, net *ChainParams, famkey bool,
	assetType asset.Type) (*AddressTaro, string, error) {

	t.Helper()

	var amount uint64
	if assetType == asset.Normal {
		amount = rand.Uint64()
	}

	var familyKey *btcec.PublicKey
	if famkey {
		familyKey = pubKey
	}

	pubKeyCopy1 := *pubKey
	pubKeyCopy2 := *pubKey

	newAddr := AddressTaro{net.TaroHRP, asset.Version(TaroScriptVersion),
		hashBytes1, familyKey, pubKeyCopy1, pubKeyCopy2,
		amount, asset.Normal}

	encodedAddr, err := newAddr.EncodeAddress()

	return &newAddr, encodedAddr, err
}

func assertAddressEqual(t *testing.T, a, b *AddressTaro) {
	t.Helper()

	require.Equal(t, a.Version, b.Version)
	require.Equal(t, a.ID, b.ID)
	require.Equal(t, a.FamilyKey, b.FamilyKey)
	require.Equal(t, a.ScriptKey, b.ScriptKey)
	require.Equal(t, a.InternalKey, b.InternalKey)
	require.Equal(t, a.Amount, b.Amount)
	require.Equal(t, a.Type, b.Type)
}

func TestNewAddress(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		f    func() (*AddressTaro, error)
		err  error
	}{
		{
			name: "normal address",
			f: func() (*AddressTaro, error) {
				return randAddress(
					t, &TestNet3Taro, false, nil, asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "collectible address with family key",
			f: func() (*AddressTaro, error) {
				return randAddress(
					t, &MainNetTaro, true, nil, asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "invalid normal asset value",
			f: func() (*AddressTaro, error) {
				zeroAmt := uint64(0)
				return randAddress(
					t, &TestNet3Taro, false, &zeroAmt, asset.Normal,
				)
			},
			err: ErrInvalidAmountNormal,
		},
		{
			name: "invalid collectible asset value",
			f: func() (*AddressTaro, error) {
				badAmt := uint64(2)
				return randAddress(
					t, &TestNet3Taro, false, &badAmt, asset.Collectible,
				)
			},
			err: ErrInvalidAmountCollectible,
		},
		{
			name: "invalid hrp",
			f: func() (*AddressTaro, error) {
				return randAddress(
					t, &invalidNet, false, nil, asset.Normal,
				)
			},
			err: ErrUnsupportedHRP,
		},
		{
			name: "invalid asset type",
			f: func() (*AddressTaro, error) {
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

func TestAddressEncoding(t *testing.T) {
	t.Parallel()

	assetAddressEncoding := func(a *AddressTaro) {
		t.Helper()

		assertAddressEqual(t, a, a.Copy())
		var buf bytes.Buffer
		require.NoError(t, a.Encode(&buf))
		var b AddressTaro
		require.NoError(t, b.Decode(&buf))
		assertAddressEqual(t, a, &b)
	}

	testCases := []struct {
		name string
		f    func() (*AddressTaro, string, error)
		err  error
	}{
		{
			name: "valid address",
			f: func() (*AddressTaro, string, error) {
				return randEncodedAddress(
					t, &TestNet3Taro, false, asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "family collectible",
			f: func() (*AddressTaro, string, error) {
				return randEncodedAddress(
					t, &MainNetTaro, true, asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "unsupported hrp",
			f: func() (*AddressTaro, string, error) {
				return randEncodedAddress(
					t, &invalidNet, true, asset.Collectible,
				)
			},
			err: ErrUnsupportedHRP,
		},
		{
			name: "mismatched hrp",
			f: func() (*AddressTaro, string, error) {
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
			f: func() (*AddressTaro, string, error) {
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
