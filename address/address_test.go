package address

import (
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/stretchr/testify/require"
)

var (
	invalidHrp     = "bc"
	invalidNet     = ChainParams{&chaincfg.MainNetParams, invalidHrp}
	pubKeyBytes, _ = hex.DecodeString(
		"a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e" +
			"078f",
	)
	pubKey, _ = schnorr.ParsePubKey(pubKeyBytes)
)

func randAddress(t *testing.T, net *ChainParams, groupPubKey, sibling bool,
	amt *uint64, assetType asset.Type) (*Tap, error) {

	t.Helper()

	amount := uint64(1)
	if amt != nil {
		amount = *amt
	}

	if amt == nil && assetType == asset.Normal {
		amount = rand.Uint64()
	}

	var tapscriptSibling *commitment.TapscriptPreimage
	if sibling {
		tapscriptSibling = commitment.NewPreimageFromLeaf(
			txscript.NewBaseTapLeaf([]byte("not a valid script")),
		)
	}

	pubKeyCopy1 := *pubKey
	pubKeyCopy2 := *pubKey

	genesis := asset.RandGenesis(t, assetType)

	var (
		groupKey *btcec.PublicKey
		groupSig *schnorr.Signature
	)

	if groupPubKey {
		groupInfo := asset.RandGroupKey(t, genesis)
		groupKey = &groupInfo.GroupPubKey
		groupSig = &groupInfo.Sig
	}

	return New(
		genesis, groupKey, groupSig, pubKeyCopy1, pubKeyCopy2, amount,
		tapscriptSibling, net,
	)
}

func randEncodedAddress(t *testing.T, net *ChainParams, groupPubKey,
	sibling bool, assetType asset.Type) (*Tap, string, error) {

	t.Helper()

	newAddr, err := randAddress(
		t, net, groupPubKey, sibling, nil, assetType,
	)
	if err != nil {
		return nil, "", err
	}

	encodedAddr, err := newAddr.EncodeAddress()

	return newAddr, encodedAddr, err
}

func assertAddressEqual(t *testing.T, a, b *Tap) {
	t.Helper()

	require.Equal(t, a.AssetVersion, b.AssetVersion)
	require.Equal(t, a.AssetID, b.AssetID)
	require.Equal(t, a.GroupKey, b.GroupKey)
	require.Equal(t, a.ScriptKey, b.ScriptKey)
	require.Equal(t, a.InternalKey, b.InternalKey)
	require.Equal(t, a.Amount, b.Amount)
}

// TestNewAddress tests edge cases around creating a new address.
func TestNewAddress(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		f    func() (*Tap, error)
		err  error
	}{
		{
			name: "normal address",
			f: func() (*Tap, error) {
				return randAddress(
					t, &TestNet3Tap, false, false, nil,
					asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "collectible address with group key",
			f: func() (*Tap, error) {
				return randAddress(
					t, &MainNetTap, true, false, nil,
					asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "collectible address with group key and sibling",
			f: func() (*Tap, error) {
				return randAddress(
					t, &MainNetTap, true, true, nil,
					asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "invalid normal asset value",
			f: func() (*Tap, error) {
				zeroAmt := uint64(0)
				return randAddress(
					t, &TestNet3Tap, false, false,
					&zeroAmt, asset.Normal,
				)
			},
			err: ErrInvalidAmountNormal,
		},
		{
			name: "invalid collectible asset value",
			f: func() (*Tap, error) {
				badAmt := uint64(2)
				return randAddress(
					t, &TestNet3Tap, false, false, &badAmt,
					asset.Collectible,
				)
			},
			err: ErrInvalidAmountCollectible,
		},
		{
			name: "invalid hrp",
			f: func() (*Tap, error) {
				return randAddress(
					t, &invalidNet, false, false, nil,
					asset.Normal,
				)
			},
			err: ErrUnsupportedHRP,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

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

func TestAddressEncoding(t *testing.T) {
	t.Parallel()

	assertAddressEncoding := func(a *Tap) {
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
		f    func() (*Tap, string, error)
		err  error
	}{
		{
			name: "valid address",
			f: func() (*Tap, string, error) {
				return randEncodedAddress(
					t, &RegressionNetTap, false, false,
					asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "group collectible",
			f: func() (*Tap, string, error) {
				return randEncodedAddress(
					t, &SigNetTap, true, false,
					asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "simnet collectible",
			f: func() (*Tap, string, error) {
				return randEncodedAddress(
					t, &SimNetTap, false, false,
					asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "simnet collectible with sibling",
			f: func() (*Tap, string, error) {
				return randEncodedAddress(
					t, &SimNetTap, false, true,
					asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "unsupported hrp",
			f: func() (*Tap, string, error) {
				return randEncodedAddress(
					t, &invalidNet, true, false,
					asset.Collectible,
				)
			},
			err: ErrUnsupportedHRP,
		},
		{
			name: "mismatched hrp",
			f: func() (*Tap, string, error) {
				newAddr, encodedAddr, _ := randEncodedAddress(
					t, &TestNet3Tap, true, false,
					asset.Collectible,
				)
				_, err := DecodeAddress(
					encodedAddr, &MainNetTap,
				)
				return newAddr, "", err
			},
			err: ErrMismatchedHRP,
		},
		{
			name: "missing hrp",
			f: func() (*Tap, string, error) {
				newAddr, encodedAddr, _ := randEncodedAddress(
					t, &TestNet3Tap, true, false,
					asset.Collectible,
				)
				encodedAddr = encodedAddr[4:]
				_, err := DecodeAddress(
					encodedAddr[4:], &TestNet3Tap,
				)
				return newAddr, "", err
			},
			err: ErrInvalidBech32m,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		success := t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			addr, _, err := testCase.f()
			require.Equal(t, testCase.err, err)
			if testCase.err == nil {
				assertAddressEncoding(addr)
			}
		})
		if !success {
			return
		}
	}
}
