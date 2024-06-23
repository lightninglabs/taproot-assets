package address_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

var (
	invalidHrp = "bc"
	invalidNet = address.ChainParams{
		Params: &chaincfg.MainNetParams,
		TapHRP: invalidHrp,
	}
	pubKeyBytes, _ = hex.DecodeString(
		"a0afeb165f0ec36880b68e0baabd9ad9c62fd1a69aa998bc30e9a346202e" +
			"078f",
	)
	pubKey, _ = schnorr.ParsePubKey(pubKeyBytes)

	generatedTestVectorName = "address_tlv_encoding_generated.json"

	allTestVectorFiles = []string{
		generatedTestVectorName,
		"address_tlv_encoding_error_cases.json",
	}
)

func randAddress(t *testing.T, net *address.ChainParams, v *address.Version,
	groupPubKey, sibling bool, amt *uint64, assetType asset.Type,
	addrOpts ...address.NewAddrOpt) (*address.Tap, error) {

	t.Helper()

	amount := uint64(1)
	if amt != nil {
		amount = *amt
	}

	if amt == nil && assetType == asset.Normal {
		amount = test.RandInt[uint64]()
	}

	var (
		tapscriptSibling *commitment.TapscriptPreimage
		err              error
	)
	if sibling {
		tapscriptSibling, err = commitment.NewPreimageFromLeaf(
			txscript.NewBaseTapLeaf([]byte("not a valid script")),
		)
		require.NoError(t, err)
	}

	scriptKey := *pubKey
	internalKey := *pubKey

	genesis := asset.RandGenesis(t, assetType)

	var (
		groupKey     *btcec.PublicKey
		groupWitness wire.TxWitness
	)

	if groupPubKey {
		protoAsset := asset.NewAssetNoErr(
			t, genesis, amount, 0, 0,
			asset.NewScriptKey(&scriptKey), nil,
		)
		groupInfo := asset.RandGroupKey(t, genesis, protoAsset)
		groupKey = &groupInfo.GroupPubKey
		groupWitness = groupInfo.Witness
	}

	proofCourierAddr := address.RandProofCourierAddr(t)

	vers := test.RandFlip(address.V0, address.V1)
	if v != nil {
		vers = *v
	}

	return address.New(
		vers, genesis, groupKey, groupWitness, scriptKey, internalKey,
		amount, tapscriptSibling, net, proofCourierAddr,
		addrOpts...,
	)
}

func randEncodedAddress(t *testing.T, net *address.ChainParams, groupPubKey,
	sibling bool, assetType asset.Type,
	addrOpts ...address.NewAddrOpt) (*address.Tap, string, error) {

	t.Helper()

	newAddr, err := randAddress(
		t, net, nil, groupPubKey, sibling, nil, assetType, addrOpts...,
	)
	if err != nil {
		return nil, "", err
	}

	encodedAddr, err := newAddr.EncodeAddress()

	return newAddr, encodedAddr, err
}

func assertAddressEqual(t *testing.T, a, b *address.Tap) {
	t.Helper()

	// TODO(jhb): assert the full chainparams, not just the HRP
	require.Equal(t, a.Version, b.Version)
	require.Equal(t, a.ChainParams.TapHRP, b.ChainParams.TapHRP)
	require.Equal(t, a.AssetVersion, b.AssetVersion)
	require.Equal(t, a.AssetID, b.AssetID)
	require.Equal(t, a.GroupKey, b.GroupKey)
	require.Equal(t, a.ScriptKey, b.ScriptKey)
	require.Equal(t, a.InternalKey, b.InternalKey)
	require.Equal(t, a.TapscriptSibling, b.TapscriptSibling)
	require.Equal(t, a.Amount, b.Amount)
	require.Equal(t, a.ProofCourierAddr, b.ProofCourierAddr)
}

// TestNewAddress tests edge cases around creating a new address.
func TestNewAddress(t *testing.T) {
	testCases := []struct {
		name string
		f    func() (*address.Tap, error)
		err  error
	}{
		{
			name: "normal address",
			f: func() (*address.Tap, error) {
				return randAddress(
					t, &address.TestNet3Tap, nil, false,
					false, nil, asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "normal address, v1 asset version",
			f: func() (*address.Tap, error) {
				return randAddress(
					t, &address.TestNet3Tap, nil, false,
					false, nil, asset.Normal,
					address.WithAssetVersion(asset.V1),
				)
			},
			err: nil,
		},
		{
			name: "collectible address with group key, v1 asset " +
				"version",
			f: func() (*address.Tap, error) {
				return randAddress(
					t, &address.MainNetTap, nil, true,
					false, nil, asset.Collectible,
					address.WithAssetVersion(asset.V1),
				)
			},
			err: nil,
		},
		{
			name: "collectible address with group key",
			f: func() (*address.Tap, error) {
				return randAddress(
					t, &address.MainNetTap, nil, true,
					false, nil, asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "collectible address with group key and sibling",
			f: func() (*address.Tap, error) {
				return randAddress(
					t, &address.MainNetTap, nil, true, true,
					nil, asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "invalid normal asset value",
			f: func() (*address.Tap, error) {
				zeroAmt := uint64(0)
				return randAddress(
					t, &address.TestNet3Tap, nil, false,
					false, &zeroAmt, asset.Normal,
				)
			},
			err: address.ErrInvalidAmountNormal,
		},
		{
			name: "invalid collectible asset value",
			f: func() (*address.Tap, error) {
				badAmt := uint64(2)
				return randAddress(
					t, &address.TestNet3Tap, nil, false,
					false, &badAmt, asset.Collectible,
				)
			},
			err: address.ErrInvalidAmountCollectible,
		},
		{
			name: "invalid hrp",
			f: func() (*address.Tap, error) {
				return randAddress(
					t, &invalidNet, nil, false, false, nil,
					asset.Normal,
				)
			},
			err: address.ErrUnsupportedHRP,
		},
		{
			name: "invalid version",
			f: func() (*address.Tap, error) {
				return randAddress(
					t, &address.TestNet3Tap,
					fn.Ptr(address.Version(123)), false,
					false, nil, asset.Normal,
				)
			},
			err: address.ErrUnknownVersion,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

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

	testVectors := &address.TestVectors{}
	assertAddressEncoding := func(comment string, a *address.Tap) {
		t.Helper()

		assertAddressEqual(t, a, a.Copy())
		addr, err := a.EncodeAddress()
		require.NoError(t, err)
		net, err := a.Net()
		require.NoError(t, err)
		b, err := address.DecodeAddress(addr, net)
		require.NoError(t, err)
		assertAddressEqual(t, a, b)

		testVectors.ValidTestCases = append(
			testVectors.ValidTestCases, &address.ValidTestCase{
				Address:  address.NewTestFromAddress(t, a),
				Expected: addr,
				Comment:  comment,
			},
		)
	}

	testCases := []struct {
		name string
		f    func() (*address.Tap, string, error)
		err  error
	}{
		{
			name: "valid regtest address",
			f: func() (*address.Tap, string, error) {
				return randEncodedAddress(
					t, &address.RegressionNetTap, false,
					false, asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "valid simnet address",
			f: func() (*address.Tap, string, error) {
				return randEncodedAddress(
					t, &address.SimNetTap, false, false,
					asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "valid testnet address",
			f: func() (*address.Tap, string, error) {
				return randEncodedAddress(
					t, &address.TestNet3Tap, false, false,
					asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "valid mainnet address",
			f: func() (*address.Tap, string, error) {
				return randEncodedAddress(
					t, &address.MainNetTap, false, false,
					asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "valid addr, v1 asset version",
			f: func() (*address.Tap, string, error) {
				return randEncodedAddress(
					t, &address.MainNetTap, false, false,
					asset.Normal,
					address.WithAssetVersion(asset.V1),
				)
			},
			err: nil,
		},
		{
			name: "signet group collectible",
			f: func() (*address.Tap, string, error) {
				return randEncodedAddress(
					t, &address.SigNetTap, true, false,
					asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "simnet collectible",
			f: func() (*address.Tap, string, error) {
				return randEncodedAddress(
					t, &address.SimNetTap, false, false,
					asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "simnet collectible with sibling",
			f: func() (*address.Tap, string, error) {
				return randEncodedAddress(
					t, &address.SimNetTap, false, true,
					asset.Collectible,
				)
			},
			err: nil,
		},
		{
			name: "unsupported hrp",
			f: func() (*address.Tap, string, error) {
				return randEncodedAddress(
					t, &invalidNet, true, false,
					asset.Collectible,
				)
			},
			err: address.ErrUnsupportedHRP,
		},
		{
			name: "mismatched hrp",
			f: func() (*address.Tap, string, error) {
				newAddr, encodedAddr, _ := randEncodedAddress(
					t, &address.TestNet3Tap, true, false,
					asset.Collectible,
				)
				_, err := address.DecodeAddress(
					encodedAddr, &address.MainNetTap,
				)
				return newAddr, "", err
			},
			err: address.ErrMismatchedHRP,
		},
		{
			name: "missing hrp",
			f: func() (*address.Tap, string, error) {
				newAddr, encodedAddr, _ := randEncodedAddress(
					t, &address.TestNet3Tap, true, false,
					asset.Collectible,
				)
				encodedAddr = encodedAddr[4:]
				_, err := address.DecodeAddress(
					encodedAddr[4:], &address.TestNet3Tap,
				)
				return newAddr, "", err
			},
			err: address.ErrInvalidBech32m,
		},
		{
			name: "unknown version number in constructor",
			f: func() (*address.Tap, string, error) {
				_, err := randAddress(
					t, &address.TestNet3Tap,
					fn.Ptr(address.Version(255)), false,
					true, nil, asset.Collectible,
				)
				return nil, "", err
			},
			err: address.ErrUnknownVersion,
		},
		{
			name: "unknown version number",
			f: func() (*address.Tap, string, error) {
				newAddr, err := randAddress(
					t, &address.TestNet3Tap, nil, false,
					true, nil, asset.Collectible,
				)
				require.NoError(t, err)

				// Patch address version to unknown version.
				newAddr.Version = 255

				// Attempt to encode then decode address.
				// We don't expect an error when encoding.
				encodedAddr, err := newAddr.EncodeAddress()
				require.NoError(t, err)

				// We expect an error to occur here when
				// decoding.
				_, err = address.DecodeAddress(
					encodedAddr, &address.TestNet3Tap,
				)
				return newAddr, "", err
			},
			err: address.ErrUnknownVersion,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		success := t.Run(testCase.name, func(t *testing.T) {
			addr, _, err := testCase.f()
			require.Equal(t, testCase.err, err)
			if testCase.err == nil {
				assertAddressEncoding(testCase.name, addr)
			}
		})
		if !success {
			return
		}
	}

	// Write test vectors to file. This is a no-op if the "gen_test_vectors"
	// build tag is not set.
	test.WriteTestVectors(t, generatedTestVectorName, testVectors)
}

// TestBIPTestVectors tests that the BIP test vectors are passing.
func TestBIPTestVectors(t *testing.T) {
	t.Parallel()

	for idx := range allTestVectorFiles {
		var (
			fileName    = allTestVectorFiles[idx]
			testVectors = &address.TestVectors{}
		)
		test.ParseTestVectors(t, fileName, &testVectors)
		t.Run(fileName, func(tt *testing.T) {
			tt.Parallel()

			runBIPTestVector(tt, testVectors)
		})
	}
}

// runBIPTestVector runs the tests in a single BIP test vector file.
func runBIPTestVector(t *testing.T, testVectors *address.TestVectors) {
	for _, validCase := range testVectors.ValidTestCases {
		validCase := validCase

		t.Run(validCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			a := validCase.Address.ToAddress(tt)

			addrString, err := a.EncodeAddress()
			require.NoError(tt, err)

			areEqual := validCase.Expected == addrString

			// Create nice diff if things don't match.
			if !areEqual {
				chainParams, err := a.Net()
				require.NoError(tt, err)

				expectedAddress, err := address.DecodeAddress(
					validCase.Expected, chainParams,
				)
				require.NoError(tt, err)

				require.Equal(tt, a, expectedAddress)

				// Make sure we still fail the test.
				require.Equal(
					tt, validCase.Expected,
					addrString,
				)
			}

			// We also want to make sure that the address is decoded
			// correctly from the encoded TLV stream.
			chainParams, err := a.Net()
			require.NoError(tt, err)

			decoded, err := address.DecodeAddress(
				validCase.Expected, chainParams,
			)
			require.NoError(tt, err)

			require.Equal(tt, a, decoded)
		})
	}

	for _, invalidCase := range testVectors.ErrorTestCases {
		invalidCase := invalidCase

		t.Run(invalidCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			require.PanicsWithValue(tt, invalidCase.Error, func() {
				invalidCase.Address.ToAddress(tt)
			})
		})
	}
}

func FuzzAddressDecode(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		a := &address.Tap{}
		_ = a.Decode(bytes.NewReader(data))
	})
}
