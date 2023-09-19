package address

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
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

	generatedTestVectorName = "address_tlv_encoding_generated.json"

	allTestVectorFiles = []string{
		generatedTestVectorName,
		"address_tlv_encoding_error_cases.json",
	}
)

func randAddress(t *testing.T, net *ChainParams, groupPubKey, sibling bool,
	amt *uint64, assetType asset.Type) (*Tap, error) {

	t.Helper()

	amount := uint64(1)
	if amt != nil {
		amount = *amt
	}

	if amt == nil && assetType == asset.Normal {
		amount = test.RandInt[uint64]()
	}

	var tapscriptSibling *commitment.TapscriptPreimage
	if sibling {
		tapscriptSibling = commitment.NewPreimageFromLeaf(
			txscript.NewBaseTapLeaf([]byte("not a valid script")),
		)
	}

	scriptKey := *pubKey
	internalKey := *pubKey

	genesis := asset.RandGenesis(t, assetType)

	var (
		groupKey     *btcec.PublicKey
		groupWitness wire.TxWitness
	)

	if groupPubKey {
		protoAsset := asset.AssetNoErr(
			t, genesis, amount, 0, 0,
			asset.NewScriptKey(&scriptKey), nil,
		)
		groupInfo := asset.RandGroupKey(t, genesis, protoAsset)
		groupKey = &groupInfo.GroupPubKey
		groupWitness = groupInfo.Witness
	}

	proofCourierAddr := RandProofCourierAddr(t)

	return New(
		genesis, groupKey, groupWitness, scriptKey, internalKey,
		amount, tapscriptSibling, net, proofCourierAddr,
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

	testVectors := &TestVectors{}
	assertAddressEncoding := func(comment string, a *Tap) {
		t.Helper()

		assertAddressEqual(t, a, a.Copy())
		addr, err := a.EncodeAddress()
		require.NoError(t, err)
		net, err := a.Net()
		require.NoError(t, err)
		b, err := DecodeAddress(addr, net)
		require.NoError(t, err)
		assertAddressEqual(t, a, b)

		testVectors.ValidTestCases = append(
			testVectors.ValidTestCases, &ValidTestCase{
				Address:  NewTestFromAddress(t, a),
				Expected: addr,
				Comment:  comment,
			},
		)
	}

	testCases := []struct {
		name string
		f    func() (*Tap, string, error)
		err  error
	}{
		{
			name: "valid regtest address",
			f: func() (*Tap, string, error) {
				return randEncodedAddress(
					t, &RegressionNetTap, false, false,
					asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "valid simnet address",
			f: func() (*Tap, string, error) {
				return randEncodedAddress(
					t, &SimNetTap, false, false,
					asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "valid testnet address",
			f: func() (*Tap, string, error) {
				return randEncodedAddress(
					t, &TestNet3Tap, false, false,
					asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "valid mainnet address",
			f: func() (*Tap, string, error) {
				return randEncodedAddress(
					t, &MainNetTap, false, false,
					asset.Normal,
				)
			},
			err: nil,
		},
		{
			name: "signet group collectible",
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
		{
			name: "unknown version number",
			f: func() (*Tap, string, error) {
				newAddr, err := randAddress(
					t, &TestNet3Tap, false, true, nil,
					asset.Collectible,
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
				_, err = DecodeAddress(
					encodedAddr, &TestNet3Tap,
				)
				return newAddr, "", err
			},
			err: ErrUnknownVersion,
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
			testVectors = &TestVectors{}
		)
		test.ParseTestVectors(t, fileName, &testVectors)
		t.Run(fileName, func(tt *testing.T) {
			tt.Parallel()

			runBIPTestVector(tt, testVectors)
		})
	}
}

// runBIPTestVector runs the tests in a single BIP test vector file.
func runBIPTestVector(t *testing.T, testVectors *TestVectors) {
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

				expectedAddress, err := DecodeAddress(
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

			decoded, err := DecodeAddress(
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
