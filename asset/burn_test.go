package asset

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

var (
	burnTestVectorName = "asset_burn_key_generated.json"

	allBurnTestVectorFiles = []string{
		burnTestVectorName,
	}
)

func TestDeriveBurnKey(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		prevID      PrevID
		expectedKey string
	}{{
		name:   "empty prev ID",
		prevID: PrevID{},
		expectedKey: "b87da731321c9e90a2f3d525cf81a2f503e04ea" +
			"49543692951e6b88752a0d72d",
	}, {
		name: "dummy value ID",
		prevID: PrevID{
			OutPoint: wire.OutPoint{
				Hash: chainhash.Hash{
					0x77, 0x88, 0x99, 0xaa,
				},
				Index: 123,
			},
			ID: ID{
				0x01, 0x02, 0x03, 0x04,
			},
			ScriptKey: SerializedKey{
				0x02, 0x03, 0x04, 0x05,
			},
		},
		expectedKey: "77493dcf8c7e6c1f214824409b2468afe8e4e5faa47e6ae" +
			"87ddb60226ad4edde",
	}, {
		name: "random value ID",
		prevID: PrevID{
			OutPoint: test.ParseOutPoint(
				t, "c8ca462e6247b1c7d67f9e2b5e371fc9303c3c3e6"+
					"d690e8fb4a6bb5ca5b78104:354062834",
			),
			ID: test.Parse32Byte(
				t, "560982cea2defb7795dda938422b4d7ae5462e64c"+
					"de32fc68ced4f503f8a5af7",
			),
			ScriptKey: test.Parse33Byte(
				t, "03c50bfc65dfb20e9b9c1c6d8b435ef91f41eb864"+
					"34576823eeaf3a69fa7e1fc78",
			),
		},
		expectedKey: "a76bc68f430c78cfdad6d72abf143de10c8b679842fe007" +
			"36072361b52ad426c",
	}}

	testVectors := &BurnTestVectors{}
	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(tt *testing.T) {
			burnKey := DeriveBurnKey(tc.prevID)
			burnKeyHex := hex.EncodeToString(
				schnorr.SerializePubKey(burnKey),
			)

			require.Equal(tt, tc.expectedKey, burnKeyHex)

			testVectors.ValidTestCases = append(
				testVectors.ValidTestCases, &ValidBurnTestCase{
					PrevID: NewTestFromPrevID(
						&tc.prevID,
					),
					Expected: burnKeyHex,
					Comment:  tc.name,
				},
			)
		})

		// Write test vectors to file. This is a no-op if the
		// "gen_test_vectors" build tag is not set.
		test.WriteTestVectors(t, burnTestVectorName, testVectors)
	}
}

// TestBurnBIPTestVectors tests that the BIP test vectors are passing.
func TestBurnBIPTestVectors(t *testing.T) {
	t.Parallel()

	for idx := range allBurnTestVectorFiles {
		var (
			fileName    = allBurnTestVectorFiles[idx]
			testVectors = &BurnTestVectors{}
		)
		test.ParseTestVectors(t, fileName, &testVectors)
		t.Run(fileName, func(tt *testing.T) {
			tt.Parallel()

			runBurnBIPTestVector(tt, testVectors)
		})
	}
}

// runBurnBIPTestVector runs the tests in a single BIP test vector file.
func runBurnBIPTestVector(t *testing.T, testVectors *BurnTestVectors) {
	for _, validCase := range testVectors.ValidTestCases {
		validCase := validCase

		t.Run(validCase.Comment, func(tt *testing.T) {
			tt.Parallel()

			p := validCase.PrevID.ToPrevID(t)
			burnKey := DeriveBurnKey(*p)

			require.Equal(
				tt, validCase.Expected, hex.EncodeToString(
					schnorr.SerializePubKey(burnKey),
				),
			)
		})
	}
}
