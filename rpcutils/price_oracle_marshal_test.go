package rpcutils

import (
	"encoding/hex"
	"testing"

	"github.com/lightninglabs/taproot-assets/taprpc/priceoraclerpc"
	"github.com/stretchr/testify/require"
)

// isAssetBtcTC is a test case for the IsAssetBtc function.
type isAssetBtcTC struct {
	testName string

	assetSpecifier *priceoraclerpc.AssetSpecifier
	expected       bool
}

// TestIsAssetBtc tests the IsAssetBtc function. The IsAssetBtc function
// returns true if the given asset specifier represents BTC, and false
// otherwise.
func TestIsAssetBtc(t *testing.T) {
	t.Parallel()

	var zeroAssetId [32]byte
	zeroAssetHexStr := hex.EncodeToString(zeroAssetId[:])

	testCases := []isAssetBtcTC{
		{
			testName:       "nil asset specifier",
			assetSpecifier: nil,
			expected:       false,
		},
		{
			testName:       "empty asset specifier",
			assetSpecifier: &priceoraclerpc.AssetSpecifier{},
			expected:       false,
		},
		{
			testName: "asset specifier with zero asset ID bytes",
			assetSpecifier: &priceoraclerpc.AssetSpecifier{
				Id: &priceoraclerpc.AssetSpecifier_AssetId{
					AssetId: zeroAssetId[:],
				},
			},
			expected: true,
		},
		{
			testName: "asset specifier with incorrect length " +
				"zero asset ID bytes",
			assetSpecifier: &priceoraclerpc.AssetSpecifier{
				Id: &priceoraclerpc.AssetSpecifier_AssetId{
					AssetId: []byte{0, 0, 0},
				},
			},
			expected: false,
		},
		{
			testName: "asset specifier with empty asset ID bytes",
			assetSpecifier: &priceoraclerpc.AssetSpecifier{
				Id: &priceoraclerpc.AssetSpecifier_AssetId{
					AssetId: []byte{},
				},
			},
			expected: false,
		},
		{
			testName: "asset specifier with zero asset ID string",
			assetSpecifier: &priceoraclerpc.AssetSpecifier{
				Id: &priceoraclerpc.AssetSpecifier_AssetIdStr{
					AssetIdStr: zeroAssetHexStr,
				},
			},
			expected: true,
		},
		{
			testName: "asset specifier with empty asset ID string",
			assetSpecifier: &priceoraclerpc.AssetSpecifier{
				Id: &priceoraclerpc.AssetSpecifier_AssetIdStr{
					AssetIdStr: "",
				},
			},
			expected: false,
		},
		{
			testName: "asset specifier with set group key bytes",
			assetSpecifier: &priceoraclerpc.AssetSpecifier{
				Id: &priceoraclerpc.AssetSpecifier_GroupKey{
					GroupKey: []byte{0, 0, 0},
				},
			},
			expected: false,
		},
		{
			testName: "asset specifier with set group key string",
			assetSpecifier: &priceoraclerpc.AssetSpecifier{
				Id: &priceoraclerpc.AssetSpecifier_GroupKeyStr{
					GroupKeyStr: "test-group-key",
				},
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(tt *testing.T) {
			// Run the test case. Ensure that the expected value is
			// returned.
			actual := IsAssetBtc(tc.assetSpecifier)
			require.Equal(tt, tc.expected, actual)
		})
	}
}
