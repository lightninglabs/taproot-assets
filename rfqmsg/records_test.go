package rfqmsg

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/stretchr/testify/require"
)

type htlcTestCase struct {
	name         string
	htlc         *Htlc
	expectedJSON string

	// sumBalances is a map of asset ID to the expected sum of balances for
	// that asset in the HTLC.
	sumBalances map[asset.ID]rfqmath.BigInt
}

// assetHtlcTestCase is a helper function that asserts different properties of
// the test case.
func assetHtlcTestCase(t *testing.T, tc htlcTestCase) {
	// Serialize the HTLC and then deserialize it again.
	var b bytes.Buffer
	err := tc.htlc.Encode(&b)
	require.NoError(t, err)

	deserializedHtlc := &Htlc{}
	err = deserializedHtlc.Decode(&b)
	require.NoError(t, err)

	require.Equal(t, tc.htlc, deserializedHtlc)

	jsonBytes, err := deserializedHtlc.AsJson()
	require.NoError(t, err)

	var formatted bytes.Buffer
	err = json.Indent(&formatted, jsonBytes, "", "  ")
	require.NoError(t, err)

	if tc.expectedJSON != "" {
		require.Equal(t, tc.expectedJSON, formatted.String())
	}

	// Check expected asset sum balances if specified in test case.
	if tc.sumBalances == nil {
		tc.sumBalances = make(map[asset.ID]rfqmath.BigInt)
	}

	for assetID, expectedBalance := range tc.sumBalances {
		assetSpecifier := asset.NewSpecifierFromId(assetID)
		balance, err := tc.htlc.SumAssetBalance(assetSpecifier)
		require.NoError(t, err)

		require.Equal(t, expectedBalance, balance)
	}
}

// TestHtlc tests encoding and decoding of the Htlc struct.
func TestHtlc(t *testing.T) {
	t.Parallel()

	testCases := []htlcTestCase{
		{
			name: "empty HTLC",
			htlc: &Htlc{},
			expectedJSON: `{
  "balances": [],
  "rfq_id": ""
}`,
		},
		{
			name: "HTLC with balance asset",
			htlc: NewHtlc([]*AssetBalance{
				NewAssetBalance([32]byte{1}, 1000),
			}, fn.None[ID]()),
			//nolint:lll
			expectedJSON: `{
  "balances": [
    {
      "asset_id": "0100000000000000000000000000000000000000000000000000000000000000",
      "amount": 1000
    }
  ],
  "rfq_id": ""
}`,
		},
		{
			name: "HTLC sum balance check",
			htlc: NewHtlc([]*AssetBalance{
				NewAssetBalance([32]byte{1}, 1000),
				NewAssetBalance([32]byte{1}, 2000),
				NewAssetBalance([32]byte{2}, 5000),
			}, fn.None[ID]()),
			sumBalances: map[asset.ID]rfqmath.BigInt{
				[32]byte{1}: rfqmath.NewBigIntFromUint64(3000),
				[32]byte{2}: rfqmath.NewBigIntFromUint64(5000),
			},
		},
		{
			name: "channel with multiple balance assets",
			htlc: NewHtlc([]*AssetBalance{
				NewAssetBalance([32]byte{1}, 1000),
				NewAssetBalance([32]byte{2}, 2000),
			}, fn.Some(ID{0, 1, 2, 3, 4, 5, 6, 7})),
			//nolint:lll
			expectedJSON: `{
  "balances": [
    {
      "asset_id": "0100000000000000000000000000000000000000000000000000000000000000",
      "amount": 1000
    },
    {
      "asset_id": "0200000000000000000000000000000000000000000000000000000000000000",
      "amount": 2000
    }
  ],
  "rfq_id": "0001020304050607000000000000000000000000000000000000000000000000"
}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assetHtlcTestCase(t, tc)
		})
	}
}
