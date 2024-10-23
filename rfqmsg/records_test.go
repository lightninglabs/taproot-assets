package rfqmsg

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/stretchr/testify/require"
)

type htlcTestCase struct {
	name         string
	htlc         *Htlc
	expectedJSON string
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
