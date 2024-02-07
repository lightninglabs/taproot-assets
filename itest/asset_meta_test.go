package itest

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// testAssetMeta tests the validation+parsing logic for asset meta data.
func testAssetMeta(t *harnessTest) {
	// In this test, we'll attempt to issue the following assets with
	// distinct meta type. Within each test case, negative failure
	// scenarios may exist.
	jsonType := taprpc.AssetMetaType_META_TYPE_JSON
	testCases := []struct {
		asset     *mintrpc.MintAssetRequest
		errString string
	}{
		// Existing opaque meta data option, should succeed.
		{
			asset: &mintrpc.MintAssetRequest{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "opaque asset",
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte("some metadata"),
					},
					Amount: 5000,
				},
			},
		},

		// Existing JSON meta data option, with valid JSON should
		// succeed.
		{
			asset: &mintrpc.MintAssetRequest{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "json asset",
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte(
							`{"key": "value"}`,
						),
						Type: jsonType,
					},
					Amount: 5000,
				},
			},
		},

		// Existing JSON meta data option, with invalid JSON should
		// fail.
		{
			asset: &mintrpc.MintAssetRequest{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "invalid json",
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte("not json"),
						Type: jsonType,
					},
					Amount: 5000,
				},
			},
			errString: "invalid asset meta: invalid JSON",
		},

		// Custom meta data type, with valid data should succeed.
		{
			asset: &mintrpc.MintAssetRequest{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "custom meta type",
					AssetMeta: &taprpc.AssetMeta{
						Data: []byte("custom stuff"),
						Type: 99,
					},
					Amount: 5000,
				},
			},
		},
	}

	ctxb := context.Background()
	for _, tc := range testCases {
		t.t.Run(tc.asset.Asset.Name, func(tt *testing.T) {
			_, err := t.tapd.MintAsset(ctxb, tc.asset)
			if err != nil {
				if tc.errString == "" {
					tt.Fatalf("unexpected error: %v", err)
				}
				require.ErrorContains(tt, err, tc.errString)
			}
		})
	}

	// We only test validation here, so we'll cancel the pending batch.
	_, err := t.tapd.CancelBatch(ctxb, &mintrpc.CancelBatchRequest{})
	require.NoError(t.t, err)
}
