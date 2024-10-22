package itest

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/lightninglabs/taproot-assets/proof"
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
			errString: proof.ErrInvalidJSON.Error(),
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

// testMintAssetWithDecimalDisplayMetaField tests that we're able to mint an
// asset with a specific decimal display value, and that the value is correctly
// encoded in the metadata field of the mint.
func testMintAssetWithDecimalDisplayMetaField(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	mintName := "test-asset-decimal-places"
	jsonData := []byte(`{"field1": "value1", "field2": "value2"}`)
	firstAsset := &mintrpc.MintAsset{
		AssetType: taprpc.AssetType_NORMAL,
		Name:      mintName,
		AssetMeta: &taprpc.AssetMeta{
			Data: jsonData,
			Type: taprpc.AssetMetaType_META_TYPE_JSON,
		},
		Amount:          500,
		DecimalDisplay:  2,
		NewGroupedAsset: true,
	}
	firstAssetReq := &mintrpc.MintAssetRequest{Asset: firstAsset}

	rpcSimpleAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{firstAssetReq},
	)
	require.Len(t.t, rpcSimpleAssets, 1)

	// Ensure minted asset with requested name was successfully minted.
	firstAssetMinted := rpcSimpleAssets[0]
	mintedAssetName := firstAssetMinted.AssetGenesis.Name
	require.Equal(t.t, mintName, mintedAssetName)
	require.NotNil(t.t, firstAssetMinted.AssetGroup)

	require.Equal(
		t.t, taprpc.AssetMetaType_META_TYPE_JSON,
		firstAsset.AssetMeta.Type,
	)
	mintedMeta := &proof.MetaReveal{
		Type: proof.MetaJson,
		Data: jsonData,
	}

	// Manually update the requested metadata and compute the expected hash.
	updatedMeta, err := mintedMeta.SetDecDisplay(firstAsset.DecimalDisplay)
	require.NoError(t.t, err)

	metaHash := updatedMeta.MetaHash()

	// The meta hash from the minted asset must match the expected hash.
	genMetaHash := firstAssetMinted.AssetGenesis.MetaHash
	require.Equal(t.t, genMetaHash, metaHash[:])

	// Mint another asset into the same asset group as the first asset.
	groupKey := firstAssetMinted.AssetGroup.TweakedGroupKey
	secondAssetReq := CopyRequest(firstAssetReq)
	secondAssetReq.Asset.Name += "-2"
	secondAssetReq.Asset.NewGroupedAsset = false
	secondAssetReq.Asset.GroupedAsset = true
	secondAssetReq.Asset.GroupKey = groupKey
	secondAssetReq.Asset.DecimalDisplay = 0

	// Reissuance should fail if the decimal display does not match the
	// group anchor.
	_, err = t.tapd.MintAsset(ctxt, secondAssetReq)
	require.ErrorContains(t.t, err, "decimal display does not match")

	// Requesting a decimal display without specifying the metadata type as
	// JSON should fail.
	secondAssetReq.Asset.DecimalDisplay = firstAsset.DecimalDisplay
	secondAssetReq.Asset.AssetMeta = nil

	_, err = t.tapd.MintAsset(ctxt, secondAssetReq)
	require.ErrorContains(t.t, err, "decimal display requires JSON")

	// If we update the decimal display to match the group anchor, minting
	// should succeed. We also unset the metadata to ensure that the decimal
	// display is set as the sole JSON object if needed.
	secondAssetReq.Asset.AssetMeta = &taprpc.AssetMeta{
		Type: taprpc.AssetMetaType_META_TYPE_JSON,
	}
	MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{secondAssetReq},
	)

	AssertGroupSizes(
		t.t, t.tapd, []string{hex.EncodeToString(groupKey)}, []int{2},
	)
}
