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

		// A mint request that doesn't specify asset meta at all should
		// be permitted.
		{
			asset: &mintrpc.MintAssetRequest{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "no meta",
					Amount:    5000,
				},
			},
		},

		// A user should also be able to specify a decimal display, but
		// not actually specify an asset meta at all.
		{
			asset: &mintrpc.MintAssetRequest{
				Asset: &mintrpc.MintAsset{
					AssetType:      taprpc.AssetType_NORMAL,
					Name:           "dec display",
					Amount:         5000,
					DecimalDisplay: 6,
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
	err := mintedMeta.SetDecDisplay(firstAsset.DecimalDisplay)
	require.NoError(t.t, err)

	metaHash := mintedMeta.MetaHash()

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

	// Re-issuance should fail if the decimal display does not match the
	// group anchor.
	_, err = t.tapd.MintAsset(ctxt, secondAssetReq)
	require.ErrorContains(t.t, err, "decimal display does not match")

	// Attempting to set a different decimal display in the JSON meta data
	// as in the new RPC request field should give us an error as well.
	secondAssetReq.Asset.DecimalDisplay = firstAsset.DecimalDisplay
	secondAssetReq.Asset.AssetMeta = &taprpc.AssetMeta{
		Type: taprpc.AssetMetaType_META_TYPE_JSON,
		Data: []byte(`{"foo": "bar", "decimal_display": 3}`),
	}
	_, err = t.tapd.MintAsset(ctxt, secondAssetReq)
	require.ErrorContains(
		t.t, err, "decimal display in JSON asset meta does not match",
	)

	// If we set a valid asset meta again, minting should succeed, using the
	// same decimal display as the group anchor.
	secondAssetReq.Asset.AssetMeta.Data = []byte(`{"foo": "bar"}`)
	secondAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{secondAssetReq},
	)
	require.Len(t.t, secondAssets, 1)
	require.NotNil(t.t, secondAssets[0].DecimalDisplay)
	require.EqualValues(
		t.t, 2, secondAssets[0].DecimalDisplay.DecimalDisplay,
	)

	// For an asset with a JSON meta data type, we also expect the decimal
	// display to be encoded in the meta data JSON.
	metaResp, err := t.tapd.FetchAssetMeta(
		ctxt, &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_AssetId{
				AssetId: secondAssets[0].AssetGenesis.AssetId,
			},
		},
	)
	require.NoError(t.t, err)
	require.Contains(t.t, string(metaResp.Data), `"foo":"bar"`)
	require.Contains(t.t, string(metaResp.Data), `"decimal_display":2`)

	AssertGroupSizes(
		t.t, t.tapd, []string{hex.EncodeToString(groupKey)}, []int{2},
	)

	// Now we also test minting an asset that uses the opaque meta data type
	// and check that the decimal display is correctly encoded as well.
	thirdAsset := &mintrpc.MintAsset{
		AssetType: taprpc.AssetType_NORMAL,
		Name:      "test-asset-opaque-decimal-display",
		AssetMeta: &taprpc.AssetMeta{
			Type: taprpc.AssetMetaType_META_TYPE_OPAQUE,
			Data: []byte("some opaque data"),
		},
		Amount:         123,
		DecimalDisplay: 7,
	}
	thirdAssetReq := &mintrpc.MintAssetRequest{Asset: thirdAsset}
	thirdAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{thirdAssetReq},
	)

	require.Len(t.t, thirdAssets, 1)
	require.NotNil(t.t, thirdAssets[0].DecimalDisplay)
	require.EqualValues(
		t.t, 7, thirdAssets[0].DecimalDisplay.DecimalDisplay,
	)
}

// testFetchAssetMetaRPC tests the FetchAssetMeta RPC endpoint with various
// scenarios, including fetching by group key.
func testFetchAssetMetaRPC(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout*3)
	defer cancel()

	// 1. Mint a group of assets.
	groupName := "meta-test-group"
	groupMetaJSON := `{"type": "test-group"}`
	groupDecimalDisplay := uint32(2)

	// Asset 1 in the group
	groupAsset1Req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      groupName + "-alpha",
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte(`{"id":"alpha"}`), // Individual meta
				Type: taprpc.AssetMetaType_META_TYPE_JSON,
			},
			Amount:          1000,
			NewGroupedAsset: true, // This will be the group anchor
			DecimalDisplay:  groupDecimalDisplay,
		},
	}

	// Mint and get the first asset to establish the group.
	rpcGroupAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{groupAsset1Req},
	)
	require.Len(t.t, rpcGroupAssets, 1)
	groupAsset1 := rpcGroupAssets[0]
	require.NotNil(t.t, groupAsset1.AssetGroup)
	groupKeyBytes := groupAsset1.AssetGroup.TweakedGroupKey
	groupKeyHex := hex.EncodeToString(groupKeyBytes)
	t.Logf("Minted group anchor %s with group key %s", groupAsset1.AssetGenesis.Name, groupKeyHex)

	// Asset 2 in the same group
	groupAsset2Req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      groupName + "-beta",
			AssetMeta: &taprpc.AssetMeta{ // Ensure meta is provided if DecimalDisplay is used
				Data: []byte(`{"id":"beta"}`), // Individual meta
				Type: taprpc.AssetMetaType_META_TYPE_JSON,
			},
			Amount:         2000,
			GroupedAsset:   true,
			GroupKey:       groupKeyBytes,
			DecimalDisplay: groupDecimalDisplay, // Must match group's
		},
	}
	rpcGroupAssets2 := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{groupAsset2Req},
	)
	require.Len(t.t, rpcGroupAssets2, 1)
	groupAsset2 := rpcGroupAssets2[0]
	t.Logf("Minted grouped asset %s into group key %s", groupAsset2.AssetGenesis.Name, groupKeyHex)

	// 2. Mint a non-grouped asset.
	soloAssetName := "solo-meta-asset"
	soloAssetMetaJSON := `{"type": "solo"}`
	soloAssetDecimalDisplay := uint32(3)
	soloAssetReq := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      soloAssetName,
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte(soloAssetMetaJSON),
				Type: taprpc.AssetMetaType_META_TYPE_JSON,
			},
			Amount:         3000,
			DecimalDisplay: soloAssetDecimalDisplay,
		},
	}
	rpcSoloAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{soloAssetReq},
	)
	require.Len(t.t, rpcSoloAssets, 1)
	soloAsset := rpcSoloAssets[0]
	soloAssetIdStr := hex.EncodeToString(soloAsset.AssetGenesis.AssetId)
	var soloAssetMetaHash [32]byte
	copy(soloAssetMetaHash[:], soloAsset.AssetGenesis.MetaHash)
	soloAssetMetaHashStr := hex.EncodeToString(soloAsset.AssetGenesis.MetaHash)
	t.Logf("Minted solo asset %s with ID %s", soloAssetName, soloAssetIdStr)

	// Test Case: RPC Fetch by Group Key - Success
	t.t.Run("RPC Fetch by Group Key - Success", func(tt *testing.T) {
		req := &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_GroupKeyStr{
				GroupKeyStr: groupKeyHex,
			},
		}
		resp, err := t.tapd.FetchAssetMeta(ctxt, req)
		require.NoError(tt, err)
		require.NotNil(tt, resp)
		require.Len(tt, resp.AssetMetas, 2, "Should fetch two assets in the group")
		require.Equal(tt, int32(groupDecimalDisplay), resp.DecimalDisplay)

		// Verify metas (content check can be shallow, e.g. name in data)
		var foundAlpha, foundBeta bool
		for _, meta := range resp.AssetMetas {
			if strings.Contains(string(meta.Data), `"id":"alpha"`) {
				foundAlpha = true
			}
			if strings.Contains(string(meta.Data), `"id":"beta"`) {
				foundBeta = true
			}
		}
		require.True(tt, foundAlpha, "GroupAssetAlpha meta not found or content mismatch")
		require.True(tt, foundBeta, "GroupAssetBeta meta not found or content mismatch")
	})

	// Test Case: RPC Fetch by Group Key - Group Not Found
	t.t.Run("RPC Fetch by Group Key - Group Not Found", func(tt *testing.T) {
		nonExistentGroupKey := "03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		req := &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_GroupKeyStr{
				GroupKeyStr: nonExistentGroupKey,
			},
		}
		resp, err := t.tapd.FetchAssetMeta(ctxt, req)
		require.NoError(tt, err) // Should not error, just return empty
		require.NotNil(tt, resp)
		require.Empty(tt, resp.AssetMetas)
		require.Equal(tt, int32(0), resp.DecimalDisplay)
	})

	// Test Case: RPC Fetch by Asset ID - Grouped Asset
	t.t.Run("RPC Fetch by Asset ID - Grouped Asset", func(tt *testing.T) {
		groupedAssetIdStr := hex.EncodeToString(groupAsset1.AssetGenesis.AssetId)
		req := &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_AssetIdStr{
				AssetIdStr: groupedAssetIdStr,
			},
		}
		resp, err := t.tapd.FetchAssetMeta(ctxt, req)
		require.NoError(tt, err)
		require.NotNil(tt, resp)
		require.Len(tt, resp.AssetMetas, 1)
		require.True(tt, strings.Contains(string(resp.AssetMetas[0].Data), `"id":"alpha"`))
		require.Equal(tt, int32(groupDecimalDisplay), resp.DecimalDisplay)
	})

	// Test Case: RPC Fetch by Asset ID - Non-Grouped Asset
	t.t.Run("RPC Fetch by Asset ID - Non-Grouped Asset", func(tt *testing.T) {
		req := &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_AssetIdStr{
				AssetIdStr: soloAssetIdStr,
			},
		}
		resp, err := t.tapd.FetchAssetMeta(ctxt, req)
		require.NoError(tt, err)
		require.NotNil(tt, resp)
		require.Len(tt, resp.AssetMetas, 1)
		require.JSONEq(tt, soloAssetMetaJSON, string(resp.AssetMetas[0].Data))
		require.Equal(tt, int32(soloAssetDecimalDisplay), resp.DecimalDisplay)
	})

	// Test Case: RPC Fetch by Meta Hash
	t.t.Run("RPC Fetch by Meta Hash", func(tt *testing.T) {
		req := &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_MetaHashStr{
				MetaHashStr: soloAssetMetaHashStr,
			},
		}
		resp, err := t.tapd.FetchAssetMeta(ctxt, req)
		require.NoError(tt, err)
		require.NotNil(tt, resp)
		require.Len(tt, resp.AssetMetas, 1)
		require.JSONEq(tt, soloAssetMetaJSON, string(resp.AssetMetas[0].Data))
		require.Equal(tt, int32(soloAssetDecimalDisplay), resp.DecimalDisplay)
	})
}

// testFetchAssetMetaCLI tests the 'tapcli assets fetchmeta' command with
// various scenarios, including fetching by group key and flag validation.
func testFetchAssetMetaCLI(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout*3)
	defer cancel()

	// Re-use the same minting logic as testFetchAssetMetaRPC for consistency.
	// Mint a group of assets.
	groupName := "cli-meta-test-group"
	groupDecimalDisplay := uint32(2)
	groupAsset1Req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      groupName + "-alpha-cli",
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte(`{"id":"alpha-cli"}`),
				Type: taprpc.AssetMetaType_META_TYPE_JSON,
			},
			Amount:          1000,
			NewGroupedAsset: true,
			DecimalDisplay:  groupDecimalDisplay,
		},
	}
	rpcGroupAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{groupAsset1Req},
	)
	require.Len(t.t, rpcGroupAssets, 1)
	groupAsset1 := rpcGroupAssets[0]
	groupKeyBytes := groupAsset1.AssetGroup.TweakedGroupKey
	groupKeyHex := hex.EncodeToString(groupKeyBytes)
	t.Logf("CLI: Minted group anchor %s with group key %s", groupAsset1.AssetGenesis.Name, groupKeyHex)

	groupAsset2Req := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      groupName + "-beta-cli",
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte(`{"id":"beta-cli"}`),
				Type: taprpc.AssetMetaType_META_TYPE_JSON,
			},
			Amount:         2000,
			GroupedAsset:   true,
			GroupKey:       groupKeyBytes,
			DecimalDisplay: groupDecimalDisplay,
		},
	}
	MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{groupAsset2Req},
	)
	t.Logf("CLI: Minted grouped asset %s into group key %s", groupAsset2Req.Asset.Name, groupKeyHex)

	// Mint a non-grouped asset.
	soloAssetName := "cli-solo-meta-asset"
	soloAssetMetaJSON := `{"type": "solo-cli"}`
	soloAssetDecimalDisplay := uint32(3)
	soloAssetReq := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      soloAssetName,
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte(soloAssetMetaJSON),
				Type: taprpc.AssetMetaType_META_TYPE_JSON,
			},
			Amount:         3000,
			DecimalDisplay: soloAssetDecimalDisplay,
		},
	}
	rpcSoloAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{soloAssetReq},
	)
	require.Len(t.t, rpcSoloAssets, 1)
	soloAsset := rpcSoloAssets[0]
	soloAssetIdStr := hex.EncodeToString(soloAsset.AssetGenesis.AssetId)
	t.Logf("CLI: Minted solo asset %s with ID %s", soloAssetName, soloAssetIdStr)

	// Test Case: CLI Fetch by Group Key - Success
	t.t.Run("CLI Fetch by Group Key - Success", func(tt *testing.T) {
		respJSON, err := ExecTapCLI(
			ctxt, t.tapd, "assets", "fetchmeta", "--group_key", groupKeyHex,
		)
		require.NoError(tt, err)

		var resp taprpc.FetchAssetMetaResponse
		require.NoError(tt, taprpc.RpcAssetsCommandJsonParser.Unmarshal(
			[]byte(respJSON.(string)), &resp,
		))

		require.Len(tt, resp.AssetMetas, 2, "Should fetch two assets in the group via CLI")
		require.Equal(tt, int32(groupDecimalDisplay), resp.DecimalDisplay)
		var foundAlpha, foundBeta bool
		for _, meta := range resp.AssetMetas {
			if strings.Contains(string(meta.Data), `"id":"alpha-cli"`) {
				foundAlpha = true
			}
			if strings.Contains(string(meta.Data), `"id":"beta-cli"`) {
				foundBeta = true
			}
		}
		require.True(tt, foundAlpha, "GroupAssetAlpha meta not found via CLI")
		require.True(tt, foundBeta, "GroupAssetBeta meta not found via CLI")
	})

	// Test Case: CLI Fetch by Group Key - Group Not Found
	t.t.Run("CLI Fetch by Group Key - Group Not Found", func(tt *testing.T) {
		nonExistentGroupKey := "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		respJSON, err := ExecTapCLI(
			ctxt, t.tapd, "assets", "fetchmeta", "--group_key", nonExistentGroupKey,
		)
		require.NoError(tt, err)
		var resp taprpc.FetchAssetMetaResponse
		require.NoError(tt, taprpc.RpcAssetsCommandJsonParser.Unmarshal(
			[]byte(respJSON.(string)), &resp,
		))
		require.Empty(tt, resp.AssetMetas)
		require.Equal(tt, int32(0), resp.DecimalDisplay)
	})

	// Test Case: CLI Fetch by Asset ID - Non-Grouped Asset
	t.t.Run("CLI Fetch by Asset ID - Non-Grouped Asset", func(tt *testing.T) {
		respJSON, err := ExecTapCLI(
			ctxt, t.tapd, "assets", "fetchmeta", "--asset_id", soloAssetIdStr,
		)
		require.NoError(tt, err)
		var resp taprpc.FetchAssetMetaResponse
		require.NoError(tt, taprpc.RpcAssetsCommandJsonParser.Unmarshal(
			[]byte(respJSON.(string)), &resp,
		))
		require.Len(tt, resp.AssetMetas, 1)
		require.JSONEq(tt, soloAssetMetaJSON, string(resp.AssetMetas[0].Data))
		require.Equal(tt, int32(soloAssetDecimalDisplay), resp.DecimalDisplay)
	})

	// Test Case: CLI - Mutual Exclusivity of Flags
	t.t.Run("CLI Mutual Exclusivity", func(tt *testing.T) {
		_, err := ExecTapCLIFail(
			ctxt, t.tapd, errStringMutuallyExclusive, "assets", "fetchmeta",
			"--group_key", groupKeyHex, "--asset_id", soloAssetIdStr,
		)
		require.NoError(tt, err) // ExecTapCLIFail checks for the error string

		_, err = ExecTapCLIFail(
			ctxt, t.tapd, errStringMutuallyExclusive, "assets", "fetchmeta",
			"--group_key", groupKeyHex, "--meta_hash", "aabbcc",
		)
		require.NoError(tt, err)

		_, err = ExecTapCLIFail(
			ctxt, t.tapd, errStringMutuallyExclusive, "assets", "fetchmeta",
			"--asset_id", soloAssetIdStr, "--meta_hash", "aabbcc",
		)
		require.NoError(tt, err)

		_, err = ExecTapCLIFail(
			ctxt, t.tapd, errStringMutuallyExclusive, "assets", "fetchmeta",
			"--group_key", groupKeyHex, "--asset_id", soloAssetIdStr, "--meta_hash", "aabbcc",
		)
		require.NoError(tt, err)

		_, err = ExecTapCLIFail(
			ctxt, t.tapd, "must specify one of asset_id, meta_hash, or group_key",
			"assets", "fetchmeta",
		)
		require.NoError(tt, err)
	})
}

// And register both in the main test list for this file.
