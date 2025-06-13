package itest

import (
	"bytes"
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// assertAnchorTxPreCommitOut checks that the anchor transaction for the
// minted asset includes a pre-commitment output for the supply commitment.
// If an expected delegation key is provided, it verifies that it matches
// the one used in the pre-commitment output. The function returns the
// delegation key found in the asset metadata.
func assertAnchorTxPreCommitOut(
	t *harnessTest, tapd *tapdHarness, rpcAsset *taprpc.Asset,
	expectedDelegationKey fn.Option[btcec.PublicKey]) btcec.PublicKey {

	// Fetch metadata for the minted asset.
	ctxb := context.Background()

	metaResp, err := tapd.FetchAssetMeta(
		ctxb, &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_AssetId{
				AssetId: rpcAsset.AssetGenesis.AssetId,
			},
		},
	)
	require.NoError(t.t, err)

	delegationKey, err := btcec.ParsePubKey(metaResp.DelegationKey)
	require.NoError(t.t, err)

	// If a specific delegation key is expected, verify it matches the one
	// retrieved from the asset metadata.
	expectedDelegationKey.WhenSome(func(expectedKey btcec.PublicKey) {
		require.True(t.t, expectedKey.IsEqual(delegationKey))
	})

	// Parse anchor tx and confirm that one output is a supply commitment
	// pre-commitment output.
	var msgTx wire.MsgTx
	err = msgTx.Deserialize(
		bytes.NewReader(rpcAsset.ChainAnchor.AnchorTx),
	)
	require.NoError(t.t, err)

	expectedTxOut, err := tapgarden.PreCommitTxOut(*delegationKey)
	require.NoError(t.t, err)

	// The pre-commitment output should be present in the anchor tx exactly
	// once.
	foundOnce := false
	for idx := range msgTx.TxOut {
		txOut := msgTx.TxOut[idx]
		if txOut.Value != expectedTxOut.Value {
			continue
		}
		if !bytes.Equal(txOut.PkScript, expectedTxOut.PkScript) {
			continue
		}

		// We found a pre-commitment output, but it should only be
		// present once.
		if foundOnce {
			t.t.Fatalf("found pre-commitment output more than once")
		}

		foundOnce = true
	}
	require.True(t.t, foundOnce)

	return *delegationKey
}

// testPreCommitOutput tests that the pre-commitment output is correctly
// included in the anchor transaction when minting an asset group with
// universe/supply commitments enabled.
func testPreCommitOutput(t *harnessTest) {
	mintReq := issuableAssets[0]
	mintReq.Asset.UniverseCommitments = true
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{mintReq},
	)
	require.Len(t.t, rpcAssets, 1, "expected one minted asset")

	rpcFirstTrancheAsset := rpcAssets[0]
	delegationKey := assertAnchorTxPreCommitOut(
		t, t.tapd, rpcFirstTrancheAsset, fn.None[btcec.PublicKey](),
	)

	// Mint another tranche into the same asset group to ensure that
	// the pre-commitment output is still included in the anchor tx when a
	// pre-existing asset group key is used.
	tweakedGroupKey := rpcFirstTrancheAsset.AssetGroup.TweakedGroupKey

	mintReq = &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      "itestbuxx-money-printer-brrr-tranche-2",
			AssetMeta: &taprpc.AssetMeta{
				Data: []byte("some metadata"),
			},
			Amount:          6000,
			AssetVersion:    taprpc.AssetVersion_ASSET_VERSION_V1,
			NewGroupedAsset: false,
			GroupedAsset:    true,
			GroupKey:        tweakedGroupKey,

			UniverseCommitments: true,
		},
	}
	rpcAssets = MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{mintReq},
	)

	rpcSecondTrancheAsset := rpcAssets[0]

	assertAnchorTxPreCommitOut(
		t, t.tapd, rpcSecondTrancheAsset, fn.Some(delegationKey),
	)

	secondAssetGroupKey := rpcSecondTrancheAsset.AssetGroup.TweakedGroupKey
	// Ensure that the second tranche asset is part of the same group.
	require.EqualValues(t.t, tweakedGroupKey, secondAssetGroupKey)
}
