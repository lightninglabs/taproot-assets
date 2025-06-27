package itest

import (
	"bytes"
	"context"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/tapgarden"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
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
	mintReq := CopyRequest(issuableAssets[0])
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

func testSupplyCommitIgnoreAsset(t *harnessTest) {
	ctxb := context.Background()

	t.Log("Minting asset group with a single normal asset and " +
		"universe/supply commitments enabled")
	mintReq := issuableAssets[0]
	mintReq.Asset.UniverseCommitments = true
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{mintReq},
	)
	require.Len(t.t, rpcAssets, 1, "expected one minted asset")

	// Send some of the asset to a secondary node. We will then use the
	// primary node to ignore the asset outpoint owned by the secondary
	// node.
	t.Log("Setting up secondary node as recipient of asset")
	secondLnd := t.lndHarness.NewNodeWithCoins("SecondLnd", nil)
	secondTapd := setupTapdHarness(t.t, t, secondLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	t.Log("Sending asset to secondary node")
	rpcAsset := rpcAssets[0]
	sendAssetAmount := uint64(10)
	sendChangeAmount := rpcAsset.Amount - sendAssetAmount

	sendResp := sendAssetAndAssert(
		ctxb, t, t.tapd, secondTapd, sendAssetAmount, sendChangeAmount,
		rpcAsset.AssetGenesis, rpcAsset, 0, 1, 1,
	)
	require.Len(t.t, sendResp.SendResp.Transfer.Outputs, 2)
	t.Log("Asset transfer completed successfully")

	// Parse the group key from the minted asset.
	groupKeyBytes := rpcAsset.AssetGroup.TweakedGroupKey
	require.NotNil(t.t, groupKeyBytes)
	groupKey, err := btcec.ParsePubKey(groupKeyBytes)
	require.NoError(t.t, err)

	// Subscribe to supply commit events for the group key.
	events := SubscribeSupplyCommitEvents(t.t, t.tapd, *groupKey)

	// Determine the transfer output owned by the secondary node.
	// This is the output that we will ignore.
	transferOutput := sendResp.SendResp.Transfer.Outputs[0]
	if sendResp.SendResp.Transfer.Outputs[1].Amount == sendAssetAmount {
		transferOutput = sendResp.SendResp.Transfer.Outputs[1]
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		t.Log("Waiting for supply commit event for ignored asset " +
			"outpoint")
		AssertSupplyCommitEvents(t.t, events)
		wg.Done()
	}()

	// Ignore the asset outpoint owned by the secondary node.
	t.Log("Registering supply commitment asset ignore for asset outpoint " +
		"owned by secondary node")

	ignoreReq := &unirpc.IgnoreAssetOutPointRequest{
		AssetOutPoint: &taprpc.AssetOutPoint{
			AnchorOutPoint: transferOutput.Anchor.Outpoint,
			AssetId:        rpcAsset.AssetGenesis.AssetId,
			ScriptKey:      transferOutput.ScriptKey,
		},
		Amount: sendAssetAmount,
	}
	respIgnore, err := t.tapd.IgnoreAssetOutPoint(ctxb, ignoreReq)
	require.NoError(t.t, err)
	require.NotNil(t.t, respIgnore)

	t.Log("Update on-chain supply commitment for asset group")
	respUpdate, err := t.tapd.UpdateSupplyCommit(
		ctxb, &unirpc.UpdateSupplyCommitRequest{
			GroupKey: groupKeyBytes,
		},
	)
	require.NoError(t.t, err)
	require.NotNil(t.t, respUpdate)

	wg.Wait()
}
