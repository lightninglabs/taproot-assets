package itest

import (
	"context"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// testTransferGroupKey verifies that transfer inputs and outputs carry enough
// asset metadata across both ListTransfers and SubscribeSendEvents to identify
// grouped fungible assets, ungrouped fungible assets, and grouped collectibles.
//
// This is the dedicated coverage for the marshal-time asset metadata resolver
// that lives in rpcserver. The bytes carried in group_key must match the
// asset's tweaked group public key exactly, and asset_type must match the
// asset's genesis type.
func testTransferGroupKey(t *harnessTest) {
	ctxb := context.Background()

	// Mint three assets in one batch so the test runs a single confirmation
	// cycle: a grouped fungible, an ungrouped fungible, and a grouped
	// collectible. Reusing the existing fixtures keeps this test in
	// lock-step with the rest of the suite.
	mintReqs := []*mintrpc.MintAssetRequest{
		issuableAssets[0], // grouped fungible.
		simpleAssets[0],   // ungrouped fungible.
		issuableAssets[1], // grouped collectible.
	}
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner(), t.tapd, mintReqs,
	)
	require.Len(t.t, rpcAssets, 3)

	groupedAsset := rpcAssets[0]
	ungroupedAsset := rpcAssets[1]
	collectibleAsset := rpcAssets[2]
	require.NotNil(t.t, groupedAsset.AssetGroup,
		"first minted asset must carry a group key")
	require.Nil(t.t, ungroupedAsset.AssetGroup,
		"second minted asset must not carry a group key")
	require.NotNil(t.t, collectibleAsset.AssetGroup,
		"third minted asset must carry a group key")

	expectedGroupKey := groupedAsset.AssetGroup.TweakedGroupKey
	require.NotEmpty(t.t, expectedGroupKey)
	expectedCollectibleGroupKey := collectibleAsset.AssetGroup.
		TweakedGroupKey
	require.NotEmpty(t.t, expectedCollectibleGroupKey)

	// Spin up a receiver tapd. One node is enough because all transfers go
	// to the same recipient.
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	const sendUnits = 100

	// Send the grouped asset.
	groupedAddr, err := secondTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:      groupedAsset.AssetGenesis.AssetId,
		Amt:          sendUnits,
		AssetVersion: groupedAsset.Version,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, secondTapd, groupedAsset, groupedAddr)

	groupedSend, groupedEvents := sendAssetsToAddr(t, t.tapd, groupedAddr)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner(), t.tapd, groupedSend,
		groupedAsset.AssetGenesis.AssetId,
		[]uint64{groupedAsset.Amount - sendUnits, sendUnits}, 0, 1,
	)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 1)
	assertCompletedSendEventAssetMeta(
		t.t, groupedEvents, expectedGroupKey, taprpc.AssetType_NORMAL,
	)

	// Send the ungrouped asset.
	ungroupedAddr, err := secondTapd.NewAddr(ctxb, &taprpc.NewAddrRequest{
		AssetId:      ungroupedAsset.AssetGenesis.AssetId,
		Amt:          sendUnits,
		AssetVersion: ungroupedAsset.Version,
	})
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, secondTapd, ungroupedAsset, ungroupedAddr)

	ungroupedSend, ungroupedEvents := sendAssetsToAddr(
		t, t.tapd, ungroupedAddr,
	)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner(), t.tapd, ungroupedSend,
		ungroupedAsset.AssetGenesis.AssetId,
		[]uint64{ungroupedAsset.Amount - sendUnits, sendUnits}, 1, 2,
	)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 2)
	assertCompletedSendEventAssetMeta(
		t.t, ungroupedEvents, nil, taprpc.AssetType_NORMAL,
	)

	// Send the grouped collectible. This is the important ambiguity check:
	// grouped fungibles and NFT collection items both carry group_key, so
	// transfer rows must also carry asset_type for SDKs to project them
	// differently.
	collectibleAddr, err := secondTapd.NewAddr(
		ctxb, &taprpc.NewAddrRequest{
			AssetId:      collectibleAsset.AssetGenesis.AssetId,
			Amt:          collectibleAsset.Amount,
			AssetVersion: collectibleAsset.Version,
		},
	)
	require.NoError(t.t, err)
	AssertAddrCreated(t.t, secondTapd, collectibleAsset, collectibleAddr)

	collectibleSend, collectibleEvents := sendAssetsToAddr(
		t, t.tapd, collectibleAddr,
	)
	ConfirmAndAssertOutboundTransfer(
		t.t, t.lndHarness.Miner(), t.tapd, collectibleSend,
		collectibleAsset.AssetGenesis.AssetId,
		[]uint64{0, collectibleAsset.Amount}, 2, 3,
	)
	AssertNonInteractiveRecvComplete(t.t, secondTapd, 3)
	assertCompletedSendEventAssetMeta(
		t.t, collectibleEvents, expectedCollectibleGroupKey,
		taprpc.AssetType_COLLECTIBLE,
	)

	// ListTransfers must surface group_key populated on every input and
	// output of grouped transfers, empty on the ungrouped one, and
	// asset_type populated for every transfer.
	transferResp, err := t.tapd.ListTransfers(
		ctxb, &taprpc.ListTransfersRequest{},
	)
	require.NoError(t.t, err)
	require.Len(t.t, transferResp.Transfers, 3)

	// The transfers come back in chronological order.
	groupedTransfer := transferResp.Transfers[0]
	ungroupedTransfer := transferResp.Transfers[1]
	collectibleTransfer := transferResp.Transfers[2]

	assertTransferAssetMeta(
		t.t, groupedTransfer, expectedGroupKey, taprpc.AssetType_NORMAL,
	)
	assertTransferAssetMeta(
		t.t, ungroupedTransfer, nil, taprpc.AssetType_NORMAL,
	)
	assertTransferAssetMeta(
		t.t, collectibleTransfer, expectedCollectibleGroupKey,
		taprpc.AssetType_COLLECTIBLE,
	)
}

func assertTransferAssetMeta(t require.TestingT,
	transfer *taprpc.AssetTransfer, groupKey []byte,
	assetType taprpc.AssetType) {

	require.NotEmpty(t, transfer.Inputs)
	for i, in := range transfer.Inputs {
		require.Equalf(t, groupKey, in.GroupKey,
			"transfer input %d group_key mismatch", i)
		require.Equalf(t, assetType, in.AssetType,
			"transfer input %d asset_type mismatch", i)
	}

	require.NotEmpty(t, transfer.Outputs)
	for i, out := range transfer.Outputs {
		require.Equalf(t, groupKey, out.GroupKey,
			"transfer output %d group_key mismatch", i)
		require.Equalf(t, assetType, out.AssetType,
			"transfer output %d asset_type mismatch", i)
	}
}

func assertCompletedSendEventAssetMeta(t *testing.T,
	stream *EventSubscription[*taprpc.SendEvent], groupKey []byte,
	assetType taprpc.AssetType) {

	success := make(chan struct{})
	timeout := time.After(defaultWaitTimeout)
	go func() {
		select {
		case <-timeout:
			t.Logf("assertCompletedSendEventAssetMeta: " +
				"cancelling stream after timeout")
			stream.Cancel()

		case <-success:
		}
	}()

	expectedStatus := tapfreighter.SendStateWaitTxConf
	for {
		event, err := stream.Recv()
		require.NoError(t, err, "receiving send event")
		require.Emptyf(t, event.Error, "send event error: %x", event)
		require.Equal(t, expectedStatus.String(), event.SendState)

		if event.SendState == tapfreighter.SendStateComplete.String() {
			require.NotNil(t, event.Transfer)
			assertTransferAssetMeta(
				t, event.Transfer, groupKey, assetType,
			)

			stream.Cancel()
			close(success)
			return
		}

		expectedStatus++
	}
}
