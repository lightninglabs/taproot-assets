package itest

import (
	"context"
	"encoding/hex"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

func testAddressV2WithGroupKey(t *harnessTest) {
	// We begin by minting a new asset group with a group key.
	firstTrancheReq := CopyRequest(issuableAssets[0])

	firstTranche := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{firstTrancheReq},
	)
	firstAsset := firstTranche[0]

	groupKey := firstTranche[0].AssetGroup.TweakedGroupKey

	// And then we mint a second tranche of the same asset group.
	secondTrancheReq := CopyRequest(firstTrancheReq)
	secondTrancheReq.Asset.Name = "itestbuxx-money-printer-brrr-tranche-2"
	secondTrancheReq.Asset.GroupedAsset = true
	secondTrancheReq.Asset.NewGroupedAsset = false
	secondTrancheReq.Asset.GroupKey = groupKey

	secondTranche := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{secondTrancheReq},
	)
	secondAsset := secondTranche[0]

	totalAmount := firstAsset.Amount + secondAsset.Amount
	t.Logf("Minted %d units for group %x", totalAmount, groupKey)

	// Now we can create an address with the group key.
	// We'll make a second node now that'll be the receiver of all the
	// assets made above.
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	groupAddr, addrEvents := NewAddrWithEventStream(
		t.t, bobTapd, &taprpc.NewAddrRequest{
			AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V2,
			GroupKey:       groupKey,
		},
	)

	t.Logf("Got group addr: %v", toJSON(t.t, groupAddr))

	sendResp, err := t.tapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		AddressesWithAmounts: []*taprpc.AddressWithAmount{
			{
				TapAddr: groupAddr.Encoded,
				Amount:  totalAmount,
			},
		},
	})
	require.NoError(t.t, err)

	t.Logf("Sent asset to group addr: %v", toJSON(t.t, sendResp))

	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	AssertReceiveEventsCustom(t.t, addrEvents, []taprpc.AddrEventStatus{
		statusConfirmed,
		proofReceived,
	})
	AssertAddrEventByStatus(t.t, bobTapd, statusCompleted, 1)

	assets, err := bobTapd.ListAssets(ctxt, &taprpc.ListAssetRequest{})
	require.NoError(t.t, err)

	t.Logf("Bob's assets: %v", toJSON(t.t, assets))
	require.Len(t.t, assets.Assets, 2)

	AssertBalanceByGroup(
		t.t, bobTapd, hex.EncodeToString(groupKey), totalAmount,
	)

	// We now make sure we can spend those assets again by sending
	// them back to ourselves.
	groupAddr, addrEvents = NewAddrWithEventStream(
		t.t, bobTapd, &taprpc.NewAddrRequest{
			Amt:            totalAmount,
			AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V2,
			GroupKey:       groupKey,
		},
	)

	sendResp, err = bobTapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		AddressesWithAmounts: []*taprpc.AddressWithAmount{
			{
				TapAddr: groupAddr.Encoded,
			},
		},
	})
	require.NoError(t.t, err)

	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)
	AssertAddrEventByStatus(t.t, bobTapd, statusCompleted, 1)

	AssertBalanceByGroup(
		t.t, bobTapd, hex.EncodeToString(groupKey), totalAmount,
	)

	// TODO:
	// - multiple outputs with the same address
	// - multiple outputs with different addresses
	// - re-try sending fragment to courier
	// - assert address events for multiple outputs
	// - resume pending address events
}
