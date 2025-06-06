package itest

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

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

	groupAddr, err := bobTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		ProofCourierAddr: fmt.Sprintf("authmailbox+universerpc://%s",
			t.universeServer.ListenAddr),
		AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V2,
		GroupKey:       groupKey,
	})
	require.NoError(t.t, err)

	t.Logf("Got group addr: %v", toJSON(t.t, groupAddr))

	sendResp, err := t.tapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		TapAddrs: []string{groupAddr.Encoded},
		AddressAmounts: map[string]uint64{
			groupAddr.Encoded: totalAmount,
		},
	})
	require.NoError(t.t, err)

	t.Logf("Sent asset to group addr: %v", toJSON(t.t, sendResp))

	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	// AssertAddrEvent(t.t, bobTapd, groupAddr, 2, proofReceived)
	time.Sleep(time.Second * 5)

	assets, err := bobTapd.ListAssets(ctxt, &taprpc.ListAssetRequest{
		ScriptKeyType: allScriptKeysQuery,
	})
	require.NoError(t.t, err)

	t.Logf("Bob's assets: %v", toJSON(t.t, assets))

	AssertBalanceByGroup(
		t.t, bobTapd, hex.EncodeToString(groupKey), totalAmount,
		WithAllScriptKeyTypes(),
	)

	// TODO:
	// - multiple outputs with the same address
	// - multiple outputs with different addresses
}
