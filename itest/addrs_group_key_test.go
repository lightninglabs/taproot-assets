package itest

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapfreighter"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// testAddressV2WithGroupKey tests that we can create an address with version 2
// that uses a group key, and that we can send assets to it. It also tests that
// we can send assets to the same address multiple times, using different
// amounts.
func testAddressV2WithGroupKey(t *harnessTest) {
	// We begin by minting a new asset group with a group key.
	firstTrancheReq := CopyRequest(issuableAssets[0])

	firstTranche := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{firstTrancheReq},
	)
	firstAsset := firstTranche[0]
	firstAssetID := firstAsset.AssetGenesis.AssetId
	groupKey := firstAsset.AssetGroup.TweakedGroupKey

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
	secondAssetID := secondAsset.AssetGenesis.AssetId

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

	groupAddrBob, addrEvents := NewAddrWithEventStream(
		t.t, bobTapd, &taprpc.NewAddrRequest{
			AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V2,
			GroupKey:       groupKey,
		},
	)

	t.Logf("Got group addr: %v", toJSON(t.t, groupAddrBob))

	sendResp, err := t.tapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		AddressesWithAmounts: []*taprpc.AddressWithAmount{
			{
				TapAddr: groupAddrBob.Encoded,
				Amount:  totalAmount,
			},
		},
	})
	require.NoError(t.t, err)

	t.Logf("Sent asset to group addr: %v", toJSON(t.t, sendResp))

	AssertAssetOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		sendResp.Transfer, [][]byte{firstAssetID, secondAssetID},
		[]uint64{0, firstAsset.Amount, 0, secondAsset.Amount}, 0,
		1, 4, true,
	)
	AssertReceiveEventsCustom(t.t, addrEvents, []taprpc.AddrEventStatus{
		statusConfirmed,
		proofReceived,
	})
	AssertAddrEventByStatus(t.t, bobTapd, statusCompleted, 1)
	AssertBalanceByGroup(
		t.t, bobTapd, hex.EncodeToString(groupKey), totalAmount,
		WithNumUtxos(2),
	)

	// The sending node should only have two tombstone outputs, but the
	// total value should be zero.
	AssertBalanceByGroup(
		t.t, t.tapd, hex.EncodeToString(groupKey), 0, WithNumUtxos(2),
		WithAllScriptKeyTypes(),
	)

	// We now make sure we can spend those assets again by sending
	// them back to ourselves, using an address with an amount.
	groupAddrBob2, _ := NewAddrWithEventStream(
		t.t, bobTapd, &taprpc.NewAddrRequest{
			Amt:            totalAmount,
			AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V2,
			GroupKey:       groupKey,
		},
	)

	_, err = bobTapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		AddressesWithAmounts: []*taprpc.AddressWithAmount{
			{
				TapAddr: groupAddrBob2.Encoded,
			},
		},
	})
	require.NoError(t.t, err)

	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)
	AssertAddrEventByStatus(t.t, bobTapd, statusCompleted, 1)
	AssertBalanceByGroup(
		t.t, bobTapd, hex.EncodeToString(groupKey), totalAmount,
		WithNumUtxos(2),
	)

	// We now make sure we can send to the same address twice, using
	// different amounts, in the same transaction.
	groupAddrAlice1, _ := NewAddrWithEventStream(
		t.t, t.tapd, &taprpc.NewAddrRequest{
			AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V2,
			GroupKey:       groupKey,
		},
	)
	groupAddrAlice2, _ := NewAddrWithEventStream(
		t.t, t.tapd, &taprpc.NewAddrRequest{
			AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V2,
			GroupKey:       groupKey,
		},
	)
	sendResp3, err := bobTapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		AddressesWithAmounts: []*taprpc.AddressWithAmount{
			{
				TapAddr: groupAddrAlice1.Encoded,
				Amount:  totalAmount/2 - 50,
			},
			{
				TapAddr: groupAddrAlice2.Encoded,
				Amount:  totalAmount/2 + 50,
			},
		},
	})
	require.NoError(t.t, err)

	AssertAssetOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, bobTapd,
		sendResp3.Transfer, [][]byte{firstAssetID, secondAssetID},
		[]uint64{0, totalAmount/2 - 50, 50, 0, totalAmount / 2}, 1,
		2, 5, true,
	)
	AssertAddrEventByStatus(t.t, t.tapd, statusCompleted, 1)
	AssertBalanceByGroup(
		t.t, t.tapd, hex.EncodeToString(groupKey), totalAmount,
		WithNumUtxos(4),
	)

	// The sending node should only have two tombstone outputs, but the
	// total value should be zero.
	AssertBalanceByGroup(
		t.t, bobTapd, hex.EncodeToString(groupKey), 0, WithNumUtxos(2),
		WithAllScriptKeyTypes(),
	)

	// And finally, we make sure we can use Bob's very first address again
	// to send assets. This will spend the largest UTXO by default, which
	// we'll need to know to make the assertion below.
	bobUtxo := LargestUtxo(t.t, t.tapd, nil, groupKey)
	sendResp4, err := t.tapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		AddressesWithAmounts: []*taprpc.AddressWithAmount{
			{
				TapAddr: groupAddrBob.Encoded,
				Amount:  1234,
			},
		},
	})
	require.NoError(t.t, err)

	AssertAssetOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		sendResp4.Transfer, [][]byte{bobUtxo.AssetGenesis.AssetId},
		[]uint64{bobUtxo.Amount - 1234, 1234}, 1, 2, 2, true,
	)
	AssertAddrEventByStatus(t.t, bobTapd, statusCompleted, 3)
	AssertBalanceByGroup(
		t.t, bobTapd, hex.EncodeToString(groupKey), 1234,
		WithNumUtxos(2),
	)
}

// testAddressV2WithGroupKeyRestart tests that we can re-try and properly
// continue the address v2 send process in various scenarios.
func testAddressV2WithGroupKeyRestart(t *harnessTest) {
	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We start by minting an asset group with a group key. We'll only use
	// one tranche for this test.
	firstTranche := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{issuableAssets[0]},
	)
	firstAsset := firstTranche[0]
	firstAssetID := firstAsset.AssetGenesis.AssetId
	groupKey := firstAsset.AssetGroup.TweakedGroupKey

	// Now we can create two more tapd nodes that we can start and stop
	// independently. To save some time, we'll use the same lnd node.
	bobCharlieLnd := t.lndHarness.NewNodeWithCoins("BobAndCharlie", nil)
	bobTapd := setupTapdHarness(t.t, t, bobCharlieLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()
	charlieTapd := setupTapdHarness(t.t, t, bobCharlieLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, charlieTapd.stop(!*noDelete))
	}()

	// We now create an address with the group key on Bob's and Charlie's
	// tapd node.
	bobAddr, err := bobTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V2,
		GroupKey:       groupKey,
	})
	require.NoError(t.t, err)
	charlieAddr, err := charlieTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V2,
		GroupKey:       groupKey,
	})
	require.NoError(t.t, err)

	// We also create an address for Charlie that uses Bob as the universe,
	// to make sure that Charlie can receive two transfers from different
	// auth mailboxes at the same time.
	charlieAddrBobUni, err := charlieTapd.NewAddr(
		ctxt, &taprpc.NewAddrRequest{
			AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V2,
			GroupKey:       groupKey,
			ProofCourierAddr: fmt.Sprintf(
				"%s://%s", proof.AuthMailboxUniRpcCourierType,
				bobTapd.rpcHost(),
			),
		},
	)
	require.NoError(t.t, err)

	// We wait a bit for the two nodes to connect to the universe server for
	// the initial proof courier ping check.
	time.Sleep(500 * time.Millisecond)

	// We now stop Bob and Charlie's tapd nodes. We can't stop the universe
	// yet, because the preliminary ping will attempt to connect to it.
	t.Logf("Stopping Bob and Charlie's tapd nodes...")
	require.NoError(t.t, bobTapd.stop(false))
	require.NoError(t.t, charlieTapd.stop(false))

	// We should still be able to send assets to the address, but we won't
	// be able to complete the send process past the proof courier step.
	// This is because the tapd nodes are stopped, so they won't be able to
	const (
		bobAmount     = 200
		charlieAmount = 300
	)
	sendResp, sendEvents := sendAsset(
		t, t.tapd, withAddV2Receiver(bobAmount, bobAddr),
		withAddV2Receiver(charlieAmount, charlieAddr),
	)

	// Now that we've sent the assets, we can stop the universe server.
	require.NoError(t.t, t.universeServer.Stop())

	time.Sleep(500 * time.Millisecond)

	// Mine a block to make sure the events are marked as confirmed.
	t.Logf("Universe stopped, going to mine a block to confirm the send...")
	_ = MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	AssertSendEvents(
		t.t, nil, sendEvents, tapfreighter.SendStateWaitTxConf,
		tapfreighter.SendStateStorePostAnchorTxConf,
	)

	// We now restart the sender and then start the universe server again.
	// The send event should then eventually complete.
	t.Logf("Restarting tapd node...")
	_ = sendEvents.CloseSend()
	sendEvents.Cancel()
	require.NoError(t.t, t.tapd.stop(false))
	require.NoError(t.t, t.tapd.start(false))

	t.Logf("Restarted tapd node, registering for send events...")
	ctxc, streamCancel := context.WithCancel(context.Background())
	stream, err := t.tapd.SubscribeSendEvents(
		ctxc, &taprpc.SubscribeSendEventsRequest{
			FilterLabel: sendResp.Transfer.Label,
		},
	)
	require.NoError(t.t, err)

	// Formulate a subscription handler for the send event stream.
	sendEvents = &EventSubscription[*taprpc.SendEvent]{
		ClientEventStream: stream,
		Cancel:            streamCancel,
	}

	t.Logf("Starting universe server...")
	require.NoError(t.t, t.universeServer.Start(nil))

	AssertSendEvents(
		t.t, nil, sendEvents,
		tapfreighter.SendStateComplete,
		tapfreighter.SendStateComplete,
	)
	_ = sendEvents.CloseSend()
	sendEvents.Cancel()

	// We now start Bob and expect it to detect and import the transfer.
	t.Logf("Starting Bob's tapd node...")
	require.NoError(t.t, bobTapd.start(false))

	AssertAddrEventByStatus(t.t, bobTapd, statusCompleted, 1)
	AssertBalanceByGroup(
		t.t, bobTapd, hex.EncodeToString(groupKey), bobAmount,
		WithNumUtxos(1),
	)

	// And we restart Bob to make sure it doesn't process the same messages
	// again.
	t.Logf("Restarting Bob's tapd node...")
	require.NoError(t.t, bobTapd.stop(false))
	require.NoError(t.t, bobTapd.start(false))

	AssertBalanceByGroup(
		t.t, bobTapd, hex.EncodeToString(groupKey), bobAmount,
		WithNumUtxos(1),
	)

	// We now forward the assets from Bob to Charlie, using the address
	// where Bob is the universe.
	sendResp2, err := bobTapd.SendAsset(ctxt, &taprpc.SendAssetRequest{
		AddressesWithAmounts: []*taprpc.AddressWithAmount{
			{
				TapAddr: charlieAddrBobUni.Encoded,
				Amount:  bobAmount / 2,
			},
		},
	})
	require.NoError(t.t, err)

	AssertAssetOutboundTransferWithOutputs(
		t.t, t.lndHarness.Miner().Client, bobTapd,
		sendResp2.Transfer, [][]byte{firstAssetID},
		[]uint64{bobAmount / 2, bobAmount / 2}, 0, 1, 2, true,
	)

	AssertBalanceByGroup(
		t.t, bobTapd, hex.EncodeToString(groupKey), bobAmount/2,
		WithNumUtxos(1),
	)

	t.Logf("Starting Charlies's tapd node...")
	require.NoError(t.t, charlieTapd.start(false))

	AssertAddrEventByStatus(t.t, charlieTapd, statusCompleted, 2)
	AssertBalanceByGroup(
		t.t, charlieTapd, hex.EncodeToString(groupKey),
		charlieAmount+bobAmount/2, WithNumUtxos(2),
	)
}
