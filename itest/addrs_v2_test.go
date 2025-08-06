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
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testAddressV2WithSimpleAsset tests the various RPC calls related to addresses
// V2 with simple (non-grouped) assets.
func testAddressV2WithSimpleAsset(t *harnessTest) {
	// First, mint a few assets, so we have some to create addresses for.
	// We mint all of them in individual batches to avoid needing to sign
	// for multiple internal asset transfers when only sending one of them
	// to an external address.
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{
			simpleAssets[0], simpleAssets[1],
		},
	)

	ctxb := context.Background()
	ctxt, cancel := context.WithTimeout(ctxb, defaultWaitTimeout)
	defer cancel()

	// We'll make a second node now that'll be the receiver of all the
	// assets made above.
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	secondTapd := setupTapdHarness(t.t, t, bobLnd, t.universeServer)
	defer func() {
		require.NoError(t.t, secondTapd.stop(!*noDelete))
	}()

	var addresses []*taprpc.Addr
	for idx, a := range rpcAssets {
		// In order to force a split, we don't try to send the full
		// asset. But we can't split a collectible, so we send the whole
		// asset.
		amountToRequest := uint64(0)
		amountToSend := a.Amount - 1
		if amountToSend == 0 {
			amountToSend = a.Amount
			amountToRequest = 1
		}

		addr, events := NewAddrWithEventStream(
			t.t, secondTapd, &taprpc.NewAddrRequest{
				AssetId:        a.AssetGenesis.AssetId,
				AssetVersion:   a.Version,
				AddressVersion: addrV2,
				Amt:            amountToRequest,
			},
		)
		addresses = append(addresses, addr)

		AssertAddrCreated(t.t, secondTapd, a, addr)

		sendResp, sendEvents := sendAsset(t, t.tapd, withAddV2Receiver(
			amountToSend, addr,
		))
		sendRespJSON, err := formatProtoJSON(sendResp)
		require.NoError(t.t, err)

		t.Logf("Got response from sending assets: %v", sendRespJSON)

		// Mine a block to make sure the events are marked as confirmed.
		MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

		// Eventually the event should be marked as confirmed.
		AssertAddrEvent(t.t, secondTapd, addr, 1, statusConfirmed)

		// Make sure we have imported and finalized all proofs.
		AssertNonInteractiveRecvComplete(t.t, secondTapd, idx+1)
		AssertSendEventsComplete(t.t, addr.ScriptKey, sendEvents)

		// Make sure the receiver has received all events in order for
		// the address.
		AssertReceiveEventsCustom(t.t, events, []taprpc.AddrEventStatus{
			statusConfirmed,
			proofReceived,
		})

		// Make sure the asset meta is also fetched correctly.
		assetResp, err := secondTapd.FetchAssetMeta(
			ctxt, &taprpc.FetchAssetMetaRequest{
				Asset: &taprpc.FetchAssetMetaRequest_AssetId{
					AssetId: a.AssetGenesis.AssetId,
				},
			},
		)
		require.NoError(t.t, err)
		require.Equal(t.t, a.AssetGenesis.MetaHash, assetResp.MetaHash)

		// We also make sure that we can't create an address for a
		// collectible asset that doesn't specify an amount of exactly
		// one.
		if a.AssetGenesis.AssetType == taprpc.AssetType_COLLECTIBLE {
			_, err := secondTapd.NewAddr(
				ctxt, &taprpc.NewAddrRequest{
					AssetId:        a.AssetGenesis.AssetId,
					AssetVersion:   a.Version,
					AddressVersion: addrV2,
				},
			)
			require.ErrorContains(
				t.t, err, "collectible asset amount not one",
			)
		}
	}

	// Now sanity-check that we can actually list the transfer.
	err := wait.NoError(func() error {
		resp, err := t.tapd.ListTransfers(
			ctxt, &taprpc.ListTransfersRequest{},
		)
		require.NoError(t.t, err)

		require.Len(t.t, resp.Transfers, len(rpcAssets))
		require.Len(t.t, resp.Transfers[0].Outputs, 2)

		firstOut := resp.Transfers[0].Outputs[0]
		require.EqualValues(t.t, 1, firstOut.Amount)
		require.Equal(
			t.t, addresses[0].AssetVersion, firstOut.AssetVersion,
		)

		firstIn := resp.Transfers[0].Inputs[0]
		require.Equal(
			t.t, rpcAssets[0].AssetGenesis.AssetId, firstIn.AssetId,
		)

		return nil
	}, defaultTimeout/2)
	require.NoError(t.t, err)

	// Let's make sure we can send all the assets back to the sender.
	// In order to force a split, we don't try to send the full
	// asset.
	for idx, a := range rpcAssets {
		// We can't split a collectible, so we send the whole asset
		// back.
		amount := a.Amount - 1
		if amount == 0 {
			amount = a.Amount
		}

		addr, events := NewAddrWithEventStream(
			t.t, t.tapd, &taprpc.NewAddrRequest{
				AssetId:      a.AssetGenesis.AssetId,
				Amt:          amount,
				AssetVersion: a.Version,
			},
		)
		addresses = append(addresses, addr)

		AssertAddrCreated(t.t, t.tapd, a, addr)

		sendResp, sendEvents := sendAssetsToAddr(t, secondTapd, addr)
		sendRespJSON, err := formatProtoJSON(sendResp)
		require.NoError(t.t, err)

		t.Logf("Got response from sending assets: %v", sendRespJSON)

		// Make sure that eventually we see a single event for the
		// address.
		AssertAddrEvent(t.t, t.tapd, addr, 1, statusDetected)

		// Mine a block to make sure the events are marked as confirmed.
		MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

		// Eventually the event should be marked as confirmed.
		AssertAddrEvent(t.t, t.tapd, addr, 1, statusConfirmed)

		// Make sure we have imported and finalized all proofs.
		AssertNonInteractiveRecvComplete(t.t, t.tapd, idx+1)
		AssertSendEventsComplete(t.t, addr.ScriptKey, sendEvents)

		// Make sure the receiver has received all events in order for
		// the address.
		AssertReceiveEvents(t.t, addr, events)
	}
}

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

	// We don't want the user to be able to create a V2 address that just
	// specifies the asset ID but is for a grouped asset.
	_, err := bobTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AddressVersion: taprpc.AddrVersion_ADDR_VERSION_V2,
		AssetId:        firstAssetID,
	})
	require.ErrorContains(
		t.t, err, "version 2 addresses for grouped assets must use "+
			"group key only",
	)

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
			AddressVersion: addrV2,
			GroupKey:       groupKey,
		},
	)

	t.Logf("Got group addr: %v", toJSON(t.t, groupAddrBob2))

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
			AddressVersion: addrV2,
			GroupKey:       groupKey,
		},
	)
	groupAddrAlice2, _ := NewAddrWithEventStream(
		t.t, t.tapd, &taprpc.NewAddrRequest{
			AddressVersion: addrV2,
			GroupKey:       groupKey,
		},
	)
	t.Logf("Got group addr: %v", toJSON(t.t, groupAddrAlice1))
	t.Logf("Got group addr: %v", toJSON(t.t, groupAddrAlice2))

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
		AddressVersion: addrV2,
		GroupKey:       groupKey,
	})
	require.NoError(t.t, err)
	charlieAddr, err := charlieTapd.NewAddr(ctxt, &taprpc.NewAddrRequest{
		AddressVersion: addrV2,
		GroupKey:       groupKey,
	})
	require.NoError(t.t, err)

	// We also create an address for Charlie that uses Bob as the universe,
	// to make sure that Charlie can receive two transfers from different
	// auth mailboxes at the same time.
	charlieAddrBobUni, err := charlieTapd.NewAddr(
		ctxt, &taprpc.NewAddrRequest{
			AddressVersion: addrV2,
			GroupKey:       groupKey,
			ProofCourierAddr: fmt.Sprintf(
				"%s://%s", proof.UniverseRpcCourierType,
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
		tapfreighter.SendStateTransferProofs,
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
