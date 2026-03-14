package itest

import (
	"context"
	"fmt"
	"time"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/authmailboxrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testAuthMailboxCleanup tests that the mailbox server periodically cleans up
// messages whose claimed outpoints have been spent on chain.
func testAuthMailboxCleanup(t *harnessTest) {
	ctx := context.Background()

	// We create a dedicated universe server with a short cleanup interval
	// so we can observe the cleanup within the test timeout.
	cleanupInterval := 2 * time.Second
	uniLnd := t.lndHarness.NewNodeWithCoins("UniCleanup", nil)
	uniService, err := newTapdHarness(
		t.t, t, tapdConfig{
			NetParams: harnessNetParams,
			LndNode:   uniLnd,
		},
		withDisableSupplyVerifierChainWatch(),
		withMboxCleanupInterval(cleanupInterval),
	)
	require.NoError(t.t, err)
	require.NoError(t.t, uniService.start(false))
	defer func() {
		require.NoError(t.t, uniService.stop(!*noDelete))
	}()

	uniServer := &universeServerHarness{
		service:    uniService,
		ListenAddr: uniService.rpcHost(),
		LndHarness: uniLnd,
	}

	// Mint a grouped asset on Alice so we can use V2 addresses.
	firstTrancheReq := CopyRequest(issuableAssets[0])
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner().Client, t.tapd,
		[]*mintrpc.MintAssetRequest{firstTrancheReq},
	)
	firstAsset := rpcAssets[0]
	groupKey := firstAsset.AssetGroup.TweakedGroupKey

	// Create Bob connected to our cleanup-enabled universe.
	bobLnd := t.lndHarness.NewNodeWithCoins("Bob", nil)
	bobTapd := setupTapdHarness(t.t, t, bobLnd, uniServer)
	defer func() {
		require.NoError(t.t, bobTapd.stop(!*noDelete))
	}()

	// Also add the cleanup universe as a federation server on Alice's
	// tapd so proof distribution works.
	t.addFederationServer(uniServer.service.rpcHost(), t.tapd)

	// Create a V2 address on Bob. This will use the universe server's
	// authmailbox as the proof courier.
	bobAddr, _ := NewAddrWithEventStream(
		t.t, bobTapd, &taprpc.NewAddrRequest{
			AddressVersion: addrV2,
			GroupKey:       groupKey,
		},
	)

	// Send from Alice to Bob via the V2 address.
	sendResp, sendEvents := sendAsset(
		t, t.tapd, withAddV2Receiver(firstAsset.Amount, bobAddr),
	)
	_ = sendResp

	// Mine a block to confirm.
	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	// Wait for Bob to receive the asset.
	AssertAddrEventByStatus(t.t, bobTapd, statusCompleted, 1)
	AssertSendEventsComplete(t.t, bobAddr.ScriptKey, sendEvents)

	// The universe server's mailbox should have at least one message.
	info, err := uniService.MailboxInfo(
		ctx, &authmailboxrpc.MailboxInfoRequest{},
	)
	require.NoError(t.t, err)
	require.Greater(t.t, info.MessageCount, uint64(0))
	t.Logf("Mailbox has %d messages before cleanup", info.MessageCount)

	// Now Bob sends the assets back to Alice, which spends the anchor
	// outputs that the mailbox message outpoints reference.
	aliceAddr, _ := NewAddrWithEventStream(
		t.t, t.tapd, &taprpc.NewAddrRequest{
			AddressVersion: addrV2,
			GroupKey:       groupKey,
			Amt:            firstAsset.Amount,
		},
	)

	_, err = bobTapd.SendAsset(ctx, &taprpc.SendAssetRequest{
		AddressesWithAmounts: []*taprpc.AddressWithAmount{
			{
				TapAddr: aliceAddr.Encoded,
			},
		},
	})
	require.NoError(t.t, err)

	// Mine a block to confirm the spend.
	MineBlocks(t.t, t.lndHarness.Miner().Client, 1, 1)

	AssertAddrEventByStatus(t.t, t.tapd, statusCompleted, 1)

	// Wait for the cleanup to detect the spent outpoints and delete the
	// messages. The cleanup interval is 2s, so we give it some margin.
	err = wait.NoError(func() error {
		info, err := uniService.MailboxInfo(
			ctx, &authmailboxrpc.MailboxInfoRequest{},
		)
		if err != nil {
			return err
		}

		if info.MessageCount > 0 {
			return fmt.Errorf("expected 0 messages, got %d",
				info.MessageCount)
		}

		return nil
	}, defaultTimeout)
	require.NoError(t.t, err)

	t.Logf("Mailbox cleanup successful, all messages deleted")
}
