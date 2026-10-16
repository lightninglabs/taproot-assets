package itest

import (
	"context"
	"net"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	unirpc "github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/stretchr/testify/require"
)

// testUniverseTLSVerification tests certificate verification for connections
// to universe servers, proof couriers and auth mailboxes, against a universe
// server with a self-signed certificate.
func testUniverseTLSVerification(t *harnessTest) {
	ctx := context.Background()

	uniService := t.universeServer.service
	uniHost, _, err := net.SplitHostPort(uniService.rpcHost())
	require.NoError(t.t, err)

	// A node that verifies certificates against the system roots can't
	// add the universe server as a federation server.
	strictLnd := t.lndHarness.NewNodeWithCoins("Strict", nil)
	strictTapd := setupTapdHarness(
		t.t, t, strictLnd, t.universeServer,
		WithStrictUniverseTLS(nil),
		func(params *tapdHarnessParams) {
			params.noDefaultUniverseSync = true
		},
	)
	defer func() {
		require.NoError(t.t, strictTapd.stop(!*noDelete))
	}()

	_, err = strictTapd.AddFederationServer(
		ctx, &unirpc.AddFederationServerRequest{
			Servers: []*unirpc.UniverseFederationServer{{
				Host: uniService.rpcHost(),
			}},
		},
	)
	require.ErrorContains(t.t, err, "certificate")

	// A node that pins the certificate of the universe server adds it as
	// a federation server during setup.
	pinnedLnd := t.lndHarness.NewNodeWithCoins("Pinned", nil)
	pinnedTapd := setupTapdHarness(
		t.t, t, pinnedLnd, t.universeServer,
		WithStrictUniverseTLS(map[string]string{
			uniHost: uniService.tlsCertPath,
		}),
	)
	defer func() {
		require.NoError(t.t, pinnedTapd.stop(!*noDelete))
	}()

	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner(), t.tapd,
		[]*mintrpc.MintAssetRequest{simpleAssets[0]},
	)
	rpcAsset := rpcAssets[0]

	// The courier connection check of a new address uses the pinned
	// certificate.
	addr, events := NewAddrWithEventStream(
		t.t, pinnedTapd, &taprpc.NewAddrRequest{
			AssetId:        rpcAsset.AssetGenesis.AssetId,
			AssetVersion:   rpcAsset.Version,
			AddressVersion: addrV2,
		},
	)
	AssertAddrCreated(t.t, pinnedTapd, rpcAsset, addr)

	// The pinned node receives the asset through the auth mailbox and the
	// proof courier of the universe server.
	amountToSend := rpcAsset.Amount - 1
	_, sendEvents := sendAsset(
		t, t.tapd, withAddV2Receiver(amountToSend, addr),
	)
	MineBlocks(t.t, t.lndHarness.Miner(), 1, 1)

	AssertAddrEvent(t.t, pinnedTapd, addr, 1, statusConfirmed)
	AssertNonInteractiveRecvComplete(t.t, pinnedTapd, 1)
	AssertSendEventsComplete(t.t, addr.ScriptKey, sendEvents)
	AssertReceiveEventsCustom(t.t, events, []taprpc.AddrEventStatus{
		statusConfirmed,
		proofReceived,
	})
}
