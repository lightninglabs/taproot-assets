//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsHoldInvoiceRouteHints tests that an asset hold invoice
// created with pre-existing RFQ route hints carries the hints whose quotes
// outlive the invoice, and can be paid and settled with assets.
func testCustomChannelsHoldInvoiceRouteHints(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	// Quotes initially expire before a default-expiry invoice does.
	oracleAddr := fmt.Sprintf("localhost:%d", port.NextAvailablePort())
	oracle := itest.NewOracleHarnessWithExpiry(
		oracleAddr, rfq.DefaultInvoiceExpiry/2,
	)
	oracle.Start(t.t)
	t.t.Cleanup(oracle.Stop)

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplateNoOracle)
	tapdArgs = append(
		tapdArgs,
		fmt.Sprintf("--experimental.rfq.priceoracleaddress="+
			"rfqrpc://%s", oracleAddr),
		"--experimental.rfq.tls.insecure",
	)
	universe := net.NewNode("Universe", lndArgs, tapdArgs)
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s", proof.UniverseRpcCourierType,
		universe.RPCAddr(),
	))
	alice := net.NewNode("Alice", lndArgs, tapdArgs)
	bob := net.NewNode("Bob", lndArgs, tapdArgs)
	nodes := []*itest.IntegratedNode{alice, bob}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	minted := itest.MintAssetsConfirmBatch(
		t.t, net.Miner, asTapd(alice),
		[]*mintrpc.MintAssetRequest{{Asset: ccItestAsset}},
	)
	assetID := minted[0].AssetGenesis.AssetId
	syncUniverses(t.t, alice, bob)

	var id asset.ID
	copy(id[:], assetID)
	assetPrice := rfqmath.NewBigIntFixedPoint(5_820_600, 0)
	oracle.SetPrice(asset.NewSpecifierFromId(id), assetPrice, assetPrice)

	funding, err := alice.FundChannel(ctx, &tchrpc.FundChannelRequest{
		AssetAmount:        fundingAmount,
		AssetId:            assetID,
		PeerPubkey:         bob.PubKey[:],
		FeeRateSatPerVbyte: 5,
	})
	require.NoError(t.t, err)
	chanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(funding.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: funding.Txid,
		},
	}
	mineBlocks(t, net, 6, 1)
	require.NoError(t.t, net.AssertNodeKnown(alice, bob))
	require.NoError(t.t, net.AssertNodeKnown(bob, alice))
	assertPeerPolicyKnown(t.t, bob, alice, chanPoint)

	// Bob negotiates buy quotes with Alice up front, then builds the
	// route hints for them himself.
	addBuyOrder := func() uint64 {
		resBuy, err := asTapd(bob).RfqClient.AddAssetBuyOrder(
			ctx, &rfqrpc.AddAssetBuyOrderRequest{
				AssetSpecifier: &rfqrpc.AssetSpecifier{
					Id: &rfqrpc.AssetSpecifier_AssetId{
						AssetId: assetID,
					},
				},
				AssetMaxAmt: 1_000,
				Expiry: uint64(
					time.Now().Add(time.Hour).Unix(),
				),
				PeerPubKey:     alice.PubKey[:],
				TimeoutSeconds: 100,
			},
		)
		require.NoError(t.t, err)

		return resBuy.GetAcceptedQuote().Scid
	}
	routeHint := func(nodeID string, scid uint64) *lnrpc.RouteHint {
		return &lnrpc.RouteHint{
			HopHints: []*lnrpc.HopHint{{
				NodeId: nodeID,
				ChanId: scid,
			}},
		}
	}

	shortScid := addBuyOrder()
	oracle.SetExpiryDelay(time.Hour)
	longScid := addBuyOrder()

	// Supplied hints whose quotes all expire before the invoice are
	// rejected.
	createAssetHodlInvoice(
		t.t, alice, bob, 1_000, assetID,
		withRouteHints([]*lnrpc.RouteHint{
			routeHint(alice.PubKeyStr, shortScid),
		}),
		withInvoiceErrSubStr(
			"no quotes in route hints with sufficient expiry",
		),
	)

	// A supplied hint that passes the expiry filter but has a malformed
	// node ID is rejected.
	createAssetHodlInvoice(
		t.t, alice, bob, 1_000, assetID,
		withRouteHints([]*lnrpc.RouteHint{
			routeHint(alice.PubKeyStr, longScid),
			routeHint("not-a-node-id", longScid),
		}),
		withInvoiceErrSubStr("error parsing route hints"),
	)

	// With mixed quote expiries, only the hint for the quote that
	// outlives the invoice is carried.
	invoice := createAssetHodlInvoice(
		t.t, alice, bob, 1_000, assetID,
		withRouteHints([]*lnrpc.RouteHint{
			routeHint(alice.PubKeyStr, shortScid),
			routeHint(alice.PubKeyStr, longScid),
		}),
	)

	decoded, err := bob.DecodePayReq(ctx, &lnrpc.PayReqString{
		PayReq: invoice.payReq,
	})
	require.NoError(t.t, err)
	require.Len(t.t, decoded.RouteHints, 1)
	require.Len(t.t, decoded.RouteHints[0].HopHints, 1)
	hint := decoded.RouteHints[0].HopHints[0]
	require.Equal(t.t, alice.PubKeyStr, hint.NodeId)
	require.Equal(t.t, longScid, hint.ChanId)

	// Alice pays the invoice with assets. The HTLC is held until Bob
	// settles the invoice.
	units, _ := payInvoiceWithAssets(
		t.t, alice, bob, invoice.payReq, assetID,
		withFailure(lnrpc.Payment_IN_FLIGHT, failureNone),
	)
	require.NotZero(t.t, units)
	assertInvoiceState(t.t, bob, invoice.payAddr, lnrpc.Invoice_ACCEPTED)

	_, err = bob.InvoicesClient.SettleInvoice(
		ctx, &invoicesrpc.SettleInvoiceMsg{
			Preimage: invoice.preimage[:],
		},
	)
	require.NoError(t.t, err)
	waitForAssetChannelHtlcSettlement(t.t, alice, chanPoint)
}
