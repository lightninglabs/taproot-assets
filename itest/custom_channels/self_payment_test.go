//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsSelfPayment tests self-payment over asset channels. Alice
// opens both an asset channel and a normal BTC channel to Bob. She then pays
// asset invoices to herself (routing out through the BTC channel and back
// through the asset channel) and also pays BTC invoices to herself (routing
// out through the asset channel and back through the BTC channel).
//
//nolint:lll
func testCustomChannelsSelfPayment(_ context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)

	// We use Alice as the proof courier. But in order for Alice to also
	// use itself, we need to define its port upfront.
	alicePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, alicePort),
	))

	// Next, we'll make Alice and Bob, who will be the main nodes under
	// test.
	aliceLndArgs := slices.Clone(lndArgs)
	aliceLndArgs = append(aliceLndArgs, fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", alicePort,
	))
	alice := net.NewNode("Alice", aliceLndArgs, tapdArgs)
	bob := net.NewNode("Bob", lndArgs, tapdArgs)

	// Now we'll connect all nodes, and also fund them with some coins.
	nodes := []*itest.IntegratedNode{alice, bob}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Next, we'll mint an asset for Alice, who will be the node that opens
	// the channel outbound.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(alice),
		[]*mintrpc.MintAssetRequest{
			{
				Asset: ccItestAsset,
			},
		},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId

	t.Logf("Minted %d lightning cents, syncing universes...",
		cents.Amount)
	syncUniverses(t.t, alice, bob)
	t.Logf("Universes synced between all nodes, distributing " +
		"assets...")

	// With the assets created, and synced -- we'll now open the channel
	// between Alice and Bob.
	ctx := context.Background()
	t.Logf("Opening asset channel...")
	assetFundResp, err := asTapd(alice).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetID,
			PeerPubkey:         bob.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded asset channel between Alice and Bob: %v",
		assetFundResp)

	assetChanPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(assetFundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: assetFundResp.Txid,
		},
	}

	// With the channel open, mine a block to confirm it.
	mineBlocks(t, net, 6, 1)

	// Before we start sending out payments, let's make sure each node can
	// see the other one in the graph and has all required features.
	require.NoError(t.t, net.AssertNodeKnown(alice, bob))
	require.NoError(t.t, net.AssertNodeKnown(bob, alice))

	t.Logf("Opening normal channel between Alice and Bob...")
	satChanPoint := openChannelAndAssert(
		t, net, alice, bob, lntest.OpenChannelParams{
			Amt:         10_000_000,
			SatPerVByte: 5,
		},
	)
	defer closeChannelAndAssert(t, net, alice, satChanPoint, false)

	assetChan := fetchChannel(t.t, alice, assetChanPoint)
	assetChanSCID := assetChan.ChanId
	satChan := fetchChannel(t.t, alice, satChanPoint)
	satChanSCID := satChan.ChanId

	t.Logf("Alice pubkey: %x", alice.PubKey[:])
	t.Logf("Bob   pubkey: %x", bob.PubKey[:])
	t.Logf("Outgoing channel SCID: %d", satChanSCID)
	logBalance(t.t, nodes, assetID, "initial")

	t.Logf("Key sending 15k assets from Alice to Bob...")
	const (
		assetKeySendAmount = 15_000
		numInvoicePayments = 10
		assetInvoiceAmount = 1_234
		btcInvoiceAmount   = 10_000
		btcKeySendAmount   = 200_000
		btcReserveAmount   = 2000
		btcHtlcCost        = numInvoicePayments * 354
	)
	sendAssetKeySendPayment(
		t.t, alice, bob, assetKeySendAmount, assetID,
		fn.Some[int64](btcReserveAmount+btcHtlcCost),
	)

	// We also send 200k sats from Alice to Bob, to make sure the BTC
	// channel has liquidity in both directions.
	sendKeySendPayment(t.t, alice, bob, btcKeySendAmount)
	logBalance(t.t, nodes, assetID, "after keysend")

	// We now do a series of small payments. They should all succeed and
	// the balances should be updated accordingly.
	aliceAssetBalance := uint64(fundingAmount - assetKeySendAmount)
	bobAssetBalance := uint64(assetKeySendAmount)
	for i := 0; i < numInvoicePayments; i++ {
		// The BTC balance of Alice before we start the payment. We
		// expect that to go down by at least the invoice amount.
		btcBalanceAliceBefore := fetchChannel(
			t.t, alice, satChanPoint,
		).LocalBalance

		invoiceResp := createAssetInvoice(
			t.t, bob, alice, assetInvoiceAmount, assetID,
		)
		payInvoiceWithSatoshi(
			t.t, alice, invoiceResp, withOutgoingChanIDs(
				[]uint64{satChanSCID},
			), withAllowSelfPayment(),
		)

		logBalance(
			t.t, nodes, assetID,
			"after paying invoice "+strconv.Itoa(i),
		)

		// The accumulated delta from the rounding of multiple sends.
		// We basically allow the balance to be off by one unit for
		// each payment.
		delta := float64(i + 1)

		// We now expect the channel balance to have decreased in the
		// BTC channel and increased in the assets channel.
		assertChannelAssetBalanceWithDelta(
			t.t, alice, assetChanPoint,
			aliceAssetBalance+assetInvoiceAmount,
			bobAssetBalance-assetInvoiceAmount, delta,
		)
		aliceAssetBalance += assetInvoiceAmount
		bobAssetBalance -= assetInvoiceAmount

		btcBalanceAliceAfter := fetchChannel(
			t.t, alice, satChanPoint,
		).LocalBalance

		// The difference between the two balances should be at least
		// the invoice amount.
		decodedInvoice, err := alice.LightningClient.DecodePayReq(
			context.Background(), &lnrpc.PayReqString{
				PayReq: invoiceResp.PaymentRequest,
			},
		)
		require.NoError(t.t, err)
		require.GreaterOrEqual(
			t.t, btcBalanceAliceBefore-btcBalanceAliceAfter,
			decodedInvoice.NumSatoshis,
		)
	}

	// We now do the opposite: We create a satoshi invoice on Alice and
	// attempt to pay it with assets.
	aliceAssetBalance, bobAssetBalance = channelAssetBalance(
		t.t, alice, assetChanPoint,
	)
	for i := 0; i < numInvoicePayments; i++ {
		// The BTC balance of Alice before we start the payment. We
		// expect that to go down by at least the invoice amount.
		btcBalanceAliceBefore := fetchChannel(
			t.t, alice, satChanPoint,
		).LocalBalance

		hopHint := &lnrpc.HopHint{
			NodeId:                    bob.PubKeyStr,
			ChanId:                    satChan.PeerScidAlias,
			CltvExpiryDelta:           80,
			FeeBaseMsat:               1000,
			FeeProportionalMillionths: 1,
		}
		invoiceResp := createNormalInvoice(
			t.t, alice, btcInvoiceAmount, withRouteHints(
				[]*lnrpc.RouteHint{{
					HopHints: []*lnrpc.HopHint{hopHint},
				}},
			),
		)
		sentUnits, _ := payInvoiceWithAssets(
			t.t, alice, bob, invoiceResp.PaymentRequest, assetID,
			withAllowSelfPayment(), withOutgoingChanIDs(
				[]uint64{assetChanSCID},
			),
		)

		logBalance(
			t.t, nodes, assetID,
			"after paying sat invoice "+strconv.Itoa(i),
		)

		// The accumulated delta from the rounding of multiple sends.
		// We basically allow the balance to be off by one unit for
		// each payment.
		delta := float64(i + 1)

		// We now expect the channel balance to have increased in the
		// BTC channel and decreased in the assets channel.
		assertChannelAssetBalanceWithDelta(
			t.t, alice, assetChanPoint,
			aliceAssetBalance-sentUnits,
			bobAssetBalance+sentUnits, delta,
		)
		aliceAssetBalance -= sentUnits
		bobAssetBalance += sentUnits

		btcBalanceAliceAfter := fetchChannel(
			t.t, alice, satChanPoint,
		).LocalBalance

		// The difference between the two balances should be at least
		// the invoice amount.
		decodedInvoice, err := alice.LightningClient.DecodePayReq(
			context.Background(), &lnrpc.PayReqString{
				PayReq: invoiceResp.PaymentRequest,
			},
		)
		require.NoError(t.t, err)
		require.GreaterOrEqual(
			t.t, btcBalanceAliceAfter-btcBalanceAliceBefore,
			decodedInvoice.NumSatoshis,
		)
	}
}
