//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	fn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsMultiChannelPathfinding tests that payments are correctly
// routed through the right asset channel when multiple asset channels exist
// between the same pair of nodes.
//
//nolint:lll
func testCustomChannelsMultiChannelPathfinding(ctx context.Context,
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
	charlie := net.NewNode("Charlie", lndArgs, tapdArgs)

	// Now we'll connect all nodes, and also fund them with some coins.
	nodes := []*itest.IntegratedNode{alice, bob, charlie}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Next, we'll mint an asset for Alice, who will be the node that opens
	// the channel outbound.
	mintedAssets1 := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(alice),
		[]*mintrpc.MintAssetRequest{
			{
				Asset: ccItestAsset,
			},
		},
	)
	cents := mintedAssets1[0]
	assetIDCents := cents.AssetGenesis.AssetId

	// We'll mint a second asset, representing british pences.
	mintedAssets2 := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(alice),
		[]*mintrpc.MintAssetRequest{
			{
				Asset: &mintrpc.MintAsset{
					AssetType: taprpc.AssetType_NORMAL,
					Name:      "itest-asset-pences",
					AssetMeta: ccDummyMetaData,
					Amount:    1_000_000,
				},
			},
		},
	)
	pences := mintedAssets2[0]
	assetIDPences := pences.AssetGenesis.AssetId

	t.Logf("Minted %d lightning cents and %d lightning pences, syncing "+
		"universes...", cents.Amount, pences.Amount)
	syncUniverses(t.t, alice, bob)
	t.Logf("Universes synced between all nodes, distributing assets...")

	// With the assets created, and synced -- we'll now open the channel
	// between Alice and Bob.
	t.Logf("Opening asset channel with cents...")
	assetFundResp1, err := asTapd(alice).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetIDCents,
			PeerPubkey:         bob.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded cents channel between Alice and Bob: %v",
		assetFundResp1)

	// With the channel open, mine a block to confirm it.
	mineBlocks(t, net, 6, 1)

	t.Logf("Opening asset channel with pences...")
	assetFundResp2, err := asTapd(alice).FundChannel(
		ctx, &tchrpc.FundChannelRequest{
			AssetAmount:        fundingAmount,
			AssetId:            assetIDPences,
			PeerPubkey:         bob.PubKey[:],
			FeeRateSatPerVbyte: 5,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded pences channel between Alice and Bob: %v",
		assetFundResp2)

	// With the channel open, mine a block to confirm it.
	mineBlocks(t, net, 6, 1)

	t.Logf("Opening normal channel between Bob and Charlie...")
	satChanPoint := openChannelAndAssert(
		t, net, bob, charlie, lntest.OpenChannelParams{
			Amt:         10_000_000,
			SatPerVByte: 5,
		},
	)
	defer closeChannelAndAssert(t, net, charlie, satChanPoint, false)

	// Before we start sending out payments, let's make sure each node can
	// see the other one in the graph and has all required features.
	require.NoError(t.t, net.AssertNodeKnown(alice, bob))
	require.NoError(t.t, net.AssertNodeKnown(bob, alice))
	require.NoError(t.t, net.AssertNodeKnown(alice, charlie))

	// We now make sure that the balance of the cents channel is higher on
	// Alice, by sending some of the pences to Bob in a keysend payment.
	const pencesKeySendAmount = 5_000
	sendAssetKeySendPayment(
		t.t, alice, bob, pencesKeySendAmount, assetIDPences,
		fn.None[int64](),
	)

	logBalance(t.t, nodes, assetIDCents, "cents, after keysend pences")
	logBalance(t.t, nodes, assetIDPences, "pences, after keysend pences")

	// We now create a normal invoice on Charlie for some amount, then try
	// to pay it with pences.
	const btcInvoiceAmount = 500_00
	invoiceResp := createNormalInvoice(t.t, charlie, btcInvoiceAmount)
	payInvoiceWithAssets(
		t.t, alice, bob, invoiceResp.PaymentRequest, assetIDPences,
	)
}
