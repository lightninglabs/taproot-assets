//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"slices"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsMultiRFQ tests the multi-RFQ functionality in a 6-node
// network topology. It verifies that payments can be split across multiple
// asset channels using different RFQ quotes, both for receiving (multi-RFQ
// receive) and sending (multi-RFQ send).
//
// Topology:
//
//	Charlie --[sats]--> Dave   --[assets]--> Fabia
//	Charlie --[sats]--> Erin   --[assets]--> Fabia
//	Charlie --[sats]--> Yara   --[assets]--> Fabia
//	Charlie --[sats]--> George --[assets]--> Fabia
//
//nolint:lll
func testCustomChannelsMultiRFQ(_ context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)
	tapdArgsDiffOracle := slices.Clone(tapdArgsTemplateDiffOracle)

	// We use Charlie as the proof courier and universe host.
	charliePort := port.NextAvailablePort()
	charlieLndArgs := slices.Clone(lndArgs)
	charlieLndArgs = append(charlieLndArgs, fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", charliePort,
	))

	charlie := net.NewNode("Charlie", charlieLndArgs, tapdArgs)

	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, charliePort),
	))

	tapdArgsDiffOracle = append(tapdArgsDiffOracle, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, charliePort),
	))

	dave := net.NewNode("Dave", lndArgs, tapdArgs)
	erin := net.NewNode("Erin", lndArgs, tapdArgs)
	fabia := net.NewNode("Fabia", lndArgs, tapdArgs)
	yara := net.NewNode("Yara", lndArgs, tapdArgs)
	george := net.NewNode("George", lndArgs, tapdArgsDiffOracle)

	nodes := []*itest.IntegratedNode{
		charlie, dave, erin, fabia, yara, george,
	}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	assetReq := itest.CopyRequest(&mintrpc.MintAssetRequest{
		Asset: ccItestAsset,
	})

	assetReq.Asset.NewGroupedAsset = true

	// Mint an asset on Charlie and sync all nodes to Charlie as the
	// universe.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{assetReq},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId
	groupID := cents.GetAssetGroup().GetTweakedGroupKey()

	syncUniverses(t.t, charlie, dave, erin, fabia, yara, george)

	mrfqNodes := multiRfqNodes{
		charlie: itestNode{
			node: charlie,
		},
		dave: itestNode{
			node: dave,
		},
		erin: itestNode{
			node: erin,
		},
		fabia: itestNode{
			node: fabia,
		},
		yara: itestNode{
			node: yara,
		},
		george: itestNode{
			node: george,
		},
		universeTap: charlie,
	}

	createTestMultiRFQAssetNetwork(
		t, net, mrfqNodes, cents, 10_000, 10_000, 10_000,
	)

	logBalance(t.t, nodes, assetID, "before multi-rfq receive")

	hodlInv := createAssetHodlInvoice(t.t, nil, fabia, 20_000, assetID)

	payInvoiceWithSatoshi(
		t.t, charlie, &lnrpc.AddInvoiceResponse{
			PaymentRequest: hodlInv.payReq,
		},
		withFailure(lnrpc.Payment_IN_FLIGHT, failureNone),
	)

	logBalance(t.t, nodes, assetID, "after inflight multi-rfq")

	// Assert that some HTLCs are present from Fabia's point of view.
	assertMinNumHtlcs(t.t, fabia, 1)

	// Assert that Charlie also has at least one outgoing HTLC as a sanity
	// check.
	assertMinNumHtlcs(t.t, charlie, 1)

	// Now let's cancel the invoice and assert that all inbound channels
	// have cleared their HTLCs.
	payHash := hodlInv.preimage.Hash()
	_, err := fabia.InvoicesClient.CancelInvoice(
		context.Background(), &invoicesrpc.CancelInvoiceMsg{
			PaymentHash: payHash[:],
		},
	)
	require.NoError(t.t, err)

	assertNumHtlcs(t.t, dave, 0)
	assertNumHtlcs(t.t, erin, 0)
	assertNumHtlcs(t.t, yara, 0)

	logBalance(t.t, nodes, assetID, "after cancelled hodl")

	// Now let's create a normal invoice that will be settled once all the
	// HTLCs have been received. This is only possible because the payer
	// uses multiple bolt11 hop hints to reach the destination.
	invoiceResp := createAssetInvoice(
		t.t, nil, fabia, 15_000, nil, withInvGroupKey(groupID),
	)

	payInvoiceWithSatoshi(
		t.t, charlie, invoiceResp,
	)

	logBalance(t.t, nodes, assetID, "after multi-rfq receive")

	// Now we'll test that sending with multiple rfq quotes works.

	// Let's start by providing some liquidity to Charlie's peers, in order
	// for them to be able to push some amount if Fabia picks them as part
	// of the route.
	sendKeySendPayment(t.t, charlie, erin, 800_000)
	sendKeySendPayment(t.t, charlie, dave, 800_000)
	sendKeySendPayment(t.t, charlie, yara, 800_000)

	// Let's ask for the rough equivalent of ~15k assets. Fabia, who's going
	// to pay the invoice, only has parts of assets that are less than 10k
	// in channels with one of the 3 intermediate peers. The only way to
	// pay this invoice is by splitting the payment across multiple peers by
	// using multiple RFQ quotes.
	invAmt := int64(15_000 * 17)

	iResp, err := charlie.InvoicesClient.AddHoldInvoice(
		context.Background(), &invoicesrpc.AddHoldInvoiceRequest{
			Memo:  "",
			Value: invAmt,
			Hash:  payHash[:],
		},
	)
	require.NoError(t.t, err)

	payReq := iResp.PaymentRequest

	payInvoiceWithAssets(
		t.t, fabia, nil, payReq, assetID,
		withFailure(lnrpc.Payment_IN_FLIGHT, failureNone),
	)

	assertMinNumHtlcs(t.t, charlie, 2)
	assertMinNumHtlcs(t.t, fabia, 2)

	logBalance(t.t, nodes, assetID, "multi-rfq send in-flight")

	_, err = charlie.InvoicesClient.SettleInvoice(
		context.Background(), &invoicesrpc.SettleInvoiceMsg{
			Preimage: hodlInv.preimage[:],
		},
	)
	require.NoError(t.t, err)

	assertNumHtlcs(t.t, charlie, 0)
	assertNumHtlcs(t.t, fabia, 0)

	logBalance(t.t, nodes, assetID, "after multi-rfq send")

	// Let's make another round-trip involving multi-rfq functionality.
	// Let's have Fabia receive another large payment and send it back
	// again, this time with a greater amount.
	invoiceResp = createAssetInvoice(t.t, nil, fabia, 25_000, assetID)

	payInvoiceWithSatoshi(
		t.t, charlie, invoiceResp,
	)

	logBalance(t.t, nodes, assetID, "after multi-rfq receive (2nd)")

	// Let's bump up the invoice amount a bit, to roughly ~22k assets.
	invAmt = 22_000 * 17
	inv, err := charlie.LightningClient.AddInvoice(
		context.Background(), &lnrpc.Invoice{
			Value: invAmt,
		},
	)
	require.NoError(t.t, err)

	payReq = inv.PaymentRequest

	payInvoiceWithAssets(
		t.t, fabia, nil, payReq, nil, withGroupKey(groupID),
	)

	logBalance(t.t, nodes, assetID, "after multi-rfq send (2nd)")
}
