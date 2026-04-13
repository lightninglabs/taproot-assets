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
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsInvoiceQuoteExpiryMismatch ensures that we
// don't create asset invoices that outlive their RFQ quotes. If
// the fix is absent, the invoice can be settled with BTC after
// the quote expires and is cleaned up.
//
//nolint:lll
func testCustomChannelsInvoiceQuoteExpiryMismatch(
	_ context.Context, net *itest.IntegratedNetworkHarness,
	t *ccHarnessTest) {

	const quoteExpiry = 15 * time.Second
	oracleAddr := fmt.Sprintf(
		"localhost:%d", port.NextAvailablePort(),
	)
	oracle := itest.NewOracleHarnessWithExpiry(
		oracleAddr, quoteExpiry,
	)
	oracle.Start(t.t)
	t.t.Cleanup(oracle.Stop)

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplateNoOracle)
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--experimental.rfq.priceoracleaddress="+
			"rfqrpc://%s", oracleAddr,
	))
	tapdArgs = append(
		tapdArgs,
		"--experimental.rfq.priceoracletlsinsecure",
	)

	// We use Charlie as the proof courier.
	charliePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, charliePort),
	))

	charlieLndArgs := slices.Clone(lndArgs)
	charlieLndArgs = append(charlieLndArgs, fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", charliePort,
	))
	charlie := net.NewNode("Charlie", charlieLndArgs, tapdArgs)
	dave := net.NewNode("Dave", lndArgs, tapdArgs)
	erin := net.NewNode("Erin", lndArgs, tapdArgs)
	fabia := net.NewNode("Fabia", lndArgs, tapdArgs)
	yara := net.NewNode("Yara", lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{
		charlie, dave, erin, fabia, yara,
	}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Open a normal BTC channel between Erin and Dave.
	t.Logf("Opening normal channel between Erin and Dave...")
	chanPointED := openChannelAndAssert(
		t, net, erin, dave, lntest.OpenChannelParams{
			Amt:         10_000_000,
			SatPerVByte: 5,
		},
	)
	defer closeChannelAndAssert(t, net, erin, chanPointED, false)

	// Mint an asset on Charlie and sync universes.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{
			{
				Asset: ccItestAsset,
			},
		},
	)
	cents := mintedAssets[0]
	assetID := cents.AssetGenesis.AssetId

	t.Logf("Minted %d asset units, syncing universes...",
		cents.Amount)
	syncUniverses(t.t, charlie, dave, erin, fabia, yara)
	t.Logf("Universes synced, distributing assets...")

	const (
		sendAmount        = uint64(400_000)
		daveFundingAmount = uint64(400_000)
		erinFundingAmount = uint64(200_000)
	)
	charlieFundingAmount := cents.Amount - 2*sendAmount

	createTestAssetNetwork(
		t, net, charlie, dave, erin, fabia, yara, charlie,
		cents, sendAmount, charlieFundingAmount,
		daveFundingAmount, erinFundingAmount, 0,
	)

	// Set a price in the oracle for the minted asset.
	var id asset.ID
	copy(id[:], assetID)
	assetPrice := rfqmath.NewBigIntFixedPoint(100_000_00, 2)
	oracle.SetPrice(
		asset.NewSpecifierFromId(id), assetPrice, assetPrice,
	)

	// Create an asset invoice whose expiry exceeds the RFQ
	// quote expiry. This should fail.
	ctxt, cancel := context.WithTimeout(
		context.Background(), wait.DefaultTimeout,
	)
	defer cancel()

	invoiceExpiry := int64((2 * time.Minute).Seconds())
	request := &tchrpc.AddInvoiceRequest{
		AssetAmount: 40,
		PeerPubkey:  charlie.PubKey[:],
		InvoiceRequest: &lnrpc.Invoice{
			Memo:   "asset invoice with long expiry",
			Expiry: invoiceExpiry,
		},
		AssetId: assetID,
	}

	_, err := dave.TaprootAssetChannelsClient.AddInvoice(
		ctxt, request,
	)
	require.Error(t.t, err)
	require.ErrorContains(
		t.t, err, "no quotes with sufficient expiry",
	)
}
