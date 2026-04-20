//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"slices"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsLimitConstraints verifies that RFQ limit-order
// constraints (asset_rate_limit, payment_min_amt) work correctly in
// the context of real asset channels. It negotiates a sell quote with
// satisfied constraints, then sends a payment using that quote.
//
//nolint:lll
func testCustomChannelsLimitConstraints(_ context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	usdMetaData := &taprpc.AssetMeta{
		Data: []byte(`{
"description":"USD stablecoin for limit constraint test"
}`),
		Type: taprpc.AssetMetaType_META_TYPE_JSON,
	}

	const decimalDisplay = 6
	tcAsset := &mintrpc.MintAsset{
		AssetType:      taprpc.AssetType_NORMAL,
		Name:           "USD-limits",
		AssetMeta:      usdMetaData,
		Amount:         1_000_000_000_000,
		DecimalDisplay: decimalDisplay,
	}

	oracleAddr := fmt.Sprintf(
		"localhost:%d", port.NextAvailablePort(),
	)
	oracle := itest.NewOracleHarness(oracleAddr)
	oracle.Start(t.t)
	t.t.Cleanup(oracle.Stop)

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplateNoOracle)
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--experimental.rfq.priceoracleaddress=rfqrpc://%s",
		oracleAddr,
	))
	tapdArgs = append(
		tapdArgs,
		"--experimental.rfq.priceoracletlsinsecure",
	)

	charliePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, charliePort),
	))

	// Topology: Charlie --[assets]--> Dave --[sats]--> Erin
	charlieLndArgs := slices.Clone(lndArgs)
	charlieLndArgs = append(charlieLndArgs, fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", charliePort,
	))
	charlie := net.NewNode("Charlie", charlieLndArgs, tapdArgs)
	dave := net.NewNode("Dave", lndArgs, tapdArgs)
	erin := net.NewNode("Erin", lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{charlie, dave, erin}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Open a normal BTC channel between Dave and Erin.
	const btcChannelFundingAmount = 10_000_000
	chanPointDE := openChannelAndAssert(
		t, net, dave, erin, lntest.OpenChannelParams{
			Amt:         btcChannelFundingAmount,
			SatPerVByte: 5,
		},
	)
	defer closeChannelAndAssert(t, net, dave, chanPointDE, false)

	assertChannelKnown(t.t, charlie, chanPointDE)

	// Mint on Charlie.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{
			{Asset: tcAsset},
		},
	)
	usdAsset := mintedAssets[0]
	assetID := usdAsset.AssetGenesis.AssetId

	var id asset.ID
	copy(id[:], assetID)

	// Oracle price: ~66,548.40 USD/BTC with decimal display 6.
	salePrice := rfqmath.NewBigIntFixedPoint(65_217_43, 2)
	purchasePrice := rfqmath.NewBigIntFixedPoint(67_879_37, 2)
	factor := rfqmath.NewBigInt(
		big.NewInt(int64(math.Pow10(decimalDisplay))),
	)
	salePrice.Coefficient = salePrice.Coefficient.Mul(factor)
	purchasePrice.Coefficient = purchasePrice.Coefficient.Mul(
		factor,
	)
	oracle.SetPrice(
		asset.NewSpecifierFromId(id), purchasePrice, salePrice,
	)

	t.Logf("Syncing universes...")
	syncUniverses(t.t, charlie, dave, erin)

	// Send assets to Dave so he has a balance.
	const sendAmount = uint64(400_000_000)
	charlieFundingAmount := usdAsset.Amount - sendAmount

	ctxb := context.Background()
	daveAddr, err := dave.NewAddr(ctxb, &taprpc.NewAddrRequest{
		Amt:     sendAmount,
		AssetId: assetID,
		ProofCourierAddr: fmt.Sprintf(
			"%s://%s", proof.UniverseRpcCourierType,
			charlie.RPCAddr(),
		),
	})
	require.NoError(t.t, err)

	sendResp, err := charlie.SendAsset(
		ctxb, &taprpc.SendAssetRequest{
			TapAddrs: []string{daveAddr.Encoded},
		},
	)
	require.NoError(t.t, err)
	itest.ConfirmAndAssertOutboundTransfer(
		t.t, net.Miner, asTapd(charlie), sendResp,
		assetID,
		[]uint64{usdAsset.Amount - sendAmount, sendAmount},
		0, 1,
	)
	itest.AssertNonInteractiveRecvComplete(t.t, asTapd(dave), 1)

	// Open asset channel Charlie → Dave.
	t.Logf("Opening asset channel Charlie → Dave...")
	net.EnsureConnected(t.t, charlie, dave)
	fundResp, err := charlie.FundChannel(
		ctxb, &tchrpc.FundChannelRequest{
			AssetAmount:        charlieFundingAmount,
			AssetId:            assetID,
			PeerPubkey:         dave.PubKey[:],
			FeeRateSatPerVbyte: 5,
			PushSat:            DefaultPushSat,
		},
	)
	require.NoError(t.t, err)
	t.Logf("Funded channel: %v", fundResp)

	mineBlocks(t, net, 6, 1)

	chanPointCD := &lnrpc.ChannelPoint{
		OutputIndex: uint32(fundResp.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: fundResp.Txid,
		},
	}

	// Wait for all nodes to see each other in the graph,
	// ensuring the full route Charlie→Dave→Erin is available
	// before we attempt any payments.
	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))
	require.NoError(t.t, net.AssertNodeKnown(charlie, erin))
	require.NoError(t.t, net.AssertNodeKnown(dave, erin))
	require.NoError(t.t, net.AssertNodeKnown(erin, dave))

	logBalance(t.t, nodes, assetID, "after channel open")

	// -----------------------------------------------------------------
	// Negotiate a sell order from Charlie with constraints.
	// Rate limit is set well above the oracle rate (ceiling for
	// sell), so the constraint is satisfied.
	// -----------------------------------------------------------------
	t.Logf("Negotiating sell order with constraints...")

	inOneHour := time.Now().Add(time.Hour)
	sellResp, err := asTapd(charlie).RfqClient.AddAssetSellOrder(
		ctxb, &rfqrpc.AddAssetSellOrderRequest{
			AssetSpecifier: &rfqrpc.AssetSpecifier{
				Id: &rfqrpc.AssetSpecifier_AssetId{
					AssetId: assetID,
				},
			},
			PaymentMaxAmt: 180_000_000,
			AssetRateLimit: &rfqrpc.FixedPoint{
				// Ceiling well above oracle rate.
				Coefficient: "100000000000000",
				Scale:       2,
			},
			Expiry:         uint64(inOneHour.Unix()),
			PeerPubKey:     dave.PubKey[:],
			TimeoutSeconds: 10,
		},
	)
	require.NoError(t.t, err, "sell order with constraints")

	accepted := sellResp.GetAcceptedQuote()
	require.NotNil(t.t, accepted, "expected accepted sell quote")
	t.Logf("Sell quote accepted: scid=%d", accepted.Scid)

	// -----------------------------------------------------------------
	// Pay an invoice using the pre-negotiated quote.
	// -----------------------------------------------------------------
	t.Logf("Paying invoice with constrained quote...")

	// Erin has no asset channel, so we create a regular BTC
	// invoice. Charlie pays it with assets via the sell quote.
	const invoiceMsat = 100_000_000 // 100K sats
	invoiceResp, err := erin.LightningClient.AddInvoice(
		ctxb, &lnrpc.Invoice{
			ValueMsat: invoiceMsat,
		},
	)
	require.NoError(t.t, err)

	var quoteID rfqmsg.ID
	copy(quoteID[:], accepted.Id)

	numUnits, _ := payInvoiceWithAssets(
		t.t, charlie, dave,
		invoiceResp.PaymentRequest,
		assetID, withRFQ(quoteID),
	)
	require.Greater(t.t, numUnits, uint64(0))

	logBalance(t.t, nodes, assetID, "after payment")
	t.Logf("Payment completed: %d asset units sent", numUnits)

	// -----------------------------------------------------------------
	// Negotiate a sell order from Charlie with FOK policy.
	// Rate limit ceiling is generous and the payment max is
	// large enough that FOK conversion yields non-zero units.
	// -----------------------------------------------------------------
	t.Logf("Negotiating sell order with FOK policy...")

	sellRespFOK, err := asTapd(charlie).RfqClient.AddAssetSellOrder(
		ctxb, &rfqrpc.AddAssetSellOrderRequest{
			AssetSpecifier: &rfqrpc.AssetSpecifier{
				Id: &rfqrpc.AssetSpecifier_AssetId{
					AssetId: assetID,
				},
			},
			PaymentMaxAmt: 180_000_000,
			AssetRateLimit: &rfqrpc.FixedPoint{
				Coefficient: "100000000000000",
				Scale:       2,
			},
			ExecutionPolicy: rfqrpc.ExecutionPolicy_EXECUTION_POLICY_FOK,
			Expiry:          uint64(inOneHour.Unix()),
			PeerPubKey:      dave.PubKey[:],
			TimeoutSeconds:  10,
		},
	)
	require.NoError(t.t, err, "sell order with FOK policy")

	acceptedFOK := sellRespFOK.GetAcceptedQuote()
	require.NotNil(
		t.t, acceptedFOK, "expected accepted FOK sell quote",
	)
	t.Logf("FOK sell quote accepted: scid=%d", acceptedFOK.Scid)

	// Pay using the FOK quote with a regular BTC invoice.
	invoiceRespFOK, err := erin.LightningClient.AddInvoice(
		ctxb, &lnrpc.Invoice{
			ValueMsat: invoiceMsat,
		},
	)
	require.NoError(t.t, err)

	var quoteIDFOK rfqmsg.ID
	copy(quoteIDFOK[:], acceptedFOK.Id)

	numUnitsFOK, _ := payInvoiceWithAssets(
		t.t, charlie, dave,
		invoiceRespFOK.PaymentRequest,
		assetID, withRFQ(quoteIDFOK),
	)
	require.Greater(t.t, numUnitsFOK, uint64(0))

	logBalance(t.t, nodes, assetID, "after FOK payment")
	t.Logf("FOK payment completed: %d units sent", numUnitsFOK)

	// Close channels.
	closeAssetChannelAndAssert(
		t, net, charlie, dave, chanPointCD,
		[][]byte{assetID}, nil, charlie,
		noOpCoOpCloseBalanceCheck,
	)
}
