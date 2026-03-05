//go:build itest

package custom_channels

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"slices"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/lntest/node"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsOraclePricing tests that payments through asset channels
// work correctly when using an external RPC price oracle with a buy/sell spread
// instead of the built-in mock oracle.
//
//nolint:lll
func testCustomChannelsOraclePricing(_ context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	usdMetaData := &taprpc.AssetMeta{
		Data: []byte(`{
"description":"this is a USD stablecoin with decimal display of 6"
}`),
		Type: taprpc.AssetMetaType_META_TYPE_JSON,
	}

	const decimalDisplay = 6
	tcAsset := &mintrpc.MintAsset{
		AssetType: taprpc.AssetType_NORMAL,
		Name:      "USD",
		AssetMeta: usdMetaData,
		// We mint 1 million USD with a decimal display of 6, which
		// results in 1 trillion asset units.
		Amount:         1_000_000_000_000,
		DecimalDisplay: decimalDisplay,
	}

	oracleAddr := fmt.Sprintf("localhost:%d", port.NextAvailablePort())
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
		tapdArgs, "--experimental.rfq.priceoracletlsinsecure",
	)

	// We use Charlie as the proof courier. But in order for Charlie to also
	// use itself, we need to define its port upfront.
	charliePort := port.NextAvailablePort()
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--proofcourieraddr=%s://%s",
		proof.UniverseRpcCourierType,
		fmt.Sprintf(node.ListenerFormat, charliePort),
	))

	// The topology we are going for looks like the following:
	//
	// Charlie  --[assets]-->  Dave  --[sats]-->  Erin  --[assets]-->  Fabia
	//                          |
	//                          |
	//                       [assets]
	//                          |
	//                          v
	//                        Yara
	//
	// With [assets] being a custom channel and [sats] being a normal, BTC
	// only channel.
	charlieLndArgs := slices.Clone(lndArgs)
	charlieLndArgs = append(charlieLndArgs, fmt.Sprintf(
		"--rpclisten=127.0.0.1:%d", charliePort,
	))
	charlie := net.NewNode("Charlie", charlieLndArgs, tapdArgs)
	dave := net.NewNode("Dave", lndArgs, tapdArgs)
	erin := net.NewNode("Erin", lndArgs, tapdArgs)
	fabia := net.NewNode("Fabia", lndArgs, tapdArgs)
	yara := net.NewNode("Yara", lndArgs, tapdArgs)

	nodes := []*itest.IntegratedNode{charlie, dave, erin, fabia, yara}
	connectAllNodes(t.t, net, nodes)
	fundAllNodes(t.t, net, nodes)

	// Create the normal channel between Dave and Erin.
	t.Logf("Opening normal channel between Dave and Erin...")
	const btcChannelFundingAmount = 10_000_000
	chanPointDE := openChannelAndAssert(
		t, net, dave, erin, lntest.OpenChannelParams{
			Amt:         btcChannelFundingAmount,
			SatPerVByte: 5,
		},
	)
	defer closeChannelAndAssert(t, net, dave, chanPointDE, false)

	// This is the only public channel, we need everyone to be aware of it.
	assertChannelKnown(t.t, charlie, chanPointDE)
	assertChannelKnown(t.t, fabia, chanPointDE)

	// Mint an asset on Charlie and sync Dave to Charlie as the universe.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(charlie),
		[]*mintrpc.MintAssetRequest{
			{
				Asset: tcAsset,
			},
		},
	)
	usdAsset := mintedAssets[0]
	assetID := usdAsset.AssetGenesis.AssetId

	// Now that we've minted the asset, we can set the price in the oracle.
	var id asset.ID
	copy(id[:], assetID)

	// Let's assume the current USD price for 1 BTC is 66,548.40. We'll
	// take that price and add a 4% spread, 2% on each side (buy/sell) to
	// earn money as the oracle. 2% is 1,330.97, so we'll set the sell
	// price to 65,217.43 and the purchase price to 67,879.37.
	// The following numbers are to help understand the magic numbers below.
	// They're the price in USD/BTC, the price of 1 USD in sats and the
	// expected price in asset units per BTC.
	// 65,217.43 => 1533.332 => 65_217_430_000
	// 66,548.40 => 1502.666 => 66_548_400_000
	// 67,879.37 => 1473.202 => 67_879_370_000
	salePrice := rfqmath.NewBigIntFixedPoint(65_217_43, 2)
	purchasePrice := rfqmath.NewBigIntFixedPoint(67_879_37, 2)

	// We now have the prices defined in USD. But the asset has a decimal
	// display of 6, so we need to multiply them by 10^6.
	factor := rfqmath.NewBigInt(
		big.NewInt(int64(math.Pow10(decimalDisplay))),
	)
	salePrice.Coefficient = salePrice.Coefficient.Mul(factor)
	purchasePrice.Coefficient = purchasePrice.Coefficient.Mul(factor)
	oracle.SetPrice(
		asset.NewSpecifierFromId(id), purchasePrice, salePrice,
	)

	t.Logf("Minted %d USD assets, syncing universes...", usdAsset.Amount)
	syncUniverses(t.t, charlie, dave, erin, fabia, yara)
	t.Logf("Universes synced between all nodes, distributing assets...")

	const (
		sendAmount        = uint64(400_000_000)
		daveFundingAmount = uint64(400_000_000)
		erinFundingAmount = uint64(200_000_000)
	)
	charlieFundingAmount := usdAsset.Amount - 2*sendAmount

	chanPointCD, chanPointDY, chanPointEF := createTestAssetNetwork(
		t, net, charlie, dave, erin, fabia, yara, charlie,
		usdAsset, sendAmount, charlieFundingAmount,
		daveFundingAmount, erinFundingAmount, 0,
	)

	// Before we start sending out payments, let's make sure each node can
	// see the other one in the graph and has all required features.
	require.NoError(t.t, net.AssertNodeKnown(charlie, dave))
	require.NoError(t.t, net.AssertNodeKnown(dave, charlie))
	require.NoError(t.t, net.AssertNodeKnown(dave, yara))
	require.NoError(t.t, net.AssertNodeKnown(yara, dave))
	require.NoError(t.t, net.AssertNodeKnown(erin, fabia))
	require.NoError(t.t, net.AssertNodeKnown(fabia, erin))
	require.NoError(t.t, net.AssertNodeKnown(charlie, erin))

	// We now create an invoice at Fabia for 100 USD, which is 100_000_000
	// asset units with decimal display of 6.
	const fabiaInvoiceAssetAmount = 100_000_000
	invoiceResp := createAssetInvoice(
		t.t, erin, fabia, fabiaInvoiceAssetAmount, assetID,
	)
	ctx := context.Background()
	decodedInvoice, err := fabia.LightningClient.DecodePayReq(
		ctx, &lnrpc.PayReqString{
			PayReq: invoiceResp.PaymentRequest,
		},
	)
	require.NoError(t.t, err)

	// The invoice amount should come out as 100 * 1533.332.
	require.EqualValues(t.t, 153_333_242, decodedInvoice.NumMsat)

	numUnits, rate := payInvoiceWithAssets(
		t.t, charlie, dave, invoiceResp.PaymentRequest, assetID,
	)
	logBalance(t.t, nodes, assetID, "after invoice")

	// The calculated amount Charlie has to pay should come out as
	// 153_333_242 / 1473.202, which is quite exactly 4% more than will
	// arrive at the destination (which is the oracle's configured spread).
	// This is before routing fees though.
	const charlieInvoiceAmount = 104_081_638
	require.EqualValues(t.t, charlieInvoiceAmount, numUnits)

	// The default routing fees are 1ppm + 1msat per hop, and we have 2
	// hops in total.
	charliePaidMSat := addRoutingFee(addRoutingFee(lnwire.MilliSatoshi(
		decodedInvoice.NumMsat,
	)))
	charliePaidAmount := rfqmath.MilliSatoshiToUnits(
		charliePaidMSat, rate,
	).ScaleTo(0).ToUint64()
	assertPaymentHtlcAssets(
		t.t, charlie, invoiceResp.RHash, assetID, nil,
		charliePaidAmount,
	)

	// We now make sure the asset and satoshi channel balances are exactly
	// what we expect them to be.
	var (
		// channelFundingAmount is the hard coded satoshi amount that
		// currently goes into asset channels.
		channelFundingAmount int64 = 100_000

		anchorAmount int64 = 330

		assetHtlcCarryAmount = int64(
			rfqmath.DefaultOnChainHtlcSat,
		)
	)

	// Derive commit fees from the actual channel state instead of relying
	// on hard-coded values. This keeps the assertions stable when the
	// configured feerate floor changes.
	commitFeeCD := fetchChannel(t.t, charlie, chanPointCD).CommitFee
	commitFeeDE := fetchChannel(t.t, dave, chanPointDE).CommitFee
	commitFeeEF := fetchChannel(t.t, erin, chanPointEF).CommitFee

	balancedLocalAmountCD := channelFundingAmount - commitFeeCD -
		2*anchorAmount
	balancedLocalAmountEF := channelFundingAmount - commitFeeEF -
		2*anchorAmount

	// Checking Charlie's sat and asset balances in channel Charlie->Dave.
	assertChannelSatBalance(
		t.t, charlie, chanPointCD,
		balancedLocalAmountCD-assetHtlcCarryAmount, assetHtlcCarryAmount,
	)
	assertChannelAssetBalance(
		t.t, charlie, chanPointCD,
		charlieFundingAmount-charliePaidAmount, charliePaidAmount,
	)

	// Checking Dave's sat and asset balances in channel Charlie->Dave.
	assertChannelSatBalance(
		t.t, dave, chanPointCD,
		assetHtlcCarryAmount, balancedLocalAmountCD-assetHtlcCarryAmount,
	)
	assertChannelAssetBalance(
		t.t, dave, chanPointCD,
		charliePaidAmount, charlieFundingAmount-charliePaidAmount,
	)

	// Checking Dave's sat balance in channel Dave->Erin.
	forwardAmountDave := addRoutingFee(
		lnwire.MilliSatoshi(decodedInvoice.NumMsat),
	).ToSatoshis()
	assertChannelSatBalance(
		t.t, dave, chanPointDE,
		btcChannelFundingAmount-commitFeeDE-2*anchorAmount-
			int64(forwardAmountDave),
		int64(forwardAmountDave),
	)

	// Checking Erin's sat balance in channel Dave->Erin.
	assertChannelSatBalance(
		t.t, erin, chanPointDE,
		int64(forwardAmountDave),
		btcChannelFundingAmount-commitFeeDE-2*anchorAmount-
			int64(forwardAmountDave),
	)

	// Checking Erin's sat and asset balances in channel Erin->Fabia.
	assertChannelSatBalance(
		t.t, erin, chanPointEF,
		balancedLocalAmountEF-assetHtlcCarryAmount, assetHtlcCarryAmount,
	)
	assertChannelAssetBalance(
		t.t, erin, chanPointEF,
		erinFundingAmount-fabiaInvoiceAssetAmount,
		fabiaInvoiceAssetAmount,
	)

	// Checking Fabia's sat and asset balances in channel Erin->Fabia.
	assertChannelSatBalance(
		t.t, fabia, chanPointEF,
		assetHtlcCarryAmount, balancedLocalAmountEF-assetHtlcCarryAmount,
	)
	assertChannelAssetBalance(
		t.t, fabia, chanPointEF,
		fabiaInvoiceAssetAmount,
		erinFundingAmount-fabiaInvoiceAssetAmount,
	)

	t.Logf("Closing Charlie -> Dave channel")
	closeAssetChannelAndAssert(
		t, net, charlie, dave, chanPointCD, [][]byte{assetID}, nil,
		charlie, noOpCoOpCloseBalanceCheck,
	)

	t.Logf("Closing Dave -> Yara channel")
	closeAssetChannelAndAssert(
		t, net, dave, yara, chanPointDY, [][]byte{assetID}, nil,
		charlie, noOpCoOpCloseBalanceCheck,
	)

	t.Logf("Closing Erin -> Fabia channel")
	closeAssetChannelAndAssert(
		t, net, erin, fabia, chanPointEF, [][]byte{assetID}, nil,
		charlie, noOpCoOpCloseBalanceCheck,
	)
}
