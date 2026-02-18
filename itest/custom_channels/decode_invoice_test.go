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
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsDecodeAssetInvoice tests that we can properly decode an
// asset invoice given a normal Lightning invoice and an asset ID or group key.
//
//nolint:lll
func testCustomChannelsDecodeAssetInvoice(_ context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	// First, we'll set up some information for our custom oracle that we'll
	// use to feed in price information.
	oracleAddr := fmt.Sprintf("localhost:%d", port.NextAvailablePort())
	oracle := itest.NewOracleHarness(oracleAddr)
	oracle.Start(t.t)
	t.t.Cleanup(oracle.Stop)

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplateNoOracle)
	tapdArgs = append(tapdArgs, fmt.Sprintf(
		"--experimental.rfq.priceoracleaddress="+
			"rfqrpc://%s", oracleAddr,
	))
	tapdArgs = append(
		tapdArgs, "--experimental.rfq.priceoracletlsinsecure",
	)

	// We'll just make a single node here, as this doesn't actually rely on
	// a set of active channels.
	alice := net.NewNode("Alice", lndArgs, tapdArgs)

	// Fund Alice so she'll have enough funds to mint the asset.
	fundAllNodes(t.t, net, []*itest.IntegratedNode{alice})

	// Next, we'll make a new asset with a specified decimal display. We'll
	// also make grouped asset as well.
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
		Amount:          1_000_000_000_000,
		DecimalDisplay:  decimalDisplay,
		NewGroupedAsset: true,
	}

	// Mint an asset on Alice and sync universes.
	mintedAssets := itest.MintAssetsConfirmBatch(
		t.t, net.Miner.Client, asTapd(alice),
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

	// We'll assume a price of $100,000.00 USD for a single BTC. This is
	// just the current subjective price our oracle will use. From this BTC
	// price, we'll scale things up to be in the precision of the asset we
	// minted above.
	btcPrice := rfqmath.NewBigIntFixedPoint(
		100_000_00, 2,
	)
	factor := rfqmath.NewBigInt(
		big.NewInt(int64(math.Pow10(decimalDisplay))),
	)
	btcPrice.Coefficient = btcPrice.Coefficient.Mul(factor)
	oracle.SetPrice(asset.NewSpecifierFromId(id), btcPrice, btcPrice)

	// Now we'll make a normal invoice for 1 BTC using Alice.
	ctx := context.Background()
	expirySeconds := 10
	amountSat := 100_000_000
	invoiceResp, err := alice.LightningClient.AddInvoice(
		ctx, &lnrpc.Invoice{
			Value:  int64(amountSat),
			Memo:   "normal invoice",
			Expiry: int64(expirySeconds),
		},
	)
	require.NoError(t.t, err)

	payReq := invoiceResp.PaymentRequest

	// Now that we have our payment request, we'll call into the new decode
	// asset pay req call.
	decodeResp, err := asTapd(alice).DecodeAssetPayReq(
		ctx, &tchrpc.AssetPayReq{
			AssetId:      assetID,
			PayReqString: payReq,
		},
	)
	require.NoError(t.t, err)

	// The decimal display information, genesis, and asset group information
	// should all match.
	require.EqualValues(
		t.t, decimalDisplay, decodeResp.DecimalDisplay.DecimalDisplay,
	)
	require.Equal(t.t, usdAsset.AssetGenesis, decodeResp.GenesisInfo)
	require.Equal(t.t, usdAsset.AssetGroup, decodeResp.AssetGroup)

	// The 1 BTC invoice should map to 100k asset units, with decimal
	// display 6 that's 100 billion asset units.
	const expectedUnits = 100_000_000_000
	require.Equal(t.t, int64(expectedUnits), int64(decodeResp.AssetAmount))

	// We do the same call again, but this time using the group key for the
	// decoding query.
	decodeResp2, err := asTapd(alice).DecodeAssetPayReq(
		ctx, &tchrpc.AssetPayReq{
			GroupKey:     usdAsset.AssetGroup.TweakedGroupKey,
			PayReqString: payReq,
		},
	)
	require.NoError(t.t, err)

	require.Equal(t.t, decodeResp.AssetAmount, decodeResp2.AssetAmount)
	require.Equal(t.t, decodeResp.AssetGroup, decodeResp2.AssetGroup)
	require.Equal(
		t.t, decodeResp.DecimalDisplay, decodeResp2.DecimalDisplay,
	)
}
