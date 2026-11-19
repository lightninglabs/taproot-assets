//go:build itest

package custom_channels

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"github.com/lightninglabs/taproot-assets/itest"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/routing"
	"github.com/stretchr/testify/require"
)

// testCustomChannelsHoldInvoiceCLTV checks that asset hold invoices preserve
// the caller's settlement deadline independently of their short RFQ lifetime.
func testCustomChannelsHoldInvoiceCLTV(ctx context.Context,
	net *itest.IntegratedNetworkHarness, t *ccHarnessTest) {

	lndArgs := slices.Clone(lndArgsTemplate)
	tapdArgs := slices.Clone(tapdArgsTemplate)
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

	funding, err := alice.FundChannel(ctx, &tchrpc.FundChannelRequest{
		AssetAmount:        fundingAmount,
		AssetId:            assetID,
		PeerPubkey:         bob.PubKey[:],
		FeeRateSatPerVbyte: 5,
	})
	require.NoError(t.t, err)
	channelPoint := &lnrpc.ChannelPoint{
		OutputIndex: uint32(funding.OutputIndex),
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
			FundingTxidStr: funding.Txid,
		},
	}
	mineBlocks(t, net, 6, 1)
	require.NoError(t.t, net.AssertNodeKnown(alice, bob))
	require.NoError(t.t, net.AssertNodeKnown(bob, alice))
	assertPeerPolicyKnown(t.t, bob, alice, channelPoint)

	// A normal invoice gives us the node's configured default, allowing the
	// zero-value case to verify the same behavior without hard-coding it.
	ordinary, err := bob.LightningClient.AddInvoice(ctx, &lnrpc.Invoice{
		Value: 1000,
	})
	require.NoError(t.t, err)
	defaultInvoice, err := bob.DecodePayReq(ctx, &lnrpc.PayReqString{
		PayReq: ordinary.PaymentRequest,
	})
	require.NoError(t.t, err)

	testCases := []struct {
		name       string
		cltv       uint64
		expected   int64
		errMessage string
	}{
		{
			name:     "default",
			expected: defaultInvoice.CltvExpiry,
		},
		{
			name:     "custom",
			cltv:     288,
			expected: 288,
		},
		{
			name:       "below minimum",
			cltv:       1,
			errMessage: "must be greater than minimum",
		},
		{
			name:       "above maximum",
			cltv:       routing.MaxCLTVDelta + 1,
			errMessage: "is too large",
		},
	}
	for _, tc := range testCases {
		t.t.Run(tc.name, func(t *testing.T) {
			var preimage lntypes.Preimage
			_, err := rand.Read(preimage[:])
			require.NoError(t, err)
			hash := preimage.Hash()

			client := bob.TaprootAssetChannelsClient
			response, err := client.AddInvoice(
				ctx, &tchrpc.AddInvoiceRequest{
					AssetId:     assetID,
					AssetAmount: 1000,
					PeerPubkey:  alice.PubKey[:],
					InvoiceRequest: &lnrpc.Invoice{
						Expiry:     60,
						CltvExpiry: tc.cltv,
					},
					HodlInvoice: &tchrpc.HodlInvoice{
						PaymentHash: hash[:],
					},
				},
			)
			if tc.errMessage != "" {
				require.ErrorContains(t, err, tc.errMessage)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, response.AcceptedBuyQuote)
			paymentRequest := response.InvoiceResult.PaymentRequest
			decoded, err := bob.DecodePayReq(ctx,
				&lnrpc.PayReqString{
					PayReq: paymentRequest,
				})
			require.NoError(t, err)
			require.Equal(t, tc.expected, decoded.CltvExpiry)
			require.EqualValues(t, 60, decoded.Expiry)
			require.Equal(t, hex.EncodeToString(hash[:]),
				decoded.PaymentHash)

			_, err = bob.CancelInvoice(ctx,
				&invoicesrpc.CancelInvoiceMsg{
					PaymentHash: hash[:],
				})
			require.NoError(t, err)
		})
	}
}
