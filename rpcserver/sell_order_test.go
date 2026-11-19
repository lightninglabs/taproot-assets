package rpcserver

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestUnmarshalAssetSellOrderSwapAmt checks that the optional swap amount of
// a sell order request is unmarshaled and validated against the max amount.
func TestUnmarshalAssetSellOrderSwapAmt(t *testing.T) {
	t.Parallel()

	newReq := func(swapAmt uint64) *rfqrpc.AddAssetSellOrderRequest {
		return &rfqrpc.AddAssetSellOrderRequest{
			AssetSpecifier: &rfqrpc.AssetSpecifier{
				Id: &rfqrpc.AssetSpecifier_AssetId{
					AssetId: test.RandBytes(32),
				},
			},
			PaymentMaxAmt:  1000,
			PaymentSwapAmt: swapAmt,
		}
	}

	// Unset swap amount.
	order, err := unmarshalAssetSellOrder(newReq(0))
	require.NoError(t, err)
	require.True(t, order.PaymentSwapAmt.IsNone())
	require.Equal(t, lnwire.MilliSatoshi(1000), order.PaymentMaxAmt)

	// Swap amount below the max.
	order, err = unmarshalAssetSellOrder(newReq(900))
	require.NoError(t, err)
	require.Equal(
		t, fn.Some(lnwire.MilliSatoshi(900)), order.PaymentSwapAmt,
	)
	require.Equal(t, lnwire.MilliSatoshi(1000), order.PaymentMaxAmt)

	// Swap amount equal to the max.
	order, err = unmarshalAssetSellOrder(newReq(1000))
	require.NoError(t, err)
	require.Equal(
		t, fn.Some(lnwire.MilliSatoshi(1000)), order.PaymentSwapAmt,
	)

	// Swap amount above the max is rejected.
	_, err = unmarshalAssetSellOrder(newReq(1001))
	require.ErrorContains(
		t, err, "payment swap amount (1001) exceeds payment max "+
			"amount (1000)",
	)
}
