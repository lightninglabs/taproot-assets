package rpcserver

import (
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

// TestPaymentSellOrderRequestAllowsPartialFill verifies that internally
// acquired payment quotes do not inherit the public RPC's full-fill default.
// A multi-RFQ payment needs each peer to accept the portion backed by its own
// asset channel.
func TestPaymentSellOrderRequestAllowsPartialFill(t *testing.T) {
	t.Parallel()

	specifier := marshalAssetSpecifier(
		asset.NewSpecifierFromId(asset.ID{0x01}),
	)
	peer := route.Vertex{0x02}
	paymentMax := lnwire.MilliSatoshi(3_000_000)

	request := newPaymentSellOrderRequest(
		&specifier, paymentMax, time.Now().Add(time.Hour), &peer,
		"metadata",
	)
	require.NotNil(t, request.PaymentMinAmt)
	require.Zero(t, *request.PaymentMinAmt)

	order, err := unmarshalAssetSellOrder(request)
	require.NoError(t, err)
	require.True(t, order.PaymentMinAmt.IsNone())
	require.Equal(t, paymentMax, order.PaymentMaxAmt)
}
