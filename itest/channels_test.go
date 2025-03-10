package itest

import (
	"context"

	"github.com/lightninglabs/taproot-assets/rfqmsg"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/record"
	"github.com/stretchr/testify/require"
)

var (
	dummyByteArr = [32]byte{0x01, 0x02, 0x03, 0x04}
)

// testChannelRPCs tests that we can call all Taproot Asset Channel related
// RPCs and get the correct error message back (as we can't really test the
// actual functionality without running within litd). This at least makes sure
// we've set up everything correctly in terms of macaroons and permissions.
func testChannelRPCs(t *harnessTest) {
	ctx := context.Background()

	// The EncodeCustomRecords RPC is available, as it only does static
	// encoding.
	encodeReq := &tchrpc.EncodeCustomRecordsRequest_RouterSendPayment{
		RouterSendPayment: &tchrpc.RouterSendPaymentData{
			RfqId: dummyByteArr[:],
		},
	}
	encodeResp, err := t.tapd.EncodeCustomRecords(
		ctx, &tchrpc.EncodeCustomRecordsRequest{
			Input: encodeReq,
		},
	)
	require.NoError(t.t, err)
	require.Len(t.t, encodeResp.CustomRecords, 1)

	var rfqIdType rfqmsg.HtlcRfqIDType
	rfqIdTlvTypeNumber := uint64(rfqIdType.TypeVal())
	require.Len(t.t, encodeResp.CustomRecords[rfqIdTlvTypeNumber], 32)

	// All the following calls can't go fully through, and we'll encounter
	// an error at some point.
	_, err = t.tapd.FundChannel(ctx, &tchrpc.FundChannelRequest{})
	require.ErrorContains(t.t, err, "only available when running inside")

	// Try the keysend path first, which should go all the way through to
	// lnd, where it should fail because we didn't set a destination public
	// key.
	stream, err := t.tapd.SendPayment(ctx, &tchrpc.SendPaymentRequest{
		AssetAmount: 123,
		AssetId:     dummyByteArr[:],
		PaymentRequest: &routerrpc.SendPaymentRequest{
			DestCustomRecords: map[uint64][]byte{
				record.KeySendType: dummyByteArr[:],
			},
		},
	})
	require.NoError(t.t, err)

	_, err = stream.Recv()
	require.ErrorContains(t.t, err, "invalid vertex length of 0, want 33")

	// Now let's also try the invoice path, which should fail because we
	// don't have any asset channels with peers that we could ask for a
	// quote.
	invoiceResp := t.tapd.cfg.LndNode.RPC.AddInvoice(&lnrpc.Invoice{
		AmtPaidSat: 1234,
	})
	stream, err = t.tapd.SendPayment(ctx, &tchrpc.SendPaymentRequest{
		AssetId: dummyByteArr[:],
		PaymentRequest: &routerrpc.SendPaymentRequest{
			PaymentRequest: invoiceResp.PaymentRequest,
		},
	})
	require.NoError(t.t, err)

	_, err = stream.Recv()
	require.ErrorContains(t.t, err, "no asset channel balance found")

	// We can't add an invoice either, because we have no peers to do RFQ
	// negotiation with.
	_, err = t.tapd.AddInvoice(ctx, &tchrpc.AddInvoiceRequest{
		AssetAmount: 123,
		AssetId:     dummyByteArr[:],
		InvoiceRequest: &lnrpc.Invoice{
			Private: false,
		},
	})
	require.ErrorContains(t.t, err, "no asset channel balance found")
}
