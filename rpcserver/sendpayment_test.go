package rpcserver

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	tchrpc "github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/record"
	"github.com/stretchr/testify/require"
)

// TestValidateSendPaymentRateLimit checks that asset_rate_limit is
// rejected together with an RFQ ID, a keysend record or first-hop
// custom records, and accepted otherwise.
func TestValidateSendPaymentRateLimit(t *testing.T) {
	t.Parallel()

	limit := &rfqrpc.FixedPoint{Coefficient: "100", Scale: 0}
	rfqID := make([]byte, 32)
	keysend := map[uint64][]byte{record.KeySendType: make([]byte, 32)}
	firstHop := map[uint64][]byte{65536: {0x01}}

	tests := []struct {
		name    string
		req     *tchrpc.SendPaymentRequest
		wantErr string
	}{
		{
			name: "invoice payment with rate limit",
			req: &tchrpc.SendPaymentRequest{
				PaymentRequest: &routerrpc.SendPaymentRequest{
					PaymentRequest: "lnbc1",
				},
				AssetRateLimit: limit,
			},
		},
		{
			name: "rfq id without rate limit",
			req: &tchrpc.SendPaymentRequest{
				PaymentRequest: &routerrpc.SendPaymentRequest{
					PaymentRequest: "lnbc1",
				},
				RfqId: rfqID,
			},
		},
		{
			name: "rfq id with rate limit",
			req: &tchrpc.SendPaymentRequest{
				PaymentRequest: &routerrpc.SendPaymentRequest{
					PaymentRequest: "lnbc1",
				},
				RfqId:          rfqID,
				AssetRateLimit: limit,
			},
			wantErr: "cannot be used with rfq_id",
		},
		{
			name: "keysend with rate limit",
			req: &tchrpc.SendPaymentRequest{
				PaymentRequest: &routerrpc.SendPaymentRequest{
					DestCustomRecords: keysend,
				},
				AssetRateLimit: limit,
			},
			wantErr: "cannot be used with keysend payments",
		},
		{
			name: "first-hop records with rate limit",
			req: &tchrpc.SendPaymentRequest{
				PaymentRequest: &routerrpc.SendPaymentRequest{
					PaymentRequest:        "lnbc1",
					FirstHopCustomRecords: firstHop,
				},
				AssetRateLimit: limit,
			},
			wantErr: "cannot be used with first-hop custom records",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateSendPaymentRateLimit(tc.req)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}
