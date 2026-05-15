package rpcserver

import (
	"math"
	"testing"

	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

func TestParseSendFeeRate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		req            *taprpc.SendAssetRequest
		expectedFee    chainfee.SatPerKWeight
		expectedErrStr string
	}{
		{
			name: "legacy fee rate",
			req: &taprpc.SendAssetRequest{
				FeeRate: 1234,
			},
			expectedFee: 1234,
		},
		{
			name: "sat per vbyte preferred",
			req: &taprpc.SendAssetRequest{
				FeeRate:     1234,
				SatPerVbyte: 5,
			},
			expectedFee: chainfee.SatPerVByte(5).FeePerKWeight(),
		},
		{
			name: "sat per vbyte too large",
			req: &taprpc.SendAssetRequest{
				SatPerVbyte: uint64(math.MaxInt64/1000) + 1,
			},
			expectedErrStr: "manual fee rate exceeds maximum",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			feeRate, err := parseSendFeeRate(testCase.req)
			if testCase.expectedErrStr != "" {
				require.ErrorContains(
					t,
					err,
					testCase.expectedErrStr,
				)
				return
			}

			require.NoError(t, err)
			require.Equal(t, testCase.expectedFee, feeRate)
		})
	}
}
