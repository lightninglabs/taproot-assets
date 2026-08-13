package lndservices

import (
	"errors"
	"testing"

	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDefinitivePublishError(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name       string
		err        error
		definitive bool
	}{
		{
			name: "spent input",
			err: status.Error(
				codes.Unknown, lnwallet.ErrDoubleSpend.Error(),
			),
			definitive: true,
		},
		{
			name: "mempool fee with detail",
			err: status.Error(
				codes.Unknown, lnwallet.ErrMempoolFee.Error()+
					": min relay fee not met",
			),
			definitive: true,
		},
		{
			name:       "generic application error",
			err:        status.Error(codes.Unknown, "backend failure"),
			definitive: false,
		},
		{
			name: "transport failure",
			err: status.Error(
				codes.Unavailable, "connection closed",
			),
			definitive: false,
		},
		{
			name:       "plain error",
			err:        errors.New("local failure"),
			definitive: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(
				t, testCase.definitive,
				isDefinitivePublishError(testCase.err),
			)
		})
	}
}
