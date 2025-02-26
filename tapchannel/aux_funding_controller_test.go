package tapchannel

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

func dummyURL(t *testing.T, protocol string) *url.URL {
	urlString := fmt.Sprintf("%s://localhost:1234", protocol)
	proofCourierAddr, err := proof.ParseCourierAddress(urlString)
	require.NoError(t, err)

	return proofCourierAddr
}

func TestValidateLocalProofCourier(t *testing.T) {
	tests := []struct {
		name        string
		courierAddr *url.URL
		expectErr   string
	}{
		{
			name:        "valid universe rpc courier",
			courierAddr: dummyURL(t, proof.UniverseRpcCourierType),
		},
		{
			name:        "invalid courier type",
			courierAddr: dummyURL(t, proof.HashmailCourierType),
			expectErr: "unsupported proof courier type " +
				"'hashmail'",
		},
		{
			name:      "nil courier address",
			expectErr: "no proof courier configured",
		},
		{
			name:        "empty courier type",
			courierAddr: &url.URL{},
			expectErr:   "unsupported proof courier type ''",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &FundingController{
				cfg: FundingControllerCfg{
					DefaultCourierAddr: tt.courierAddr,
				},
			}

			err := fc.validateLocalProofCourier()
			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)

				return
			}

			require.NoError(t, err)
		})
	}
}
