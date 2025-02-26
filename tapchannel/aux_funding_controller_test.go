package tapchannel

import (
	"net/url"
	"testing"

	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

// TestValidateLocalProofCourier tests that the local proof courier is
// validated correctly.
func TestValidateLocalProofCourier(t *testing.T) {
	tests := []struct {
		name        string
		courierAddr *url.URL
		expectErr   string
	}{
		{
			name: "valid universe rpc courier",
			courierAddr: proof.MockCourierURL(
				t, proof.UniverseRpcCourierType, ":1234",
			),
		},
		{
			name: "invalid courier type",
			courierAddr: proof.MockCourierURL(
				t, proof.HashmailCourierType, ":1234",
			),
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
