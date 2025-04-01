package tapchannel

import (
	"context"
	"net/url"
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestValidateLocalProofCourier tests that the local proof courier is
// validated correctly.
func TestValidateLocalProofCourier(t *testing.T) {
	serverOpts := []grpc.ServerOption{
		grpc.Creds(insecure.NewCredentials()),
	}
	grpcServer := grpc.NewServer(serverOpts...)

	server := proof.MockUniverseServer{}
	universerpc.RegisterUniverseServer(grpcServer, &server)

	mockServerAddr, cleanup, err := test.StartMockGRPCServer(
		t, grpcServer, true,
	)
	require.NoError(t, err)
	t.Cleanup(cleanup)

	tests := []struct {
		name        string
		courierAddr *url.URL
		expectErr   string
	}{
		{
			name: "valid universe rpc courier",
			courierAddr: proof.MockCourierURL(
				t, proof.UniverseRpcCourierType, mockServerAddr,
			),
		},
		{
			name: "invalid courier type",
			courierAddr: proof.MockCourierURL(
				t, proof.HashmailCourierType, mockServerAddr,
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

			// We use a short timeout here, since we don't want to
			// wait for the full default timeout of the funding
			// controller
			ctxb := context.Background()
			ctxb, cancel := context.WithTimeout(
				ctxb, test.StartupWaitTime*2,
			)
			defer cancel()

			err := fc.validateLocalProofCourier(ctxb)
			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)

				return
			}

			require.NoError(t, err)
		})
	}
}
