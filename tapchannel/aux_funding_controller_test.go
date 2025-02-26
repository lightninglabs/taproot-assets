package tapchannel

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc/universerpc"
	"github.com/lightningnetwork/lnd/lntest/port"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type mockUniverseServer struct {
	universerpc.UnimplementedUniverseServer
}

// GetInfo is a mock implementation of the GetInfo RPC.
func (m *mockUniverseServer) Info(context.Context,
	*universerpc.InfoRequest) (*universerpc.InfoResponse, error) {

	return &universerpc.InfoResponse{}, nil
}

func dummyURL(t *testing.T, protocol, addr string) *url.URL {
	urlString := fmt.Sprintf("%s://%s", protocol, addr)
	proofCourierAddr, err := proof.ParseCourierAddress(urlString)
	require.NoError(t, err)

	return proofCourierAddr
}

func TestValidateLocalProofCourier(t *testing.T) {
	serverOpts := []grpc.ServerOption{
		grpc.Creds(insecure.NewCredentials()),
	}
	grpcServer := grpc.NewServer(serverOpts...)

	server := mockUniverseServer{}
	universerpc.RegisterUniverseServer(grpcServer, &server)

	// We also grab a port that is free to listen on for our negative test.
	// Since we know the port is free, and we don't listen on it, we expect
	// the connection to fail.
	noConnectPort := port.NextAvailablePort()
	noConnectAddr := fmt.Sprintf(test.ListenAddrTemplate, noConnectPort)

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
			courierAddr: dummyURL(
				t, proof.UniverseRpcCourierType, mockServerAddr,
			),
		},
		{
			name: "valid universe rpc courier, but can't connect",
			courierAddr: dummyURL(
				t, proof.UniverseRpcCourierType, noConnectAddr,
			),
			expectErr: "unable to connect to courier service",
		},
		{
			name: "invalid courier type",
			courierAddr: dummyURL(
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
