package rpcserver

// validation_test.go contains unit tests for RPC input validation.
// These tests verify that invalid input returns codes.InvalidArgument.
//
// Happy-path testing (valid input -> successful response) is covered by
// integration tests in itest/ which exercise complete request flows.

import (
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/proof"
	wrpc "github.com/lightninglabs/taproot-assets/taprpc/assetwalletrpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// assertCode checks that the error is a gRPC status error with the expected
// status code.
func assertCode(t *testing.T, err error, wantCode codes.Code) {
	t.Helper()

	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status error")
	require.Equal(t, wantCode, st.Code())
}

// TestTransitionProofOption tests the mapping from RPC proof versions to
// internal proof generation options.
func TestTransitionProofOption(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		rpcVersion  wrpc.TransitionProofVersion
		wantVersion proof.TransitionVersion
		wantErr     bool
	}{
		{
			name:        "default v0",
			rpcVersion:  wrpc.TransitionProofVersion(0),
			wantVersion: proof.TransitionV0,
		},
		{
			name:        "v1",
			rpcVersion:  wrpc.TransitionProofVersion(1),
			wantVersion: proof.TransitionV1,
		},
		{
			name:       "unsupported",
			rpcVersion: wrpc.TransitionProofVersion(2),
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			option, err := transitionProofOption(tc.rpcVersion)
			if tc.wantErr {
				assertCode(t, err, codes.InvalidArgument)
				return
			}

			require.NoError(t, err)

			cfg := proof.DefaultGenConfig()
			option(&cfg)
			require.Equal(t, tc.wantVersion, cfg.TransitionVersion)
		})
	}
}

// TestCommitVirtualPsbtsProofVersionValidation tests that unsupported proof
// versions are rejected before the request is decoded or any funding is
// attempted.
func TestCommitVirtualPsbtsProofVersionValidation(t *testing.T) {
	t.Parallel()

	server := newTestServer()
	_, err := server.CommitVirtualPsbts(
		context.Background(), &wrpc.CommitVirtualPsbtsRequest{
			VirtualPsbts:           [][]byte{{0x01}},
			TransitionProofVersion: wrpc.TransitionProofVersion(2),
		},
	)
	assertCode(t, err, codes.InvalidArgument)
}
