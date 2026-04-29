package rpcserver

// validation_test.go contains unit tests for RPC input validation.
// These tests verify that invalid input returns codes.InvalidArgument
// (not codes.Unknown).
//
// Happy-path testing (valid input -> successful response) is covered by
// integration tests in itest/ which exercise complete request flows.

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapconfig"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// assertInvalidArgument checks that the error is a gRPC status error with
// code InvalidArgument and that the message contains the expected substring.
func assertInvalidArgument(t *testing.T, err error, wantMsgContains string) {
	t.Helper()

	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status error")
	require.Equal(t, codes.InvalidArgument, st.Code(),
		"expected InvalidArgument, got %v", st.Code())
	require.Contains(t, st.Message(), wantMsgContains)
}

// newTestServer creates a minimal RPCServer for validation testing.
func newTestServer() *RPCServer {
	return &RPCServer{
		cfg: &tapconfig.Config{
			ChainParams: address.MainNetTap,
		},
	}
}

// TestDecodeAddrValidation tests that DecodeAddr returns InvalidArgument
// for validation errors.
func TestDecodeAddrValidation(t *testing.T) {
	t.Parallel()

	server := newTestServer()

	tests := []struct {
		name    string
		req     *taprpc.DecodeAddrRequest
		wantMsg string
	}{
		{
			name:    "empty address",
			req:     &taprpc.DecodeAddrRequest{Addr: ""},
			wantMsg: "must specify an addr",
		},
		{
			name: "invalid address format",
			req: &taprpc.DecodeAddrRequest{
				Addr: "not-a-valid-addr",
			},
			wantMsg: "unable to decode addr",
		},
		{
			name: "wrong network prefix",
			req: &taprpc.DecodeAddrRequest{
				// Testnet address (taptb1) on mainnet config
				// (expects tapbc1). DecodeAddress compares the
				// HRP against net.TapHRP and returns
				// ErrMismatchedHRP when they don't match.
				// See address/address.go ErrMismatchedHRP
				Addr: "taptb1qqqszqspqqqqqqqqqqqqqqqqqqqq" +
					"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpqqq" +
					"sqqspqqqqp8hlm7nfnydq5wvs6j5mczq8tf" +
					"vemhy7082",
			},
			wantMsg: "unable to decode addr",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := server.DecodeAddr(
				context.Background(), tc.req,
			)
			assertInvalidArgument(t, err, tc.wantMsg)
		})
	}
}

// TestDecodeProofValidation tests that DecodeProof returns InvalidArgument
// for validation errors.
//
// Note: DecodeProof's validation is inherent to decoding - malformed proofs
// correctly return InvalidArgument. Testing valid input requires a real proof
// fixture; this is covered by integration tests (e.g., itest/proof_test.go).
func TestDecodeProofValidation(t *testing.T) {
	t.Parallel()

	server := newTestServer()

	// Create invalid proof bytes that don't match either magic prefix.
	invalidMagicBytes := []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03}

	// Create bytes with single proof magic but invalid content.
	invalidSingleProof := append(
		proof.PrefixMagicBytes[:],
		[]byte{0x00, 0x01, 0x02, 0x03}...,
	)

	// Create bytes with file magic but invalid content.
	invalidFileProof := append(
		proof.FilePrefixMagicBytes[:],
		[]byte{0x00, 0x01, 0x02, 0x03}...,
	)

	tests := []struct {
		name    string
		req     *taprpc.DecodeProofRequest
		wantMsg string
	}{
		{
			// Covers both nil and empty raw proof
			name:    "empty proof",
			req:     &taprpc.DecodeProofRequest{RawProof: nil},
			wantMsg: "could not identify decoding format",
		},
		{
			name: "invalid magic bytes",
			req: &taprpc.DecodeProofRequest{
				RawProof: invalidMagicBytes,
			},
			wantMsg: "could not identify decoding format",
		},
		{
			name: "invalid single proof content",
			req: &taprpc.DecodeProofRequest{
				RawProof: invalidSingleProof,
			},
			wantMsg: "unable to decode proof",
		},
		{
			name: "invalid file proof content",
			req: &taprpc.DecodeProofRequest{
				RawProof: invalidFileProof,
			},
			wantMsg: "unable to decode proof file",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := server.DecodeProof(
				context.Background(), tc.req,
			)
			assertInvalidArgument(t, err, tc.wantMsg)
		})
	}
}

// TestExportProofValidation tests that ExportProof returns InvalidArgument
// for validation errors.
func TestExportProofValidation(t *testing.T) {
	t.Parallel()

	server := newTestServer()

	// Generate a valid compressed public key for testing.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	validScriptKey := privKey.PubKey().SerializeCompressed()

	tests := []struct {
		name    string
		req     *taprpc.ExportProofRequest
		wantMsg string
	}{
		{
			name:    "empty script key",
			req:     &taprpc.ExportProofRequest{ScriptKey: nil},
			wantMsg: "a valid script key must be specified",
		},
		{
			name: "invalid script key - wrong length",
			req: &taprpc.ExportProofRequest{
				ScriptKey: []byte{0x01, 0x02, 0x03},
			},
			wantMsg: "invalid script key",
		},
		{
			name: "invalid script key - bad prefix",
			req: &taprpc.ExportProofRequest{
				ScriptKey: make([]byte, 33), // all zeros
			},
			wantMsg: "invalid script key",
		},
		{
			name: "asset ID wrong length - empty",
			req: &taprpc.ExportProofRequest{
				ScriptKey: validScriptKey,
				AssetId:   nil,
			},
			wantMsg: "asset ID must be 32 bytes",
		},
		{
			name: "asset ID wrong length - too short",
			req: &taprpc.ExportProofRequest{
				ScriptKey: validScriptKey,
				AssetId:   make([]byte, 31),
			},
			wantMsg: "asset ID must be 32 bytes",
		},
		{
			name: "asset ID wrong length - too long",
			req: &taprpc.ExportProofRequest{
				ScriptKey: validScriptKey,
				AssetId:   make([]byte, 33),
			},
			wantMsg: "asset ID must be 32 bytes",
		},
		{
			name: "invalid outpoint - bad txid",
			req: &taprpc.ExportProofRequest{
				ScriptKey: validScriptKey,
				AssetId:   make([]byte, 32),
				Outpoint: &taprpc.OutPoint{
					// Wrong length for txid.
					Txid:        []byte{0x01, 0x02},
					OutputIndex: 0,
				},
			},
			wantMsg: "unmarshalling outpoint",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := server.ExportProof(
				context.Background(), tc.req,
			)
			assertInvalidArgument(t, err, tc.wantMsg)
		})
	}
}
