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

// assertCode checks that the error is a gRPC status error with the expected
// status code.
func assertCode(t *testing.T, err error, wantCode codes.Code) {
	t.Helper()

	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status error")
	require.Equal(t, wantCode, st.Code())
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
		name     string
		req      *taprpc.DecodeAddrRequest
		wantCode codes.Code
	}{
		{
			name:     "empty address",
			req:      &taprpc.DecodeAddrRequest{Addr: ""},
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "invalid address format",
			req:      &taprpc.DecodeAddrRequest{Addr: "not-valid"},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "wrong network prefix",
			req: &taprpc.DecodeAddrRequest{
				// Testnet address on mainnet config.
				Addr: "taptb1qqqszqspqqqqqqqqqqqqqqqqqqq" +
					"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpqqq" +
					"sqqspqqqqp8hlm7nfnydq5wvs6j5mczq8tf" +
					"vemhy7082",
			},
			wantCode: codes.InvalidArgument,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := server.DecodeAddr(
				context.Background(), tc.req)
			assertCode(t, err, tc.wantCode)
		})
	}
}

// TestDecodeProofValidation tests that DecodeProof returns InvalidArgument
// for validation errors.
func TestDecodeProofValidation(t *testing.T) {
	t.Parallel()

	server := newTestServer()

	// Invalid proof bytes that don't match either magic prefix.
	invalidMagicBytes := []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03}

	// Bytes with single proof magic but invalid content.
	invalidSingleProof := append(
		proof.PrefixMagicBytes[:], []byte{0x00, 0x01, 0x02, 0x03}...,
	)

	// Bytes with file magic but invalid content.
	invalidFileProof := append(
		proof.FilePrefixMagicBytes[:],
		[]byte{0x00, 0x01, 0x02, 0x03}...,
	)

	tests := []struct {
		name     string
		req      *taprpc.DecodeProofRequest
		wantCode codes.Code
	}{
		{
			name:     "empty proof",
			req:      &taprpc.DecodeProofRequest{RawProof: nil},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "invalid magic bytes",
			req: &taprpc.DecodeProofRequest{
				RawProof: invalidMagicBytes,
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "invalid single proof",
			req: &taprpc.DecodeProofRequest{
				RawProof: invalidSingleProof,
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "invalid file proof",
			req: &taprpc.DecodeProofRequest{
				RawProof: invalidFileProof,
			},
			wantCode: codes.InvalidArgument,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := server.DecodeProof(
				context.Background(), tc.req)
			assertCode(t, err, tc.wantCode)
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
		name     string
		req      *taprpc.ExportProofRequest
		wantCode codes.Code
	}{
		{
			name:     "empty script key",
			req:      &taprpc.ExportProofRequest{ScriptKey: nil},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "invalid script key length",
			req: &taprpc.ExportProofRequest{
				ScriptKey: []byte{0x01, 0x02, 0x03},
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "invalid script key prefix",
			req: &taprpc.ExportProofRequest{
				// 33 bytes is correct length for compressed
				// pubkey, but 0x00 prefix is invalid.
				ScriptKey: make([]byte, 33),
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "empty asset ID",
			req: &taprpc.ExportProofRequest{
				ScriptKey: validScriptKey,
				AssetId:   nil,
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "asset ID too short",
			req: &taprpc.ExportProofRequest{
				ScriptKey: validScriptKey,
				AssetId:   make([]byte, 31),
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "asset ID too long",
			req: &taprpc.ExportProofRequest{
				ScriptKey: validScriptKey,
				AssetId:   make([]byte, 33),
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "invalid outpoint",
			req: &taprpc.ExportProofRequest{
				ScriptKey: validScriptKey,
				AssetId:   make([]byte, 32),
				Outpoint: &taprpc.OutPoint{
					Txid:        []byte{0x01, 0x02},
					OutputIndex: 0,
				},
			},
			wantCode: codes.InvalidArgument,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := server.ExportProof(
				context.Background(), tc.req)
			assertCode(t, err, tc.wantCode)
		})
	}
}
