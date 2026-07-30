package rpcserver

import (
	"bytes"
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/tapconfig"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/stretchr/testify/require"
)

// TestVerifyProofInvalidProofResponse ensures that a proof file that fails
// verification results in a successful RPC response with valid=false and no
// decoded proof, instead of failing the whole RPC. Decoding the last proof
// of an invalid file can itself fail (for example when the asset is unknown
// to the node), which previously surfaced as an RPC error.
func TestVerifyProofInvalidProofResponse(t *testing.T) {
	t.Parallel()

	server := newTestServer()

	// The verifier context promotes fields through the embedded
	// database config, which must therefore be present. Its stores can
	// stay unset: verification fails before any of them is consulted.
	server.cfg.DatabaseConfig = &tapconfig.DatabaseConfig{}

	// Build a well-encoded proof file that is guaranteed to fail
	// verification at its very first step: an unknown proof file
	// version. This keeps the test hermetic, as verification aborts
	// before any chain or Universe dependency is consulted.
	proofFile, err := proof.NewFile(proof.V0)
	require.NoError(t, err)
	require.NoError(t, proofFile.AppendProofRaw([]byte{0x01, 0x02, 0x03}))
	proofFile.Version = proof.Version(99)

	var buf bytes.Buffer
	require.NoError(t, proofFile.Encode(&buf))

	resp, err := server.VerifyProof(context.Background(), &taprpc.ProofFile{
		RawProofFile: buf.Bytes(),
	})
	require.NoError(t, err)
	require.False(t, resp.Valid)
	require.Nil(t, resp.DecodedProof)
}
