package commitment

import (
	"bytes"
	"testing"

	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
)

// TestTreeProofDecoderTrailingData checks that a tree proof record is rejected
// when bytes follow the compressed proof it holds.
func TestTreeProofDecoderTrailingData(t *testing.T) {
	t.Parallel()

	var (
		proof  = mssmt.RandProof(t)
		record bytes.Buffer
		buf    [8]byte
	)
	require.NoError(t, TreeProofEncoder(&record, proof, &buf))

	decode := func(b []byte) error {
		var decoded mssmt.Proof
		return TreeProofDecoder(
			bytes.NewReader(b), &decoded, &buf, uint64(len(b)),
		)
	}

	require.NoError(t, decode(record.Bytes()))

	err := decode(append(bytes.Clone(record.Bytes()), 0))
	require.ErrorContains(t, err, "trailing data")
}
