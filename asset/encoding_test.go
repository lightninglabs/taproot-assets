package asset

import (
	"bytes"
	"testing"

	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
)

// TestSplitCommitmentDecoderTrailingData checks that a split commitment record
// is rejected when bytes follow the compressed proof it holds.
func TestSplitCommitmentDecoderTrailingData(t *testing.T) {
	t.Parallel()

	var compressed, rootAsset bytes.Buffer
	err := mssmt.RandProof(t).Compress().Encode(&compressed)
	require.NoError(t, err)
	require.NoError(t, RandAsset(t, Normal).Encode(&rootAsset))

	var buf [8]byte
	decode := func(proofBytes []byte) error {
		var record bytes.Buffer
		rootAssetBytes := rootAsset.Bytes()
		err := InlineVarBytesEncoder(&record, &proofBytes, &buf)
		require.NoError(t, err)
		err = InlineVarBytesEncoder(&record, &rootAssetBytes, &buf)
		require.NoError(t, err)

		var decoded *SplitCommitment
		return SplitCommitmentDecoder(
			bytes.NewReader(record.Bytes()), &decoded, &buf,
			uint64(record.Len()),
		)
	}

	require.NoError(t, decode(compressed.Bytes()))

	err = decode(append(bytes.Clone(compressed.Bytes()), 0))
	require.ErrorContains(t, err, "trailing data")
}
