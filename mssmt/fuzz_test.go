package mssmt

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func FuzzCompressedProof(f *testing.F) {
	// The proof of a key in the empty tree.
	f.Add(append([]byte{0, 0}, bytes.Repeat(
		[]byte{0xff}, MaxTreeLevels/8,
	)...))

	f.Fuzz(func(t *testing.T, data []byte) {
		proof, err := NewProofFromCompressedBytes(data)
		if err != nil {
			return
		}

		// Re-encoding the decoded proof yields the input.
		var buf bytes.Buffer
		require.NoError(t, proof.Compress().Encode(&buf))
		require.Equal(t, data, buf.Bytes())
	})
}
