package mssmt

import (
	"bytes"
	"testing"
)

func FuzzCompressedProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var compressedProof CompressedProof
		_ = compressedProof.Decode(bytes.NewReader(data))
	})
}
