package mssmt

import (
	"bytes"
	"testing"
)

func FuzzCompressedProof(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x01, 0x00})
	f.Add([]byte{0x01, 0x01})
	f.Add([]byte{0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		var compressedProof CompressedProof
		_ = compressedProof.Decode(bytes.NewReader(data))
	})
}
