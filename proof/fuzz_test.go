package proof

import (
	"bytes"
	"testing"
)

func FuzzFile(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fileData := make([]byte, 0)
		fileData = append(fileData, FilePrefixMagicBytes[:]...)
		fileData = append(fileData, data...)

		f := &File{}

		_ = f.Decode(bytes.NewReader(fileData))
	})
}

func FuzzProof(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		proof := &Proof{}

		proofData := make([]byte, 0)
		proofData = append(proofData, PrefixMagicBytes[:]...)
		proofData = append(proofData, data...)

		_ = proof.Decode(bytes.NewReader(proofData))
	})
}
