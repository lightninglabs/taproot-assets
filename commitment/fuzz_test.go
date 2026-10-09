package commitment

import (
	"bytes"
	"testing"
)

// FuzzCommitmentProofDecode exercises the nested commitment proof TLV stream
// from the same crash-shaped length seed as its proof callers.
func FuzzCommitmentProofDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("0\xff00000000"))

	f.Fuzz(func(t *testing.T, data []byte) {
		proof := &Proof{}
		_ = proof.Decode(bytes.NewReader(data))
	})
}
