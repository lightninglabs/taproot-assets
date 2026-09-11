package proof

import (
	"bytes"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
)

// BenchmarkProofEncode measures encoding a single proof, the unit of work
// behind proof files, universe leaves and channel commitment blobs.
func BenchmarkProofEncode(b *testing.B) {
	amt := uint64(5000)
	genesisProof, _ := genRandomGenesisWithProof(
		b, asset.Normal, &amt, nil, false, nil, nil, nil, nil, asset.V0,
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		if err := genesisProof.Encode(&buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkProofDecode measures decoding a single proof from its bytes.
func BenchmarkProofDecode(b *testing.B) {
	amt := uint64(5000)
	genesisProof, _ := genRandomGenesisWithProof(
		b, asset.Normal, &amt, nil, false, nil, nil, nil, nil, asset.V0,
	)
	proofBytes, err := genesisProof.Bytes()
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := Decode(proofBytes); err != nil {
			b.Fatal(err)
		}
	}
}
