package proof

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

var declaredLengthCrashSeed = []byte("0\xff00000000")

func addHexFuzzSeed(f *testing.F, fileName string, prefix []byte) {
	f.Helper()

	hexBytes, err := os.ReadFile(filepath.Join("testdata", fileName))
	if err != nil {
		f.Fatalf("unable to read fuzz seed %s: %v", fileName, err)
	}

	seed := make([]byte, hex.DecodedLen(len(hexBytes)))
	n, err := hex.Decode(seed, hexBytes)
	if err != nil {
		f.Fatalf("unable to decode fuzz seed %s: %v", fileName, err)
	}
	seed = seed[:n]

	if !bytes.HasPrefix(seed, prefix) {
		f.Fatalf("fuzz seed %s has an invalid prefix", fileName)
	}

	f.Add(seed[len(prefix):])
}

func nestedAssetCrashSeed() []byte {
	seed := make([]byte, 0, 2+len(declaredLengthCrashSeed))
	seed = append(
		seed, byte(AssetLeafType), byte(len(declaredLengthCrashSeed)),
	)
	return append(seed, declaredLengthCrashSeed...)
}

func FuzzFile(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
	addHexFuzzSeed(f, "proof-file.hex", FilePrefixMagicBytes[:])

	f.Fuzz(func(t *testing.T, data []byte) {
		fileData := make([]byte, 0)
		fileData = append(fileData, FilePrefixMagicBytes[:]...)
		fileData = append(fileData, data...)

		proofFile := &File{}
		err := proofFile.Decode(bytes.NewReader(fileData))
		if err != nil {
			return
		}

		for idx := 0; idx < proofFile.NumProofs(); idx++ {
			_, _ = proofFile.ProofAt(uint32(idx))
		}
	})
}

func FuzzProof(f *testing.F) {
	f.Add([]byte{})
	f.Add(declaredLengthCrashSeed)
	f.Add(nestedAssetCrashSeed())
	addHexFuzzSeed(f, "proof.hex", PrefixMagicBytes[:])

	f.Fuzz(func(t *testing.T, data []byte) {
		proof := &Proof{}

		proofData := make([]byte, 0)
		proofData = append(proofData, PrefixMagicBytes[:]...)
		proofData = append(proofData, data...)

		_ = proof.Decode(bytes.NewReader(proofData))
	})
}

// FuzzFileProofDecode wraps each generated proof in a proof file with a valid
// checksum so mutations always reach the nested proof decoder.
func FuzzFileProofDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add(declaredLengthCrashSeed)
	f.Add(nestedAssetCrashSeed())
	addHexFuzzSeed(f, "proof.hex", PrefixMagicBytes[:])

	f.Fuzz(func(t *testing.T, data []byte) {
		proofBytes := make([]byte, 0, len(PrefixMagicBytes)+len(data))
		proofBytes = append(proofBytes, PrefixMagicBytes[:]...)
		proofBytes = append(proofBytes, data...)

		proofFile := NewEmptyFile(V0)
		if err := proofFile.AppendProofRaw(proofBytes); err != nil {
			t.Fatalf("unable to append raw proof: %v", err)
		}

		var encoded bytes.Buffer
		if err := proofFile.Encode(&encoded); err != nil {
			t.Fatalf("unable to encode proof file: %v", err)
		}

		decodedFile := &File{}
		err := decodedFile.Decode(bytes.NewReader(encoded.Bytes()))
		if err != nil {
			t.Fatalf(
				"unable to decode generated proof "+
					"file: %v", err,
			)
		}

		_, _ = decodedFile.ProofAt(0)
	})
}
