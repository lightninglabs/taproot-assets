package tapchannelmsg

import (
	"bytes"
	"testing"
)

// FuzzTapChannelTLVDecode exercises each tap-channel record decoder from a
// shared crash-shaped TLV seed.
func FuzzTapChannelTLVDecode(f *testing.F) {
	seed := []byte("0\xff00000000")
	for decoder := uint8(0); decoder < 17; decoder++ {
		f.Add(decoder, seed)
	}

	// This is an AuxShutdownMsg script-key record with an impossible entry
	// count. The record contains only the count and no map entries.
	f.Add(uint8(13), []byte{
		0xfe, 0x00, 0x01, 0x00, 0x05, 0x03,
		0xfd, 0xff, 0xff,
	})

	f.Fuzz(func(t *testing.T, decoder uint8, data []byte) {
		reader := bytes.NewReader(data)

		switch decoder % 17 {
		case 0:
			value := &OpenChannel{}
			_ = value.Decode(reader)

		case 1:
			value := &AuxLeaves{}
			_ = value.Decode(reader)

		case 2:
			value := &Commitment{}
			_ = value.Decode(reader)

		case 3:
			value := &CommitSig{}
			_ = value.Decode(reader)

		case 4:
			value := &HtlcAuxLeaf{}
			_ = value.Decode(reader)

		case 5:
			value := &AssetSig{}
			_ = value.Decode(reader)

		case 6:
			value := &AssetSigListRecord{}
			_ = value.Decode(reader)

		case 7:
			value := &HtlcPartialSigsRecord{}
			_ = value.Decode(reader)

		case 8:
			value := &HtlcAuxLeafMapRecord{}
			_ = value.Decode(reader)

		case 9:
			value := &AssetOutput{}
			_ = value.Decode(reader)

		case 10:
			value := &HtlcAssetOutput{}
			_ = value.Decode(reader)

		case 11:
			value := &AssetOutputListRecord{}
			_ = value.Decode(reader)

		case 12:
			value := &TapLeafRecord{}
			_ = value.Decode(reader)

		case 13:
			value := &AuxShutdownMsg{}
			_ = value.Decode(reader)

		case 14:
			value := &TapscriptSigDesc{}
			_ = value.Decode(reader)

		case 15:
			value := &ContractResolution{}
			_ = value.Decode(reader)

		case 16:
			value := &ProofChunk{}
			_ = value.Decode(reader)
		}
	})
}
