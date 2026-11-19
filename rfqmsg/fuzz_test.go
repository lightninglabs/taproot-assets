package rfqmsg

import (
	"bytes"
	"testing"
)

// FuzzRfqTLVDecode exercises the RFQ message decoders from a shared
// crash-shaped TLV seed.
func FuzzRfqTLVDecode(f *testing.F) {
	seed := []byte("0\xff00000000")
	for decoder := uint8(0); decoder < 6; decoder++ {
		f.Add(decoder, seed)
	}

	f.Fuzz(func(t *testing.T, decoder uint8, data []byte) {
		reader := bytes.NewReader(data)

		switch decoder % 6 {
		case 0:
			value := &requestWireMsgData{}
			_ = value.Decode(reader)

		case 1:
			value := &acceptWireMsgData{}
			_ = value.Decode(reader)

		case 2:
			value := &rejectWireMsgData{}
			_ = value.Decode(reader)

		case 3:
			value := &Htlc{}
			_ = value.Decode(reader)

		case 4:
			value := &AssetBalance{}
			_ = value.Decode(reader)

		case 5:
			value := &AssetBalanceListRecord{}
			_ = value.Decode(reader)
		}
	})
}
