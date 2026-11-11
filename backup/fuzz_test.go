package backup

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/lightningnetwork/lnd/tlv"
)

// FuzzBackupTLVDecode exercises each backup type that uses parsed TLV
// decoding. AssetBackup inputs are wrapped in their required length prefix.
func FuzzBackupTLVDecode(f *testing.F) {
	seed := []byte("0\xff00000000")
	for decoder := uint8(0); decoder < 5; decoder++ {
		f.Add(decoder, seed)
	}

	f.Fuzz(func(t *testing.T, decoder uint8, data []byte) {
		reader := bytes.NewReader(data)

		switch decoder % 5 {
		case 0:
			var (
				encoded bytes.Buffer
				buf     [8]byte
			)
			if err := tlv.WriteVarInt(
				&encoded, uint64(len(data)), &buf,
			); err != nil {
				t.Fatalf(
					"unable to encode backup "+
						"length: %v", err,
				)
			}
			_, _ = encoded.Write(data)

			value := &AssetBackup{}
			_ = value.Decode(bytes.NewReader(encoded.Bytes()))

		case 1:
			value := &ScriptKeyBackup{}
			_ = value.Decode(reader)

		case 2:
			value := &KeyDescriptorBackup{}
			_ = value.Decode(reader)

		case 3:
			var encoded bytes.Buffer
			_, _ = encoded.WriteString(backupMagicBytes)
			if err := binary.Write(
				&encoded, binary.BigEndian,
				BackupVersionOptimistic,
			); err != nil {
				t.Fatalf(
					"unable to encode backup "+
						"version: %v", err,
				)
			}
			_, _ = encoded.Write(data)

			value := &WalletBackup{}
			_ = value.Decode(bytes.NewReader(encoded.Bytes()))

		case 4:
			value := &GroupKeyBackup{}
			_ = value.Decode(reader)
		}
	})
}
