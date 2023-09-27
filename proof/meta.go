package proof

import (
	"bytes"
	"crypto/sha256"
	"io"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/tlv"
)

// MetaType is the type of the meta data being revealed.
type MetaType uint8

const (
	// MetaOpaque signals that the meta data is simply a set of opaque
	// bytes without any specific interpretation.
	MetaOpaque MetaType = 0
)

// MetaReveal is an optional TLV type that can be added to the proof of a
// genesis asset to reveal pre-image to the metadata hash. If present, then the
// following equality must hold for the genesis proof to be valid:
//
//   - sha256(tlvEncode(metaReveal)) == metaHash
type MetaReveal struct {
	// Type is the type of the metadata.
	Type MetaType

	// Data is the committed data being revealed.
	Data []byte
}

// MetaHash returns the computed meta hash based on the TLV serialization of
// the meta data itself.
func (m *MetaReveal) MetaHash() [asset.MetaHashLen]byte {
	var b bytes.Buffer
	_ = m.Encode(&b)

	return sha256.Sum256(b.Bytes())
}

// EncodeRecords returns the TLV encode records for the meta reveal.
func (m *MetaReveal) EncodeRecords() []tlv.Record {
	return []tlv.Record{
		MetaRevealTypeRecord(&m.Type),
		MetaRevealDataRecord(&m.Data),
	}
}

// DecodeRecords returns the TLV decode records for the meta reveal.
func (m *MetaReveal) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		MetaRevealTypeRecord(&m.Type),
		MetaRevealDataRecord(&m.Data),
	}
}

// Encode encodes the meta reveal to the given writer.
func (m *MetaReveal) Encode(w io.Writer) error {
	stream, err := tlv.NewStream(m.EncodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(w)
}

// Decode decodes the meta reveal from the given reader.
func (m *MetaReveal) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(m.DecodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Decode(r)
}
