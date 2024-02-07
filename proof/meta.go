package proof

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
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

	// MetaJson signals that the meta data is a JSON object.
	MetaJson MetaType = 1
)

const (
	// MetaDataMaxSizeBytes is the maximum length of the meta data. We limit
	// this to 1MiB for now. This should be of sufficient size to commit to
	// any JSON data or even medium resolution images. If there is need to
	// commit to even more data, it would make sense to instead commit to an
	// annotated hash of the data instead. The reason for the limit is that
	// the meta data will be part of the genesis proof, which is stored in
	// the universe and needs to be validated by all senders and receivers
	// of the asset.
	MetaDataMaxSizeBytes = 1024 * 1024
)

var (
	// ErrMetaDataMissing signals that the meta data is missing.
	ErrMetaDataMissing = errors.New("meta data missing")

	// ErrMetaDataTooLarge signals that the meta data is too large.
	ErrMetaDataTooLarge = errors.New("meta data too large")

	// ErrInvalidJSON signals that the meta data is not a valid JSON.
	ErrInvalidJSON = errors.New("invalid JSON")
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

// Validate validates the meta reveal.
func (m *MetaReveal) Validate() error {
	// A meta reveal is allowed to be nil.
	if m == nil {
		return nil
	}

	// If a meta reveal is present, then the data must be non-empty.
	if len(m.Data) == 0 {
		return ErrMetaDataMissing
	}

	if len(m.Data) > MetaDataMaxSizeBytes {
		return ErrMetaDataTooLarge
	}

	// If the type is JSON, then it should be parseable as a JSON string.
	if m.Type == MetaJson {
		if !json.Valid(m.Data) {
			return ErrInvalidJSON
		}
	}

	return nil
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
