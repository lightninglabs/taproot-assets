package proof

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/tlv"
	"golang.org/x/exp/constraints"
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

	// MetadataDecDisplayKey is the JSON key used in the metadata field of a
	// minted asset to express the decimal display of the minted asset.
	MetadataDecDisplayKey = "decimal_display"

	// MaxDecDisplay is the maximum value of decimal display that a user can
	// define when minting assets. Since the uint64 max value has 19 decimal
	// places we will allow for a max of 12 decimal places.
	MaxDecDisplay = uint32(12)
)

var (
	// ErrMetaDataMissing signals that the meta data is missing.
	ErrMetaDataMissing = errors.New("meta data missing")

	// ErrMetaDataTooLarge signals that the meta data is too large.
	ErrMetaDataTooLarge = errors.New("meta data too large")

	// ErrMetaTypeNegative signals that the given value is an invalid meta
	// type because it is negative.
	ErrMetaTypeNegative = errors.New("meta type cannot be negative")

	// ErrMetaTypeTooLarge signals that the given value is an invalid meta
	// type because it is too large.
	ErrMetaTypeTooLarge = errors.New("meta type above limit of 255")

	// ErrInvalidJSON signals that the meta data is not a valid JSON.
	ErrInvalidJSON = errors.New("invalid JSON")

	// ErrDecDisplayTooLarge is returned if the decimal display value
	// exceeds the current limit.
	ErrDecDisplayTooLarge = errors.New("decimal display too large")
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

	// DecimalDisplay is the decimal display value of the asset. This is
	// used to determine the number of decimal places to display when
	// presenting the asset amount to the user. If this field is not
	// explicitly encoded in the TLV, the default value of 0 is used. If the
	// meta type is JSON then the decimal display is also added as a field
	// to the JSON object.
	DecimalDisplay uint32
}

// SizableInteger is a subset of Integer that excludes int8, since we never use
// it in practice.
type SizableInteger interface {
	constraints.Unsigned | ~int | ~int16 | ~int32 | ~int64
}

// Validate validates the meta reveal.
func (m *MetaReveal) Validate() error {
	// A meta reveal is allowed to be nil.
	if m == nil {
		return nil
	}

	// If a meta reveal is present, then the data must be non-empty.
	err := IsValidMetaSize(m.Data, MetaDataMaxSizeBytes)
	if err != nil {
		return err
	}

	// The meta type must be valid.
	_, err = IsValidMetaType(m.Type)
	if err != nil {
		return err
	}

	// If the type is JSON, then it should be parseable as a JSON string.
	if m.Type == MetaJson {
		if !json.Valid(m.Data) {
			return ErrInvalidJSON
		}
	}

	return IsValidDecDisplay(m.DecimalDisplay)
}

// IsValidMetaType checks if the passed value is a valid meta type.
func IsValidMetaType[T SizableInteger](num T) (MetaType, error) {
	switch {
	case num < 0:
		return 0, fmt.Errorf("%w: %d", ErrMetaTypeNegative, num)

	case num > math.MaxUint8:
		return 0, fmt.Errorf("%w: %d", ErrMetaTypeTooLarge, num)

	default:
		return MetaType(num), nil
	}
}

// IsValidMetaSize checks if the passed data is non-empty and below the maximum
// size.
func IsValidMetaSize(mBytes []byte, maxSize int) error {
	mSize := len(mBytes)
	switch {
	case mSize == 0:
		return ErrMetaDataMissing

	case mSize > maxSize:
		return ErrMetaDataTooLarge

	default:
		return nil
	}
}

// IsValidDecDisplay checks if the decimal display value is below the maximum.
func IsValidDecDisplay(decDisplay uint32) error {
	if decDisplay > MaxDecDisplay {
		return fmt.Errorf("%w: %d", ErrDecDisplayTooLarge, decDisplay)
	}

	return nil
}

// DecodeMetaJSON decodes bytes as a JSON object, after checking that the bytes
// could be valid metadata.
func DecodeMetaJSON(jBytes []byte) (map[string]interface{}, error) {
	jMeta := make(map[string]interface{})

	// These bytes must match our metadata size constraints.
	err := IsValidMetaSize(jBytes, MetaDataMaxSizeBytes)
	if err != nil {
		return nil, err
	}

	// Unmarshal checks internally if the JSON is valid.
	err = json.Unmarshal(jBytes, &jMeta)
	if err != nil {
		return nil, err
	}

	return jMeta, nil
}

// EncodeMetaJSON encodes a JSON object as bytes and checks that the resulting
// bytes are below the maximum metadata size.
func EncodeMetaJSON(jMeta map[string]interface{}) ([]byte, error) {
	if jMeta == nil {
		return []byte{}, nil
	}

	jBytes, err := json.Marshal(jMeta)
	if err != nil {
		return nil, err
	}

	err = IsValidMetaSize(jBytes, MetaDataMaxSizeBytes)
	if err != nil {
		return nil, err
	}

	return jBytes, nil
}

// SetDecDisplay attempts to set the decimal display value in existing JSON
// metadata. It checks that the new metadata is below the maximum metadata size.
func (m *MetaReveal) SetDecDisplay(decDisplay uint32) error {
	err := IsValidDecDisplay(decDisplay)
	if err != nil {
		return err
	}

	m.DecimalDisplay = decDisplay

	// If the meta type is not JSON, we're done already, as the decimal
	// display will only be encoded in the TLV.
	if m.Type != MetaJson {
		return nil
	}

	// If the meta type is JSON, we'll also want to set the decimal display
	// value in the JSON object.
	metaJSON, err := DecodeMetaJSON(m.Data)
	switch {
	// If the metadata is currently empty, we'll just start with an empty
	// JSON object.
	case errors.Is(err, ErrMetaDataMissing):
		metaJSON = make(map[string]interface{})

	case err != nil:
		return err
	}

	updatedJSON := make(map[string]interface{})
	maps.Copy(updatedJSON, metaJSON)

	updatedJSON[MetadataDecDisplayKey] = decDisplay

	m.Data, err = EncodeMetaJSON(updatedJSON)
	if err != nil {
		return fmt.Errorf("invalid metadata after setting decimal "+
			"display: %w", err)
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
		MetaRevealDecimalDisplayRecord(&m.DecimalDisplay),
	}
}

// DecodeRecords returns the TLV decode records for the meta reveal.
func (m *MetaReveal) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		MetaRevealTypeRecord(&m.Type),
		MetaRevealDataRecord(&m.Data),
		MetaRevealDecimalDisplayRecord(&m.DecimalDisplay),
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
