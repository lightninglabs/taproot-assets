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

	// maxDecDisplay is the maximum value of decimal display that a user can
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

	// ErrNotJSON is returned if the metadata is expected to be JSON but
	// is another meta type.
	ErrNotJSON = errors.New("metadata is not JSON")

	// ErrDecDisplayInvalid is returned if the decimal display value is
	// invalid.
	ErrDecDisplayInvalid = errors.New("invalid decimal display")

	// ErrDecDisplayTooLarge is returned if the decimal display value
	// exceeds the current limit.
	ErrDecDisplayTooLarge = errors.New("decimal display too large")

	// ErrDecDisplayInvalidType is returned if the value in a JSON object
	// assigned to the decimal display key is not a uint32.
	ErrDecDisplayInvalidType = errors.New("decimal display JSON field is " +
		"not a number")

	// ErrDecDisplayMissing is returned if the decimal display key is
	// not present in a JSON object.
	ErrDecDisplayMissing = errors.New("decimal display field missing")
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

// A subset of Integer that excludes int8, since we never use it in practice.
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

	return nil
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

// GetDecDisplay attempts to decode metadata as JSON and return the decimal
// display value. If the metadata is not JSON, or the decimal display key is
// missing, the default decimal display value of 0 is returned.
func (m *MetaReveal) GetDecDisplay() (map[string]interface{}, uint32, error) {
	// An empty meta reveal has an implicit decimal display value of 0.
	if m == nil {
		return nil, 0, nil
	}

	if m.Type != MetaJson {
		return nil, 0, ErrNotJSON
	}

	// Data must first be valid metadata JSON.
	metaJSON, err := DecodeMetaJSON(m.Data)
	if err != nil {
		return nil, 0, err
	}

	// Our default decimal display value is 0.
	decDisplay, ok := metaJSON[MetadataDecDisplayKey]
	if !ok {
		return metaJSON, 0, ErrDecDisplayMissing
	}

	// We have to typecheck the value stored for the decimal display key;
	// it could be another JSON type.
	switch decDisplayVal := decDisplay.(type) {
	case float64:
		// Any Number-like values are stored in a float64. We need to
		// range check the decoded value.
		if decDisplayVal < 0 {
			return nil, 0, fmt.Errorf("decoded decimal display "+
				"value is negative: %v", decDisplayVal)
		}

		if decDisplayVal > float64(MaxDecDisplay) {
			return nil, 0, fmt.Errorf("%w: %v",
				ErrDecDisplayTooLarge, decDisplayVal)
		}

		// Ensure that the decoded value is a whole number.
		if math.Round(decDisplayVal) != decDisplayVal {
			return nil, 0, fmt.Errorf("decoded decimal display "+
				"value is not an integer: %v", decDisplayVal)
		}

		return metaJSON, uint32(decDisplayVal), nil

	default:
		return nil, 0, ErrDecDisplayInvalidType
	}
}

// SetDecDisplay attempts to set the decimal display value in existing JSON
// metadata. It checks that the new metadata is below the maximum metadata size.
func (m *MetaReveal) SetDecDisplay(decDisplay uint32) (*MetaReveal, error) {
	err := IsValidDecDisplay(decDisplay)
	if err != nil {
		return nil, err
	}

	// Fetch the current decimal display value.
	currentMetaJSON, currentDecDisplay, err := m.GetDecDisplay()
	switch {
	// The current metadata is valid JSON. Either no decimal display value
	// is present, or it is but doesn't match the desired value.
	case errors.Is(err, ErrDecDisplayMissing),
		currentDecDisplay != decDisplay:

		// If the requested decimal display value is 0, we don't need to
		// add the field at all, as that is the default.
		if decDisplay == 0 {
			return &MetaReveal{
				Type: m.Type,
				Data: m.Data,
			}, nil
		}

		// Otherwise, set the decimal display value and re-validate the
		// JSON object.
		updatedJSON := make(map[string]interface{})
		maps.Copy(updatedJSON, currentMetaJSON)

		updatedJSON[MetadataDecDisplayKey] = decDisplay

		updatedJSONBytes, err := EncodeMetaJSON(updatedJSON)
		if err != nil {
			return nil, fmt.Errorf("invalid metadata after "+
				"setting decimal display: %w", err)
		}

		return &MetaReveal{
			Type: m.Type,
			Data: updatedJSONBytes,
		}, nil

	// No metadata update needed.
	case currentDecDisplay == decDisplay:
		return &MetaReveal{
			Type: m.Type,
			Data: m.Data,
		}, nil

	// Our metadata is invalid in another way.
	default:
		return nil, fmt.Errorf("%w: %d", ErrDecDisplayInvalid,
			decDisplay)
	}
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
