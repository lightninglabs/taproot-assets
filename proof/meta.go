package proof

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
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

	// MaxNumCanonicalUniverseURLs is the maximum number of canonical
	// universe URLs that can be set.
	MaxNumCanonicalUniverseURLs = 16

	// MaxCanonicalUniverseURLLength is the maximum length of the canonical
	// universe URL.
	MaxCanonicalUniverseURLLength = 255
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

	// ErrCanonicalUniverseInvalid is returned if the canonical universe
	// URL is invalid.
	ErrCanonicalUniverseInvalid = errors.New(
		"canonical universe URL invalid",
	)

	// ErrTooManyCanonicalUniverseURLs is returned if the number of
	// canonical universe URLs exceeds the maximum.
	ErrTooManyCanonicalUniverseURLs = fmt.Errorf(
		"too many canonical universe URLs, max %d",
		MaxNumCanonicalUniverseURLs,
	)

	// ErrCanonicalUniverseURLTooLong is returned if the canonical universe
	// URL is too long.
	ErrCanonicalUniverseURLTooLong = fmt.Errorf(
		"canonical universe URL too long, max %d characters",
		MaxCanonicalUniverseURLLength,
	)

	// ErrDelegationKeyEmpty is returned if the delegation key is empty.
	ErrDelegationKeyEmpty = errors.New("delegation key is empty")

	// ErrDelegationKeyNotOnCurve is returned if the delegation key is not
	// on the curve.
	ErrDelegationKeyNotOnCurve = errors.New(
		"delegation key is not on curve",
	)
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
	// explicitly encoded in the TLV, this is an older asset that didn't
	// have this field. New assets will always set an explicit value, even
	// if that is the default value of zero. If the meta type is JSON and
	// this value is not zero, then the decimal display is also added as a
	// field to the JSON object for backward compatibility.
	DecimalDisplay fn.Option[uint32]

	// UniverseCommitments indicates that the asset group this asset belongs
	// to will create and push universe commitments to the canonical
	// universe. A universe commitment is a "proof of inventory" that
	// commits the issuer's current total asset balance (sum of all mints
	// minus burns or ignored assets) on-chain.
	UniverseCommitments bool

	// CanonicalUniverses is a list of URLs of the canonical (approved,
	// authoritative) universe where the asset minting and universe
	// commitment proofs will be pushed to.
	CanonicalUniverses fn.Option[[]url.URL]

	// DelegationKey is the public key that is used to verify universe
	// commitment related on-chain outputs and proofs.
	DelegationKey fn.Option[btcec.PublicKey]

	// UnknownOddTypes is a map of unknown odd types that were encountered
	// during decoding. This map is used to preserve unknown types that we
	// don't know of yet, so we can still encode them back when serializing.
	// This enables forward compatibility with future versions of the
	// protocol as it allows new odd (optional) types to be added without
	// breaking old clients that don't yet fully understand them.
	UnknownOddTypes tlv.TypeMap
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

	// If the decimal display is set, it must be valid.
	err = fn.MapOptionZ(m.DecimalDisplay, IsValidDecDisplay)
	if err != nil {
		return err
	}

	err = fn.MapOptionZ(m.CanonicalUniverses, func(urls []url.URL) error {
		// If the option is set, the slice must not be empty.
		if len(urls) == 0 {
			return ErrCanonicalUniverseInvalid
		}

		if len(urls) > MaxNumCanonicalUniverseURLs {
			return ErrTooManyCanonicalUniverseURLs
		}

		for _, u := range urls {
			if len(u.String()) > MaxCanonicalUniverseURLLength {
				return ErrCanonicalUniverseURLTooLong
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// The asset metadata is invalid when the universe commitments feature
	// is enabled but no delegation key is specified.
	if m.UniverseCommitments && m.DelegationKey.IsNone() {
		return fmt.Errorf("universe commitments enabled in asset " +
			"metadata but delegation key is unspecified")
	}

	return fn.MapOptionZ(m.DelegationKey, func(key btcec.PublicKey) error {
		if key == emptyKey {
			return ErrDelegationKeyEmpty
		}

		if !key.IsOnCurve() {
			return ErrDelegationKeyNotOnCurve
		}

		return nil
	})
}

// SizableInteger is a subset of Integer that excludes int8, since we never use
// it in practice.
type SizableInteger interface {
	constraints.Unsigned | ~int | ~int16 | ~int32 | ~int64
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
//
// TODO(ffranr): Add unit test for `jBytes := []byte{}`.
func DecodeMetaJSON(jBytes []byte) (map[string]interface{}, error) {
	jMeta := make(map[string]interface{})

	// These bytes must match our metadata size constraints.
	err := IsValidMetaSize(jBytes, MetaDataMaxSizeBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidJSON, err.Error())
	}

	// Unmarshal checks internally if the JSON is valid.
	err = json.Unmarshal(jBytes, &jMeta)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidJSON, err.Error())
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

	// If the decimal display is set as the new TLV value, we can use that
	// directly.
	if m.DecimalDisplay.IsSome() {
		return nil, m.DecimalDisplay.UnwrapOr(0), nil
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

// DecDisplayOption attempts to decode a decimal display value from metadata. If
// no custom decimal display value is decoded, an empty option is returned
// without error.
func (m *MetaReveal) DecDisplayOption() (fn.Option[uint32], error) {
	_, decDisplay, err := m.GetDecDisplay()
	switch {
	// If it isn't JSON, or doesn't have a dec display, we'll just return 0
	// below.
	case errors.Is(err, ErrNotJSON):
		fallthrough
	case errors.Is(err, ErrInvalidJSON):
		fallthrough
	case errors.Is(err, ErrDecDisplayMissing):
		fallthrough
	case errors.Is(err, ErrDecDisplayInvalidType):
		// We can't determine if there is a decimal display value set.
		return fn.None[uint32](), nil

	case err != nil:
		return fn.None[uint32](), fmt.Errorf("unable to extract "+
			"decimal display: %v", err)
	}

	return fn.Some(decDisplay), nil
}

// SetDecDisplay attempts to set the decimal display value in existing JSON
// metadata. It checks that the new metadata is below the maximum metadata size.
func (m *MetaReveal) SetDecDisplay(decDisplay uint32) error {
	err := IsValidDecDisplay(decDisplay)
	if err != nil {
		return err
	}

	m.DecimalDisplay = fn.Some(decDisplay)

	// We only set the decimal display value in the JSON if it isn't the
	// default value of 0.
	if decDisplay == 0 {
		return nil
	}

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
	case len(m.Data) == 0 || errors.Is(err, ErrMetaDataMissing):
		metaJSON = make(map[string]interface{})

	case err != nil:
		return err
	}

	metaJSON[MetadataDecDisplayKey] = decDisplay

	m.Data, err = EncodeMetaJSON(metaJSON)
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
	err := m.Encode(&b)
	if err != nil {
		log.Errorf("Unable to encode meta reveal: %v", err)
	}

	return sha256.Sum256(b.Bytes())
}

// EncodeRecords returns the TLV encode records for the meta reveal.
func (m *MetaReveal) EncodeRecords() []tlv.Record {
	records := []tlv.Record{
		MetaRevealTypeRecord(&m.Type),
		MetaRevealDataRecord(&m.Data),
	}

	// In order not to change the encoding of existing records if
	// we de-serialize and re-serialize them, we only encode this boolean
	// value if it's actually true.
	if m.UniverseCommitments {
		records = append(records, MetaRevealUniverseCommitmentsRecord(
			&m.UniverseCommitments,
		))
	}

	// To make sure we don't re-encode old assets that don't have a decimal
	// display value as a TLV field with a different value, we only encode
	// the decimal display value if it is explicitly set.
	if m.DecimalDisplay.IsSome() {
		records = append(records, MetaRevealDecimalDisplayRecord(
			&m.DecimalDisplay,
		))
	}

	if m.CanonicalUniverses.IsSome() {
		records = append(records, MetaRevealCanonicalUniversesRecord(
			&m.CanonicalUniverses,
		))
	}

	if m.DelegationKey.IsSome() {
		records = append(records, MetaRevealDelegationKeyRecord(
			&m.DelegationKey,
		))
	}

	// Add any unknown odd types that were encountered during decoding.
	return asset.CombineRecords(records, m.UnknownOddTypes)
}

// DecodeRecords returns the TLV decode records for the meta reveal.
func (m *MetaReveal) DecodeRecords() []tlv.Record {
	return []tlv.Record{
		MetaRevealTypeRecord(&m.Type),
		MetaRevealDataRecord(&m.Data),
		MetaRevealDecimalDisplayRecord(&m.DecimalDisplay),
		MetaRevealUniverseCommitmentsRecord(&m.UniverseCommitments),
		MetaRevealCanonicalUniversesRecord(&m.CanonicalUniverses),
		MetaRevealDelegationKeyRecord(&m.DelegationKey),
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

	// Note, we can't use the DecodeP2P method here, because the meta data
	// itself can be larger than 65k bytes. But we impose limits in the
	// individual decoding functions.
	unknownOddTypes, err := asset.TlvStrictDecode(
		stream, r, KnownMetaRevealTypes,
	)
	if err != nil {
		return err
	}

	m.UnknownOddTypes = unknownOddTypes

	return nil
}
