package proof

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

var (
	// proofInvalidJsonHexFileName is the name of the file that contains the
	// hex proof data for a proof where the meta type is declared as JSON
	// but the data is not valid JSON.
	proofInvalidJsonHexFileName = filepath.Join(
		testDataFileName, "proof-invalid-json-meta-reveal.hex",
	)
)

// TestValidateMetaReveal tests the validation of a MetaReveal.
func TestValidateMetaReveal(t *testing.T) {
	t.Parallel()

	dummyURL, err := url.Parse("universerpc://localhost:1234")
	require.NoError(t, err)

	dummyURL2, err := url.Parse("universerpc://another-host:765")
	require.NoError(t, err)

	tooLongURL, err := url.Parse(
		"universerpc://localhost:1234/" + strings.Repeat("a", 255),
	)
	require.NoError(t, err)

	oneURL := fn.Some[[]url.URL]([]url.URL{*dummyURL})
	twoURL := fn.Some[[]url.URL]([]url.URL{*dummyURL, *dummyURL2})
	twoURLTooLong := fn.Some[[]url.URL]([]url.URL{*dummyURL, *tooLongURL})

	dummyKey := test.RandPubKey(t)

	testCases := []struct {
		name        string
		reveal      *MetaReveal
		expectedErr error
	}{
		{
			name:        "nil reveal",
			reveal:      nil,
			expectedErr: nil,
		},
		{
			name: "valid reveal",
			reveal: &MetaReveal{
				Type: MetaOpaque,
				Data: []byte("data"),
			},
			expectedErr: nil,
		},
		{
			name: "missing data",
			reveal: &MetaReveal{
				Type: MetaOpaque,
				Data: nil,
			},
		},
		{
			name: "too much data",
			reveal: &MetaReveal{
				Type: MetaOpaque,
				Data: make([]byte, MetaDataMaxSizeBytes+1),
			},
			expectedErr: ErrMetaDataTooLarge,
		},
		{
			name: "invalid JSON",
			reveal: &MetaReveal{
				Type: MetaJson,
				Data: []byte("invalid"),
			},
			expectedErr: ErrInvalidJSON,
		},
		{
			name: "valid JSON",
			reveal: &MetaReveal{
				Type: MetaJson,
				Data: []byte(`{"key": "value"}`),
			},
			expectedErr: nil,
		},
		{
			name: "invalid decimal display",
			reveal: &MetaReveal{
				Type:           MetaJson,
				Data:           []byte(`{"key": "value"}`),
				DecimalDisplay: fn.Some[uint32](999),
			},
			expectedErr: ErrDecDisplayTooLarge,
		},
		{
			name: "correct decimal display",
			reveal: &MetaReveal{
				Type:           MetaJson,
				Data:           []byte(`{"key": "value"}`),
				DecimalDisplay: fn.Some[uint32](8),
			},
			expectedErr: nil,
		},
		{
			name: "new asset meta reveal with explicit zero " +
				"decimal display and uni fields",
			reveal: &MetaReveal{
				Type:                MetaOpaque,
				Data:                []byte(`not JSON`),
				DecimalDisplay:      fn.Some[uint32](0),
				UniverseCommitments: true,
				CanonicalUniverses:  oneURL,
				DelegationKey:       fn.MaybeSome(dummyKey),
			},
			expectedErr: nil,
		},
		{
			name: "new asset meta reveal with two URLs",
			reveal: &MetaReveal{
				Type:               MetaOpaque,
				Data:               []byte(`not JSON`),
				CanonicalUniverses: twoURL,
			},
			expectedErr: nil,
		},
		{
			name: "universe URL too long",
			reveal: &MetaReveal{
				Type:               MetaOpaque,
				Data:               []byte(`not JSON`),
				CanonicalUniverses: twoURLTooLong,
			},
			expectedErr: ErrCanonicalUniverseURLTooLong,
		},
		{
			name: "empty universe URL slice",
			reveal: &MetaReveal{
				Type:               MetaOpaque,
				Data:               []byte(`not JSON`),
				CanonicalUniverses: fn.Some[[]url.URL](nil),
			},
			expectedErr: ErrCanonicalUniverseInvalid,
		},
		{
			name: "empty delegation key",
			reveal: &MetaReveal{
				Type:          MetaOpaque,
				Data:          []byte(`not JSON`),
				DelegationKey: fn.Some(emptyKey),
			},
			expectedErr: ErrDelegationKeyEmpty,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()

			err := tc.reveal.Validate()
			if tc.expectedErr == nil {
				require.NoError(tt, err)
				return
			}

			require.Error(tt, err)
			require.ErrorIs(tt, err, tc.expectedErr)
		})
	}
}

// TestProofInvalidJsonMetaReveal tests that a proof with a meta reveal that
// is declared as JSON but is not valid JSON will return the correct error when
// trying to decode the decimal display.
func TestProofInvalidJsonMetaReveal(t *testing.T) {
	proofHex, err := os.ReadFile(proofInvalidJsonHexFileName)
	require.NoError(t, err)

	proofBytes, err := hex.DecodeString(
		strings.Trim(string(proofHex), "\n"),
	)
	require.NoError(t, err)

	p := &Proof{}
	err = p.Decode(bytes.NewReader(proofBytes))
	require.NoError(t, err)

	require.NotNil(t, p.MetaReveal)

	_, decDisplay, err := p.MetaReveal.GetDecDisplay()
	require.ErrorIs(t, err, ErrInvalidJSON)
	require.Zero(t, decDisplay)
}

// TestMetaRevealUnknownOddType tests that an unknown odd type is allowed in a
// meta reveal and that we can still arrive at the correct meta hash with it.
func TestMetaRevealUnknownOddType(t *testing.T) {
	knownMeta := &MetaReveal{
		Type: 123,
		Data: []byte("probably some JPEG or something"),
	}
	knownMetaHash := knownMeta.MetaHash()

	test.RunUnknownOddTypeTest(
		t, knownMeta, &asset.ErrUnknownType{},
		func(buf *bytes.Buffer, meta *MetaReveal) error {
			return meta.Encode(buf)
		},
		func(buf *bytes.Buffer) (*MetaReveal, error) {
			var parsedMeta MetaReveal
			return &parsedMeta, parsedMeta.Decode(buf)
		},
		func(parsedMeta *MetaReveal, unknownTypes tlv.TypeMap) {
			require.Equal(
				t, unknownTypes, parsedMeta.UnknownOddTypes,
			)

			// The meta should've changed, to make sure the unknown
			// value was taken into account when creating the
			// serialized meta.
			parsedMetaHash := parsedMeta.MetaHash()

			require.NotEqual(t, knownMetaHash, parsedMetaHash)

			parsedMeta.UnknownOddTypes = nil
			require.Equal(t, knownMeta, parsedMeta)
		},
	)
}

// TestMetaDataRevealEncoding tests the encoding and decoding of valid meta
// reveal structs.
func TestMetaDataRevealEncoding(t *testing.T) {
	t.Parallel()

	dummyURL, err := url.Parse("universerpc://localhost:1234")
	require.NoError(t, err)

	dummyURL2, err := url.Parse("universerpc://another-host:765")
	require.NoError(t, err)

	oneURL := fn.Some[[]url.URL]([]url.URL{*dummyURL})
	twoURL := fn.Some[[]url.URL]([]url.URL{*dummyURL, *dummyURL2})

	testCases := []struct {
		name     string
		reveal   *MetaReveal
		expected []byte
	}{
		{
			name: "valid reveal",
			reveal: &MetaReveal{
				Type: MetaOpaque,
				Data: []byte("data"),
			},
			expected: []byte{
				0x00, 0x01, 0x00, // Type
				0x02, 0x04, 0x64, 0x61, 0x74, 0x61, // Data
			},
		},
		{
			name: "valid JSON reveal",
			reveal: &MetaReveal{
				Type: MetaJson,
				Data: []byte(`{"key": "value"}`),
			},
			expected: append([]byte{
				0x00, 0x01, 0x01, // Type
				0x02, 0x10, // Data
			}, []byte(`{"key": "value"}`)...),
		},
		{
			name: "valid custom reveal",
			reveal: &MetaReveal{
				Type: MetaType(99),
				Data: []byte("custom stuff"),
			},
			expected: []byte{
				0x00, 0x01, 0x63, // Type
				0x02, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d,
				0x20, 0x73, 0x74, 0x75, 0x66, 0x66, // Data
			},
		},
		{
			name: "correct decimal display",
			reveal: &MetaReveal{
				Type:           MetaJson,
				Data:           []byte(`{"key": "value"}`),
				DecimalDisplay: fn.Some[uint32](8),
			},
			expected: []byte{
				0x00, 0x01, 0x01, // Type
				0x02, 0x10, 0x7b, 0x22, 0x6b, 0x65, 0x79, 0x22,
				0x3a, 0x20, 0x22, 0x76, 0x61, 0x6c, 0x75, 0x65,
				0x22, 0x7d, // Data
				0x05, 0x04, 0x00, 0x00, 0x00, 0x8, // DecDisplay
			},
		},
		{
			name: "correct non-JSON, all fields",
			reveal: &MetaReveal{
				Type:                MetaOpaque,
				Data:                []byte(`not JSON`),
				DecimalDisplay:      fn.Some[uint32](8),
				UniverseCommitments: true,
				CanonicalUniverses:  oneURL,
				DelegationKey: fn.MaybeSome(
					asset.NUMSPubKey,
				),
			},
			expected: []byte{
				0x00, 0x01, 0x00, // Type
				// Data:
				0x02, 0x08, 0x6e, 0x6f, 0x74, 0x20, 0x4a, 0x53,
				0x4f, 0x4e,
				// DecDisplay:
				0x05, 0x04, 0x00, 0x00, 0x00, 0x08,
				// SupplyCommitments:
				0x07, 0x01, 0x01,
				// CanonicalUniverses:
				0x09, 0x1e, 0x01, 0x1c, 0x75, 0x6e, 0x69, 0x76,
				0x65, 0x72, 0x73, 0x65, 0x72, 0x70, 0x63, 0x3a,
				0x2f, 0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68,
				0x6f, 0x73, 0x74, 0x3a, 0x31, 0x32, 0x33, 0x34,
				// DelegationKey:
				0x0b, 0x21, 0x02, 0x7c, 0x79, 0xb9, 0xb2, 0x6e,
				0x46, 0x38, 0x95, 0xee, 0xf5, 0x67, 0x9d, 0x85,
				0x58, 0x94, 0x2c, 0x86, 0xc4, 0xad, 0x22, 0x33,
				0xad, 0xef, 0x01, 0xbc, 0x3e, 0x6d, 0x54, 0x0b,
				0x36, 0x53, 0xfe,
			},
		},
		{
			name: "correct non-JSON, just URLs",
			reveal: &MetaReveal{
				Type:               MetaOpaque,
				Data:               []byte(`not JSON`),
				CanonicalUniverses: twoURL,
			},
			expected: []byte{
				0x00, 0x01, 0x00, // Type
				// Data:
				0x02, 0x08, 0x6e, 0x6f, 0x74, 0x20, 0x4a, 0x53,
				0x4f, 0x4e,
				// CanonicalUniverses:
				0x09, 0x3d, 0x02,
				0x1c, 0x75, 0x6e, 0x69, 0x76, 0x65, 0x72, 0x73,
				0x65, 0x72, 0x70, 0x63, 0x3a, 0x2f, 0x2f, 0x6c,
				0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
				0x3a, 0x31, 0x32, 0x33, 0x34,
				0x1e, 0x75, 0x6e, 0x69, 0x76, 0x65, 0x72, 0x73,
				0x65, 0x72, 0x70, 0x63, 0x3a, 0x2f, 0x2f, 0x61,
				0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x2d, 0x68,
				0x6f, 0x73, 0x74, 0x3a, 0x37, 0x36, 0x35,
			},
		},
		{
			name: "new asset meta reveal with explicit zero " +
				"decimal display",
			reveal: &MetaReveal{
				Type:           MetaOpaque,
				Data:           []byte(`not JSON`),
				DecimalDisplay: fn.Some[uint32](0),
			},
			expected: []byte{
				0x00, 0x01, 0x00, // Type
				// Data:
				0x02, 0x08, 0x6e, 0x6f, 0x74, 0x20, 0x4a, 0x53,
				0x4f, 0x4e,
				// DecDisplay:
				0x05, 0x04, 0x00, 0x00, 0x00, 0x00,
			},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()

			var buf bytes.Buffer
			err := tc.reveal.Encode(&buf)
			require.NoError(tt, err)

			rawBytes := buf.Bytes()
			require.Equal(tt, tc.expected, rawBytes)

			decoded := &MetaReveal{}
			err = decoded.Decode(&buf)
			require.NoError(tt, err)

			require.Equal(tt, tc.reveal, decoded)
		})
	}
}

// TestDecodeOldMetaReveal tests decoding an old MetaReveal encoding that does
// not include the decimal display.
func TestDecodeOldMetaReveal(t *testing.T) {
	metaWithoutDecimalDisplay := []byte{
		0x00,                   // Type (0, MetaRevealEncodingType)
		0x01,                   // Length (1)
		0x00,                   // Value (0, MetaOpaque)
		0x02,                   // Type (1, MetaRevealDataType)
		0x04,                   // Length (4)
		0x64, 0x61, 0x74, 0x61, // Value ("data")
	}

	var decoded MetaReveal
	err := decoded.Decode(bytes.NewReader(metaWithoutDecimalDisplay))
	require.NoError(t, err)

	require.Equal(t, MetaOpaque, decoded.Type)
	require.Equal(t, []byte("data"), decoded.Data)
	require.Equal(t, fn.None[uint32](), decoded.DecimalDisplay)
	require.Equal(t, false, decoded.UniverseCommitments)
	require.Equal(t, fn.None[[]url.URL](), decoded.CanonicalUniverses)
	require.Equal(t, fn.None[btcec.PublicKey](), decoded.DelegationKey)
}

// TestDecodeNewMetaReveal tests that an old client with the old MetaReveal
// decoding fields does not fail when presented with a new MetaReveal encoding
// that includes the decimal display.
func TestDecodeNewMetaReveal(t *testing.T) {
	metaWithDecimalDisplay := []byte{
		0x00, 0x01, 0x01, // Type
		0x02, 0x10, 0x7b, 0x22, 0x6b, 0x65, 0x79, 0x22,
		0x3a, 0x20, 0x22, 0x76, 0x61, 0x6c, 0x75, 0x65,
		0x22, 0x7d, // Data
		0x05, 0x04, 0x00, 0x00, 0x00, 0x8, // DecDisplay
	}

	var decoded MetaReveal

	oldDecodeRecords := []tlv.Record{
		MetaRevealTypeRecord(&decoded.Type),
		MetaRevealDataRecord(&decoded.Data),
	}

	stream, err := tlv.NewStream(oldDecodeRecords...)
	require.NoError(t, err)

	err = stream.Decode(bytes.NewReader(metaWithDecimalDisplay))
	require.NoError(t, err)

	require.Equal(t, MetaJson, decoded.Type)
	require.Equal(t, []byte(`{"key": "value"}`), decoded.Data)
	require.Equal(t, fn.None[uint32](), decoded.DecimalDisplay)
	require.Equal(t, false, decoded.UniverseCommitments)
	require.Equal(t, fn.None[[]url.URL](), decoded.CanonicalUniverses)
	require.Equal(t, fn.None[btcec.PublicKey](), decoded.DelegationKey)
}

// TestDecodeMetaJSONEmptyBytes tests DecodeMetaJSON with an empty byte slice.
func TestDecodeMetaJSONEmptyBytes(t *testing.T) {
	t.Parallel()

	_, err := DecodeMetaJSON([]byte{})
	require.ErrorIs(t, err, ErrInvalidJSON)
}

// TestEncodeMetaJSONEmptyOrNilMap tests EncodeMetaJSON with nil and empty maps.
func TestEncodeMetaJSONEmptyOrNilMap(t *testing.T) {
	t.Parallel()

	t.Run("nil map", func(t *testing.T) {
		nilMapBytes, err := EncodeMetaJSON(nil)
		require.NoError(t, err)
		require.Equal(
			t, []byte{}, nilMapBytes,
			"encoding nil map should produce empty bytes",
		)
	})

	t.Run("empty map", func(t *testing.T) {
		emptyMap := make(map[string]interface{})
		emptyMapBytes, err := EncodeMetaJSON(emptyMap)
		require.NoError(t, err)
		require.Equal(t, []byte("{}"), emptyMapBytes,
			"Encoding empty map should produce '{}'")
	})
}

// simpleJSONMap is a helper struct for generating map[string]interface{}
// values for property-based testing.
type simpleJSONMap struct {
	StringEntries map[string]string
	FloatEntries  map[string]float64
	BoolEntries   map[string]bool
}

// toMap converts a simpleJSONMap to a map[string]interface{}.
func (s simpleJSONMap) toMap() map[string]interface{} {
	m := make(map[string]interface{})
	for k, v := range s.StringEntries {
		// To avoid key collisions if rapid generates identical keys for
		// different entry types, we could prefix them, but for
		// simplicity, we'll assume distinct keys or accept overwrites
		// if rapid generates identical string keys for different map
		// types (unlikely to be an issue for typical map generation).
		m[k] = v
	}
	for k, v := range s.FloatEntries {
		m[k] = v
	}
	for k, v := range s.BoolEntries {
		m[k] = v
	}
	return m
}

// TestMetaJsonEncodeDecodeProperties tests the EncodeMetaJSON and
// DecodeMetaJSON functions using property-based testing. It ensures that
// encoding and then decoding a map yields the original map.
func TestMetaJsonEncodeDecodeProperties(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		// Generate a simpleJSONMap instance.
		sjm := rapid.Custom(func(t *rapid.T) simpleJSONMap {
			return simpleJSONMap{
				StringEntries: rapid.MapOf(
					rapid.String(), rapid.String(),
				).Draw(t, "StringEntries"),
				FloatEntries: rapid.MapOf(
					rapid.String(), rapid.Float64(),
				).Draw(t, "FloatEntries"),
				BoolEntries: rapid.MapOf(
					rapid.String(), rapid.Bool(),
				).Draw(t, "BoolEntries"),
			}
		}).Draw(rt, "sjm")

		originalMap := sjm.toMap()

		encodedBytes, err := EncodeMetaJSON(originalMap)
		if err != nil {
			// If the generated map is too large, EncodeMetaJSON
			// will return ErrMetaDataTooLarge. This is an expected
			// behavior, not a property failure.
			if errors.Is(err, ErrMetaDataTooLarge) {
				return
			}

			// Any other encoding error is a failure.
			rt.Fatalf("EncodeMetaJSON failed for map %#v: %v",
				originalMap, err)
		}

		decodedMap, err := DecodeMetaJSON(encodedBytes)
		if err != nil {
			rt.Fatalf("DecodeMetaJSON failed for bytes %s "+
				"(from map %#v): %v",
				string(encodedBytes), originalMap, err)
		}

		if !reflect.DeepEqual(originalMap, decodedMap) {
			rt.Fatalf("Decoded map does not match original map.\n"+
				"Original: %#v\nEncoded:  %s\nDecoded:  %#v",
				originalMap, string(encodedBytes), decodedMap)
		}
	})
}

// TestDecodeMetaJSONOversizedProperty tests that DecodeMetaJSON returns an
// error when the input byte slice is larger than MetaDataMaxSizeBytes.
func TestDecodeMetaJSONOversizedProperty(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		// Generate a byte slice that is guaranteed to be too large. We
		// add a small delta to avoid generating slices that are
		// excessively large and slow down the test.
		oversizedBytes := rapid.SliceOfN(
			rapid.Byte(),
			MetaDataMaxSizeBytes+1,
			MetaDataMaxSizeBytes+10,
		).Draw(rt, "oversizedBytes")

		_, err := DecodeMetaJSON(oversizedBytes)
		require.ErrorIs(rt, err, ErrMetaDataTooLarge)
	})
}

// TestDecodeMetaJSONInvalidJSONProperty tests that DecodeMetaJSON returns an
// error for byte slices that are not valid JSON but are within size limits.
func TestDecodeMetaJSONInvalidJSONProperty(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		// Generate a byte slice that is within the size limit. There's
		// a high chance this random byte slice won't be valid JSON.
		inputBytes := rapid.SliceOfN(
			rapid.Byte(),
			0, MetaDataMaxSizeBytes,
		).Draw(rt, "inputBytes")

		// If, by chance, we generated valid JSON or an empty slice
		// (which DecodeMetaJSON handles as valid empty JSON), we skip
		// this iteration as we want to test invalid JSON.
		// DecodeMetaJSON considers empty bytes as valid (empty map).
		if json.Valid(inputBytes) {
			rt.Skip("Generated valid JSON or empty " +
				"slice, skipping to test invalid case")
			return
		}

		_, err := DecodeMetaJSON(inputBytes)
		require.ErrorIs(rt, err, ErrInvalidJSON)
	})
}
