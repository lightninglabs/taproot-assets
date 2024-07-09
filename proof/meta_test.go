package proof

import (
	"bytes"
	"testing"

	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestValidateMetaReveal tests the validation of a MetaReveal.
func TestValidateMetaReveal(t *testing.T) {
	t.Parallel()

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
			expectedErr: ErrMetaDataMissing,
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
				DecimalDisplay: 999,
			},
			expectedErr: ErrDecDisplayTooLarge,
		},
		{
			name: "correct decimal display",
			reveal: &MetaReveal{
				Type:           MetaJson,
				Data:           []byte(`{"key": "value"}`),
				DecimalDisplay: 8,
			},
			expectedErr: nil,
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

// TestMetaDataRevealEncoding tests the encoding and decoding of valid meta
// reveal structs.
func TestMetaDataRevealEncoding(t *testing.T) {
	t.Parallel()

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
				DecimalDisplay: 8,
			},
			expected: []byte{
				0x00, 0x01, 0x01, // Type
				0x02, 0x10, 0x7b, 0x22, 0x6b, 0x65, 0x79, 0x22,
				0x3a, 0x20, 0x22, 0x76, 0x61, 0x6c, 0x75, 0x65,
				0x22, 0x7d, // Data
				0x03, 0x04, 0x00, 0x00, 0x00, 0x8, // DecDisplay
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
	require.Equal(t, uint32(0), decoded.DecimalDisplay)
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
		0x03, 0x04, 0x00, 0x00, 0x00, 0x8, // DecDisplay
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
	require.Equal(t, uint32(0), decoded.DecimalDisplay)
}
