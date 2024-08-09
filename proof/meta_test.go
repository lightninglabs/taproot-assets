package proof

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

var (
	// proofInvalidJsonHexFileName is the name of the file that contains the
	// hex proof data for a proof where the meta type is declared as JSON
	// but the data is not valid JSON.
	proofInvalidJsonHexFileName = filepath.Join(
		testDataFileName, "proof-invalid-json-meta-reveal.hex",
	)
)

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

	var buf bytes.Buffer
	err := knownMeta.Encode(&buf)
	require.NoError(t, err)

	// With the known meta reveal now encoded, we can add an unknown even
	// type to the encoded bytes. That should provoke an error when parsed
	// again.
	unknownTypeValue := []byte("I could be anything, really")
	unknownEvenType := append([]byte{
		byte(40),                    // Type 40 is unknown.
		byte(len(unknownTypeValue)), // Length of the value.
	}, unknownTypeValue...)
	buf.Write(unknownEvenType)

	// Try to parse it again.
	var parsedMeta MetaReveal
	err = parsedMeta.Decode(&buf)
	require.ErrorAs(t, err, &asset.ErrUnknownType{})

	// Now clear the buffer, encode the meta reveal again, but this time add
	// an unknown _odd_ type, which should be allowed.
	unknownOddType := append([]byte{
		byte(39),                    // Type 39 is unknown.
		byte(len(unknownTypeValue)), // Length of the value.
	}, unknownTypeValue...)
	buf.Reset()
	err = knownMeta.Encode(&buf)
	require.NoError(t, err)
	buf.Write(unknownOddType)

	err = parsedMeta.Decode(&buf)
	require.NoError(t, err)

	expectedUnknownTypes := tlv.TypeMap{
		39: unknownTypeValue,
	}
	require.Equal(t, expectedUnknownTypes, parsedMeta.unknownOddTypes)

	// The leaf should've changed, to make sure the unknown value was taken
	// into account when creating the serialized leaf.
	parsedMetaHash := parsedMeta.MetaHash()

	require.NotEqual(t, knownMetaHash, parsedMetaHash)
}
