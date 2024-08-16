package test

import (
	"bytes"
	"testing"

	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

var (
	// TestVectorAllowedUnknownType is a custom odd TLV type that can be
	// used in test vectors to verify that unknown odd types are allowed.
	TestVectorAllowedUnknownType tlv.Type = 31337
)

// RunUnknownOddTypeTest is a generic test that can be used to test the behavior
// of a TLV decoding function when an unknown odd type is encountered. The test
// will encode a known item, add an unknown even type to the encoded bytes, and
// verify that the decoding function returns an error. It will then encode the
// known item again, add an unknown odd type, and verify that the decoding
// function returns the expected item and unknown types.
func RunUnknownOddTypeTest[T any](t *testing.T, knownItem T,
	unknownTypeErr error, encode func(*bytes.Buffer, T) error,
	decode func(*bytes.Buffer) (T, error), verify func(T, tlv.TypeMap)) {

	var buf bytes.Buffer
	err := encode(&buf, knownItem)
	require.NoError(t, err)

	// With the known item now encoded, we can add an unknown even type to
	// the encoded bytes. That should provoke an error when parsed again.
	unknownTypeValue := []byte("I could be anything, really")
	unknownEvenType := append([]byte{
		byte(40),                    // Type 40 is unknown.
		byte(len(unknownTypeValue)), // Length of the value.
	}, unknownTypeValue...)
	buf.Write(unknownEvenType)

	// Try to parse it again.
	_, err = decode(&buf)
	require.ErrorAs(t, err, unknownTypeErr)

	// Now clear the buffer, encode the item again, but this time add an
	// unknown _odd_ type, which should be allowed.
	unknownOddType := append([]byte{
		byte(39),                    // Type 39 is unknown.
		byte(len(unknownTypeValue)), // Length of the value.
	}, unknownTypeValue...)
	buf.Reset()

	err = encode(&buf, knownItem)
	require.NoError(t, err)
	buf.Write(unknownOddType)

	parsedItem, err := decode(&buf)
	require.NoError(t, err)

	expectedUnknownTypes := tlv.TypeMap{
		39: unknownTypeValue,
	}
	verify(parsedItem, expectedUnknownTypes)
}
