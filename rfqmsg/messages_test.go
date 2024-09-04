package rfqmsg

import (
	"bytes"
	"testing"

	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestUint64FixedPoint tests encoding and decoding of the
// Uint64FixedPoint struct.
func TestUint64FixedPoint(t *testing.T) {
	type testStruct struct {
		ExchangeRate tlv.RecordT[tlv.TlvType1, Uint64FixedPoint]
	}

	foo := &testStruct{
		ExchangeRate: tlv.NewRecordT[tlv.TlvType1](
			NewUint64FixedPoint(123456789, 7),
		),
	}

	tlvStream, err := tlv.NewStream(foo.ExchangeRate.Record())
	require.NoError(t, err)

	var buf bytes.Buffer
	err = tlvStream.Encode(&buf)
	require.NoError(t, err)

	decodedFoo := &testStruct{}

	tlvStream, err = tlv.NewStream(decodedFoo.ExchangeRate.Record())
	require.NoError(t, err)

	err = tlvStream.Decode(&buf)
	require.NoError(t, err)

	require.Equal(t, foo, decodedFoo)
}
