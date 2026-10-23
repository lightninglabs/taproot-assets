package rfqmsg

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestOracleMetadataLimit checks that decoding enforces the metadata limit
// without rejecting an empty field or a field exactly at the limit.
func TestOracleMetadataLimit(t *testing.T) {
	t.Parallel()

	sizes := []int{0, MaxOracleMetadataLength, MaxOracleMetadataLength + 1}
	for _, size := range sizes {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			value := bytes.Repeat([]byte{42}, size)
			stream := tlv.MustNewStream(
				tlv.MakePrimitiveRecord(27, &value),
			)
			var encoded bytes.Buffer
			require.NoError(t, stream.Encode(&encoded))

			var decoded requestWireMsgData
			err := decoded.Decode(&encoded)
			if size > MaxOracleMetadataLength {
				require.ErrorIs(t, err, tlv.ErrRecordTooLarge)
				return
			}
			require.NoError(t, err)
			metadata := decoded.PriceOracleMetadata.UnwrapOrFail(t)
			require.Equal(t, value, metadata.Val)
		})
	}
}

// TestRejectErrorLimit covers the smallest and largest valid rejection
// records, as well as an oversized record.
func TestRejectErrorLimit(t *testing.T) {
	t.Parallel()

	sizes := []int{1, tlv.MaxRecordSize, tlv.MaxRecordSize + 1}
	for _, size := range sizes {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			var decoded RejectErr
			var scratch [8]byte
			err := rejectErrDecoder(
				bytes.NewReader(make([]byte, size)), &decoded,
				&scratch, uint64(size),
			)
			if size > tlv.MaxRecordSize {
				require.ErrorIs(t, err, tlv.ErrRecordTooLarge)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
