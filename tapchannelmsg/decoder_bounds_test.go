package tapchannelmsg

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestChannelByteRecordLimits covers empty, maximum-sized and oversized
// channel fields through the public decoders that consume them.
func TestChannelByteRecordLimits(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		typ    tlv.Type
		decode func(io.Reader) ([]byte, error)
	}{
		{
			name: "tap tweak",
			typ:  0,
			decode: func(r io.Reader) ([]byte, error) {
				var value TapscriptSigDesc
				err := value.Decode(r)
				return value.TapTweak.Val, err
			},
		},
		{
			name: "control block",
			typ:  1,
			decode: func(r io.Reader) ([]byte, error) {
				var value TapscriptSigDesc
				err := value.Decode(r)
				return value.CtrlBlock.Val, err
			},
		},
		{
			name: "proof chunk",
			typ:  1,
			decode: func(r io.Reader) ([]byte, error) {
				var value ProofChunk
				err := value.Decode(r)
				return value.Chunk.Val, err
			},
		},
	} {
		for _, size := range []int{
			0, tlv.MaxRecordSize, tlv.MaxRecordSize + 1,
		} {
			name := fmt.Sprintf("%s/%d", test.name, size)
			t.Run(name, func(t *testing.T) {
				value := bytes.Repeat([]byte{42}, size)
				record := tlv.MakePrimitiveRecord(
					test.typ, &value,
				)
				stream := tlv.MustNewStream(record)
				var encoded bytes.Buffer
				require.NoError(t, stream.Encode(&encoded))
				decoded, err := test.decode(&encoded)
				if size > tlv.MaxRecordSize {
					require.ErrorIs(
						t, err, tlv.ErrRecordTooLarge,
					)
					return
				}
				require.NoError(t, err)
				require.Equal(t, value, decoded)
			})
		}
	}
}
