package tapchannelmsg

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"testing"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestBalanceChannelCountBounds rejects counts that cannot fit in the
// remaining input, before allocating either channel slice.
func TestBalanceChannelCountBounds(t *testing.T) {
	t.Parallel()

	for _, pending := range []bool{false, true} {
		for _, count := range []uint64{2, math.MaxUint64} {
			name := fmt.Sprintf(
				"pending=%v/count=%d", pending, count,
			)
			t.Run(name, func(t *testing.T) {
				var encoded bytes.Buffer
				if pending {
					// Start with an empty open commitment.
					encoded.Write([]byte{1, 0})
				}
				require.NoError(t, wire.WriteVarInt(
					&encoded, 0, count,
				))
				encoded.WriteByte(0)

				require.NotPanics(t, func() {
					result, err := ReadBalanceCustomData(
						encoded.Bytes(),
					)
					require.ErrorIs(
						t, err, io.ErrUnexpectedEOF,
					)
					require.Nil(t, result)
				})
			})
		}
	}
}

// TestBalanceChannelCountCompatibility preserves zero counts, empty TLV
// commitments, and counts larger than a single-byte varint can encode.
func TestBalanceChannelCountCompatibility(t *testing.T) {
	t.Parallel()

	for _, counts := range [][2]int{{0, 0}, {1, 0}, {0, 1}, {253, 253}} {
		name := fmt.Sprintf("open=%d/pending=%d", counts[0], counts[1])
		t.Run(name, func(t *testing.T) {
			var encoded bytes.Buffer
			for _, count := range counts {
				require.NoError(t, wire.WriteVarInt(
					&encoded, 0, uint64(count),
				))
				// Empty commitments have a one-byte prefix.
				encoded.Write(make([]byte, count))
			}
			result, err := ReadBalanceCustomData(encoded.Bytes())
			require.NoError(t, err)
			require.Len(t, result.OpenChannels, counts[0])
			require.Len(t, result.PendingChannels, counts[1])
			for _, commitment := range append(
				result.OpenChannels, result.PendingChannels...,
			) {
				require.NotNil(t, commitment)
			}
		})
	}
}

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
