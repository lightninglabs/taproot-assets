package rfqmsg

import (
	"bytes"
	"testing"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/stretchr/testify/require"
)

// TestHtlc tests encoding and decoding of the Htlc struct.
func TestHtlc(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		htlc *Htlc
	}{
		{
			name: "empty HTLC",
			htlc: &Htlc{},
		},
		{
			name: "HTLC with balance asset",
			htlc: NewHtlc([]*AssetBalance{
				NewAssetBalance([32]byte{1}, 1000),
			}, fn.None[ID]()),
		},
		{
			name: "channel with multiple balance assets",
			htlc: NewHtlc([]*AssetBalance{
				NewAssetBalance([32]byte{1}, 1000),
				NewAssetBalance([32]byte{2}, 2000),
			}, fn.Some(ID{0, 1, 2, 3, 4, 5, 6, 7})),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Serialize the HTLC and then deserialize it again.
			var b bytes.Buffer
			err := tc.htlc.Encode(&b)
			require.NoError(t, err)

			deserializedHtlc := &Htlc{}
			err = deserializedHtlc.Decode(&b)
			require.NoError(t, err)

			require.Equal(t, tc.htlc, deserializedHtlc)
		})
	}
}
