package proof

import (
	"bytes"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// TestSendFragmentEncodeDecode tests the encoding and decoding of SendFragment
// structs.
func TestSendFragmentEncodeDecode(t *testing.T) {
	output1 := SendOutput{
		AssetVersion:     asset.Version(1),
		Amount:           100,
		DerivationMethod: asset.ScriptKeyDerivationUniquePedersen,
		ScriptKey:        asset.SerializedKey{0x04},
	}
	output2 := SendOutput{
		AssetVersion:     asset.Version(2),
		Amount:           200,
		DerivationMethod: asset.ScriptKeyDerivationUniquePedersen,
		ScriptKey:        asset.SerializedKey{0x05, 0x06},
	}

	tests := []struct {
		name     string
		fragment SendFragment
	}{
		{
			name: "basic fragment",
			fragment: SendFragment{
				Version: SendFragmentV1,
				BlockHeader: wire.BlockHeader{
					Version:    1,
					PrevBlock:  [32]byte{0x01},
					MerkleRoot: [32]byte{0x02},
					Timestamp:  time.Unix(1234567890, 0),
					Bits:       0x1d00ffff,
					Nonce:      0,
				},
				BlockHeight: 1234,
				OutPoint: wire.OutPoint{
					Hash:  [32]byte{0x03},
					Index: 1,
				},
				Outputs: map[asset.ID]SendOutput{
					{0x01}: output1,
					{0x02}: output2,
				},
				TaprootAssetRoot: [32]byte{
					0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
				},
				UnknownOddTypes: tlv.TypeMap{
					0x1001: []byte{0x05, 0x06},
				},
			},
		},
		{
			name: "empty fragment",
			fragment: SendFragment{
				Version: SendFragmentV1,
				BlockHeader: wire.BlockHeader{
					Timestamp: time.Unix(1234567890, 0),
				},
				Outputs: map[asset.ID]SendOutput{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode the fragment.
			var buf bytes.Buffer
			err := tt.fragment.Encode(&buf)
			require.NoError(t, err)

			// Decode the fragment.
			var decodedFragment SendFragment
			err = decodedFragment.Decode(&buf)
			require.NoError(t, err)

			// Verify the decoded fragment matches the original.
			require.Equal(t, tt.fragment, decodedFragment)
		})
	}
}
