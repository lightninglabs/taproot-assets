package asset

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/stretchr/testify/require"
)

// TestGenChallengeNUMS tests the generation of NUMS challenges.
func TestGenChallengeNUMS(t *testing.T) {
	t.Parallel()

	gx, gy := secp256k1.Params().Gx, secp256k1.Params().Gy

	// addG is a helper function that adds G to the given public key.
	addG := func(p *btcec.PublicKey) *btcec.PublicKey {
		x, y := secp256k1.S256().Add(p.X(), p.Y(), gx, gy)
		var xFieldVal, yFieldVal secp256k1.FieldVal
		xFieldVal.SetByteSlice(x.Bytes())
		yFieldVal.SetByteSlice(y.Bytes())
		return btcec.NewPublicKey(&xFieldVal, &yFieldVal)
	}

	testCases := []struct {
		name        string
		challenge   fn.Option[[32]byte]
		expectedKey ScriptKey
	}{
		{
			name:        "no challenge",
			challenge:   fn.None[[32]byte](),
			expectedKey: NUMSScriptKey,
		},
		{
			name: "challenge is scalar 1",
			challenge: fn.Some([32]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			}),
			expectedKey: NewScriptKey(addG(NUMSPubKey)),
		},
		{
			name: "challenge is scalar 2",
			challenge: fn.Some([32]byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
			}),
			expectedKey: NewScriptKey(addG(addG(NUMSPubKey))),
		},
	}

	for _, tc := range testCases {
		result := GenChallengeNUMS(tc.challenge)
		require.Equal(
			t, tc.expectedKey.PubKey.SerializeCompressed(),
			result.PubKey.SerializeCompressed(),
		)
	}
}
