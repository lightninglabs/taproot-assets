package rfqmsg

import (
	"bytes"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/stretchr/testify/require"
)

// acceptEncodeDecodeTC is a test case for encoding and decoding a
// AcceptWireMsg.
type acceptEncodeDecodeTC struct {
	testName string

	buyAccept BuyAccept
}

// TestAcceptMsgDataEncodeDecode tests AcceptWireMsg encoding/decoding.
func TestAcceptMsgDataEncodeDecode(t *testing.T) {
	t.Parallel()

	// Create a random ID.
	randomIdBytes := test.RandBytes(32)
	id := ID(randomIdBytes)

	// Compute a future expiry timestamp.
	expiry := uint64(time.Now().Add(time.Hour).Unix())

	// Create a signature.
	randomSigBytes := test.RandBytes(64)
	var randSig [64]byte
	copy(randSig[:], randomSigBytes)

	// Crate an all zero signature.
	var zeroSig [64]byte

	inAssetPrice := NewUint64FixedPoint(123456, 7)
	outAssetPrice := NewUint64FixedPoint(9876543, 2)

	testCases := []acceptEncodeDecodeTC{
		{
			testName: "rand sig, in-out rate tick set, out-in " +
				"prices set",
			buyAccept: BuyAccept{
				Version:       1,
				ID:            id,
				Expiry:        expiry,
				sig:           randSig,
				InAssetPrice:  inAssetPrice,
				OutAssetPrice: outAssetPrice,
			},
		},
		{
			testName: "zero sig, in-out rate tick unset, out-in " +
				"prices set",
			buyAccept: BuyAccept{
				Version:       1,
				ID:            id,
				Expiry:        expiry,
				sig:           zeroSig,
				InAssetPrice:  inAssetPrice,
				OutAssetPrice: outAssetPrice,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(tt *testing.T) {
			msgData := newAcceptWireMsgDataFromBuy(tc.buyAccept)

			// Encode the message.
			msgDataBytes, err := msgData.Bytes()
			require.NoError(tt, err, "unable to encode message")

			// Decode the message.
			decodedMsgData := AcceptWireMsg{}
			err = decodedMsgData.Decode(
				bytes.NewReader(msgDataBytes),
			)
			require.NoError(tt, err, "unable to decode message")

			// Assert that the decoded message is equal to
			// the original message.
			require.Equal(tt, msgData, decodedMsgData)
		})
	}
}
