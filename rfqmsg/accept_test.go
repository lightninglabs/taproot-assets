package rfqmsg

import (
	"bytes"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// acceptEncodeDecodeTC is a test case for encoding and decoding a
// acceptWireMsgData.
type acceptEncodeDecodeTC struct {
	testName string

	version      WireMsgDataVersion
	id           ID
	expiry       uint64
	sig          [64]byte
	inAssetRate  TlvFixedPoint
	outAssetRate TlvFixedPoint
}

// MsgData generates a acceptWireMsgData instance from the test case.
func (tc acceptEncodeDecodeTC) MsgData() acceptWireMsgData {
	version := tlv.NewPrimitiveRecord[tlv.TlvType0](tc.version)
	id := tlv.NewPrimitiveRecord[tlv.TlvType2](tc.id)
	expiry := tlv.NewPrimitiveRecord[tlv.TlvType4](tc.expiry)
	sig := tlv.NewPrimitiveRecord[tlv.TlvType6](tc.sig)
	inAssetRate := tlv.NewRecordT[tlv.TlvType8](tc.inAssetRate)
	outAssetRate := tlv.NewRecordT[tlv.TlvType10](tc.outAssetRate)

	return acceptWireMsgData{
		Version:      version,
		ID:           id,
		Expiry:       expiry,
		Sig:          sig,
		InAssetRate:  inAssetRate,
		OutAssetRate: outAssetRate,
	}
}

// TestAcceptMsgDataEncodeDecode tests acceptWireMsgData encoding/decoding.
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

	inOutRateTick := NewTlvFixedPointFromUint64(42000, 0)
	outInRateTick := NewTlvFixedPointFromUint64(22000, 0)

	testCases := []acceptEncodeDecodeTC{
		{
			testName: "rand sig, in-out rate tick set, out-in " +
				"rate tick unset",
			version:      V1,
			id:           id,
			expiry:       expiry,
			sig:          randSig,
			inAssetRate:  inOutRateTick,
			outAssetRate: outInRateTick,
		},
		{
			testName: "zero sig, in-out rate tick unset, out-in " +
				"rate tick set",
			version:      V1,
			id:           id,
			expiry:       expiry,
			sig:          zeroSig,
			inAssetRate:  inOutRateTick,
			outAssetRate: outInRateTick,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(tt *testing.T) {
			msgData := tc.MsgData()

			// Encode the message.
			msgDataBytes, err := msgData.Bytes()
			require.NoError(tt, err, "unable to encode message")

			// Decode the message.
			decodedMsgData := acceptWireMsgData{}
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
