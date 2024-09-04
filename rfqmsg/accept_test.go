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
// AcceptWireMsg.
type acceptEncodeDecodeTC struct {
	testName string

	version WireMsgDataVersion
	id      ID
	expiry  uint64
	sig     [64]byte

	inOutRateTick *uint64
	outInRateTick *uint64
}

// MsgData generates a AcceptWireMsg instance from the test case.
func (tc acceptEncodeDecodeTC) MsgData() AcceptWireMsg {
	version := tlv.NewPrimitiveRecord[tlv.TlvType0](tc.version)
	id := tlv.NewPrimitiveRecord[tlv.TlvType1](tc.id)
	expiry := tlv.NewPrimitiveRecord[tlv.TlvType2](tc.expiry)
	sig := tlv.NewPrimitiveRecord[tlv.TlvType3](tc.sig)

	var inOutRateTick acceptInOutRateTick
	if tc.inOutRateTick != nil {
		inOutRateTick = tlv.SomeRecordT[tlv.TlvType4](
			tlv.NewPrimitiveRecord[tlv.TlvType4](
				*tc.inOutRateTick,
			),
		)
	}

	var outInRateTick acceptOutInRateTick
	if tc.outInRateTick != nil {
		outInRateTick = tlv.SomeRecordT[tlv.TlvType5](
			tlv.NewPrimitiveRecord[tlv.TlvType5](
				*tc.outInRateTick,
			),
		)
	}

	return AcceptWireMsg{
		Version:       version,
		ID:            id,
		Expiry:        expiry,
		Sig:           sig,
		InOutRateTick: inOutRateTick,
		OutInRateTick: outInRateTick,
	}
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

	inOutRateTick := uint64(42000)
	outInRateTick := uint64(22000)

	testCases := []acceptEncodeDecodeTC{
		{
			testName: "rand sig, in-out rate tick set, out-in " +
				"rate tick unset",
			version:       0,
			id:            id,
			expiry:        expiry,
			sig:           randSig,
			inOutRateTick: &inOutRateTick,
		},
		{
			testName: "rand sig, in-out rate tick unset, out-in " +
				"rate tick set",
			version:       0,
			id:            id,
			expiry:        expiry,
			sig:           randSig,
			outInRateTick: &outInRateTick,
		},
		{
			testName: "zero sig, in-out rate tick unset, out-in " +
				"rate tick set",
			version:       0,
			id:            id,
			expiry:        expiry,
			sig:           zeroSig,
			outInRateTick: &outInRateTick,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(tt *testing.T) {
			msgData := tc.MsgData()

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
