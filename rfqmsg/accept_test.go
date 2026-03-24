package rfqmsg

import (
	"bytes"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightningnetwork/lnd/routing/route"
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
	maxInAsset   acceptMaxInAsset
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
		MaxInAsset:   tc.maxInAsset,
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

	inAssetRate := NewTlvFixedPointFromUint64(42000, 0)
	outAssetRate := NewTlvFixedPointFromUint64(22000, 0)

	testCases := []acceptEncodeDecodeTC{
		{
			testName:     "rand sig, asset rates set",
			version:      V1,
			id:           id,
			expiry:       expiry,
			sig:          randSig,
			inAssetRate:  inAssetRate,
			outAssetRate: outAssetRate,
		},
		{
			testName:     "zero sig, asset rates set",
			version:      V1,
			id:           id,
			expiry:       expiry,
			sig:          zeroSig,
			inAssetRate:  inAssetRate,
			outAssetRate: outAssetRate,
		},
		{
			testName:     "with max in-asset fill",
			version:      V1,
			id:           id,
			expiry:       expiry,
			sig:          randSig,
			inAssetRate:  inAssetRate,
			outAssetRate: outAssetRate,
			maxInAsset: tlv.SomeRecordT(
				tlv.NewPrimitiveRecord[tlv.TlvType11](
					uint64(500),
				),
			),
		},
		{
			testName:     "no max in-asset fill",
			version:      V1,
			id:           id,
			expiry:       expiry,
			sig:          randSig,
			inAssetRate:  inAssetRate,
			outAssetRate: outAssetRate,
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

	// Verify that a zero fill value on the wire is normalised to
	// None during decode.
	t.Run("zero max in-asset normalised to None", func(tt *testing.T) {
		zeroFill := acceptEncodeDecodeTC{
			testName:     "zero fill",
			version:      V1,
			id:           id,
			expiry:       expiry,
			sig:          randSig,
			inAssetRate:  inAssetRate,
			outAssetRate: outAssetRate,
			maxInAsset: tlv.SomeRecordT(
				tlv.NewPrimitiveRecord[tlv.TlvType11](
					uint64(0),
				),
			),
		}
		msgData := zeroFill.MsgData()

		msgDataBytes, err := msgData.Bytes()
		require.NoError(tt, err)

		var decoded acceptWireMsgData
		err = decoded.Decode(bytes.NewReader(msgDataBytes))
		require.NoError(tt, err)

		// Zero should have been normalised away.
		require.True(tt, decoded.MaxInAsset.IsNone())
	})
}

func TestNewIncomingAcceptFromWireRejectsMismatchedRequestID(t *testing.T) {
	t.Parallel()

	peer := route.Vertex{0x01}
	spec := asset.NewSpecifierFromId(asset.ID{0xAA})
	req1, err := NewBuyRequest(
		peer, spec, 100, fn.None[uint64](),
		fn.None[rfqmath.BigIntFixedPoint](),
		fn.None[AssetRate](), "",
		fn.None[ExecutionPolicy](),
	)
	require.NoError(t, err)

	req2, err := NewBuyRequest(
		peer, spec, 100, fn.None[uint64](),
		fn.None[rfqmath.BigIntFixedPoint](),
		fn.None[AssetRate](), "",
		fn.None[ExecutionPolicy](),
	)
	require.NoError(t, err)
	require.NotEqual(t, req1.ID, req2.ID)

	accept := NewBuyAcceptFromRequest(
		*req1, NewAssetRate(rfqmath.NewBigIntFixedPoint(42_000, 0),
			time.Now().Add(time.Minute)),
		fn.None[uint64](),
	)
	wireMsg, err := accept.ToWire()
	require.NoError(t, err)

	_, err = NewIncomingAcceptFromWire(
		wireMsg, func(ID) (OutgoingMsg, bool) {
			return req2, true
		},
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match request id")
}
