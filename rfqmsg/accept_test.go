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

// buildBuyAcceptWire constructs a wire-encoded buy Accept message
// originating from sender, in response to request.
func buildBuyAcceptWire(t *testing.T, sender route.Vertex,
	request BuyRequest) WireMessage {

	t.Helper()

	rate := rfqmath.NewBigIntFixedPoint(42_000, 0)
	assetRate := NewAssetRate(rate, time.Now().Add(time.Hour))
	accept := NewBuyAcceptFromRequest(request, assetRate, fn.None[uint64]())

	msgData, err := newAcceptWireMsgDataFromBuy(*accept)
	require.NoError(t, err)

	data, err := msgData.Bytes()
	require.NoError(t, err)

	return WireMessage{
		Peer:    sender,
		MsgType: MsgTypeAccept,
		Data:    data,
	}
}

// TestIncomingAcceptPeerBinding verifies that
// NewIncomingAcceptFromWire only accepts an Accept whose wire-level
// sender matches the peer the original Request was sent to.
func TestIncomingAcceptPeerBinding(t *testing.T) {
	t.Parallel()

	requestPeer := route.Vertex{0x01}
	otherPeer := route.Vertex{0x02}
	spec := asset.NewSpecifierFromId(asset.ID{0xAA})

	request, err := NewBuyRequest(
		requestPeer, spec, 100, fn.None[uint64](),
		fn.None[rfqmath.BigIntFixedPoint](),
		fn.None[AssetRate](), "",
		fn.None[ExecutionPolicy](),
	)
	require.NoError(t, err)

	lookup := func(id ID) (OutgoingMsg, bool) {
		if id != request.ID {
			return nil, false
		}
		return request, true
	}

	t.Run("matching peer accepted", func(tt *testing.T) {
		wire := buildBuyAcceptWire(tt, requestPeer, *request)

		msg, err := NewIncomingAcceptFromWire(wire, lookup)
		require.NoError(tt, err)

		ba, ok := msg.(*BuyAccept)
		require.True(tt, ok)
		require.Equal(tt, requestPeer, ba.Peer)
	})

	t.Run("mismatched peer rejected", func(tt *testing.T) {
		wire := buildBuyAcceptWire(tt, otherPeer, *request)

		_, err := NewIncomingAcceptFromWire(wire, lookup)
		require.ErrorContains(tt, err, "does not match original "+
			"request peer")
	})
}
