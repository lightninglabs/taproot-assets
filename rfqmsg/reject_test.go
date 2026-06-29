package rfqmsg

import (
	"bytes"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

// TestRejectEncodeDecode tests the encoding and decoding of a reject message.
func TestRejectEncodeDecode(t *testing.T) {
	t.Parallel()

	// Create a random ID.
	randomIdBytes := test.RandBytes(32)
	id := ID(randomIdBytes)

	testCases := []struct {
		testName string

		peer    route.Vertex
		version WireMsgDataVersion
		id      ID
		err     RejectErr
	}{
		{
			testName: "all fields populated with basic values, " +
				"zero version",
			peer:    route.Vertex{1, 2, 3},
			version: 0,
			id:      id,
		},
		{
			testName: "all fields populated with basic values",
			peer:     route.Vertex{1, 2, 3},
			version:  5,
			id:       id,
		},
		{
			testName: "all fields populated with basic values; " +
				"error field populated",
			peer:    route.Vertex{1, 2, 3},
			version: 5,
			id:      id,
			err:     ErrPriceOracleUnavailable,
		},
		{
			testName: "empty error message",
			peer:     route.Vertex{1, 2, 3},
			version:  5,
			id:       id,
			err:      RejectErr{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(tt *testing.T) {
			msg := NewReject(tc.peer, tc.id, tc.err)

			// Encode the message.
			reqBytes, err := msg.Bytes()
			require.NoError(tt, err, "unable to encode message")

			// Decode the message.
			decodedMsg := &Reject{}
			err = decodedMsg.Decode(bytes.NewReader(reqBytes))
			require.NoError(tt, err, "unable to decode message")

			// Assert that the decoded message is equal to the
			// original message.
			require.Equal(
				tt, msg.rejectWireMsgData,
				decodedMsg.rejectWireMsgData,
			)
		})
	}
}

// buildRejectWire constructs a wire-encoded Reject message originating
// from sender, in response to a request with the given ID.
func buildRejectWire(t *testing.T, sender route.Vertex, id ID) WireMessage {
	t.Helper()

	reject := NewReject(sender, id, ErrPriceOracleUnavailable)

	data, err := reject.rejectWireMsgData.Bytes()
	require.NoError(t, err)

	return WireMessage{
		Peer:    sender,
		MsgType: MsgTypeReject,
		Data:    data,
	}
}

// TestIncomingRejectPeerBinding verifies that NewQuoteRejectFromWireMsg
// only accepts a Reject whose wire-level sender matches the peer the
// original Request was sent to.
func TestIncomingRejectPeerBinding(t *testing.T) {
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
		wire := buildRejectWire(tt, requestPeer, request.ID)

		reject, err := NewQuoteRejectFromWireMsg(wire, lookup)
		require.NoError(tt, err)
		require.Equal(tt, requestPeer, reject.Peer)
	})

	t.Run("mismatched peer rejected", func(tt *testing.T) {
		wire := buildRejectWire(tt, otherPeer, request.ID)

		_, err := NewQuoteRejectFromWireMsg(wire, lookup)
		require.ErrorContains(tt, err, "does not match original "+
			"request peer")
	})

	t.Run("missing session rejected", func(tt *testing.T) {
		var unknownID ID
		copy(unknownID[:], []byte{0xFF})

		wire := buildRejectWire(tt, requestPeer, unknownID)

		_, err := NewQuoteRejectFromWireMsg(wire, lookup)
		require.ErrorContains(tt, err, "no outgoing request found")
	})
}
