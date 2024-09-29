package rfqmsg

import (
	"bytes"
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
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
