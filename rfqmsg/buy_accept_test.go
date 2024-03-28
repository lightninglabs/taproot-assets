package rfqmsg

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestAcceptShortChannelId tests the ShortChannelId method of a quote accept
// message.
func TestAcceptShortChannelId(t *testing.T) {
	t.Parallel()

	// Generate a random short channel ID.
	scidInt := rand.Uint64()
	scid := lnwire.NewShortChanIDFromInt(scidInt)

	// Create a random ID.
	randomIdBytes := test.RandBytes(32)
	id := ID(randomIdBytes)

	// Set the last 8 bytes of the ID to the short channel ID.
	binary.BigEndian.PutUint64(id[24:], scid.ToUint64())

	// Create an accept message.
	acceptMsg := BuyAccept{
		buyAcceptMsgData: buyAcceptMsgData{
			ID: id,
		},
	}

	// Derive the short channel ID from the accept message.
	actualScidInt := acceptMsg.ShortChannelId()

	// Assert that the derived short channel ID is equal to the expected
	// short channel ID.
	require.Equal(t, scidInt, uint64(actualScidInt))
}

// TestBuyAcceptMsgDataEncodeDecode tests the encoding and decoding of a buy
// accept message.
func TestBuyAcceptMsgDataEncodeDecode(t *testing.T) {
	t.Parallel()

	// Create a random ID.
	randomIdBytes := test.RandBytes(32)
	id := ID(randomIdBytes)

	// Create a random signature.
	randomSigBytes := test.RandBytes(64)
	var signature [64]byte
	copy(signature[:], randomSigBytes[:])

	testCases := []struct {
		testName string

		id       ID
		askPrice lnwire.MilliSatoshi
		expiry   uint64
		sig      [64]byte
	}{
		{
			testName: "all fields populated with basic values",
			id:       id,
			askPrice: 1000,
			expiry:   42000,
			sig:      signature,
		},
		{
			testName: "empty fields",
			id:       [32]byte{},
			askPrice: 0,
			expiry:   0,
			sig:      [64]byte{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(tt *testing.T) {
			msg := buyAcceptMsgData{
				ID:       tc.id,
				AskPrice: tc.askPrice,
				Expiry:   tc.expiry,
				sig:      tc.sig,
			}

			// Encode the message.
			reqBytes, err := msg.Bytes()
			require.NoError(tt, err, "unable to encode message")

			// Decode the message.
			decodedMsg := buyAcceptMsgData{}
			err = decodedMsg.Decode(bytes.NewReader(reqBytes))
			require.NoError(tt, err, "unable to decode message")

			// Assert that the decoded message is equal to the
			// original message.
			require.Equal(tt, msg, decodedMsg)
		})
	}
}
