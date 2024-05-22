package rfqmsg

import (
	"bytes"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestSellAcceptMsgDataEncodeDecode tests the encoding and decoding of a sell
// accept message.
func TestSellAcceptMsgDataEncodeDecode(t *testing.T) {
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

		version  WireMsgDataVersion
		id       ID
		bidPrice lnwire.MilliSatoshi
		expiry   uint64
		sig      [64]byte
		assetID  *asset.ID
	}{
		{
			testName: "all fields populated with basic values",
			version:  latestSellAcceptVersion,
			id:       id,
			bidPrice: 1000,
			expiry:   42000,
			sig:      signature,
			assetID:  &asset.ID{1, 2, 3},
		},
		{
			testName: "empty fields",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(tt *testing.T) {
			msg := sellAcceptMsgData{
				Version:  tc.version,
				ID:       tc.id,
				BidPrice: tc.bidPrice,
				Expiry:   tc.expiry,
				sig:      tc.sig,
			}

			// Encode the message.
			reqBytes, err := msg.Bytes()
			require.NoError(tt, err, "unable to encode message")

			// Decode the message.
			decodedMsg := sellAcceptMsgData{}
			err = decodedMsg.Decode(bytes.NewReader(reqBytes))
			require.NoError(tt, err, "unable to decode message")

			// Assert that the decoded message is equal to the
			// original message.
			require.Equal(tt, msg, decodedMsg)
		})
	}
}
