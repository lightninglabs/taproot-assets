package rfqmsg

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/stretchr/testify/require"
)

// TestSellRequestMsgDataEncodeDecode tests the encoding and decoding of a sell
// request message.
func TestSellRequestMsgDataEncodeDecode(t *testing.T) {
	t.Parallel()

	// Create a random ID.
	randomIdBytes := test.RandBytes(32)
	id := ID(randomIdBytes)

	// Create a random asset ID.
	randomAssetIdBytes := test.RandBytes(32)
	assetId := asset.ID(randomAssetIdBytes)

	testCases := []struct {
		testName string

		id            ID
		assetId       *asset.ID
		assetGroupKey *btcec.PublicKey
		assetAmount   uint64
		askPrice      lnwire.MilliSatoshi
	}{
		{
			testName:      "all fields populated with basic values",
			id:            id,
			assetId:       &assetId,
			assetGroupKey: nil,
			assetAmount:   1000,
			askPrice:      lnwire.MilliSatoshi(42000),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(tt *testing.T) {
			msg := sellRequestMsgData{
				ID:            tc.id,
				AssetID:       tc.assetId,
				AssetGroupKey: tc.assetGroupKey,
				AssetAmount:   tc.assetAmount,
				AskPrice:      tc.askPrice,
			}

			// Encode the message.
			reqBytes, err := msg.Bytes()
			require.NoError(tt, err, "unable to encode message")

			// Decode the message.
			decodedMsg := sellRequestMsgData{}
			err = decodedMsg.Decode(bytes.NewReader(reqBytes))
			require.NoError(tt, err, "unable to decode message")

			// Assert that the decoded message is equal to the
			// original message.
			require.Equal(tt, msg, decodedMsg)
		})
	}
}
