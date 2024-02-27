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

// TestBuyRequestMsgDataEncodeDecode tests the encoding and decoding of a buy
// request message.
func TestBuyRequestMsgDataEncodeDecode(t *testing.T) {
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
		bidPrice      lnwire.MilliSatoshi
	}{
		{
			testName:      "asset group key nil",
			id:            id,
			assetId:       &assetId,
			assetGroupKey: nil,
			assetAmount:   1000,
			bidPrice:      lnwire.MilliSatoshi(42000),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(tt *testing.T) {
			req := buyRequestMsgData{
				ID:            tc.id,
				AssetID:       tc.assetId,
				AssetGroupKey: tc.assetGroupKey,
				AssetAmount:   tc.assetAmount,
				BidPrice:      tc.bidPrice,
			}

			// Encode the request message.
			reqBytes, err := req.Bytes()
			require.NoError(tt, err, "unable to encode request")

			// Decode the request message.
			decodedReq := buyRequestMsgData{}
			err = decodedReq.Decode(bytes.NewReader(reqBytes))
			require.NoError(tt, err, "unable to decode request")

			// Assert that the decoded request message is equal to
			// the original request message.
			require.Equal(tt, req, decodedReq)
		})
	}
}
