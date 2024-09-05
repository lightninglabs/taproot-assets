package rfqmsg

import (
	"bytes"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/stretchr/testify/require"
)

// testCaseEncodeDecode is a test case for encoding and decoding a
// requestWireMsgData.
type testCaseEncodeDecode struct {
	testName string

	buyReq BuyRequest

	outAssetId       *asset.ID
	outAssetGroupKey *btcec.PublicKey
}

// Request generates a requestWireMsgData instance from the test case.
func (tc testCaseEncodeDecode) Request() requestWireMsgData {
	data := newRequestWireMsgDataFromBuy(tc.buyReq)

	if tc.outAssetId != nil {
		data.OutAssetID = tlv.SomeRecordT[tlv.TlvType8](
			tlv.NewPrimitiveRecord[tlv.TlvType8](*tc.outAssetId),
		)
	}

	if tc.outAssetGroupKey != nil {
		data.OutAssetID = tlv.OptionalRecordT[tlv.TlvType8, asset.ID]{}
		data.OutAssetGroupKey = tlv.SomeRecordT[tlv.TlvType9](
			tlv.NewPrimitiveRecord[tlv.TlvType9](
				tc.outAssetGroupKey,
			),
		)
	}

	return data
}

// TestRequestMsgDataEncodeDecode tests requestWireMsgData encoding/decoding.
func TestRequestMsgDataEncodeDecode(t *testing.T) {
	t.Parallel()

	// Create a random ID.
	randomIdBytes := test.RandBytes(32)
	id := ID(randomIdBytes)

	// Compute a future expiry timestamp.
	expiry := time.Now().Add(time.Hour)

	// Create a random asset ID.
	randomAssetIdBytes := test.RandBytes(32)
	assetId := asset.ID(randomAssetIdBytes)

	// Create a random asset group key.
	assetGroupKey := test.RandPrivKey(t).PubKey()

	// Create a zero asset ID. An asset ID of all zeros indicates BTC in the
	// context of the request message.
	var zeroAssetId asset.ID

	suggestedInAssetPrice := NewUint64FixedPoint(123456, 7)
	suggestedOutAssetPrice := NewUint64FixedPoint(9876543, 2)

	testCases := []testCaseEncodeDecode{
		{
			testName: "in asset ID, out asset ID zero, " +
				"no asset group keys, suggested tick rate",
			buyReq: BuyRequest{
				Version:                1,
				ID:                     id,
				Expiry:                 expiry,
				InAssetMaxAmount:       1000,
				SuggestedInAssetPrice:  &suggestedInAssetPrice,
				SuggestedOutAssetPrice: &suggestedOutAssetPrice,
				AssetID:                &assetId,
				AssetGroupKey:          nil,
			},
			outAssetId:       &zeroAssetId,
			outAssetGroupKey: nil,
		},
		{
			testName: "in asset ID, out asset ID zero, no asset " +
				"group keys",
			buyReq: BuyRequest{
				Version:                1,
				ID:                     id,
				Expiry:                 expiry,
				InAssetMaxAmount:       1000,
				SuggestedInAssetPrice:  nil,
				SuggestedOutAssetPrice: &suggestedOutAssetPrice,
				AssetID:                &assetId,
				AssetGroupKey:          nil,
			},
			outAssetId:       &zeroAssetId,
			outAssetGroupKey: nil,
		},
		{
			testName: "in asset group key, out asset ID zero",
			buyReq: BuyRequest{
				Version:                1,
				ID:                     id,
				Expiry:                 expiry,
				InAssetMaxAmount:       1000,
				SuggestedInAssetPrice:  &suggestedInAssetPrice,
				SuggestedOutAssetPrice: nil,
				AssetID:                nil,
				AssetGroupKey:          assetGroupKey,
			},
			outAssetId:       &zeroAssetId,
			outAssetGroupKey: nil,
		},
		{
			testName: "in asset ID zero, out asset group key",
			buyReq: BuyRequest{
				Version:                1,
				ID:                     id,
				Expiry:                 expiry,
				InAssetMaxAmount:       1000,
				SuggestedInAssetPrice:  nil,
				SuggestedOutAssetPrice: nil,
				AssetID:                &zeroAssetId,
				AssetGroupKey:          nil,
			},
			outAssetGroupKey: assetGroupKey,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(tt *testing.T) {
			req := tc.Request()

			// Encode the request message.
			reqBytes, err := req.Bytes()
			require.NoError(tt, err, "unable to encode request")

			// Decode the request message.
			decodedReq := requestWireMsgData{}
			err = decodedReq.Decode(bytes.NewReader(reqBytes))
			require.NoError(tt, err, "unable to decode request")

			// Assert that the decoded request message is equal to
			// the original request message.
			require.Equal(tt, req, decodedReq)
		})
	}
}
