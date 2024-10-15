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

	version        WireMsgDataVersion
	id             ID
	expiry         uint64
	assetMaxAmount uint64

	suggestedAssetRate *uint64

	inAssetId       *asset.ID
	inAssetGroupKey *btcec.PublicKey

	outAssetId       *asset.ID
	outAssetGroupKey *btcec.PublicKey
}

// Request generates a requestWireMsgData instance from the test case.
func (tc testCaseEncodeDecode) Request() requestWireMsgData {
	version := tlv.NewPrimitiveRecord[tlv.TlvType0](tc.version)
	id := tlv.NewPrimitiveRecord[tlv.TlvType1](tc.id)
	expiry := tlv.NewPrimitiveRecord[tlv.TlvType2](tc.expiry)
	assetMaxAmount := tlv.NewPrimitiveRecord[tlv.TlvType3](
		tc.assetMaxAmount,
	)

	var suggestedAssetRate requestSuggestedAssetRate
	if tc.suggestedAssetRate != nil {
		rate := NewTlvFixedPointFromUint64(*tc.suggestedAssetRate, 0)
		suggestedAssetRate = tlv.SomeRecordT[tlv.TlvType4](
			tlv.NewRecordT[tlv.TlvType4](rate),
		)
	}

	var inAssetID requestInAssetID
	if tc.inAssetId != nil {
		inAssetID = tlv.SomeRecordT[tlv.TlvType5](
			tlv.NewPrimitiveRecord[tlv.TlvType5](*tc.inAssetId),
		)
	}

	var inAssetGroupKey requestInAssetGroupKey
	if tc.inAssetGroupKey != nil {
		inAssetGroupKey = tlv.SomeRecordT[tlv.TlvType6](
			tlv.NewPrimitiveRecord[tlv.TlvType6](
				tc.inAssetGroupKey,
			),
		)
	}

	var outAssetID requestOutAssetID
	if tc.outAssetId != nil {
		outAssetID = tlv.SomeRecordT[tlv.TlvType7](
			tlv.NewPrimitiveRecord[tlv.TlvType7](*tc.outAssetId),
		)
	}

	var outAssetGroupKey requestOutAssetGroupKey
	if tc.outAssetGroupKey != nil {
		outAssetGroupKey = tlv.SomeRecordT[tlv.TlvType8](
			tlv.NewPrimitiveRecord[tlv.TlvType8](
				tc.outAssetGroupKey,
			),
		)
	}

	return requestWireMsgData{
		Version:            version,
		ID:                 id,
		Expiry:             expiry,
		AssetMaxAmount:     assetMaxAmount,
		SuggestedAssetRate: suggestedAssetRate,
		InAssetID:          inAssetID,
		InAssetGroupKey:    inAssetGroupKey,
		OutAssetID:         outAssetID,
		OutAssetGroupKey:   outAssetGroupKey,
	}
}

// TestRequestMsgDataEncodeDecode tests requestWireMsgData encoding/decoding.
func TestRequestMsgDataEncodeDecode(t *testing.T) {
	t.Parallel()

	// Create a random ID.
	randomIdBytes := test.RandBytes(32)
	id := ID(randomIdBytes)

	// Compute a future expiry timestamp.
	expiry := uint64(time.Now().Add(time.Hour).Unix())

	// Create a random asset ID.
	randomAssetIdBytes := test.RandBytes(32)
	assetId := asset.ID(randomAssetIdBytes)

	// Create a random asset group key.
	assetGroupKey := test.RandPrivKey(t).PubKey()

	// Create a zero asset ID. An asset ID of all zeros indicates BTC in the
	// context of the request message.
	var zeroAssetId asset.ID

	suggestedAssetRate := uint64(1000)

	testCases := []testCaseEncodeDecode{
		{
			testName: "in asset ID, out asset ID zero, " +
				"no asset group keys, suggested tick rate",
			version:            0,
			id:                 id,
			expiry:             expiry,
			assetMaxAmount:     1000,
			suggestedAssetRate: &suggestedAssetRate,
			inAssetId:          &assetId,
			inAssetGroupKey:    nil,
			outAssetId:         &zeroAssetId,
			outAssetGroupKey:   nil,
		},
		{
			testName: "in asset ID, out asset ID zero, no asset " +
				"group keys",
			version:            0,
			id:                 id,
			expiry:             expiry,
			assetMaxAmount:     1000,
			suggestedAssetRate: nil,
			inAssetId:          &assetId,
			inAssetGroupKey:    nil,
			outAssetId:         &zeroAssetId,
			outAssetGroupKey:   nil,
		},
		{
			testName: "in asset group key, out asset " +
				"ID zero",
			version:            0,
			id:                 id,
			expiry:             expiry,
			assetMaxAmount:     1000,
			suggestedAssetRate: nil,
			inAssetGroupKey:    assetGroupKey,
			outAssetId:         &zeroAssetId,
			outAssetGroupKey:   nil,
		},
		{
			testName: "in asset ID zero, out asset " +
				"group key",
			version:            0,
			id:                 id,
			expiry:             expiry,
			assetMaxAmount:     1000,
			suggestedAssetRate: nil,
			inAssetId:          &zeroAssetId,
			inAssetGroupKey:    nil,
			outAssetGroupKey:   assetGroupKey,
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
