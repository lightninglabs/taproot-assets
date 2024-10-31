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

	version WireMsgDataVersion
	id      ID
	expiry  uint64

	inAssetId       *asset.ID
	inAssetGroupKey *btcec.PublicKey

	outAssetId       *asset.ID
	outAssetGroupKey *btcec.PublicKey

	maxInAsset       uint64
	inAssetRateHint  *uint64
	outAssetRateHint *uint64

	minInAsset  *uint64
	minOutAsset *uint64
}

// Request generates a requestWireMsgData instance from the test case.
func (tc testCaseEncodeDecode) Request() requestWireMsgData {
	version := tlv.NewPrimitiveRecord[tlv.TlvType0](tc.version)
	id := tlv.NewPrimitiveRecord[tlv.TlvType2](tc.id)
	expiry := tlv.NewPrimitiveRecord[tlv.TlvType6](tc.expiry)

	var inAssetID requestInAssetID
	if tc.inAssetId != nil {
		inAssetID = tlv.SomeRecordT[tlv.TlvType9](
			tlv.NewPrimitiveRecord[tlv.TlvType9](*tc.inAssetId),
		)
	}

	var inAssetGroupKey requestInAssetGroupKey
	if tc.inAssetGroupKey != nil {
		inAssetGroupKey = tlv.SomeRecordT[tlv.TlvType11](
			tlv.NewPrimitiveRecord[tlv.TlvType11](
				tc.inAssetGroupKey,
			),
		)
	}

	var outAssetID requestOutAssetID
	if tc.outAssetId != nil {
		outAssetID = tlv.SomeRecordT[tlv.TlvType13](
			tlv.NewPrimitiveRecord[tlv.TlvType13](*tc.outAssetId),
		)
	}

	var outAssetGroupKey requestOutAssetGroupKey
	if tc.outAssetGroupKey != nil {
		outAssetGroupKey = tlv.SomeRecordT[tlv.TlvType15](
			tlv.NewPrimitiveRecord[tlv.TlvType15](
				tc.outAssetGroupKey,
			),
		)
	}

	maxInAsset := tlv.NewPrimitiveRecord[tlv.TlvType16](tc.maxInAsset)

	var inAssetRateHint requestInAssetRateHint
	if tc.inAssetRateHint != nil {
		// We use a fixed-point scale of 2 here just for testing.
		rate := NewTlvFixedPointFromUint64(*tc.inAssetRateHint, 2)
		inAssetRateHint = tlv.SomeRecordT[tlv.TlvType19](
			tlv.NewRecordT[tlv.TlvType19](rate),
		)
	}

	var outAssetRateHint requestOutAssetRateHint
	if tc.outAssetRateHint != nil {
		// We use a fixed-point scale of 2 here just for testing.
		rate := NewTlvFixedPointFromUint64(*tc.outAssetRateHint, 2)
		outAssetRateHint = tlv.SomeRecordT[tlv.TlvType21](
			tlv.NewRecordT[tlv.TlvType21](rate),
		)
	}

	var minInAsset tlv.OptionalRecordT[tlv.TlvType23, uint64]
	if tc.minInAsset != nil {
		minInAsset = tlv.SomeRecordT[tlv.TlvType23](
			tlv.NewPrimitiveRecord[tlv.TlvType23](*tc.minInAsset),
		)
	}

	var minOutAsset tlv.OptionalRecordT[tlv.TlvType25, uint64]
	if tc.minOutAsset != nil {
		minOutAsset = tlv.SomeRecordT[tlv.TlvType25](
			tlv.NewPrimitiveRecord[tlv.TlvType25](*tc.minOutAsset),
		)
	}

	return requestWireMsgData{
		Version:          version,
		ID:               id,
		Expiry:           expiry,
		InAssetID:        inAssetID,
		InAssetGroupKey:  inAssetGroupKey,
		OutAssetID:       outAssetID,
		OutAssetGroupKey: outAssetGroupKey,
		MaxInAsset:       maxInAsset,
		InAssetRateHint:  inAssetRateHint,
		OutAssetRateHint: outAssetRateHint,
		MinInAsset:       minInAsset,
		MinOutAsset:      minOutAsset,
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
	assetGroupKey := test.RandPrivKey().PubKey()

	// Create a zero asset ID. An asset ID of all zeros indicates BTC in the
	// context of the request message.
	var zeroAssetId asset.ID

	inAssetRateHint := uint64(1000)
	outAssetRateHint := uint64(2000)

	minInAsset := uint64(1)
	minOutAsset := uint64(10)

	testCases := []testCaseEncodeDecode{
		{
			testName: "in asset ID, out asset ID zero, " +
				"no asset group keys, in-asset rate hint " +
				"set, out-asset rate hint set",
			version:          V1,
			id:               id,
			expiry:           expiry,
			inAssetId:        &assetId,
			inAssetGroupKey:  nil,
			outAssetId:       &zeroAssetId,
			outAssetGroupKey: nil,
			maxInAsset:       1000,
			inAssetRateHint:  &inAssetRateHint,
			outAssetRateHint: &outAssetRateHint,
			minInAsset:       &minInAsset,
			minOutAsset:      &minOutAsset,
		},
		{
			testName: "in asset ID, out asset ID zero, no asset " +
				"group keys",
			version:          V1,
			id:               id,
			expiry:           expiry,
			inAssetId:        &assetId,
			inAssetGroupKey:  nil,
			outAssetId:       &zeroAssetId,
			outAssetGroupKey: nil,
			maxInAsset:       1000,
			inAssetRateHint:  nil,
			outAssetRateHint: nil,
		},
		{
			testName: "in asset group key, out asset " +
				"ID zero",
			version:          V1,
			id:               id,
			expiry:           expiry,
			inAssetGroupKey:  assetGroupKey,
			outAssetId:       &zeroAssetId,
			outAssetGroupKey: nil,
			maxInAsset:       1000,
			inAssetRateHint:  nil,
			outAssetRateHint: nil,
		},
		{
			testName: "in asset ID zero, out asset " +
				"group key",
			version:          V1,
			id:               id,
			expiry:           expiry,
			inAssetId:        &zeroAssetId,
			inAssetGroupKey:  nil,
			outAssetGroupKey: assetGroupKey,
			maxInAsset:       1000,
			inAssetRateHint:  nil,
			outAssetRateHint: nil,
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
