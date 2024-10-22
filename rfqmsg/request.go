package rfqmsg

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// defaultRequestExpiry is the default duration after which a quote
	// request will expire.
	defaultRequestExpiry = 10 * time.Minute

	// latestRequestWireMsgDataVersion is the latest supported quote request
	// wire message data field version.
	latestRequestWireMsgDataVersion = V1
)

type (
	// requestSuggestedAssetRate is a type alias for a record that
	// represents the suggested asset to BTC rate for the quote request.
	requestSuggestedAssetRate = tlv.OptionalRecordT[
		tlv.TlvType19, TlvFixedPoint,
	]

	// requestInAssetID is a type alias for a record that represents the
	// asset ID of the inbound asset.
	requestInAssetID = tlv.OptionalRecordT[tlv.TlvType9, asset.ID]

	// requestInAssetGroupKey is a type alias for a record that represents
	// the public group key of the inbound asset.
	requestInAssetGroupKey = tlv.OptionalRecordT[
		tlv.TlvType11, *btcec.PublicKey,
	]

	// requestOutAssetID is a type alias for a record that represents the
	// asset ID of the outbound asset.
	requestOutAssetID = tlv.OptionalRecordT[tlv.TlvType13, asset.ID]

	// requestOutAssetGroupKey is a type alias for a record that represents
	// the public group key of the outbound asset.
	requestOutAssetGroupKey = tlv.OptionalRecordT[
		tlv.TlvType15, *btcec.PublicKey,
	]
)

// requestWireMsgData is a struct that represents the message data field for
// a quote request wire message.
type requestWireMsgData struct {
	// Version is the version of the message data.
	Version tlv.RecordT[tlv.TlvType0, WireMsgDataVersion]

	// ID is the unique identifier of the quote request.
	ID tlv.RecordT[tlv.TlvType2, ID]

	// TODO(ffranr): Add transfer type field with TLV type 4.

	// Expiry is the Unix timestamp (in seconds) when the quote expires.
	// The quote becomes invalid after this time.
	Expiry tlv.RecordT[tlv.TlvType6, uint64]

	// AssetMaxAmount represents the maximum asset amount that the target
	// peer is expected to accept/divest.
	AssetMaxAmount tlv.RecordT[tlv.TlvType16, uint64]

	// SuggestedAssetRate is the peer's proposed asset to BTC rate. This is
	// not the final rate, but a suggested rate that the requesting peer
	// would be willing to accept.
	//
	// NOTE: This field is optional.
	SuggestedAssetRate requestSuggestedAssetRate

	// InAssetID represents the identifier of the asset which will be
	// inbound to the requesting peer (therefore outbound to the
	// counterparty peer).
	//
	// NOTE: An asset ID of all zeros indicates BTC.
	InAssetID requestInAssetID

	// InAssetGroupKey is the public group key of the asset which will be
	// inbound to the requesting peer (therefore outbound to the
	// counterparty peer).
	InAssetGroupKey requestInAssetGroupKey

	// OutAssetID represents the identifier of the asset which will be
	// outbound to the requesting peer (therefore inbound to the
	// counterparty peer).
	//
	// NOTE: An asset ID of all zeros indicates BTC.
	OutAssetID requestOutAssetID

	// OutAssetGroupKey is the public group key of the asset which will be
	// outbound to the requesting peer (therefore inbound to the
	// counterparty peer).
	OutAssetGroupKey requestOutAssetGroupKey
}

// newRequestWireMsgDataFromBuy creates a new requestWireMsgData from a buy
// request.
func newRequestWireMsgDataFromBuy(q BuyRequest) (requestWireMsgData, error) {
	version := tlv.NewRecordT[tlv.TlvType0](q.Version)
	id := tlv.NewRecordT[tlv.TlvType2](q.ID)

	// Calculate the expiration unix timestamp in seconds.
	// TODO(ffranr): The expiry timestamp should be obtained from the
	//  request message.
	expiry := tlv.NewPrimitiveRecord[tlv.TlvType6](
		uint64(time.Now().Add(defaultRequestExpiry).Unix()),
	)

	assetMaxAmount := tlv.NewPrimitiveRecord[tlv.TlvType16](q.AssetAmount)

	// Convert the suggested asset to BTC rate to a TLV record.
	var suggestedAssetRate requestSuggestedAssetRate
	q.SuggestedAssetRate.WhenSome(func(rate rfqmath.BigIntFixedPoint) {
		// Convert the BigIntFixedPoint to a Uint64FixedPoint.
		wireRate := NewTlvFixedPointFromBigInt(rate)
		suggestedAssetRate = tlv.SomeRecordT[tlv.TlvType19](
			tlv.NewRecordT[tlv.TlvType19](wireRate),
		)
	})

	var inAssetID requestInAssetID
	if q.AssetID != nil {
		inAssetID = tlv.SomeRecordT[tlv.TlvType9](
			tlv.NewPrimitiveRecord[tlv.TlvType9](*q.AssetID),
		)
	}

	var inAssetGroupKey requestInAssetGroupKey
	if q.AssetGroupKey != nil {
		inAssetGroupKey = tlv.SomeRecordT[tlv.TlvType11](
			tlv.NewPrimitiveRecord[tlv.TlvType11](
				q.AssetGroupKey,
			),
		)
	}

	// Use a zero asset ID for the outbound asset ID. This indicates that
	// the outbound asset is BTC.
	var zeroOutAssetID asset.ID
	outAssetID := tlv.SomeRecordT[tlv.TlvType13](
		tlv.NewPrimitiveRecord[tlv.TlvType13](zeroOutAssetID),
	)

	outAssetGroupKey := requestOutAssetGroupKey{}

	// Encode message data component as TLV bytes.
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
	}, nil
}

// newRequestWireMsgDataFromSell creates a new requestWireMsgData from a sell
// request.
func newRequestWireMsgDataFromSell(q SellRequest) (requestWireMsgData, error) {
	version := tlv.NewPrimitiveRecord[tlv.TlvType0](q.Version)
	id := tlv.NewRecordT[tlv.TlvType2](q.ID)

	// Calculate the expiration unix timestamp in seconds.
	expiry := tlv.NewPrimitiveRecord[tlv.TlvType6](
		uint64(time.Now().Add(defaultRequestExpiry).Unix()),
	)

	assetMaxAmount := tlv.NewPrimitiveRecord[tlv.TlvType16](q.AssetAmount)

	// Convert the suggested asset rate to a TLV record.
	var suggestedAssetRate requestSuggestedAssetRate
	q.SuggestedAssetRate.WhenSome(func(rate rfqmath.BigIntFixedPoint) {
		// Convert the BigIntFixedPoint to a Uint64FixedPoint.
		wireRate := NewTlvFixedPointFromBigInt(rate)
		suggestedAssetRate = tlv.SomeRecordT[tlv.TlvType19](
			tlv.NewRecordT[tlv.TlvType19](
				wireRate,
			),
		)
	})

	// We are constructing a sell request. Therefore, the requesting peer's
	// outbound asset is the taproot asset, and the inbound asset is BTC.
	//
	// Use a zero asset ID for the inbound asset ID. This indicates that
	// the inbound asset is BTC.
	var zeroAssetID asset.ID
	inAssetID := tlv.SomeRecordT[tlv.TlvType9](
		tlv.NewPrimitiveRecord[tlv.TlvType9](zeroAssetID),
	)

	outAssetID := requestOutAssetID{}
	if q.AssetID != nil {
		outAssetID = tlv.SomeRecordT[tlv.TlvType13](
			tlv.NewPrimitiveRecord[tlv.TlvType13](*q.AssetID),
		)
	}

	outAssetGroupKey := requestOutAssetGroupKey{}
	if q.AssetGroupKey != nil {
		outAssetGroupKey = tlv.SomeRecordT[tlv.TlvType15](
			tlv.NewPrimitiveRecord[tlv.TlvType15](
				q.AssetGroupKey,
			),
		)
	}

	// Encode message data component as TLV bytes.
	return requestWireMsgData{
		Version:            version,
		ID:                 id,
		Expiry:             expiry,
		AssetMaxAmount:     assetMaxAmount,
		SuggestedAssetRate: suggestedAssetRate,
		InAssetID:          inAssetID,
		OutAssetID:         outAssetID,
		OutAssetGroupKey:   outAssetGroupKey,
	}, nil
}

// Validate ensures that the quote request is valid.
func (m *requestWireMsgData) Validate() error {
	// Ensure the version specified in the version field is supported.
	if m.Version.Val != latestRequestWireMsgDataVersion {
		return fmt.Errorf("unsupported quote request message data "+
			"version: %d", m.Version.Val)
	}

	// Ensure that the expiry is set to a future time.
	if m.Expiry.Val <= uint64(time.Now().Unix()) {
		return fmt.Errorf("expiry must be set to a future time")
	}

	// Ensure that the input asset is specified correctly.
	if m.InAssetID.IsNone() && m.InAssetGroupKey.IsNone() {
		return fmt.Errorf("InAssetID and InAssetGroupKey cannot both " +
			"be unset")
	}

	if m.InAssetID.IsSome() && m.InAssetGroupKey.IsSome() {
		return fmt.Errorf("InAssetID and InAssetGroupKey cannot both " +
			"be set")
	}

	// Ensure that the output asset is specified correctly.
	if m.OutAssetID.IsNone() && m.OutAssetGroupKey.IsNone() {
		return fmt.Errorf("OutAssetID and OutAssetGroupKey cannot " +
			"both be unset")
	}

	if m.OutAssetID.IsSome() && m.OutAssetGroupKey.IsSome() {
		return fmt.Errorf("OutAssetID and OutAssetGroupKey cannot " +
			"both be set")
	}

	// An all zero asset ID indicates BTC. Therefore, the inbound asset ID
	// and the outbound asset ID cannot both be set to all zeros.
	var zeroAssetID [32]byte

	inAssetIsBTC := false
	m.InAssetID.WhenSome(
		func(inAssetID tlv.RecordT[tlv.TlvType9, asset.ID]) {
			inAssetIsBTC = inAssetID.Val == zeroAssetID
		},
	)

	outAssetIsBTC := false
	m.OutAssetID.WhenSome(
		func(outAssetID tlv.RecordT[tlv.TlvType13, asset.ID]) {
			outAssetIsBTC = outAssetID.Val == zeroAssetID
		},
	)

	if inAssetIsBTC && outAssetIsBTC {
		return fmt.Errorf("inbound and outbound asset IDs cannot " +
			"both be set to all zeros")
	}

	return nil
}

// Encode serializes the requestWireMsgData to the given io.Writer.
func (m *requestWireMsgData) Encode(w io.Writer) error {
	// Validate the message before encoding.
	err := m.Validate()
	if err != nil {
		return err
	}

	records := []tlv.Record{
		m.Version.Record(),
		m.ID.Record(),
		m.Expiry.Record(),
		m.AssetMaxAmount.Record(),
	}

	m.SuggestedAssetRate.WhenSome(
		func(r tlv.RecordT[tlv.TlvType19, TlvFixedPoint]) {
			records = append(records, r.Record())
		},
	)

	// Encode the inbound asset.
	m.InAssetID.WhenSome(
		func(r tlv.RecordT[tlv.TlvType9, asset.ID]) {
			records = append(records, r.Record())
		},
	)
	m.InAssetGroupKey.WhenSome(
		func(r tlv.RecordT[tlv.TlvType11, *btcec.PublicKey]) {
			records = append(records, r.Record())
		},
	)

	// Encode the outbound asset.
	m.OutAssetID.WhenSome(
		func(r tlv.RecordT[tlv.TlvType13, asset.ID]) {
			records = append(records, r.Record())
		},
	)
	m.OutAssetGroupKey.WhenSome(
		func(r tlv.RecordT[tlv.TlvType15, *btcec.PublicKey]) {
			records = append(records, r.Record())
		},
	)

	tlv.SortRecords(records)

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the requestWireMsgData from the given io.Reader.
func (m *requestWireMsgData) Decode(r io.Reader) error {
	// Define zero values for optional fields.
	suggestedAssetRate := m.SuggestedAssetRate.Zero()

	inAssetID := m.InAssetID.Zero()
	inAssetGroupKey := m.InAssetGroupKey.Zero()

	outAssetID := m.OutAssetID.Zero()
	outAssetGroupKey := m.OutAssetGroupKey.Zero()

	// Create a tlv stream with all the fields.
	tlvStream, err := tlv.NewStream(
		m.Version.Record(),
		m.ID.Record(),
		m.Expiry.Record(),

		inAssetID.Record(),
		inAssetGroupKey.Record(),

		outAssetID.Record(),
		outAssetGroupKey.Record(),

		m.AssetMaxAmount.Record(),

		suggestedAssetRate.Record(),
	)
	if err != nil {
		return err
	}

	// Decode the reader's contents into the tlv stream.
	tlvMap, err := tlvStream.DecodeWithParsedTypes(r)
	if err != nil {
		return err
	}

	// Set optional fields if they are present.
	if _, ok := tlvMap[suggestedAssetRate.TlvType()]; ok {
		m.SuggestedAssetRate = tlv.SomeRecordT(suggestedAssetRate)
	}

	if _, ok := tlvMap[inAssetID.TlvType()]; ok {
		m.InAssetID = tlv.SomeRecordT(inAssetID)
	}
	if _, ok := tlvMap[inAssetGroupKey.TlvType()]; ok {
		m.InAssetGroupKey = tlv.SomeRecordT(inAssetGroupKey)
	}

	if _, ok := tlvMap[outAssetID.TlvType()]; ok {
		m.OutAssetID = tlv.SomeRecordT(outAssetID)
	}
	if _, ok := tlvMap[outAssetGroupKey.TlvType()]; ok {
		m.OutAssetGroupKey = tlv.SomeRecordT(outAssetGroupKey)
	}

	return nil
}

// Bytes encodes the structure into a TLV stream and returns the bytes.
func (m *requestWireMsgData) Bytes() ([]byte, error) {
	var b bytes.Buffer
	err := m.Encode(&b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// NewIncomingRequestFromWire creates a new request message from an incoming
// wire message.
//
// Note that this is an incoming request. Which means that a buy request
// is a request from our peer to buy the asset from us, and a sell request is a
// request from out peer to sell the asset to us.
func NewIncomingRequestFromWire(wireMsg WireMessage) (IncomingMsg, error) {
	// Ensure that the message type is a request message.
	if wireMsg.MsgType != MsgTypeRequest {
		return nil, ErrUnknownMessageType
	}

	var msgData requestWireMsgData
	err := msgData.Decode(bytes.NewBuffer(wireMsg.Data))
	if err != nil {
		return nil, fmt.Errorf("unable to decode incoming request "+
			"message data: %w", err)
	}

	if err := msgData.Validate(); err != nil {
		return nil, fmt.Errorf("unable to validate incoming "+
			"request: %w", err)
	}

	// We will now determine whether this is a buy or sell request. We
	// currently only support exchanging a taproot asset for BTC. Therefore,
	// we can distinguish between buy/sell requests by identifying the all
	// zero in/out asset ID which designates BTC.
	isBuyRequest := false

	// Check the outgoing asset ID to determine if this is a buy request.
	msgData.OutAssetID.WhenSome(
		func(outAssetID tlv.RecordT[tlv.TlvType13, asset.ID]) {
			var zeroAssetID [32]byte

			// If the outgoing asset ID is all zeros (signifying
			// BTC), then this is a buy request. In other words, the
			// incoming asset is the taproot asset, and the outgoing
			// asset is BTC.
			isBuyRequest = outAssetID.Val == zeroAssetID
		},
	)

	// The outgoing asset ID may not be set, but the outgoing asset group
	// key may be set. If the outbound asset group key is not specified
	// (and the outbound asset ID is not set), then this is a buy request.
	// In other words, only the inbound asset is specified, and the outbound
	// asset is BTC.
	msgData.OutAssetGroupKey.WhenSome(
		func(gk tlv.RecordT[tlv.TlvType15, *btcec.PublicKey]) {
			// Here we carry through any ture value of isBuyRequest
			// from the previous check.
			isBuyRequest = isBuyRequest || (gk.Val != nil)
		},
	)

	// If this is a buy request, then we will create a new buy request
	// message.
	if isBuyRequest {
		return NewBuyRequestMsgFromWire(wireMsg, msgData)
	}

	// Otherwise, this is a sell request.
	return NewSellRequestMsgFromWire(wireMsg, msgData)
}
