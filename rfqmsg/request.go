package rfqmsg

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// latestRequestWireMsgDataVersion is the latest supported quote request
	// wire message data field version.
	latestRequestWireMsgDataVersion = V1
)

// requestWireMsgData is a struct that represents the message data field for
// a quote request wire message.
type requestWireMsgData struct {
	// Version is the version of the message data.
	Version tlv.RecordT[tlv.TlvType0, WireMsgDataVersion]

	// ID is the unique identifier of the quote request.
	ID tlv.RecordT[tlv.TlvType1, ID]

	// Expiry is the expiry Unix timestamp (in seconds) of the quote
	// request. This timestamp defines the lifetime of both the suggested
	// rate tick and the quote request.
	Expiry tlv.RecordT[tlv.TlvType2, uint64]

	// InAssetMaxAmount represents the maximum in asset amount that the
	// target peer is expected to accept/divest. This denotes the maximum
	// total volume (in units specified in InAssetID/InAssetGroupKey) that
	// might be swapped from the inbound asset to the outbound asset for
	// this request.
	InAssetMaxAmount tlv.RecordT[tlv.TlvType3, uint64]

	// SuggestedInAssetPrice is the requester's proposed price for the in
	// asset (in asset units per BTC). This is not the final price, but a
	// suggested price that the requesting peer would be willing to accept.
	//
	// NOTE: This field is optional.
	SuggestedInAssetPrice tlv.OptionalRecordT[
		tlv.TlvType4, Uint64FixedPoint,
	]

	// SuggestedOutAssetPrice is the requester's proposed price for the out
	// asset (in asset units per BTC). This is not the final price, but a
	// suggested price that the requesting peer would be willing to accept.
	//
	// NOTE: This field is optional.
	SuggestedOutAssetPrice tlv.OptionalRecordT[
		tlv.TlvType5, Uint64FixedPoint,
	]

	// InAssetID represents the identifier of the asset which will be
	// inbound to the requesting peer (therefore outbound to the
	// counterparty peer).
	//
	// NOTE: An asset ID of all zeros indicates BTC and the unit of
	// InAssetMaxAmount is milli-satoshi.
	InAssetID tlv.OptionalRecordT[tlv.TlvType6, asset.ID]

	// InAssetGroupKey is the public group key of the asset which will be
	// inbound to the requesting peer (therefore outbound to the
	// counterparty peer).
	InAssetGroupKey tlv.OptionalRecordT[tlv.TlvType7, *btcec.PublicKey]

	// OutAssetID represents the identifier of the asset which will be
	// outbound to the requesting peer (therefore inbound to the
	// counterparty peer).
	//
	// NOTE: An asset ID of all zeros indicates BTC.
	OutAssetID tlv.OptionalRecordT[tlv.TlvType8, asset.ID]

	// OutAssetGroupKey is the public group key of the asset which will be
	// outbound to the requesting peer (therefore inbound to the
	// counterparty peer).
	OutAssetGroupKey tlv.OptionalRecordT[tlv.TlvType9, *btcec.PublicKey]
}

// newRequestWireMsgDataFromBuy creates a new requestWireMsgData from a buy
// request.
func newRequestWireMsgDataFromBuy(q BuyRequest) requestWireMsgData {
	var (
		suggestedInAssetPrice tlv.OptionalRecordT[
			tlv.TlvType4, Uint64FixedPoint,
		]
		suggestedOutAssetPrice tlv.OptionalRecordT[
			tlv.TlvType5, Uint64FixedPoint,
		]
	)
	if q.SuggestedPrice != nil {
		suggestedInAssetPrice = tlv.SomeRecordT[tlv.TlvType4](
			tlv.NewRecordT[tlv.TlvType4](
				q.SuggestedPrice.InAssetPrice,
			),
		)
		suggestedOutAssetPrice = tlv.SomeRecordT[tlv.TlvType5](
			tlv.NewRecordT[tlv.TlvType5](
				q.SuggestedPrice.OutAssetPrice,
			),
		)
	}

	var inAssetID tlv.OptionalRecordT[tlv.TlvType6, asset.ID]
	if q.AssetID != nil {
		inAssetID = tlv.SomeRecordT[tlv.TlvType6](
			tlv.NewPrimitiveRecord[tlv.TlvType6](*q.AssetID),
		)
	}

	var inAssetGroupKey tlv.OptionalRecordT[tlv.TlvType7, *btcec.PublicKey]
	if q.AssetGroupKey != nil {
		inAssetGroupKey = tlv.SomeRecordT[tlv.TlvType7](
			tlv.NewPrimitiveRecord[tlv.TlvType7](q.AssetGroupKey),
		)
	}

	// Use a zero asset ID for the outbound asset ID. This indicates that
	// the outbound asset is BTC.
	var zeroOutAssetID asset.ID
	outAssetID := tlv.SomeRecordT[tlv.TlvType8](
		tlv.NewPrimitiveRecord[tlv.TlvType8](zeroOutAssetID),
	)

	// Encode message data component as TLV bytes.
	return requestWireMsgData{
		Version: tlv.NewRecordT[tlv.TlvType0](q.Version),
		ID:      tlv.NewRecordT[tlv.TlvType1](q.ID),
		Expiry: tlv.NewPrimitiveRecord[tlv.TlvType2](
			uint64(q.Expiry.Unix()),
		),
		InAssetMaxAmount: tlv.NewPrimitiveRecord[tlv.TlvType3](
			q.InAssetMaxAmount,
		),
		SuggestedInAssetPrice:  suggestedInAssetPrice,
		SuggestedOutAssetPrice: suggestedOutAssetPrice,
		InAssetID:              inAssetID,
		InAssetGroupKey:        inAssetGroupKey,
		OutAssetID:             outAssetID,
	}
}

// newRequestWireMsgDataFromSell creates a new requestWireMsgData from a sell
// request.
func newRequestWireMsgDataFromSell(q SellRequest) requestWireMsgData {
	var (
		suggestedInAssetPrice tlv.OptionalRecordT[
			tlv.TlvType4, Uint64FixedPoint,
		]
		suggestedOutAssetPrice tlv.OptionalRecordT[
			tlv.TlvType5, Uint64FixedPoint,
		]
	)
	if q.SuggestedPrice != nil {
		suggestedInAssetPrice = tlv.SomeRecordT[tlv.TlvType4](
			tlv.NewRecordT[tlv.TlvType4](
				q.SuggestedPrice.InAssetPrice,
			),
		)
		suggestedOutAssetPrice = tlv.SomeRecordT[tlv.TlvType5](
			tlv.NewRecordT[tlv.TlvType5](
				q.SuggestedPrice.OutAssetPrice,
			),
		)
	}

	var inAssetID tlv.OptionalRecordT[tlv.TlvType6, asset.ID]
	if q.AssetID != nil {
		inAssetID = tlv.SomeRecordT[tlv.TlvType6](
			tlv.NewPrimitiveRecord[tlv.TlvType6](*q.AssetID),
		)
	}

	var inAssetGroupKey tlv.OptionalRecordT[tlv.TlvType7, *btcec.PublicKey]
	if q.AssetGroupKey != nil {
		inAssetGroupKey = tlv.SomeRecordT[tlv.TlvType7](
			tlv.NewPrimitiveRecord[tlv.TlvType7](q.AssetGroupKey),
		)
	}

	// Use a zero asset ID for the outbound asset ID. This indicates that
	// the outbound asset is BTC.
	var zeroOutAssetID asset.ID
	outAssetID := tlv.SomeRecordT[tlv.TlvType8](
		tlv.NewPrimitiveRecord[tlv.TlvType8](zeroOutAssetID),
	)

	// Encode message data component as TLV bytes.
	return requestWireMsgData{
		Version: tlv.NewRecordT[tlv.TlvType0](q.Version),
		ID:      tlv.NewRecordT[tlv.TlvType1](q.ID),
		Expiry: tlv.NewPrimitiveRecord[tlv.TlvType2](
			uint64(q.Expiry.Unix()),
		),
		InAssetMaxAmount: tlv.NewPrimitiveRecord[tlv.TlvType3](
			q.InAssetMaxAmount,
		),
		SuggestedInAssetPrice:  suggestedInAssetPrice,
		SuggestedOutAssetPrice: suggestedOutAssetPrice,
		InAssetID:              inAssetID,
		InAssetGroupKey:        inAssetGroupKey,
		OutAssetID:             outAssetID,
	}
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
		func(inAssetID tlv.RecordT[tlv.TlvType6, asset.ID]) {
			inAssetIsBTC = inAssetID.Val == zeroAssetID
		},
	)

	outAssetIsBTC := false
	m.OutAssetID.WhenSome(
		func(outAssetID tlv.RecordT[tlv.TlvType8, asset.ID]) {
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
		m.InAssetMaxAmount.Record(),
	}

	m.SuggestedInAssetPrice.WhenSome(
		func(r tlv.RecordT[tlv.TlvType4, Uint64FixedPoint]) {
			records = append(records, r.Record())
		},
	)

	m.SuggestedOutAssetPrice.WhenSome(
		func(r tlv.RecordT[tlv.TlvType5, Uint64FixedPoint]) {
			records = append(records, r.Record())
		},
	)

	// Encode the inbound asset.
	m.InAssetID.WhenSome(
		func(r tlv.RecordT[tlv.TlvType6, asset.ID]) {
			records = append(records, r.Record())
		},
	)
	m.InAssetGroupKey.WhenSome(
		func(r tlv.RecordT[tlv.TlvType7, *btcec.PublicKey]) {
			records = append(records, r.Record())
		},
	)

	// Encode the outbound asset.
	m.OutAssetID.WhenSome(
		func(r tlv.RecordT[tlv.TlvType8, asset.ID]) {
			records = append(records, r.Record())
		},
	)
	m.OutAssetGroupKey.WhenSome(
		func(r tlv.RecordT[tlv.TlvType9, *btcec.PublicKey]) {
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
	suggestedInAssetPrice := m.SuggestedInAssetPrice.Zero()
	suggestedOutAssetPrice := m.SuggestedOutAssetPrice.Zero()

	inAssetID := m.InAssetID.Zero()
	inAssetGroupKey := m.InAssetGroupKey.Zero()

	outAssetID := m.OutAssetID.Zero()
	outAssetGroupKey := m.OutAssetGroupKey.Zero()

	// Create a tlv stream with all the fields.
	tlvStream, err := tlv.NewStream(
		m.Version.Record(),
		m.ID.Record(),
		m.Expiry.Record(),
		m.InAssetMaxAmount.Record(),

		suggestedInAssetPrice.Record(),
		suggestedOutAssetPrice.Record(),

		inAssetID.Record(),
		inAssetGroupKey.Record(),

		outAssetID.Record(),
		outAssetGroupKey.Record(),
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
	if _, ok := tlvMap[suggestedInAssetPrice.TlvType()]; ok {
		m.SuggestedInAssetPrice = tlv.SomeRecordT(suggestedInAssetPrice)
	}
	if _, ok := tlvMap[suggestedOutAssetPrice.TlvType()]; ok {
		m.SuggestedOutAssetPrice = tlv.SomeRecordT(
			suggestedOutAssetPrice,
		)
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
		func(outAssetID tlv.RecordT[tlv.TlvType8, asset.ID]) {
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
		func(gk tlv.RecordT[tlv.TlvType9, *btcec.PublicKey]) {
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
