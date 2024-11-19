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
	// DefaultQuoteLifetime is the default duration after which a quote
	// request will expire.
	DefaultQuoteLifetime = 10 * time.Minute

	// latestRequestWireMsgDataVersion is the latest supported quote request
	// wire message data field version.
	latestRequestWireMsgDataVersion = V1
)

type (
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

	// requestInAssetRateHint is a type alias for a record that represents
	// the in-asset to BTC rate hint for the quote request.
	requestInAssetRateHint = tlv.OptionalRecordT[
		tlv.TlvType19, TlvFixedPoint,
	]

	// requestOutAssetRateHint is a type alias for a record that represents
	// the out-asset to BTC rate hint for the quote request.
	requestOutAssetRateHint = tlv.OptionalRecordT[
		tlv.TlvType21, TlvFixedPoint,
	]
)

// requestWireMsgData is a struct that represents the message data field for
// a quote request wire message.
type requestWireMsgData struct {
	// Version is the version of the message data.
	Version tlv.RecordT[tlv.TlvType0, WireMsgDataVersion]

	// ID is the unique identifier of the quote request.
	ID tlv.RecordT[tlv.TlvType2, ID]

	// TransferType defines the type of transaction which will be performed
	// if the quote request leads to an accepted agreement.
	TransferType tlv.RecordT[tlv.TlvType4, TransferType]

	// Expiry is the Unix timestamp (in seconds) when the quote expires.
	// The quote becomes invalid after this time.
	Expiry tlv.RecordT[tlv.TlvType6, uint64]

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

	// MaxInAsset represents the maximum quantity of in-asset that the
	// counterparty is expected to divest, whether the asset involved is BTC
	// or otherwise.
	MaxInAsset tlv.RecordT[tlv.TlvType16, uint64]

	// InAssetRateHint is the peer's proposed in-asset to BTC rate. This is
	// not the final rate, but a suggested rate that the requesting peer
	// would be willing to accept.
	//
	// NOTE: This field is optional.
	InAssetRateHint requestInAssetRateHint

	// OutAssetRateHint is the peer's proposed out-asset to BTC rate. This
	// is not the final rate, but a suggested rate that the requesting peer
	// would be willing to accept.
	//
	// NOTE: This field is optional.
	OutAssetRateHint requestOutAssetRateHint

	// MinInAsset is an optional minimum quantity of in-asset that may be
	// transferred under the terms of the quote, applicable whether the
	// asset is BTC or any other.
	MinInAsset tlv.OptionalRecordT[tlv.TlvType23, uint64]

	// MinOutAsset is an optional minimum quantity of out-asset that may be
	// transferred under the terms of the quote, applicable whether the
	// asset is BTC or any other.
	MinOutAsset tlv.OptionalRecordT[tlv.TlvType25, uint64]
}

// newRequestWireMsgDataFromBuy creates a new requestWireMsgData from a buy
// request.
func newRequestWireMsgDataFromBuy(q BuyRequest) (requestWireMsgData, error) {
	version := tlv.NewRecordT[tlv.TlvType0](q.Version)
	id := tlv.NewRecordT[tlv.TlvType2](q.ID)
	transferType := tlv.NewRecordT[tlv.TlvType4](RecvPaymentTransferType)

	// Set the expiry to the default request lifetime unless an asset rate
	// hint is provided.
	expiry := time.Now().Add(DefaultQuoteLifetime).Unix()
	q.AssetRateHint.WhenSome(func(assetRate AssetRate) {
		expiry = assetRate.Expiry.Unix()
	})
	expiryTlv := tlv.NewPrimitiveRecord[tlv.TlvType6](uint64(expiry))

	var inAssetID requestInAssetID
	q.AssetSpecifier.WhenId(func(id asset.ID) {
		inAssetID = tlv.SomeRecordT[tlv.TlvType9](
			tlv.NewPrimitiveRecord[tlv.TlvType9](id),
		)
	})

	var inAssetGroupKey requestInAssetGroupKey
	q.AssetSpecifier.WhenGroupPubKey(func(groupPubKey btcec.PublicKey) {
		inAssetGroupKey = tlv.SomeRecordT[tlv.TlvType11](
			tlv.NewPrimitiveRecord[tlv.TlvType11](
				&groupPubKey,
			),
		)
	})

	// Use a zero asset ID for the outbound asset ID. This indicates that
	// the outbound asset is BTC.
	var zeroOutAssetID asset.ID
	outAssetID := tlv.SomeRecordT[tlv.TlvType13](
		tlv.NewPrimitiveRecord[tlv.TlvType13](zeroOutAssetID),
	)

	outAssetGroupKey := requestOutAssetGroupKey{}

	// Convert the suggested asset to BTC rate to a TLV record.
	var inAssetRateHint requestInAssetRateHint
	q.AssetRateHint.WhenSome(func(assetRate AssetRate) {
		// Convert the BigIntFixedPoint to a TlvFixedPoint.
		wireRate := NewTlvFixedPointFromBigInt(assetRate.Rate)
		inAssetRateHint = tlv.SomeRecordT[tlv.TlvType19](
			tlv.NewRecordT[tlv.TlvType19](wireRate),
		)
	})

	maxInAsset := tlv.NewPrimitiveRecord[tlv.TlvType16](q.AssetMaxAmt)

	// Encode message data component as TLV bytes.
	return requestWireMsgData{
		Version:          version,
		ID:               id,
		TransferType:     transferType,
		Expiry:           expiryTlv,
		InAssetID:        inAssetID,
		InAssetGroupKey:  inAssetGroupKey,
		OutAssetID:       outAssetID,
		OutAssetGroupKey: outAssetGroupKey,
		MaxInAsset:       maxInAsset,
		InAssetRateHint:  inAssetRateHint,
	}, nil
}

// newRequestWireMsgDataFromSell creates a new requestWireMsgData from a sell
// request.
func newRequestWireMsgDataFromSell(q SellRequest) (requestWireMsgData, error) {
	version := tlv.NewPrimitiveRecord[tlv.TlvType0](q.Version)
	id := tlv.NewRecordT[tlv.TlvType2](q.ID)
	transferType := tlv.NewRecordT[tlv.TlvType4](PayInvoiceTransferType)

	// Set the expiry to the default request lifetime unless an asset rate
	// hint is provided.
	expiry := time.Now().Add(DefaultQuoteLifetime).Unix()
	q.AssetRateHint.WhenSome(func(assetRate AssetRate) {
		expiry = assetRate.Expiry.Unix()
	})
	expiryTlv := tlv.NewPrimitiveRecord[tlv.TlvType6](uint64(expiry))

	maxInAsset := tlv.NewPrimitiveRecord[tlv.TlvType16](
		uint64(q.PaymentMaxAmt),
	)

	// Convert the in-asset to BTC rate to a TLV record.
	var outAssetRateHint requestOutAssetRateHint
	q.AssetRateHint.WhenSome(func(assetRate AssetRate) {
		// Convert the BigIntFixedPoint to a TlvFixedPoint.
		wireRate := NewTlvFixedPointFromBigInt(assetRate.Rate)
		outAssetRateHint = tlv.SomeRecordT[tlv.TlvType21](
			tlv.NewRecordT[tlv.TlvType21](wireRate),
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
	q.AssetSpecifier.WhenId(func(id asset.ID) {
		outAssetID = tlv.SomeRecordT[tlv.TlvType13](
			tlv.NewPrimitiveRecord[tlv.TlvType13](id),
		)
	})

	outAssetGroupKey := requestOutAssetGroupKey{}
	q.AssetSpecifier.WhenGroupPubKey(func(groupPubKey btcec.PublicKey) {
		outAssetGroupKey = tlv.SomeRecordT[tlv.TlvType15](
			tlv.NewPrimitiveRecord[tlv.TlvType15](
				&groupPubKey,
			),
		)
	})

	// Encode message data component as TLV bytes.
	return requestWireMsgData{
		Version:          version,
		ID:               id,
		TransferType:     transferType,
		Expiry:           expiryTlv,
		InAssetID:        inAssetID,
		OutAssetID:       outAssetID,
		OutAssetGroupKey: outAssetGroupKey,
		MaxInAsset:       maxInAsset,
		OutAssetRateHint: outAssetRateHint,
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
		m.TransferType.Record(),
		m.Expiry.Record(),
		m.MaxInAsset.Record(),
	}

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

	m.InAssetRateHint.WhenSome(
		func(r tlv.RecordT[tlv.TlvType19, TlvFixedPoint]) {
			records = append(records, r.Record())
		},
	)
	m.OutAssetRateHint.WhenSome(
		func(r tlv.RecordT[tlv.TlvType21, TlvFixedPoint]) {
			records = append(records, r.Record())
		},
	)

	m.MinInAsset.WhenSome(
		func(r tlv.RecordT[tlv.TlvType23, uint64]) {
			records = append(records, r.Record())
		},
	)
	m.MinOutAsset.WhenSome(
		func(r tlv.RecordT[tlv.TlvType25, uint64]) {
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
	inAssetID := m.InAssetID.Zero()
	inAssetGroupKey := m.InAssetGroupKey.Zero()

	outAssetID := m.OutAssetID.Zero()
	outAssetGroupKey := m.OutAssetGroupKey.Zero()

	inAssetRateHint := m.InAssetRateHint.Zero()
	outAssetRateHint := m.OutAssetRateHint.Zero()

	minInAsset := m.MinInAsset.Zero()
	minOutAsset := m.MinOutAsset.Zero()

	// Create a tlv stream with all the fields.
	tlvStream, err := tlv.NewStream(
		m.Version.Record(),
		m.ID.Record(),
		m.TransferType.Record(),
		m.Expiry.Record(),

		inAssetID.Record(),
		inAssetGroupKey.Record(),

		outAssetID.Record(),
		outAssetGroupKey.Record(),

		m.MaxInAsset.Record(),

		inAssetRateHint.Record(),
		outAssetRateHint.Record(),

		minInAsset.Record(),
		minOutAsset.Record(),
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

	if _, ok := tlvMap[inAssetRateHint.TlvType()]; ok {
		m.InAssetRateHint = tlv.SomeRecordT(inAssetRateHint)
	}
	if _, ok := tlvMap[outAssetRateHint.TlvType()]; ok {
		m.OutAssetRateHint = tlv.SomeRecordT(outAssetRateHint)
	}

	if _, ok := tlvMap[minInAsset.TlvType()]; ok {
		m.MinInAsset = tlv.SomeRecordT(minInAsset)
	}
	if _, ok := tlvMap[minOutAsset.TlvType()]; ok {
		m.MinOutAsset = tlv.SomeRecordT(minOutAsset)
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

	// Classify the incoming request as a buy or sell.
	//
	// When the requesting peer attempts to pay an invoice using a Tap
	// asset, they are "selling" the Tap asset to the edge node. Conversely,
	// when the requesting peer attempts to receive a Tap asset as payment
	// to settle an invoice, they are "buying" the Tap asset from the edge
	// node.
	switch msgData.TransferType.Val {
	case PayInvoiceTransferType:
		return NewSellRequestFromWire(wireMsg, msgData)
	case RecvPaymentTransferType:
		return NewBuyRequestFromWire(wireMsg, msgData)
	default:
		return nil, fmt.Errorf("unknown incoming request message "+
			"transfer type: %d", msgData.TransferType.Val)
	}
}
