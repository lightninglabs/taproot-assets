package rfqmsg

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// latestAcceptWireMsgDataVersion is the latest supported quote accept
	// wire message data field version.
	latestAcceptWireMsgDataVersion = V1
)

// acceptWireMsgData is a struct that represents the message data field for
// a quote accept wire message.
type acceptWireMsgData struct {
	// Version is the version of the message data.
	Version tlv.RecordT[tlv.TlvType0, WireMsgDataVersion]

	// ID is the unique identifier of the quote request.
	ID tlv.RecordT[tlv.TlvType2, ID]

	// Expiry is the Unix timestamp (in seconds) when the quote expires.
	// The quote becomes invalid after this time.
	Expiry tlv.RecordT[tlv.TlvType4, uint64]

	// Sig is a signature over the serialized contents of the message.
	Sig tlv.RecordT[tlv.TlvType6, [64]byte]

	// InAssetRate is the in-asset to BTC rate.
	InAssetRate tlv.RecordT[tlv.TlvType8, TlvFixedPoint]

	// OutAssetRate is the out-asset to BTC rate.
	OutAssetRate tlv.RecordT[tlv.TlvType10, TlvFixedPoint]
}

// newAcceptWireMsgDataFromBuy creates a new acceptWireMsgData from a buy
// accept message.
func newAcceptWireMsgDataFromBuy(q BuyAccept) (acceptWireMsgData, error) {
	version := tlv.NewPrimitiveRecord[tlv.TlvType0](q.Version)
	id := tlv.NewRecordT[tlv.TlvType2](q.ID)

	expiryUnix := q.AssetRate.Expiry.Unix()
	expiry := tlv.NewPrimitiveRecord[tlv.TlvType4](uint64(expiryUnix))

	sig := tlv.NewPrimitiveRecord[tlv.TlvType6](q.sig)

	// The rate provided in the buy acceptance message represents the
	// exchange rate from the incoming asset to BTC.
	rate := NewTlvFixedPointFromBigInt(q.AssetRate.Rate)
	inAssetRate := tlv.NewRecordT[tlv.TlvType8](rate)

	// Currently, only BTC is supported as the outgoing asset in buy
	// request and accept messages.
	outAssetRate := tlv.NewRecordT[tlv.TlvType10](
		NewTlvFixedPointFromBigInt(MilliSatPerBtc),
	)

	// Encode message data component as TLV bytes.
	return acceptWireMsgData{
		Version:      version,
		ID:           id,
		Expiry:       expiry,
		Sig:          sig,
		InAssetRate:  inAssetRate,
		OutAssetRate: outAssetRate,
	}, nil
}

// newAcceptWireMsgDataFromSell creates a new acceptWireMsgData from a sell
// accept message.
func newAcceptWireMsgDataFromSell(q SellAccept) (acceptWireMsgData, error) {
	version := tlv.NewPrimitiveRecord[tlv.TlvType0](q.Version)
	id := tlv.NewRecordT[tlv.TlvType2](q.ID)

	expiryUnix := q.AssetRate.Expiry.Unix()
	expiry := tlv.NewPrimitiveRecord[tlv.TlvType4](uint64(expiryUnix))

	sig := tlv.NewPrimitiveRecord[tlv.TlvType6](q.sig)

	// Currently, only BTC is supported as the incoming asset in sell
	// request and accept messages.
	inAssetRate := tlv.NewRecordT[tlv.TlvType8](
		NewTlvFixedPointFromBigInt(MilliSatPerBtc),
	)

	// The rate provided in the sell acceptance message represents the
	// exchange rate from the outgoing asset to BTC.
	rate := NewTlvFixedPointFromBigInt(q.AssetRate.Rate)
	outAssetRate := tlv.NewRecordT[tlv.TlvType10](rate)

	// Encode message data component as TLV bytes.
	return acceptWireMsgData{
		Version:      version,
		ID:           id,
		Expiry:       expiry,
		Sig:          sig,
		InAssetRate:  inAssetRate,
		OutAssetRate: outAssetRate,
	}, nil
}

// Validate ensures that the quote accept message is valid.
func (m *acceptWireMsgData) Validate() error {
	// Ensure the version specified in the version field is supported.
	if m.Version.Val != latestAcceptWireMsgDataVersion {
		return fmt.Errorf("unsupported quote accept message data "+
			"version: %d", m.Version.Val)
	}

	// Ensure that the expiry is set to a future time.
	if m.Expiry.Val <= uint64(time.Now().Unix()) {
		return fmt.Errorf("expiry must be set to a future time")
	}

	return nil
}

// Encode serializes the acceptWireMsgData to the given io.Writer.
func (m *acceptWireMsgData) Encode(w io.Writer) error {
	// Validate the message before encoding.
	err := m.Validate()
	if err != nil {
		return err
	}

	records := []tlv.Record{
		m.Version.Record(),
		m.ID.Record(),
		m.Expiry.Record(),
		m.Sig.Record(),
		m.InAssetRate.Record(),
		m.OutAssetRate.Record(),
	}

	tlv.SortRecords(records)

	// Create the tlv stream.
	tlvStream, err := tlv.NewStream(records...)
	if err != nil {
		return err
	}

	return tlvStream.Encode(w)
}

// Decode deserializes the acceptWireMsgData from the given io.Reader.
func (m *acceptWireMsgData) Decode(r io.Reader) error {
	// Create a tlv stream with all the fields.
	tlvStream, err := tlv.NewStream(
		m.Version.Record(),
		m.ID.Record(),
		m.Expiry.Record(),
		m.Sig.Record(),
		m.InAssetRate.Record(),
		m.OutAssetRate.Record(),
	)
	if err != nil {
		return err
	}

	// Decode the reader's contents into the tlv stream.
	_, err = tlvStream.DecodeWithParsedTypes(r)
	if err != nil {
		return err
	}

	return nil
}

// Bytes encodes the structure into a TLV stream and returns the bytes.
func (m *acceptWireMsgData) Bytes() ([]byte, error) {
	var b bytes.Buffer
	err := m.Encode(&b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// NewIncomingAcceptFromWire creates a new quote accept message from an incoming
// wire message.
//
// This is an incoming accept message. An incoming buy accept message indicates
// that our peer accepts our buy request, meaning they are willing to sell the
// asset to us. Conversely, an incoming sell accept message indicates that our
// peer accepts our sell request, meaning they are willing to buy the asset from
// us.
func NewIncomingAcceptFromWire(wireMsg WireMessage,
	sessionLookup SessionLookup) (IncomingMsg, error) {

	// Ensure that the message type is a quote accept message.
	if wireMsg.MsgType != MsgTypeAccept {
		return nil, ErrUnknownMessageType
	}

	var msgData acceptWireMsgData
	err := msgData.Decode(bytes.NewBuffer(wireMsg.Data))
	if err != nil {
		return nil, fmt.Errorf("unable to decode incoming quote "+
			"accept message data: %w", err)
	}

	if err := msgData.Validate(); err != nil {
		return nil, fmt.Errorf("unable to validate incoming "+
			"quote accept message: %w", err)
	}

	// Before we can determine whether this is a buy or sell accept, we need
	// to look up the corresponding outgoing request message. This step is
	// necessary because the accept message data does not contain sufficient
	// data to distinguish between buy and sell accept messages.
	if sessionLookup == nil {
		return nil, fmt.Errorf("RFQ session lookup function is " +
			"required")
	}

	request, found := sessionLookup(msgData.ID.Val)
	if !found {
		return nil, fmt.Errorf("no outgoing request found for "+
			"incoming accept message: %s", msgData.ID.Val.String())
	}

	// Use the corresponding request to determine the type of accept
	// message.
	switch typedRequest := request.(type) {
	case *BuyRequest:
		return newBuyAcceptFromWireMsg(wireMsg, msgData, *typedRequest)
	case *SellRequest:
		return newSellAcceptFromWireMsg(wireMsg, msgData, *typedRequest)
	default:
		return nil, fmt.Errorf("unknown request type for incoming "+
			"accept message: %T", request)
	}
}
