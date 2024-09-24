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
	latestAcceptWireMsgDataVersion = V0
)

type (
	// acceptInOutRateTick is a type alias for a record that represents the
	// in-out rate tick of a quote accept message.
	acceptInOutRateTick = tlv.OptionalRecordT[tlv.TlvType4, uint64]

	// acceptOutInRateTick is a type alias for a record that represents the
	// out-in rate tick of a quote accept message.
	acceptOutInRateTick = tlv.OptionalRecordT[tlv.TlvType5, uint64]
)

// acceptWireMsgData is a struct that represents the message data field for
// a quote accept wire message.
type acceptWireMsgData struct {
	// Version is the version of the message data.
	Version tlv.RecordT[tlv.TlvType0, WireMsgDataVersion]

	// ID is the unique identifier of the quote request.
	ID tlv.RecordT[tlv.TlvType1, ID]

	// Expiry is the expiry Unix timestamp (in seconds) of the quote
	// request. This timestamp defines the lifetime of both the suggested
	// rate tick and the quote request.
	Expiry tlv.RecordT[tlv.TlvType2, uint64]

	// Sig is a signature over the serialized contents of the message.
	Sig tlv.RecordT[tlv.TlvType3, [64]byte]

	// InOutRateTick is the tick rate for the accept, defined in
	// in_asset/out_asset. This is only set in a buy accept message.
	InOutRateTick acceptInOutRateTick

	// OutInRateTick is the tick rate for the accept, defined in
	// out_asset/in_asset. This is only set in a sell accept message.
	OutInRateTick acceptOutInRateTick
}

// newAcceptWireMsgDataFromBuy creates a new acceptWireMsgData from a buy
// accept message.
func newAcceptWireMsgDataFromBuy(q BuyAccept) acceptWireMsgData {
	version := tlv.NewPrimitiveRecord[tlv.TlvType0](q.Version)
	id := tlv.NewRecordT[tlv.TlvType1](q.ID)
	expiry := tlv.NewPrimitiveRecord[tlv.TlvType2](q.Expiry)
	sig := tlv.NewPrimitiveRecord[tlv.TlvType3](q.sig)

	// When processing a buy request/accept, the incoming asset must be
	// specified. Currently, we assume the outgoing asset is BTC,
	// considering the perspective of the quote request initiator.
	// To indicate that this quote accept wire message is for a buy request,
	// we set the in-out rate tick instead of the out-in rate tick.
	inOutRateTick := tlv.SomeRecordT[tlv.TlvType4](
		tlv.NewPrimitiveRecord[tlv.TlvType4](
			// TODO(ffranr): Temp solution.
			q.AssetRate.Coefficient.ToUint64(),
		),
	)

	// Encode message data component as TLV bytes.
	return acceptWireMsgData{
		Version:       version,
		ID:            id,
		Expiry:        expiry,
		Sig:           sig,
		InOutRateTick: inOutRateTick,
	}
}

// newAcceptWireMsgDataFromSell creates a new acceptWireMsgData from a sell
// accept message.
func newAcceptWireMsgDataFromSell(q SellAccept) acceptWireMsgData {
	version := tlv.NewPrimitiveRecord[tlv.TlvType0](q.Version)
	id := tlv.NewRecordT[tlv.TlvType1](q.ID)
	expiry := tlv.NewPrimitiveRecord[tlv.TlvType2](q.Expiry)
	sig := tlv.NewPrimitiveRecord[tlv.TlvType3](q.sig)

	// When processing a sell request/accept, the outgoing asset must be
	// specified. Currently, we assume the incoming asset is BTC,
	// considering the perspective of the quote request initiator.
	// To indicate that this quote accept wire message is for a sell
	// request, we set the out-in rate tick instead of the in-out rate tick.
	outInRateTick := tlv.SomeRecordT[tlv.TlvType5](
		tlv.NewPrimitiveRecord[tlv.TlvType5](
			uint64(q.BidPrice),
		),
	)

	// Encode message data component as TLV bytes.
	return acceptWireMsgData{
		Version:       version,
		ID:            id,
		Expiry:        expiry,
		Sig:           sig,
		OutInRateTick: outInRateTick,
	}
}

// Validate ensures that the quote accept message is valid.
func (m *acceptWireMsgData) Validate() error {
	// Ensure the version specified in the version field is supported.
	if m.Version.Val > latestAcceptWireMsgDataVersion {
		return fmt.Errorf("unsupported quote accept message data "+
			"version: %d", m.Version.Val)
	}

	// Ensure that the expiry is set to a future time.
	if m.Expiry.Val <= uint64(time.Now().Unix()) {
		return fmt.Errorf("expiry must be set to a future time")
	}

	// Ensure that at least one of the rate ticks is set.
	if m.InOutRateTick.IsNone() && m.OutInRateTick.IsNone() {
		return fmt.Errorf("at least one of the rate ticks must be set")
	}

	// Ensure that both rate ticks are not set.
	if m.InOutRateTick.IsSome() && m.OutInRateTick.IsSome() {
		return fmt.Errorf("both rate ticks cannot be set")
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
	}

	m.InOutRateTick.WhenSome(
		func(r tlv.RecordT[tlv.TlvType4, uint64]) {
			records = append(records, r.Record())
		},
	)

	m.OutInRateTick.WhenSome(
		func(r tlv.RecordT[tlv.TlvType5, uint64]) {
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

// Decode deserializes the acceptWireMsgData from the given io.Reader.
func (m *acceptWireMsgData) Decode(r io.Reader) error {
	// Define zero values for optional fields.
	inOutRateTick := m.InOutRateTick.Zero()
	outInRateTick := m.OutInRateTick.Zero()

	// Create a tlv stream with all the fields.
	tlvStream, err := tlv.NewStream(
		m.Version.Record(),
		m.ID.Record(),
		m.Expiry.Record(),
		m.Sig.Record(),

		inOutRateTick.Record(),
		outInRateTick.Record(),
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
	if _, ok := tlvMap[inOutRateTick.TlvType()]; ok {
		m.InOutRateTick = tlv.SomeRecordT(inOutRateTick)
	}

	if _, ok := tlvMap[outInRateTick.TlvType()]; ok {
		m.OutInRateTick = tlv.SomeRecordT(outInRateTick)
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
			"incoming accept message: %s", msgData.ID.Val)
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
