package rfqmsg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// Sell accept message type field TLV types.

	TypeSellAcceptID        tlv.Type = 0
	TypeSellAcceptBidPrice  tlv.Type = 2
	TypeSellAcceptExpiry    tlv.Type = 4
	TypeSellAcceptSignature tlv.Type = 6
)

func TypeRecordSellAcceptID(id *ID) tlv.Record {
	const recordSize = 32

	return tlv.MakeStaticRecord(
		TypeSellAcceptID, id, recordSize, IdEncoder, IdDecoder,
	)
}

func TypeRecordSellAcceptBidPrice(bidPrice *lnwire.MilliSatoshi) tlv.Record {
	return tlv.MakeStaticRecord(
		TypeSellAcceptBidPrice, bidPrice, 8, milliSatoshiEncoder,
		milliSatoshiDecoder,
	)
}

func TypeRecordSellAcceptExpiry(expirySeconds *uint64) tlv.Record {
	return tlv.MakePrimitiveRecord(TypeSellAcceptExpiry, expirySeconds)
}

func TypeRecordSellAcceptSig(sig *[64]byte) tlv.Record {
	return tlv.MakePrimitiveRecord(TypeSellAcceptSignature, sig)
}

// sellAcceptMsgData is a struct that represents the data field of an asset sell
// quote request accept message.
type sellAcceptMsgData struct {
	// ID represents the unique identifier of the asset sell quote request
	// message that this response is associated with.
	ID ID

	// BidPrice is the bid price that the message author is willing to pay
	// for the asset that is for sale.
	BidPrice lnwire.MilliSatoshi

	// Expiry is the bid price expiry lifetime unix timestamp.
	Expiry uint64

	// sig is a signature over the serialized contents of the message.
	sig [64]byte
}

// records provides all TLV records for encoding/decoding.
func (q *sellAcceptMsgData) records() []tlv.Record {
	return []tlv.Record{
		TypeRecordSellAcceptID(&q.ID),
		TypeRecordSellAcceptBidPrice(&q.BidPrice),
		TypeRecordSellAcceptExpiry(&q.Expiry),
		TypeRecordSellAcceptSig(&q.sig),
	}
}

// Encode encodes the structure into a TLV stream.
func (q *sellAcceptMsgData) Encode(writer io.Writer) error {
	stream, err := tlv.NewStream(q.records()...)
	if err != nil {
		return err
	}
	return stream.Encode(writer)
}

// Decode decodes the structure from a TLV stream.
func (q *sellAcceptMsgData) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(q.records()...)
	if err != nil {
		return err
	}
	return stream.DecodeP2P(r)
}

// Bytes encodes the structure into a TLV stream and returns the bytes.
func (q *sellAcceptMsgData) Bytes() ([]byte, error) {
	var b bytes.Buffer
	err := q.Encode(&b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// SellAccept is a struct that represents a sell quote request accept message.
type SellAccept struct {
	// Peer is the peer that sent the quote request.
	Peer route.Vertex

	// AssetAmount is the amount of the asset that the accept message
	// is for.
	AssetAmount uint64

	// sellAcceptMsgData is the message data for the quote accept message.
	sellAcceptMsgData
}

// NewSellAcceptFromRequest creates a new instance of an asset sell quote accept
// message given an asset sell quote request message.
func NewSellAcceptFromRequest(request SellRequest, bidPrice lnwire.MilliSatoshi,
	expiry uint64) *SellAccept {

	return &SellAccept{
		Peer:        request.Peer,
		AssetAmount: request.AssetAmount,
		sellAcceptMsgData: sellAcceptMsgData{
			ID:       request.ID,
			BidPrice: bidPrice,
			Expiry:   expiry,
		},
	}
}

// NewSellAcceptFromWireMsg instantiates a new instance from a wire message.
func NewSellAcceptFromWireMsg(wireMsg WireMessage) (*SellAccept, error) {
	// Ensure that the message type is an accept message.
	if wireMsg.MsgType != MsgTypeSellAccept {
		return nil, fmt.Errorf("unable to create an asset sell "+
			"accept message from wire message of type %d",
			wireMsg.MsgType)
	}

	// Decode message data component from TLV bytes.
	var msgData sellAcceptMsgData
	err := msgData.Decode(bytes.NewReader(wireMsg.Data))
	if err != nil {
		return nil, fmt.Errorf("unable to decode sell accept "+
			"message data: %w", err)
	}

	return &SellAccept{
		Peer:              wireMsg.Peer,
		sellAcceptMsgData: msgData,
	}, nil
}

// ShortChannelId returns the short channel ID associated with the asset sale
// event.
func (q *SellAccept) ShortChannelId() SerialisedScid {
	// Given valid RFQ message id, we then define a RFQ short chain id
	// (SCID) by taking the last 8 bytes of the RFQ message id and
	// interpreting them as a 64-bit integer.
	scidBytes := q.ID[24:]

	scidInteger := binary.BigEndian.Uint64(scidBytes)
	return SerialisedScid(scidInteger)
}

// ToWire returns a wire message with a serialized data field.
//
// TODO(ffranr): This method should accept a signer so that we can generate a
// signature over the message data.
func (q *SellAccept) ToWire() (WireMessage, error) {
	// Encode message data component as TLV bytes.
	msgDataBytes, err := q.sellAcceptMsgData.Bytes()
	if err != nil {
		return WireMessage{}, fmt.Errorf("unable to encode message "+
			"data: %w", err)
	}

	return WireMessage{
		Peer:    q.Peer,
		MsgType: MsgTypeSellAccept,
		Data:    msgDataBytes,
	}, nil
}

// String returns a human-readable string representation of the message.
func (q *SellAccept) String() string {
	return fmt.Sprintf("SellAccept(peer=%x, id=%x, bid_price=%d, "+
		"expiry=%d, scid=%d)", q.Peer[:], q.ID, q.BidPrice, q.Expiry,
		q.ShortChannelId())
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*SellAccept)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*SellAccept)(nil)
