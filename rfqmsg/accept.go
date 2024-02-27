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
	// Accept message type field TLV types.

	TypeAcceptID        tlv.Type = 0
	TypeAcceptAskPrice  tlv.Type = 2
	TypeAcceptExpiry    tlv.Type = 4
	TypeAcceptSignature tlv.Type = 6
)

func TypeRecordAcceptID(id *ID) tlv.Record {
	const recordSize = 32

	return tlv.MakeStaticRecord(
		TypeAcceptID, id, recordSize, IdEncoder, IdDecoder,
	)
}

func TypeRecordAcceptAskPrice(askPrice *lnwire.MilliSatoshi) tlv.Record {
	return tlv.MakeStaticRecord(
		TypeAcceptAskPrice, askPrice, 8, milliSatoshiEncoder,
		milliSatoshiDecoder,
	)
}

func milliSatoshiEncoder(w io.Writer, val interface{}, buf *[8]byte) error {
	if ms, ok := val.(*lnwire.MilliSatoshi); ok {
		msUint64 := uint64(*ms)
		return tlv.EUint64(w, &msUint64, buf)
	}

	return tlv.NewTypeForEncodingErr(val, "MilliSatoshi")
}

func milliSatoshiDecoder(r io.Reader, val interface{}, buf *[8]byte,
	l uint64) error {

	if ms, ok := val.(*lnwire.MilliSatoshi); ok {
		var msInt uint64
		err := tlv.DUint64(r, &msInt, buf, l)
		if err != nil {
			return err
		}

		*ms = lnwire.MilliSatoshi(msInt)
		return nil
	}

	return tlv.NewTypeForDecodingErr(val, "MilliSatoshi", l, 8)
}

func TypeRecordAcceptExpiry(expirySeconds *uint64) tlv.Record {
	return tlv.MakePrimitiveRecord(
		TypeAcceptExpiry, expirySeconds,
	)
}

func TypeRecordAcceptSig(sig *[64]byte) tlv.Record {
	return tlv.MakePrimitiveRecord(
		TypeAcceptSignature, sig,
	)
}

// acceptMsgData is a struct that represents the data field of a quote
// accept message.
type acceptMsgData struct {
	// ID represents the unique identifier of the quote request message that
	// this response is associated with.
	ID ID

	// AskPrice is the asking price of the quote.
	AskPrice lnwire.MilliSatoshi

	// Expiry is the asking price expiry lifetime unix timestamp.
	Expiry uint64

	// sig is a signature over the serialized contents of the message.
	sig [64]byte
}

// encodeRecords determines the non-nil records to include when encoding at
// runtime.
func (q *acceptMsgData) encodeRecords() []tlv.Record {
	var records []tlv.Record

	// Add id record.
	records = append(records, TypeRecordAcceptID(&q.ID))

	// Add ask price record.
	records = append(records, TypeRecordAcceptAskPrice(&q.AskPrice))

	// Add expiry record.
	records = append(
		records, TypeRecordAcceptExpiry(&q.Expiry),
	)

	// Add signature record.
	records = append(
		records, TypeRecordAcceptSig(&q.sig),
	)

	return records
}

// Encode encodes the structure into a TLV stream.
func (q *acceptMsgData) Encode(writer io.Writer) error {
	stream, err := tlv.NewStream(q.encodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(writer)
}

// DecodeRecords provides all TLV records for decoding.
func (q *acceptMsgData) decodeRecords() []tlv.Record {
	return []tlv.Record{
		TypeRecordAcceptID(&q.ID),
		TypeRecordAcceptAskPrice(&q.AskPrice),
		TypeRecordAcceptExpiry(&q.Expiry),
		TypeRecordAcceptSig(&q.sig),
	}
}

// Decode decodes the structure from a TLV stream.
func (q *acceptMsgData) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(q.decodeRecords()...)
	if err != nil {
		return err
	}
	return stream.DecodeP2P(r)
}

// Bytes encodes the structure into a TLV stream and returns the bytes.
func (q *acceptMsgData) Bytes() ([]byte, error) {
	var b bytes.Buffer
	err := q.Encode(&b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// Accept is a struct that represents an accepted quote message.
type Accept struct {
	// Peer is the peer that sent the quote request.
	Peer route.Vertex

	// AssetAmount is the amount of the asset that the accept message
	// is for.
	AssetAmount uint64

	// acceptMsgData is the message data for the quote accept message.
	acceptMsgData
}

// NewAcceptFromRequest creates a new instance of a quote accept message given
// a quote request message.
func NewAcceptFromRequest(request BuyRequest, askPrice lnwire.MilliSatoshi,
	expiry uint64) *Accept {

	return &Accept{
		Peer:        request.Peer,
		AssetAmount: request.AssetAmount,
		acceptMsgData: acceptMsgData{
			ID:       request.ID,
			AskPrice: askPrice,
			Expiry:   expiry,
		},
	}
}

// NewAcceptFromWireMsg instantiates a new instance from a wire message.
func NewAcceptFromWireMsg(wireMsg WireMessage) (*Accept, error) {
	// Ensure that the message type is an accept message.
	if wireMsg.MsgType != MsgTypeAccept {
		return nil, fmt.Errorf("unable to create an accept message "+
			"from wire message of type %d", wireMsg.MsgType)
	}

	// Decode message data component from TLV bytes.
	var msgData acceptMsgData
	err := msgData.Decode(bytes.NewReader(wireMsg.Data))
	if err != nil {
		return nil, fmt.Errorf("unable to decode quote accept "+
			"message data: %w", err)
	}

	return &Accept{
		Peer:          wireMsg.Peer,
		acceptMsgData: msgData,
	}, nil
}

// ShortChannelId returns the short channel ID of the quote accept.
func (q *Accept) ShortChannelId() SerialisedScid {
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
func (q *Accept) ToWire() (WireMessage, error) {
	// Encode message data component as TLV bytes.
	msgDataBytes, err := q.acceptMsgData.Bytes()
	if err != nil {
		return WireMessage{}, fmt.Errorf("unable to encode message "+
			"data: %w", err)
	}

	return WireMessage{
		Peer:    q.Peer,
		MsgType: MsgTypeAccept,
		Data:    msgDataBytes,
	}, nil
}

// String returns a human-readable string representation of the message.
func (q *Accept) String() string {
	return fmt.Sprintf("Accept(peer=%x, id=%x, ask_price=%d, expiry=%d)",
		q.Peer[:], q.ID, q.AskPrice, q.Expiry)
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*Accept)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*Accept)(nil)
