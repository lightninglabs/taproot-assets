package rfqmsg

import (
	"bytes"
	"fmt"
	"io"

	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

// rejectErrEncoder is a function that encodes a RejectErr into a writer.
func rejectErrEncoder(w io.Writer, val any, buf *[8]byte) error {
	if typ, ok := val.(*RejectErr); ok {
		if err := tlv.EUint8(w, &typ.Code, buf); err != nil {
			return err
		}

		msgBytes := []byte(typ.Msg)
		if err := tlv.EVarBytes(w, &msgBytes, buf); err != nil {
			return err
		}

		return nil
	}

	return tlv.NewTypeForEncodingErr(val, "RejectErr")
}

// rejectErrDecoder is a function that decodes a RejectErr from a reader.
func rejectErrDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if typ, ok := val.(*RejectErr); ok {
		var rejectCode uint8
		if err := tlv.DUint8(r, &rejectCode, buf, 1); err != nil {
			return err
		}

		var errMsgBytes []byte
		err := tlv.DVarBytes(r, &errMsgBytes, buf, l-1)
		if err != nil {
			return err
		}

		*typ = RejectErr{
			Code: rejectCode,
			Msg:  string(errMsgBytes),
		}

		return nil
	}

	return tlv.NewTypeForDecodingErr(val, "RejectErr", l, l)
}

// RejectErr is a struct that represents the error code and message of a quote
// reject message.
type RejectErr struct {
	// Code is the error code that provides the reason for the rejection.
	Code uint8

	// Msg is the error message that provides the reason for the rejection.
	Msg string
}

// Record returns a TLV record that can be used to encode/decode a RejectErr
// to/from a TLV stream.
func (v *RejectErr) Record() tlv.Record {
	sizeFunc := func() uint64 {
		return 1 + uint64(len(v.Msg))
	}

	// We set the type to zero here because the type parameter in
	// tlv.RecordT will be used as the actual type.
	return tlv.MakeDynamicRecord(
		0, v, sizeFunc, rejectErrEncoder, rejectErrDecoder,
	)
}

var (
	// ErrUnknownReject is the error code for when the quote is rejected
	// for an unspecified reason.
	ErrUnknownReject = RejectErr{
		Code: 0,
		Msg:  "unknown reject error",
	}

	// ErrPriceOracleUnavailable is the error code for when the price oracle
	// is unavailable.
	ErrPriceOracleUnavailable = RejectErr{
		Code: 1,
		Msg:  "price oracle unavailable",
	}
)

const (
	// latestRejectVersion is the latest supported reject wire message data
	// field version.
	latestRejectVersion = V1
)

// rejectWireMsgData is a struct that represents the data field of a quote
// reject wire message.
type rejectWireMsgData struct {
	// Version is the version of the message data.
	Version tlv.RecordT[tlv.TlvType0, WireMsgDataVersion]

	// ID represents the unique identifier of the quote request message that
	// this response is associated with.
	ID tlv.RecordT[tlv.TlvType2, ID]

	// Err is the error code and message that provides the reason for the
	// rejection.
	Err tlv.RecordT[tlv.TlvType5, RejectErr]
}

// records returns all records for encoding/decoding.
func (q *rejectWireMsgData) records() []tlv.Record {
	return []tlv.Record{
		q.Version.Record(),
		q.ID.Record(),
		q.Err.Record(),
	}
}

// Encode encodes the structure into a TLV stream.
func (q *rejectWireMsgData) Encode(writer io.Writer) error {
	stream, err := tlv.NewStream(q.records()...)
	if err != nil {
		return err
	}
	return stream.Encode(writer)
}

// Decode decodes the structure from a TLV stream.
func (q *rejectWireMsgData) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(q.records()...)
	if err != nil {
		return err
	}
	return stream.DecodeP2P(r)
}

// Bytes encodes the structure into a TLV stream and returns the bytes.
func (q *rejectWireMsgData) Bytes() ([]byte, error) {
	var b bytes.Buffer
	err := q.Encode(&b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// Reject is a struct that represents a quote reject message.
type Reject struct {
	// Peer is the peer that sent the quote request.
	Peer route.Vertex

	// rejectWireMsgData is the message data for the quote reject wire
	// message.
	rejectWireMsgData
}

// NewReject creates a new instance of a quote reject message.
func NewReject(peer route.Vertex, requestId ID,
	rejectErr RejectErr) *Reject {

	return &Reject{
		Peer: peer,
		rejectWireMsgData: rejectWireMsgData{
			Version: tlv.NewRecordT[tlv.TlvType0](
				latestRejectVersion,
			),
			ID:  tlv.NewRecordT[tlv.TlvType2](requestId),
			Err: tlv.NewRecordT[tlv.TlvType5](rejectErr),
		},
	}
}

// NewQuoteRejectFromWireMsg instantiates a new instance from a wire message.
func NewQuoteRejectFromWireMsg(wireMsg WireMessage) (*Reject, error) {
	// Ensure that the message type is a reject message.
	if wireMsg.MsgType != MsgTypeReject {
		return nil, fmt.Errorf("unable to create a reject message "+
			"from wire message of type %d", wireMsg.MsgType)
	}

	// Decode message data component from TLV bytes.
	var msgData rejectWireMsgData
	err := msgData.Decode(bytes.NewReader(wireMsg.Data))
	if err != nil {
		return nil, fmt.Errorf("unable to decode quote reject "+
			"message data: %w", err)
	}

	// Ensure that the message version is supported.
	if msgData.Version.Val != latestRejectVersion {
		return nil, fmt.Errorf("unsupported reject message version: %d",
			msgData.Version.Val)
	}

	return &Reject{
		Peer:              wireMsg.Peer,
		rejectWireMsgData: msgData,
	}, nil
}

// ToWire returns a wire message with a serialized data field.
func (q *Reject) ToWire() (WireMessage, error) {
	// Encode message data component as TLV bytes.
	msgDataBytes, err := q.rejectWireMsgData.Bytes()
	if err != nil {
		return WireMessage{}, fmt.Errorf("unable to encode message "+
			"data: %w", err)
	}

	return WireMessage{
		Peer:    q.Peer,
		MsgType: MsgTypeReject,
		Data:    msgDataBytes,
	}, nil
}

// MsgPeer returns the peer that sent the message.
func (q *Reject) MsgPeer() route.Vertex {
	return q.Peer
}

// MsgID returns the quote request session ID.
func (q *Reject) MsgID() ID {
	return q.ID.Val
}

// String returns a human-readable string representation of the message.
func (q *Reject) String() string {
	return fmt.Sprintf("Reject(id=%x, err_code=%d, err_msg=%s)",
		q.ID.Val[:], q.Err.Val.Code, q.Err.Val.Msg)
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*Reject)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*Reject)(nil)
