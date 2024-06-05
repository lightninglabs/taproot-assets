package rfqmsg

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

// SerialisedScid is a serialised short channel id (SCID).
type SerialisedScid uint64

// ID is the identifier for a RFQ message.
type ID [32]byte

// String returns the string representation of the ID.
func (id ID) String() string {
	return hex.EncodeToString(id[:])
}

// Scid returns the short channel id (SCID) of the RFQ message.
func (id ID) Scid() SerialisedScid {
	// Given valid RFQ message id, we then define a RFQ short channel id
	// (SCID) by taking the last 8 bytes of the RFQ message id and
	// interpreting them as a 64-bit integer.
	scidBytes := id[24:]

	scidInteger := binary.BigEndian.Uint64(scidBytes)
	return SerialisedScid(scidInteger)
}

// Record returns a TLV record that can be used to encode/decode an ID to/from a
// TLV stream.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (id *ID) Record() tlv.Record {
	const recordSize = sha256.Size

	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeStaticRecord(0, id, recordSize, IdEncoder, IdDecoder)
}

// MaxMessageType is the maximum supported message type value.
const MaxMessageType = lnwire.MessageType(math.MaxUint16)

// TapMessageTypeBaseOffset is the taproot-assets specific message type
// identifier base offset. All tap messages will have a type identifier that is
// greater than this value.
//
// This offset was chosen as the concatenation of the alphabetical index
// positions of the letters "t" (20), "a" (1), and "p" (16).
const TapMessageTypeBaseOffset = 20116 + lnwire.CustomTypeStart

const (
	// MsgTypeRequest is the message type identifier for a quote request
	// message.
	MsgTypeRequest = TapMessageTypeBaseOffset + 0

	// MsgTypeBuyAccept is the message type identifier for a quote accept
	// message.
	MsgTypeBuyAccept = TapMessageTypeBaseOffset + 1

	// MsgTypeSellAccept is the message type identifier for an asset sell
	// quote accept message.
	MsgTypeSellAccept = TapMessageTypeBaseOffset + 3

	// MsgTypeReject is the message type identifier for a quote
	// reject message.
	MsgTypeReject = TapMessageTypeBaseOffset + 4
)

var (
	// ErrUnknownMessageType is an error that is returned when an unknown
	// message type is encountered.
	ErrUnknownMessageType = errors.New("unknown message type")
)

// WireMessage is a struct that represents a general wire message.
type WireMessage struct {
	// Peer is the origin/destination peer for this message.
	Peer route.Vertex

	// MsgType is the protocol message type number.
	MsgType lnwire.MessageType

	// Data is the data exchanged.
	Data []byte
}

// NewIncomingMsgFromWire creates a new RFQ message from a wire message.
func NewIncomingMsgFromWire(wireMsg WireMessage) (IncomingMsg, error) {
	switch wireMsg.MsgType {
	case MsgTypeRequest:
		return NewIncomingRequestFromWire(wireMsg)
	case MsgTypeBuyAccept:
		return NewBuyAcceptFromWireMsg(wireMsg)
	case MsgTypeSellAccept:
		return NewSellAcceptFromWireMsg(wireMsg)
	case MsgTypeReject:
		return NewQuoteRejectFromWireMsg(wireMsg)
	default:
		return nil, ErrUnknownMessageType
	}
}

// WireMsgDataVersion specifies the version of the contents within a wire
// message data field.
type WireMsgDataVersion uint8

const (
	// V0 represents version 0 of the contents in a wire message data field.
	V0 WireMsgDataVersion = 0
)

// Record returns a TLV record that can be used to encode/decode a
// WireMsgDataVersion to/from a TLV stream.
func (v *WireMsgDataVersion) Record() tlv.Record {
	// We set the type to zero here because the type parameter in
	// tlv.RecordT will be used as the actual type.
	return tlv.MakeStaticRecord(
		0, v, 1, WireMsgDataVersionEncoder, WireMsgDataVersionDecoder,
	)
}

// WireMsgDataVersionEncoder is a function that can be used to encode a
// WireMsgDataVersion to a writer.
func WireMsgDataVersionEncoder(w io.Writer, val any, buf *[8]byte) error {
	if version, ok := val.(*WireMsgDataVersion); ok {
		versionUint8 := uint8(*version)
		return tlv.EUint8(w, &versionUint8, buf)
	}

	return tlv.NewTypeForEncodingErr(val, "WireMsgDataVersion")
}

// WireMsgDataVersionDecoder is a function that can be used to decode a
// WireMsgDataVersion from a reader.
func WireMsgDataVersionDecoder(r io.Reader, val any, buf *[8]byte,
	l uint64) error {

	if version, ok := val.(*WireMsgDataVersion); ok {
		var versionInt uint8
		err := tlv.DUint8(r, &versionInt, buf, l)
		if err != nil {
			return err
		}

		*version = WireMsgDataVersion(versionInt)
		return nil
	}

	return tlv.NewTypeForDecodingErr(val, "WireMsgDataVersion", l, 8)
}

// IncomingMsg is an interface that represents an inbound wire message
// that has been received from a peer.
type IncomingMsg interface {
	// String returns a human-readable string representation of the message.
	String() string
}

// OutgoingMsg is an interface that represents an outbound wire message
// that can be sent to a peer.
type OutgoingMsg interface {
	// String returns a human-readable string representation of the message.
	String() string

	// ToWire returns a wire message with a serialized data field.
	ToWire() (WireMessage, error)
}

// QuoteResponse defines an interface for handling incoming peer messages
// that serve as responses to quote requests.
type QuoteResponse interface {
	// MsgPeer returns the peer that sent the message.
	MsgPeer() route.Vertex

	// MsgID returns the quote request session ID.
	MsgID() ID

	// String returns a human-readable string representation of the message.
	String() string
}
