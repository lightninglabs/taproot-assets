package rfqmsg

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
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
	// MsgTypeBuyRequest is the message type identifier for an asset buy
	// quote request message.
	MsgTypeBuyRequest = TapMessageTypeBaseOffset + 0

	// MsgTypeBuyAccept is the message type identifier for a quote accept
	// message.
	MsgTypeBuyAccept = TapMessageTypeBaseOffset + 1

	// MsgTypeSellRequest is the message type identifier for an asset sell
	// quote request message.
	MsgTypeSellRequest = TapMessageTypeBaseOffset + 2

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
	case MsgTypeBuyRequest:
		return NewBuyRequestMsgFromWire(wireMsg)
	case MsgTypeBuyAccept:
		return NewBuyAcceptFromWireMsg(wireMsg)
	case MsgTypeSellRequest:
		return NewSellRequestMsgFromWire(wireMsg)
	case MsgTypeSellAccept:
		return NewSellAcceptFromWireMsg(wireMsg)
	case MsgTypeReject:
		return NewQuoteRejectFromWireMsg(wireMsg)
	default:
		return nil, ErrUnknownMessageType
	}
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
