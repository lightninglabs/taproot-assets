package rfqmsg

import (
	"encoding/hex"
	"errors"
	"math"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

// ID is the identifier for a RFQ message.
type ID [32]byte

// String returns the string representation of the ID.
func (id ID) String() string {
	return hex.EncodeToString(id[:])
}

// SerialisedScid is a serialised short channel id (SCID).
type SerialisedScid uint64

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

	// MsgTypeReject is the message type identifier for a quote
	// reject message.
	MsgTypeReject = TapMessageTypeBaseOffset + 2
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
