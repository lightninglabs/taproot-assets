package rfqmsg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"

	"github.com/lightningnetwork/lnd/aliasmgr"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

// SerialisedScid is a serialised short channel id (SCID).
type SerialisedScid uint64

// ID is the identifier for a RFQ message. A new ID _MUST_ be created using the
// NewID constructor to make sure it can be transformed into a valid SCID alias.
type ID [32]byte

// NewID generates a new random ID that can be transformed into a valid SCID
// alias that is in the allowed range for lnd.
func NewID() (ID, error) {
	// We make sure we don't loop endlessly in case we can't find a valid
	// ID. We should never reach this limit in practice, the chances for
	// finding a valid ID are very high.
	const maxNumTries = 10e6
	var (
		id       ID
		numTries int
	)

	for {
		_, err := rand.Read(id[:])
		if err != nil {
			return id, err
		}

		// We make sure that when deriving the SCID alias from the ID,
		// we get a valid alias. If not, we try again.
		scid := lnwire.NewShortChanIDFromInt(uint64(id.Scid()))
		if aliasmgr.IsAlias(scid) {
			break
		}

		numTries++

		if numTries >= maxNumTries {
			return id, errors.New("unable to find valid ID")
		}
	}

	return id, nil
}

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
	scid := lnwire.NewShortChanIDFromInt(scidInteger)

	return SerialisedScid(scid.ToUint64())
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

	// MsgTypeAccept is the message type identifier for a quote accept
	// message.
	MsgTypeAccept = TapMessageTypeBaseOffset + 1

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

// SessionLookup is a function that can be used to look up a session quote
// request message given a session ID.
type SessionLookup func(id ID) (OutgoingMsg, bool)

// NewIncomingMsgFromWire creates a new RFQ message from a wire message.
func NewIncomingMsgFromWire(wireMsg WireMessage,
	sessionLookup SessionLookup) (IncomingMsg, error) {

	switch wireMsg.MsgType {
	case MsgTypeRequest:
		return NewIncomingRequestFromWire(wireMsg)
	case MsgTypeAccept:
		return NewIncomingAcceptFromWire(wireMsg, sessionLookup)
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

	// V1 represents version 1 of the contents in a wire message data field.
	V1 WireMsgDataVersion = 1
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
	// MsgPeer returns the peer that sent the message.
	MsgPeer() route.Vertex

	// MsgID returns the quote request session ID.
	MsgID() ID

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
