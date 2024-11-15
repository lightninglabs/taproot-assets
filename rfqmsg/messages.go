package rfqmsg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/lightninglabs/taproot-assets/rfqmath"
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
func (id *ID) String() string {
	return hex.EncodeToString(id[:])
}

// Scid returns the short channel id (SCID) of the RFQ message.
func (id *ID) Scid() SerialisedScid {
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

// TransferType defines the type of transaction which will be performed if the
// quote request leads to an accepted agreement.
type TransferType uint8

const (
	// UnspecifiedTransferType represents an undefined or transfer type.
	UnspecifiedTransferType TransferType = 0

	// PayInvoiceTransferType indicates that the requesting peer wants to
	// pay a Lightning Network invoice using a taproot asset.
	PayInvoiceTransferType TransferType = 1

	// RecvPaymentTransferType indicates that the requesting peer wants
	// to receive taproot asset funds linked to a Lightning Network invoice.
	RecvPaymentTransferType TransferType = 2
)

// Record returns a TLV record that can be used to encode/decode a transfer type
// to/from a TLV stream.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (t *TransferType) Record() tlv.Record {
	// Note that we set the type here as zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeStaticRecord(
		0, t, 1, TransferTypeEncoder, TransferTypeDecoder,
	)
}

// TransferTypeEncoder is a function that can be used to encode a TransferType
// to a writer.
func TransferTypeEncoder(w io.Writer, val any, buf *[8]byte) error {
	if transferType, ok := val.(*TransferType); ok {
		transferTypeInt := uint8(*transferType)
		return tlv.EUint8(w, &transferTypeInt, buf)
	}

	return tlv.NewTypeForEncodingErr(val, "TransferType")
}

// TransferTypeDecoder is a function that can be used to decode a TransferType
// from a reader.
func TransferTypeDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	if transferType, ok := val.(*TransferType); ok {
		var transferTypeInt uint8
		err := tlv.DUint8(r, &transferTypeInt, buf, l)
		if err != nil {
			return err
		}

		*transferType = TransferType(transferTypeInt)
		return nil
	}

	return tlv.NewTypeForDecodingErr(val, "TransferType", l, 8)
}

// AssetRate represents the exchange rate of an asset to BTC, encapsulating
// both the rate in fixed-point format and an expiration timestamp.
//
// These fields are combined in AssetRate because each rate is inherently tied
// to an expiry, ensuring that the rate's validity is clear and time-limited.
type AssetRate struct {
	// Rate defines the exchange rate of asset units to BTC using a
	// fixed-point representation, ensuring precision for fractional asset
	// rates.
	Rate rfqmath.BigIntFixedPoint

	// Expiry indicates the UTC timestamp when this rate expires and should
	// no longer be considered valid.
	Expiry time.Time
}

// String returns a human-readable string representation of the asset rate.
func (a *AssetRate) String() string {
	// Format the expiry timestamp into a string.
	expiryUtc := a.Expiry.UTC()
	expiryString := expiryUtc.Format(time.RFC3339)

	return fmt.Sprintf("AssetRate(rate=%s, expiry=%s)", a.Rate.String(),
		expiryString)
}

// NewAssetRate creates a new asset rate.
func NewAssetRate(rate rfqmath.BigIntFixedPoint, expiry time.Time) AssetRate {
	return AssetRate{
		Rate:   rate,
		Expiry: expiry,
	}
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
	// ErrUnknownMessageType is an error returned when an unknown message
	// type is encountered.
	ErrUnknownMessageType = errors.New("unknown message type")

	// MilliSatPerBtc is the number of milli-satoshis in one bitcoin:
	// 100 billion = 100 * (10^9).
	MilliSatPerBtc = rfqmath.FixedPointFromUint64[rfqmath.BigInt](100, 9)
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

// TlvFixedPoint is a fixed-point that can be TLV encode/decode.
type TlvFixedPoint struct {
	// fp is the underlying BigInt fixed-point.
	fp rfqmath.BigIntFixedPoint
}

// NewTlvFixedPointFromBigInt creates a new fixed-point given a BigInt
// fixed-point.
func NewTlvFixedPointFromBigInt(fp rfqmath.BigIntFixedPoint) TlvFixedPoint {
	return TlvFixedPoint{
		fp: fp,
	}
}

// NewTlvFixedPointFromUint64 creates a new fixed point record given a `uint64`
// coefficient and scale.
func NewTlvFixedPointFromUint64(coefficient uint64, scale uint8) TlvFixedPoint {
	return TlvFixedPoint{
		fp: rfqmath.NewBigIntFixedPoint(coefficient, scale),
	}
}

// Record returns a TLV record that can be used to encode/decode an ID to/from a
// TLV stream.
//
// NOTE: This is part of the tlv.RecordProducer interface.
func (f *TlvFixedPoint) Record() tlv.Record {
	recordSize := func() uint64 {
		// 1 byte for the scale (uint8)
		scaleLength := uint64(1)

		coefficientBytesLength := uint64(len(f.fp.Coefficient.Bytes()))
		return scaleLength + coefficientBytesLength
	}

	// Note that the type here is set to zero, as when used with a
	// tlv.RecordT, the type param will be used as the type.
	return tlv.MakeDynamicRecord(
		0, f, recordSize, TlvFixedPointEncoder,
		TlvFixedPointDecoder,
	)
}

// IntoBigIntFixedPoint converts the TlvFixedPoint to a BigIntFixedPoint.
func (f *TlvFixedPoint) IntoBigIntFixedPoint() rfqmath.BigIntFixedPoint {
	return rfqmath.BigIntFixedPoint{
		Coefficient: f.fp.Coefficient,
		Scale:       f.fp.Scale,
	}
}
