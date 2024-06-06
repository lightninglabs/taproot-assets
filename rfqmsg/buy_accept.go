package rfqmsg

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// Buy accept message type field TLV types.

	TypeBuyAcceptVersion   tlv.Type = 0
	TypeBuyAcceptID        tlv.Type = 2
	TypeBuyAcceptAskPrice  tlv.Type = 4
	TypeBuyAcceptExpiry    tlv.Type = 6
	TypeBuyAcceptSignature tlv.Type = 8
	TypeBuyAcceptAssetID   tlv.Type = 10
)

func TypeRecordBuyAcceptVersion(version *WireMsgDataVersion) tlv.Record {
	const recordSize = 1

	return tlv.MakeStaticRecord(
		TypeBuyAcceptVersion, version, recordSize,
		WireMsgDataVersionEncoder, WireMsgDataVersionDecoder,
	)
}

func TypeRecordBuyAcceptID(id *ID) tlv.Record {
	const recordSize = 32

	return tlv.MakeStaticRecord(
		TypeBuyAcceptID, id, recordSize, IdEncoder, IdDecoder,
	)
}

func TypeRecordBuyAcceptAskPrice(askPrice *lnwire.MilliSatoshi) tlv.Record {
	return tlv.MakeStaticRecord(
		TypeBuyAcceptAskPrice, askPrice, 8, milliSatoshiEncoder,
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

func TypeRecordBuyAcceptExpiry(expirySeconds *uint64) tlv.Record {
	return tlv.MakePrimitiveRecord(TypeBuyAcceptExpiry, expirySeconds)
}

func TypeRecordBuyAcceptSig(sig *[64]byte) tlv.Record {
	return tlv.MakePrimitiveRecord(TypeBuyAcceptSignature, sig)
}

func TypeRecordBuyAcceptAssetID(assetID **asset.ID) tlv.Record {
	const recordSize = sha256.Size

	return tlv.MakeStaticRecord(
		TypeBuyAcceptAssetID, assetID, recordSize,
		AssetIdEncoder, AssetIdDecoder,
	)
}

const (
	// latestBuyAcceptVersion is the latest supported buy accept wire
	// message data field version.
	latestBuyAcceptVersion = V0
)

// buyAcceptMsgData is a struct that represents the data field of a quote
// accept message.
type buyAcceptMsgData struct {
	// Version is the version of the message data.
	Version WireMsgDataVersion

	// ID represents the unique identifier of the quote request message that
	// this response is associated with.
	ID ID

	// AskPrice is the asking price of the quote in milli-satoshis per asset
	// unit.
	AskPrice lnwire.MilliSatoshi

	// Expiry is the asking price expiry lifetime unix timestamp.
	Expiry uint64

	// sig is a signature over the serialized contents of the message.
	sig [64]byte

	// AssetID is the asset ID of the asset that the accept message is for.
	AssetID *asset.ID
}

// encodeRecords provides all TLV records for encoding.
func (q *buyAcceptMsgData) encodeRecords() []tlv.Record {
	records := []tlv.Record{
		TypeRecordBuyAcceptVersion(&q.Version),
		TypeRecordBuyAcceptID(&q.ID),
		TypeRecordBuyAcceptAskPrice(&q.AskPrice),
		TypeRecordBuyAcceptExpiry(&q.Expiry),
		TypeRecordBuyAcceptSig(&q.sig),
	}

	if q.AssetID != nil {
		records = append(
			records, TypeRecordBuyAcceptAssetID(&q.AssetID),
		)
	}

	return records
}

// decodeRecords provides all TLV records for decoding.
func (q *buyAcceptMsgData) decodeRecords() []tlv.Record {
	return []tlv.Record{
		TypeRecordBuyAcceptVersion(&q.Version),
		TypeRecordBuyAcceptID(&q.ID),
		TypeRecordBuyAcceptAskPrice(&q.AskPrice),
		TypeRecordBuyAcceptExpiry(&q.Expiry),
		TypeRecordBuyAcceptSig(&q.sig),
		TypeRecordBuyAcceptAssetID(&q.AssetID),
	}
}

// Encode encodes the structure into a TLV stream.
func (q *buyAcceptMsgData) Encode(writer io.Writer) error {
	stream, err := tlv.NewStream(q.encodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(writer)
}

// Decode decodes the structure from a TLV stream.
func (q *buyAcceptMsgData) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(q.decodeRecords()...)
	if err != nil {
		return err
	}
	return stream.DecodeP2P(r)
}

// Bytes encodes the structure into a TLV stream and returns the bytes.
func (q *buyAcceptMsgData) Bytes() ([]byte, error) {
	var b bytes.Buffer
	err := q.Encode(&b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// BuyAccept is a struct that represents a buy quote request accept message.
type BuyAccept struct {
	// Peer is the peer that sent the quote request.
	Peer route.Vertex

	// Request is the quote request message that this message responds to.
	// This field is not included in the wire message.
	Request BuyRequest

	// AssetAmount is the amount of the asset that the accept message
	// is for.
	AssetAmount uint64

	// buyAcceptMsgData is the message data for the quote accept message.
	buyAcceptMsgData
}

// NewBuyAcceptFromRequest creates a new instance of a quote accept message
// given a quote request message.
func NewBuyAcceptFromRequest(request BuyRequest, askPrice lnwire.MilliSatoshi,
	expiry uint64) *BuyAccept {

	return &BuyAccept{
		Peer:        request.Peer,
		AssetAmount: request.AssetAmount,
		Request:     request,
		buyAcceptMsgData: buyAcceptMsgData{
			Version:  latestBuyAcceptVersion,
			ID:       request.ID,
			AskPrice: askPrice,
			Expiry:   expiry,
			AssetID:  request.AssetID,
		},
	}
}

// NewBuyAcceptFromWireMsg instantiates a new instance from a wire message.
func NewBuyAcceptFromWireMsg(wireMsg WireMessage) (*BuyAccept, error) {
	// Ensure that the message type is an accept message.
	if wireMsg.MsgType != MsgTypeBuyAccept {
		return nil, fmt.Errorf("unable to create an accept message "+
			"from wire message of type %d", wireMsg.MsgType)
	}

	// Decode message data component from TLV bytes.
	var msgData buyAcceptMsgData
	err := msgData.Decode(bytes.NewReader(wireMsg.Data))
	if err != nil {
		return nil, fmt.Errorf("unable to decode quote accept "+
			"message data: %w", err)
	}

	// Ensure that the message version is supported.
	if msgData.Version > latestBuyAcceptVersion {
		return nil, fmt.Errorf("unsupported buy accept message "+
			"version: %d", msgData.Version)
	}

	return &BuyAccept{
		Peer:             wireMsg.Peer,
		buyAcceptMsgData: msgData,
	}, nil
}

// ShortChannelId returns the short channel ID of the quote accept.
func (q *BuyAccept) ShortChannelId() SerialisedScid {
	return q.ID.Scid()
}

// ToWire returns a wire message with a serialized data field.
//
// TODO(ffranr): This method should accept a signer so that we can generate a
// signature over the message data.
func (q *BuyAccept) ToWire() (WireMessage, error) {
	// Encode message data component as TLV bytes.
	msgDataBytes, err := q.buyAcceptMsgData.Bytes()
	if err != nil {
		return WireMessage{}, fmt.Errorf("unable to encode message "+
			"data: %w", err)
	}

	return WireMessage{
		Peer:    q.Peer,
		MsgType: MsgTypeBuyAccept,
		Data:    msgDataBytes,
	}, nil
}

// MsgPeer returns the peer that sent the message.
func (q *BuyAccept) MsgPeer() route.Vertex {
	return q.Peer
}

// MsgID returns the quote request session ID.
func (q *BuyAccept) MsgID() ID {
	return q.ID
}

// String returns a human-readable string representation of the message.
func (q *BuyAccept) String() string {
	return fmt.Sprintf("BuyAccept(peer=%x, id=%x, ask_price=%d, "+
		"expiry=%d, scid=%d)",
		q.Peer[:], q.ID[:], q.AskPrice, q.Expiry, q.ShortChannelId())
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*BuyAccept)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*BuyAccept)(nil)
