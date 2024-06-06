package rfqmsg

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// Sell accept message type field TLV types.

	TypeSellAcceptVersion   tlv.Type = 0
	TypeSellAcceptID        tlv.Type = 2
	TypeSellAcceptBidPrice  tlv.Type = 4
	TypeSellAcceptExpiry    tlv.Type = 6
	TypeSellAcceptSignature tlv.Type = 8
	TypeSellAcceptAssetID   tlv.Type = 10
)

func TypeRecordSellAcceptVersion(version *WireMsgDataVersion) tlv.Record {
	const recordSize = 1

	return tlv.MakeStaticRecord(
		TypeSellAcceptVersion, version, recordSize,
		WireMsgDataVersionEncoder, WireMsgDataVersionDecoder,
	)
}

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

func TypeRecordSellAcceptAssetID(assetID **asset.ID) tlv.Record {
	const recordSize = sha256.Size

	return tlv.MakeStaticRecord(
		TypeSellAcceptAssetID, assetID, recordSize,
		AssetIdEncoder, AssetIdDecoder,
	)
}

const (
	// latestSellAcceptVersion is the latest supported sell accept wire
	// message data field version.
	latestSellAcceptVersion = V0
)

// sellAcceptMsgData is a struct that represents the data field of an asset sell
// quote request accept message.
type sellAcceptMsgData struct {
	// Version is the version of the message data.
	Version WireMsgDataVersion

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

	// AssetID is the asset ID of the asset that the accept message is for.
	AssetID *asset.ID
}

// encodeRecords provides all TLV records for encoding.
func (q *sellAcceptMsgData) encodeRecords() []tlv.Record {
	records := []tlv.Record{
		TypeRecordSellAcceptVersion(&q.Version),
		TypeRecordSellAcceptID(&q.ID),
		TypeRecordSellAcceptBidPrice(&q.BidPrice),
		TypeRecordSellAcceptExpiry(&q.Expiry),
		TypeRecordSellAcceptSig(&q.sig),
	}

	if q.AssetID != nil {
		records = append(
			records, TypeRecordSellAcceptAssetID(&q.AssetID),
		)
	}

	return records
}

// decodeRecords provides all TLV records for decoding.
func (q *sellAcceptMsgData) decodeRecords() []tlv.Record {
	return []tlv.Record{
		TypeRecordSellAcceptVersion(&q.Version),
		TypeRecordSellAcceptID(&q.ID),
		TypeRecordSellAcceptBidPrice(&q.BidPrice),
		TypeRecordSellAcceptExpiry(&q.Expiry),
		TypeRecordSellAcceptSig(&q.sig),
		TypeRecordSellAcceptAssetID(&q.AssetID),
	}
}

// Encode encodes the structure into a TLV stream.
func (q *sellAcceptMsgData) Encode(writer io.Writer) error {
	stream, err := tlv.NewStream(q.encodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(writer)
}

// Decode decodes the structure from a TLV stream.
func (q *sellAcceptMsgData) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(q.decodeRecords()...)
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

	// Request is the quote request message that this message responds to.
	// This field is not included in the wire message.
	Request SellRequest

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
		Request:     request,
		sellAcceptMsgData: sellAcceptMsgData{
			Version:  latestSellAcceptVersion,
			ID:       request.ID,
			BidPrice: bidPrice,
			Expiry:   expiry,
			AssetID:  request.AssetID,
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

	// Ensure that the message version is supported.
	if msgData.Version > latestSellAcceptVersion {
		return nil, fmt.Errorf("unsupported sell accept message "+
			"version: %d", msgData.Version)
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

// MsgPeer returns the peer that sent the message.
func (q *SellAccept) MsgPeer() route.Vertex {
	return q.Peer
}

// MsgID returns the quote request session ID.
func (q *SellAccept) MsgID() ID {
	return q.ID
}

// String returns a human-readable string representation of the message.
func (q *SellAccept) String() string {
	return fmt.Sprintf("SellAccept(peer=%x, id=%x, bid_price=%d, "+
		"expiry=%d, scid=%d)", q.Peer[:], q.ID[:], q.BidPrice, q.Expiry,
		q.ShortChannelId())
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*SellAccept)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*SellAccept)(nil)
