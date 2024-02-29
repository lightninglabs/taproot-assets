package rfqmsg

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// Request message type field TLV types.

	TypeRequestID            tlv.Type = 0
	TypeRequestAssetID       tlv.Type = 1
	TypeRequestAssetGroupKey tlv.Type = 3
	TypeRequestAssetAmount   tlv.Type = 4
	TypeRequestBidPrice      tlv.Type = 6
)

func TypeRecordRequestID(id *ID) tlv.Record {
	const recordSize = 32

	return tlv.MakeStaticRecord(
		TypeRequestID, id, recordSize,
		IdEncoder, IdDecoder,
	)
}

func IdEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(*ID); ok {
		id := [32]byte(*t)
		return tlv.EBytes32(w, &id, buf)
	}

	return tlv.NewTypeForEncodingErr(val, "MessageID")
}

func IdDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	const idBytesLen = 32

	if typ, ok := val.(*ID); ok {
		var idBytes [idBytesLen]byte

		err := tlv.DBytes32(r, &idBytes, buf, idBytesLen)
		if err != nil {
			return err
		}

		id := ID(idBytes)

		*typ = id
		return nil
	}

	return tlv.NewTypeForDecodingErr(val, "MessageID", l, idBytesLen)
}

func TypeRecordRequestAssetID(assetID **asset.ID) tlv.Record {
	const recordSize = sha256.Size

	return tlv.MakeStaticRecord(
		TypeRequestAssetID, assetID, recordSize,
		AssetIdEncoder, AssetIdDecoder,
	)
}

func AssetIdEncoder(w io.Writer, val any, buf *[8]byte) error {
	if t, ok := val.(**asset.ID); ok {
		id := [sha256.Size]byte(**t)
		return tlv.EBytes32(w, &id, buf)
	}

	return tlv.NewTypeForEncodingErr(val, "assetId")
}

func AssetIdDecoder(r io.Reader, val any, buf *[8]byte, l uint64) error {
	const assetIDBytesLen = sha256.Size

	if typ, ok := val.(**asset.ID); ok {
		var idBytes [assetIDBytesLen]byte

		err := tlv.DBytes32(r, &idBytes, buf, assetIDBytesLen)
		if err != nil {
			return err
		}

		id := asset.ID(idBytes)
		assetId := &id

		*typ = assetId
		return nil
	}

	return tlv.NewTypeForDecodingErr(val, "assetId", l, sha256.Size)
}

func TypeRecordRequestAssetGroupKey(groupKey **btcec.PublicKey) tlv.Record {
	const recordSize = btcec.PubKeyBytesLenCompressed

	return tlv.MakeStaticRecord(
		TypeRequestAssetGroupKey, groupKey, recordSize,
		asset.CompressedPubKeyEncoder, asset.CompressedPubKeyDecoder,
	)
}

func TypeRecordRequestAssetAmount(assetAmount *uint64) tlv.Record {
	return tlv.MakePrimitiveRecord(TypeRequestAssetAmount, assetAmount)
}

func TypeRecordRequestBidPrice(bid *lnwire.MilliSatoshi) tlv.Record {
	return tlv.MakeStaticRecord(
		TypeRequestBidPrice, bid, 8,
		milliSatoshiEncoder, milliSatoshiDecoder,
	)
}

// requestMsgData is a struct that represents the message data from a quote
// request message.
type requestMsgData struct {
	// ID is the unique identifier of the quote request.
	ID ID

	// AssetID represents the identifier of the asset for which the peer
	// is requesting a quote.
	AssetID *asset.ID

	// AssetGroupKey is the public group key of the asset for which the peer
	// is requesting a quote.
	AssetGroupKey *btcec.PublicKey

	// AssetAmount is the amount of the asset for which the peer is
	// requesting a quote.
	AssetAmount uint64

	// BidPrice is the peer's proposed bid price for the asset amount.
	BidPrice lnwire.MilliSatoshi
}

// Validate ensures that the quote request is valid.
func (q *requestMsgData) Validate() error {
	if q.AssetID == nil && q.AssetGroupKey == nil {
		return fmt.Errorf("asset id and group key cannot both be nil")
	}

	if q.AssetID != nil && q.AssetGroupKey != nil {
		return fmt.Errorf("asset id and group key cannot both be " +
			"non-nil")
	}

	return nil
}

// EncodeRecords determines the non-nil records to include when encoding an
// at runtime.
func (q *requestMsgData) encodeRecords() []tlv.Record {
	var records []tlv.Record

	records = append(records, TypeRecordRequestID(&q.ID))

	if q.AssetID != nil {
		records = append(records, TypeRecordRequestAssetID(&q.AssetID))
	}

	if q.AssetGroupKey != nil {
		record := TypeRecordRequestAssetGroupKey(&q.AssetGroupKey)
		records = append(records, record)
	}

	records = append(records, TypeRecordRequestAssetAmount(&q.AssetAmount))
	records = append(records, TypeRecordRequestBidPrice(&q.BidPrice))

	return records
}

// Encode encodes the structure into a TLV stream.
func (q *requestMsgData) Encode(writer io.Writer) error {
	stream, err := tlv.NewStream(q.encodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(writer)
}

// Bytes encodes the structure into a TLV stream and returns the bytes.
func (q *requestMsgData) Bytes() ([]byte, error) {
	var b bytes.Buffer
	err := q.Encode(&b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// DecodeRecords provides all TLV records for decoding.
func (q *requestMsgData) decodeRecords() []tlv.Record {
	return []tlv.Record{
		TypeRecordRequestID(&q.ID),
		TypeRecordRequestAssetID(&q.AssetID),
		TypeRecordRequestAssetGroupKey(&q.AssetGroupKey),
		TypeRecordRequestAssetAmount(&q.AssetAmount),
		TypeRecordRequestBidPrice(&q.BidPrice),
	}
}

// Decode decodes the structure from a TLV stream.
func (q *requestMsgData) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(q.decodeRecords()...)
	if err != nil {
		return err
	}
	return stream.DecodeP2P(r)
}

// Request is a struct that represents a request for a quote (RFQ).
type Request struct {
	// Peer is the peer that sent the quote request.
	Peer route.Vertex

	// requestMsgData is the message data for the quote request
	// message.
	requestMsgData
}

// NewRequest creates a new quote request.
func NewRequest(peer route.Vertex, assetID *asset.ID,
	assetGroupKey *btcec.PublicKey, assetAmount uint64,
	bidPrice lnwire.MilliSatoshi) (*Request, error) {

	var id [32]byte
	_, err := rand.Read(id[:])
	if err != nil {
		return nil, fmt.Errorf("unable to generate random "+
			"quote request id: %w", err)
	}

	return &Request{
		Peer: peer,
		requestMsgData: requestMsgData{
			ID:            id,
			AssetID:       assetID,
			AssetGroupKey: assetGroupKey,
			AssetAmount:   assetAmount,
			BidPrice:      bidPrice,
		},
	}, nil
}

// NewRequestMsgFromWire instantiates a new instance from a wire message.
func NewRequestMsgFromWire(wireMsg WireMessage) (*Request, error) {
	// Ensure that the message type is a quote request message.
	if wireMsg.MsgType != MsgTypeRequest {
		return nil, fmt.Errorf("unable to create a quote request "+
			"message from wire message of type %d", wireMsg.MsgType)
	}

	var msgData requestMsgData
	err := msgData.Decode(bytes.NewBuffer(wireMsg.Data))
	if err != nil {
		return nil, fmt.Errorf("unable to decode incoming quote "+
			"request message data: %w", err)
	}

	quoteRequest := Request{
		Peer:           wireMsg.Peer,
		requestMsgData: msgData,
	}

	// Perform basic sanity checks on the quote request.
	err = quoteRequest.Validate()
	if err != nil {
		return nil, fmt.Errorf("unable to validate quote request: %w",
			err)
	}

	return &quoteRequest, nil
}

// Validate ensures that the quote request is valid.
func (q *Request) Validate() error {
	return q.requestMsgData.Validate()
}

// ToWire returns a wire message with a serialized data field.
func (q *Request) ToWire() (WireMessage, error) {
	// Encode message data component as TLV bytes.
	msgDataBytes, err := q.requestMsgData.Bytes()
	if err != nil {
		return WireMessage{}, fmt.Errorf("unable to encode message "+
			"data: %w", err)
	}

	return WireMessage{
		Peer:    q.Peer,
		MsgType: MsgTypeRequest,
		Data:    msgDataBytes,
	}, nil
}

// String returns a human-readable string representation of the message.
func (q *Request) String() string {
	var groupKeyBytes []byte
	if q.AssetGroupKey != nil {
		groupKeyBytes = q.AssetGroupKey.SerializeCompressed()
	}

	return fmt.Sprintf("Request(peer=%s, id=%x, asset_id=%s, "+
		"asset_group_key=%x, asset_amount=%d, bid_price=%d)", q.Peer,
		q.ID, q.AssetID, groupKeyBytes, q.AssetAmount, q.BidPrice)
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*Request)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*Request)(nil)
