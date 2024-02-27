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
	// Buy request message type field TLV types.

	TypeBuyRequestID            tlv.Type = 0
	TypeBuyRequestAssetID       tlv.Type = 1
	TypeBuyRequestAssetGroupKey tlv.Type = 3
	TypeBuyRequestAssetAmount   tlv.Type = 4
	TypeBuyRequestBidPrice      tlv.Type = 6
)

func TypeRecordBuyRequestID(id *ID) tlv.Record {
	const recordSize = 32

	return tlv.MakeStaticRecord(
		TypeBuyRequestID, id, recordSize,
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

func TypeRecordBuyRequestAssetID(assetID **asset.ID) tlv.Record {
	const recordSize = sha256.Size

	return tlv.MakeStaticRecord(
		TypeBuyRequestAssetID, assetID, recordSize,
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

func TypeRecordBuyRequestAssetGroupKey(groupKey **btcec.PublicKey) tlv.Record {
	const recordSize = btcec.PubKeyBytesLenCompressed

	return tlv.MakeStaticRecord(
		TypeBuyRequestAssetGroupKey, groupKey, recordSize,
		asset.CompressedPubKeyEncoder, asset.CompressedPubKeyDecoder,
	)
}

func TypeRecordBuyRequestAssetAmount(assetAmount *uint64) tlv.Record {
	return tlv.MakePrimitiveRecord(TypeBuyRequestAssetAmount, assetAmount)
}

func TypeRecordBuyRequestBidPrice(bid *lnwire.MilliSatoshi) tlv.Record {
	return tlv.MakeStaticRecord(
		TypeBuyRequestBidPrice, bid, 8,
		milliSatoshiEncoder, milliSatoshiDecoder,
	)
}

// buyRequestMsgData is a struct that represents the message data from an asset
// buy quote request message.
type buyRequestMsgData struct {
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

// Validate ensures that the asset buy quote request is valid.
func (q *buyRequestMsgData) Validate() error {
	if q.AssetID == nil && q.AssetGroupKey == nil {
		return fmt.Errorf("asset id and group key cannot both be nil")
	}

	if q.AssetID != nil && q.AssetGroupKey != nil {
		return fmt.Errorf("asset id and group key cannot both be " +
			"non-nil")
	}

	return nil
}

// EncodeRecords determines the non-nil records to include when encoding an at
// runtime.
func (q *buyRequestMsgData) encodeRecords() []tlv.Record {
	var records []tlv.Record

	records = append(records, TypeRecordBuyRequestID(&q.ID))

	if q.AssetID != nil {
		records = append(
			records, TypeRecordBuyRequestAssetID(&q.AssetID),
		)
	}

	if q.AssetGroupKey != nil {
		record := TypeRecordBuyRequestAssetGroupKey(&q.AssetGroupKey)
		records = append(records, record)
	}

	records = append(
		records, TypeRecordBuyRequestAssetAmount(&q.AssetAmount),
	)
	records = append(records, TypeRecordBuyRequestBidPrice(&q.BidPrice))

	return records
}

// Encode encodes the structure into a TLV stream.
func (q *buyRequestMsgData) Encode(writer io.Writer) error {
	stream, err := tlv.NewStream(q.encodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(writer)
}

// Bytes encodes the structure into a TLV stream and returns the bytes.
func (q *buyRequestMsgData) Bytes() ([]byte, error) {
	var b bytes.Buffer
	err := q.Encode(&b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// DecodeRecords provides all TLV records for decoding.
func (q *buyRequestMsgData) decodeRecords() []tlv.Record {
	return []tlv.Record{
		TypeRecordBuyRequestID(&q.ID),
		TypeRecordBuyRequestAssetID(&q.AssetID),
		TypeRecordBuyRequestAssetGroupKey(&q.AssetGroupKey),
		TypeRecordBuyRequestAssetAmount(&q.AssetAmount),
		TypeRecordBuyRequestBidPrice(&q.BidPrice),
	}
}

// Decode decodes the structure from a TLV stream.
func (q *buyRequestMsgData) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(q.decodeRecords()...)
	if err != nil {
		return err
	}
	return stream.DecodeP2P(r)
}

// BuyRequest is a struct that represents an asset buy quote request.
type BuyRequest struct {
	// Peer is the peer that sent the quote request.
	Peer route.Vertex

	// buyRequestMsgData is the message data for the asset buy quote request
	// message.
	buyRequestMsgData
}

// NewBuyRequest creates a new asset buy quote request.
func NewBuyRequest(peer route.Vertex, assetID *asset.ID,
	assetGroupKey *btcec.PublicKey, assetAmount uint64,
	bidPrice lnwire.MilliSatoshi) (*BuyRequest, error) {

	var id [32]byte
	_, err := rand.Read(id[:])
	if err != nil {
		return nil, fmt.Errorf("unable to generate random "+
			"quote request id: %w", err)
	}

	return &BuyRequest{
		Peer: peer,
		buyRequestMsgData: buyRequestMsgData{
			ID:            id,
			AssetID:       assetID,
			AssetGroupKey: assetGroupKey,
			AssetAmount:   assetAmount,
			BidPrice:      bidPrice,
		},
	}, nil
}

// NewBuyRequestMsgFromWire instantiates a new instance from a wire message.
func NewBuyRequestMsgFromWire(wireMsg WireMessage) (*BuyRequest, error) {
	// Ensure that the message type is a quote request message.
	if wireMsg.MsgType != MsgTypeBuyRequest {
		return nil, fmt.Errorf("unable to create a buy request "+
			"message from wire message of type %d", wireMsg.MsgType)
	}

	var msgData buyRequestMsgData
	err := msgData.Decode(bytes.NewBuffer(wireMsg.Data))
	if err != nil {
		return nil, fmt.Errorf("unable to decode incoming buy "+
			"request message data: %w", err)
	}

	req := BuyRequest{
		Peer:              wireMsg.Peer,
		buyRequestMsgData: msgData,
	}

	// Perform basic sanity checks on the quote request.
	err = req.Validate()
	if err != nil {
		return nil, fmt.Errorf("unable to validate buy request: %w",
			err)
	}

	return &req, nil
}

// Validate ensures that the buy request is valid.
func (q *BuyRequest) Validate() error {
	return q.buyRequestMsgData.Validate()
}

// ToWire returns a wire message with a serialized data field.
func (q *BuyRequest) ToWire() (WireMessage, error) {
	// Encode message data component as TLV bytes.
	msgDataBytes, err := q.buyRequestMsgData.Bytes()
	if err != nil {
		return WireMessage{}, fmt.Errorf("unable to encode message "+
			"data: %w", err)
	}

	return WireMessage{
		Peer:    q.Peer,
		MsgType: MsgTypeBuyRequest,
		Data:    msgDataBytes,
	}, nil
}

// String returns a human-readable string representation of the message.
func (q *BuyRequest) String() string {
	var groupKeyBytes []byte
	if q.AssetGroupKey != nil {
		groupKeyBytes = q.AssetGroupKey.SerializeCompressed()
	}

	return fmt.Sprintf("BuyRequest(peer=%s, id=%x, asset_id=%s, "+
		"asset_group_key=%x, asset_amount=%d, bid_price=%d)", q.Peer,
		q.ID, q.AssetID, groupKeyBytes, q.AssetAmount, q.BidPrice)
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*BuyRequest)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*BuyRequest)(nil)
