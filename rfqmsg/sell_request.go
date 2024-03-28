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
	// SellRequest message type field TLV types.

	TypeSellRequestID            tlv.Type = 0
	TypeSellRequestAssetID       tlv.Type = 1
	TypeSellRequestAssetGroupKey tlv.Type = 3
	TypeSellRequestAssetAmount   tlv.Type = 4
	TypeSellRequestSuggestedAsk  tlv.Type = 6
)

func TypeRecordSellRequestID(id *ID) tlv.Record {
	const recordSize = 32

	return tlv.MakeStaticRecord(
		TypeSellRequestID, id, recordSize,
		IdEncoder, IdDecoder,
	)
}

func TypeRecordSellRequestAssetID(assetID **asset.ID) tlv.Record {
	const recordSize = sha256.Size

	return tlv.MakeStaticRecord(
		TypeSellRequestAssetID, assetID, recordSize,
		AssetIdEncoder, AssetIdDecoder,
	)
}

func TypeRecordSellRequestAssetGroupKey(groupKey **btcec.PublicKey) tlv.Record {
	const recordSize = btcec.PubKeyBytesLenCompressed

	return tlv.MakeStaticRecord(
		TypeSellRequestAssetGroupKey, groupKey, recordSize,
		asset.CompressedPubKeyEncoder, asset.CompressedPubKeyDecoder,
	)
}

func TypeRecordSellRequestAssetAmount(assetAmount *uint64) tlv.Record {
	return tlv.MakePrimitiveRecord(TypeSellRequestAssetAmount, assetAmount)
}

func TypeRecordSellRequestAskPrice(ask *lnwire.MilliSatoshi) tlv.Record {
	return tlv.MakeStaticRecord(
		TypeSellRequestSuggestedAsk, ask, 8,
		milliSatoshiEncoder, milliSatoshiDecoder,
	)
}

// sellRequestMsgData is a struct that represents the message data from an asset
// sell quote request message.
type sellRequestMsgData struct {
	// ID is the unique identifier of the quote request.
	ID ID

	// AssetID represents the identifier of the asset for which the peer
	// is requesting a quote.
	AssetID *asset.ID

	// AssetGroupKey is the public group key of the asset for which the peer
	// is requesting a quote.
	AssetGroupKey *btcec.PublicKey

	// AssetAmount represents the quantity of the specific asset that the
	// peer intends to sell.
	AssetAmount uint64

	// AskPrice is the peer's proposed ask price for the asset amount. This
	// is not the final price, but a suggested price that the requesting
	// peer is willing to accept.
	AskPrice lnwire.MilliSatoshi

	// TODO(ffranr): Add expiry time for suggested ask price.
}

// Validate ensures that the quote request is valid.
func (q *sellRequestMsgData) Validate() error {
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
func (q *sellRequestMsgData) encodeRecords() []tlv.Record {
	var records []tlv.Record

	records = append(records, TypeRecordSellRequestID(&q.ID))

	if q.AssetID != nil {
		records = append(
			records, TypeRecordSellRequestAssetID(&q.AssetID),
		)
	}

	if q.AssetGroupKey != nil {
		record := TypeRecordSellRequestAssetGroupKey(&q.AssetGroupKey)
		records = append(records, record)
	}

	records = append(
		records, TypeRecordSellRequestAssetAmount(&q.AssetAmount),
	)
	records = append(
		records, TypeRecordSellRequestAskPrice(&q.AskPrice),
	)

	return records
}

// Encode encodes the structure into a TLV stream.
func (q *sellRequestMsgData) Encode(writer io.Writer) error {
	stream, err := tlv.NewStream(q.encodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Encode(writer)
}

// Bytes encodes the structure into a TLV stream and returns the bytes.
func (q *sellRequestMsgData) Bytes() ([]byte, error) {
	var b bytes.Buffer
	err := q.Encode(&b)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// DecodeRecords provides all TLV records for decoding.
func (q *sellRequestMsgData) decodeRecords() []tlv.Record {
	return []tlv.Record{
		TypeRecordSellRequestID(&q.ID),
		TypeRecordSellRequestAssetID(&q.AssetID),
		TypeRecordSellRequestAssetGroupKey(&q.AssetGroupKey),
		TypeRecordSellRequestAssetAmount(&q.AssetAmount),
		TypeRecordSellRequestAskPrice(&q.AskPrice),
	}
}

// Decode decodes the structure from a TLV stream.
func (q *sellRequestMsgData) Decode(r io.Reader) error {
	stream, err := tlv.NewStream(q.decodeRecords()...)
	if err != nil {
		return err
	}
	return stream.Decode(r)
}

// SellRequest is a struct that represents a asset sell quote request.
type SellRequest struct {
	// Peer is the peer that sent the quote request.
	Peer route.Vertex

	// sellRequestMsgData is the message data for the quote request
	// message.
	sellRequestMsgData
}

// NewSellRequest creates a new asset sell quote request.
func NewSellRequest(peer route.Vertex, assetID *asset.ID,
	assetGroupKey *btcec.PublicKey, assetAmount uint64,
	askPrice lnwire.MilliSatoshi) (*SellRequest, error) {

	var id [32]byte
	_, err := rand.Read(id[:])
	if err != nil {
		return nil, fmt.Errorf("unable to generate random id: %w", err)
	}

	return &SellRequest{
		Peer: peer,
		sellRequestMsgData: sellRequestMsgData{
			ID:            id,
			AssetID:       assetID,
			AssetGroupKey: assetGroupKey,
			AssetAmount:   assetAmount,
			AskPrice:      askPrice,
		},
	}, nil
}

// NewSellRequestMsgFromWire instantiates a new instance from a wire message.
func NewSellRequestMsgFromWire(wireMsg WireMessage) (*SellRequest, error) {
	// Ensure that the message type is a sell request message.
	if wireMsg.MsgType != MsgTypeSellRequest {
		return nil, fmt.Errorf("unable to create a sell request "+
			"message from wire message of type %d", wireMsg.MsgType)
	}

	// Parse the message data from the wire message.
	var msgData sellRequestMsgData
	err := msgData.Decode(bytes.NewBuffer(wireMsg.Data))
	if err != nil {
		return nil, fmt.Errorf("unable to decode incoming sell "+
			"request message data: %w", err)
	}

	req := SellRequest{
		Peer:               wireMsg.Peer,
		sellRequestMsgData: msgData,
	}

	// Perform basic sanity checks on the quote request.
	err = req.Validate()
	if err != nil {
		return nil, fmt.Errorf("unable to validate sell request: %w",
			err)
	}

	return &req, nil
}

// Validate ensures that the quote request is valid.
func (q *SellRequest) Validate() error {
	return q.sellRequestMsgData.Validate()
}

// ToWire returns a wire message with a serialized data field.
func (q *SellRequest) ToWire() (WireMessage, error) {
	// Encode message data component as TLV bytes.
	msgDataBytes, err := q.sellRequestMsgData.Bytes()
	if err != nil {
		return WireMessage{}, fmt.Errorf("unable to encode message "+
			"data: %w", err)
	}

	return WireMessage{
		Peer:    q.Peer,
		MsgType: MsgTypeSellRequest,
		Data:    msgDataBytes,
	}, nil
}

// String returns a human-readable string representation of the message.
func (q *SellRequest) String() string {
	var groupKeyBytes []byte
	if q.AssetGroupKey != nil {
		groupKeyBytes = q.AssetGroupKey.SerializeCompressed()
	}

	return fmt.Sprintf("SellRequest(peer=%s, id=%x, asset_id=%s, "+
		"asset_group_key=%x, asset_amount=%d, ask_price=%d)", q.Peer,
		q.ID, q.AssetID, groupKeyBytes, q.AssetAmount, q.AskPrice)
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*SellRequest)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*SellRequest)(nil)
