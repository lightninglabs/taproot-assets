package rfqmsg

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// latestBuyRequestVersion is the latest supported buy request wire
	// message data field version.
	latestBuyRequestVersion = V0
)

// BuyRequest is a struct that represents an asset buy quote request.
type BuyRequest struct {
	// Peer is the peer that sent the quote request.
	Peer route.Vertex

	// Version is the version of the message data.
	Version WireMsgDataVersion

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

// NewBuyRequest creates a new asset buy quote request.
func NewBuyRequest(peer route.Vertex, assetID *asset.ID,
	assetGroupKey *btcec.PublicKey, assetAmount uint64,
	bidPrice lnwire.MilliSatoshi) (*BuyRequest, error) {

	id, err := NewID()
	if err != nil {
		return nil, fmt.Errorf("unable to generate random "+
			"quote request id: %w", err)
	}

	return &BuyRequest{
		Peer:          peer,
		Version:       latestBuyRequestVersion,
		ID:            id,
		AssetID:       assetID,
		AssetGroupKey: assetGroupKey,
		AssetAmount:   assetAmount,
		BidPrice:      bidPrice,
	}, nil
}

// NewBuyRequestMsgFromWire instantiates a new instance from a wire message.
func NewBuyRequestMsgFromWire(wireMsg WireMessage,
	msgData requestWireMsgData) (*BuyRequest, error) {

	// Ensure that the message type is a quote request message.
	if wireMsg.MsgType != MsgTypeRequest {
		return nil, fmt.Errorf("unable to create a buy request "+
			"message from wire message of type %d", wireMsg.MsgType)
	}

	var assetID *asset.ID
	msgData.InAssetID.WhenSome(
		func(inAssetID tlv.RecordT[tlv.TlvType5, asset.ID]) {
			assetID = &inAssetID.Val
		},
	)

	var assetGroupKey *btcec.PublicKey
	msgData.InAssetGroupKey.WhenSome(
		func(key tlv.RecordT[tlv.TlvType6, *btcec.PublicKey]) {
			assetGroupKey = key.Val
		},
	)

	// Sanity check that at least one of the inbound asset ID or
	// group key is set. At least one must be set in a buy request.
	if assetID == nil && assetGroupKey == nil {
		return nil, fmt.Errorf("inbound asset ID and group " +
			"key cannot both be unset for incoming buy " +
			"request")
	}

	// Extract the suggested rate tick if provided.
	var bidPrice lnwire.MilliSatoshi
	msgData.SuggestedRateTick.WhenSome(
		func(rate tlv.RecordT[tlv.TlvType4, uint64]) {
			bidPrice = lnwire.MilliSatoshi(rate.Val)
		},
	)

	req := BuyRequest{
		Peer:          wireMsg.Peer,
		Version:       msgData.Version.Val,
		ID:            msgData.ID.Val,
		AssetID:       assetID,
		AssetGroupKey: assetGroupKey,
		AssetAmount:   msgData.AssetMaxAmount.Val,
		BidPrice:      bidPrice,
	}

	// Perform basic sanity checks on the quote request.
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("unable to validate buy request: %w",
			err)
	}

	return &req, nil
}

// Validate ensures that the buy request is valid.
func (q *BuyRequest) Validate() error {
	if q.AssetID == nil && q.AssetGroupKey == nil {
		return fmt.Errorf("asset id and group key cannot both be nil")
	}

	if q.AssetID != nil && q.AssetGroupKey != nil {
		return fmt.Errorf("asset id and group key cannot both be " +
			"non-nil")
	}

	// Ensure that the message version is supported.
	if q.Version > latestBuyRequestVersion {
		return fmt.Errorf("unsupported buy request message version: %d",
			q.Version)
	}

	return nil
}

// ToWire returns a wire message with a serialized data field.
func (q *BuyRequest) ToWire() (WireMessage, error) {
	if q == nil {
		return WireMessage{}, fmt.Errorf("cannot serialize nil buy " +
			"request")
	}

	// Formulate the message data.
	msgData := newRequestWireMsgDataFromBuy(*q)
	msgDataBytes, err := msgData.Bytes()
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

// MsgPeer returns the peer that sent the message.
func (q *BuyRequest) MsgPeer() route.Vertex {
	return q.Peer
}

// MsgID returns the quote request session ID.
func (q *BuyRequest) MsgID() ID {
	return q.ID
}

// String returns a human-readable string representation of the message.
func (q *BuyRequest) String() string {
	var groupKeyBytes []byte
	if q.AssetGroupKey != nil {
		groupKeyBytes = q.AssetGroupKey.SerializeCompressed()
	}

	return fmt.Sprintf("BuyRequest(peer=%x, id=%x, asset_id=%s, "+
		"asset_group_key=%x, asset_amount=%d, bid_price=%d)", q.Peer[:],
		q.ID[:], q.AssetID, groupKeyBytes, q.AssetAmount, q.BidPrice)
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*BuyRequest)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*BuyRequest)(nil)
