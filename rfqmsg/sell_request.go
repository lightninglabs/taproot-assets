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
	// latestSellRequestVersion is the latest supported sell request wire
	// message data field version.
	latestSellRequestVersion = V0
)

// SellRequest is a struct that represents a asset sell quote request.
type SellRequest struct {
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

	// AssetAmount represents the quantity of the specific asset that the
	// peer intends to sell.
	AssetAmount uint64

	// AskPrice is the peer's proposed ask price for the asset amount. This
	// is not the final price, but a suggested price that the requesting
	// peer is willing to accept.
	AskPrice lnwire.MilliSatoshi

	// TODO(ffranr): Add expiry time for suggested ask price.
}

// NewSellRequest creates a new asset sell quote request.
func NewSellRequest(peer route.Vertex, assetID *asset.ID,
	assetGroupKey *btcec.PublicKey, assetAmount uint64,
	askPrice lnwire.MilliSatoshi) (*SellRequest, error) {

	id, err := NewID()
	if err != nil {
		return nil, fmt.Errorf("unable to generate random id: %w", err)
	}

	return &SellRequest{
		Peer:          peer,
		Version:       latestSellRequestVersion,
		ID:            id,
		AssetID:       assetID,
		AssetGroupKey: assetGroupKey,
		AssetAmount:   assetAmount,
		AskPrice:      askPrice,
	}, nil
}

// NewSellRequestMsgFromWire instantiates a new instance from a wire message.
func NewSellRequestMsgFromWire(wireMsg WireMessage,
	msgData requestWireMsgData) (*SellRequest, error) {

	// Ensure that the message type is a quote request message.
	if wireMsg.MsgType != MsgTypeRequest {
		return nil, fmt.Errorf("unable to create a sell request "+
			"message from wire message of type %d", wireMsg.MsgType)
	}

	// Extract outbound asset ID/group key.
	var assetID *asset.ID
	msgData.OutAssetID.WhenSome(
		func(inAssetID tlv.RecordT[tlv.TlvType7, asset.ID]) {
			assetID = &inAssetID.Val
		},
	)

	var assetGroupKey *btcec.PublicKey
	msgData.OutAssetGroupKey.WhenSome(
		// nolint: lll
		func(inAssetGroupKey tlv.RecordT[tlv.TlvType8, *btcec.PublicKey]) {
			assetGroupKey = inAssetGroupKey.Val
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
	var askPrice lnwire.MilliSatoshi
	msgData.SuggestedRateTick.WhenSome(
		// nolint: lll
		func(suggestedRateTick tlv.RecordT[tlv.TlvType4, uint64]) {
			askPrice = lnwire.MilliSatoshi(suggestedRateTick.Val)
		},
	)

	req := SellRequest{
		Peer:          wireMsg.Peer,
		Version:       msgData.Version.Val,
		ID:            msgData.ID.Val,
		AssetID:       assetID,
		AssetGroupKey: assetGroupKey,
		AssetAmount:   msgData.AssetMaxAmount.Val,
		AskPrice:      askPrice,
	}

	// Perform basic sanity checks on the quote request.
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("unable to validate sell request: %w",
			err)
	}

	return &req, nil
}

// Validate ensures that the quote request is valid.
func (q *SellRequest) Validate() error {
	if q.AssetID == nil && q.AssetGroupKey == nil {
		return fmt.Errorf("asset id and group key cannot both be nil")
	}

	if q.AssetID != nil && q.AssetGroupKey != nil {
		return fmt.Errorf("asset id and group key cannot both be " +
			"non-nil")
	}

	// Ensure that the message version is supported.
	if q.Version > latestSellRequestVersion {
		return fmt.Errorf("unsupported sell request message version: "+
			"%d", q.Version)
	}

	return nil
}

// ToWire returns a wire message with a serialized data field.
func (q *SellRequest) ToWire() (WireMessage, error) {
	if q == nil {
		return WireMessage{}, fmt.Errorf("cannot serialize nil sell " +
			"request")
	}

	// Formulate the message data.
	msgData := newRequestWireMsgDataFromSell(*q)
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
func (q *SellRequest) MsgPeer() route.Vertex {
	return q.Peer
}

// MsgID returns the quote request session ID.
func (q *SellRequest) MsgID() ID {
	return q.ID
}

// String returns a human-readable string representation of the message.
func (q *SellRequest) String() string {
	var groupKeyBytes []byte
	if q.AssetGroupKey != nil {
		groupKeyBytes = q.AssetGroupKey.SerializeCompressed()
	}

	return fmt.Sprintf("SellRequest(peer=%x, id=%x, asset_id=%s, "+
		"asset_group_key=%x, asset_amount=%d, ask_price=%d)", q.Peer[:],
		q.ID[:], q.AssetID, groupKeyBytes, q.AssetAmount, q.AskPrice)
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*SellRequest)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*SellRequest)(nil)
