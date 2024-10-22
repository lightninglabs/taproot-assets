package rfqmsg

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// latestSellRequestVersion is the latest supported sell request wire
	// message data field version.
	latestSellRequestVersion = V1
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

	// AssetRateHint represents a proposed conversion rate between the
	// subject asset and BTC. This rate is an initial suggestion intended to
	// initiate the RFQ negotiation process and may differ from the final
	// agreed rate.
	AssetRateHint fn.Option[AssetRate]
}

// NewSellRequest creates a new asset sell quote request.
func NewSellRequest(peer route.Vertex, assetID *asset.ID,
	assetGroupKey *btcec.PublicKey, assetAmount uint64,
	assetRateHint fn.Option[AssetRate]) (*SellRequest, error) {

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
		AssetRateHint: assetRateHint,
	}, nil
}

// NewSellRequestFromWire instantiates a new instance from a wire message.
func NewSellRequestFromWire(wireMsg WireMessage,
	msgData requestWireMsgData) (*SellRequest, error) {

	// Ensure that the message type is a quote request message.
	if wireMsg.MsgType != MsgTypeRequest {
		return nil, fmt.Errorf("unable to create a sell request "+
			"message from wire message of type %d", wireMsg.MsgType)
	}

	// Extract outbound asset ID/group key.
	var assetID *asset.ID
	msgData.OutAssetID.WhenSome(
		func(inAssetID tlv.RecordT[tlv.TlvType13, asset.ID]) {
			assetID = &inAssetID.Val
		},
	)

	var assetGroupKey *btcec.PublicKey
	msgData.OutAssetGroupKey.WhenSome(
		// nolint: lll
		func(inAssetGroupKey tlv.RecordT[tlv.TlvType15, *btcec.PublicKey]) {
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

	expiry := time.Unix(int64(msgData.Expiry.Val), 0)

	// Extract the suggested asset to BTC rate if provided.
	var assetRateHint fn.Option[AssetRate]
	msgData.OutAssetRateHint.WhenSome(
		func(rate tlv.RecordT[tlv.TlvType21, TlvFixedPoint]) {
			fp := rate.Val.IntoBigIntFixedPoint()
			assetRateHint = fn.Some(NewAssetRate(fp, expiry))
		},
	)

	req := SellRequest{
		Peer:          wireMsg.Peer,
		Version:       msgData.Version.Val,
		ID:            msgData.ID.Val,
		AssetID:       assetID,
		AssetGroupKey: assetGroupKey,
		AssetAmount:   msgData.MaxInAsset.Val,
		AssetRateHint: assetRateHint,
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
	msgData, err := newRequestWireMsgDataFromSell(*q)
	if err != nil {
		return WireMessage{}, fmt.Errorf("unable to create wire "+
			"message from sell request: %w", err)
	}

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

	// Convert the asset rate hint to a string representation. Use empty
	// string if the hint is not set.
	assetRateHintStr := fn.MapOptionZ(
		q.AssetRateHint,
		func(rate AssetRate) string {
			return rate.String()
		},
	)

	return fmt.Sprintf("SellRequest(peer=%x, id=%x, asset_id=%s, "+
		"asset_group_key=%x, asset_amount=%d, asset_rate_hint=%s)",
		q.Peer[:], q.ID[:], q.AssetID, groupKeyBytes, q.AssetAmount,
		assetRateHintStr)
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*SellRequest)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*SellRequest)(nil)
