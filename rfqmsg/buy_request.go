package rfqmsg

import (
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// latestBuyRequestVersion is the latest supported buy request wire
	// message data field version.
	latestBuyRequestVersion = V1
)

// BuyRequest is a struct that represents an asset buy quote request.
//
// Normal usage of a buy request:
//  1. Alice, operating a wallet node, wants to receive a Tap asset as payment
//     by issuing a Lightning invoice.
//  2. Alice has an asset channel established with Bob's edge node.
//  3. Before issuing the invoice, Alice needs to agree on an exchange rate with
//     Bob, who will facilitate the asset transfer.
//  4. To obtain the best exchange rate, Alice creates a buy order specifying
//     the desired asset.
//  5. Alice's RFQ subsystem processes the buy order and sends buy requests to
//     relevant peers to find the best rate. In this example, Bob is the only
//     available peer.
//  6. Once Bob provides a satisfactory quote, Alice accepts it.
//  7. Alice issues the Lightning invoice, which Charlie will pay.
//  8. Instead of paying Alice directly, Charlie pays Bob.
//  9. Bob then forwards the agreed amount of the Tap asset to Alice over their
//     asset channel.
type BuyRequest struct {
	// Peer is the peer that sent the quote request.
	Peer route.Vertex

	// Version is the version of the message data.
	Version WireMsgDataVersion

	// ID is the unique identifier of the quote request.
	ID ID

	// AssetSpecifier represents the asset for which this quote request is
	// made. It specifies the particular asset involved in the request.
	AssetSpecifier asset.Specifier

	// AssetMaxAmt represents the maximum asset amount that the responding
	// peer must agree to divest.
	AssetMaxAmt uint64

	// AssetRateHint represents a proposed conversion rate between the
	// subject asset and BTC. This rate is an initial suggestion intended to
	// initiate the RFQ negotiation process and may differ from the final
	// agreed rate.
	AssetRateHint fn.Option[AssetRate]
}

// NewBuyRequest creates a new asset buy quote request.
func NewBuyRequest(peer route.Vertex, assetSpecifier asset.Specifier,
	assetMaxAmt uint64, assetRateHint fn.Option[AssetRate]) (*BuyRequest,
	error) {

	id, err := NewID()
	if err != nil {
		return nil, fmt.Errorf("unable to generate random "+
			"quote request id: %w", err)
	}

	return &BuyRequest{
		Peer:           peer,
		Version:        latestBuyRequestVersion,
		ID:             id,
		AssetSpecifier: assetSpecifier,
		AssetMaxAmt:    assetMaxAmt,
		AssetRateHint:  assetRateHint,
	}, nil
}

// NewBuyRequestFromWire instantiates a new instance from a wire message.
func NewBuyRequestFromWire(wireMsg WireMessage,
	msgData requestWireMsgData) (*BuyRequest, error) {

	// Ensure that the message type is a quote request message.
	if wireMsg.MsgType != MsgTypeRequest {
		return nil, fmt.Errorf("unable to create a buy request "+
			"message from wire message of type %d", wireMsg.MsgType)
	}

	var assetID *asset.ID
	msgData.InAssetID.WhenSome(
		func(inAssetID tlv.RecordT[tlv.TlvType9, asset.ID]) {
			assetID = &inAssetID.Val
		},
	)

	var assetGroupKey *btcec.PublicKey
	msgData.InAssetGroupKey.WhenSome(
		func(key tlv.RecordT[tlv.TlvType11, *btcec.PublicKey]) {
			assetGroupKey = key.Val
		},
	)

	assetSpecifier, err := asset.NewSpecifier(
		assetID, assetGroupKey, nil, true,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create asset specifier: %w",
			err)
	}

	// Sanity check that at least one of the inbound asset ID or
	// group key is set. At least one must be set in a buy request.
	if assetID == nil && assetGroupKey == nil {
		return nil, fmt.Errorf("inbound asset ID and group " +
			"key cannot both be unset for incoming buy " +
			"request")
	}

	// Convert the wire message expiration time to a time.Time.
	if msgData.Expiry.Val > math.MaxInt64 {
		return nil, fmt.Errorf("expiry time exceeds maximum int64")
	}

	expiry := time.Unix(int64(msgData.Expiry.Val), 0).UTC()

	// Extract the suggested asset to BTC rate if provided.
	var assetRateHint fn.Option[AssetRate]
	msgData.InAssetRateHint.WhenSome(
		func(rate tlv.RecordT[tlv.TlvType19, TlvFixedPoint]) {
			fp := rate.Val.IntoBigIntFixedPoint()
			assetRateHint = fn.Some(NewAssetRate(fp, expiry))
		},
	)

	req := BuyRequest{
		Peer:           wireMsg.Peer,
		Version:        msgData.Version.Val,
		ID:             msgData.ID.Val,
		AssetSpecifier: assetSpecifier,
		AssetMaxAmt:    msgData.MaxInAsset.Val,
		AssetRateHint:  assetRateHint,
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
	// Ensure that the asset specifier is set.
	err := q.AssetSpecifier.AssertNotEmpty()
	if err != nil {
		return err
	}

	// Ensure that the message version is supported.
	if q.Version != latestBuyRequestVersion {
		return fmt.Errorf("unsupported buy request message version: %d",
			q.Version)
	}

	// Ensure that the suggested asset rate has not expired.
	err = fn.MapOptionZ(q.AssetRateHint, func(rate AssetRate) error {
		if rate.Expiry.Before(time.Now()) {
			return fmt.Errorf("suggested asset rate has expired")
		}
		return nil
	})
	if err != nil {
		return err
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
	msgData, err := newRequestWireMsgDataFromBuy(*q)
	if err != nil {
		return WireMessage{}, fmt.Errorf("unable to create wire "+
			"message from buy request: %w", err)
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
func (q *BuyRequest) MsgPeer() route.Vertex {
	return q.Peer
}

// MsgID returns the quote request session ID.
func (q *BuyRequest) MsgID() ID {
	return q.ID
}

// String returns a human-readable string representation of the message.
func (q *BuyRequest) String() string {
	// Convert the asset rate hint to a string representation. Use empty
	// string if the hint is not set.
	assetRateHintStr := fn.MapOptionZ(
		q.AssetRateHint,
		func(rate AssetRate) string {
			return rate.String()
		},
	)

	return fmt.Sprintf("BuyRequest(peer=%x, id=%x, asset=%s, "+
		"max_asset_amount=%d, asset_rate_hint=%s)",
		q.Peer[:], q.ID[:], q.AssetSpecifier.String(), q.AssetMaxAmt,
		assetRateHintStr)
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*BuyRequest)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*BuyRequest)(nil)
