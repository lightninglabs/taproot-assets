package rfqmsg

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// latestSellRequestVersion is the latest supported sell request wire
	// message data field version.
	latestSellRequestVersion = V1
)

// SellRequest is a struct that represents an asset sell quote request.
//
// Normal usage of a sell request:
//  1. Alice creates a Lightning invoice for Bob to pay.
//  2. Bob wants to pay the invoice using a Tap asset. To do so, Bob pays an
//     edge node with a Tap asset, and the edge node forwards the payment to the
//     network to settle Alice's invoice. Bob submits a SellOrder to his local
//     RFQ service.
//  3. The RFQ service converts the SellOrder into one or more SellRequests.
//     These requests are sent to Charlie (the edge node), who shares a relevant
//     Tap asset channel with Bob and can forward payments to settle Alice's
//     invoice.
//  4. Charlie responds with a quote that satisfies Bob.
//  5. Bob transfers the appropriate Tap asset amount to Charlie via their
//     shared Tap asset channel, and Charlie forwards the corresponding amount
//     to Alice to settle the Lightning invoice.
type SellRequest struct {
	// Peer is the peer that sent the quote request.
	Peer route.Vertex

	// Version is the version of the message data.
	Version WireMsgDataVersion

	// ID is the unique identifier of the quote request.
	ID ID

	// AssetSpecifier represents the asset for which this quote request is
	// made. It specifies the particular asset involved in the request.
	AssetSpecifier asset.Specifier

	// PaymentMaxAmt is the maximum msat amount that the responding peer
	// must agree to pay.
	PaymentMaxAmt lnwire.MilliSatoshi

	// AssetRateHint represents a proposed conversion rate between the
	// subject asset and BTC. This rate is an initial suggestion intended to
	// initiate the RFQ negotiation process and may differ from the final
	// agreed rate.
	AssetRateHint fn.Option[AssetRate]
}

// NewSellRequest creates a new asset sell quote request.
func NewSellRequest(peer route.Vertex, assetSpecifier asset.Specifier,
	paymentMaxAmt lnwire.MilliSatoshi,
	assetRateHint fn.Option[AssetRate]) (*SellRequest, error) {

	id, err := NewID()
	if err != nil {
		return nil, fmt.Errorf("unable to generate random id: %w", err)
	}

	return &SellRequest{
		Peer:           peer,
		Version:        latestSellRequestVersion,
		ID:             id,
		AssetSpecifier: assetSpecifier,
		PaymentMaxAmt:  paymentMaxAmt,
		AssetRateHint:  assetRateHint,
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

	expiry := time.Unix(int64(msgData.Expiry.Val), 0).UTC()

	// Extract the suggested asset to BTC rate if provided.
	var assetRateHint fn.Option[AssetRate]
	msgData.OutAssetRateHint.WhenSome(
		func(rate tlv.RecordT[tlv.TlvType21, TlvFixedPoint]) {
			fp := rate.Val.IntoBigIntFixedPoint()
			assetRateHint = fn.Some(NewAssetRate(fp, expiry))
		},
	)

	req := SellRequest{
		Peer:           wireMsg.Peer,
		Version:        msgData.Version.Val,
		ID:             msgData.ID.Val,
		AssetSpecifier: assetSpecifier,
		PaymentMaxAmt:  lnwire.MilliSatoshi(msgData.MaxInAsset.Val),
		AssetRateHint:  assetRateHint,
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
	// Ensure that the asset specifier is not empty.
	err := q.AssetSpecifier.AssertNotEmpty()
	if err != nil {
		return err
	}

	// Ensure that the message version is supported.
	if q.Version != latestSellRequestVersion {
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
	// Convert the asset rate hint to a string representation. Use empty
	// string if the hint is not set.
	assetRateHintStr := fn.MapOptionZ(
		q.AssetRateHint,
		func(rate AssetRate) string {
			return rate.String()
		},
	)

	return fmt.Sprintf("SellRequest(peer=%x, id=%x, asset=%s, "+
		"payment_max_amt=%d, asset_rate_hint=%s)",
		q.Peer[:], q.ID[:], q.AssetSpecifier.String(), q.PaymentMaxAmt,
		assetRateHintStr)
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*SellRequest)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*SellRequest)(nil)
