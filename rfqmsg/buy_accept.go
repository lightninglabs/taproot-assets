package rfqmsg

import (
	"fmt"

	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// latestBuyAcceptVersion is the latest supported buy accept wire
	// message data field version.
	latestBuyAcceptVersion = V0
)

// BuyAccept is a struct that represents a buy quote request accept message.
type BuyAccept struct {
	// Peer is the peer that sent the quote request.
	Peer route.Vertex

	// Request is the quote request message that this message responds to.
	// This field is not included in the wire message.
	Request BuyRequest

	// Version is the version of the message data.
	Version WireMsgDataVersion

	// ID represents the unique identifier of the quote request message that
	// this response is associated with.
	ID ID

	// AssetRate is the accepted asset to BTC rate.
	AssetRate rfqmath.BigIntFixedPoint

	// Expiry is the asking price expiry lifetime unix timestamp.
	Expiry uint64

	// sig is a signature over the serialized contents of the message.
	sig [64]byte
}

// NewBuyAcceptFromRequest creates a new instance of a quote accept message
// given a quote request message.
func NewBuyAcceptFromRequest(request BuyRequest,
	assetRate rfqmath.BigIntFixedPoint, expiry uint64) *BuyAccept {

	return &BuyAccept{
		Peer:      request.Peer,
		Request:   request,
		Version:   latestBuyAcceptVersion,
		ID:        request.ID,
		AssetRate: assetRate,
		Expiry:    expiry,
	}
}

// newBuyAcceptFromWireMsg instantiates a new instance from a wire message.
func newBuyAcceptFromWireMsg(wireMsg WireMessage,
	msgData acceptWireMsgData, request BuyRequest) (*BuyAccept, error) {

	// Ensure that the message type is an accept message.
	if wireMsg.MsgType != MsgTypeAccept {
		return nil, fmt.Errorf("unable to create an accept message "+
			"from wire message of type %d", wireMsg.MsgType)
	}

	// Extract the rate tick from the in-out rate tick field. We use this
	// field (and not the out-in rate tick field) because this is the rate
	// tick field populated in response to a peer initiated buy quote
	// request.
	var assetRate rfqmath.BigIntFixedPoint
	msgData.InOutRateTick.WhenSome(
		func(rate tlv.RecordT[tlv.TlvType4, uint64]) {
			// TODO(ffranr): Temp solution.
			assetRate = rfqmath.NewBigIntFixedPoint(rate.Val, 0)
		},
	)

	return &BuyAccept{
		Peer:      wireMsg.Peer,
		Request:   request,
		Version:   msgData.Version.Val,
		ID:        msgData.ID.Val,
		Expiry:    msgData.Expiry.Val,
		sig:       msgData.Sig.Val,
		AssetRate: assetRate,
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
	if q == nil {
		return WireMessage{}, fmt.Errorf("cannot serialize nil buy " +
			"accept")
	}

	// Encode message data component as TLV bytes.
	msgData := newAcceptWireMsgDataFromBuy(*q)
	msgDataBytes, err := msgData.Bytes()
	if err != nil {
		return WireMessage{}, fmt.Errorf("unable to encode message "+
			"data: %w", err)
	}

	return WireMessage{
		Peer:    q.Peer,
		MsgType: MsgTypeAccept,
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
		q.Peer[:], q.ID[:], q.AssetRate, q.Expiry, q.ShortChannelId())
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*BuyAccept)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*BuyAccept)(nil)
