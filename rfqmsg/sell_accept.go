package rfqmsg

import (
	"fmt"
	"time"

	"github.com/lightningnetwork/lnd/routing/route"
)

const (
	// latestSellAcceptVersion is the latest supported sell accept wire
	// message data field version.
	latestSellAcceptVersion = V1
)

// SellAccept is a struct that represents a sell quote request accept message.
type SellAccept struct {
	// Peer is the peer that sent the quote request.
	Peer route.Vertex

	// Request is the quote request message that this message responds to.
	// This field is not included in the wire message.
	Request SellRequest

	// Version is the version of the message data.
	Version WireMsgDataVersion

	// ID represents the unique identifier of the asset sell quote request
	// message that this response is associated with.
	ID ID

	// AssetRate is the accepted asset to BTC rate.
	AssetRate AssetRate

	// sig is a signature over the serialized contents of the message.
	sig [64]byte
}

// NewSellAcceptFromRequest creates a new instance of an asset sell quote accept
// message given an asset sell quote request message.
func NewSellAcceptFromRequest(request SellRequest,
	assetRate AssetRate) *SellAccept {

	return &SellAccept{
		Peer:      request.Peer,
		Request:   request,
		Version:   latestSellAcceptVersion,
		ID:        request.ID,
		AssetRate: assetRate,
	}
}

// newSellAcceptFromWireMsg instantiates a new instance from a wire message.
func newSellAcceptFromWireMsg(wireMsg WireMessage,
	msgData acceptWireMsgData, request SellRequest) (*SellAccept,
	error) {

	// Ensure that the message type is an accept message.
	if wireMsg.MsgType != MsgTypeAccept {
		return nil, fmt.Errorf("unable to create an asset sell "+
			"accept message from wire message of type %d",
			wireMsg.MsgType)
	}

	// Extract the out-asset to BTC rate. We use this field because we
	// currently assume that the in-asset is BTC.
	assetRate := msgData.OutAssetRate.Val.IntoBigIntFixedPoint()

	// Convert the unix timestamp in seconds to a time.Time.
	expiry := time.Unix(int64(msgData.Expiry.Val), 0).UTC()

	// Note that the `Request` field is populated later in the RFQ stream
	// service.
	return &SellAccept{
		Peer:      wireMsg.Peer,
		Request:   request,
		Version:   msgData.Version.Val,
		ID:        msgData.ID.Val,
		AssetRate: NewAssetRate(assetRate, expiry),
		sig:       msgData.Sig.Val,
	}, nil
}

// ShortChannelId returns the short channel ID associated with the asset sale
// event.
func (q *SellAccept) ShortChannelId() SerialisedScid {
	return q.ID.Scid()
}

// ToWire returns a wire message with a serialized data field.
//
// TODO(ffranr): This method should accept a signer so that we can generate a
// signature over the message data.
func (q *SellAccept) ToWire() (WireMessage, error) {
	if q == nil {
		return WireMessage{}, fmt.Errorf("cannot serialize nil sell " +
			"accept")
	}

	// Formulate the message data.
	msgData, err := newAcceptWireMsgDataFromSell(*q)
	if err != nil {
		return WireMessage{}, fmt.Errorf("failed to derive accept "+
			"wire message data from sell accept: %w", err)
	}

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
func (q *SellAccept) MsgPeer() route.Vertex {
	return q.Peer
}

// MsgID returns the quote request session ID.
func (q *SellAccept) MsgID() ID {
	return q.ID
}

// String returns a human-readable string representation of the message.
func (q *SellAccept) String() string {
	return fmt.Sprintf("SellAccept(peer=%x, id=%x, asset_rate=%s, "+
		"scid=%d)", q.Peer[:], q.ID[:], q.AssetRate.String(),
		q.ShortChannelId())
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*SellAccept)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*SellAccept)(nil)
