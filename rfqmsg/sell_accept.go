package rfqmsg

import (
	"fmt"

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

	// Price is the accepted price quote given by the responder.
	Price PriceQuote

	// sig is a signature over the serialized contents of the message.
	sig [64]byte
}

// NewSellAcceptFromRequest creates a new instance of an asset sell quote accept
// message given an asset sell quote request message.
func NewSellAcceptFromRequest(request SellRequest,
	acceptedPrice PriceQuote) *SellAccept {

	return &SellAccept{
		Peer:    request.Peer,
		Request: request,
		Version: latestSellAcceptVersion,
		ID:      request.ID,
		Price:   acceptedPrice,
	}
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
	msgData := newAcceptWireMsgDataFromSell(*q)
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
	return fmt.Sprintf("SellAccept(peer=%x, id=%x, scid=%d, price=%v",
		q.Peer[:], q.ID[:], q.ShortChannelId(), q.Price)
}

// Ensure that the message type implements the OutgoingMsg interface.
var _ OutgoingMsg = (*SellAccept)(nil)

// Ensure that the message type implements the IncomingMsg interface.
var _ IncomingMsg = (*SellAccept)(nil)
