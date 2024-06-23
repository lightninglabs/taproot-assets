package rfq

import (
	"fmt"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
)

// MarshalAcceptedSellQuoteEvent marshals a peer accepted sell quote event to
// its rpc representation.
func MarshalAcceptedSellQuoteEvent(
	event *PeerAcceptedSellQuoteEvent) *rfqrpc.PeerAcceptedSellQuote {

	return &rfqrpc.PeerAcceptedSellQuote{
		Peer:        event.Peer.String(),
		Id:          event.ID[:],
		Scid:        uint64(event.ShortChannelId()),
		AssetAmount: event.Request.AssetAmount,
		BidPrice:    uint64(event.BidPrice),
		Expiry:      event.Expiry,
	}
}

// MarshalAcceptedBuyQuoteEvent marshals a peer accepted buy quote event to
// its rpc representation.
func MarshalAcceptedBuyQuoteEvent(
	event *PeerAcceptedBuyQuoteEvent) *rfqrpc.PeerAcceptedBuyQuote {

	return &rfqrpc.PeerAcceptedBuyQuote{
		Peer:        event.Peer.String(),
		Id:          event.ID[:],
		Scid:        uint64(event.ShortChannelId()),
		AssetAmount: event.Request.AssetAmount,
		AskPrice:    uint64(event.AskPrice),
		Expiry:      event.Expiry,
	}
}

// MarshalInvalidQuoteRespEvent marshals an invalid quote response event to
// its rpc representation.
func MarshalInvalidQuoteRespEvent(
	event *InvalidQuoteRespEvent) *rfqrpc.InvalidQuoteResponse {

	peer := event.QuoteResponse.MsgPeer()
	id := event.QuoteResponse.MsgID()

	return &rfqrpc.InvalidQuoteResponse{
		Status: rfqrpc.QuoteRespStatus(event.Status),
		Peer:   peer.String(),
		Id:     id[:],
	}
}

// MarshalIncomingRejectQuoteEvent marshals an incoming reject quote event to
// its RPC representation.
func MarshalIncomingRejectQuoteEvent(
	event *IncomingRejectQuoteEvent) *rfqrpc.RejectedQuoteResponse {

	return &rfqrpc.RejectedQuoteResponse{
		Peer:         event.Peer.String(),
		Id:           event.ID[:],
		ErrorMessage: event.Err.Msg,
		ErrorCode:    uint32(event.Err.Code),
	}
}

// NewAddAssetBuyOrderResponse creates a new AddAssetBuyOrderResponse from
// the given RFQ event.
func NewAddAssetBuyOrderResponse(
	event fn.Event) (*rfqrpc.AddAssetBuyOrderResponse, error) {

	resp := &rfqrpc.AddAssetBuyOrderResponse{}

	switch e := event.(type) {
	case *PeerAcceptedBuyQuoteEvent:
		resp.Response = &rfqrpc.AddAssetBuyOrderResponse_AcceptedQuote{
			AcceptedQuote: MarshalAcceptedBuyQuoteEvent(e),
		}
		return resp, nil

	case *InvalidQuoteRespEvent:
		resp.Response = &rfqrpc.AddAssetBuyOrderResponse_InvalidQuote{
			InvalidQuote: MarshalInvalidQuoteRespEvent(e),
		}
		return resp, nil

	case *IncomingRejectQuoteEvent:
		resp.Response = &rfqrpc.AddAssetBuyOrderResponse_RejectedQuote{
			RejectedQuote: MarshalIncomingRejectQuoteEvent(e),
		}
		return resp, nil

	default:
		return nil, fmt.Errorf("unknown AddAssetBuyOrder event "+
			"type: %T", e)
	}
}

// NewAddAssetSellOrderResponse creates a new AddAssetSellOrderResponse from
// the given RFQ event.
func NewAddAssetSellOrderResponse(
	event fn.Event) (*rfqrpc.AddAssetSellOrderResponse, error) {

	resp := &rfqrpc.AddAssetSellOrderResponse{}

	switch e := event.(type) {
	case *PeerAcceptedSellQuoteEvent:
		resp.Response = &rfqrpc.AddAssetSellOrderResponse_AcceptedQuote{
			AcceptedQuote: MarshalAcceptedSellQuoteEvent(e),
		}
		return resp, nil

	case *InvalidQuoteRespEvent:
		resp.Response = &rfqrpc.AddAssetSellOrderResponse_InvalidQuote{
			InvalidQuote: MarshalInvalidQuoteRespEvent(e),
		}
		return resp, nil

	case *IncomingRejectQuoteEvent:
		resp.Response = &rfqrpc.AddAssetSellOrderResponse_RejectedQuote{
			RejectedQuote: MarshalIncomingRejectQuoteEvent(e),
		}
		return resp, nil

	default:
		return nil, fmt.Errorf("unknown AddAssetSellOrder event "+
			"type: %T", e)
	}
}
