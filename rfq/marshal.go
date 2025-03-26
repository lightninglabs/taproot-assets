package rfq

import (
	"fmt"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
)

// MarshalAcceptedSellQuoteEvent marshals a peer accepted sell quote event to
// its RPC representation.
func MarshalAcceptedSellQuoteEvent(
	event *PeerAcceptedSellQuoteEvent) *rfqrpc.PeerAcceptedSellQuote {

	return MarshalAcceptedSellQuote(event.SellAccept)
}

// MarshalAcceptedSellQuote marshals a peer accepted sell quote to its RPC
// representation.
func MarshalAcceptedSellQuote(
	accept rfqmsg.SellAccept) *rfqrpc.PeerAcceptedSellQuote {

	rpcAssetRate := &rfqrpc.FixedPoint{
		Coefficient: accept.AssetRate.Rate.Coefficient.String(),
		Scale:       uint32(accept.AssetRate.Rate.Scale),
	}

	// Calculate the equivalent asset units for the given total BTC amount
	// based on the asset-to-BTC conversion rate.
	numAssetUnits := rfqmath.MilliSatoshiToUnits(
		accept.Request.PaymentMaxAmt, accept.AssetRate.Rate,
	)

	minTransportableMSat := rfqmath.MinTransportableMSat(
		rfqmath.DefaultOnChainHtlcMSat, accept.AssetRate.Rate,
	)

	return &rfqrpc.PeerAcceptedSellQuote{
		Peer:                 accept.Peer.String(),
		Id:                   accept.ID[:],
		Scid:                 uint64(accept.ShortChannelId()),
		BidAssetRate:         rpcAssetRate,
		Expiry:               uint64(accept.AssetRate.Expiry.Unix()),
		AssetAmount:          numAssetUnits.ScaleTo(0).ToUint64(),
		MinTransportableMsat: uint64(minTransportableMSat),
	}
}

// MarshalAcceptedBuyQuoteEvent marshals a peer accepted buy quote event to
// its rpc representation.
func MarshalAcceptedBuyQuoteEvent(
	event *PeerAcceptedBuyQuoteEvent) (*rfqrpc.PeerAcceptedBuyQuote,
	error) {

	// We now calculate the minimum amount of asset units that can be
	// transported within a single HTLC for this asset at the given rate.
	// This corresponds to the 354 satoshi minimum non-dust HTLC value.
	minTransportableUnits := rfqmath.MinTransportableUnits(
		rfqmath.DefaultOnChainHtlcMSat, event.AssetRate.Rate,
	).ScaleTo(0).ToUint64()

	return &rfqrpc.PeerAcceptedBuyQuote{
		Peer:           event.Peer.String(),
		Id:             event.ID[:],
		Scid:           uint64(event.ShortChannelId()),
		AssetMaxAmount: event.Request.AssetMaxAmt,
		AskAssetRate: &rfqrpc.FixedPoint{
			Coefficient: event.AssetRate.Rate.Coefficient.String(),
			Scale:       uint32(event.AssetRate.Rate.Scale),
		},
		Expiry:                uint64(event.AssetRate.Expiry.Unix()),
		MinTransportableUnits: minTransportableUnits,
	}, nil
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
		Id:           event.ID.Val[:],
		ErrorMessage: event.Err.Val.Msg,
		ErrorCode:    uint32(event.Err.Val.Code),
	}
}

// NewAddAssetBuyOrderResponse creates a new AddAssetBuyOrderResponse from
// the given RFQ event.
func NewAddAssetBuyOrderResponse(
	event fn.Event) (*rfqrpc.AddAssetBuyOrderResponse, error) {

	resp := &rfqrpc.AddAssetBuyOrderResponse{}

	switch e := event.(type) {
	case *PeerAcceptedBuyQuoteEvent:
		acceptedQuote, err := MarshalAcceptedBuyQuoteEvent(e)
		if err != nil {
			return nil, err
		}

		resp.Response = &rfqrpc.AddAssetBuyOrderResponse_AcceptedQuote{
			AcceptedQuote: acceptedQuote,
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
