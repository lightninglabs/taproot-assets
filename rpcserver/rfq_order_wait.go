package rpcserver

import (
	"fmt"
	"time"

	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/taprpc/rfqrpc"
	"github.com/lightningnetwork/lnd/routing/route"
)

// waitForBuyOrderResponse blocks until the RFQ event that resolves the buy
// order with the given quote request ID arrives, the server quits or the
// timeout fires.
func waitForBuyOrderResponse(events <-chan fn.Event, quit <-chan struct{},
	timeout <-chan time.Time, id rfqmsg.ID, order rfq.BuyOrder,
	peer route.Vertex) (*rfqrpc.AddAssetBuyOrderResponse, error) {

	type (
		targetEventType = *rfq.PeerAcceptedBuyQuoteEvent
		rejectEventType = *rfq.InvalidQuoteRespEvent
		peerRejectType  = *rfq.IncomingRejectQuoteEvent
	)

	for {
		select {
		case event := <-events:
			switch e := event.(type) {
			case rejectEventType:
				if e.QuoteResponse.MsgID() == id {
					return nil, fmt.Errorf("peer %s "+
						"rejected quote %v",
						peer.String(),
						e.QuoteResponse.String())
				}

			case peerRejectType:
				if e.MsgID() == id {
					return nil, fmt.Errorf(
						"peer %s rejected "+
							"quote %v",
						peer.String(),
						e.String(),
					)
				}

			case targetEventType:
				if e.MsgID() != id || !e.MatchesOrder(order) {
					rpcsLog.Debugf("Received event of "+
						"type %T but order doesn't "+
						"match, skipping", event)

					continue
				}

				resp, err := rfq.NewAddAssetBuyOrderResponse(
					event,
				)
				if err != nil {
					return nil, fmt.Errorf("error "+
						"marshalling buy order "+
						"response: %w", err)
				}

				return resp, nil

			default:
				rpcsLog.Debugf("Received event of type %T "+
					"but expected accepted sell quote, "+
					"skipping", event)

				continue
			}

		case <-quit:
			return nil, fmt.Errorf("server shutting down")

		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for response "+
				"(peer=%s)", peer.String())
		}
	}
}

// waitForSellOrderResponse blocks until the RFQ event that resolves the sell
// order with the given quote request ID arrives, the server quits or the
// timeout fires.
func waitForSellOrderResponse(events <-chan fn.Event, quit <-chan struct{},
	timeout <-chan time.Time, id rfqmsg.ID, order rfq.SellOrder,
	peer route.Vertex) (*rfqrpc.AddAssetSellOrderResponse, error) {

	type (
		targetEventType = *rfq.PeerAcceptedSellQuoteEvent
		rejectEventType = *rfq.InvalidQuoteRespEvent
		peerRejectType  = *rfq.IncomingRejectQuoteEvent
	)

	for {
		select {
		case event := <-events:
			switch e := event.(type) {
			case rejectEventType:
				if e.QuoteResponse.MsgID() == id {
					return nil, fmt.Errorf("peer %s "+
						"rejected quote %v",
						peer.String(),
						e.QuoteResponse.String())
				}

			case peerRejectType:
				if e.MsgID() == id {
					return nil, fmt.Errorf(
						"peer %s rejected "+
							"quote %v",
						peer.String(),
						e.String(),
					)
				}

			case targetEventType:
				if e.MsgID() != id || !e.MatchesOrder(order) {
					rpcsLog.Debugf("Received event of "+
						"type %T but order doesn't "+
						"match, skipping", event)

					continue
				}

				resp, err := rfq.NewAddAssetSellOrderResponse(
					event,
				)
				if err != nil {
					return nil, fmt.Errorf("error "+
						"marshalling sell order "+
						"response: %w", err)
				}

				return resp, nil

			default:
				rpcsLog.Debugf("Received event of type %T "+
					"but expected accepted sell quote, "+
					"skipping", event)

				continue
			}

		case <-quit:
			return nil, fmt.Errorf("server shutting down")

		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for response "+
				"from peer %s", peer.String())
		}
	}
}
