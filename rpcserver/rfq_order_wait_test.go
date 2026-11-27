package rpcserver

import (
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

var (
	testPeer = route.Vertex{2}

	testSpecifier = asset.NewSpecifierFromId(asset.ID{1})

	testRate = rfqmsg.AssetRate{
		Rate:   rfqmath.NewBigIntFixedPoint(1000, 0),
		Expiry: time.Now().Add(time.Hour),
	}
)

func testQuoteID(t *testing.T) rfqmsg.ID {
	t.Helper()

	id, err := rfqmsg.NewID()
	require.NoError(t, err)

	return id
}

func eventChan(events ...fn.Event) <-chan fn.Event {
	c := make(chan fn.Event, len(events))
	for _, e := range events {
		c <- e
	}

	return c
}

// TestWaitForBuyOrderResponseMatchesID checks that two concurrent buy orders
// for the same peer and asset each get the quote with their own ID, even when
// the quote of the other order arrives first.
func TestWaitForBuyOrderResponseMatchesID(t *testing.T) {
	t.Parallel()

	idSmall, idLarge := testQuoteID(t), testQuoteID(t)

	accept := func(id rfqmsg.ID, maxAmt uint64) fn.Event {
		return rfq.NewPeerAcceptedBuyQuoteEvent(&rfqmsg.BuyAccept{
			Peer: testPeer,
			Request: rfqmsg.BuyRequest{
				Peer:           testPeer,
				ID:             id,
				AssetSpecifier: testSpecifier,
				AssetMaxAmt:    maxAmt,
			},
			ID:        id,
			AssetRate: testRate,
		})
	}

	order := func(maxAmt uint64) rfq.BuyOrder {
		return rfq.BuyOrder{
			AssetSpecifier: testSpecifier,
			AssetMaxAmt:    maxAmt,
			Peer:           fn.Some(testPeer),
		}
	}

	// Both subscribers see the same stream, the large quote arrives first.
	events := func() <-chan fn.Event {
		return eventChan(accept(idLarge, 11), accept(idSmall, 2))
	}

	timeout := time.After(time.Second)

	resp, err := waitForBuyOrderResponse(
		events(), nil, timeout, idSmall, order(2), testPeer,
	)
	require.NoError(t, err)
	require.Equal(t, idSmall[:], resp.GetAcceptedQuote().Id)
	require.EqualValues(t, 2, resp.GetAcceptedQuote().AssetMaxAmount)

	resp, err = waitForBuyOrderResponse(
		events(), nil, timeout, idLarge, order(11), testPeer,
	)
	require.NoError(t, err)
	require.Equal(t, idLarge[:], resp.GetAcceptedQuote().Id)
	require.EqualValues(t, 11, resp.GetAcceptedQuote().AssetMaxAmount)
}

// TestWaitForSellOrderResponseMatchesID is the sell order twin of the buy
// test above.
func TestWaitForSellOrderResponseMatchesID(t *testing.T) {
	t.Parallel()

	idSmall, idLarge := testQuoteID(t), testQuoteID(t)

	accept := func(id rfqmsg.ID, maxAmt lnwire.MilliSatoshi) fn.Event {
		return rfq.NewPeerAcceptedSellQuoteEvent(&rfqmsg.SellAccept{
			Peer: testPeer,
			Request: rfqmsg.SellRequest{
				Peer:           testPeer,
				ID:             id,
				AssetSpecifier: testSpecifier,
				PaymentMaxAmt:  maxAmt,
			},
			ID:        id,
			AssetRate: testRate,
		})
	}

	order := func(maxAmt lnwire.MilliSatoshi) rfq.SellOrder {
		return rfq.SellOrder{
			AssetSpecifier: testSpecifier,
			PaymentMaxAmt:  maxAmt,
			Peer:           fn.Some(testPeer),
		}
	}

	events := func() <-chan fn.Event {
		return eventChan(
			accept(idLarge, 11_000), accept(idSmall, 2_000),
		)
	}

	timeout := time.After(time.Second)

	resp, err := waitForSellOrderResponse(
		events(), nil, timeout, idSmall, order(2_000), testPeer,
	)
	require.NoError(t, err)
	require.Equal(t, idSmall[:], resp.GetAcceptedQuote().Id)

	resp, err = waitForSellOrderResponse(
		events(), nil, timeout, idLarge, order(11_000), testPeer,
	)
	require.NoError(t, err)
	require.Equal(t, idLarge[:], resp.GetAcceptedQuote().Id)
}
