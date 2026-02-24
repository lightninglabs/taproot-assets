package tapdb

import (
	"context"
	"database/sql"
	"math/big"
	"testing"
	"time"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmath"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/stretchr/testify/require"
)

// newPolicyStore creates a new PersistedPolicyStore for testing.
func newPolicyStore(t *testing.T) *PersistedPolicyStore {
	db := NewTestDB(t)

	txCreator := func(tx *sql.Tx) RfqPolicyStore {
		return db.WithTx(tx)
	}

	policyDB := NewTransactionExecutor(db, txCreator)

	return NewPersistedPolicyStore(policyDB)
}

// testBuyAccept creates a BuyAccept suitable for persistence tests.
func testBuyAccept(t *testing.T) rfqmsg.BuyAccept {
	rfqID := randRfqID(t)
	peer := randPeer(t)
	assetID := asset.RandID(t)

	rate := rfqmath.BigIntFixedPoint{
		Coefficient: rfqmath.NewBigInt(big.NewInt(100_000)),
		Scale:       0,
	}

	return rfqmsg.BuyAccept{
		Peer:    peer,
		Version: rfqmsg.V1,
		ID:      rfqID,
		AssetRate: rfqmsg.NewAssetRate(
			rate, time.Now().Add(5*time.Minute),
		),
		Request: rfqmsg.BuyRequest{
			Peer:           peer,
			Version:        rfqmsg.V1,
			ID:             rfqID,
			AssetSpecifier: asset.NewSpecifierFromId(assetID),
			AssetMaxAmt:    1_000_000,
			AssetRateHint:  fn.None[rfqmsg.AssetRate](),
		},
		AgreedAt: time.Now().UTC(),
	}
}

// TestStorePeerAcceptedBuyQuote tests that a peer-accepted buy quote can be
// persisted and that the SCID can be looked up afterwards.
func TestStorePeerAcceptedBuyQuote(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newPolicyStore(t)

	accept := testBuyAccept(t)

	// Store the peer-accepted buy quote.
	err := store.StorePeerAcceptedBuyQuote(ctx, accept)
	require.NoError(t, err)

	// Verify we can look up the peer by SCID.
	scid := uint64(accept.ShortChannelId())
	peer, err := store.LookUpScid(ctx, scid)
	require.NoError(t, err)
	require.Equal(t, accept.Peer, peer)
}

// TestLookUpScidNotFound verifies that LookUpScid returns an error when no
// policy exists for the given SCID.
func TestLookUpScidNotFound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newPolicyStore(t)

	_, err := store.LookUpScid(ctx, 99999)
	require.Error(t, err)
	require.Contains(t, err.Error(), "error fetching policy by SCID")
}

// TestLookUpScidMultiplePolicies verifies that LookUpScid returns a valid peer
// even when multiple policies exist with different SCIDs.
func TestLookUpScidMultiplePolicies(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newPolicyStore(t)

	// Store two different peer-accepted buy quotes.
	accept1 := testBuyAccept(t)
	accept2 := testBuyAccept(t)

	err := store.StorePeerAcceptedBuyQuote(ctx, accept1)
	require.NoError(t, err)

	err = store.StorePeerAcceptedBuyQuote(ctx, accept2)
	require.NoError(t, err)

	// Look up each SCID and verify the correct peer is returned.
	peer1, err := store.LookUpScid(
		ctx, uint64(accept1.ShortChannelId()),
	)
	require.NoError(t, err)
	require.Equal(t, accept1.Peer, peer1)

	peer2, err := store.LookUpScid(
		ctx, uint64(accept2.ShortChannelId()),
	)
	require.NoError(t, err)
	require.Equal(t, accept2.Peer, peer2)
}

// TestFetchAcceptedQuotesSeparatesPeerAcceptedBuy verifies that
// FetchAcceptedQuotes returns peer-accepted buy quotes in the third return
// value, separate from sale and purchase policies.
func TestFetchAcceptedQuotesSeparatesPeerAcceptedBuy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newPolicyStore(t)

	// Store a peer-accepted buy quote.
	accept := testBuyAccept(t)
	err := store.StorePeerAcceptedBuyQuote(ctx, accept)
	require.NoError(t, err)

	// Also store a regular sale policy.
	saleAccept := testBuyAccept(t)
	err = store.StoreSalePolicy(ctx, saleAccept)
	require.NoError(t, err)

	buyAccepts, sellAccepts, peerBuys, err :=
		store.FetchAcceptedQuotes(ctx)
	require.NoError(t, err)

	// Sale policy appears in buyAccepts, peer buy quote appears
	// separately in peerBuys.
	require.Len(t, buyAccepts, 1)
	require.Len(t, sellAccepts, 0)
	require.Len(t, peerBuys, 1)
	require.Equal(t, saleAccept.ID, buyAccepts[0].ID)
	require.Equal(t, accept.ID, peerBuys[0].ID)
}

// TestLookUpScidOnlyFindsPeerAcceptedBuy verifies that LookUpScid only returns
// peers from peer-accepted buy quotes, not from sale or purchase policies.
func TestLookUpScidOnlyFindsPeerAcceptedBuy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newPolicyStore(t)

	// Store a peer-accepted buy quote — should be found.
	peerBuy := testBuyAccept(t)
	err := store.StorePeerAcceptedBuyQuote(ctx, peerBuy)
	require.NoError(t, err)

	peer, err := store.LookUpScid(
		ctx, uint64(peerBuy.ShortChannelId()),
	)
	require.NoError(t, err)
	require.Equal(t, peerBuy.Peer, peer)

	// Store a sale policy — should NOT be found by LookUpScid.
	sale := testBuyAccept(t)
	err = store.StoreSalePolicy(ctx, sale)
	require.NoError(t, err)

	_, err = store.LookUpScid(
		ctx, uint64(sale.ShortChannelId()),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "error fetching policy by SCID")
}

// testSellAccept creates a SellAccept suitable for persistence tests.
func testSellAccept(t *testing.T) rfqmsg.SellAccept {
	rfqID := randRfqID(t)
	peer := randPeer(t)
	assetID := asset.RandID(t)

	rate := rfqmath.BigIntFixedPoint{
		Coefficient: rfqmath.NewBigInt(big.NewInt(100_000)),
		Scale:       0,
	}

	return rfqmsg.SellAccept{
		Peer:    peer,
		Version: rfqmsg.V1,
		ID:      rfqID,
		AssetRate: rfqmsg.NewAssetRate(
			rate, time.Now().Add(5*time.Minute),
		),
		Request: rfqmsg.SellRequest{
			Peer:           peer,
			Version:        rfqmsg.V1,
			ID:             rfqID,
			AssetSpecifier: asset.NewSpecifierFromId(assetID),
			PaymentMaxAmt:  500_000,
			AssetRateHint:  fn.None[rfqmsg.AssetRate](),
		},
		AgreedAt: time.Now().UTC(),
	}
}

// TestFetchAcceptedQuotesAllThreeTypes verifies that FetchAcceptedQuotes
// correctly categorises all three policy types: sale policies appear as buy
// accepts, purchase policies appear as sell accepts, and peer-accepted buy
// quotes are returned separately.
func TestFetchAcceptedQuotesAllThreeTypes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newPolicyStore(t)

	// Store one of each type.
	sale := testBuyAccept(t)
	err := store.StoreSalePolicy(ctx, sale)
	require.NoError(t, err)

	purchase := testSellAccept(t)
	err = store.StorePurchasePolicy(ctx, purchase)
	require.NoError(t, err)

	peerBuy := testBuyAccept(t)
	err = store.StorePeerAcceptedBuyQuote(ctx, peerBuy)
	require.NoError(t, err)

	buyAccepts, sellAccepts, peerBuys, err :=
		store.FetchAcceptedQuotes(ctx)
	require.NoError(t, err)

	// Sale → buyAccepts, Purchase → sellAccepts, PeerBuy → peerBuys.
	require.Len(t, buyAccepts, 1)
	require.Len(t, sellAccepts, 1)
	require.Len(t, peerBuys, 1)
	require.Equal(t, sale.ID, buyAccepts[0].ID)
	require.Equal(t, purchase.ID, sellAccepts[0].ID)
	require.Equal(t, peerBuy.ID, peerBuys[0].ID)
}

// TestLookUpScidIgnoresSalePolicy verifies that a sale policy stored in the
// database is not returned by LookUpScid, which is scoped to peer-accepted
// buy quotes only.
func TestLookUpScidIgnoresSalePolicy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newPolicyStore(t)

	accept := testBuyAccept(t)
	err := store.StoreSalePolicy(ctx, accept)
	require.NoError(t, err)

	_, err = store.LookUpScid(ctx, uint64(accept.ShortChannelId()))
	require.Error(t, err)
	require.Contains(t, err.Error(), "error fetching policy by SCID")
}
