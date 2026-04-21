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

	buyAccepts, sellAccepts, peerBuys, peerSells, err :=
		store.FetchAcceptedQuotes(ctx)
	require.NoError(t, err)

	// Sale policy appears in buyAccepts, peer buy quote appears
	// separately in peerBuys.
	require.Len(t, buyAccepts, 1)
	require.Len(t, sellAccepts, 0)
	require.Len(t, peerBuys, 1)
	require.Len(t, peerSells, 0)
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

// TestFetchAcceptedQuotesAllFourTypes verifies that FetchAcceptedQuotes
// correctly categorises all four policy types: sale policies appear as
// buy accepts, purchase policies appear as sell accepts, and
// peer-accepted buy/sell quotes are returned separately.
func TestFetchAcceptedQuotesAllFourTypes(t *testing.T) {
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

	peerSell := testSellAccept(t)
	err = store.StorePeerAcceptedSellQuote(ctx, peerSell)
	require.NoError(t, err)

	buyAccepts, sellAccepts, peerBuys, peerSells, err :=
		store.FetchAcceptedQuotes(ctx)
	require.NoError(t, err)

	require.Len(t, buyAccepts, 1)
	require.Len(t, sellAccepts, 1)
	require.Len(t, peerBuys, 1)
	require.Len(t, peerSells, 1)
	require.Equal(t, sale.ID, buyAccepts[0].ID)
	require.Equal(t, purchase.ID, sellAccepts[0].ID)
	require.Equal(t, peerBuy.ID, peerBuys[0].ID)
	require.Equal(t, peerSell.ID, peerSells[0].ID)
}

// TestAcceptedMaxAmountRoundTrip verifies that the AcceptedMaxAmount
// field survives a store-then-fetch cycle for all three policy types.
func TestAcceptedMaxAmountRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newPolicyStore(t)

	// Sale policy with a fill cap.
	sale := testBuyAccept(t)
	sale.AcceptedMaxAmount = fn.Some[uint64](500_000)
	err := store.StoreSalePolicy(ctx, sale)
	require.NoError(t, err)

	// Purchase policy with a fill cap.
	purchase := testSellAccept(t)
	purchase.AcceptedMaxAmount = fn.Some[uint64](250_000)
	err = store.StorePurchasePolicy(ctx, purchase)
	require.NoError(t, err)

	// Peer-accepted buy quote with a fill cap.
	peerBuy := testBuyAccept(t)
	peerBuy.AcceptedMaxAmount = fn.Some[uint64](750_000)
	err = store.StorePeerAcceptedBuyQuote(ctx, peerBuy)
	require.NoError(t, err)

	buys, sells, peerBuys, _, err := store.FetchAcceptedQuotes(ctx)
	require.NoError(t, err)

	require.Len(t, buys, 1)
	require.Len(t, sells, 1)
	require.Len(t, peerBuys, 1)

	require.Equal(t, fn.Some[uint64](500_000),
		buys[0].AcceptedMaxAmount)
	require.Equal(t, fn.Some[uint64](250_000),
		sells[0].AcceptedMaxAmount)
	require.Equal(t, fn.Some[uint64](750_000),
		peerBuys[0].AcceptedMaxAmount)
}

// TestAcceptedMaxAmountNilRoundTrip verifies that a policy stored
// without AcceptedMaxAmount restores with None.
func TestAcceptedMaxAmountNilRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newPolicyStore(t)

	sale := testBuyAccept(t)
	err := store.StoreSalePolicy(ctx, sale)
	require.NoError(t, err)

	buys, _, _, _, err := store.FetchAcceptedQuotes(ctx)
	require.NoError(t, err)
	require.Len(t, buys, 1)
	require.True(t, buys[0].AcceptedMaxAmount.IsNone())
}

// TestExecutionPolicyRoundTrip verifies that the ExecutionPolicy
// field survives a store-then-fetch cycle for sale and purchase
// policies.
func TestExecutionPolicyRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newPolicyStore(t)

	// Sale policy with FOK execution policy.
	sale := testBuyAccept(t)
	sale.Request.ExecutionPolicy = fn.Some(
		rfqmsg.ExecutionPolicyFOK,
	)
	err := store.StoreSalePolicy(ctx, sale)
	require.NoError(t, err)

	// Purchase policy with IOC execution policy.
	purchase := testSellAccept(t)
	purchase.Request.ExecutionPolicy = fn.Some(
		rfqmsg.ExecutionPolicyIOC,
	)
	err = store.StorePurchasePolicy(ctx, purchase)
	require.NoError(t, err)

	// Sale policy without execution policy.
	saleNone := testBuyAccept(t)
	err = store.StoreSalePolicy(ctx, saleNone)
	require.NoError(t, err)

	buys, sells, _, _, err := store.FetchAcceptedQuotes(ctx)
	require.NoError(t, err)
	require.Len(t, buys, 2)
	require.Len(t, sells, 1)

	// Find the sale with FOK and verify.
	for _, b := range buys {
		if b.ID == sale.ID {
			require.Equal(t,
				fn.Some(rfqmsg.ExecutionPolicyFOK),
				b.Request.ExecutionPolicy,
			)
		}
		if b.ID == saleNone.ID {
			require.True(
				t,
				b.Request.ExecutionPolicy.IsNone(),
			)
		}
	}

	// Verify purchase policy round-tripped IOC.
	require.Equal(t,
		fn.Some(rfqmsg.ExecutionPolicyIOC),
		sells[0].Request.ExecutionPolicy,
	)
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

// TestStorePeerAcceptedSellQuote tests that a peer-accepted sell quote
// can be persisted and round-tripped through FetchAcceptedQuotes.
func TestStorePeerAcceptedSellQuote(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newPolicyStore(t)

	accept := testSellAccept(t)

	err := store.StorePeerAcceptedSellQuote(ctx, accept)
	require.NoError(t, err)

	_, _, _, peerSells, err := store.FetchAcceptedQuotes(ctx)
	require.NoError(t, err)

	require.Len(t, peerSells, 1)
	require.Equal(t, accept.ID, peerSells[0].ID)
	require.Equal(t, accept.Peer, peerSells[0].Peer)
	require.Equal(
		t, accept.Request.PaymentMaxAmt,
		peerSells[0].Request.PaymentMaxAmt,
	)
}

// TestFetchAcceptedQuotesSeparatesPeerAcceptedSell verifies that
// FetchAcceptedQuotes returns peer-accepted sell quotes in the fourth
// return value, separate from purchase policies.
func TestFetchAcceptedQuotesSeparatesPeerAcceptedSell(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newPolicyStore(t)

	// Store a peer-accepted sell quote.
	peerSell := testSellAccept(t)
	err := store.StorePeerAcceptedSellQuote(ctx, peerSell)
	require.NoError(t, err)

	// Also store a regular purchase policy.
	purchase := testSellAccept(t)
	err = store.StorePurchasePolicy(ctx, purchase)
	require.NoError(t, err)

	buyAccepts, sellAccepts, peerBuys, peerSells, err :=
		store.FetchAcceptedQuotes(ctx)
	require.NoError(t, err)

	// Purchase policy appears in sellAccepts, peer sell quote
	// appears separately in peerSells.
	require.Len(t, buyAccepts, 0)
	require.Len(t, sellAccepts, 1)
	require.Len(t, peerBuys, 0)
	require.Len(t, peerSells, 1)
	require.Equal(t, purchase.ID, sellAccepts[0].ID)
	require.Equal(t, peerSell.ID, peerSells[0].ID)
}

// TestUpsertPolicyIdempotent verifies that storing the same quote
// twice (identical rfq_id) does not error and does not create a
// duplicate row.
func TestUpsertPolicyIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newPolicyStore(t)

	accept := testBuyAccept(t)

	err := store.StorePeerAcceptedBuyQuote(ctx, accept)
	require.NoError(t, err)

	// Second store with the same rfq_id must not error.
	err = store.StorePeerAcceptedBuyQuote(ctx, accept)
	require.NoError(t, err)

	// Only one row should exist.
	_, _, peerBuys, _, err := store.FetchAcceptedQuotes(ctx)
	require.NoError(t, err)
	require.Len(t, peerBuys, 1)
}
