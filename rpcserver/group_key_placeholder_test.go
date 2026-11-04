package rpcserver

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/tapdb"
	"github.com/lightninglabs/taproot-assets/taprpc/tapchannelrpc"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/stretchr/testify/require"
)

// federationSyncSpy stands in for the federation envoy and records every
// asset lookup that is escalated to the universe servers.
type federationSyncSpy struct {
	address.AssetSyncer

	lookups []asset.Specifier
}

func (s *federationSyncSpy) SyncAssetInfo(_ context.Context,
	spec asset.Specifier) error {

	s.lookups = append(s.lookups, spec)
	return fmt.Errorf("asset lookup failed for asset: %v", &spec)
}

// newGroupedAssetBook returns an address book backed by a real sqlite store
// that knows one grouped asset, the group's key and a spy for the federation.
func newGroupedAssetBook(t *testing.T) (*address.Book, *asset.GroupKey,
	*federationSyncSpy) {

	t.Helper()
	ctx := context.Background()

	db := tapdb.NewTestDB(t)
	txCreator := func(tx *sql.Tx) tapdb.AddrBook {
		return db.WithTx(tx)
	}
	addrStore := tapdb.NewTapAddressBook(
		tapdb.NewTransactionExecutor(db, txCreator),
		&address.RegressionNetTap, clock.NewDefaultClock(),
	)

	gen := asset.RandGenesis(t, asset.Normal)
	genesisAsset := asset.NewAssetNoErr(
		t, gen, 1, 0, 0, asset.RandScriptKey(t), nil,
	)
	groupKey := asset.RandGroupKey(t, gen, genesisAsset)
	require.NoError(t, addrStore.InsertAssetGen(ctx, &gen, groupKey))

	group, err := addrStore.QueryAssetGroupByGroupKey(
		ctx, &groupKey.GroupPubKey,
	)
	require.NoError(t, err)
	require.NotNil(t, group, "the group is known locally")

	syncer := &federationSyncSpy{}
	book := address.NewBook(address.BookConfig{
		Store:  addrStore,
		Syncer: syncer,
	})

	return book, groupKey, syncer
}

// requirePlaceholderResolved checks that an amount decoded from a group-key
// placeholder carries the group's key and that nothing was looked up in the
// federation.
func requirePlaceholderResolved(t *testing.T,
	amounts []*tapchannelrpc.AssetAmount, groupKey *asset.GroupKey,
	syncer *federationSyncSpy, units uint64) {

	t.Helper()

	groupKeyX := schnorr.SerializePubKey(&groupKey.GroupPubKey)

	require.Len(t, amounts, 1)
	require.Equal(t, units, amounts[0].Amount)
	require.Equal(t, groupKeyX, amounts[0].AssetId)

	// A locally known group must not be looked up in the federation.
	for _, lookup := range syncer.lookups {
		t.Errorf("placeholder escalated to a universe sync as %s "+
			"(group key x-coordinate %x)", lookup.String(),
			groupKeyX)
	}
	require.Empty(t, syncer.lookups)

	// The RPC promises the tweaked group key alongside the amount.
	require.Equal(
		t, groupKey.GroupPubKey.SerializeCompressed(),
		amounts[0].GroupKey,
	)
}

// TestGroupKeyPlaceholderResolvesLocally checks that the asset-aware list
// RPCs resolve the group-key placeholder from the local database.
//
// For a payment made against a group key, tapd cannot know up front which
// tranche will move, so it writes the x-coordinate of the group key into the
// HTLC balance's asset ID field as a placeholder (rfq/order.go,
// tapchannel/aux_traffic_shaper.go, rfq.Manager.AssetMatchesSpecifier). A
// node that holds the grouped asset knows that group in its address book. The
// group key the list RPCs attach to each amount must therefore come from the
// local database, and the lookup must not be escalated to the federation.
func TestGroupKeyPlaceholderResolvesLocally(t *testing.T) {
	ctx := context.Background()

	t.Run("payment", func(t *testing.T) {
		book, groupKey, syncer := newGroupedAssetBook(t)
		groupKeyX := schnorr.SerializePubKey(&groupKey.GroupPubKey)

		// The route data of a group-key payment, as lnd's aux data
		// parser renders it.
		jsonHtlc, err := json.Marshal(&rfqmsg.JsonHtlc{
			Balances: []*rfqmsg.JsonAssetTranche{{
				AssetID: hex.EncodeToString(groupKeyX),
				Amount:  1_003_797,
			}},
		})
		require.NoError(t, err)

		out, isAsset, err := marshalAssetPayment(
			paymentWithRouteData(jsonHtlc),
			newAssetGroupLookup(ctx, book),
		)
		require.NoError(t, err)
		require.True(t, isAsset)
		requirePlaceholderResolved(
			t, out.AssetAmounts, groupKey, syncer, 1_003_797,
		)
	})

	t.Run("invoice", func(t *testing.T) {
		book, groupKey, syncer := newGroupedAssetBook(t)
		groupKeyX := schnorr.SerializePubKey(&groupKey.GroupPubKey)

		// The settled HTLC's custom records, as written by the payer.
		htlc := rfqmsg.NewHtlc(
			[]*rfqmsg.AssetBalance{
				rfqmsg.NewAssetBalance(
					asset.ID(groupKeyX), 1_000_115,
				),
			},
			fn.None[rfqmsg.ID](),
			fn.None[[]rfqmsg.ID](),
		)
		records, err := htlc.ToCustomRecords()
		require.NoError(t, err)

		invoice := &lnrpc.Invoice{
			RHash: []byte("hash"),
			Htlcs: []*lnrpc.InvoiceHTLC{{
				State:         lnrpc.InvoiceHTLCState_SETTLED,
				CustomRecords: records,
			}},
		}

		out, isAsset, err := marshalAssetInvoice(
			invoice, newAssetGroupLookup(ctx, book), nil,
		)
		require.NoError(t, err)
		require.True(t, isAsset)
		requirePlaceholderResolved(
			t, out.AssetAmounts, groupKey, syncer, 1_000_115,
		)
	})

	t.Run("unknown tranche id still bootstraps", func(t *testing.T) {
		book, _, syncer := newGroupedAssetBook(t)

		var unknownID asset.ID
		copy(unknownID[:], []byte("a tranche this node never saw   "))

		jsonHtlc, err := json.Marshal(&rfqmsg.JsonHtlc{
			Balances: []*rfqmsg.JsonAssetTranche{{
				AssetID: hex.EncodeToString(unknownID[:]),
				Amount:  7,
			}},
		})
		require.NoError(t, err)

		out, _, err := marshalAssetPayment(
			paymentWithRouteData(jsonHtlc),
			newAssetGroupLookup(ctx, book),
		)
		require.NoError(t, err)
		require.Len(t, out.AssetAmounts, 1)
		require.Empty(t, out.AssetAmounts[0].GroupKey)

		// A genuinely unknown asset is still looked up by ID.
		require.Len(t, syncer.lookups, 1)
		require.True(t, syncer.lookups[0].HasId())
	})
}
