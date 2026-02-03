package tapdb

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/rfq"
	"github.com/lightninglabs/taproot-assets/rfqmsg"
	"github.com/lightninglabs/taproot-assets/tapdb/sqlc"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/stretchr/testify/require"
)

// newForwardStore creates a new PersistedForwardStore for testing along with
// the underlying database handles needed to set up test data.
func newForwardStore(t *testing.T) (*PersistedForwardStore,
	*PersistedPolicyStore, sqlc.Querier) {

	db := NewTestDB(t)

	forwardTxCreator := func(tx *sql.Tx) ForwardStore {
		return db.WithTx(tx)
	}
	policyTxCreator := func(tx *sql.Tx) RfqPolicyStore {
		return db.WithTx(tx)
	}

	forwardDB := NewTransactionExecutor(db, forwardTxCreator)
	policyDB := NewTransactionExecutor(db, policyTxCreator)

	return NewPersistedForwardStore(forwardDB),
		NewPersistedPolicyStore(policyDB),
		db
}

// randRfqID generates a random RFQ ID for testing.
func randRfqID(t *testing.T) rfqmsg.ID {
	var id rfqmsg.ID
	copy(id[:], test.RandBytes(32))
	return id
}

// randPeer generates a random peer vertex for testing.
func randPeer(t *testing.T) route.Vertex {
	var peer route.Vertex
	copy(peer[:], test.RandBytes(33))
	return peer
}

// insertTestPolicy inserts an RFQ policy into the database for testing.
// This is required because forwards has a foreign key to rfq_policies.
func insertTestPolicy(t *testing.T, ctx context.Context, db sqlc.Querier,
	rfqID rfqmsg.ID, policyType rfq.RfqPolicyType, peer route.Vertex,
	assetID *asset.ID, groupKey *btcec.PublicKey) {

	var assetIDBytes []byte
	if assetID != nil {
		assetIDBytes = assetID[:]
	}

	var groupKeyBytes []byte
	if groupKey != nil {
		groupKeyBytes = groupKey.SerializeCompressed()
	}

	// Create a simple rate coefficient (just bytes for testing).
	rateCoeffBytes := []byte{0x01, 0x23, 0x45}

	_, err := db.InsertRfqPolicy(ctx, sqlc.InsertRfqPolicyParams{
		PolicyType:      string(policyType),
		Scid:            12345,
		RfqID:           rfqID[:],
		Peer:            peer[:],
		AssetID:         assetIDBytes,
		AssetGroupKey:   groupKeyBytes,
		RateCoefficient: rateCoeffBytes,
		RateScale:       6,
		Expiry:          time.Now().Add(time.Hour).Unix(),
		AgreedAt:        time.Now().Unix(),
	})
	require.NoError(t, err)
}

// TestUpsertForward tests the UpsertForward method with various scenarios.
func TestUpsertForward(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		setupFn func(t *testing.T, ctx context.Context,
			db sqlc.Querier) ([]rfq.ForwardInput, any)

		verifyFn func(t *testing.T, ctx context.Context,
			store *PersistedForwardStore, inputs []rfq.ForwardInput,
			setupData any)
	}{{
		name: "basic insert and retrieve",
		setupFn: func(t *testing.T, ctx context.Context,
			db sqlc.Querier) ([]rfq.ForwardInput, any) {

			rfqID := randRfqID(t)
			peer := randPeer(t)
			assetID := asset.RandID(t)

			insertTestPolicy(
				t, ctx, db, rfqID, rfq.RfqPolicyTypeAssetSale,
				peer, &assetID, nil,
			)

			openedAt := time.Now().UTC().Truncate(time.Second)
			input := rfq.ForwardInput{
				OpenedAt:   openedAt,
				RfqID:      rfqID,
				ChanIDIn:   100,
				ChanIDOut:  200,
				HtlcID:     1,
				AssetAmt:   500,
				AmtInMsat:  42000,
				AmtOutMsat: 41000,
			}

			return []rfq.ForwardInput{input}, map[string]any{
				"rfqID":    rfqID,
				"peer":     peer,
				"assetID":  assetID,
				"openedAt": openedAt,
			}
		},
		verifyFn: func(t *testing.T, ctx context.Context,
			store *PersistedForwardStore, inputs []rfq.ForwardInput,
			setupData any) {

			data := setupData.(map[string]any)
			rfqID := data["rfqID"].(rfqmsg.ID)
			peer := data["peer"].(route.Vertex)
			assetID := data["assetID"].(asset.ID)
			openedAt := data["openedAt"].(time.Time)

			records, _, err := store.QueryForwardsWithCount(
				ctx, rfq.QueryForwardsParams{Limit: 10},
			)
			require.NoError(t, err)
			require.Len(t, records, 1)

			record := records[0]
			require.Equal(t, openedAt.Truncate(time.Microsecond),
				record.OpenedAt)
			require.Nil(t, record.SettledAt)
			require.Nil(t, record.FailedAt)
			require.Equal(t, rfqID, record.RfqID)
			require.Equal(t, uint64(100), record.ChanIDIn)
			require.Equal(t, uint64(200), record.ChanIDOut)
			require.Equal(t, uint64(1), record.HtlcID)
			require.Equal(t, uint64(500), record.AssetAmt)
			require.Equal(t, uint64(42000), record.AmtInMsat)
			require.Equal(t, uint64(41000), record.AmtOutMsat)

			// Verify joined policy data.
			require.Equal(
				t, rfq.RfqPolicyTypeAssetSale,
				record.PolicyType,
			)
			require.Equal(t, peer, record.Peer)
			assetIDPtr := record.AssetSpecifier.UnwrapIdToPtr()
			require.NotNil(t, assetIDPtr)
			require.Equal(t, assetID, *assetIDPtr)
			require.False(t, record.AssetSpecifier.HasGroupPubKey())
		},
	}, {
		name: "duplicate insert updates",
		setupFn: func(t *testing.T, ctx context.Context,
			db sqlc.Querier) ([]rfq.ForwardInput, any) {

			rfqID := randRfqID(t)
			peer := randPeer(t)

			insertTestPolicy(
				t, ctx, db, rfqID, rfq.RfqPolicyTypeAssetSale,
				peer, nil, nil,
			)

			input1 := rfq.ForwardInput{
				OpenedAt:   time.Now().UTC(),
				RfqID:      rfqID,
				ChanIDIn:   100,
				ChanIDOut:  200,
				HtlcID:     1,
				AssetAmt:   500,
				AmtInMsat:  42000,
				AmtOutMsat: 41000,
			}
			input2 := rfq.ForwardInput{
				OpenedAt:   time.Now().UTC(),
				RfqID:      rfqID,
				ChanIDIn:   100,
				ChanIDOut:  300,
				HtlcID:     1,
				AssetAmt:   1000,
				AmtInMsat:  42000,
				AmtOutMsat: 41000,
			}

			return []rfq.ForwardInput{input1, input2}, nil
		},
		verifyFn: func(t *testing.T, ctx context.Context,
			store *PersistedForwardStore, inputs []rfq.ForwardInput,
			setupData any) {

			records, _, err := store.QueryForwardsWithCount(
				ctx, rfq.QueryForwardsParams{Limit: 10},
			)
			require.NoError(t, err)
			require.Len(t, records, 1)

			record := records[0]
			require.Equal(t, inputs[1].OpenedAt.Unix(),
				record.OpenedAt.Unix(),
			)
			require.Equal(t, inputs[1].ChanIDOut, record.ChanIDOut)
			require.Equal(t, inputs[1].AssetAmt, record.AssetAmt)
			require.Equal(t, inputs[1].AmtInMsat, record.AmtInMsat)
			require.Equal(t, inputs[1].AmtOutMsat,
				record.AmtOutMsat)
		},
	}, {
		name: "forward with group key",
		setupFn: func(t *testing.T, ctx context.Context,
			db sqlc.Querier) ([]rfq.ForwardInput, any) {

			rfqID := randRfqID(t)
			peer := randPeer(t)
			groupKey := test.RandPubKey(t)

			insertTestPolicy(
				t, ctx, db, rfqID,
				rfq.RfqPolicyTypeAssetPurchase, peer, nil,
				groupKey,
			)

			input := rfq.ForwardInput{
				OpenedAt:   time.Now(),
				RfqID:      rfqID,
				ChanIDIn:   100,
				ChanIDOut:  200,
				HtlcID:     1,
				AssetAmt:   500,
				AmtInMsat:  42000,
				AmtOutMsat: 41000,
			}

			return []rfq.ForwardInput{input}, groupKey
		},
		verifyFn: func(t *testing.T, ctx context.Context,
			store *PersistedForwardStore, inputs []rfq.ForwardInput,
			setupData any) {

			groupKey := setupData.(*btcec.PublicKey)

			records, _, err := store.QueryForwardsWithCount(
				ctx, rfq.QueryForwardsParams{Limit: 10},
			)
			require.NoError(t, err)
			require.Len(t, records, 1)

			groupKeyPtr := records[0].AssetSpecifier.
				UnwrapGroupKeyToPtr()
			require.NotNil(t, groupKeyPtr)
			require.True(t, groupKey.IsEqual(groupKeyPtr))
			require.False(t, records[0].AssetSpecifier.HasId())

			// Query filtered by group key.
			groupSpec := asset.NewSpecifierFromGroupKey(*groupKey)
			records, _, err = store.QueryForwardsWithCount(
				ctx, rfq.QueryForwardsParams{
					AssetSpecifier: &groupSpec,
					Limit:          10,
				},
			)
			require.NoError(t, err)
			require.Len(t, records, 1)
		},
	}, {
		name: "multiple forwards same RFQ ID",
		setupFn: func(t *testing.T, ctx context.Context,
			db sqlc.Querier) ([]rfq.ForwardInput, any) {

			rfqID := randRfqID(t)
			peer := randPeer(t)

			insertTestPolicy(
				t, ctx, db, rfqID, rfq.RfqPolicyTypeAssetSale,
				peer, nil, nil,
			)

			// Multiple forwards with same RFQ ID but different
			// HTLCs.
			var inputs []rfq.ForwardInput
			for i := 0; i < 5; i++ {
				inputs = append(inputs, rfq.ForwardInput{
					OpenedAt:   time.Now(),
					RfqID:      rfqID,
					ChanIDIn:   uint64(100 + i),
					ChanIDOut:  200,
					HtlcID:     uint64(i),
					AssetAmt:   100,
					AmtInMsat:  42000,
					AmtOutMsat: 41000,
				})
			}

			return inputs, rfqID
		},
		verifyFn: func(t *testing.T, ctx context.Context,
			store *PersistedForwardStore, inputs []rfq.ForwardInput,
			setupData any) {

			rfqID := setupData.(rfqmsg.ID)

			records, _, err := store.QueryForwardsWithCount(
				ctx, rfq.QueryForwardsParams{Limit: 100},
			)
			require.NoError(t, err)
			require.Len(t, records, 5)

			for _, r := range records {
				require.Equal(t, rfqID, r.RfqID)
			}
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			forwardStore, _, db := newForwardStore(t)

			inputs, setupData := tc.setupFn(t, ctx, db)

			for _, input := range inputs {
				err := forwardStore.UpsertForward(ctx, input)
				require.NoError(t, err)
			}

			if tc.verifyFn != nil {
				tc.verifyFn(t, ctx, forwardStore, inputs,
					setupData,
				)
			}
		})
	}
}

// TestPendingForwards verifies pending forwards are returned.
func TestPendingForwards(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	forwardStore, _, db := newForwardStore(t)

	rfqID := randRfqID(t)
	peer := randPeer(t)
	insertTestPolicy(
		t, ctx, db, rfqID, rfq.RfqPolicyTypeAssetSale,
		peer, nil, nil,
	)

	openedAt := time.Now().UTC().Truncate(time.Second)
	pending := rfq.ForwardInput{
		OpenedAt:   openedAt,
		RfqID:      rfqID,
		ChanIDIn:   100,
		ChanIDOut:  200,
		HtlcID:     1,
		AssetAmt:   500,
		AmtInMsat:  42000,
		AmtOutMsat: 41000,
	}

	settledAt := openedAt.Add(10 * time.Second)
	settled := rfq.ForwardInput{
		OpenedAt:   openedAt.Add(1 * time.Second),
		SettledAt:  fn.Some(settledAt),
		RfqID:      rfqID,
		ChanIDIn:   101,
		ChanIDOut:  201,
		HtlcID:     2,
		AssetAmt:   600,
		AmtInMsat:  42000,
		AmtOutMsat: 41000,
	}

	failedAt := openedAt.Add(20 * time.Second)
	failed := rfq.ForwardInput{
		OpenedAt:   openedAt.Add(2 * time.Second),
		FailedAt:   fn.Some(failedAt),
		RfqID:      rfqID,
		ChanIDIn:   102,
		ChanIDOut:  202,
		HtlcID:     3,
		AssetAmt:   700,
		AmtInMsat:  42000,
		AmtOutMsat: 41000,
	}

	for _, input := range []rfq.ForwardInput{pending, settled, failed} {
		require.NoError(t, forwardStore.UpsertForward(ctx, input))
	}

	forwards, err := forwardStore.PendingForwards(ctx)
	require.NoError(t, err)
	require.Len(t, forwards, 1)

	forward := forwards[0]
	require.Equal(t, pending.OpenedAt.Truncate(time.Microsecond),
		forward.OpenedAt)
	require.Equal(t, pending.RfqID, forward.RfqID)
	require.Equal(t, pending.ChanIDIn, forward.ChanIDIn)
	require.Equal(t, pending.ChanIDOut, forward.ChanIDOut)
	require.Equal(t, pending.HtlcID, forward.HtlcID)
	require.Equal(t, pending.AssetAmt, forward.AssetAmt)
	require.Equal(t, pending.AmtInMsat, forward.AmtInMsat)
	require.Equal(t, pending.AmtOutMsat, forward.AmtOutMsat)
	require.True(t, forward.SettledAt.IsNone())
	require.True(t, forward.FailedAt.IsNone())
}

type forwardTestSetup struct {
	rfqID1   rfqmsg.ID
	rfqID2   rfqmsg.ID
	peer1    route.Vertex
	peer2    route.Vertex
	assetID1 asset.ID
	assetID2 asset.ID
	groupKey *btcec.PublicKey
	times    []time.Time
}

// setupQueryTestData sets up test data for query tests and returns the setup.
func setupQueryTestData(t *testing.T, ctx context.Context,
	store *PersistedForwardStore,
	db sqlc.Querier) *forwardTestSetup {

	setup := &forwardTestSetup{
		rfqID1:   randRfqID(t),
		rfqID2:   randRfqID(t),
		peer1:    randPeer(t),
		peer2:    randPeer(t),
		assetID1: asset.RandID(t),
		assetID2: asset.RandID(t),
		groupKey: test.RandPubKey(t),
	}

	now := time.Now().UTC()
	setup.times = []time.Time{
		now.Add(-3 * time.Hour),
		now.Add(-2 * time.Hour),
		now.Add(-1 * time.Hour),
		now,
	}

	// Insert policies.
	insertTestPolicy(
		t, ctx, db, setup.rfqID1, rfq.RfqPolicyTypeAssetSale,
		setup.peer1, &setup.assetID1, nil,
	)
	insertTestPolicy(
		t, ctx, db, setup.rfqID2, rfq.RfqPolicyTypeAssetPurchase,
		setup.peer2, &setup.assetID2, nil,
	)

	// Insert forwards at different times for rfqID1.
	for i, openedAt := range setup.times {
		input := rfq.ForwardInput{
			OpenedAt:   openedAt,
			RfqID:      setup.rfqID1,
			ChanIDIn:   uint64(100 + i),
			ChanIDOut:  200,
			HtlcID:     uint64(i),
			AssetAmt:   uint64(500 * (i + 1)),
			AmtInMsat:  42000,
			AmtOutMsat: 41000,
		}
		require.NoError(t, store.UpsertForward(ctx, input))
	}

	// Insert forwards for rfqID2 (different peer and asset).
	for i := 0; i < 2; i++ {
		input := rfq.ForwardInput{
			OpenedAt:   time.Now(),
			RfqID:      setup.rfqID2,
			ChanIDIn:   uint64(200 + i),
			ChanIDOut:  300,
			HtlcID:     uint64(i),
			AssetAmt:   1000,
			AmtInMsat:  42000,
			AmtOutMsat: 41000,
		}
		require.NoError(t, store.UpsertForward(ctx, input))
	}

	return setup
}

// TestQueryForwardsWithCountFilters tests QueryForwardsWithCount filters.
func TestQueryForwardsWithCountFilters(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	forwardStore, _, db := newForwardStore(t)
	setup := setupQueryTestData(t, ctx, forwardStore, db)
	now := setup.times[3]
	assetID1Spec := asset.NewSpecifierFromId(setup.assetID1)
	assetID2Spec := asset.NewSpecifierFromId(setup.assetID2)

	testCases := []struct {
		name      string
		params    rfq.QueryForwardsParams
		numResult int
	}{{
		name:      "no filters",
		params:    rfq.QueryForwardsParams{Limit: 100},
		numResult: 6,
	}, {
		name: "min timestamp filter",
		params: rfq.QueryForwardsParams{
			MinTimestamp: fn.Some(now.Add(-2 * time.Hour)),
			Limit:        100,
		},
		// -2h, -1h, now from rfqID1, plus 2 from rfqID2
		numResult: 5,
	}, {
		name: "max timestamp filter",
		params: rfq.QueryForwardsParams{
			MaxTimestamp: fn.Some(now.Add(-1 * time.Hour)),
			Limit:        100,
		},
		// -3h, -2h, -1h from rfqID1
		numResult: 3,
	}, {
		name: "min and max timestamp filter",
		params: rfq.QueryForwardsParams{
			MinTimestamp: fn.Some(now.Add(-2 * time.Hour)),
			MaxTimestamp: fn.Some(now.Add(-1 * time.Hour)),
			Limit:        100,
		},
		// -2h, -1h from rfqID1
		numResult: 2,
	}, {
		name: "peer filter - peer1",
		params: rfq.QueryForwardsParams{
			Peer:  &setup.peer1,
			Limit: 100,
		},
		numResult: 4,
	}, {
		name: "peer filter - peer2",
		params: rfq.QueryForwardsParams{
			Peer:  &setup.peer2,
			Limit: 100,
		},
		numResult: 2,
	}, {
		name: "asset filter - assetID1",
		params: rfq.QueryForwardsParams{
			AssetSpecifier: &assetID1Spec,
			Limit:          100,
		},
		numResult: 4,
	}, {
		name: "asset filter - assetID2",
		params: rfq.QueryForwardsParams{
			AssetSpecifier: &assetID2Spec,
			Limit:          100,
		},
		numResult: 2,
	}, {
		name: "pagination - first page",
		params: rfq.QueryForwardsParams{
			Limit:  3,
			Offset: 0,
		},
		numResult: 3,
	}, {
		name: "pagination - second page",
		params: rfq.QueryForwardsParams{
			Limit:  3,
			Offset: 3,
		},
		numResult: 3,
	}, {
		name: "pagination - third page (empty)",
		params: rfq.QueryForwardsParams{
			Limit:  3,
			Offset: 6,
		},
		numResult: 0,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			records, _, err := forwardStore.QueryForwardsWithCount(
				ctx, tc.params,
			)
			require.NoError(t, err)
			require.Len(t, records, tc.numResult)

			// Verify peer filter results have correct peer.
			if tc.params.Peer != nil {
				for _, r := range records {
					require.Equal(
						t, *tc.params.Peer, r.Peer,
					)
				}
			}
		})
	}
}

// TestQueryForwardsWithCountCounts tests QueryForwardsWithCount counts.
func TestQueryForwardsWithCountCounts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	forwardStore, _, db := newForwardStore(t)
	setup := setupQueryTestData(t, ctx, forwardStore, db)
	assetID1Spec := asset.NewSpecifierFromId(setup.assetID1)

	testCases := []struct {
		name     string
		params   rfq.QueryForwardsParams
		expCount int64
	}{{
		name:     "count all",
		params:   rfq.QueryForwardsParams{},
		expCount: 6,
	}, {
		name: "count filtered by asset",
		params: rfq.QueryForwardsParams{
			AssetSpecifier: &assetID1Spec,
		},
		expCount: 4,
	}, {
		name: "count filtered by peer",
		params: rfq.QueryForwardsParams{
			Peer: &setup.peer2,
		},
		expCount: 2,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, count, err := forwardStore.QueryForwardsWithCount(
				ctx, tc.params,
			)
			require.NoError(t, err)
			require.Equal(t, tc.expCount, count)
		})
	}
}

// TestQueryForwardsWithCount tests the QueryForwardsWithCount method.
func TestQueryForwardsWithCount(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, _, db := newForwardStore(t)
	setup := setupQueryTestData(t, ctx, store, db)
	assetID1Spec := asset.NewSpecifierFromId(setup.assetID1)

	testCases := []struct {
		name     string
		params   rfq.QueryForwardsParams
		expCount int64
		expLen   int
	}{{
		name: "limit without filters",
		params: rfq.QueryForwardsParams{
			Limit: 3,
		},
		expCount: 6,
		expLen:   3,
	}, {
		name: "offset without filters",
		params: rfq.QueryForwardsParams{
			Limit:  3,
			Offset: 3,
		},
		expCount: 6,
		expLen:   3,
	}, {
		name: "filtered by asset",
		params: rfq.QueryForwardsParams{
			AssetSpecifier: &assetID1Spec,
			Limit:          10,
		},
		expCount: 4,
		expLen:   4,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			records, count, err := store.QueryForwardsWithCount(
				ctx,
				tc.params,
			)
			require.NoError(t, err)
			require.Len(t, records, tc.expLen)
			require.Equal(t, tc.expCount, count)
		})
	}
}
