package tapdb

import (
	"context"
	"errors"
	"testing"

	"github.com/lightninglabs/taproot-assets/address"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/universe"
	"github.com/lightninglabs/taproot-assets/universe/supplycommit"
	lfn "github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockGroupQuery is a mock implementation of assetGroupQuery.
type mockGroupQuery struct {
	mock.Mock
}

func (m *mockGroupQuery) QueryAssetGroupByID(ctx context.Context,
	id asset.ID) (*asset.AssetGroup, error) {

	args := m.Called(ctx, id)
	return args.Get(0).(*asset.AssetGroup), args.Error(1)
}

// mockIgnoreStore is a mock implementation of ignoreCheckerStore.
type mockIgnoreStore struct {
	mock.Mock
}

func (m *mockIgnoreStore) FetchSupplyLeavesByType(ctx context.Context,
	spec asset.Specifier, tree supplycommit.SupplySubTree, startHeight,
	endHeight uint32) lfn.Result[supplycommit.SupplyLeaves] {

	args := m.Called(ctx, spec, tree, startHeight, endHeight)
	return args.Get(0).(lfn.Result[supplycommit.SupplyLeaves])
}

// TestCachingIgnoreChecker_IsIgnored tests the IsIgnored method of
// CachingIgnoreChecker for all possible cases.
func TestCachingIgnoreChecker_IsIgnored(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	assetID := asset.ID{1, 2, 3}
	groupPubKey := test.RandPubKey(t)
	groupKeySpecifier := asset.NewSpecifierFromGroupKey(*groupPubKey)
	otherAssetID := asset.ID{7, 8, 9}
	outPoint := test.RandOp(t)
	scriptKey := [33]byte{2}
	assetPoint := proof.AssetPoint{
		OutPoint:  outPoint,
		ID:        assetID,
		ScriptKey: scriptKey,
	}

	ignoreLeaf := supplycommit.NewIgnoreEvent{
		SignedIgnoreTuple: universe.NewSignedIgnoreTuple(
			universe.IgnoreTuple{
				PrevID:      assetPoint,
				Amount:      123,
				BlockHeight: 345,
			}, universe.IgnoreSig{},
		),
	}

	leaves := supplycommit.SupplyLeaves{
		IgnoreLeafEntries: []supplycommit.NewIgnoreEvent{ignoreLeaf},
	}

	testCases := []struct {
		name          string
		setupMocks    func(*mockGroupQuery, *mockIgnoreStore)
		assetPoint    proof.AssetPoint
		preIgnored    bool
		expectIgnored bool
		expectErr     bool
	}{
		{
			name: "already ignored asset point",
			setupMocks: func(*mockGroupQuery, *mockIgnoreStore) {
			},
			assetPoint:    assetPoint,
			preIgnored:    true,
			expectIgnored: true,
			expectErr:     false,
		},
		{
			name: "non-grouped asset",
			setupMocks: func(g *mockGroupQuery,
				s *mockIgnoreStore) {

				g.On(
					"QueryAssetGroupByID", mock.Anything,
					assetID,
				).Return(&asset.AssetGroup{
					GroupKey: nil,
				}, nil).Once()
			},
			assetPoint:    assetPoint,
			preIgnored:    false,
			expectIgnored: false,
			expectErr:     false,
		},
		{
			name: "grouped asset, not ignored",
			setupMocks: func(g *mockGroupQuery,
				s *mockIgnoreStore) {

				g.On(
					"QueryAssetGroupByID", mock.Anything,
					otherAssetID,
				).Return(&asset.AssetGroup{
					GroupKey: &asset.GroupKey{
						GroupPubKey: *groupPubKey,
					},
				}, nil).Once()
				s.On(
					"FetchSupplyLeavesByType",
					mock.Anything, groupKeySpecifier,
					supplycommit.IgnoreTreeType, uint32(0),
					uint32(0),
				).Return(lfn.Ok(leaves)).Once()
			},
			assetPoint: proof.AssetPoint{
				OutPoint:  outPoint,
				ID:        otherAssetID,
				ScriptKey: scriptKey,
			},
			preIgnored:    false,
			expectIgnored: false,
			expectErr:     false,
		},
		{
			name: "grouped asset, is ignored",
			setupMocks: func(g *mockGroupQuery,
				s *mockIgnoreStore) {

				g.On(
					"QueryAssetGroupByID", mock.Anything,
					assetID,
				).Return(&asset.AssetGroup{
					GroupKey: &asset.GroupKey{
						GroupPubKey: *groupPubKey,
					},
				}, nil).Once()
				s.On(
					"FetchSupplyLeavesByType",
					mock.Anything, groupKeySpecifier,
					supplycommit.IgnoreTreeType, uint32(0),
					uint32(0),
				).Return(lfn.Ok(leaves)).Once()
			},
			assetPoint:    assetPoint,
			preIgnored:    false,
			expectIgnored: true,
			expectErr:     false,
		},
		{
			name: "asset group unknown error",
			setupMocks: func(g *mockGroupQuery,
				s *mockIgnoreStore) {

				g.On(
					"QueryAssetGroupByID", mock.Anything,
					assetID,
				).Return(
					&asset.AssetGroup{},
					address.ErrAssetGroupUnknown,
				).Once()
			},
			assetPoint:    assetPoint,
			preIgnored:    false,
			expectIgnored: false,
			expectErr:     false,
		},
		{
			name: "asset group query error",
			setupMocks: func(g *mockGroupQuery,
				s *mockIgnoreStore) {

				g.On(
					"QueryAssetGroupByID", mock.Anything,
					assetID,
				).Return(
					&asset.AssetGroup{}, errors.New("fail"),
				).Once()
			},
			assetPoint:    assetPoint,
			preIgnored:    false,
			expectIgnored: false,
			expectErr:     true,
		},
		{
			name: "fetch supply leaves error",
			setupMocks: func(g *mockGroupQuery,
				s *mockIgnoreStore) {

				g.On(
					"QueryAssetGroupByID", mock.Anything,
					assetID,
				).Return(&asset.AssetGroup{
					GroupKey: &asset.GroupKey{
						GroupPubKey: *groupPubKey,
					},
				}, nil).Once()
				s.On(
					"FetchSupplyLeavesByType",
					mock.Anything, groupKeySpecifier,
					supplycommit.IgnoreTreeType, uint32(0),
					uint32(0),
				).Return(lfn.Errf[supplycommit.SupplyLeaves](
					"fail",
				)).Once()
			},
			assetPoint:    assetPoint,
			preIgnored:    false,
			expectIgnored: false,
			expectErr:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			groupQuery := &mockGroupQuery{}
			store := &mockIgnoreStore{}

			t.Cleanup(func() {
				groupQuery.AssertExpectations(t)
				store.AssertExpectations(t)
			})

			if tc.setupMocks != nil {
				tc.setupMocks(groupQuery, store)
			}

			checker := NewCachingIgnoreChecker(IgnoreCheckerCfg{
				GroupQuery: groupQuery,
				Store:      store,
			})

			if tc.preIgnored {
				checker.ignoredAssetPoints.Add(tc.assetPoint)
			}

			res, err := checker.IsIgnored(ctx, tc.assetPoint).
				Unpack()
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expectIgnored, res)
			}
		})
	}
}

// TestNegativeLookupCacheLogger tests the negative lookup cache and
// validates the cache logger's hit/miss ratio for cache hits and misses.
func TestNegativeLookupCacheLogger(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	assetID := asset.ID{1, 2, 3}
	groupPubKey := test.RandPubKey(t)
	groupKeySpecifier := asset.NewSpecifierFromGroupKey(*groupPubKey)
	outPoint := test.RandOp(t)
	scriptKey := [33]byte{2}
	assetPoint := proof.AssetPoint{
		OutPoint:  outPoint,
		ID:        assetID,
		ScriptKey: scriptKey,
	}

	groupQuery := &mockGroupQuery{}
	store := &mockIgnoreStore{}

	groupQuery.On(
		"QueryAssetGroupByID", mock.Anything, assetID,
	).Return(&asset.AssetGroup{
		GroupKey: &asset.GroupKey{
			GroupPubKey: *groupPubKey,
		},
	}, nil).Once()
	store.On(
		"FetchSupplyLeavesByType",
		mock.Anything, groupKeySpecifier,
		supplycommit.IgnoreTreeType, uint32(0), uint32(0),
	).Return(lfn.Ok(supplycommit.SupplyLeaves{})).Once()

	checker := NewCachingIgnoreChecker(IgnoreCheckerCfg{
		GroupQuery:              groupQuery,
		Store:                   store,
		NegativeLookupCacheSize: 100,
	})

	// First call: should be a cache miss, asset point added to negative
	// cache.
	res, err := checker.IsIgnored(ctx, assetPoint).Unpack()
	require.NoError(t, err)
	require.False(t, res)
	misses := checker.nonIgnoredAssetPoints.cacheLogger.miss.Load()
	require.EqualValues(t, 1, misses)

	// Second call: should be a cache hit, no DB call.
	res, err = checker.IsIgnored(ctx, assetPoint).Unpack()
	require.NoError(t, err)
	require.False(t, res)
	misses = checker.nonIgnoredAssetPoints.cacheLogger.miss.Load()
	require.EqualValues(t, 1, misses)
	hits := checker.nonIgnoredAssetPoints.cacheLogger.hit.Load()
	require.EqualValues(t, 1, hits)
}
