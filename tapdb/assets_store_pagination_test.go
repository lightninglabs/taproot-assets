package tapdb

import (
	"bytes"
	"context"
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/stretchr/testify/require"
)

// TestFetchAllAssetsPaginated tests the paginated asset fetching functionality.
func TestFetchAllAssetsPaginated(t *testing.T) {
	t.Parallel()

	const (
		numAssets    = 25 // Create enough assets to test pagination
		numGroupKeys = 2
	)

	ctx := context.Background()
	// Create enough unique genesis assets for our test
	assetGen := newAssetGenerator(t, numAssets, numGroupKeys)
	
	// Create a variety of assets with different properties
	var availableAssets []assetDesc
	for i := 0; i < numAssets; i++ {
		desc := assetDesc{
			assetGen:    assetGen.assetGens[i],
			anchorPoint: assetGen.anchorPoints[i],
			amt:         uint64(i + 1) * 10, // Amounts: 10, 20, 30, ...
		}
		
		// Mark some as spent
		if i%5 == 0 {
			desc.spent = true
		}
		
		availableAssets = append(availableAssets, desc)
	}

	// Create a new assets store and insert the assets
	_, assetsStore, _ := newAssetStore(t)
	genAssets, _ := assetGen.genAssets(t, assetsStore, availableAssets)
	
	// Count how many assets should be returned (non-spent)
	expectedNonSpent := 0
	for _, desc := range availableAssets {
		if !desc.spent {
			expectedNonSpent++
		}
	}

	testCases := []struct {
		name          string
		offset        int32
		limit         int32
		direction     taprpc.SortDirection
		includeSpent  bool
		includeLeased bool
		filter        *AssetQueryFilters
		expectedCount int
		hasMore       bool
	}{
		{
			name:          "first page - default limit",
			offset:        0,
			limit:         10,
			direction:     taprpc.SortDirection_SORT_DIRECTION_ASC,
			includeSpent:  false,
			expectedCount: 10,
			hasMore:       true,
		},
		{
			name:          "second page",
			offset:        10,
			limit:         10,
			direction:     taprpc.SortDirection_SORT_DIRECTION_ASC,
			includeSpent:  false,
			expectedCount: 10,
			hasMore:       false, // Last partial page
		},
		{
			name:          "small page size",
			offset:        0,
			limit:         5,
			direction:     taprpc.SortDirection_SORT_DIRECTION_ASC,
			includeSpent:  false,
			expectedCount: 5,
			hasMore:       true,
		},
		{
			name:          "large page size - all results",
			offset:        0,
			limit:         100,
			direction:     taprpc.SortDirection_SORT_DIRECTION_ASC,
			includeSpent:  false,
			expectedCount: expectedNonSpent,
			hasMore:       false,
		},
		{
			name:          "descending order",
			offset:        0,
			limit:         10,
			direction:     taprpc.SortDirection_SORT_DIRECTION_DESC,
			includeSpent:  false,
			expectedCount: 10,
			hasMore:       true,
		},
		{
			name:          "include spent assets",
			offset:        0,
			limit:         10,
			direction:     taprpc.SortDirection_SORT_DIRECTION_ASC,
			includeSpent:  true,
			expectedCount: 10,
			hasMore:       true,
		},
		{
			name:          "offset beyond results",
			offset:        1000,
			limit:         10,
			direction:     taprpc.SortDirection_SORT_DIRECTION_ASC,
			includeSpent:  false,
			expectedCount: 0,
			hasMore:       false,
		},
		{
			name:          "last page exact boundary",
			offset:        int32(expectedNonSpent - 5),
			limit:         5,
			direction:     taprpc.SortDirection_SORT_DIRECTION_ASC,
			includeSpent:  false,
			expectedCount: 5,
			hasMore:       false,
		},
		{
			name:          "last page partial",
			offset:        int32(expectedNonSpent - 3),
			limit:         10,
			direction:     taprpc.SortDirection_SORT_DIRECTION_ASC,
			includeSpent:  false,
			expectedCount: 3,
			hasMore:       false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Fetch paginated assets
			assets, totalCount, err := assetsStore.FetchAllAssetsPaginated(
				ctx, tc.includeSpent, tc.includeLeased, tc.filter,
				tc.offset, tc.limit, tc.direction,
			)
			require.NoError(t, err)
			
			// Check the number of returned assets
			require.Len(t, assets, tc.expectedCount, 
				"expected %d assets, got %d", tc.expectedCount, len(assets))
			
			// Verify total count is consistent
			if tc.includeSpent {
				require.Equal(t, uint64(numAssets), totalCount)
			} else {
				require.Equal(t, uint64(expectedNonSpent), totalCount)
			}
			
			// Check if sorting is correct for non-empty results
			if len(assets) > 1 {
				for i := 1; i < len(assets); i++ {
					prevID := assets[i-1].ID()
					currID := assets[i].ID()
					prev := prevID[:]
					curr := currID[:]
					
					if tc.direction == taprpc.SortDirection_SORT_DIRECTION_ASC {
						require.True(t, bytes.Compare(prev, curr) < 0,
							"assets should be in ascending order")
					} else {
						require.True(t, bytes.Compare(prev, curr) > 0,
							"assets should be in descending order")
					}
				}
			}
			
			// Verify assets match the original generated assets
			for _, returnedAsset := range assets {
				found := false
				returnedID := returnedAsset.ID()
				for _, genAsset := range genAssets {
					genID := genAsset.ID()
					if returnedID == genID {
						found = true
						break
					}
				}
				require.True(t, found, "returned asset should be in generated assets")
			}
		})
	}
}

// TestFetchAllAssetsPaginatedWithFilters tests pagination with various filters.
func TestFetchAllAssetsPaginatedWithFilters(t *testing.T) {
	t.Parallel()

	const (
		numAssets    = 30
		numGroupKeys = 3
	)

	ctx := context.Background()
	assetGen := newAssetGenerator(t, numAssets, numGroupKeys)
	
	// Create assets with varying amounts for filtering
	var availableAssets []assetDesc
	for i := 0; i < numAssets; i++ {
		desc := assetDesc{
			assetGen:    assetGen.assetGens[i],
			anchorPoint: assetGen.anchorPoints[i],
			amt:         uint64((i % 10) + 1) * 10, // Amounts: 10-100
		}
		
		// Add group keys to some assets
		if i%3 == 0 && len(assetGen.groupKeys) > 0 {
			desc.keyGroup = assetGen.groupKeys[i%len(assetGen.groupKeys)]
		}
		
		availableAssets = append(availableAssets, desc)
	}

	_, assetsStore, _ := newAssetStore(t)
	assetGen.genAssets(t, assetsStore, availableAssets)

	makeFilter := func(opts ...filterOpt) *AssetQueryFilters {
		var filter AssetQueryFilters
		for _, opt := range opts {
			opt(&filter)
		}
		return &filter
	}

	testCases := []struct {
		name      string
		offset    int32
		limit     int32
		filter    *AssetQueryFilters
		minAssets int // Minimum expected assets (exact count depends on random generation)
	}{
		{
			name:      "filter with min amount and pagination",
			offset:    0,
			limit:     5,
			filter:    makeFilter(filterMinAmt(50)),
			minAssets: 5,
		},
		{
			name:      "filter with max amount and pagination",
			offset:    0,
			limit:     10,
			filter:    makeFilter(filterMaxAmt(50)),
			minAssets: 10,
		},
		{
			name:   "filter with amount range and pagination",
			offset: 0,
			limit:  5,
			filter: makeFilter(
				filterMinAmt(30),
				filterMaxAmt(70),
			),
			minAssets: 5,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assets, totalCount, err := assetsStore.FetchAllAssetsPaginated(
				ctx, false, false, tc.filter, tc.offset, tc.limit,
				taprpc.SortDirection_SORT_DIRECTION_ASC,
			)
			require.NoError(t, err)
			
			// Should return up to limit items
			require.LessOrEqual(t, len(assets), int(tc.limit))
			
			// Total count should be non-zero for these filters
			require.Greater(t, totalCount, uint64(0))
			
			// Verify filters are applied correctly
			if tc.filter != nil {
				for _, asset := range assets {
					if tc.filter.MinAmt != 0 {
						require.GreaterOrEqual(t, asset.Amount, tc.filter.MinAmt)
					}
					if tc.filter.MaxAmt != 0 {
						require.LessOrEqual(t, asset.Amount, tc.filter.MaxAmt)
					}
				}
			}
		})
	}
}

// TestFetchAllAssetsPaginatedConsistency tests that pagination returns consistent results.
func TestFetchAllAssetsPaginatedConsistency(t *testing.T) {
	t.Parallel()

	const numAssets = 15

	ctx := context.Background()
	assetGen := newAssetGenerator(t, numAssets, 0)
	
	var availableAssets []assetDesc
	for i := 0; i < numAssets; i++ {
		availableAssets = append(availableAssets, assetDesc{
			assetGen:    assetGen.assetGens[i],
			anchorPoint: assetGen.anchorPoints[i],
			amt:         uint64(i + 1),
		})
	}

	_, assetsStore, _ := newAssetStore(t)
	assetGen.genAssets(t, assetsStore, availableAssets)

	// Fetch all assets in one go
	allAssets, totalCount1, err := assetsStore.FetchAllAssetsPaginated(
		ctx, false, false, nil, 0, 100,
		taprpc.SortDirection_SORT_DIRECTION_ASC,
	)
	require.NoError(t, err)
	require.Equal(t, numAssets, len(allAssets))

	// Fetch assets in pages and combine
	pageSize := int32(5)
	var pagedAssets []*asset.ChainAsset
	for offset := int32(0); offset < int32(numAssets); offset += pageSize {
		page, totalCount2, err := assetsStore.FetchAllAssetsPaginated(
			ctx, false, false, nil, offset, pageSize,
			taprpc.SortDirection_SORT_DIRECTION_ASC,
		)
		require.NoError(t, err)
		require.Equal(t, totalCount1, totalCount2, "total count should be consistent")
		
		pagedAssets = append(pagedAssets, page...)
	}

	// Verify we got the same assets
	require.Equal(t, len(allAssets), len(pagedAssets))
	
	// Compare asset IDs (they should be in the same order)
	for i := range allAssets {
		allID := allAssets[i].ID()
		pagedID := pagedAssets[i].ID()
		require.Equal(t, allID, pagedID)
	}
}

// TestFetchAllAssetsBackwardsCompatibility tests that the non-paginated FetchAllAssets
// still works correctly alongside the paginated version.
func TestFetchAllAssetsBackwardsCompatibility(t *testing.T) {
	t.Parallel()

	const numAssets = 20

	ctx := context.Background()
	assetGen := newAssetGenerator(t, numAssets, 0)
	
	var availableAssets []assetDesc
	for i := 0; i < numAssets; i++ {
		desc := assetDesc{
			assetGen:    assetGen.assetGens[i],
			anchorPoint: assetGen.anchorPoints[i],
			amt:         uint64(i + 1),
		}
		// Mark some as spent
		if i%4 == 0 {
			desc.spent = true
		}
		availableAssets = append(availableAssets, desc)
	}

	_, assetsStore, _ := newAssetStore(t)
	assetGen.genAssets(t, assetsStore, availableAssets)

	// Fetch using the original non-paginated method
	originalAssets, err := assetsStore.FetchAllAssets(ctx, false, false, nil)
	require.NoError(t, err)

	// Fetch using the paginated method with a large limit (simulating no pagination)
	paginatedAssets, totalCount, err := assetsStore.FetchAllAssetsPaginated(
		ctx, false, false, nil, 0, 1000,
		taprpc.SortDirection_SORT_DIRECTION_ASC,
	)
	require.NoError(t, err)

	// Both methods should return the same number of assets
	require.Equal(t, len(originalAssets), len(paginatedAssets))
	require.Equal(t, uint64(len(originalAssets)), totalCount)

	// Create maps for easier comparison
	originalMap := make(map[string]*asset.ChainAsset)
	for _, a := range originalAssets {
		aID := a.ID()
		originalMap[string(aID[:])] = a
	}

	// Verify all paginated assets exist in original results
	for _, paginatedAsset := range paginatedAssets {
		pID := paginatedAsset.ID()
		originalAsset, exists := originalMap[string(pID[:])]
		require.True(t, exists, "paginated asset should exist in original results")
		require.Equal(t, originalAsset.Amount, paginatedAsset.Amount)
	}
}