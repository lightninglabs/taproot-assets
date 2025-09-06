package supplycommit

import (
	"context"
	"fmt"
	"testing"

	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/stretchr/testify/require"
)

// createTreeWithSum creates an in-memory mssmt tree with the specified sum.
// If sum is 0, returns an empty tree.
func createTreeWithSum(sum uint64) mssmt.Tree {
	store := mssmt.NewDefaultStore()
	tree := mssmt.NewCompactedTree(store)

	if sum > 0 {
		// Insert a leaf with the desired sum.
		//
		// Use sum to create unique key.
		key := [32]byte{byte(sum % 256)}
		leaf := mssmt.NewLeafNode(
			[]byte(fmt.Sprintf("value-%d", sum)), sum,
		)
		newTree, _ := tree.Insert(context.Background(), key, leaf)
		return newTree
	}

	return tree
}

// TestCalcTotalOutstandingSupply tests the CalcTotalOutstandingSupply function
// with various combinations of supply trees.
func TestCalcTotalOutstandingSupply(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	testCases := []struct {
		name           string
		supplyTrees    SupplyTrees
		expectedResult uint64
		expectedError  string
	}{
		{
			name:           "empty supply trees",
			supplyTrees:    SupplyTrees{},
			expectedResult: 0,
			expectedError:  "",
		},
		{
			name: "only mint tree with zero sum",
			supplyTrees: SupplyTrees{
				MintTreeType: createTreeWithSum(0),
			},
			expectedResult: 0,
			expectedError:  "",
		},
		{
			name: "only mint tree with positive sum",
			supplyTrees: SupplyTrees{
				MintTreeType: createTreeWithSum(1000),
			},
			expectedResult: 1000,
			expectedError:  "",
		},
		{
			name: "mint and burn trees",
			supplyTrees: SupplyTrees{
				MintTreeType: createTreeWithSum(1000),
				BurnTreeType: createTreeWithSum(300),
			},
			expectedResult: 700,
			expectedError:  "",
		},
		{
			name: "mint and ignore trees",
			supplyTrees: SupplyTrees{
				MintTreeType:   createTreeWithSum(1000),
				IgnoreTreeType: createTreeWithSum(200),
			},
			expectedResult: 800,
			expectedError:  "",
		},
		{
			name: "all three tree types",
			supplyTrees: SupplyTrees{
				MintTreeType:   createTreeWithSum(1000),
				BurnTreeType:   createTreeWithSum(200),
				IgnoreTreeType: createTreeWithSum(100),
			},
			expectedResult: 700,
			expectedError:  "",
		},
		{
			name: "burned amount exceeds total minted",
			supplyTrees: SupplyTrees{
				MintTreeType: createTreeWithSum(500),
				BurnTreeType: createTreeWithSum(600),
			},
			expectedResult: 0,
			expectedError: "total burned 600 exceeds total " +
				"outstanding 500",
		},
		{
			name: "ignored amount exceeds remaining supply",
			supplyTrees: SupplyTrees{
				MintTreeType:   createTreeWithSum(1000),
				BurnTreeType:   createTreeWithSum(200),
				IgnoreTreeType: createTreeWithSum(900),
			},
			expectedResult: 0,
			expectedError: "total ignored 900 exceeds total " +
				"outstanding 800",
		},
		{
			name: "burn exactly equals mint",
			supplyTrees: SupplyTrees{
				MintTreeType: createTreeWithSum(500),
				BurnTreeType: createTreeWithSum(500),
			},
			expectedResult: 0,
			expectedError:  "",
		},
		{
			name: "ignore exactly equals remaining supply",
			supplyTrees: SupplyTrees{
				MintTreeType:   createTreeWithSum(1000),
				BurnTreeType:   createTreeWithSum(300),
				IgnoreTreeType: createTreeWithSum(700),
			},
			expectedResult: 0,
			expectedError:  "",
		},
		{
			name: "only burn tree (no mint)",
			supplyTrees: SupplyTrees{
				BurnTreeType: createTreeWithSum(100),
			},
			expectedResult: 0,
			expectedError:  "",
		},
		{
			name: "only ignore tree (no mint)",
			supplyTrees: SupplyTrees{
				IgnoreTreeType: createTreeWithSum(100),
			},
			expectedResult: 0,
			expectedError:  "",
		},
	}

	for idx := range testCases {
		tc := testCases[idx]

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := CalcTotalOutstandingSupply(
				ctx, tc.supplyTrees,
			)

			if tc.expectedError != "" {
				require.True(
					t, result.IsErr(),
					"expected error but got success",
				)
				err := result.Err()
				require.Contains(
					t, err.Error(), tc.expectedError,
				)

				return
			}

			require.True(
				t, result.IsOk(),
				"expected success but got error: %v",
				result.Err(),
			)
			actual := result.UnwrapOr(0)
			require.Equal(t, tc.expectedResult, actual)
		})
	}
}
