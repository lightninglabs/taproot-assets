package tapsend

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestInPlaceAllocationSort tests the in-place sorting of allocations.
func TestInPlaceAllocationSort(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		allocations []*Allocation
		expected    []*Allocation
	}{
		{
			name: "",
			allocations: []*Allocation{
				{
					BtcAmount:           2000,
					SortTaprootKeyBytes: []byte("b"),
					SortCLTV:            300,
				},
				{
					BtcAmount:           3000,
					SortTaprootKeyBytes: []byte("a"),
					SortCLTV:            100,
				},
				{
					BtcAmount:           1000,
					SortTaprootKeyBytes: []byte("a"),
					SortCLTV:            200,
				},
				{
					BtcAmount:           1000,
					SortTaprootKeyBytes: []byte("b"),
					SortCLTV:            100,
				},
				{
					BtcAmount:           1000,
					SortTaprootKeyBytes: []byte("b"),
					SortCLTV:            100,
					HtlcIndex:           1,
				},
				{
					BtcAmount:           1000,
					SortTaprootKeyBytes: []byte("b"),
					SortCLTV:            100,
					HtlcIndex:           9,
				},
				{
					BtcAmount:           1000,
					SortTaprootKeyBytes: []byte("b"),
					SortCLTV:            100,
					HtlcIndex:           3,
				},
				{
					BtcAmount:           1000,
					SortTaprootKeyBytes: []byte("a"),
					SortCLTV:            100,
				},
			},
			expected: []*Allocation{
				{
					BtcAmount:           1000,
					SortTaprootKeyBytes: []byte("a"),
					SortCLTV:            100,
				},
				{
					BtcAmount:           1000,
					SortTaprootKeyBytes: []byte("a"),
					SortCLTV:            200,
				},
				{
					BtcAmount:           1000,
					SortTaprootKeyBytes: []byte("b"),
					SortCLTV:            100,
				},
				{
					BtcAmount:           1000,
					SortTaprootKeyBytes: []byte("b"),
					SortCLTV:            100,
					HtlcIndex:           1,
				},
				{
					BtcAmount:           1000,
					SortTaprootKeyBytes: []byte("b"),
					SortCLTV:            100,
					HtlcIndex:           3,
				},
				{
					BtcAmount:           1000,
					SortTaprootKeyBytes: []byte("b"),
					SortCLTV:            100,
					HtlcIndex:           9,
				},
				{
					BtcAmount:           2000,
					SortTaprootKeyBytes: []byte("b"),
					SortCLTV:            300,
				},
				{
					BtcAmount:           3000,
					SortTaprootKeyBytes: []byte("a"),
					SortCLTV:            100,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			InPlaceAllocationSort(tc.allocations)

			require.Equal(t, tc.expected, tc.allocations)
		})
	}
}
