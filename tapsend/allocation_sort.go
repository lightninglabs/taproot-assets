package tapsend

import (
	"bytes"
	"cmp"
	"slices"
)

// InPlaceAllocationSort performs an in-place sort of output allocations.
//
// The sort applied is a modified BIP69 sort, that uses the CLTV values of HTLCs
// as a tiebreaker in case two HTLC outputs have an identical amount and
// pkScript. The pkScripts can be the same if they share the same payment hash,
// but since the CLTV is enforced via the nLockTime of the second-layer
// transactions, the script does not directly commit to them. Instead, the CLTVs
// must be supplied separately to act as a tie-breaker, otherwise we may produce
// invalid HTLC signatures if the receiver produces an alternative ordering
// during verification. Because multiple shards of the same MPP payment can be
// identical in all other fields, we also use the HtlcIndex as a final
// tie-breaker.
//
// NOTE: Commitment and commitment anchor outputs should have a 0 CLTV and
// HtlcIndex value.
func InPlaceAllocationSort(allocations []*Allocation) {
	slices.SortFunc(allocations, func(i, j *Allocation) int {
		return cmp.Or(
			cmp.Compare(i.BtcAmount, j.BtcAmount),
			bytes.Compare(
				i.SortTaprootKeyBytes, j.SortTaprootKeyBytes,
			),
			cmp.Compare(i.SortCLTV, j.SortCLTV),
			cmp.Compare(i.HtlcIndex, j.HtlcIndex),
		)
	})
}
