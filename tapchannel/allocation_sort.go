package tapchannel

import (
	"bytes"
	"sort"
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
// during verification.
//
// NOTE: Commitment and commitment anchor outputs should have a 0 CLTV value.
func InPlaceAllocationSort(allocations []*Allocation) {
	sort.Sort(sortableAllocationSlice{allocations})
}

// sortableAllocationSlice is a slice of allocations and the corresponding CLTV
// values of any HTLCs. Commitment and commitment anchor outputs should have a
// CLTV of 0.
type sortableAllocationSlice struct {
	allocations []*Allocation
}

// Len returns the length of the sortableAllocationSlice.
//
// NOTE: Part of the sort.Interface interface.
func (s sortableAllocationSlice) Len() int {
	return len(s.allocations)
}

// Swap exchanges the position of outputs i and j.
//
// NOTE: Part of the sort.Interface interface.
func (s sortableAllocationSlice) Swap(i, j int) {
	s.allocations[i], s.allocations[j] = s.allocations[j], s.allocations[i]
}

// Less is a modified BIP69 output comparison, that sorts based on value, then
// pkScript, then CLTV value.
//
// NOTE: Part of the sort.Interface interface.
func (s sortableAllocationSlice) Less(i, j int) bool {
	allocI, allocJ := s.allocations[i], s.allocations[j]

	if allocI.BtcAmount != allocJ.BtcAmount {
		return allocI.BtcAmount < allocJ.BtcAmount
	}

	pkScriptCmp := bytes.Compare(
		allocI.SortTaprootKeyBytes, allocJ.SortTaprootKeyBytes,
	)
	if pkScriptCmp != 0 {
		return pkScriptCmp < 0
	}

	return allocI.CLTV < allocJ.CLTV
}
