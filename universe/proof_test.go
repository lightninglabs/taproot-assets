package universe

import (
	"testing"

	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/mssmt"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/stretchr/testify/require"
)

// randUniverseProof builds a non-trivial universe proof populated with random
// data.
func randUniverseProof(t testing.TB) *Proof {
	t.Helper()

	randAsset := asset.RandAsset(t, asset.Normal)
	leaf := &Leaf{
		GenesisWithGroup: GenesisWithGroup{
			Genesis:  randAsset.Genesis,
			GroupKey: randAsset.GroupKey,
		},
		RawProof: proof.Blob(test.RandBytes(64)),
		Asset:    randAsset,
		Amt:      uint64(test.RandInt[uint32]()) + 1,
		IsBurn:   test.RandBool(),
	}

	leafKey := BaseLeafKey{
		OutPoint:  test.RandOp(t),
		ScriptKey: fn.Ptr(asset.RandScriptKey(t)),
	}

	universeRoot := mssmt.NewBranch(
		mssmt.NewLeafNode(test.RandBytes(16), mssmt.RandLeafAmount()),
		mssmt.NewLeafNode(test.RandBytes(12), mssmt.RandLeafAmount()),
	)

	multiverseRoot := mssmt.NewBranch(
		mssmt.NewLeafNode(test.RandBytes(20), mssmt.RandLeafAmount()),
		mssmt.NewLeafNode(test.RandBytes(8), mssmt.RandLeafAmount()),
	)

	return &Proof{
		Leaf:                     leaf,
		LeafKey:                  leafKey,
		UniverseRoot:             universeRoot,
		UniverseInclusionProof:   mssmt.RandProof(t),
		MultiverseRoot:           multiverseRoot,
		MultiverseInclusionProof: mssmt.RandProof(t),
	}
}

// TestProofLowerBoundByteSizeRawProofDelta verifies that changes to the raw
// proof byte slice length are reflected in the size estimate.
func TestProofLowerBoundByteSizeRawProofDelta(t *testing.T) {
	t.Parallel()

	p := randUniverseProof(t)
	baseSize := p.LowerBoundByteSize()
	baseLen := len(p.Leaf.RawProof)

	// Increase RawProof length.
	p.Leaf.RawProof = make([]byte, baseLen+25)
	require.Equal(
		t, baseSize+25, p.LowerBoundByteSize(),
	)

	// Decrease RawProof length (ensure > 0).
	newLen := baseLen - 10
	if newLen <= 0 {
		newLen = 1
	}
	p.Leaf.RawProof = make([]byte, newLen)
	require.Equal(
		t, baseSize-uint64(baseLen-newLen), p.LowerBoundByteSize(),
	)
}

// TestProofLowerBoundByteSizeInclusionProofDelta ensures inclusion proofs with
// different payload sizes produce corresponding size deltas in the estimate.
func TestProofLowerBoundByteSizeInclusionProofDelta(t *testing.T) {
	t.Parallel()

	p := randUniverseProof(t)

	smallInclusion := &mssmt.Proof{
		Nodes: []mssmt.Node{
			mssmt.NewLeafNode(make([]byte, 4), 1),
		},
	}
	largeInclusion := &mssmt.Proof{
		Nodes: []mssmt.Node{
			mssmt.NewLeafNode(make([]byte, 4), 1),
			mssmt.NewLeafNode(make([]byte, 24), 2),
		},
	}

	smallIncSize := fn.LowerBoundByteSize(smallInclusion)
	largeIncSize := fn.LowerBoundByteSize(largeInclusion)
	expectedDelta := largeIncSize - smallIncSize
	require.Greater(t, expectedDelta, uint64(0))

	// Attach the smaller inclusion proof and record the total size.
	p.UniverseInclusionProof = smallInclusion
	smallTotal := p.LowerBoundByteSize()

	// Swap in the larger inclusion proof and record the new total size.
	p.UniverseInclusionProof = largeInclusion
	largeTotal := p.LowerBoundByteSize()

	// The total size should increase exactly by the difference in inclusion
	// proof sizes.
	require.Equal(t, smallTotal+expectedDelta, largeTotal)
}

// TestProofLowerBoundByteSizeRootDelta checks that changes in the universe root
// payload are reflected in the size estimate.
func TestProofLowerBoundByteSizeRootDelta(t *testing.T) {
	t.Parallel()

	p := randUniverseProof(t)

	smallRoot := mssmt.NewLeafNode(make([]byte, 8), 10)
	largeRoot := mssmt.NewLeafNode(make([]byte, 40), 10)

	smallSize := fn.LowerBoundByteSize(smallRoot)
	largeSize := fn.LowerBoundByteSize(largeRoot)
	expectedDelta := largeSize - smallSize
	require.Greater(t, expectedDelta, uint64(0))

	// Attach the small root.
	p.UniverseRoot = smallRoot
	smallTotal := p.LowerBoundByteSize()

	// Swap in the large root.
	p.UniverseRoot = largeRoot
	largeTotal := p.LowerBoundByteSize()

	// Verify delta.
	require.Equal(t, smallTotal+expectedDelta, largeTotal)
}
